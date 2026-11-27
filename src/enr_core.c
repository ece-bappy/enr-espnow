/* ENR runtime: ESP-NOW transport, controller role and node role.
 *
 * Threading: one protocol task owns all session state. ESP-NOW receive callbacks and enr_send()
 * only copy frames into queues. X25519 runs in a low-priority worker task so the data path is
 * never blocked by a key exchange. Ephemeral keys are generated only when a handshake is
 * requested and wiped as soon as it completes (a precomputed key would defeat PCS). */
#include <string.h>
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "enr.h"
#include "enr_proto.h"

static const char *TAG = "enr";

/* ------------------------------------------------------------------ common */

static enr_config_t C;
static uint8_t SELF[6];
static enum { R_NONE, R_CTRL, R_NODE } ROLE;
static QueueHandle_t s_rxq, s_txq, s_jobq, s_resq;
static enr_recv_cb_t s_rx_cb;
static void *s_rx_ctx;
static enr_event_cb_t s_ev_cb;
static void *s_ev_ctx;

typedef struct { uint8_t src[6]; int len; uint8_t data[ENR_MAX_FRAME]; } rxm_t;
typedef struct { uint8_t peer[6]; uint8_t len; uint8_t data[ENR_MAX_PAYLOAD]; } txm_t;

#define PROTO_CORE (portNUM_PROCESSORS > 1 ? 1 : 0)
#define T_REFRESH_US (MS(C.t_epoch_ms) * C.m)

static int64_t retx_us(int tries) {
    int64_t t = ENR_T_HS_MS;
    if (C.backoff) {
        t <<= (tries > 0 ? tries - 1 : 0);
        if (t > 8000) t = 8000;
    }
    return MS(t);
}
static int64_t hs_window_us(void) {
    return C.backoff ? MS((int64_t)ENR_T_HS_MS * ((1 << ENR_R_MAX) - 1)) : MS((int64_t)ENR_T_HS_MS * ENR_R_MAX);
}
static void emit(const uint8_t peer[6], enr_event_t ev) { if (s_ev_cb) s_ev_cb(peer, ev, s_ev_ctx); }

void enr_on_receive(enr_recv_cb_t cb, void *ctx) { s_rx_ctx = ctx; s_rx_cb = cb; }
void enr_on_event(enr_event_cb_t cb, void *ctx) { s_ev_ctx = ctx; s_ev_cb = cb; }
void enr_self_mac(uint8_t mac[6]) { esp_read_mac(mac, ESP_MAC_WIFI_STA); }

/* ------------------------------------------------------------------ transport */

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
static void on_recv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    const uint8_t *src = info->src_addr;
#else
static void on_recv(const uint8_t *src, const uint8_t *data, int len) {
#endif
    if (!s_rxq || len < HDR_LEN || len > ENR_MAX_FRAME) return;
    rxm_t m;
    memcpy(m.src, src, 6);
    m.len = len;
    memcpy(m.data, data, len);
    xQueueSend(s_rxq, &m, 0); /* drop if full */
}

static int net_send(const uint8_t dst[6], const uint8_t *buf, int len) {
    if (!esp_now_is_peer_exist(dst)) {
        esp_now_peer_info_t p;
        memset(&p, 0, sizeof p);
        memcpy(p.peer_addr, dst, 6);
        p.channel = 0;          /* current channel */
        p.ifidx = WIFI_IF_STA;
        p.encrypt = false;      /* all protection is at the ENR layer */
        if (esp_now_add_peer(&p) != ESP_OK) return -1;
    }
    return esp_now_send(dst, buf, len) == ESP_OK ? 0 : -1;
}

static esp_err_t net_init(void) {
    esp_err_t e;
    wifi_mode_t mode = WIFI_MODE_NULL;
    if (esp_wifi_get_mode(&mode) == ESP_ERR_WIFI_NOT_INIT) {
        e = nvs_flash_init();
        if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            nvs_flash_erase();
            nvs_flash_init();
        }
        e = esp_netif_init();
        if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return e;
        e = esp_event_loop_create_default();
        if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return e;
        wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
        if ((e = esp_wifi_init(&wc)) != ESP_OK) return e;
        esp_wifi_set_storage(WIFI_STORAGE_RAM);
        mode = WIFI_MODE_NULL;
    }
    if (mode == WIFI_MODE_NULL && (e = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return e;
    e = esp_wifi_start();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) return e;
    esp_wifi_set_ps(WIFI_PS_NONE);
    if (C.channel && esp_wifi_set_channel(C.channel, WIFI_SECOND_CHAN_NONE) != ESP_OK)
        ESP_LOGW(TAG, "could not set channel %u (STA connected to an AP?)", C.channel);
    e = esp_now_init();
    if (e != ESP_OK) return e;
    if ((e = esp_now_register_recv_cb(on_recv)) != ESP_OK) return e;
    esp_read_mac(SELF, ESP_MAC_WIFI_STA);
    s_rxq = xQueueCreate(16, sizeof(rxm_t));
    s_txq = xQueueCreate(8, sizeof(txm_t));
    return (s_rxq && s_txq) ? ESP_OK : ESP_ERR_NO_MEM;
}

static esp_err_t check_cfg(const enr_config_t *cfg) {
    enr_config_t d = ENR_CONFIG_DEFAULT();
    C = cfg ? *cfg : d;
    if (C.t_epoch_ms < 1000 || C.m < 1 || C.keepalive_ms < 500) return ESP_ERR_INVALID_ARG;
    /* T_refresh below the DH rate limit makes every refresh fail (see the paper, E9). */
    if (T_REFRESH_US < MS(ENR_T_RL_MS) * 2) return ESP_ERR_INVALID_ARG;
    return ESP_OK;
}

esp_err_t enr_send(const uint8_t *peer, const void *data, size_t len) {
    if (ROLE == R_NONE) return ESP_ERR_INVALID_STATE;
    if (len > ENR_MAX_PAYLOAD || (len && !data)) return ESP_ERR_INVALID_SIZE;
    if (!enr_is_established(peer)) return ESP_ERR_INVALID_STATE;
    txm_t t;
    memset(t.peer, 0, 6);
    if (peer) memcpy(t.peer, peer, 6);
    t.len = (uint8_t)len;
    if (len) memcpy(t.data, data, len);
    return xQueueSend(s_txq, &t, 0) == pdTRUE ? ESP_OK : ESP_ERR_NO_MEM;
}

static void deliver(const uint8_t peer[6], const uint8_t *pt, int n) {
    if (s_rx_cb) s_rx_cb(peer, pt + 1, (size_t)(n - 1), s_rx_ctx);
}

/* ================================================================== controller */

typedef struct {
    volatile bool used;
    uint8_t mac[6];
    uint8_t kauth[32];
    /* current session */
    volatile bool est;
    uint8_t r, rk[32];
    enr_chain_t tx, rx, old_rx;
    int64_t old_expire;
    /* pending generation (after HS2, before HS3) */
    bool pend;
    uint8_t p_r, p_rk[32], p_kconf[16], p_th[32];
    enr_chain_t p_tx, p_rx;
    int64_t p_expire;
    bool p_is_refresh;
    /* handshake caches */
    bool hs2_valid;
    uint8_t last_nn[16], last_pkn[32], hs2[LEN_HS2];
    uint8_t used_nn[4][16]; /* recent bootstrap n_N values: blocks replay of older HS1s */
    uint8_t used_nn_n, used_nn_i;
    int64_t last_dh;
    /* DH worker job / output */
    volatile bool dh_busy;
    uint8_t j_nc[16], j_nn[16], j_pkn[32], j_rk_prev[32], j_rp;
    bool j_refresh;
    int w_rc;
    uint8_t w_pkc[32], w_th[32], w_rk[32], w_ck_c2n[32], w_ck_n2c[32], w_kconf[16];
    /* refresh scheduling */
    bool ref_out;
    uint8_t ref_nc[16];
    int64_t ref_sent, next_refresh, last_commit;
    int ref_tries;
    bool degraded;
} csess_t;

static csess_t S[ENR_MAX_NODES];
static uint8_t K_COOKIE[32];
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

esp_err_t enr_controller_add_node(const uint8_t mac[6], const uint8_t kauth[32]) {
    if (!mac || !kauth) return ESP_ERR_INVALID_ARG;
    for (int i = 0; i < ENR_MAX_NODES; i++)
        if (S[i].used && memcmp(S[i].mac, mac, 6) == 0) return ESP_ERR_INVALID_STATE;
    for (int i = 0; i < ENR_MAX_NODES; i++) {
        if (S[i].used) continue;
        csess_t *s = &S[i];
        taskENTER_CRITICAL(&s_mux);
        memset(s, 0, sizeof *s);
        memcpy(s->mac, mac, 6);
        memcpy(s->kauth, kauth, 32);
        s->used = true;
        taskEXIT_CRITICAL(&s_mux);
        return ESP_OK;
    }
    return ESP_ERR_NO_MEM;
}

static csess_t *sess_find(const uint8_t mac[6]) {
    for (int i = 0; i < ENR_MAX_NODES; i++)
        if (S[i].used && memcmp(S[i].mac, mac, 6) == 0) return &S[i];
    return NULL;
}

static uint32_t cur_slot(int64_t now) { return (uint32_t)(now / MS(ENR_T_SLOT_MS)); }

static void send_refresh_req(csess_t *s, int64_t now) {
    uint8_t pt[17], f[ENR_MAX_FRAME];
    pt[0] = P_REFRESH;
    memcpy(pt + 1, s->ref_nc, 16);
    int n = frame_seal(&s->tx, T_REFRESH, pt, sizeof pt, f);
    if (n > 0) net_send(s->mac, f, n);
    s->ref_sent = now;
    s->ref_tries++;
}

static void commit_pending(csess_t *s, int64_t now) {
    bool was_est = s->est;
    if (s->est) {
        chain_move(&s->old_rx, &s->rx);
        s->old_expire = now + MS(ENR_T_GRACE_MS);
        chain_wipe(&s->tx);
    }
    chain_move(&s->tx, &s->p_tx);
    chain_move(&s->rx, &s->p_rx);
    memcpy(s->rk, s->p_rk, 32);
    s->r = s->p_r;
    enr_zero(s->p_rk, 32);
    enr_zero(s->p_kconf, 16);
    enr_zero(s->p_th, 32);
    s->pend = false;
    s->est = true;
    bool refresh = s->p_is_refresh;
    if (refresh) s->ref_out = false;
    s->last_commit = now;
    /* Spread refreshes: slot k of ENR_MAX_NODES gets phase k/ENR_MAX_NODES of T_refresh. */
    int64_t T = T_REFRESH_US, phase = T * (int64_t)(s - S) / ENR_MAX_NODES;
    int64_t base = now + T / 2 - phase;
    s->next_refresh = (base / T + 1) * T + phase;
    s->degraded = false;
    ESP_LOGI(TAG, "C: " MACSTR " %s r=%u", MAC2STR(s->mac), refresh ? "refreshed" : "established", s->r);
    emit(s->mac, (refresh && was_est) ? ENR_EV_REFRESHED : ENR_EV_ESTABLISHED);
}

static void c_on_hello(csess_t *s, int64_t now) {
    uint8_t f[LEN_CHAL];
    enr_hdr_t h = {.type = T_CHAL};
    hdr_put(f, &h);
    cookie_for(K_COOKIE, s->mac, cur_slot(now), f + HDR_LEN);
    net_send(s->mac, f, sizeof f);
}

static void c_on_hs1(csess_t *s, const enr_hdr_t *h, const uint8_t *f, int64_t now) {
    const uint8_t *nc = f + 8, *nn = f + 24, *pkn = f + 40, *tag = f + 72;
    uint8_t rp = h->r, exp[16];

    /* 1. authenticate (cheap HMAC) before anything else */
    hs_tag_n(s->kauth, SELF, s->mac, rp, nc, nn, pkn, exp);
    if (!enr_ct_eq(exp, tag, 16)) { ESP_LOGD(TAG, "hs1 bad tag"); return; }
    if (s->dh_busy) return; /* DH in progress: drop retransmits until HS2 is out */

    /* 2. retransmitted HS1 -> resend cached HS2, no DH */
    if (s->hs2_valid && enr_ct_eq(nn, s->last_nn, 16) && enr_ct_eq(pkn, s->last_pkn, 32)) {
        net_send(s->mac, s->hs2, LEN_HS2);
        return;
    }

    /* 3. freshness of n_C: in-session refresh nonce, or unused stateless cookie */
    bool is_refresh = s->est && s->ref_out && enr_ct_eq(nc, s->ref_nc, 16) && rp == (uint8_t)(s->r + 1);
    if (!is_refresh) {
        uint8_t c0[16], c1[16];
        uint32_t sl = cur_slot(now);
        cookie_for(K_COOKIE, s->mac, sl, c0);
        cookie_for(K_COOKIE, s->mac, sl - 1, c1);
        bool ok = rp == 0 && (enr_ct_eq(nc, c0, 16) || enr_ct_eq(nc, c1, 16));
        for (int k = 0; ok && k < s->used_nn_n; k++)
            if (enr_ct_eq(nn, s->used_nn[k], 16)) ok = false;
        if (!ok) { ESP_LOGD(TAG, "hs1 stale"); return; }
    }

    /* 4. DH rate limit */
    if (s->last_dh && now - s->last_dh < MS(ENR_T_RL_MS)) { ESP_LOGD(TAG, "hs1 rate-limited"); return; }

    /* 5. hand the key share to the DH worker; the data path keeps running */
    memcpy(s->j_nc, nc, 16);
    memcpy(s->j_nn, nn, 16);
    memcpy(s->j_pkn, pkn, 32);
    if (is_refresh) memcpy(s->j_rk_prev, s->rk, 32); else memset(s->j_rk_prev, 0, 32);
    s->j_rp = rp;
    s->j_refresh = is_refresh;
    s->dh_busy = true;
    s->last_dh = now;
    if (!is_refresh) {
        memcpy(s->used_nn[s->used_nn_i], nn, 16);
        s->used_nn_i = (s->used_nn_i + 1) % 4;
        if (s->used_nn_n < 4) s->used_nn_n++;
    }
    int idx = (int)(s - S);
    if (xQueueSend(s_jobq, &idx, 0) != pdTRUE) {
        s->dh_busy = false;
        enr_zero(s->j_rk_prev, 32);
    }
}

static void c_worker(void *arg) {
    (void)arg;
    int idx;
    for (;;) {
        if (xQueueReceive(s_jobq, &idx, portMAX_DELAY) != pdTRUE) continue;
        csess_t *s = &S[idx];
        uint8_t skc[32], z[32];
        int rc = enr_x25519_keygen(skc, s->w_pkc);
        if (!rc) rc = enr_x25519(z, skc, s->j_pkn);
        enr_zero(skc, 32);
        if (!rc) {
            hs_th(SELF, s->mac, s->j_rp, s->j_nc, s->j_nn, s->j_pkn, s->w_pkc, s->w_th);
            hs_derive(s->j_rk_prev, z, s->w_th, s->w_rk, s->w_ck_c2n, s->w_ck_n2c, s->w_kconf);
        }
        enr_zero(z, 32);
        enr_zero(s->j_rk_prev, 32);
        s->w_rc = rc;
        xQueueSend(s_resq, &idx, portMAX_DELAY);
    }
}

static void c_wipe_worker_out(csess_t *s) {
    enr_zero(s->w_rk, 32); enr_zero(s->w_ck_c2n, 32); enr_zero(s->w_ck_n2c, 32);
    enr_zero(s->w_kconf, 16); enr_zero(s->w_th, 32);
}

static void c_on_dh_result(csess_t *s, int64_t now) {
    s->dh_busy = false;
    bool still_valid = s->j_refresh ? (s->est && s->ref_out && s->j_rp == (uint8_t)(s->r + 1)) : (s->j_rp == 0);
    if (s->w_rc || !still_valid) { c_wipe_worker_out(s); return; }
    if (s->pend) { chain_wipe(&s->p_tx); chain_wipe(&s->p_rx); }
    chain_init(&s->p_tx, s->w_ck_c2n, s->j_rp, SELF, s->mac, now);
    chain_init(&s->p_rx, s->w_ck_n2c, s->j_rp, s->mac, SELF, now);
    memcpy(s->p_rk, s->w_rk, 32);
    memcpy(s->p_kconf, s->w_kconf, 16);
    memcpy(s->p_th, s->w_th, 32);
    s->p_r = s->j_rp;
    s->pend = true;
    s->p_is_refresh = s->j_refresh;
    s->p_expire = now + hs_window_us() * 2;

    enr_hdr_t hh = {.type = T_HS2, .r = s->j_rp};
    hdr_put(s->hs2, &hh);
    memcpy(s->hs2 + 8, s->w_pkc, 32);
    hs_tag_c(s->kauth, s->w_th, s->hs2 + 40);
    hs_conf(s->p_kconf, 'C', s->w_th, s->hs2 + 56);
    memcpy(s->last_nn, s->j_nn, 16);
    memcpy(s->last_pkn, s->j_pkn, 32);
    s->hs2_valid = true;
    c_wipe_worker_out(s);
    net_send(s->mac, s->hs2, LEN_HS2);
}

static void c_on_hs3(csess_t *s, const enr_hdr_t *h, const uint8_t *f, int64_t now) {
    if (!s->pend || h->r != s->p_r) return;
    uint8_t exp[8];
    hs_conf(s->p_kconf, 'N', s->p_th, exp);
    if (!enr_ct_eq(exp, f + 8, 8)) return;
    commit_pending(s, now);
}

static void c_on_data(csess_t *s, const enr_hdr_t *h, const uint8_t *f, int len, int64_t now) {
    uint8_t pt[ENR_MAX_FRAME];
    int why = OPEN_BAD, n = -1;
    if (s->est && h->r == s->r) {
        n = frame_open(&s->rx, f, len, pt, now, &why);
    } else if (s->pend && h->r == s->p_r) {
        n = frame_open(&s->p_rx, f, len, pt, now, &why);
        if (n >= 0) commit_pending(s, now); /* implicit HS3: first frame under the new keys */
    } else if (s->old_rx.valid && h->r == s->old_rx.r) {
        n = frame_open(&s->old_rx, f, len, pt, now, &why);
    }
    if (n < 1) { if (n < 0) ESP_LOGD(TAG, "rx reject %d", why); return; }
    if (pt[0] == P_APP) {
        deliver(s->mac, pt, n);
    } else if (pt[0] == P_KA && s->est) {
        uint8_t a = P_KA_ACK, out[ENR_MAX_FRAME];
        int m = frame_seal(&s->tx, T_DATA, &a, 1, out);
        if (m > 0) net_send(s->mac, out, m);
    }
}

static void c_tick(int64_t now) {
    for (int i = 0; i < ENR_MAX_NODES; i++) {
        csess_t *s = &S[i];
        if (!s->used) continue;
        if (s->old_rx.valid && now >= s->old_expire) chain_wipe(&s->old_rx);
        if (s->pend && now >= s->p_expire) {
            chain_wipe(&s->p_tx); chain_wipe(&s->p_rx);
            enr_zero(s->p_rk, 32); enr_zero(s->p_kconf, 16); enr_zero(s->p_th, 32);
            s->pend = false;
        }
        if (!s->est) continue;

        /* epoch ratchet: sender advances on time (or sequence exhaustion), receiver is forced along */
        if (now - s->tx.t_epoch_start >= MS(C.t_epoch_ms) || s->tx.seq >= 0x80000000u) chain_advance(&s->tx, now, false);
        if (now - s->rx.t_epoch_start >= MS(C.t_epoch_ms + ENR_T_GRACE_MS)) chain_advance(&s->rx, now, true);
        chain_expire(&s->rx, now);
        if (s->tx.e >= 0xffff - ENR_W_E) s->next_refresh = now; /* epoch space exhausted */

        /* scheduled refresh with retries */
        if (!s->ref_out && now >= s->next_refresh) {
            enr_rand(s->ref_nc, 16);
            s->ref_out = true;
            s->ref_tries = 0;
            send_refresh_req(s, now);
        } else if (s->ref_out && !s->pend && !s->dh_busy && now - s->ref_sent >= retx_us(s->ref_tries)) {
            if (s->ref_tries < ENR_R_MAX) {
                send_refresh_req(s, now);
            } else {
                s->ref_out = false;
                s->next_refresh = now + MS(ENR_T_SLOT_MS);
                emit(s->mac, ENR_EV_REFRESH_FAILED);
            }
        }
        if (!s->degraded && now - s->last_commit > 2 * T_REFRESH_US) {
            s->degraded = true;
            ESP_LOGW(TAG, "C: " MACSTR " DEGRADED", MAC2STR(s->mac));
            emit(s->mac, ENR_EV_DEGRADED);
        }
    }
}

static void c_send_app(const txm_t *t) {
    csess_t *s = sess_find(t->peer);
    if (!s || !s->est) return;
    uint8_t pt[ENR_MAX_PT], f[ENR_MAX_FRAME];
    pt[0] = P_APP;
    memcpy(pt + 1, t->data, t->len);
    int n = frame_seal(&s->tx, T_DATA, pt, 1 + t->len, f);
    if (n > 0) net_send(s->mac, f, n);
}

static void ctrl_task(void *arg) {
    (void)arg;
    rxm_t m;
    txm_t t;
    for (;;) {
        int idx;
        while (xQueueReceive(s_resq, &idx, 0) == pdTRUE) c_on_dh_result(&S[idx], enr_now_us());
        if (xQueueReceive(s_rxq, &m, pdMS_TO_TICKS(2)) == pdTRUE) {
            int64_t now = enr_now_us();
            enr_hdr_t h;
            csess_t *s = sess_find(m.src); /* only provisioned nodes have a K_auth */
            if (s && hdr_get(m.data, m.len, &h)) {
                switch (h.type) {
                case T_HELLO: if (m.len == LEN_HELLO) c_on_hello(s, now); break;
                case T_HS1: if (m.len == LEN_HS1) c_on_hs1(s, &h, m.data, now); break;
                case T_HS3: if (m.len == LEN_HS3) c_on_hs3(s, &h, m.data, now); break;
                case T_DATA: c_on_data(s, &h, m.data, m.len, now); break;
                default: break;
                }
            }
        }
        while (xQueueReceive(s_txq, &t, 0) == pdTRUE) c_send_app(&t);
        c_tick(enr_now_us());
    }
}

esp_err_t enr_controller_begin(const enr_config_t *cfg) {
    if (ROLE != R_NONE) return ESP_ERR_INVALID_STATE;
    esp_err_t e = check_cfg(cfg);
    if (e != ESP_OK) return e;
    if ((e = net_init()) != ESP_OK) return e;
    enr_rand(K_COOKIE, sizeof K_COOKIE);
    s_jobq = xQueueCreate(ENR_MAX_NODES, sizeof(int));
    s_resq = xQueueCreate(ENR_MAX_NODES, sizeof(int));
    if (!s_jobq || !s_resq) return ESP_ERR_NO_MEM;
    ROLE = R_CTRL;
    if (xTaskCreatePinnedToCore(c_worker, "enr_dh", 8192, NULL, 3, NULL, 0) != pdPASS ||
        xTaskCreatePinnedToCore(ctrl_task, "enr", 8192, NULL, 5, NULL, PROTO_CORE) != pdPASS) {
        ROLE = R_NONE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "controller " MACSTR ", T_epoch %lu ms, M %u", MAC2STR(SELF), (unsigned long)C.t_epoch_ms, C.m);
    return ESP_OK;
}

/* ================================================================== node */

typedef enum { N_INIT, N_WAIT_CHAL, N_EST } nstate_t;
enum { JOB_KEYGEN = 1, JOB_DH = 2 };

static struct {
    nstate_t st;
    uint8_t ctrl[6], kauth[32];
    volatile bool est;
    uint8_t r, rk[32];
    enr_chain_t tx, rx, old_rx;
    int64_t old_expire, last_valid_rx, last_ka, next_hello;
    /* in-flight handshake */
    bool in_hs, hs1_ready;
    uint8_t hs_r, sk[32], pkn[32], nn[16], nc[16], hs1[LEN_HS1];
    int hs_tries;
    int64_t hs_sent;
    /* duplicate-HS2 handling */
    uint8_t last_pkc[32], hs3[LEN_HS3];
    bool hs3_valid;
    /* worker interface (owned by the worker while the matching *_busy flag is set) */
    volatile bool kg_busy, dh_busy;
    uint8_t j_pkc[32], j_th[32], j_rk_prev[32];
    int w_rc;
    uint8_t w_rk[32], w_ck_c2n[32], w_ck_n2c[32], w_kconf[16];
} N;

static void n_worker(void *arg) {
    (void)arg;
    int job;
    for (;;) {
        if (xQueueReceive(s_jobq, &job, portMAX_DELAY) != pdTRUE) continue;
        if (job == JOB_KEYGEN) {
            N.w_rc = enr_x25519_keygen(N.sk, N.pkn);
        } else {
            uint8_t z[32];
            N.w_rc = enr_x25519(z, N.sk, N.j_pkc);
            if (!N.w_rc) hs_derive(N.j_rk_prev, z, N.j_th, N.w_rk, N.w_ck_c2n, N.w_ck_n2c, N.w_kconf);
            enr_zero(z, 32);
            enr_zero(N.j_rk_prev, 32);
        }
        xQueueSend(s_resq, &job, portMAX_DELAY);
    }
}

static void n_wipe_worker_out(void) {
    enr_zero(N.w_rk, 32); enr_zero(N.w_ck_c2n, 32); enr_zero(N.w_ck_n2c, 32);
    enr_zero(N.w_kconf, 16); enr_zero(N.j_th, 32);
}

static void n_abort_hs(void) {
    N.in_hs = false;
    N.hs1_ready = false;
    if (!N.kg_busy && !N.dh_busy) enr_zero(N.sk, 32); /* else wiped when the job returns */
}

static void n_reset_session(void) {
    chain_wipe(&N.tx); chain_wipe(&N.rx); chain_wipe(&N.old_rx);
    enr_zero(N.rk, 32);
    n_abort_hs();
    N.est = false;
    N.hs3_valid = false;
    N.st = N_INIT;
}

static void n_post(int job) {
    if (job == JOB_KEYGEN) N.kg_busy = true; else N.dh_busy = true;
    if (xQueueSend(s_jobq, &job, 0) != pdTRUE) {
        if (job == JOB_KEYGEN) N.kg_busy = false; else N.dh_busy = false;
    }
}

static void n_start_hs(uint8_t rp, const uint8_t nc[16]) {
    if (N.kg_busy || N.dh_busy) return; /* worker owns N.sk; the peer will retransmit */
    memcpy(N.nc, nc, 16);
    N.hs_r = rp;
    N.in_hs = true;
    N.hs1_ready = false;
    N.hs_tries = 0;
    n_post(JOB_KEYGEN);
}

static void n_on_keygen_done(int64_t now) {
    N.kg_busy = false;
    if (!N.in_hs || N.w_rc) { enr_zero(N.sk, 32); return; }
    enr_rand(N.nn, 16);
    enr_hdr_t h = {.type = T_HS1, .r = N.hs_r};
    hdr_put(N.hs1, &h);
    memcpy(N.hs1 + 8, N.nc, 16);
    memcpy(N.hs1 + 24, N.nn, 16);
    memcpy(N.hs1 + 40, N.pkn, 32);
    hs_tag_n(N.kauth, N.ctrl, SELF, N.hs_r, N.nc, N.nn, N.pkn, N.hs1 + 72);
    net_send(N.ctrl, N.hs1, LEN_HS1);
    N.hs1_ready = true;
    N.hs_tries = 1;
    N.hs_sent = now;
}

static void n_on_hs2(const enr_hdr_t *h, const uint8_t *f) {
    const uint8_t *pkc = f + 8, *tagc = f + 40;
    if (!N.in_hs) {
        /* duplicate HS2 for the generation we already committed: our HS3 was lost */
        if (N.est && h->r == N.r && N.hs3_valid && enr_ct_eq(pkc, N.last_pkc, 32)) net_send(N.ctrl, N.hs3, LEN_HS3);
        return;
    }
    if (h->r != N.hs_r || !N.hs1_ready || N.dh_busy) return;
    uint8_t th[32], tag[16];
    hs_th(N.ctrl, SELF, N.hs_r, N.nc, N.nn, N.pkn, pkc, th);
    hs_tag_c(N.kauth, th, tag);
    if (!enr_ct_eq(tag, tagc, 16)) { enr_zero(th, 32); return; }
    static const uint8_t zero32[32] = {0};
    memcpy(N.j_pkc, pkc, 32);
    memcpy(N.j_th, th, 32);
    memcpy(N.j_rk_prev, (N.est && N.hs_r == (uint8_t)(N.r + 1)) ? N.rk : zero32, 32);
    memcpy(N.hs3 + 8, f + 56, 8); /* stash conf_C until the DH result arrives */
    enr_zero(th, 32);
    n_post(JOB_DH);
}

static void n_on_dh_done(int64_t now) {
    N.dh_busy = false;
    if (!N.in_hs || N.w_rc) { enr_zero(N.sk, 32); n_wipe_worker_out(); return; }
    uint8_t conf[8];
    hs_conf(N.w_kconf, 'C', N.j_th, conf);
    if (!enr_ct_eq(conf, N.hs3 + 8, 8)) { n_wipe_worker_out(); return; }
    bool is_refresh = N.est;
    enr_hdr_t hh = {.type = T_HS3, .r = N.hs_r};
    hdr_put(N.hs3, &hh);
    hs_conf(N.w_kconf, 'N', N.j_th, N.hs3 + 8);
    N.hs3_valid = true;
    net_send(N.ctrl, N.hs3, LEN_HS3);

    /* commit (make-before-break: old receive keys kept for T_grace) */
    if (N.est) {
        chain_move(&N.old_rx, &N.rx);
        N.old_expire = now + MS(ENR_T_GRACE_MS);
        chain_wipe(&N.tx);
    }
    chain_init(&N.tx, N.w_ck_n2c, N.hs_r, SELF, N.ctrl, now);
    chain_init(&N.rx, N.w_ck_c2n, N.hs_r, N.ctrl, SELF, now);
    memcpy(N.rk, N.w_rk, 32);
    N.r = N.hs_r;
    memcpy(N.last_pkc, N.j_pkc, 32);
    n_wipe_worker_out();
    enr_zero(N.sk, 32);
    N.in_hs = false;
    N.hs1_ready = false;
    N.est = true;
    N.st = N_EST;
    N.last_valid_rx = N.last_ka = now;
    ESP_LOGI(TAG, "N: %s r=%u", is_refresh ? "refreshed" : "established", N.r);
    emit(N.ctrl, is_refresh ? ENR_EV_REFRESHED : ENR_EV_ESTABLISHED);
}

static void n_on_aead(const enr_hdr_t *h, const uint8_t *f, int len, int64_t now) {
    uint8_t pt[ENR_MAX_FRAME];
    int why = OPEN_EPOCH, n = -1;
    if (N.est && h->r == N.r) n = frame_open(&N.rx, f, len, pt, now, &why);
    else if (N.old_rx.valid && h->r == N.old_rx.r) n = frame_open(&N.old_rx, f, len, pt, now, &why);
    if (n < 1) { if (n < 0) ESP_LOGD(TAG, "rx reject %d", why); return; }
    N.last_valid_rx = now;
    if (h->type == T_REFRESH && n == 17 && pt[0] == P_REFRESH) {
        if (N.in_hs && enr_ct_eq(pt + 1, N.nc, 16)) return; /* already working on it */
        if (N.in_hs) n_abort_hs();
        n_start_hs((uint8_t)(N.r + 1), pt + 1);
    } else if (h->type == T_DATA && pt[0] == P_APP) {
        deliver(N.ctrl, pt, n);
    }
}

static void n_tick(int64_t now) {
    if (N.st != N_EST && !N.in_hs && now >= N.next_hello) {
        uint8_t f[LEN_HELLO];
        enr_hdr_t h = {.type = T_HELLO};
        hdr_put(f, &h);
        net_send(N.ctrl, f, sizeof f);
        N.st = N_WAIT_CHAL;
        N.next_hello = now + MS(1000);
    }
    if (N.in_hs && N.hs1_ready && !N.dh_busy && now - N.hs_sent >= retx_us(N.hs_tries)) {
        if (N.hs_tries < ENR_R_MAX) {
            net_send(N.ctrl, N.hs1, LEN_HS1);
            N.hs_tries++;
            N.hs_sent = now;
        } else {
            n_abort_hs();
            if (!N.est) N.st = N_INIT;
        }
    }
    if (N.old_rx.valid && now >= N.old_expire) chain_wipe(&N.old_rx);
    if (!N.est) return;

    if (now - N.tx.t_epoch_start >= MS(C.t_epoch_ms) || N.tx.seq >= 0x80000000u) chain_advance(&N.tx, now, false);
    if (now - N.rx.t_epoch_start >= MS(C.t_epoch_ms + ENR_T_GRACE_MS)) chain_advance(&N.rx, now, true);
    chain_expire(&N.rx, now);

    /* liveness: probe after keepalive_ms of silence, re-bootstrap after 3x */
    if (now - N.last_valid_rx > MS(C.keepalive_ms) && now - N.last_ka > MS(C.keepalive_ms)) {
        uint8_t k = P_KA, f[ENR_MAX_FRAME];
        int n = frame_seal(&N.tx, T_DATA, &k, 1, f);
        if (n > 0) net_send(N.ctrl, f, n);
        N.last_ka = now;
    }
    if (now - N.last_valid_rx > 3 * MS(C.keepalive_ms)) {
        ESP_LOGW(TAG, "N: controller lost, re-handshaking");
        n_reset_session();
        emit(N.ctrl, ENR_EV_LOST);
    }
}

static void n_send_app(const txm_t *t) {
    if (!N.est) return;
    uint8_t pt[ENR_MAX_PT], f[ENR_MAX_FRAME];
    pt[0] = P_APP;
    memcpy(pt + 1, t->data, t->len);
    int n = frame_seal(&N.tx, T_DATA, pt, 1 + t->len, f);
    if (n > 0) net_send(N.ctrl, f, n);
}

static void node_task(void *arg) {
    (void)arg;
    rxm_t m;
    txm_t t;
    for (;;) {
        int job;
        while (xQueueReceive(s_resq, &job, 0) == pdTRUE) {
            if (job == JOB_KEYGEN) n_on_keygen_done(enr_now_us());
            else n_on_dh_done(enr_now_us());
        }
        if (xQueueReceive(s_rxq, &m, pdMS_TO_TICKS(2)) == pdTRUE && memcmp(m.src, N.ctrl, 6) == 0) {
            int64_t now = enr_now_us();
            enr_hdr_t h;
            if (hdr_get(m.data, m.len, &h)) {
                switch (h.type) {
                case T_CHAL:
                    if (m.len == LEN_CHAL && N.st == N_WAIT_CHAL && !N.in_hs) n_start_hs(0, m.data + 8);
                    break;
                case T_HS2: if (m.len == LEN_HS2) n_on_hs2(&h, m.data); break;
                case T_DATA:
                case T_REFRESH: n_on_aead(&h, m.data, m.len, now); break;
                default: break;
                }
            }
        }
        while (xQueueReceive(s_txq, &t, 0) == pdTRUE) n_send_app(&t);
        n_tick(enr_now_us());
    }
}

esp_err_t enr_node_begin(const enr_config_t *cfg, const uint8_t ctrl_mac[6], const uint8_t kauth[32]) {
    if (ROLE != R_NONE) return ESP_ERR_INVALID_STATE;
    if (!ctrl_mac || !kauth) return ESP_ERR_INVALID_ARG;
    esp_err_t e = check_cfg(cfg);
    if (e != ESP_OK) return e;
    if ((e = net_init()) != ESP_OK) return e;
    memset(&N, 0, sizeof N);
    memcpy(N.ctrl, ctrl_mac, 6);
    memcpy(N.kauth, kauth, 32);
    n_reset_session();
    s_jobq = xQueueCreate(2, sizeof(int));
    s_resq = xQueueCreate(2, sizeof(int));
    if (!s_jobq || !s_resq) return ESP_ERR_NO_MEM;
    ROLE = R_NODE;
    if (xTaskCreatePinnedToCore(n_worker, "enr_dh", 8192, NULL, 3, NULL, 0) != pdPASS ||
        xTaskCreatePinnedToCore(node_task, "enr", 8192, NULL, 5, NULL, PROTO_CORE) != pdPASS) {
        ROLE = R_NONE;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "node " MACSTR " -> controller " MACSTR, MAC2STR(SELF), MAC2STR(N.ctrl));
    return ESP_OK;
}

bool enr_is_established(const uint8_t *peer) {
    if (ROLE == R_NODE) return N.est;
    if (ROLE == R_CTRL && peer) { csess_t *s = sess_find(peer); return s && s->est; }
    return false;
}
