#include "enr_proto.h"
#include "enr.h"

#include <string.h>

static void be16(uint8_t *b, uint16_t v) { b[0] = v >> 8; b[1] = v; }
static void be32(uint8_t *b, uint32_t v) { b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v; }
static uint16_t rd16(const uint8_t *b) { return (uint16_t)(b[0] << 8 | b[1]); }
static uint32_t rd32(const uint8_t *b) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

void hdr_put(uint8_t *b, const enr_hdr_t *h) {
    b[0] = (ENR_VER << 4) | (h->type & 0x0f);
    b[1] = h->r;
    be16(b + 2, h->e);
    be32(b + 4, h->seq);
}

bool hdr_get(const uint8_t *b, size_t len, enr_hdr_t *h) {
    if (len < HDR_LEN || (b[0] >> 4) != ENR_VER) return false;
    h->type = b[0] & 0x0f;
    h->r = b[1];
    h->e = rd16(b + 2);
    h->seq = rd32(b + 4);
    return true;
}

/* ---------- epoch ratchet (spec §8) ---------- */

static void derive_step(const uint8_t ck[32], uint8_t r, uint16_t e, const uint8_t src[6],
                        const uint8_t dst[6], uint8_t mk[16], uint8_t ck_next[32]) {
    uint8_t e_be[2], e1_be[2];
    be16(e_be, e);
    be16(e1_be, (uint16_t)(e + 1));
    enr_buf_t imk[] = {EL("ENR1 mk"), EB(src, 6), EB(dst, 6), EB(&r, 1), EB(e_be, 2)};
    enr_hkdf_expand(ck, imk, 5, mk, 16);
    enr_buf_t ick[] = {EL("ENR1 ck"), EB(&r, 1), EB(e1_be, 2)};
    enr_hkdf_expand(ck, ick, 3, ck_next, 32);
}

void chain_wipe(enr_chain_t *c) { enr_zero(c, sizeof *c); }

void chain_move(enr_chain_t *dst, enr_chain_t *src) {
    chain_wipe(dst);
    memcpy(dst, src, sizeof *dst);
    chain_wipe(src);
}

void chain_init(enr_chain_t *c, const uint8_t ck0[32], uint8_t r, const uint8_t src[6],
                const uint8_t dst[6], int64_t now) {
    chain_wipe(c);
    c->valid = true;
    c->r = r;
    c->e = 0;
    c->seq = 0;
    memcpy(c->src, src, 6);
    memcpy(c->dst, dst, 6);
    derive_step(ck0, r, 0, src, dst, c->mk, c->ck_next);
    c->t_epoch_start = now;
}

void chain_advance(enr_chain_t *c, int64_t now, bool keep_prev) {
    uint8_t mk[16], ckn[32];
    derive_step(c->ck_next, c->r, (uint16_t)(c->e + 1), c->src, c->dst, mk, ckn);
    if (keep_prev) {
        memcpy(c->mk_prev, c->mk, 16);
        c->has_prev = true;
        c->prev_expire = now + MS(ENR_T_GRACE_MS);
        c->win_any_prev = c->win_any;
        c->win_max_prev = c->win_max;
        c->win_bits_prev = c->win_bits;
    }
    memcpy(c->mk, mk, 16);
    memcpy(c->ck_next, ckn, 32);
    c->e++;
    c->seq = 0;
    c->win_any = false;
    c->win_max = 0;
    c->win_bits = 0;
    c->t_epoch_start = now;
    enr_zero(mk, sizeof mk);
    enr_zero(ckn, sizeof ckn);
}

void chain_expire(enr_chain_t *c, int64_t now) {
    if (c->has_prev && now >= c->prev_expire) {
        enr_zero(c->mk_prev, 16);
        c->has_prev = false;
        c->win_any_prev = false;
    }
}

/* ---------- AEAD frames (spec §9) ---------- */

static void build_nonce(uint8_t n[13], const uint8_t src[6], uint8_t r, uint16_t e, uint32_t seq) {
    memcpy(n, src, 6);
    n[6] = r;
    be16(n + 7, e);
    be32(n + 9, seq);
}

static void build_aad(uint8_t aad[20], const uint8_t *hdr, const uint8_t src[6], const uint8_t dst[6]) {
    memcpy(aad, hdr, HDR_LEN);
    memcpy(aad + 8, src, 6);
    memcpy(aad + 14, dst, 6);
}

int frame_seal(enr_chain_t *tx, uint8_t type, const uint8_t *pt, size_t pl, uint8_t *out) {
    if (!tx->valid || pl > ENR_MAX_PT) return -1;
    enr_hdr_t h = {.type = type, .r = tx->r, .e = tx->e, .seq = tx->seq};
    hdr_put(out, &h);
    uint8_t nonce[13], aad[20];
    build_nonce(nonce, tx->src, tx->r, tx->e, tx->seq);
    build_aad(aad, out, tx->src, tx->dst);
    if (enr_ccm_seal(tx->mk, nonce, aad, sizeof aad, pt, pl, out + HDR_LEN, out + HDR_LEN + pl)) return -1;
    tx->seq++;
    return (int)(HDR_LEN + pl + ENR_TAG_LEN);
}

static bool win_ok(bool any, uint32_t max, uint64_t bits, uint32_t s) {
    if (!any || s > max) return true;
    uint32_t d = max - s;
    if (d >= 64) return false;
    return !((bits >> d) & 1);
}

static void win_set(bool *any, uint32_t *max, uint64_t *bits, uint32_t s) {
    if (!*any) { *any = true; *max = s; *bits = 1; return; }
    if (s > *max) {
        uint32_t sh = s - *max;
        *bits = (sh >= 64) ? 0 : (*bits << sh);
        *bits |= 1;
        *max = s;
    } else {
        *bits |= (1ULL << (*max - s));
    }
}

int frame_open(enr_chain_t *rx, const uint8_t *f, size_t len, uint8_t *pt, int64_t now, int *why) {
    enr_hdr_t h;
    *why = OPEN_BAD;
    if (!rx->valid || !hdr_get(f, len, &h) || h.r != rx->r || len < HDR_LEN + ENR_TAG_LEN) return -1;
    size_t cl = len - HDR_LEN - ENR_TAG_LEN;

    enum { K_CUR, K_PREV, K_FWD } which;
    const uint8_t *key;
    uint8_t cand_mk[16], cand_prev[16], cand_ckn[32];
    bool *wa; uint32_t *wm; uint64_t *wb;
    bool fresh_any = false; uint32_t fresh_max = 0; uint64_t fresh_bits = 0;

    chain_expire(rx, now);
    if (h.e == rx->e) {
        which = K_CUR; key = rx->mk;
        wa = &rx->win_any; wm = &rx->win_max; wb = &rx->win_bits;
    } else if (rx->has_prev && h.e == (uint16_t)(rx->e - 1)) {
        which = K_PREV; key = rx->mk_prev;
        wa = &rx->win_any_prev; wm = &rx->win_max_prev; wb = &rx->win_bits_prev;
    } else if (h.e > rx->e && h.e - rx->e <= ENR_W_E) {
        /* Derive candidates in scratch; commit only after authentication. */
        which = K_FWD;
        uint8_t ck[32];
        memcpy(ck, rx->ck_next, 32);
        memcpy(cand_prev, rx->mk, 16);
        for (uint16_t k = rx->e + 1;; k++) {
            uint8_t mk[16], ckn[32];
            derive_step(ck, rx->r, k, rx->src, rx->dst, mk, ckn);
            memcpy(ck, ckn, 32);
            enr_zero(ckn, 32);
            if (k == h.e) { memcpy(cand_mk, mk, 16); enr_zero(mk, 16); break; }
            memcpy(cand_prev, mk, 16);
            enr_zero(mk, 16);
        }
        memcpy(cand_ckn, ck, 32);
        enr_zero(ck, 32);
        key = cand_mk;
        wa = &fresh_any; wm = &fresh_max; wb = &fresh_bits;
    } else {
        *why = OPEN_EPOCH;
        return -1;
    }

    if (!win_ok(*wa, *wm, *wb, h.seq)) {
        *why = OPEN_REPLAY;
        if (which == K_FWD) { enr_zero(cand_mk, 16); enr_zero(cand_prev, 16); enr_zero(cand_ckn, 32); }
        return -1;
    }

    uint8_t nonce[13], aad[20];
    build_nonce(nonce, rx->src, h.r, h.e, h.seq);
    build_aad(aad, f, rx->src, rx->dst);
    if (enr_ccm_open(key, nonce, aad, sizeof aad, f + HDR_LEN, cl, f + HDR_LEN + cl, pt)) {
        *why = OPEN_TAG;
        if (which == K_FWD) { enr_zero(cand_mk, 16); enr_zero(cand_prev, 16); enr_zero(cand_ckn, 32); }
        enr_zero(pt, cl);
        return -1;
    }

    if (which == K_FWD) {
        bool adjacent = (h.e == rx->e + 1);
        if (adjacent) {
            rx->win_any_prev = rx->win_any; rx->win_max_prev = rx->win_max; rx->win_bits_prev = rx->win_bits;
        } else {
            rx->win_any_prev = false;
        }
        memcpy(rx->mk_prev, cand_prev, 16);
        rx->has_prev = true;
        rx->prev_expire = now + MS(ENR_T_GRACE_MS);
        memcpy(rx->mk, cand_mk, 16);
        memcpy(rx->ck_next, cand_ckn, 32);
        rx->e = h.e;
        rx->t_epoch_start = now;
        rx->win_any = false;
        wa = &rx->win_any; wm = &rx->win_max; wb = &rx->win_bits;
        enr_zero(cand_mk, 16); enr_zero(cand_prev, 16); enr_zero(cand_ckn, 32);
    }
    win_set(wa, wm, wb, h.seq);
    *why = OPEN_OK;
    return (int)cl;
}

/* ---------- handshake (spec §7) ---------- */

/* Per-node K_auth = HMAC(master, "ENR1 auth" || MAC_node). Provisioning helper (public API, enr.h). */
void enr_derive_node_key(const uint8_t master[32], const uint8_t node_mac[6], uint8_t kauth[32]) {
    enr_buf_t p[] = {EL("ENR1 auth"), EB(node_mac, 6)};
    enr_hmac(master, 32, p, 2, kauth);
}

void hs_tag_n(const uint8_t kauth[32], const uint8_t idc[6], const uint8_t idn[6], uint8_t r,
              const uint8_t nc[16], const uint8_t nn[16], const uint8_t pkn[32], uint8_t out[16]) {
    uint8_t full[32];
    enr_buf_t p[] = {EL("ENR1 HS1"), EB(idc, 6), EB(idn, 6), EB(&r, 1), EB(nc, 16), EB(nn, 16), EB(pkn, 32)};
    enr_hmac(kauth, 32, p, 7, full);
    memcpy(out, full, 16);
    enr_zero(full, 32);
}

void hs_th(const uint8_t idc[6], const uint8_t idn[6], uint8_t r, const uint8_t nc[16],
           const uint8_t nn[16], const uint8_t pkn[32], const uint8_t pkc[32], uint8_t th[32]) {
    enr_buf_t p[] = {EB(idc, 6), EB(idn, 6), EB(&r, 1), EB(nc, 16), EB(nn, 16), EB(pkn, 32), EB(pkc, 32)};
    enr_sha256(p, 7, th);
}

void hs_tag_c(const uint8_t kauth[32], const uint8_t th[32], uint8_t out[16]) {
    uint8_t full[32];
    enr_buf_t p[] = {EL("ENR1 HS2"), EB(th, 32)};
    enr_hmac(kauth, 32, p, 2, full);
    memcpy(out, full, 16);
    enr_zero(full, 32);
}

void hs_derive(const uint8_t rk_prev[32], const uint8_t z[32], const uint8_t th[32], uint8_t rk[32],
               uint8_t ck_c2n[32], uint8_t ck_n2c[32], uint8_t kconf[16]) {
    /* RK never leaves this function. Callers get only RK* = Expand(RK, "ENR1 rk"), which is
     * mixed into the next refresh. Storing RK would let a later state compromise recompute
     * ck_c2n/ck_n2c (TH is public) and so every message key of the generation, breaking
     * per-epoch forward secrecy. */
    uint8_t RK[32];
    enr_buf_t ikm[] = {EB(z, 32), EB(th, 32)};
    enr_hkdf_extract(rk_prev, 32, ikm, 2, RK);
    enr_buf_t i1[] = {EL("ENR1 ck c2n"), EB(th, 32)};
    enr_hkdf_expand(RK, i1, 2, ck_c2n, 32);
    enr_buf_t i2[] = {EL("ENR1 ck n2c"), EB(th, 32)};
    enr_hkdf_expand(RK, i2, 2, ck_n2c, 32);
    enr_buf_t i3[] = {EL("ENR1 conf"), EB(th, 32)};
    enr_hkdf_expand(RK, i3, 2, kconf, 16);
    enr_buf_t i4[] = {EL("ENR1 rk")};
    enr_hkdf_expand(RK, i4, 1, rk, 32); /* rk out = RK* (one-way) */
    enr_zero(RK, 32);
}

void hs_conf(const uint8_t kconf[16], char who, const uint8_t th[32], uint8_t out[8]) {
    uint8_t full[32];
    enr_buf_t p[] = {who == 'C' ? EL("ENR1 confC") : EL("ENR1 confN"), EB(th, 32)};
    enr_hmac(kconf, 16, p, 2, full);
    memcpy(out, full, 8);
    enr_zero(full, 32);
}

void cookie_for(const uint8_t kcookie[32], const uint8_t idn[6], uint32_t slot, uint8_t out[16]) {
    uint8_t full[32], s[4];
    be32(s, slot);
    enr_buf_t p[] = {EL("ENR1 cookie"), EB(idn, 6), EB(s, 4)};
    enr_hmac(kcookie, 32, p, 3, full);
    memcpy(out, full, 16);
    enr_zero(full, 32);
}
