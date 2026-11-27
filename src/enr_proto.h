#pragma once
/* ENR v1 protocol core: frame format, key schedule, epoch ratchet, replay window. Internal header. */
#include <stdbool.h>
#include <stdint.h>
#include "esp_timer.h"
#include "enr_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Compile-time protocol constants (spec defaults). Runtime settings live in enr_config_t (enr.h). */
#ifndef ENR_W_E
#define ENR_W_E 4                 /* receiver look-ahead epochs */
#endif
#ifndef ENR_T_GRACE_MS
#define ENR_T_GRACE_MS 2000       /* old-key retention */
#endif
#ifndef ENR_T_HS_MS
#define ENR_T_HS_MS 500           /* handshake retransmit timeout */
#endif
#ifndef ENR_R_MAX
#define ENR_R_MAX 5               /* handshake tries */
#endif
#ifndef ENR_T_SLOT_MS
#define ENR_T_SLOT_MS 10000       /* stateless cookie slot */
#endif
#ifndef ENR_T_RL_MS
#define ENR_T_RL_MS 2000          /* min interval between DH operations per node */
#endif

#define ENR_VER 1
enum {
    T_HELLO = 0x1, T_CHAL = 0x2, T_HS1 = 0x3, T_HS2 = 0x4, T_HS3 = 0x5,
    T_REFRESH = 0x6, T_DATA = 0x7, T_ALERT = 0x8,
};
/* First plaintext byte of AEAD-protected frames */
enum { P_REFRESH = 0x03, P_APP = 0x04, P_KA = 0x05, P_KA_ACK = 0x06 };

#define HDR_LEN 8
#define LEN_HELLO HDR_LEN
#define LEN_CHAL (HDR_LEN + 16)
#define LEN_HS1 (HDR_LEN + 16 + 16 + 32 + 16)
#define LEN_HS2 (HDR_LEN + 32 + 16 + 8)
#define LEN_HS3 (HDR_LEN + 8)
#define ENR_MAX_FRAME 250
#define ENR_MAX_PT (ENR_MAX_FRAME - HDR_LEN - ENR_TAG_LEN)

typedef struct {
    uint8_t type, r;
    uint16_t e;
    uint32_t seq;
} enr_hdr_t;

void hdr_put(uint8_t *b, const enr_hdr_t *h);
bool hdr_get(const uint8_t *b, size_t len, enr_hdr_t *h);

/* One direction of one root generation. Used as sender (tx) or receiver (rx). */
typedef struct {
    bool valid;
    uint8_t r;
    uint16_t e;
    uint8_t src[6], dst[6];
    uint8_t mk[16];       /* MK_{d,r,e} */
    uint8_t ck_next[32];  /* CK_{d,r,e+1} */
    int64_t t_epoch_start;
    uint32_t seq;         /* tx: next sequence number */
    /* rx only */
    bool has_prev;
    uint8_t mk_prev[16];  /* MK_{d,r,e-1}, kept for T_grace */
    int64_t prev_expire;
    bool win_any, win_any_prev;
    uint32_t win_max, win_max_prev;
    uint64_t win_bits, win_bits_prev;
} enr_chain_t;

void chain_init(enr_chain_t *c, const uint8_t ck0[32], uint8_t r, const uint8_t src[6],
                const uint8_t dst[6], int64_t now);
void chain_advance(enr_chain_t *c, int64_t now, bool keep_prev);
void chain_expire(enr_chain_t *c, int64_t now);
void chain_wipe(enr_chain_t *c);
void chain_move(enr_chain_t *dst, enr_chain_t *src); /* dst := src, src wiped */

/* Returns frame length, or -1. */
int frame_seal(enr_chain_t *tx, uint8_t type, const uint8_t *pt, size_t pl, uint8_t *out);

enum { OPEN_OK = 0, OPEN_BAD = 1, OPEN_EPOCH = 2, OPEN_REPLAY = 3, OPEN_TAG = 4 };
/* Returns plaintext length (>=0) or -1 with *why set. Caller selects chain by hdr.r. */
int frame_open(enr_chain_t *rx, const uint8_t *f, size_t len, uint8_t *pt, int64_t now, int *why);

/* Handshake helpers */
void hs_tag_n(const uint8_t kauth[32], const uint8_t idc[6], const uint8_t idn[6], uint8_t r,
              const uint8_t nc[16], const uint8_t nn[16], const uint8_t pkn[32], uint8_t out[16]);
void hs_th(const uint8_t idc[6], const uint8_t idn[6], uint8_t r, const uint8_t nc[16],
           const uint8_t nn[16], const uint8_t pkn[32], const uint8_t pkc[32], uint8_t th[32]);
void hs_tag_c(const uint8_t kauth[32], const uint8_t th[32], uint8_t out[16]);
void hs_derive(const uint8_t rk_prev[32], const uint8_t z[32], const uint8_t th[32], uint8_t rk[32],
               uint8_t ck_c2n[32], uint8_t ck_n2c[32], uint8_t kconf[16]);
void hs_conf(const uint8_t kconf[16], char who, const uint8_t th[32], uint8_t out[8]);
void cookie_for(const uint8_t kcookie[32], const uint8_t idn[6], uint32_t slot, uint8_t out[16]);

static inline int64_t enr_now_us(void) { return esp_timer_get_time(); }
#define MS(x) ((int64_t)(x) * 1000)

#ifdef __cplusplus
}
#endif
