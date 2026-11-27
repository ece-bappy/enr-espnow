#pragma once
/* ENR crypto primitives: HMAC-SHA256 / HKDF and AES-128-CCM (mbedTLS, hardware-accelerated on ESP32),
 * X25519 (Monocypher 4.0.2). Internal header. */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Scatter-gather buffer for multi-part MAC/KDF inputs. */
typedef struct { const void *p; size_t n; } enr_buf_t;
#define EB(ptr, len) ((enr_buf_t){(ptr), (len)})
#define EL(str) EB((str), sizeof(str) - 1) /* ASCII label without NUL */

void enr_rand(uint8_t *out, size_t n);
void enr_zero(void *p, size_t n);
bool enr_ct_eq(const uint8_t *a, const uint8_t *b, size_t n);

int enr_sha256(const enr_buf_t *parts, int np, uint8_t out[32]);
int enr_hmac(const uint8_t *key, size_t kl, const enr_buf_t *parts, int np, uint8_t out[32]);
int enr_hkdf_extract(const uint8_t *salt, size_t sl, const enr_buf_t *ikm, int np, uint8_t prk[32]);
int enr_hkdf_expand(const uint8_t prk[32], const enr_buf_t *info, int np, uint8_t *out, size_t L);

int enr_x25519_keygen(uint8_t sk[32], uint8_t pk[32]);
int enr_x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t peer_pk[32]);

#define ENR_NONCE_LEN 13
#define ENR_TAG_LEN 8
int enr_ccm_seal(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                 const uint8_t *pt, size_t pl, uint8_t *ct, uint8_t tag[ENR_TAG_LEN]);
int enr_ccm_open(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                 const uint8_t *ct, size_t cl, const uint8_t tag[ENR_TAG_LEN], uint8_t *pt);

#ifdef __cplusplus
}
#endif
