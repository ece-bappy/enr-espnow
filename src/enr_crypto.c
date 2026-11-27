#include "enr_crypto.h"

#include <string.h>
#include "esp_random.h"
#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "monocypher.h"

void enr_rand(uint8_t *out, size_t n) { esp_fill_random(out, n); }

void enr_zero(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }

bool enr_ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

/* Uses the generic md layer: direct mbedtls_sha256_* multi-part hashing gave wrong
 * digests on classic ESP32 (hardware SHA) in IDF 5.4.1 while the md/HMAC path was correct. */
int enr_sha256(const enr_buf_t *parts, int np, uint8_t out[32]) {
    mbedtls_md_context_t c;
    mbedtls_md_init(&c);
    int rc = mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    if (!rc) rc = mbedtls_md_starts(&c);
    for (int i = 0; !rc && i < np; i++)
        if (parts[i].n) rc = mbedtls_md_update(&c, parts[i].p, parts[i].n);
    if (!rc) rc = mbedtls_md_finish(&c, out);
    mbedtls_md_free(&c);
    return rc;
}

int enr_hmac(const uint8_t *key, size_t kl, const enr_buf_t *parts, int np, uint8_t out[32]) {
    mbedtls_md_context_t c;
    mbedtls_md_init(&c);
    int rc = mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (!rc) rc = mbedtls_md_hmac_starts(&c, key, kl);
    for (int i = 0; !rc && i < np; i++)
        if (parts[i].n) rc = mbedtls_md_hmac_update(&c, parts[i].p, parts[i].n);
    if (!rc) rc = mbedtls_md_hmac_finish(&c, out);
    mbedtls_md_free(&c);
    return rc;
}

int enr_hkdf_extract(const uint8_t *salt, size_t sl, const enr_buf_t *ikm, int np, uint8_t prk[32]) {
    static const uint8_t zeros[32] = {0};
    if (salt == NULL || sl == 0) { salt = zeros; sl = sizeof zeros; }
    return enr_hmac(salt, sl, ikm, np, prk);
}

/* RFC 5869 Expand: T(i) = HMAC(PRK, T(i-1) || info || i) */
int enr_hkdf_expand(const uint8_t prk[32], const enr_buf_t *info, int np, uint8_t *out, size_t L) {
    if (np > 8 || L > 255 * 32) return -1;
    uint8_t t[32];
    size_t tlen = 0, done = 0;
    int rc = 0;
    for (uint8_t i = 1; done < L; i++) {
        enr_buf_t parts[10];
        int k = 0;
        parts[k++] = EB(t, tlen);
        for (int j = 0; j < np; j++) parts[k++] = info[j];
        parts[k++] = EB(&i, 1);
        rc = enr_hmac(prk, 32, parts, k, t);
        if (rc) break;
        tlen = 32;
        size_t n = (L - done < 32) ? (L - done) : 32;
        memcpy(out + done, t, n);
        done += n;
    }
    enr_zero(t, sizeof t);
    return rc;
}

static const uint8_t ZERO32[32] = {0};

int enr_x25519_keygen(uint8_t sk[32], uint8_t pk[32]) {
    esp_fill_random(sk, 32);
    sk[0] &= 248; sk[31] &= 127; sk[31] |= 64; /* RFC 7748 clamping */
    crypto_x25519_public_key(pk, sk);
    return 0;
}

int enr_x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t peer_pk[32]) {
    crypto_x25519(out, sk, peer_pk);
    return enr_ct_eq(out, ZERO32, 32) ? -2 : 0; /* reject low-order points */
}

int enr_ccm_seal(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                 const uint8_t *pt, size_t pl, uint8_t *ct, uint8_t tag[ENR_TAG_LEN]) {
    mbedtls_ccm_context c;
    mbedtls_ccm_init(&c);
    int rc = mbedtls_ccm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (!rc) rc = mbedtls_ccm_encrypt_and_tag(&c, pl, nonce, ENR_NONCE_LEN, aad, al, pt, ct, tag, ENR_TAG_LEN);
    mbedtls_ccm_free(&c);
    return rc;
}

int enr_ccm_open(const uint8_t key[16], const uint8_t nonce[13], const uint8_t *aad, size_t al,
                 const uint8_t *ct, size_t cl, const uint8_t tag[ENR_TAG_LEN], uint8_t *pt) {
    mbedtls_ccm_context c;
    mbedtls_ccm_init(&c);
    int rc = mbedtls_ccm_setkey(&c, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (!rc) rc = mbedtls_ccm_auth_decrypt(&c, cl, nonce, ENR_NONCE_LEN, aad, al, ct, pt, tag, ENR_TAG_LEN);
    mbedtls_ccm_free(&c);
    return rc;
}
