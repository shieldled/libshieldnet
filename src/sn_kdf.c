/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_kdf.h"

#include <sodium.h>
#include <string.h>

#define TYPE_INIT  0x01
#define TYPE_RETRY 0x02
#define TYPE_FIN   0x05
#define TYPE_ADMIT 0x06
#define VERSION    0x01

/* L(label) = uint8(len) || label, appended at *off in buf. Labels are short
 * compile-time constants, so one length octet always suffices. */
static void put_label(uint8_t *buf, size_t *off, const char *label) {
    size_t n = strlen(label);
    buf[(*off)++] = (uint8_t)n;
    memcpy(buf + *off, label, n);
    *off += n;
}

static void put(uint8_t *buf, size_t *off, const uint8_t *src, size_t n) {
    memcpy(buf + *off, src, n);
    *off += n;
}

/* libsodium's HKDF calls return -1 only for an output longer than 255 hash
 * blocks, which no call here asks for -- but a key derivation that "cannot
 * fail" and then does must not leave a predictable buffer behind. On failure
 * the output becomes random: whatever it keys can then never match the peer's,
 * so the handshake fails closed rather than running under a zero key. */
static void hkdf_expand(uint8_t *out, size_t out_len, const char *ctx, size_t ctx_len,
                        const uint8_t prk[32]) {
    if (crypto_kdf_hkdf_sha256_expand(out, out_len, ctx, ctx_len, prk) != 0) {
        randombytes_buf(out, out_len);
    }
}

static void hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len) {
    if (crypto_kdf_hkdf_sha256_extract(prk, salt, salt_len, ikm, ikm_len) != 0) {
        randombytes_buf(prk, 32);
    }
}

/* HKDF-Extract with salt="" meaning 32 zero octets (§0). */
static void extract_zero_salt(const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
    uint8_t zero[32];
    memset(zero, 0, sizeof zero);
    hkdf_extract(prk, zero, sizeof zero, ikm, ikm_len);
}

void sn_hmac128(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t out16[16]) {
    uint8_t full[crypto_auth_hmacsha256_BYTES]; /* 32 */
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, msg, msg_len);
    crypto_auth_hmacsha256_final(&st, full);
    memcpy(out16, full, 16);
    sodium_memzero(full, sizeof full);
    sodium_memzero(&st, sizeof st);
}

/* The k_dev derivation, reporting failure instead of substituting random bytes,
 * so that provisioning can stay unprovisioned on failure (transport 3.2). */
static int derive_kdev(const uint8_t psk[32], const uint8_t device_id[8],
                       uint8_t out[32]) {
    uint8_t prk_psk[32], info[64], zero[32];
    size_t off = 0;
    int rc = 0;
    memset(zero, 0, sizeof zero);
    if (crypto_kdf_hkdf_sha256_extract(prk_psk, zero, sizeof zero, psk, 32) != 0) {
        rc = -1;
    } else {
        put_label(info, &off, "shieldled/v1/device");
        put(info, &off, device_id, 8);
        if (crypto_kdf_hkdf_sha256_expand(out, 32, (const char *)info, off, prk_psk) != 0) {
            rc = -1;
        }
    }
    sodium_memzero(prk_psk, sizeof prk_psk);
    return rc;
}

void sn_derive_kdev(const uint8_t psk[32], const uint8_t device_id[8],
                    uint8_t k_dev_out[32]) {
    if (derive_kdev(psk, device_id, k_dev_out) != 0) {
        randombytes_buf(k_dev_out, 32);
    }
}

int sn_provision_kdev(uint8_t psk[32], const uint8_t device_id[8], uint8_t k_dev_out[32]) {
    if (sodium_init() < 0) {
        sodium_memzero(psk, 32);
        sodium_memzero(k_dev_out, 32);
        return -1;
    }
    uint8_t kd[32];
    int rc = derive_kdev(psk, device_id, kd);
    sodium_memzero(psk, 32);
    if (rc != 0) {
        sodium_memzero(kd, sizeof kd);
        sodium_memzero(k_dev_out, 32);
        return -1;
    }
    memcpy(k_dev_out, kd, 32);
    sodium_memzero(kd, sizeof kd);
    return 0;
}

void sn_derive_static(const uint8_t k_dev[32],
                      uint8_t k_req_out[32], uint8_t k_resp_out[32]) {
    uint8_t prk[32], info[32];
    size_t off;
    extract_zero_salt(k_dev, 32, prk);
    off = 0; put_label(info, &off, "shieldled/v1/req");
    hkdf_expand(k_req_out, 32, (const char *)info, off, prk);
    off = 0; put_label(info, &off, "shieldled/v1/resp");
    hkdf_expand(k_resp_out, 32, (const char *)info, off, prk);
    sodium_memzero(prk, sizeof prk);
}

void sn_init_mac(const uint8_t k_req[32], const uint8_t client_nonce[24],
                 const uint8_t device_id[8], uint8_t out16[16]) {
    uint8_t m[64];
    size_t off = 0;
    put_label(m, &off, "shieldled/v1/init");
    m[off++] = TYPE_INIT; m[off++] = VERSION;
    put(m, &off, client_nonce, 24);
    put(m, &off, device_id, 8);
    sn_hmac128(k_req, 32, m, off, out16);
}

void sn_epoch_tag(const uint8_t cookie_secret[32], const uint8_t cookie_epoch_be[4],
                  uint8_t out8[8]) {
    uint8_t m[32], full[32];
    size_t off = 0;
    put_label(m, &off, "shieldled/v1/epoch");
    put(m, &off, cookie_epoch_be, 4);
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, cookie_secret, 32);
    crypto_auth_hmacsha256_update(&st, m, off);
    crypto_auth_hmacsha256_final(&st, full);
    memcpy(out8, full, 8);
    sodium_memzero(full, sizeof full);
    sodium_memzero(&st, sizeof st);
}

void sn_cookie(const uint8_t cookie_secret[32], const uint8_t epoch_tag[8],
               const uint8_t canonical_source[18], const uint8_t client_nonce[24],
               uint8_t out16[16]) {
    uint8_t m[80];
    size_t off = 0;
    put_label(m, &off, "shieldled/v1/cookie");
    put(m, &off, epoch_tag, 8);
    put(m, &off, canonical_source, 18);
    put(m, &off, client_nonce, 24);
    sn_hmac128(cookie_secret, 32, m, off, out16);
}

void sn_retry_mac(const uint8_t k_resp[32], const uint8_t client_nonce[24],
                  const uint8_t epoch_tag[8], const uint8_t cookie[16],
                  const uint8_t admission_epoch[8], const uint8_t device_id[8],
                  const uint8_t observed_source[18], uint8_t out16[16]) {
    uint8_t m[128];
    size_t off = 0;
    put_label(m, &off, "shieldled/v1/retry");
    m[off++] = TYPE_RETRY; m[off++] = VERSION;
    put(m, &off, client_nonce, 24);
    put(m, &off, epoch_tag, 8);
    put(m, &off, cookie, 16);
    put(m, &off, admission_epoch, 8);
    put(m, &off, device_id, 8);
    put(m, &off, observed_source, 18);
    sn_hmac128(k_resp, 32, m, off, out16);
}

void sn_context(const uint8_t client_nonce[24], const uint8_t epoch_tag[8],
                const uint8_t cookie[16], const uint8_t admission_epoch[8],
                const uint8_t device_id[8], uint8_t out65[65]) {
    size_t off = 0;
    out65[off++] = VERSION;
    put(out65, &off, client_nonce, 24);
    put(out65, &off, epoch_tag, 8);
    put(out65, &off, cookie, 16);
    put(out65, &off, admission_epoch, 8);
    put(out65, &off, device_id, 8);
}

void sn_context2(const uint8_t context[65], const uint8_t e_c[32],
                 const uint8_t e_s[32], uint8_t out129[129]) {
    memcpy(out129, context, 65);
    memcpy(out129 + 65, e_c, 32);
    memcpy(out129 + 97, e_s, 32);
}

void sn_client_tag(const uint8_t k_req[32], const uint8_t context[65],
                   const uint8_t e_c[32], uint8_t out16[16]) {
    uint8_t m[128];
    size_t off = 0;
    put_label(m, &off, "shieldled/v1/finish");
    m[off++] = TYPE_FIN; m[off++] = VERSION;
    put(m, &off, context, 65);
    put(m, &off, e_c, 32);
    sn_hmac128(k_req, 32, m, off, out16);
}

void sn_admit_pre(const uint8_t k_resp[32], const uint8_t context2[129],
                  uint8_t out16[16]) {
    uint8_t m[160];
    size_t off = 0;
    put_label(m, &off, "shieldled/v1/admit-pre");
    m[off++] = TYPE_ADMIT; m[off++] = VERSION;
    put(m, &off, context2, 129);
    sn_hmac128(k_resp, 32, m, off, out16);
}

int sn_dh(const uint8_t own_priv[32], const uint8_t peer_pub[32], uint8_t out32[32]) {
    /* crypto_scalarmult returns -1 iff the result is all zero (a low-order point),
     * which is exactly §4.5's rejection rule. */
    return crypto_scalarmult(out32, own_priv, peer_pub);
}

void sn_master(const uint8_t context2[129], const uint8_t k_dev[32],
               const uint8_t dh[32], uint8_t out32[32]) {
    uint8_t salt[160], ikm[64];
    size_t off = 0;
    put_label(salt, &off, "shieldled/v1/master");
    put(salt, &off, context2, 129);
    memcpy(ikm, k_dev, 32);
    memcpy(ikm + 32, dh, 32);
    hkdf_extract(out32, salt, off, ikm, 64);
    sodium_memzero(ikm, sizeof ikm);
}

static void expand_label(const uint8_t master[32], const char *label,
                         uint8_t *out, size_t out_len) {
    uint8_t info[32];
    size_t off = 0;
    put_label(info, &off, label);
    hkdf_expand(out, out_len, (const char *)info, off, master);
}

void sn_session_keys(const uint8_t master[32],
                     uint8_t k_c2s[32], uint8_t k_s2c[32],
                     uint8_t k_kcp_c2s[32], uint8_t k_kcp_s2c[32]) {
    expand_label(master, "shieldled/v1/c2s", k_c2s, 32);
    expand_label(master, "shieldled/v1/s2c", k_s2c, 32);
    expand_label(master, "shieldled/v1/kcp-c2s", k_kcp_c2s, 32);
    expand_label(master, "shieldled/v1/kcp-s2c", k_kcp_s2c, 32);
}

void sn_admit_tag(const uint8_t master[32], uint8_t out16[16]) {
    expand_label(master, "shieldled/v1/admit", out16, 16);
}
