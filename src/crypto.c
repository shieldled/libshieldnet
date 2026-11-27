/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * XChaCha20-Poly1305 AEAD + v2 key schedule (ESP-IDF).
 *
 * libsodium primitives, byte-identical to Go's crypto/hkdf and
 * x/crypto/chacha20poly1305.NewX.
 */

#include "crypto.h"

#include <sodium.h>
#include <stdatomic.h>
#include <string.h>

#include "shieldnet_log.h"

static const char *TAG = "crypto";

/* Authentication failures are peer-triggerable, and on ESP32 an ERR log is a
 * synchronous UART write: logging each one turns a flood of bad frames into a
 * flood of log I/O on the receive path. Log the first, then one line per
 * AUTH_FAIL_LOG_EVERY with the running count. The counter is shared by every
 * caller (any thread), hence atomic; relaxed is enough -- it orders nothing,
 * and a 32-bit atomic add is lock-free on Xtensa (S32C1I) as on the host. */
#define AUTH_FAIL_LOG_EVERY 1024u
static _Atomic uint32_t g_auth_failures;

static void note_auth_failure(const char *what)
{
    uint32_t n = atomic_fetch_add_explicit(&g_auth_failures, 1, memory_order_relaxed) + 1;
    if (n == 1 || n % AUTH_FAIL_LOG_EVERY == 0) {
        SHIELDNET_LOG_ERR(TAG, "%s (%lu failures so far)", what, (unsigned long)n);
    }
    (void)what; (void)n; /* the log is a no-op macro on the host */
}

_Static_assert(crypto_aead_xchacha20poly1305_ietf_KEYBYTES == CRYPTO_KEY_SIZE, "key size mismatch");
_Static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == CRYPTO_NONCE_SIZE, "nonce size mismatch");
_Static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES == CRYPTO_TAG_SIZE, "tag size mismatch");
_Static_assert(crypto_kdf_hkdf_sha256_KEYBYTES == CRYPTO_KEY_SIZE, "hkdf prk size mismatch");

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

void crypto_wipe(void *p, size_t n)
{
    if (p) sodium_memzero(p, n);
}

int crypto_init(crypto_cipher_t *cipher, const uint8_t key[CRYPTO_KEY_SIZE])
{
    if (!cipher || !key) return -1;
    if (sodium_init() < 0) {
        SHIELDNET_LOG_ERR(TAG, "sodium_init failed");
        return -1;
    }
    memcpy(cipher->key, key, CRYPTO_KEY_SIZE);
    return 0;
}

int crypto_init_hex(crypto_cipher_t *cipher, const char *hex_key)
{
    if (!cipher || !hex_key) return -1;
    uint8_t key[CRYPTO_KEY_SIZE];
    if (hex_to_bytes(hex_key, key, CRYPTO_KEY_SIZE) < 0) {
        SHIELDNET_LOG_ERR(TAG, "invalid hex key (expected 64 hex chars)");
        crypto_wipe(key, sizeof(key));
        return -1;
    }
    int rc = crypto_init(cipher, key);
    crypto_wipe(key, sizeof(key));
    return rc;
}



int crypto_encrypt(const uint8_t key[CRYPTO_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_NONCE_SIZE],
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *out_buf, size_t *out_len)
{
    if (!key || !nonce || !out_buf || !out_len) return -1;
    if (plaintext_len > 0 && !plaintext) return -1;

    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out_buf, &ct_len, plaintext, plaintext_len,
            aad, aad_len, NULL, nonce, key) != 0) {
        SHIELDNET_LOG_ERR(TAG, "encryption failed");
        return -1;
    }
    *out_len = (size_t)ct_len;   /* plaintext_len + 16 */
    return 0;
}

int crypto_decrypt(const uint8_t key[CRYPTO_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_NONCE_SIZE],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *out_buf, size_t *out_len)
{
    if (!key || !nonce || !ciphertext || !out_buf || !out_len) return -1;
    if (ciphertext_len < CRYPTO_TAG_SIZE) {
        note_auth_failure("ciphertext shorter than the tag");
        return -1;
    }

    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            out_buf, &pt_len, NULL, ciphertext, ciphertext_len,
            aad, aad_len, nonce, key) != 0) {
        note_auth_failure("authentication failed");
        return -1;
    }
    *out_len = (size_t)pt_len;
    return 0;
}
