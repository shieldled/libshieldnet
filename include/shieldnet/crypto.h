/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * XChaCha20-Poly1305 AEAD for the message layer (libsodium).
 *
 * The PSK is not the AEAD key: the per-session, per-direction keys come from
 * admission (sn_kdf.h), and sn_app_frame.c seals and opens with them. The
 * nonce is derived from MessageNum and does not travel on the wire, so the
 * per-message overhead is just the 16-byte Poly1305 tag.
 *
 * The AEAD is byte-identical to golang.org/x/crypto/chacha20poly1305.NewX.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_KEY_SIZE    32
#define CRYPTO_NONCE_SIZE  24   /* XChaCha20 extended nonce */
#define CRYPTO_TAG_SIZE    16   /* Poly1305 tag */
#define CRYPTO_OVERHEAD    CRYPTO_TAG_SIZE   /* v2: tag only (no on-wire nonce) */

#define CRYPTO_RANDOM_SIZE 24   /* client_random / server_random */

/* Pre-shared key holder (used only to derive session keys). */
typedef struct {
    uint8_t key[CRYPTO_KEY_SIZE];
} crypto_cipher_t;

/* Per-session, per-direction keys derived at handshake. */
typedef struct {
    uint8_t k_c2s[CRYPTO_KEY_SIZE];   /* client -> server */
    uint8_t k_s2c[CRYPTO_KEY_SIZE];   /* server -> client */
} session_keys_t;

/* Securely wipe sensitive memory (constant-time, not optimized away). */
void crypto_wipe(void *p, size_t n);

/* Init the PSK holder from a raw 32-byte key / 64-char hex. Returns 0/-1. */
int crypto_init(crypto_cipher_t *cipher, const uint8_t key[CRYPTO_KEY_SIZE]);
int crypto_init_hex(crypto_cipher_t *cipher, const char *hex_key);



/*
 * AEAD with an explicit direction key and explicit nonce (derived from
 * MessageNum by the caller). Encrypt output is ciphertext||tag
 * (plaintext_len + 16); decrypt requires ciphertext_len >= 16. Returns 0/-1.
 */
int crypto_encrypt(const uint8_t key[CRYPTO_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_NONCE_SIZE],
                   const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *out_buf, size_t *out_len);

int crypto_decrypt(const uint8_t key[CRYPTO_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_NONCE_SIZE],
                   const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *out_buf, size_t *out_len);

#ifdef __cplusplus
}
#endif
