/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* ChaCha20-Poly1305-IETF (RFC 8439) built from the Xtensa-tuned primitives.
 * Same construction as libsodium's crypto_aead_chacha20poly1305_ietf_*_detached:
 *   - one-time Poly1305 key = ChaCha20 block 0 (first 32 bytes)
 *   - ciphertext = ChaCha20 from block 1
 *   - MAC over: AAD || pad16 || CT || pad16 || len(AAD)_LE64 || len(CT)_LE64
 * Verified against libsodium on-device.
 */
#pragma once
/* Built ONLY on Xtensa (see sn_wire.c); the host and non-Xtensa targets use
 * libsodium. Equivalence is pinned by the §15 golden vectors and by an on-device
 * check against libsodium (benchmark/shieldnet-esp32). */
#include "sn_chacha_xtensa.h"
#include "sn_poly_xtensa.h"

#include <sodium.h> /* sodium_memzero */

static inline void aead_opt_mac(uint8_t tag[16], const uint8_t polykey[32],
                                const uint8_t *ad, size_t ad_len,
                                const uint8_t *ct, size_t ct_len) {
    static const uint8_t zeros[16] = {0};
    poly_opt_ctx st;
    poly_opt_init(&st, polykey);

    uint8_t blk[16];
    size_t n;
    /* AAD || pad16 */
    n = ad_len & ~(size_t)15;
    if (n) poly_opt_blocks(&st, ad, n);
    if (ad_len - n) {
        memcpy(blk, ad + n, ad_len - n);
        memcpy(blk + (ad_len - n), zeros, 16 - (ad_len - n));
        poly_opt_blocks(&st, blk, 16);
    }
    /* CT || pad16 */
    n = ct_len & ~(size_t)15;
    if (n) poly_opt_blocks(&st, ct, n);
    if (ct_len - n) {
        memcpy(blk, ct + n, ct_len - n);
        memcpy(blk + (ct_len - n), zeros, 16 - (ct_len - n));
        poly_opt_blocks(&st, blk, 16);
    }
    /* len(AAD) || len(CT), little-endian u64 each */
    memset(blk, 0, 16);
    st32le(blk + 0, (uint32_t)ad_len);
    st32le(blk + 4, (uint32_t)((uint64_t)ad_len >> 32));
    st32le(blk + 8, (uint32_t)ct_len);
    st32le(blk + 12, (uint32_t)((uint64_t)ct_len >> 32));
    poly_opt_blocks(&st, blk, 16);

    st.leftover = 0;
    poly_opt_finish(&st, tag);
    /* st holds r and s (the one-time key); blk the last AAD/CT block. */
    sodium_memzero(&st, sizeof(st));
    sodium_memzero(blk, sizeof(blk));
}

/* Encrypt msg -> ct (same length) and produce tag. */
static inline void aead_opt_encrypt(uint8_t *ct, uint8_t tag[16],
                                    const uint8_t *msg, size_t msg_len,
                                    const uint8_t *ad, size_t ad_len,
                                    const uint8_t nonce[12], const uint8_t key[32]) {
    uint8_t polykey[64], zeros[64];
    memset(zeros, 0, sizeof(zeros));
    chacha20_xor_opt(key, nonce, 0, zeros, 64, polykey);   /* block 0 */
    chacha20_xor_opt(key, nonce, 1, msg, msg_len, ct);     /* from block 1 */
    aead_opt_mac(tag, polykey, ad, ad_len, ct, msg_len);
    sodium_memzero(polykey, sizeof(polykey));
}

/* Decrypt ct -> msg and verify tag. Returns 0 on success, -1 on auth failure. */
static inline int aead_opt_decrypt(uint8_t *msg, const uint8_t *ct, size_t ct_len,
                                   const uint8_t tag[16],
                                   const uint8_t *ad, size_t ad_len,
                                   const uint8_t nonce[12], const uint8_t key[32]) {
    uint8_t polykey[64], zeros[64], want[16];
    memset(zeros, 0, sizeof(zeros));
    chacha20_xor_opt(key, nonce, 0, zeros, 64, polykey);
    aead_opt_mac(want, polykey, ad, ad_len, ct, ct_len);
    sodium_memzero(polykey, sizeof(polykey));
    /* Tag before decrypt: nothing is written to msg for a forgery. */
    int bad = crypto_verify_16(want, tag);                  /* constant-time */
    sodium_memzero(want, sizeof(want));
    if (bad != 0) return -1;
    chacha20_xor_opt(key, nonce, 1, ct, ct_len, msg);
    return 0;
}
