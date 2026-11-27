/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Optimized ChaCha20 block function for Xtensa (ESP32).
 *
 * libsodium's portable `ref` core measures 4.54 MB/s on an ESP32 @240MHz. Two
 * things cost it: the 32-bit rotates (portable C may not emit Xtensa's one-cycle
 * funnel shift) and per-block state reload. This keeps the 16 words in locals for
 * the whole 20 rounds and uses an explicit funnel-shift rotate on Xtensa.
 */
#pragma once
/* Built ONLY on Xtensa (see sn_wire.c); the host and non-Xtensa targets use
 * libsodium. Equivalence is pinned by the §15 golden vectors and by an on-device
 * check against libsodium (benchmark/shieldnet-esp32). */
#include <stdint.h>
#include <string.h>

#include <sodium.h> /* sodium_memzero */

#if defined(__XTENSA__)
/* Xtensa: ssai sets the shift amount, src does a 64-bit funnel shift, so a
 * constant-amount rotate is two instructions with no register pressure. */
/* Constant-amount rotate: the amount is known at compile time, so ssai takes an
 * immediate and the pair is 2 instructions with no register pressure. */
#define ROTL_K(v, k) ({ uint32_t _v = (v), _r;                       \
    __asm__("ssai %2\n\tsrc %0, %1, %1"                              \
            : "=&a"(_r) : "a"(_v), "i"(32 - (k)));                   \
    _r; })
#else
#define ROTL_K(v, k) (((uint32_t)(v) << (k)) | ((uint32_t)(v) >> (32 - (k))))
#endif

#define QR(a, b, c, d)                         \
    a += b; d ^= a; d = ROTL_K(d, 16);         \
    c += d; b ^= c; b = ROTL_K(b, 12);         \
    a += b; d ^= a; d = ROTL_K(d, 8);          \
    c += d; b ^= c; b = ROTL_K(b, 7);

/* Produce one 64-byte keystream block from a 16-word state. */
static inline void chacha20_block_opt(const uint32_t in[16], uint8_t out[64]) {
    uint32_t x0=in[0],x1=in[1],x2=in[2],x3=in[3],x4=in[4],x5=in[5],x6=in[6],x7=in[7],
             x8=in[8],x9=in[9],x10=in[10],x11=in[11],x12=in[12],x13=in[13],
             x14=in[14],x15=in[15];
    for (int i = 0; i < 10; i++) {
        QR(x0, x4,  x8, x12)  QR(x1, x5,  x9, x13)
        QR(x2, x6, x10, x14)  QR(x3, x7, x11, x15)
        QR(x0, x5, x10, x15)  QR(x1, x6, x11, x12)
        QR(x2, x7,  x8, x13)  QR(x3, x4,  x9, x14)
    }
    /* Each word straight to out (little-endian target): no o[16] keystream
     * copy on the stack to wipe, and nothing extra in the per-block hot path. */
#define SN_CHACHA_OUT(i, x) do { uint32_t w_ = (x) + in[i]; memcpy(out + 4 * (i), &w_, 4); } while (0)
    SN_CHACHA_OUT(0, x0);   SN_CHACHA_OUT(1, x1);   SN_CHACHA_OUT(2, x2);   SN_CHACHA_OUT(3, x3);
    SN_CHACHA_OUT(4, x4);   SN_CHACHA_OUT(5, x5);   SN_CHACHA_OUT(6, x6);   SN_CHACHA_OUT(7, x7);
    SN_CHACHA_OUT(8, x8);   SN_CHACHA_OUT(9, x9);   SN_CHACHA_OUT(10, x10); SN_CHACHA_OUT(11, x11);
    SN_CHACHA_OUT(12, x12); SN_CHACHA_OUT(13, x13); SN_CHACHA_OUT(14, x14); SN_CHACHA_OUT(15, x15);
#undef SN_CHACHA_OUT
}

/* XOR len bytes of keystream over msg->out, starting at block counter ctr. */
static inline void chacha20_xor_opt(const uint8_t key[32], const uint8_t nonce[12],
                                    uint32_t ctr, const uint8_t *msg, size_t len,
                                    uint8_t *out) {
    uint32_t st[16];
    st[0]=0x61707865; st[1]=0x3320646e; st[2]=0x79622d32; st[3]=0x6b206574;
    memcpy(&st[4], key, 32);
    st[12]=ctr;
    memcpy(&st[13], nonce, 12);
    uint8_t blk[64];
    while (len >= 64) {
        chacha20_block_opt(st, blk);
        for (int i = 0; i < 64; i++) out[i] = msg[i] ^ blk[i];
        st[12]++; msg += 64; out += 64; len -= 64;
    }
    if (len) {
        chacha20_block_opt(st, blk);
        for (size_t i = 0; i < len; i++) out[i] = msg[i] ^ blk[i];
    }
    /* The last keystream block (block 0 is the Poly1305 one-time key) and the
     * state's copy of the key would otherwise sit in this dead frame. */
    sodium_memzero(blk, sizeof(blk));
    sodium_memzero(st, sizeof(st));
}
