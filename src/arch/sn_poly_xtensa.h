/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Poly1305 (32-bit limb) for Xtensa.
 *
 * libsodium's donna32 measures 6.86 MB/s on an ESP32 @240MHz. The cost is the
 * 5x26-bit limb multiply-accumulate. Xtensa LX6 has a 32x32->32 multiplier
 * (MUL32) but no widening 32x32->64 in the base ISA, so the 64-bit products the
 * classic donna32 code needs are synthesized. Keeping the accumulator in locals
 * and hoisting the precomputed r*5 terms cuts the reload traffic.
 *
 * This is the standard donna-style 26-bit-limb algorithm, restructured; it is NOT
 * a new construction. Verified against libsodium on-device.
 */
#pragma once
/* Built ONLY on Xtensa (see sn_wire.c); the host and non-Xtensa targets use
 * libsodium. Equivalence is pinned by the §15 golden vectors and by an on-device
 * check against libsodium (benchmark/shieldnet-esp32). */
#include <stdint.h>
#include <string.h>

#include <sodium.h> /* sodium_memzero */

typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t  buf[16];
    size_t   leftover;
    int      final;
} poly_opt_ctx;

static inline uint32_t ld32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static inline void st32le(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

static void poly_opt_init(poly_opt_ctx *st, const uint8_t key[32]) {
    st->r[0] = (ld32le(key +  0)     ) & 0x3ffffff;
    st->r[1] = (ld32le(key +  3) >> 2) & 0x3ffff03;
    st->r[2] = (ld32le(key +  6) >> 4) & 0x3ffc0ff;
    st->r[3] = (ld32le(key +  9) >> 6) & 0x3f03fff;
    st->r[4] = (ld32le(key + 12) >> 8) & 0x00fffff;
    for (int i = 0; i < 5; i++) st->h[i] = 0;
    for (int i = 0; i < 4; i++) st->pad[i] = ld32le(key + 16 + 4 * i);
    st->leftover = 0;
    st->final = 0;
}

static void poly_opt_blocks(poly_opt_ctx *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1UL << 24);
    const uint32_t r0=st->r[0], r1=st->r[1], r2=st->r[2], r3=st->r[3], r4=st->r[4];
    const uint32_t s1=r1*5, s2=r2*5, s3=r3*5, s4=r4*5;   /* hoisted */
    uint32_t h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];

    while (bytes >= 16) {
        h0 += (ld32le(m +  0)     ) & 0x3ffffff;
        h1 += (ld32le(m +  3) >> 2) & 0x3ffffff;
        h2 += (ld32le(m +  6) >> 4) & 0x3ffffff;
        h3 += (ld32le(m +  9) >> 6) & 0x3ffffff;
        h4 += (ld32le(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;  c = h0 >> 26;  h0 &= 0x3ffffff;
        h1 += c;

        m += 16; bytes -= 16;
    }
    st->h[0]=h0; st->h[1]=h1; st->h[2]=h2; st->h[3]=h3; st->h[4]=h4;
}

static void poly_opt_finish(poly_opt_ctx *st, uint8_t mac[16]) {
    if (st->leftover) {
        size_t i = st->leftover;
        st->buf[i++] = 1;
        for (; i < 16; i++) st->buf[i] = 0;
        st->final = 1;
        poly_opt_blocks(st, st->buf, 16);
    }
    uint32_t h0=st->h[0], h1=st->h[1], h2=st->h[2], h3=st->h[3], h4=st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1UL << 26);

    uint32_t mask = (g4 >> 31) - 1;      /* 0xffffffff if g >= p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    uint64_t f;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    st32le(mac + 0, h0); st32le(mac + 4, h1);
    st32le(mac + 8, h2); st32le(mac + 12, h3);
}

/* One-shot: mac = Poly1305(key, m[0..len)) */
static inline void poly1305_opt(uint8_t mac[16], const uint8_t *m, size_t len,
                                const uint8_t key[32]) {
    poly_opt_ctx st;
    poly_opt_init(&st, key);
    size_t n = len & ~(size_t)15;
    if (n) poly_opt_blocks(&st, m, n);
    st.leftover = len - n;
    if (st.leftover) memcpy(st.buf, m + n, st.leftover);
    poly_opt_finish(&st, mac);
    sodium_memzero(&st, sizeof(st)); /* r and s (pad) are the one-time key */
}
