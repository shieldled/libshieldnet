/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_source.h"

#include <string.h>

void sn_canonical_source(const uint8_t a16[16], uint16_t port, uint8_t out18[18]) {
    memcpy(out18, a16, 16);
    out18[16] = (uint8_t)(port >> 8);
    out18[17] = (uint8_t)(port & 0xff);
}

static int is_mapped(const uint8_t a16[16]) {
    static const uint8_t pfx[12] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff };
    return memcmp(a16, pfx, 12) == 0;
}

/* v4 octets of a mapped address are a16[12..15]. */
static int rejected4(const uint8_t a16[16]) {
    const uint8_t *b = a16 + 12;
    if (b[0] >= 224 && b[0] <= 239) return 1;                 /* 224.0.0.0/4 multicast */
    if (b[0]==255 && b[1]==255 && b[2]==255 && b[3]==255) return 1; /* 255.255.255.255 */
    if (b[0] == 0)   return 1;                                /* 0.0.0.0/8 */
    if (b[0] == 127) return 1;                                /* 127.0.0.0/8 */
    return 0;
}

static int rejected6(const uint8_t a16[16]) {
    if (a16[0] == 0xff) return 1;                             /* ff00::/8 multicast */
    /* :: and ::1 */
    int hi_zero = 1;
    for (int i = 0; i < 15; i++) if (a16[i]) { hi_zero = 0; break; }
    if (hi_zero && (a16[15] == 0 || a16[15] == 1)) return 1;
    /* ::/96 IPv4-compatible: first 12 octets zero (:: and ::1 handled above) */
    int lo96_zero = 1;
    for (int i = 0; i < 12; i++) if (a16[i]) { lo96_zero = 0; break; }
    if (lo96_zero) return 1;
    return 0;
}

/* subnet broadcast of a v4 prefix into out[12..15]; host = all ones below `bits`.
 * The caller guarantees 0 <= bits <= 32, so every write lands in out16[12..15]. */
static void subnet_broadcast(const sn_prefix *p, uint8_t out16[16]) {
    memcpy(out16, p->a16, 16);
    int host = 32 - p->bits;
    for (int i = 0; i < host; i++) {
        int byte_idx = 15 - i / 8;
        out16[byte_idx] |= (uint8_t)(1u << (i % 8));
    }
}

int sn_source_rejected(int is_v4, const uint8_t a16[16],
                       const sn_prefix *local, size_t n_local) {
    /* Own-interface address (either family) and v4 subnet broadcast. */
    for (size_t i = 0; i < n_local; i++) {
        if (memcmp(local[i].a16, a16, 16) == 0) return 1;
        if (is_v4 && local[i].is_v4) {
            /* An out-of-range prefix has no broadcast to compute (and would index
             * outside a16 below): a misconfigured interface table fails closed,
             * which bring-up notices at once, rather than silently skipping the
             * broadcast reject. */
            if (local[i].bits < 0 || local[i].bits > 32) return 1;
            /* /31 (RFC 3021 point-to-point) and /32 have no broadcast address:
             * the all-ones host is the peer, or this interface itself. */
            if (local[i].bits >= 31) continue;
            uint8_t bcast[16];
            /* mask the interface addr to its network, then set host bits */
            sn_prefix masked = local[i];
            int host = 32 - masked.bits;
            for (int b = 0; b < host; b++) {
                int byte_idx = 15 - b / 8;
                masked.a16[byte_idx] &= (uint8_t)~(1u << (b % 8));
            }
            subnet_broadcast(&masked, bcast);
            if (memcmp(bcast, a16, 16) == 0) return 1;
        }
    }
    if (is_v4) return rejected4(a16);
    /* A v4-mapped address arriving as a genuine v6 source is rejected. */
    if (is_mapped(a16)) return 1;
    return rejected6(a16);
}

int sn_source_rejected_a16(const uint8_t a16[16], const sn_prefix *local, size_t n_local) {
    return sn_source_rejected(is_mapped(a16), a16, local, n_local);
}
