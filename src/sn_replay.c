/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_replay.h"

#include <string.h>

static int get_bit(const sn_replay_window *w, uint64_t o) {
    return (w->bits[o / 8] >> (o % 8)) & 1;
}

static void put_bit(sn_replay_window *w, uint64_t o, int v) {
    if (v) {
        w->bits[o / 8] |= (uint8_t)(1u << (o % 8));
    } else {
        w->bits[o / 8] &= (uint8_t)~(1u << (o % 8));
    }
}

/* Move every mark up by n offsets; marks past REPLAY_WINDOW age out.
 *
 * Byte-wise, not bit-by-bit: the old version ran a 256-iteration loop for EVERY
 * accepted datagram (n == 1 is the common in-order case), which measured ~69 us
 * per op on an ESP32 @240MHz — about 1000 memory ops on the protocol's hottest
 * path. Shifting whole bytes and OR-ing the carry is the same transformation in
 * a handful of operations. Bit b holds seq (hwm - b), so shifting "up" by n means
 * bit b takes the old bit (b - n) => a left shift of the bit array.
 */
static void shift_up(sn_replay_window *w, uint64_t n) {
    if (n >= SN_REPLAY_WINDOW) {
        memset(w->bits, 0, sizeof(w->bits));
        return;
    }
    const size_t nbytes = sizeof(w->bits);      /* 32 */
    size_t byte_shift = (size_t)(n / 8);
    unsigned bit_shift = (unsigned)(n % 8);

    if (bit_shift == 0) {
        /* whole-byte move: bits[i] <- bits[i - byte_shift] */
        memmove(w->bits + byte_shift, w->bits, nbytes - byte_shift);
        memset(w->bits, 0, byte_shift);
        return;
    }
    for (size_t i = nbytes; i-- > 0;) {
        uint8_t v = 0;
        if (i >= byte_shift) {
            size_t src = i - byte_shift;
            v = (uint8_t)(w->bits[src] << bit_shift);
            if (src > 0) {
                v |= (uint8_t)(w->bits[src - 1] >> (8 - bit_shift));
            }
        }
        w->bits[i] = v;
    }
}

/* `<=` admits offset == SN_REPLAY_WINDOW, one past the last bit the window
 * holds, so such a candidate is opened and then refused by test_and_mark: one
 * wasted AEAD open, never an accepted replay. It stays `<=` because this is the
 * §8.3 range check the Go implementation applies (goshieldnet's inRange), and
 * the two are kept identical on purpose; the differential oracle
 * (fuzz/sn_oracle.c) compares sn_reconstruct, the candidate that feeds it. */
int sn_in_range(int64_t candidate, uint64_t hwm) {
    if (candidate < 1) {
        return 0;
    }
    return (int64_t)hwm - candidate <= SN_REPLAY_WINDOW;
}

int sn_replay_would_accept(const sn_replay_window *w, uint64_t seq) {
    if (seq > w->hwm) {
        return 1;
    }
    uint64_t offset = w->hwm - seq;
    if (offset >= SN_REPLAY_WINDOW || get_bit(w, offset)) {
        return 0;
    }
    return 1;
}

int sn_replay_test_and_mark(sn_replay_window *w, uint64_t seq) {
    if (seq > w->hwm) {
        shift_up(w, seq - w->hwm);
        w->hwm = seq;
        put_bit(w, 0, 1);
        return 1;
    }
    uint64_t offset = w->hwm - seq;
    if (offset >= SN_REPLAY_WINDOW || get_bit(w, offset)) {
        return 0;
    }
    put_bit(w, offset, 1);
    return 1;
}

int sn_replay_open(sn_replay_window *w, const uint8_t key[32], int c2s,
                   const uint8_t *datagram, size_t len,
                   uint8_t *out, size_t *out_len, uint64_t *seq_out) {
    if (len < SN_ENVELOPE_LEN) {
        return 0;
    }
    const uint8_t *sw = datagram + (len - SN_ENVELOPE_LEN); /* seq_wire[4] */
    uint32_t seq_wire = ((uint32_t)sw[0] << 24) | ((uint32_t)sw[1] << 16) |
                        ((uint32_t)sw[2] << 8) | (uint32_t)sw[3];
    int64_t candidate = sn_reconstruct(seq_wire, w->hwm);
    if (!sn_in_range(candidate, w->hwm)) { /* §8.3 → fall through */
        return 0;
    }
    if (sn_open(key, c2s, (uint64_t)candidate, datagram, len, out, out_len) != 0) {
        return 0; /* AEAD failure → fall through */
    }
    if (!sn_replay_test_and_mark(w, (uint64_t)candidate)) { /* replay → drop */
        return 0;
    }
    *seq_out = (uint64_t)candidate;
    return 1;
}

void sn_sender_init(sn_sender *s) { atomic_store(&s->next, (uint64_t)1); }

int sn_sender_alloc(sn_sender *s, uint64_t *out) {
    uint64_t cur = atomic_load(&s->next);
    for (;;) {
        if (cur == 0) {
            return 0; /* exhausted */
        }
        uint64_t nextv = (cur != UINT64_MAX) ? cur + 1 : 0;
        if (atomic_compare_exchange_weak(&s->next, &cur, nextv)) {
            *out = cur;
            return 1;
        }
        /* cur reloaded by the CAS on failure; loop */
    }
}
