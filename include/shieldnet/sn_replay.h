/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet replay window, §8.3 range check, and outbound seq_full allocator —
 * §8.2–§8.4 of shieldnet-protocol design/transport.md. Byte-for-byte with goshieldnet/v1/replay.go.
 * Standalone (no KCP): promotion (§8.5) and the primary session that owns these
 * arrive in a later step.
 */
#ifndef SHIELDNET_REPLAY_H
#define SHIELDNET_REPLAY_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "shieldnet/sn_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SN_REPLAY_WINDOW 256 /* REPLAY_WINDOW (§2) */

/* One direction's anti-replay state (§8.2). Bit offset o corresponds to
 * seq = hwm - o. A zeroed window (hwm 0, no marks) accepts the first datagram
 * (seq_full 1, §3.6). */
typedef struct {
    uint64_t hwm;
    uint8_t bits[SN_REPLAY_WINDOW / 8];
} sn_replay_window;

/* §8.3 range check against hwm: candidate ≥ 1 and not more than REPLAY_WINDOW
 * below hwm. A failure falls through like an AEAD failure (§8.1 step 3). */
int sn_in_range(int64_t candidate, uint64_t hwm);

/* §8.2 accept test against the current hwm, marking on acceptance, as one atomic
 * operation (§8.1 step 4). Returns 0 without marking for a replay or aged-out
 * sequence. seq is the reconstructed 64-bit value; call only after the AEAD has
 * verified. */
int sn_replay_test_and_mark(sn_replay_window *w, uint64_t seq);

/* §8.2 accept test WITHOUT marking, for §8.5(a)2 where the sn==0 check (a3) must
 * run before the mark (a4). Returns 1 if seq would be accepted. */
int sn_replay_would_accept(const sn_replay_window *w, uint64_t seq);

/* One §8.1 candidate: reconstruct seq_full (§8.3), range-check, open the AEAD, and
 * on success test-and-mark. Returns 1 and writes the plaintext (out/out_len) and
 * seq_full (*seq_out) on acceptance, or 0 to fall through / drop. key is
 * k_kcp_<dir>. out must hold at least env_len bytes. */
int sn_replay_open(sn_replay_window *w, const uint8_t key[32], int c2s,
                   const uint8_t *datagram, size_t len,
                   uint8_t *out, size_t *out_len, uint64_t *seq_out);

/* Outbound seq_full allocator (§10.1): a lock-free CAS that fails closed on wrap
 * (§3.6), never an atomic add. The stored value is the NEXT seq_full to hand out,
 * starting at 1; a stored 0 is the exhausted sentinel. */
typedef struct {
    _Atomic uint64_t next;
} sn_sender;

void sn_sender_init(sn_sender *s);

/* Writes the next seq_full to *out and returns 1, or returns 0 once exhausted. */
int sn_sender_alloc(sn_sender *s, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_REPLAY_H */
