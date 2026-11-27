/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet envelope path, promotion, and established dispatch — §8.1, §8.5,
 * §8.6 of shieldnet-protocol design/transport.md, over the vendored raw ikcp and the §10 locks
 * (shieldnet_os). This is the device (responder) role; the controller side lives
 * in goshieldnet.
 *
 * Concurrency: kcp_lock is a shieldnet_os mutex (held across a flush and, in
 * promotion, continuously across (a)(b)(c)); rec_lock a shieldnet_os critical
 * section (short, record/primary metadata). §10.3 orders kcp_lock before rec_lock.
 * The host build exercises the logic and (under TSan) data races; it cannot
 * reproduce the ESP32-only spinlock/lock-order hazards (§10, and shieldnet_os.h).
 */

#include "shieldnet/sn_device.h"
#include "shieldnet_log.h"

#include <sodium.h>
#include <string.h>

#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_replay.h"
#include "ikcp.h"

#define KCP_CMD_PUSH 81 /* IKCP_CMD_PUSH (vendor/ikcp.c) */

#define SN_KCP_DEAD ((uint32_t)-1)  /* kcp->state when dead-link latches */

static void sn_kcp_rebase(ikcpcb *kcp, uint32_t now); /* §9.4, defined below */

static void be4(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}

/* read the big-endian seq_wire[4] that precedes the 16-octet tag (§3.6). */
static uint32_t read_seq_wire(const uint8_t *datagram, size_t len) {
    const uint8_t *p = datagram + (len - SN_ENVELOPE_LEN);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

/* ── §8.4 output callback ──────────────────────────────────────────────────
 * Called from ikcp_flush (under kcp_lock) with a raw KCP datagram to emit. Seals
 * it under the primary's k_kcp_s2c with a fresh s2c seq_full (fail-closed CAS),
 * and hands the sealed datagram to the device's send sink. */
static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    (void)kcp;
    sn_device *d = user;
    if (!d->primary.active || (d->send_dgram == NULL && d->send_dgram_to == NULL) ||
        len <= 0) {
        return 0;
    }
    uint64_t seq;
    if (!sn_sender_alloc(&d->primary.s2c_seq, &seq)) {
        return 0; /* seq space exhausted: fail closed (§3.6), drop */
    }
    uint8_t out[SN_WIRE_MTU + SN_ENVELOPE_LEN];
    size_t out_len = 0;
    if (sn_seal(d->primary.k_kcp_s2c, /*c2s=*/0, seq, (const uint8_t *)buf,
                (size_t)len, out, &out_len) != 0) {
        return 0;
    }
    /* primary.tuple is written only under kcp_lock + rec_lock (promotion (c)),
     * and this callback runs under kcp_lock, so it is stable here. */
    if (d->send_dgram_to) {
        d->send_dgram_to(d->send_ctx, out, out_len, d->primary.tuple);
    } else {
        d->send_dgram(d->send_ctx, out, out_len);
    }
    return 0;
}

static void configure_kcp(ikcpcb *kcp, const sn_kcp_tuning *t) {
    ikcp_setmtu(kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN); /* 1380 (§8.4) */
    ikcp_nodelay(kcp, t->nodelay, t->interval, t->resend, t->nc);
    /* Stream mode MUST be set before ikcp_wndsize: the window setter only honours
     * an rcv_wnd below IKCP_WND_RCV (128) when kcp->stream is already non-zero,
     * and silently clamps upward otherwise. Setting it afterwards left every
     * session committed to 128 segments (~179 KB at MTU) instead of the
     * configured ceiling. */
    kcp->stream = 1; /* byte stream — the app layer (protocol.c) reads exact bytes */
    ikcp_wndsize(kcp, t->snd_wnd, t->rcv_wnd); /* §11: rcv_wnd is the buffer ceiling */
}

void sn_device_set_tuning(sn_device *d, sn_kcp_tuning tuning) { d->tuning = tuning; }

/* ── setup ─────────────────────────────────────────────────────────────────── */

void sn_device_locks_init(sn_device *d) {
    d->kcp_lock = shieldnet_mutex_create();
    shieldnet_crit_init(&d->rec_lock);
    d->data_ready = shieldnet_signal_create();
    d->locks_ready = 1;
}

void sn_device_locks_free(sn_device *d) {
    if (d->kcp_lock) {
        shieldnet_mutex_destroy(d->kcp_lock);
        d->kcp_lock = NULL;
    }
    if (d->data_ready) {
        shieldnet_signal_destroy(d->data_ready);
        d->data_ready = NULL;
    }
    d->locks_ready = 0;
}

void sn_device_set_send(sn_device *d,
                        void (*fn)(void *ctx, const uint8_t *buf, size_t len),
                        void *ctx) {
    d->send_dgram = fn;
    d->send_dgram_to = NULL;
    d->send_ctx = ctx;
}

void sn_device_set_send_to(sn_device *d,
                           void (*fn)(void *ctx, const uint8_t *buf, size_t len,
                                      const uint8_t dst[18]),
                           void *ctx) {
    d->send_dgram = NULL;
    d->send_dgram_to = fn;
    d->send_ctx = ctx;
}

static void kcp_lock(sn_device *d) {
    shieldnet_mutex_lock(d->kcp_lock, SHIELDNET_OS_WAIT_FOREVER);
}
static void kcp_unlock(sn_device *d) { shieldnet_mutex_unlock(d->kcp_lock); }
static void rec_lock(sn_device *d) { shieldnet_crit_enter(&d->rec_lock); }
static void rec_unlock(sn_device *d) { shieldnet_crit_exit(&d->rec_lock); }

/* §9.4 / transport 12.4: KCP declared the link dead, on whichever path ran the
 * update that found it -- the tick, the RX flush or the send path -- so stop
 * output and retain the session. Called with kcp_lock held after every
 * ikcp_update on the primary; takes rec_lock under it, as the tick does. */
static void latch_dead_link(sn_device *d) {
    if (d->primary.kcp->state == SN_KCP_DEAD) {
        rec_lock(d);
        d->primary.quiesced = 1;
        rec_unlock(d);
    }
}

#ifdef SN_TEST_HOOKS
void (*sn_test_promote_hook)(sn_device *d) = NULL;
#endif

/* ── §8.5 promotion ─────────────────────────────────────────────────────────
 * Called with kcp_lock held continuously. pi is the pending slot; claimed_gen is
 * the pending_generation copied at §8.1 step 2; seq the reconstructed candidate;
 * plaintext the decrypted first KCP datagram. Returns SN_ENV_PROMOTED or DROP. */
static sn_env_result promote(sn_device *d, int pi, uint32_t claimed_gen, uint64_t seq,
                             const uint8_t *plaintext, size_t pt_len, uint32_t now32) {
    /* (a) Claim — rec_lock inside kcp_lock. */
    rec_lock(d);
    sn_pending *r = &d->pending[pi];
    /* (a)1 re-check exists, unexpired, pending_generation unchanged */
    if (!r->used || (int32_t)(r->expiry - now32) <= 0 || r->generation != claimed_gen) {
        rec_unlock(d);
        return SN_ENV_DROP;
    }
    /* (a)2 accept-test against the record's CURRENT window — no mark yet */
    if (!sn_replay_would_accept(&r->c2s_window, seq)) {
        rec_unlock(d);
        return SN_ENV_DROP;
    }
    /* (a)3 require KCP PUSH sn==0 on the first segment; else drop WITHOUT marking */
    if (pt_len < 24 || plaintext[4] != KCP_CMD_PUSH) {
        rec_unlock(d);
        return SN_ENV_DROP;
    }
    uint32_t sn = (uint32_t)plaintext[12] | ((uint32_t)plaintext[13] << 8) |
                  ((uint32_t)plaintext[14] << 16) | ((uint32_t)plaintext[15] << 24);
    if (sn != 0) {
        rec_unlock(d);
        return SN_ENV_DROP;
    }
    /* (a)4 mark, increment pending_generation (claim), copy everything (c) installs */
    sn_replay_test_and_mark(&r->c2s_window, seq);
    r->generation = d->gen_ctr++;
    uint32_t my_claim = r->generation; /* the claim value, captured before the buffer is wiped */
    memcpy(d->promo.k_c2s, r->k_c2s, 32);
    memcpy(d->promo.k_s2c, r->k_s2c, 32);
    memcpy(d->promo.k_kcp_c2s, r->k_kcp_c2s, 32);
    memcpy(d->promo.k_kcp_s2c, r->k_kcp_s2c, 32);
    memcpy(d->promo.tuple, r->tuple, 18);
    d->promo.window = r->c2s_window; /* the just-marked window (hwm AND bitmap) */
    d->promo.generation = r->generation;
    d->promo.filled = 1;
    /* (a)5 retire the outgoing primary: invalidate, detach — nothing freed yet */
    ikcpcb *retired_kcp = NULL;
    uint8_t retired_keys[4][32];
    int had_primary = d->primary.active;
    if (had_primary) {
        /* Stale any copy taken before this, with a value of its own. A bare
         * generation++ landed on exactly the new_gen below (the two counters
         * move together), so a reader between (a) and (c) saw the NEW session's
         * generation next to the keys just wiped here -- and bound to it. */
        d->primary.generation = ++d->promo_gen;
        retired_kcp = d->primary.kcp;
        memcpy(retired_keys[0], d->primary.k_c2s, 32);
        memcpy(retired_keys[1], d->primary.k_s2c, 32);
        memcpy(retired_keys[2], d->primary.k_kcp_c2s, 32);
        memcpy(retired_keys[3], d->primary.k_kcp_s2c, 32);
        /* Wipe the canonical primary key storage now (§8.5 wipe-before-free). The
         * success path's (c) would overwrite these, but the allocation-failure
         * path has no (c) — without this the retired keys would sit in d->primary
         * indefinitely while promotions keep failing (§9.5). */
        sodium_memzero(d->primary.k_c2s, 32);
        sodium_memzero(d->primary.k_s2c, 32);
        sodium_memzero(d->primary.k_kcp_c2s, 32);
        sodium_memzero(d->primary.k_kcp_s2c, 32);
        d->primary.active = 0; /* detached: no lookup resolves it */
        /* Null the pointer with the flag. The allocation-failure branch below
         * releases retired_kcp, and every reader gates on `active`, so a stale
         * d->primary.kcp is unreachable today -- but it is a freed pointer left
         * in a live struct, and sn_device_release_primary and the tick both
         * dereference it under `active` alone. */
        d->primary.kcp = NULL;
    }
    uint32_t new_gen = ++d->promo_gen;
    uint32_t conv = ikcp_getconv(plaintext);
    rec_unlock(d);
#ifdef SN_TEST_HOOKS
    /* between (a) and (b)/(c): kcp_lock held, rec_lock released (sn_device.h) */
    if (sn_test_promote_hook != NULL) sn_test_promote_hook(d);
#endif

    /* (b) Build — kcp_lock only (rec_lock nested only in the failure branch). */
    ikcpcb *new_kcp = ikcp_create(conv, d);
    if (new_kcp == NULL) {
        /* allocation-failure branch (§8.5): wipe the buffer (2nd live key copy),
         * discard the claimed record only if its generation still equals the
         * claim (rec_lock nested here), then wipe+free the already-retired primary. */
        sodium_memzero(&d->promo, sizeof(d->promo));
        rec_lock(d);
        if (r->used && r->generation == my_claim) {
            sodium_memzero(r->k_c2s, 32); sodium_memzero(r->k_s2c, 32);
            sodium_memzero(r->k_kcp_c2s, 32); sodium_memzero(r->k_kcp_s2c, 32);
            r->used = 0;
        }
        rec_unlock(d);
        if (had_primary) {
            sodium_memzero(retired_keys, sizeof(retired_keys));
            ikcp_release(retired_kcp);
        }
        return SN_ENV_DROP;
    }
    ikcp_setoutput(new_kcp, kcp_output);
    configure_kcp(new_kcp, &d->tuning);
    sn_sender_init(&d->primary.s2c_seq); /* s2c seq_full = 1 BEFORE feeding (§8.5b) */
    ikcp_input(new_kcp, (const char *)plaintext, (long)pt_len);
    /* wipe and free the retired primary now that the new object exists and is fed */
    if (had_primary) {
        sodium_memzero(retired_keys, sizeof(retired_keys));
        ikcp_release(retired_kcp);
    }

    /* (c) Install — rec_lock inside kcp_lock. Everything from the buffer. */
    rec_lock(d);
    d->primary.active = 1;
    d->primary.kcp = new_kcp;
    memcpy(d->primary.k_c2s, d->promo.k_c2s, 32);
    memcpy(d->primary.k_s2c, d->promo.k_s2c, 32);
    memcpy(d->primary.k_kcp_c2s, d->promo.k_kcp_c2s, 32);
    memcpy(d->primary.k_kcp_s2c, d->promo.k_kcp_s2c, 32);
    memcpy(d->primary.tuple, d->promo.tuple, 18);
    d->primary.c2s_window = d->promo.window; /* already-marked, NOT re-initialised */
    d->primary.generation = new_gen;
    d->primary.app_s2c_next = 1; /* §13: fresh k_s2c, so MessageNum starts again */
    d->primary.conv = conv;
    d->primary.quiesced = 0;
    /* s2c seq_full already 1 (set in (b), §8.5). */
    sodium_memzero(&d->promo, sizeof(d->promo)); /* wipe the buffer once installed */
    /* §8.5 (c): clear the pending record and wipe its keys, only if its generation
     * still equals the claim. No reaper visits a cleared slot, so unwiped copies
     * would outlive the primary. The generation guard leaves a slot re-claimed by
     * a concurrent FINISH untouched. */
    if (r->used && r->generation == my_claim) {
        sodium_memzero(r->k_c2s, 32); sodium_memzero(r->k_s2c, 32);
        sodium_memzero(r->k_kcp_c2s, 32); sodium_memzero(r->k_kcp_s2c, 32);
        r->used = 0;
    }
    rec_unlock(d);
    /* §8.4/§12: ACK the promoting PUSH now, exactly as the established RX path
     * does. Without this the first PUSH is only ACKed when the §9.2 tick next
     * runs — and if the tick is slow or stalled the client never sees an ACK, its
     * window never opens, it stops sending, and no further datagram arrives to
     * drive the RX-path flush: a deadlock right after a successful promotion.
     * Observed on hardware: promotion succeeded, the agent dispatched the first
     * message, then the session went silent with the client blocked on a full
     * send window. kcp_lock is still held here; rec_lock is released above, as
     * §10.3 requires for a flush. */
    ikcp_update(new_kcp, now32);
    return SN_ENV_PROMOTED;
}

/* ── §8.1 receive + §8.6 established ─────────────────────────────────────────
 * Try the primary candidate, then the pending record for this tuple. */
sn_env_result sn_handle_envelope(sn_device *d, const uint8_t *datagram, size_t len,
                                 const uint8_t src_a16[16], uint16_t src_port,
                                 uint64_t now_ms) {
    /* step 1: §3.6 size bounds */
    if (len < (size_t)(24 + SN_ENVELOPE_LEN) || len > (size_t)SN_WIRE_MTU) {
        return SN_ENV_DROP;
    }
    uint8_t tuple[18];
    sn_canonical_source(src_a16, src_port, tuple);
    uint32_t now32 = (uint32_t)now_ms;

    /* step 2: copy candidates under rec_lock (primary first) */
    rec_lock(d);
    int have_primary = d->primary.active && memcmp(d->primary.tuple, tuple, 18) == 0;
    uint8_t prim_key[32];
    uint64_t prim_hwm = 0;
    uint32_t prim_gen = 0;
    if (have_primary) {
        memcpy(prim_key, d->primary.k_kcp_c2s, 32);
        prim_hwm = d->primary.c2s_window.hwm;
        prim_gen = d->primary.generation;
    }
    int pi = sn_find_pending_index(d, tuple);
    if (pi >= 0 && (int32_t)(d->pending[pi].expiry - now32) <= 0) {
        /* discard-on-expiry (§8.1 step 2 / §6.3) */
        sodium_memzero(d->pending[pi].k_c2s, 32); sodium_memzero(d->pending[pi].k_s2c, 32);
        sodium_memzero(d->pending[pi].k_kcp_c2s, 32); sodium_memzero(d->pending[pi].k_kcp_s2c, 32);
        d->pending[pi].used = 0;
        pi = -1;
    }
    int have_pending = pi >= 0;
    uint8_t pend_key[32];
    uint64_t pend_hwm = 0;
    uint32_t pend_claim = 0;
    if (have_pending) {
        memcpy(pend_key, d->pending[pi].k_kcp_c2s, 32);
        pend_hwm = d->pending[pi].c2s_window.hwm;
        pend_claim = d->pending[pi].generation;
    }
    rec_unlock(d);

    if (!have_primary && !have_pending) {
        return SN_ENV_DROP; /* neither key copy was written */
    }

    uint8_t pt[SN_WIRE_MTU];
    size_t pt_len = 0;

    /* step 3: try the primary first — reconstruct + range + AEAD open, no lock */
    if (have_primary) {
        int64_t cand = sn_reconstruct(read_seq_wire(datagram, len), prim_hwm);
        if (sn_in_range(cand, prim_hwm) &&
            sn_open(prim_key, /*c2s=*/1, (uint64_t)cand, datagram, len, pt, &pt_len) == 0) {
            /* §8.6 established — kcp_lock, then rec_lock for the re-check + mark */
            kcp_lock(d);
            rec_lock(d);
            int ok = d->primary.active && d->primary.generation == prim_gen &&
                     memcmp(d->primary.tuple, tuple, 18) == 0;
            if (ok) {
                ok = sn_replay_test_and_mark(&d->primary.c2s_window, (uint64_t)cand);
            }
            uint32_t conv = d->primary.conv;
            rec_unlock(d);
            sn_env_result res = SN_ENV_DROP;
            if (ok) {
                if (ikcp_getconv(pt) == conv &&
                    ikcp_input(d->primary.kcp, (const char *)pt, (long)pt_len) == 0) {
                    rec_lock(d); /* §10.3: quiesced is rec_lock state */
                    int was_quiesced = d->primary.quiesced;
                    d->primary.quiesced = 0;        /* §9.1 quiesced -> live */
                    rec_unlock(d);
                    if (d->data_ready) shieldnet_signal_post(d->data_ready);
                    if (was_quiesced) {
                        /* §9.4 resume: re-base in place, never recreate. kcp_lock held. */
                        sn_kcp_rebase(d->primary.kcp, now32);
                    }
                    /* §8.4/§12: the RX path flushes to emit ACKs. Without this the
                     * peer's window only drains at the §9.2 tick cadence, and a
                     * sustained inbound stream collapses — measured over Wi-Fi as a
                     * fall from ~0.45 MB/s to ~0.005 MB/s with the device idle
                     * (rcv_que=0) while the sender's writes blocked for ~800 ms.
                     * §10.3 requires rec_lock be RELEASED before this flush (it is,
                     * just above) and the callback must not re-enter it (§10.1). */
                    ikcp_update(d->primary.kcp, now32);
                    latch_dead_link(d);
                    res = SN_ENV_ESTABLISHED;
                }
            }
            kcp_unlock(d);
            sodium_memzero(pt, sizeof(pt));
            sodium_memzero(prim_key, sizeof(prim_key));
            sodium_memzero(pend_key, sizeof(pend_key));
            return res;
        }
    }

    /* step 3 cont.: fall through to the pending record (promotion) */
    if (have_pending) {
        int64_t cand = sn_reconstruct(read_seq_wire(datagram, len), pend_hwm);
        if (sn_in_range(cand, pend_hwm) &&
            sn_open(pend_key, /*c2s=*/1, (uint64_t)cand, datagram, len, pt, &pt_len) == 0) {
            kcp_lock(d);
            sn_env_result res = promote(d, pi, pend_claim, (uint64_t)cand, pt, pt_len, now32);
            kcp_unlock(d);
            if (res == SN_ENV_PROMOTED && d->data_ready) shieldnet_signal_post(d->data_ready);
            sodium_memzero(pt, sizeof(pt));
            sodium_memzero(prim_key, sizeof(prim_key));
            sodium_memzero(pend_key, sizeof(pend_key));
            return res;
        }
    }
    sodium_memzero(pt, sizeof(pt));
    sodium_memzero(prim_key, sizeof(prim_key));
    sodium_memzero(pend_key, sizeof(pend_key));
    return SN_ENV_DROP;
}

/* ── app I/O over the primary ─────────────────────────────────────────────── */

int sn_primary_recv_gen(sn_device *d, uint32_t gen, uint8_t *buf, int cap) {
    kcp_lock(d);
    int n = -1;
    /* Only the session that owns `gen` may consume from the stream. Without this
     * a retiring agent -- still inside its read when a new primary is promoted --
     * reads d->primary.kcp, which is by then the *new* session's kcp, and eats
     * its opening bytes into a carry buffer it is about to discard. The new
     * session then starts mid-frame and desyncs on its first header (§8.5). */
    if (d->primary.active && d->primary.generation == gen) {
        n = ikcp_recv(d->primary.kcp, (char *)buf, cap);
        if (n < 0) {
            n = 0; /* nothing ready */
        }
    }
    kcp_unlock(d);
    return n;
}

int sn_primary_recv(sn_device *d, uint8_t *buf, int cap) {
    kcp_lock(d);
    uint32_t gen = d->primary.generation;
    kcp_unlock(d);
    return sn_primary_recv_gen(d, gen, buf, cap);
}

int sn_primary_send(sn_device *d, const uint8_t *msg, int len, uint32_t now_ms) {
    kcp_lock(d);
    uint32_t gen = d->primary.generation;
    kcp_unlock(d);
    return sn_primary_send_gen(d, gen, msg, len, now_ms);
}

int sn_primary_send_gen(sn_device *d, uint32_t gen, const uint8_t *msg, int len,
                        uint32_t now_ms) {
    kcp_lock(d);
    int rc = -1;
    /* The generation is written only under kcp_lock (promotion holds it across
     * (a)(b)(c)), so this check holds for the whole send -- the same guard
     * sn_primary_recv_gen applies to the read side. */
    if (d->primary.active && d->primary.generation == gen) {
        /* §9.4: while quiesced the device stops output but retains the session.
         * The write still queues; the flush waits for the resume re-base on the
         * RX path, which is the only thing that may clear the dead-link. */
        rec_lock(d);
        int quiesced = d->primary.quiesced;
        rec_unlock(d);
        /* §9.5: refuse rather than grow the queue against a vanished peer, and
         * refuse rather than drop silently. ikcp_waitsnd counts snd_buf plus
         * snd_queue segments; mss is the post-MTU payload each one carries.
         * Charge the segments this message will occupy, not one: a single large
         * write otherwise passes the check and then queues dozens. */
        int mss = (int)d->primary.kcp->mss;
        int segs = mss > 0 && len > 0 ? (len + mss - 1) / mss : 1;
        if ((ikcp_waitsnd(d->primary.kcp) + segs) * mss > SN_SEND_QUEUE_MAX) {
            /* Drive the flush before refusing. §9.5 requires the device to resume
             * accepting writes "once the total falls below the cap", so a caller
             * that retries has to be able to make progress; returning without an
             * update leaves snd_buf unflushed and the queue never drains. */
            if (!quiesced) {
                ikcp_update(d->primary.kcp, now_ms);
                latch_dead_link(d);
            }
            kcp_unlock(d);
            return SN_SEND_QUEUE_FULL;
        }
        rc = ikcp_send(d->primary.kcp, (const char *)msg, len);
        /* ikcp_send reports OOM as -2 -- the same value as SN_SEND_QUEUE_FULL,
         * which io_write retries -- after possibly queuing part of the message.
         * A retry would then put those bytes in the stream twice. Any failure,
         * or a short send, is fatal to the session; only the cap check above
         * may return SN_SEND_QUEUE_FULL. */
        if (rc != len) rc = -1;
        if (!quiesced) {
            ikcp_update(d->primary.kcp, now_ms);
            latch_dead_link(d);
        }
    }
    kcp_unlock(d);
    return rc;
}

void sn_primary_update(sn_device *d, uint32_t now_ms) {
    kcp_lock(d);
    if (d->primary.active) {
        /* §9.4 / transport 12.4: a quiesced primary MUST stop output, so no
         * retransmission here either; only the RX path's resume restarts it. */
        rec_lock(d);
        int quiesced = d->primary.quiesced;
        rec_unlock(d);
        if (!quiesced) {
            ikcp_update(d->primary.kcp, now_ms);
            latch_dead_link(d);
        }
    }
    kcp_unlock(d);
}

/* ── §9.4 dead-link quiesce / resume ─────────────────────────────────────────
 * On KCP dead-link the device stops output but retains the session; resume MUST
 * NOT recreate the object (a fresh object desyncs sequence state permanently).
 * Clear the latched state in place and re-base every stored timestamp against the
 * current clock, so the signed-32-bit _itimediff comparisons inside ikcp cannot
 * invert after a long quiesce (§9.4). kcp_lock-only work (§10.2). */
#define SN_KCP_RTO_DEF 200          /* IKCP_RTO_DEF (vendor/ikcp.c) */

static void sn_kcp_rebase(ikcpcb *kcp, uint32_t now) {
    kcp->state = 0; /* clear the latched dead-link */
    kcp->rx_rto = SN_KCP_RTO_DEF;   /* not IKCP_RTO_MAX, or the first loss stalls 60s;
                                     * reset BEFORE the segments copy it */
    struct IQUEUEHEAD *p;
    for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
        struct IKCPSEG *seg = iqueue_entry(p, struct IKCPSEG, node);
        seg->xmit = 0;              /* else the first flush re-latches immediately */
        seg->rto = (uint32_t)kcp->rx_rto;
        seg->resendts = now;        /* re-base */
        seg->ts = now;
    }
    kcp->probe = 0;
    kcp->probe_wait = 0;
    kcp->ts_probe = now;
    kcp->ts_flush = now;            /* the one that must not be missed (§9.4) */
}

/* ── §9.2 maintenance tick ───────────────────────────────────────────────────
 * Runs in every lifecycle state (§9.2): rolls the cached epoch_tag on a boundary
 * (§4.4, HMAC computed OUTSIDE rec_lock per §10.3), sweeps pending-slot expiry
 * (§6.3), and drives the primary's KCP. Not the admission timer §9.2 forbids: it
 * sends nothing of its own and retransmits only KCP's established ARQ. now_ms is
 * the 64-bit clock (§2); now_ms_lo is its low-32 KCP timebase. */
void sn_device_tick(sn_device *d, uint32_t now_ms_lo, uint64_t now_ms) {
    /* epoch roll — HMAC outside any lock (§10.3 forbids crypto under rec_lock) */
    uint32_t ep = (uint32_t)(now_ms / SN_COOKIE_EPOCH_MS);
    rec_lock(d);
    uint32_t cur = d->cookie_epoch;
    int have = d->have_epoch;
    rec_unlock(d);
    if (!have || ep != cur) {
        uint8_t epb[4];
        be4(ep, epb);
        uint8_t newtag[8];
        sn_epoch_tag(d->cookie_secret, epb, newtag); /* no lock held */
        rec_lock(d);
        if (d->cookie_epoch == cur) { /* nobody rolled in between */
            /* §4.4: the outgoing tag is "previous" only if it is exactly ep-1. A
             * tick that stalled across several epochs drops it instead -- carrying
             * it forward kept cookies valid for the whole stall. */
            if (have && ep - cur == 1) {
                memcpy(d->prev_epoch_tag, d->epoch_tag, 8);
                d->prev_epoch = cur;
                d->have_prev = 1;
            } else {
                memset(d->prev_epoch_tag, 0, 8);
                d->have_prev = 0;
            }
            memcpy(d->epoch_tag, newtag, 8);
            d->cookie_epoch = ep;
            d->have_epoch = 1;
        }
        rec_unlock(d);
    }

    /* pending expiry sweep (§6.3): wipe the four keys of every expired slot */
    rec_lock(d);
    for (int i = 0; i < SN_PENDING_SLOTS; i++) {
        if (d->pending[i].used && (int32_t)(d->pending[i].expiry - now_ms_lo) <= 0) {
            sodium_memzero(d->pending[i].k_c2s, 32); sodium_memzero(d->pending[i].k_s2c, 32);
            sodium_memzero(d->pending[i].k_kcp_c2s, 32); sodium_memzero(d->pending[i].k_kcp_s2c, 32);
            d->pending[i].used = 0;
        }
    }
    rec_unlock(d);

    /* drive the primary's KCP ARQ, unless quiesced (§9.4 stops retransmit work) */
    kcp_lock(d);
    if (d->primary.active) {
        rec_lock(d);
        int quiesced = d->primary.quiesced;
        rec_unlock(d);
        if (!quiesced) {
            ikcp_update(d->primary.kcp, now_ms_lo);
            latch_dead_link(d);  /* §9.4: stop output, retain session */
        }
    }
    kcp_unlock(d);
}

/* ── tick thread ─────────────────────────────────────────────────────────────
 * Runs sn_device_tick on a fixed cadence over shieldnet_os. Single deletion owner
 * (shieldnet_os.h teardown contract): fn returns on the stop signal, posts done,
 * then the stop path joins via release. */
typedef struct {
    sn_device *dev;
    shieldnet_signal_t *stop;
    shieldnet_signal_t *done;
    shieldnet_thread_t *thread;
    uint64_t base_ms; /* clock base captured at start (host has no fixed epoch) */
    uint32_t interval_ms;
} sn_tick_ctx;

static sn_tick_ctx g_tick; /* one device per process on the host; boards own theirs */

static void tick_fn(void *arg) {
    sn_tick_ctx *t = arg;
    uint32_t prev = shieldnet_os_now_ms();
    while (!shieldnet_signal_wait(t->stop, 0)) {
        uint64_t now = shieldnet_os_now_ms64();
        sn_device_tick(t->dev, (uint32_t)now, now);
        shieldnet_os_sleep_until_ms(&prev, t->interval_ms);
    }
    shieldnet_signal_post(t->done);
}

int sn_device_start_tick(sn_device *d, uint32_t interval_ms) {
    g_tick.dev = d;
    g_tick.interval_ms = interval_ms;
    g_tick.stop = shieldnet_signal_create();
    g_tick.done = shieldnet_signal_create();
    if (!g_tick.stop || !g_tick.done ||
        !shieldnet_thread_create(tick_fn, "v3tick", 8192, &g_tick, 5, -1, &g_tick.thread)) {
        /* Release both signals on every failure path. g_tick.thread stays NULL,
         * so sn_device_stop_tick returns early and would never free them; and
         * one of the two may have been created successfully even when the other
         * was not. */
        if (g_tick.stop) { shieldnet_signal_destroy(g_tick.stop); g_tick.stop = NULL; }
        if (g_tick.done) { shieldnet_signal_destroy(g_tick.done); g_tick.done = NULL; }
        g_tick.thread = NULL;
        return -1;
    }
    return 0;
}

void sn_device_stop_tick(void) {
    if (g_tick.thread == NULL) {
        return;
    }
    shieldnet_signal_post(g_tick.stop);
    shieldnet_signal_wait(g_tick.done, SHIELDNET_OS_WAIT_FOREVER);
    shieldnet_thread_release(g_tick.thread);
    shieldnet_signal_destroy(g_tick.stop);
    shieldnet_signal_destroy(g_tick.done);
    g_tick.thread = NULL;
}

/* ── session generation accessors (for a generation-aware agent) ────────────── */

uint32_t sn_device_current_gen(sn_device *d) {
    rec_lock(d);
    uint32_t g = d->primary.generation;
    rec_unlock(d);
    return g;
}

int sn_device_session_active(sn_device *d, uint32_t gen) {
    rec_lock(d);
    int alive = d->primary.active && d->primary.generation == gen;
    rec_unlock(d);
    return alive;
}

int sn_primary_bind_app(sn_device *d, uint32_t *gen, uint8_t k_c2s[32], uint8_t k_s2c[32]) {
    rec_lock(d);
    int active = d->primary.active;
    *gen = d->primary.generation;
    if (active) {
        memcpy(k_c2s, d->primary.k_c2s, 32);
        memcpy(k_s2c, d->primary.k_s2c, 32);
    }
    rec_unlock(d);
    if (!active) {
        sodium_memzero(k_c2s, 32);
        sodium_memzero(k_s2c, 32);
        return -1;
    }
    return 0;
}

int sn_primary_next_s2c_msgnum(sn_device *d, uint32_t gen, uint64_t *msgnum) {
    int rc = -1;
    rec_lock(d);
    /* 0 is the reserved handshake-tag MessageNum, never an app one: a primary
     * still zero-initialised here simply has not started its sequence. */
    if (d->primary.app_s2c_next == 0) d->primary.app_s2c_next = 1;
    if (d->primary.active && d->primary.generation == gen &&
        d->primary.app_s2c_next != UINT64_MAX) {
        *msgnum = d->primary.app_s2c_next++;
        rc = 0;
    }
    rec_unlock(d);
    return rc;
}

void sn_device_end_primary(sn_device *d, uint32_t gen) {
    kcp_lock(d);
    rec_lock(d);
    ikcpcb *k = NULL;
    if (d->primary.active && d->primary.generation == gen) {
        k = d->primary.kcp;
        d->primary.active = 0;
        d->primary.kcp = NULL;
        d->primary.generation = ++d->promo_gen; /* no copy of `gen` matches again */
        sodium_memzero(d->primary.k_c2s, 32);
        sodium_memzero(d->primary.k_s2c, 32);
        sodium_memzero(d->primary.k_kcp_c2s, 32);
        sodium_memzero(d->primary.k_kcp_s2c, 32);
    }
    rec_unlock(d);
    if (k) {
        ikcp_release(k);
    }
    kcp_unlock(d);
    /* Wake a reader blocked on the ended session so it sees it is gone. */
    if (k && d->data_ready) shieldnet_signal_post(d->data_ready);
}

/* Release the primary KCP object at device teardown (§8.5 frees it only on
 * re-promotion, so without this the last session's ikcpcb + its queues leak).
 * Call after the tick and any agent are stopped — nothing may be flushing. */
void sn_device_release_primary(sn_device *d) {
    kcp_lock(d);
    rec_lock(d);
    ikcpcb *k = d->primary.active ? d->primary.kcp : NULL;
    d->primary.active = 0;
    d->primary.kcp = NULL;
    sodium_memzero(d->primary.k_c2s, 32);
    sodium_memzero(d->primary.k_s2c, 32);
    sodium_memzero(d->primary.k_kcp_c2s, 32);
    sodium_memzero(d->primary.k_kcp_s2c, 32);
    rec_unlock(d);
    if (k) {
        ikcp_release(k);
    }
    kcp_unlock(d);
}

void sn_device_wipe(sn_device *d) {
    rec_lock(d);
    for (int i = 0; i < SN_PENDING_SLOTS; i++) {
        sodium_memzero(d->pending[i].k_c2s, 32); sodium_memzero(d->pending[i].k_s2c, 32);
        sodium_memzero(d->pending[i].k_kcp_c2s, 32); sodium_memzero(d->pending[i].k_kcp_s2c, 32);
        d->pending[i].used = 0;
    }
    sodium_memzero(&d->promo, sizeof(d->promo));
    rec_unlock(d);
    sodium_memzero(d->k_dev, 32);
    sodium_memzero(d->k_req, 32);
    sodium_memzero(d->k_resp, 32);
    sodium_memzero(d->cookie_secret, 32);
}
