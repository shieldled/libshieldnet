/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_client.h"

#include "shieldnet/sn_agent.h"   /* SN_MID_FRAME_BUDGET_MS */
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_kdf.h"

#include "crypto.h"
#include "protocol.h"

#include "ikcp.h"
#include "lz4.h"

#include <limits.h>
#include <sodium.h>
#include <string.h>

/* The send buffer for the largest message the app buffers can carry must hold
 * LZ4's worst case, or an incompressible body would not fit it. */
_Static_assert(SN_CLIENT_COMPRESS_BUF_MIN >= LZ4_COMPRESSBOUND(SN_CS_MSG_MAX + 64),
               "SN_CLIENT_COMPRESS_BUF_MIN must cover LZ4_COMPRESSBOUND of the largest message");

/* Transport 4.2: FINISH_PHASE_MS is less than COOKIE_EPOCH_MS. A deployment
 * that raises it to meet 4.3's FINISH-phase budget (round-trip time plus the
 * device's FINISH processing) must keep it below. */
_Static_assert(SN_FINISH_PHASE_MS < SN_COOKIE_EPOCH_MS,
               "SN_FINISH_PHASE_MS must be below SN_COOKIE_EPOCH_MS (transport 4.2)");

/* ikcp_send refuses a message of this many fragments or more; the same value
 * as sn_client_session.c's private SN_KCP_MAX_FRAGMENTS (IKCP_WND_RCV). */
#define SN_CLIENT_KCP_MAX_FRAGMENTS 128

static void app_on_stream(void *ctx, const uint8_t *msg, size_t len);
static int  app_write(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                      int pad, uint32_t now_ms);

static void fill_random(sn_client *c, uint8_t *buf, size_t n) {
    if (c->cfg.rand_fill) c->cfg.rand_fill(c->cfg.rand_ctx, buf, n);
    else                  randombytes_buf(buf, n);
}

/* 80..120% of d, as the Go client does, drawn through the same seam as every
 * other secret so a failing attempt replays. */
static uint32_t jitter(sn_client *c, uint32_t d) {
    uint8_t b[8];
    fill_random(c, b, sizeof b);
    uint64_t v = 0;
    for (size_t i = 0; i < sizeof b; i++) v = (v << 8) | b[i];
    uint64_t pct = 80 + (v % 41);
    return (uint32_t)((uint64_t)d * pct / 100);
}

/* Every per-attempt secret goes here, and this is called on success and on
 * failure alike -- the failure path being the branch least likely to clean up.
 * The session is left alone: on success it is the point of the attempt.
 * Nothing in it is read once the promoting PUSH is queued: INIT and FINISH are
 * resent only from AWAIT_RETRY / AWAIT_ADMIT, and a late RETRY or ADMIT is
 * ignored by every later state. */
static void wipe_handshake(sn_client *c) {
    sodium_memzero(c->nonce,   sizeof c->nonce);
    sodium_memzero(c->ec_priv, sizeof c->ec_priv);
    sodium_memzero(c->e_c,     sizeof c->e_c);
    sodium_memzero(c->init,    sizeof c->init);
    sodium_memzero(c->finish,  sizeof c->finish);
    sodium_memzero(c->context, sizeof c->context);
    sodium_memzero(c->sent_ae, sizeof c->sent_ae);
    sodium_memzero(c->cached_es, sizeof c->cached_es);
    sodium_memzero(c->cached_dh, sizeof c->cached_dh);
    sodium_memzero(c->first,   sizeof c->first);
    c->first_len = 0;
    c->dh_cached = 0;
    c->init_sent = 0;
    c->app_first = 0;
    c->app_first_pad = 0;
    c->app_first_kind = 0;
}

/* The handshake plus the session's liveness and framing state: everything a
 * return to IDLE, or a fresh take-control, must not inherit. */
static void wipe_attempt(sn_client *c) {
    wipe_handshake(c);
    c->desync = 0;
    c->carry_len = 0;
    c->last_rx_ms = 0;
    c->liveness_armed = 0;
    c->partial_armed = 0;
    c->partial_since_ms = 0;
    c->outstanding = 0;
    c->outstanding_since_ms = 0;
}

/* §7.2's gate goes up. Only the false -> true edge starts the clock: a second
 * write while the first is still unanswered must not extend the deadline, or a
 * client that keeps writing to a dead device would never notice. */
static void mark_outstanding(sn_client *c, uint32_t now_ms) {
    if (!c->outstanding) {
        c->outstanding = 1;
        c->outstanding_since_ms = now_ms;
    }
}

/* Sets the end reason after wipe_attempt, which must not (and does not) touch
 * it: the next take-control is what clears it. */
static int to_idle(sn_client *c, sn_client_end_reason why) {
    if (c->sess_live) {
        sn_client_session_free(&c->sess);
        c->sess_live = 0;
    }
    /* The directional AEAD keys and the plaintext they produced outlive the
     * session otherwise: nothing else reaches into these structs. */
    sn_app_rx_wipe(&c->app_rx, 1);
    sn_app_tx_wipe(&c->app_tx, 1);
    if (c->comp) sodium_memzero(c->comp, c->comp_size);
    c->carry_len = 0;
    c->desync = 0;
    wipe_attempt(c);
    c->end_reason = why;
    c->state = SN_CLIENT_IDLE;
    c->gen++;
    return SN_CLIENT_FAILED;
}

static void emit(sn_client *c, const uint8_t *dg, size_t len) {
    if (c->send) c->send(c->send_ctx, dg, len);
}

int sn_client_init(sn_client *c, const sn_client_config *cfg) {
    if (!c || !cfg) return SN_CLIENT_ERR;
    /* Nothing else here initialises libsodium, and randombytes_buf and
     * crypto_scalarmult_base are the first things take-control reaches for.
     * Idempotent and thread-safe, so a caller that already did it pays a
     * flag check; a caller that did not no longer depends on luck. */
    if (sodium_init() < 0) return SN_CLIENT_ERR;
    memset(c, 0, sizeof(*c));
    c->cfg = *cfg;
    sn_derive_kdev(c->cfg.psk, c->cfg.device_id, c->k_dev);
    sn_derive_static(c->k_dev, c->k_req, c->k_resp);
    c->state = SN_CLIENT_IDLE;
    return SN_CLIENT_OK;
}

void sn_client_free(sn_client *c) {
    if (!c) return;
    if (c->sess_live) { sn_client_session_free(&c->sess); c->sess_live = 0; }
    sn_app_rx_wipe(&c->app_rx, 1);
    sn_app_tx_wipe(&c->app_tx, 1);
    if (c->comp) sodium_memzero(c->comp, c->comp_size);
    wipe_attempt(c);
    sodium_memzero(c->k_dev,  sizeof c->k_dev);
    sodium_memzero(c->k_req,  sizeof c->k_req);
    sodium_memzero(c->k_resp, sizeof c->k_resp);
    sodium_memzero(c->cfg.psk, sizeof c->cfg.psk);
    c->state = SN_CLIENT_IDLE;
    c->gen++;   /* may be running inside a callback: see app_drain */
}

void sn_client_set_send(sn_client *c, sn_client_send_fn fn, void *ctx) {
    if (!c) return;
    c->send = fn;
    c->send_ctx = ctx;
}

void sn_client_set_on_msg(sn_client *c, sn_client_msg_fn fn, void *ctx) {
    if (!c) return;
    c->on_msg = fn;
    c->msg_ctx = ctx;
}
sn_client_state sn_client_get_state(const sn_client *c) {
    return c ? c->state : SN_CLIENT_IDLE;
}

sn_client_end_reason sn_client_get_end_reason(const sn_client *c) {
    return c ? c->end_reason : SN_CLIENT_END_NONE;
}

/* `framed`: the app layer seals first_msg into a frame at ADMIT, so an empty
 * body is still a complete message. Raw, first_msg is sent as it is and must
 * already be one complete sealed frame (transport 12.2), so it cannot be
 * empty. */
static int take_control(sn_client *c, const uint8_t *first_msg, size_t len,
                        int framed, uint32_t now_ms) {
    if (!c) return SN_CLIENT_ERR;
    /* §7.2 is one-shot: a second attempt on a live client is a caller bug, not
     * a retry. Failing here rather than tearing down is what stops one. */
    if (c->state != SN_CLIENT_IDLE) return SN_CLIENT_ERR;
    if (len > SN_CLIENT_FIRST_MAX) return SN_CLIENT_ERR;
    if (!framed && len == 0) return SN_CLIENT_ERR;
    /* NULL with a non-zero length used to be taken as "no message": the
     * caller's payload vanished and the attempt proceeded with an empty one. */
    if (!first_msg && len) return SN_CLIENT_ERR;

    wipe_attempt(c);
    c->dead = 0;
    /* Here and not in wipe_attempt: to_idle calls that, and would erase the
     * reason it had just set. */
    c->end_reason = SN_CLIENT_END_NONE;
    if (first_msg && len) { memcpy(c->first, first_msg, len); c->first_len = len; }

    fill_random(c, c->nonce, sizeof c->nonce);
    fill_random(c, c->ec_priv, sizeof c->ec_priv);
    crypto_scalarmult_base(c->e_c, c->ec_priv);

    uint8_t mac[16];
    sn_init_mac(c->k_req, c->nonce, c->cfg.device_id, mac);
    sn_encode_init(c->nonce, c->cfg.device_id, mac, c->init);
    sodium_memzero(mac, sizeof mac);

    emit(c, c->init, SN_INIT_LEN);
    c->init_sent   = 1;
    c->state       = SN_CLIENT_AWAIT_RETRY;
    c->next_tx_ms  = now_ms + jitter(c, SN_INIT_RETRY_MS);
    /* The INIT phase is bounded by its three transmissions, not by a separate
     * timer: the third one's interval expiring is what ends it. */
    c->phase_end_ms = 0;
    return SN_CLIENT_IN_PROGRESS;
}

int sn_client_take_control(sn_client *c, const uint8_t *first_msg, size_t len,
                           uint32_t now_ms) {
    return take_control(c, first_msg, len, 0, now_ms);
}

/* AWAIT_RETRY: a valid RETRY moves us to AWAIT_ADMIT with FINISH already sent. */
static int on_retry(sn_client *c, const uint8_t *dg, size_t len, uint32_t now_ms) {
    sn_retry_msg r;
    if (sn_decode_retry(dg, len, &r) != SN_CW_OK) return SN_CLIENT_IN_PROGRESS;
    if (sn_check_retry(&r, c->k_resp, c->nonce, c->cfg.own_source,
                       c->cfg.device_id) != SN_CW_OK) {
        /* §7.3: discard and keep waiting. A forged RETRY must not be able to
         * end someone else's attempt. */
        return SN_CLIENT_IN_PROGRESS;
    }

    /* §7.3 step 5: retain the three as a SET -- all three feed context, and
     * admission_epoch is additionally what §7.4 step 2 compares. They are
     * copies already (sn_decode_retry), never aliases of the read buffer. */
    sn_context(c->nonce, r.epoch_tag, r.cookie, r.admission_epoch,
               c->cfg.device_id, c->context);
    memcpy(c->sent_ae, r.admission_epoch, 8);

    uint8_t tag[16];
    sn_client_tag(c->k_req, c->context, c->e_c, tag);
    sn_encode_finish(c->nonce, r.epoch_tag, r.cookie, r.admission_epoch,
                     c->e_c, tag, c->finish);
    sodium_memzero(tag, sizeof tag);

    emit(c, c->finish, SN_FINISH_LEN);
    c->state        = SN_CLIENT_AWAIT_ADMIT;
    c->next_tx_ms   = now_ms + jitter(c, SN_FINISH_RETRY_MS);
    c->phase_end_ms = now_ms + SN_FINISH_PHASE_MS;
    return SN_CLIENT_IN_PROGRESS;
}

/* AWAIT_ADMIT: a valid ADMIT commits the session and sends the promoting PUSH. */
static int on_admit(sn_client *c, const uint8_t *dg, size_t len, uint32_t now_ms) {
    sn_admit_msg a;
    if (sn_decode_admit(dg, len, &a) != SN_CW_OK) return SN_CLIENT_IN_PROGRESS;

    /* §7.4's required dh cache, keyed on e_s. An attacker who captures one
     * genuine ADMIT can flip an admit_tag octet and replay at line rate; every
     * copy passes admit_pre, so without this each one costs an X25519. */
    uint8_t master[32];
    sn_cw_result res;
    if (c->dh_cached && sodium_memcmp(c->cached_es, a.e_s, 32) == 0) {
        res = sn_check_admit_dh(&a, c->k_dev, c->k_resp, c->context, c->sent_ae,
                                c->e_c, c->cached_dh, master);
    } else {
        /* sn_check_admit_caching runs epoch and admit_pre FIRST and only then
         * the X25519, handing back the dh it computed. Computing the DH here in
         * order to cache it -- which an earlier version did -- hoists the scalar
         * multiplication above admit_pre and throws away exactly the property
         * §7.4's check order buys: an off-path attacker spraying 82-byte
         * datagrams with random e_s then costs one X25519 each instead of one
         * HMAC, on a client that may be an ESP32. The order is pinned by a test
         * inside sn_client_wire.c; nothing pinned it out here. */
        uint8_t dh[32];
        int dh_valid = 0;
        res = sn_check_admit_caching(&a, c->k_dev, c->k_resp, c->context, c->sent_ae,
                                     c->e_c, c->ec_priv, master, dh, &dh_valid);
        /* Cache only what verified this far: admit_pre covers e_s, so a cached
         * entry cannot be poisoned by a forgery. */
        if (dh_valid && (res == SN_CW_OK || res == SN_CW_BAD_TAG)) {
            memcpy(c->cached_es, a.e_s, 32);
            memcpy(c->cached_dh, dh, 32);
            c->dh_cached = 1;
        }
        sodium_memzero(dh, sizeof dh);
    }
    if (res != SN_CW_OK) {
        sodium_memzero(master, sizeof master);
        return SN_CLIENT_IN_PROGRESS; /* discard, keep waiting */
    }

    /* §7.4 step 5, exactly once per attempt. */
    uint8_t k_c2s[32], k_s2c[32], k_kcp_c2s[32], k_kcp_s2c[32];
    sn_session_keys(master, k_c2s, k_s2c, k_kcp_c2s, k_kcp_s2c);
    sodium_memzero(master, sizeof master);

    /* §8.4: the client chooses conv, and Go draws a fresh one per commit. A
     * fixed value collides with the device's stale primary on re-admission and
     * is a linkable identifier across sessions. cfg.conv, if set, is honoured
     * for callers that need a deterministic one (the tests do). */
    uint32_t conv = c->cfg.conv;
    if (conv == 0) {
        uint8_t cb[4];
        fill_random(c, cb, sizeof cb);
        conv = ((uint32_t)cb[0] << 24) | ((uint32_t)cb[1] << 16) |
               ((uint32_t)cb[2] << 8)  | (uint32_t)cb[3];
        if (conv == 0) conv = 1;
    }
    int rc = sn_client_session_init(&c->sess, conv, k_kcp_c2s, k_kcp_s2c);
    sodium_memzero(k_kcp_c2s, 32); sodium_memzero(k_kcp_s2c, 32);
    if (rc != SN_CS_OK) {
        sodium_memzero(k_c2s, 32);
        sodium_memzero(k_s2c, 32);
        return to_idle(c, SN_CLIENT_END_INTERNAL);
    }
    c->sess_live = 1;
    sn_client_session_set_send(&c->sess, c->send, c->send_ctx);
    sn_client_session_set_on_msg(&c->sess, c->on_msg, c->msg_ctx);

    /* §7.4 step 5 says to wipe the ephemeral private key AND the cached dh at
     * commit, so they go now. The rest of the attempt -- nonce, e_c, the INIT
     * and FINISH datagrams, the context, and up to 512 bytes of application
     * plaintext in `first` -- is still needed to build the promoting PUSH and
     * goes the moment it is queued (wipe_handshake below). An earlier version
     * stopped here, and all of that survived for the life of the session. */
    sodium_memzero(c->ec_priv, sizeof c->ec_priv);
    sodium_memzero(c->cached_dh, sizeof c->cached_dh);
    sodium_memzero(c->cached_es, sizeof c->cached_es);
    c->dh_cached = 0;

    /* The same core the device uses, with the keys swapped. The device
     * reads c2s and writes s2c; the client is the mirror. */
    if (c->app_ready) {
        uint8_t *dec = c->app_rx.dec, *decomp = c->app_rx.decomp, *enc = c->app_tx.enc;
        size_t ds = c->app_rx.dec_size, cs2 = c->app_rx.decomp_size, es = c->app_tx.enc_size;
        sn_app_rx_init(&c->app_rx, k_s2c, dec, ds, decomp, cs2);
        sn_app_tx_init(&c->app_tx, k_c2s, enc, es);
        c->carry_len = 0;
        /* Stream bytes come here first so frames can be reassembled across
         * datagrams; the user's app callback is what finally sees a message. */
        sn_client_session_set_on_msg(&c->sess, app_on_stream, c);
    }
    /* Only now: the app layer had to bind these first. An earlier version
     * wiped them two lines after sn_client_session_init and bound the app
     * layer afterwards, so it sealed under an all-zero key -- the session
     * promoted normally and every app frame was then dropped by the device's
     * AEAD, which looks exactly like a silent peer. */
    sodium_memzero(k_c2s, 32);
    sodium_memzero(k_s2c, 32);

    /* In app mode the promoting PUSH is a framed message, so it must go out even
     * with an empty body: PING and the other payload-free kinds are exactly the
     * ones a controller opens with, and gating on first_len left them queuing
     * nothing and hanging in AWAIT_PUSH_ACK until the timeout. */
    if (c->app_first) {
        if (app_write(c, c->app_first_kind, c->first, c->first_len,
                      c->app_first_pad, now_ms) != SN_CS_OK) {
            return to_idle(c, SN_CLIENT_END_INTERNAL);
        }
    } else {
        /* Raw: the caller's sealed frame, never empty (take-control refused
         * that), so the PUSH that binds conv (§8.5) is never empty either. */
        if (sn_client_session_send(&c->sess, c->first, c->first_len, now_ms) != SN_CS_OK) {
            return to_idle(c, SN_CLIENT_END_INTERNAL);
        }
    }
    /* The PUSH is queued; nothing of the handshake is read again. This is what
     * makes wipe_attempt's "on success and on failure alike" true. */
    wipe_handshake(c);

    /* §7.2: arm the liveness timer. last_rx starts at admission so a device
     * that goes silent immediately is still detected. */
    c->last_rx_ms   = now_ms;
    c->liveness_armed = 1;
    c->outstanding  = 0;
    mark_outstanding(c, now_ms); /* the promoting PUSH is outstanding until acked */
    c->state        = SN_CLIENT_AWAIT_PUSH_ACK;
    c->phase_end_ms = now_ms + SN_PUSH_ACK_TIMEOUT_MS;
    return SN_CLIENT_IN_PROGRESS;
}

int sn_client_input(sn_client *c, const uint8_t *datagram, size_t len, uint32_t now_ms) {
    if (!c || !datagram) return SN_CLIENT_ERR;

    sn_class cls = sn_classify_datagram(SN_ROLE_CLIENT, datagram, len);

    switch (c->state) {
    case SN_CLIENT_AWAIT_RETRY:
        if (cls == SN_CLASS_RETRY) return on_retry(c, datagram, len, now_ms);
        return SN_CLIENT_IN_PROGRESS;

    case SN_CLIENT_AWAIT_ADMIT:
        if (cls == SN_CLASS_ADMIT) return on_admit(c, datagram, len, now_ms);
        return SN_CLIENT_IN_PROGRESS;

    case SN_CLIENT_AWAIT_PUSH_ACK:
    case SN_CLIENT_ESTABLISHED:
        if (cls == SN_CLASS_ENVELOPE && c->sess_live) {
            /* Promotion must be gated on an envelope that VERIFIED, not on the
             * send queue draining. sn_client_session_input returns < 0 only on a
             * caller error; a forged datagram returns 0 having changed nothing,
             * so the queue check alone would let any unauthenticated datagram
             * that classifies as an envelope flip the state -- and with an empty
             * promoting message the queue is empty from the start, so the very
             * first piece of junk would report an ESTABLISHED session the device
             * does not have. Go promotes on the first successfully opened s2c
             * envelope for exactly this reason. */
            uint64_t before = c->sess.accepted;
            unsigned gen = c->gen;
            sn_client_session_input(&c->sess, datagram, len, now_ms);
            if (c->gen != gen) {
                /* A callback closed (or freed) the client. Everything below
                 * would write liveness into a wiped attempt or promote an IDLE
                 * client; the attempt ended, and that is all there is to say. */
                return c->state == SN_CLIENT_IDLE ? SN_CLIENT_FAILED : SN_CLIENT_IN_PROGRESS;
            }
            int verified = (c->sess.accepted != before);
            if (verified) {
                /* §7.2: only an ACCEPTED envelope refreshes liveness. Data is
                 * outstanding until ALL of it is acknowledged (transport
                 * 10.3): with nothing left unacknowledged the gate clears;
                 * otherwise it stays set and its timer restarts here, so it
                 * runs from the last authenticated datagram. A partly
                 * acknowledged write whose device then goes silent is dead
                 * SESSION_DEAD_MS later, and a long transfer the device
                 * acknowledges steadily is not. */
                c->last_rx_ms = now_ms;
                if (ikcp_waitsnd(c->sess.kcp) == 0) {
                    c->outstanding = 0;
                } else {
                    c->outstanding_since_ms = now_ms;
                }
            }
            /* §7.2: the first accepted s2c envelope confirms the promotion, as
             * in Go; the send queue draining is not part of the gate. */
            if (c->state == SN_CLIENT_AWAIT_PUSH_ACK && verified) {
                c->state = SN_CLIENT_ESTABLISHED;
            }
            /* Message layer 8 item 2: part of a message (a partial header
             * included) is now held; start its clock. Here, not in app_drain,
             * which has no clock -- and only after the gen check above. */
            if (c->carry_len > 0 && !c->partial_armed) {
                c->partial_armed = 1;
                c->partial_since_ms = now_ms;
            }
            if (c->desync) {
                /* app_drain lost the stream position. Nothing further on this
                 * session can be parsed, so end it rather than keep returning
                 * OK while delivering nothing. */
                return to_idle(c, SN_CLIENT_END_DESYNC);
            }
        }
        return c->state == SN_CLIENT_ESTABLISHED ? SN_CLIENT_OK : SN_CLIENT_IN_PROGRESS;

    case SN_CLIENT_IDLE:
    default:
        return SN_CLIENT_FAILED;
    }
}

int sn_client_tick(sn_client *c, uint32_t now_ms) {
    if (!c) return SN_CLIENT_ERR;

    switch (c->state) {
    case SN_CLIENT_AWAIT_RETRY:
        if ((int32_t)(now_ms - c->next_tx_ms) >= 0) {
            if (c->init_sent >= SN_INIT_TRANSMISSIONS) return to_idle(c, SN_CLIENT_END_ATTEMPT_FAILED);
            /* §7.2: up to three transmissions of the SAME INIT. A fresh nonce
             * would be a new attempt, and the device would cookie it separately. */
            emit(c, c->init, SN_INIT_LEN);
            c->init_sent++;
            c->next_tx_ms = now_ms + jitter(c, SN_INIT_RETRY_MS);
        }
        return SN_CLIENT_IN_PROGRESS;

    case SN_CLIENT_AWAIT_ADMIT:
        if ((int32_t)(now_ms - c->phase_end_ms) >= 0) return to_idle(c, SN_CLIENT_END_ATTEMPT_FAILED);
        if ((int32_t)(now_ms - c->next_tx_ms) >= 0) {
            /* §6.2 step 2 compares the whole datagram, so a resend must be
             * byte-identical -- which is why the FINISH is kept rather than
             * rebuilt. */
            emit(c, c->finish, SN_FINISH_LEN);
            c->next_tx_ms = now_ms + jitter(c, SN_FINISH_RETRY_MS);
        }
        return SN_CLIENT_IN_PROGRESS;

    case SN_CLIENT_AWAIT_PUSH_ACK:
        if ((int32_t)(now_ms - c->phase_end_ms) >= 0) return to_idle(c, SN_CLIENT_END_ATTEMPT_FAILED);
        if (c->sess_live) sn_client_session_update(&c->sess, now_ms);
        return SN_CLIENT_IN_PROGRESS;

    case SN_CLIENT_ESTABLISHED:
        if (c->sess_live) sn_client_session_update(&c->sess, now_ms);
        /* §3.6: the c2s sequence space ran out. KCP holds a segment that can
         * never be sealed, so only a rekey (a fresh admission) can continue. */
        if (c->sess_live && c->sess.seq_exhausted) {
            c->dead = 1;
            return to_idle(c, SN_CLIENT_END_SEQ_EXHAUSTED);
        }
        /* §7.2: ESTABLISHED leaves for IDLE on no authenticated datagram for
         * SESSION_DEAD_MS *while data is outstanding*. Both halves matter --
         * see the note on `outstanding` in the header for why a bare timeout
         * would tear down a healthy idle controller and orphan the device.
         *
         * The timer runs from max(last_rx_ms, outstanding_since_ms), not from
         * last_rx_ms: after an idle spell longer than SESSION_DEAD_MS the
         * first write would otherwise be dead at the next tick, where §7.2
         * says the client "then waits the full 10 s". While outstanding is
         * set that max is always outstanding_since_ms -- an accepted envelope
         * either clears outstanding or, with data still unacknowledged,
         * moves outstanding_since_ms up to its own arrival, so last_rx_ms can
         * never be later (transport 10.3). Measuring from
         * outstanding_since_ms alone gives the max without comparing the two
         * timestamps, which a wrap-safe int32 difference would misorder once
         * an idle spell passes 2^31 ms. */
        if (c->outstanding && c->liveness_armed &&
            (int32_t)(now_ms - c->outstanding_since_ms) >= (int32_t)SN_SESSION_DEAD_MS) {
            c->dead = 1;
            return to_idle(c, SN_CLIENT_END_DEAD);
        }
        /* Message layer 8 item 2: a message left partly read past the budget
         * is a partial message, and the stream cannot be realigned. Checked
         * after the dead-session limit: when both expire on one tick the
         * session is dead, which is what sn_client_session_dead reports. */
        if (c->partial_armed &&
            (int32_t)(now_ms - c->partial_since_ms) >= (int32_t)SN_MID_FRAME_BUDGET_MS) {
            c->desync = 1;
            return to_idle(c, SN_CLIENT_END_DESYNC);
        }
        return SN_CLIENT_OK;

    case SN_CLIENT_IDLE:
    default:
        return SN_CLIENT_FAILED;
    }
}

int sn_client_send(sn_client *c, const uint8_t *msg, size_t len, uint32_t now_ms) {
    if (!c || c->state != SN_CLIENT_ESTABLISHED || !c->sess_live) return SN_CLIENT_ERR;
    int rc = sn_client_session_send(&c->sess, msg, len, now_ms);
    if (rc == SN_CS_OK) mark_outstanding(c, now_ms); /* §7.2's gate */
    else if (c->sess.broken) (void)to_idle(c, SN_CLIENT_END_BROKEN);  /* part of it may be queued */
    return rc;
}

int sn_client_session_dead(const sn_client *c) { return c ? c->dead : 0; }

void sn_client_close(sn_client *c) {
    if (!c) return;
    (void)to_idle(c, SN_CLIENT_END_USER);   /* frees the session and wipes the attempt */
}

/* ── the app layer ──────────────────────────────────────────────────────────
 *
 * The device pulls frames through a blocking io seam; the client has no thread
 * to block, so it reassembles on the push path instead. Bytes arrive from the
 * session as whatever KCP happened to deliver, which is not frame-aligned:
 * carry holds the remainder between calls, exactly as sn_agent_io does across
 * waits. */

static void app_drain(sn_client *c) {
    for (;;) {
        if (c->carry_len < PROTOCOL_HEADER_SIZE) return;
        /* The header is plaintext and its own AAD, so it can be read before the
         * body arrives -- that is what makes a length-prefixed stream parseable
         * at all. It is authenticated with the body, never trusted before. */
        uint32_t size = ((uint32_t)c->carry[0] << 24) | ((uint32_t)c->carry[1] << 16) |
                        ((uint32_t)c->carry[2] << 8)  | (uint32_t)c->carry[3];
        if ((size_t)size > c->raw_size ||
            PROTOCOL_HEADER_SIZE + (size_t)size > c->carry_size) {
            /* Unrecoverable, not merely unfinished. KCP is reliable and in
             * stream mode, so the next bytes are the interior of this frame:
             * resetting the buffer and carrying on parses frame bodies as
             * headers forever, delivering nothing and reporting nothing. The
             * device poisons the stream and ends the session for exactly this
             * condition; so does this now. */
            c->desync = 1;
            c->carry_len = 0;
            return;
        }
        size_t need = PROTOCOL_HEADER_SIZE + (size_t)size;
        if (c->carry_len < need) return;   /* incomplete: wait for more */

        protocol_msg_header_t hdr;
        hdr.size          = size;
        hdr.original_size = ((uint32_t)c->carry[4] << 24) | ((uint32_t)c->carry[5] << 16) |
                            ((uint32_t)c->carry[6] << 8)  | (uint32_t)c->carry[7];
        hdr.message_type  = ((uint32_t)c->carry[8] << 24) | ((uint32_t)c->carry[9] << 16) |
                            ((uint32_t)c->carry[10] << 8) | (uint32_t)c->carry[11];
        hdr.message_num = 0;
        for (int i = 0; i < 8; i++) hdr.message_num = (hdr.message_num << 8) | c->carry[12 + i];

        memcpy(c->raw, c->carry + PROTOCOL_HEADER_SIZE, size);

        const uint8_t *payload = NULL;
        size_t payload_len = 0;
        sn_app_result r = sn_app_open(&c->app_rx, &hdr, c->raw, &payload, &payload_len);
        if (r == SN_APP_OK && c->on_app) {
            unsigned gen = c->gen;
            c->on_app(c->app_ctx, hdr.message_type & 0x7fffffffu, payload, payload_len);
            /* "The device said goodbye, close it" is the natural thing to write
             * here, and to_idle zeroes carry_len: the memmove below then ran
             * with carry_len - need wrapped to nearly SIZE_MAX. The session
             * path already tolerates a close from its callback; so does this.
             * The rest of the stream belonged to the session that just ended. */
            if (c->gen != gen) return;
        }
        /* A dropped frame is still consumed: it was a whole frame on a reliable
         * stream, so the next one starts after it. */
        memmove(c->carry, c->carry + need, c->carry_len - need);
        c->carry_len -= need;
        c->partial_armed = 0; /* a frame completed; sn_client_input re-arms on a remainder */
    }
}

/* The session hands us raw stream bytes; append and parse what is complete. */
static void app_on_stream(void *ctx, const uint8_t *msg, size_t len) {
    sn_client *c = ctx;
    if (!c->app_ready || !c->carry) return;
    if (c->carry_len + len > c->carry_size) {
        /* Same reasoning as above: nothing can be recovered from a lost stream
         * position, so say so rather than silently resyncing onto garbage. */
        c->desync = 1;
        c->carry_len = 0;
        return;
    }
    memcpy(c->carry + c->carry_len, msg, len);
    c->carry_len += len;
    app_drain(c);
}

int sn_client_set_app_buffers(sn_client *c,
                              uint8_t *carry, size_t carry_size,
                              uint8_t *raw, size_t raw_size,
                              uint8_t *dec, size_t dec_size,
                              uint8_t *decomp, size_t decomp_size,
                              uint8_t *enc, size_t enc_size) {
    if (!c) return SN_CLIENT_ERR;
    /* The keys are bound at ADMIT, and only for a client whose buffers were
     * already here. Accepting them later would leave app_ready set over a
     * zero tx key and an unbound stream callback: every send sealed under
     * zeroes and dropped by the device, nothing delivered inbound, and no
     * error anywhere to say why. */
    if (c->state != SN_CLIENT_IDLE) return SN_CLIENT_ERR;
    c->carry = carry; c->carry_size = carry_size; c->carry_len = 0;
    c->raw = raw; c->raw_size = raw_size;
    /* Keys are bound at ADMIT; these only record where the buffers are. */
    c->app_rx.dec = dec; c->app_rx.dec_size = dec_size;
    c->app_rx.decomp = decomp; c->app_rx.decomp_size = decomp_size;
    c->app_tx.enc = enc; c->app_tx.enc_size = enc_size;
    /* carry must hold a whole frame, or app_drain can see one it will never be
     * able to assemble and has to declare a desync it could have prevented. */
    c->app_ready = (carry && raw && dec && decomp && enc &&
                    carry_size >= PROTOCOL_HEADER_SIZE + raw_size) ? 1 : 0;
    return SN_CLIENT_OK;
}

void sn_client_set_on_app(sn_client *c, sn_client_app_fn fn, void *ctx) {
    if (!c) return;
    c->on_app = fn;
    c->app_ctx = ctx;
}

/* Write one sealed frame, whose ciphertext is in app_tx.enc, into the session. */
static int app_emit(sn_client *c, uint32_t type, uint64_t msgnum, uint32_t original,
                    size_t ct_len, uint32_t now_ms) {
    /* Bounded by raw_size, which is what this stages into. An earlier version
     * checked carry_size -- the INBOUND buffer -- so an integrator who sized
     * carry for reassembly and raw for large sends got a refusal on every big
     * message, and via the app_first path a failed admission with no diagnosis. */
    uint8_t hdr[PROTOCOL_HEADER_SIZE];
    hdr[0]=(uint8_t)(ct_len>>24); hdr[1]=(uint8_t)(ct_len>>16);
    hdr[2]=(uint8_t)(ct_len>>8);  hdr[3]=(uint8_t)ct_len;
    hdr[4]=(uint8_t)(original>>24); hdr[5]=(uint8_t)(original>>16);
    hdr[6]=(uint8_t)(original>>8);  hdr[7]=(uint8_t)original;
    hdr[8]=(uint8_t)(type>>24); hdr[9]=(uint8_t)(type>>16);
    hdr[10]=(uint8_t)(type>>8); hdr[11]=(uint8_t)type;
    for (int i = 0; i < 8; i++) hdr[12+i] = (uint8_t)(msgnum >> (56 - 8*i));

    /* One ikcp_send per frame would still be a stream; sending header and body
     * separately is equally correct but doubles the segment count for small
     * responses, so stage them together. */
    if (PROTOCOL_HEADER_SIZE + ct_len > c->raw_size) return SN_CLIENT_ERR;
    uint8_t *staging = c->raw;
    memcpy(staging, hdr, PROTOCOL_HEADER_SIZE);
    memcpy(staging + PROTOCOL_HEADER_SIZE, c->app_tx.enc, ct_len);
    return sn_client_session_send(&c->sess, staging, PROTOCOL_HEADER_SIZE + ct_len, now_ms);
}

/* Frame one app message into the session. */
static int app_write(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                     int pad, uint32_t now_ms) {
    uint32_t type = 0, original = 0;
    uint64_t msgnum = 0;
    size_t ct_len = 0;
    int rc = pad
        ? sn_app_seal_padded(&c->app_tx, kind, body, len, &type, &msgnum, &original, &ct_len)
        : sn_app_seal(&c->app_tx, kind, body, len, &type, &msgnum, &original, &ct_len);
    if (rc != 0) return SN_CLIENT_ERR;
    return app_emit(c, type, msgnum, original, ct_len, now_ms);
}

int sn_client_send_app(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                       uint32_t now_ms) {
    if (!c || c->state != SN_CLIENT_ESTABLISHED || !c->sess_live) return SN_CLIENT_ERR;
    if (!c->app_ready) return SN_CLIENT_ERR;
    int rc = app_write(c, kind, body, len, 0, now_ms);
    if (rc == SN_CS_OK) mark_outstanding(c, now_ms); /* §7.2's gate */
    else if (c->sess.broken) (void)to_idle(c, SN_CLIENT_END_BROKEN);  /* see sn_client_send */
    return rc;
}

int sn_client_send_app_padded(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                              uint32_t now_ms) {
    if (!c || c->state != SN_CLIENT_ESTABLISHED || !c->sess_live) return SN_CLIENT_ERR;
    if (!c->app_ready) return SN_CLIENT_ERR;
    int rc = app_write(c, kind, body, len, 1, now_ms);
    if (rc == SN_CS_OK) mark_outstanding(c, now_ms);
    else if (c->sess.broken) (void)to_idle(c, SN_CLIENT_END_BROKEN);  /* see sn_client_send */
    return rc;
}

uint64_t sn_client_last_tx_num(const sn_client *c) {
    if (!c || c->app_tx.next_msgnum == 0) return 0;
    return c->app_tx.next_msgnum - 1;
}

size_t sn_client_max_app_body(const sn_client *c) {
    if (!c || !c->sess_live || !c->sess.kcp) return 0;
    size_t mss = c->sess.kcp->mss;
    if (mss == 0) return 0;
    /* sn_client_session_send charges whole segments against SN_SEND_QUEUE_MAX
     * and ikcp_send refuses SN_CLIENT_KCP_MAX_FRAGMENTS or more. The frame
     * around the body is a 20-byte header and a 16-byte tag. */
    size_t segs = (size_t)SN_SEND_QUEUE_MAX / mss;
    if (segs > SN_CLIENT_KCP_MAX_FRAGMENTS - 1) segs = SN_CLIENT_KCP_MAX_FRAGMENTS - 1;
    size_t cap = segs * mss;
    size_t frame = PROTOCOL_HEADER_SIZE + CRYPTO_OVERHEAD;
    return cap > frame ? cap - frame : 0;
}

int sn_client_set_compress_buffer(sn_client *c, uint8_t *buf, size_t size) {
    if (!c) return SN_CLIENT_ERR;
    if (c->state != SN_CLIENT_IDLE) return SN_CLIENT_ERR;
    c->comp = buf;
    c->comp_size = buf ? size : 0;
    return SN_CLIENT_OK;
}

int sn_client_send_app_compressed(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                                  uint32_t now_ms) {
    if (!c || c->state != SN_CLIENT_ESTABLISHED || !c->sess_live) return SN_CLIENT_ERR;
    if (!c->app_ready || !c->comp || c->comp_size == 0) return SN_CLIENT_ERR;
    /* Same rule as Go's compressBlock: only when it actually shrinks the body.
     * LZ4 returns 0 when the output does not fit, which here means the same as
     * "not shorter". */
    int n = 0;
    if (body && len > 0 && len <= (size_t)INT_MAX) {
        size_t cap = c->comp_size < (size_t)INT_MAX ? c->comp_size : (size_t)INT_MAX;
        n = LZ4_compress_default((const char *)body, (char *)c->comp, (int)len, (int)cap);
    }
    int rc;
    if (n > 0 && (size_t)n < len) {
        uint32_t type = 0, original = 0;
        uint64_t msgnum = 0;
        size_t ct_len = 0;
        rc = sn_app_seal_compressed(&c->app_tx, kind, c->comp, (size_t)n, len,
                                    &type, &msgnum, &original, &ct_len) != 0
                 ? SN_CLIENT_ERR
                 : app_emit(c, type, msgnum, original, ct_len, now_ms);
    } else {
        rc = app_write(c, kind, body, len, 0, now_ms);
    }
    if (rc == SN_CS_OK) mark_outstanding(c, now_ms); /* §7.2's gate */
    else if (c->sess.broken) (void)to_idle(c, SN_CLIENT_END_BROKEN);  /* see sn_client_send */
    return rc;
}

int sn_client_take_control_app(sn_client *c, uint8_t kind,
                               const uint8_t *body, size_t len, uint32_t now_ms) {
    if (!c || !c->app_ready) return SN_CLIENT_ERR;
    /* Set the flag AFTER the inner call: take_control starts with wipe_attempt,
     * which clears every per-attempt field including this one. Setting it first
     * left app_first at 0, so the promoting PUSH was never framed and never
     * sent, and the client sat in AWAIT_PUSH_ACK until the timeout. */
    int rc = take_control(c, body, len, 1, now_ms);
    if (rc == SN_CLIENT_IN_PROGRESS) {
        c->app_first = 1;
        c->app_first_kind = kind;
    }
    return rc;
}

int sn_client_take_control_app_padded(sn_client *c, uint8_t kind,
                                      const uint8_t *body, size_t len, uint32_t now_ms) {
    int rc = sn_client_take_control_app(c, kind, body, len, now_ms);
    if (rc == SN_CLIENT_IN_PROGRESS) c->app_first_pad = 1;
    return rc;
}
