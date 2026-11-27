/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_client_session.h"

#include "shieldnet/sn_device.h"  /* SN_WIRE_MTU, SN_SEND_QUEUE_MAX, tuning */

#include <sodium.h>
#include <string.h>

/* One reassembly buffer per drain, sized like the device's: ikcp_recv needs a
 * buffer at least as large as the message it is about to hand back, and the
 * app layer bounds that by the envelope. */
/* ikcp's own segment header, which §7.5's floor counts alongside the envelope.
 * Mirrors goshieldnet's KcpOverhead. */
#define SN_KCP_OVERHEAD 24
/* IKCP_WND_RCV in vendor/ikcp.c, which is not exported: ikcp_send refuses a
 * message of this many fragments or more, after possibly appending part of it
 * to the last queued segment in stream mode. */
#define SN_KCP_MAX_FRAGMENTS 128

/* ikcp_flush hands us a raw KCP datagram; seal it under k_kcp_c2s with a fresh
 * c2s seq_full and pass it to the caller's sink. */
static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    (void)kcp;
    sn_client_session *s = user;
    if (s->send == NULL || len <= 0) {
        return 0;
    }
    /* A broken stream holds a partial message; flushing it would hand the
     * device a frame that can never complete. Nothing more goes out. */
    if (s->broken) {
        return 0;
    }
    uint64_t seq;
    if (!sn_sender_alloc(&s->c2s_seq, &seq)) {
        /* §3.6: fail closed. KCP believes the segment went out and will
         * retransmit it forever, so record it -- the session is unusable and
         * only a rekey fixes it, which the caller can only do if it is told. */
        s->seq_exhausted = 1;
        return 0;
    }
    uint8_t out[SN_WIRE_MTU + SN_ENVELOPE_LEN];
    size_t out_len = 0;
    if (sn_seal(s->k_kcp_c2s, /*c2s=*/1, seq, (const uint8_t *)buf, (size_t)len,
                out, &out_len) != 0) {
        return 0;
    }
    s->send(s->send_ctx, out, out_len);
    return 0;
}

int sn_client_session_init(sn_client_session *s, uint32_t conv,
                           const uint8_t k_kcp_c2s[32], const uint8_t k_kcp_s2c[32]) {
    if (!s || !k_kcp_c2s || !k_kcp_s2c) return SN_CS_ERR;
    memset(s, 0, sizeof(*s));
    memcpy(s->k_kcp_c2s, k_kcp_c2s, 32);
    memcpy(s->k_kcp_s2c, k_kcp_s2c, 32);
    /* §7.4 step 5: c2s starts at 1 and the s2c window starts empty, once per
     * attempt. memset above is the empty window; sn_sender_init is the 1. */
    sn_sender_init(&s->c2s_seq);

    s->kcp = ikcp_create(conv, s);
    if (!s->kcp) {
        sodium_memzero(s->k_kcp_c2s, 32);
        sodium_memzero(s->k_kcp_s2c, 32);
        return SN_CS_ERR;
    }
    ikcp_setoutput(s->kcp, kcp_output);
    /* The envelope costs SN_ENVELOPE_LEN on every datagram, so KCP's MTU is the
     * wire MTU minus it -- the same arithmetic the device does. */
    ikcp_setmtu(s->kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    sn_kcp_tuning t = (sn_kcp_tuning)SN_KCP_TUNING_DEFAULT;
    /* Stream mode BEFORE ikcp_wndsize: the window setter only honours an rcv_wnd
     * below IKCP_WND_RCV (128) when kcp->stream is already non-zero, and
     * silently clamps upward otherwise (see configure_kcp in sn_session.c). */
    s->kcp->stream = 1; /* stream mode, as the device's app layer expects */
    ikcp_wndsize(s->kcp, t.snd_wnd, t.rcv_wnd);
    ikcp_nodelay(s->kcp, t.nodelay, t.interval, t.resend, t.nc);
    return SN_CS_OK;
}

void sn_client_session_free(sn_client_session *s) {
    if (!s) return;
    if (s->kcp) {
        ikcp_release(s->kcp);
        s->kcp = NULL;
    }
    sodium_memzero(s->k_kcp_c2s, 32);
    sodium_memzero(s->k_kcp_s2c, 32);
}

void sn_client_session_set_send(sn_client_session *s, sn_client_send_fn fn, void *ctx) {
    if (!s) return;
    s->send = fn;
    s->send_ctx = ctx;
}

void sn_client_session_set_on_msg(sn_client_session *s, sn_client_msg_fn fn, void *ctx) {
    if (!s) return;
    s->on_msg = fn;
    s->msg_ctx = ctx;
}

int sn_client_session_send(sn_client_session *s, const uint8_t *msg, size_t len,
                           uint32_t now_ms) {
    if (!s || !s->kcp || !msg || len == 0 || s->broken) return SN_CS_ERR;
    /* A message that could never fit under the cap is a caller error, not a
     * full queue: SN_CS_QUEUE_FULL would have the caller retry it forever.
     * Refusing it here, before any arithmetic, also keeps len inside int for
     * ikcp_send -- a size_t above INT_MAX used to be truncated by the cast
     * (2^32 + 4 bytes went out as 4) and overflowed the int product below. */
    size_t mss = s->kcp->mss;
    if (len > SN_CS_MSG_MAX || mss == 0) return SN_CS_ERR;
    /* §9.5: refuse rather than grow the queue against a vanished peer, and
     * refuse rather than drop silently. ikcp_waitsnd counts snd_buf plus
     * snd_queue segments; mss is the payload each carries. */
    /* Charge the segments this message will actually occupy, not one. A single
     * large write otherwise passes the check and then queues dozens of
     * segments, which is the memory §11 budgets and §9.5 is meant to bind. */
    size_t segs = (len + mss - 1) / mss;
    /* Unreachable at the default cap (24 segments), but SN_SEND_QUEUE_MAX is a
     * deployment constant and ikcp_send would refuse this many fragments. */
    if (segs >= SN_KCP_MAX_FRAGMENTS) return SN_CS_ERR;
    /* Message layer 7.3: a message whose whole segments exceed the cap can
     * never be accepted, even on an empty queue; QUEUE_FULL would have the
     * caller retry it forever. */
    if (segs * mss > (size_t)SN_SEND_QUEUE_MAX) return SN_CS_ERR;
    if (((size_t)ikcp_waitsnd(s->kcp) + segs) * mss > (size_t)SN_SEND_QUEUE_MAX) {
        /* Flush before refusing: §9.5 requires accepting writes again once the
         * total falls below the cap, so a retrying caller must be able to make
         * progress. Returning without an update leaves snd_buf unflushed. */
        ikcp_update(s->kcp, now_ms);
        return SN_CS_QUEUE_FULL;
    }
    /* ikcp_send reports OOM as -2 after possibly queuing part of the message,
     * and in stream mode can return a short count. Either way the stream may
     * now carry a fragment of it, and a retry would put those bytes in twice:
     * the session is finished. Mirrors sn_primary_send_gen on the device. */
    if (ikcp_send(s->kcp, (const char *)msg, (int)len) != (int)len) {
        s->broken = 1;
        return SN_CS_ERR;
    }
    ikcp_update(s->kcp, now_ms);
    return SN_CS_OK;
}

int sn_client_session_input(sn_client_session *s, const uint8_t *datagram, size_t len,
                            uint32_t now_ms) {
    if (!s || !s->kcp || !datagram) return SN_CS_ERR;

    /* One buffer, reused for the opened envelope and then for each drained
     * message. Two live at once cost ~3.5 KB of stack on the datagram path,
     * against the 4 KB task stacks an ESP32 integrator typically budgets --
     * a stack overflow rather than a bug report. */
    uint8_t plain[SN_WIRE_MTU];
    size_t  plain_len = 0;
    uint64_t seq = 0;
    /* §7.5 bounds the envelope in both directions: KCP's own header plus the
     * envelope is the floor, WIRE_MTU the ceiling. Sub-floor junk otherwise
     * reaches the AEAD and the replay window for no reason. */
    if (len < SN_KCP_OVERHEAD + SN_ENVELOPE_LEN || len > SN_WIRE_MTU) return 0;
    /* §8.1 in one call: reconstruct, range-check, open, then test-and-mark. A
     * failure at any stage is a silent drop -- §8.1 makes a forged datagram
     * indistinguishable from noise deliberately. */
    if (!sn_replay_open(&s->s2c_replay, s->k_kcp_s2c, /*c2s=*/0, datagram, len,
                        plain, &plain_len, &seq)) {
        return 0;
    }
    s->accepted++;
    if (ikcp_input(s->kcp, (const char *)plain, (long)plain_len) < 0) {
        return 0;
    }
    ikcp_update(s->kcp, now_ms);

    /* Push, not pull: drain everything the stream now holds. */
    int delivered = 0;
    for (;;) {
        /* Re-checked every iteration: the callback is where an integrator
         * naturally writes "the device is gone, close it", and that frees the
         * session out from under this loop. Cheap, and the alternative is a
         * NULL dereference in the most obvious use of the API. */
        if (!s->kcp) break;
        int n = ikcp_recv(s->kcp, (char *)plain, (int)sizeof plain);
        if (n <= 0) break;
        if (s->on_msg) s->on_msg(s->msg_ctx, plain, (size_t)n);
        delivered++;
    }
    return delivered;
}

void sn_client_session_update(sn_client_session *s, uint32_t now_ms) {
    if (!s || !s->kcp) return;
    ikcp_update(s->kcp, now_ms);
}
