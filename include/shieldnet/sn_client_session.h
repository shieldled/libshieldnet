/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * The client's established session.
 *
 * One ikcp instance on a client-chosen conv, the c2s sequence counter feeding
 * sn_seal, an s2c replay window, and an output callback handing sealed
 * datagrams to whatever the caller uses for a socket.
 *
 * **Deliberately much smaller than the device's**. sn_session.c is ~600
 * lines because a device juggles a primary and a pending generation with §8.5
 * promotion under kcp_lock. A client has exactly one session: no generations,
 * no promotion, no lock ordering. If this file starts growing generation
 * handling, something is wrong -- stop and report.
 *
 * **Callee-threaded, and it owns no thread**. The caller owns the socket,
 * so the caller owns the thread that reads it: datagrams arrive through
 * sn_client_session_input and time arrives through sn_client_session_update.
 * Nothing here reads a clock or takes a lock, and every sn_client_session_*
 * call on one session must be externally serialised -- on FreeRTOS by giving
 * one task ownership and feeding it a queue, not by wrapping a mutex around it.
 *
 * Receive is push, not pull: input decrypts and feeds ikcp, then hands
 * whatever complete messages the stream now holds to a callback. There is no
 * blocking read, because there is no thread here to block.
 */
#ifndef SHIELDNET_CLIENT_SESSION_H
#define SHIELDNET_CLIENT_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "shieldnet/sn_device.h"  /* SN_SEND_QUEUE_MAX, which SN_CS_MSG_MAX tracks */
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_wire.h"
#include "ikcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Sealed datagram out. The callback must not re-enter the session. */
typedef void (*sn_client_send_fn)(void *ctx, const uint8_t *datagram, size_t len);

/* One reassembled application message in. Must not re-enter the session,
 * allocate, or block: a Dart FFI binding can only post to an isolate from an
 * arbitrary thread, so anything more forecloses the mobile client. */
typedef void (*sn_client_msg_fn)(void *ctx, const uint8_t *msg, size_t len);

typedef struct {
    ikcpcb          *kcp;
    uint8_t          k_kcp_c2s[32];
    uint8_t          k_kcp_s2c[32];
    sn_sender        c2s_seq;      /* §3.6 outbound allocator, fails closed on wrap */
    sn_replay_window s2c_replay;   /* §8.2, the only direction a client receives */
    uint64_t         accepted;     /* envelopes that verified (§7.2 liveness) */
    sn_client_send_fn send;
    void            *send_ctx;
    sn_client_msg_fn on_msg;
    void            *msg_ctx;
    /* §3.6: the c2s sequence space ran out. Terminal -- only a rekey clears it,
     * and KCP will otherwise retransmit a segment that can never be sealed. */
    int              seq_exhausted;
    /* ikcp_send failed or came up short, possibly after queuing part of the
     * message (ShieldNet's ikcp returns -2 on OOM mid-fragmentation). The
     * stream now holds a partial message, so this is terminal too: further
     * sends are refused and nothing more is put on the wire. */
    int              broken;
} sn_client_session;

#define SN_CS_OK             0
#define SN_CS_ERR           -1
#define SN_CS_QUEUE_FULL    -2  /* §9.5: mirrors the device's SN_SEND_QUEUE_FULL */

/* The largest single message sn_client_session_send accepts: one that could
 * never fit under §9.5's cap is a caller error, not a full queue to retry. */
#define SN_CS_MSG_MAX       SN_SEND_QUEUE_MAX

/* conv is the client's choice (§8.4). The two keys are k_kcp_c2s / k_kcp_s2c
 * from §4.5, which sn_check_admit's master produces. Zeroes the replay window
 * and sets the c2s counter to 1, which §7.4 step 5 requires exactly once per
 * attempt. Returns SN_CS_OK or SN_CS_ERR if ikcp_create fails. */
int  sn_client_session_init(sn_client_session *s, uint32_t conv,
                            const uint8_t k_kcp_c2s[32], const uint8_t k_kcp_s2c[32]);

/* Frees the ikcp instance and wipes both keys. Safe on a zeroed struct, and
 * safe to call twice. */
void sn_client_session_free(sn_client_session *s);

void sn_client_session_set_send(sn_client_session *s, sn_client_send_fn fn, void *ctx);
void sn_client_session_set_on_msg(sn_client_session *s, sn_client_msg_fn fn, void *ctx);

/* Application write. Returns SN_CS_OK, or SN_CS_QUEUE_FULL when §9.5's byte cap
 * would be exceeded -- refused rather than queued against a vanished peer, and
 * refused rather than dropped silently. now_ms drives the flush before the
 * refusal so a caller that retries can make progress.
 *
 * SN_CS_ERR for a len of 0 or above SN_CS_MSG_MAX, or whose whole segments
 * (len rounded up to mss) exceed SN_SEND_QUEUE_MAX -- such a message never fits
 * even an empty queue (message layer 7.3); nothing is queued. Also for a
 * session that is `broken`: if ikcp_send fails or is short, part of the
 * message may already be queued, so the session is marked broken and must be
 * torn down, never retried. */
int  sn_client_session_send(sn_client_session *s, const uint8_t *msg, size_t len,
                            uint32_t now_ms);

/* One inbound datagram: open the envelope under k_kcp_s2c with §8.3
 * reconstruction and the §8.2 window, feed ikcp, then drain every complete
 * message to on_msg. Returns the number of messages delivered, or SN_CS_ERR.
 * A datagram that fails the AEAD or the window is dropped and returns 0 --
 * §8.1 makes that indistinguishable from noise on purpose. */
int  sn_client_session_input(sn_client_session *s, const uint8_t *datagram, size_t len,
                             uint32_t now_ms);

/* Drives retransmission. The caller pumps this; nothing here reads a clock. */
void sn_client_session_update(sn_client_session *s, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_CLIENT_SESSION_H */
