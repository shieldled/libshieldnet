/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * The §7 client state machine.
 *
 * Five states, one-shot take-control, INIT up to three times, byte-identical
 * FINISH resends, then the promoting PUSH. Mirrors goshieldnet/v1/client.go's
 * states and transitions; it does NOT mirror its blocking surface.
 *
 * **Nothing here blocks, starts a thread, takes a lock, or reads a clock.**
 * The caller owns the socket, so the caller owns the thread that reads it:
 *
 *     sn_client_take_control(...)         -> SN_CLIENT_IN_PROGRESS
 *     loop:
 *         recvfrom(...)                   -> sn_client_input(dg, len, now_ms)
 *         on timeout                      -> sn_client_tick(now_ms)
 *     until sn_client_get_state() is ESTABLISHED or IDLE
 *
 * The socket MUST be connected to the device (connect(2)) before the first
 * datagram is read. sn_client_input takes no source address, so the kernel's
 * connected-socket filter is what keeps datagrams from any other address out
 * (transport 7.2, 8; transport 10.2: "a socket bound to a wildcard address does
 * not provide this until it is connected"). A connected UDP socket also
 * reports an ICMP error as ECONNREFUSED (or similar) on the next recv/send: the
 * caller MUST ignore it -- no state change, no teardown (transport 9.4 item 4).
 * host/sn_client_host.c does both.
 *
 * All sn_client_* calls on one client must be externally serialised. On
 * FreeRTOS that means one task owns it and everything reaches it by queue --
 * the RX task posts datagrams, the app posts writes -- rather than wrapping a
 * mutex around a shared client. xQueueReceive's timeout is what drives the
 * tick, so the timers cost no timer.
 *
 * A consumer that wants Go's blocking shape wraps this: one thread, poll(), and
 * a condition variable over IN_PROGRESS. That wrapper is host/sn_client_host.c,
 * not this file.
 */
#ifndef SHIELDNET_CLIENT_H
#define SHIELDNET_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "shieldnet/sn_client_session.h"
#include "shieldnet/sn_app_frame.h"
#include "shieldnet/sn_client_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* §2 client timing, mirroring goshieldnet/v1/device.go's constants. */
#define SN_INIT_RETRY_MS        1000u
#define SN_INIT_TRANSMISSIONS   3u
#define SN_FINISH_RETRY_MS      500u
/* A deployment constant (transport 4.2): a deployment may set it, below
 * SN_COOKIE_EPOCH_MS; src/sn_client.c checks that at compile time. */
#ifndef SN_FINISH_PHASE_MS
#define SN_FINISH_PHASE_MS      1500u
#endif
#define SN_PUSH_ACK_TIMEOUT_MS  2000u
#define SN_SESSION_DEAD_MS     10000u

/* The largest first message a take-control can carry. It is held until the
 * promoting PUSH goes out, so it is a fixed buffer rather than a caller pointer
 * whose lifetime this cannot see. */
#define SN_CLIENT_FIRST_MAX 512

/* The smallest buffer sn_client_set_compress_buffer needs for the largest
 * message an app buffer set sized SN_CS_MSG_MAX + 64 can carry: LZ4's worst
 * case, written out so this header needs no lz4.h. sn_client.c asserts it
 * against LZ4_COMPRESSBOUND. */
#define SN_CLIENT_COMPRESS_BUF_MIN \
    ((SN_CS_MSG_MAX + 64) + (SN_CS_MSG_MAX + 64) / 255 + 16)

typedef enum {
    SN_CLIENT_IDLE = 0,
    SN_CLIENT_AWAIT_RETRY,
    SN_CLIENT_AWAIT_ADMIT,
    SN_CLIENT_AWAIT_PUSH_ACK,
    SN_CLIENT_ESTABLISHED
} sn_client_state;

/* Why the client last left a session for IDLE. Set by every return to IDLE, and
 * cleared by the next take-control (not by the return to IDLE itself, which
 * would erase it). SN_CLIENT_END_NONE before any session. */
typedef enum {
    SN_CLIENT_END_NONE = 0,
    SN_CLIENT_END_ATTEMPT_FAILED, /* INIT, FINISH or PUSH_ACK phase timed out */
    SN_CLIENT_END_INTERNAL,       /* session init, the promoting write or a probe send failed */
    SN_CLIENT_END_DESYNC,         /* the app stream lost framing */
    SN_CLIENT_END_SEQ_EXHAUSTED,  /* §3.6: the c2s sequence space ran out */
    SN_CLIENT_END_DEAD,           /* §7.2 liveness expired */
    SN_CLIENT_END_BROKEN,         /* a send may have queued part of a message */
    SN_CLIENT_END_USER            /* sn_client_close */
} sn_client_end_reason;

#define SN_CLIENT_OK           0
#define SN_CLIENT_ERR         -1
#define SN_CLIENT_IN_PROGRESS  1   /* the attempt is running; keep pumping */
#define SN_CLIENT_FAILED       2   /* the attempt ended; the client is IDLE again */

/* One decoded application message: its MessageType, bits 0-30 (bit 31, the
 * compression flag, is cleared; message layer 4.1), and its payload. The sled
 * layer takes its kind from the low byte (sled 3.1): (uint8_t)message_type. The payload
 * points into the client's buffers and is valid only for the call. Same
 * contract as the session's raw callback -- enqueue, do not re-enter, do not
 * block.
 *
 * The one exception, for this callback and the raw one alike, is ending the
 * session: "the device said goodbye, close it" is where an integrator writes
 * sn_client_close or sn_client_free, so both are tolerated from inside it.
 * Nothing after the callback touches the wiped state, the remaining bytes of
 * that datagram are dropped, and sn_client_input reports SN_CLIENT_FAILED.
 * Releasing the sn_client's own memory from the callback is NOT tolerated:
 * the caller is still on the stack holding a pointer into it. */
typedef void (*sn_client_app_fn)(void *ctx, uint32_t message_type, const uint8_t *body, size_t len);

typedef struct {
    uint8_t  psk[32];
    uint8_t  device_id[8];
    uint8_t  own_source[18];   /* §4.3 canonical_source of our own socket, an
                                * INPUT (§7.2) -- this never opens one */
    uint32_t conv;             /* §8.4: the client chooses it */
    /* Without this the client cannot be dropped into any existing test,
     * all of which fix their nonce and ephemeral key so a failure replays, and
     * the differential fuzzer cannot drive both stacks from one seed. NULL uses
     * the platform CSPRNG. */
    void (*rand_fill)(void *ctx, uint8_t *buf, size_t n);
    void *rand_ctx;
} sn_client_config;

typedef struct {
    sn_client_config cfg;
    sn_client_state  state;

    uint8_t k_dev[32], k_req[32], k_resp[32];

    /* Per attempt. All of this is wiped on any return to IDLE. */
    uint8_t  nonce[24];
    uint8_t  ec_priv[32], e_c[32];
    uint8_t  init[SN_INIT_LEN];
    uint8_t  finish[SN_FINISH_LEN];   /* kept for byte-identical resends (§6.2) */
    uint8_t  context[65];
    uint8_t  sent_ae[8];              /* what FINISH presented; §7.4 step 2 */
    uint8_t  first[SN_CLIENT_FIRST_MAX];
    size_t   first_len;

    /* §7.4's required dh cache, keyed on e_s. An attacker can flip one octet of
     * a captured admit_tag and replay at line rate; without this each copy buys
     * a scalar multiplication. */
    uint8_t  cached_es[32], cached_dh[32];
    int      dh_cached;

    unsigned init_sent;
    uint32_t next_tx_ms;      /* next INIT or FINISH retransmission */
    uint32_t phase_end_ms;    /* end of the current phase */

    sn_client_session sess;
    int               sess_live;

    /* §7.2 liveness. last_rx_ms is when the most recent ACCEPTED s2c envelope
     * arrived; outstanding is the "unacknowledged data outstanding" gate.
     *
     * The gate is not optional. Without it a healthy but idle controller is
     * torn down every SESSION_DEAD_MS, and since §9.5 forbids the device
     * reclaiming its primary for inactivity, the device would be left holding
     * an orphan while the client pays a full re-admission. §7.2 is explicit
     * that a quiet controller "learns nothing until it next sends". */
    uint32_t last_rx_ms;
    int      outstanding;
    /* Whether last_rx_ms holds a time at all. It used to be "last_rx_ms != 0",
     * but 0 is an ordinary uint32 millisecond reading -- at boot, and once
     * every ~49.7 days -- and an envelope accepted at that instant disarmed
     * the timer for the rest of the session. */
    int      liveness_armed;
    /* Message layer 8 item 2: how long a message may stay partly read. Set
     * when carry first holds octets of an unfinished frame (header included),
     * cleared when a frame is consumed; the ESTABLISHED tick ends the session
     * SN_MID_FRAME_BUDGET_MS later. A flag beside the time, as for liveness,
     * because 0 is a valid now_ms. */
    int      partial_armed;
    uint32_t partial_since_ms;
    /* When outstanding last went from false to true, or the last accepted
     * envelope that left data unacknowledged (transport 10.3). §7.2's timer runs from
     * max(last_rx_ms, outstanding_since_ms): measuring from last_rx_ms alone
     * meant that after an idle spell longer than SESSION_DEAD_MS the first
     * write was declared dead at the next tick, instead of the client waiting
     * "the full 10 s" for an answer. Meaningful only while outstanding. */
    uint32_t outstanding_since_ms;
    int      dead;

    sn_client_send_fn send;
    void             *send_ctx;
    sn_client_msg_fn  on_msg;
    void             *msg_ctx;

    /* The app layer, the same core the device uses with the keys swapped:
     * the client reads s2c and writes c2s. Buffers are caller-owned, exactly as
     * the device's are -- an ESP32 integrator sizes them, rather than finding
     * four of them inside this struct. */
    sn_app_rx  app_rx;
    sn_app_tx  app_tx;
    int        app_ready;
    int        app_first;       /* the promoting PUSH is a framed app message */
    int        app_first_pad;
    uint8_t    app_first_kind;
    int        desync;          /* framing lost; the session cannot continue */
    uint8_t   *comp;   size_t comp_size;   /* LZ4 output; see set_compress_buffer */
    sn_client_end_reason end_reason;
    uint8_t   *carry;  size_t carry_size, carry_len;
    uint8_t   *raw;    size_t raw_size;
    sn_client_app_fn on_app;
    void            *app_ctx;

    /* Bumped on every return to IDLE (close, free, failure). Code that calls
     * out to a user callback snapshots it first: a callback that closes the
     * client wipes the very state the caller was about to touch next. */
    unsigned         gen;
} sn_client;

/* Calls sodium_init itself (idempotent and thread-safe), since everything
 * here draws on libsodium -- the CSPRNG and the X25519 above all -- and a
 * caller that never initialised it would otherwise run on whatever state it
 * happens to be in. Returns SN_CLIENT_OK, or SN_CLIENT_ERR on NULL arguments
 * or when sodium_init fails (the client is then left untouched). */
int  sn_client_init(sn_client *c, const sn_client_config *cfg);
void sn_client_free(sn_client *c);

void sn_client_set_send(sn_client *c, sn_client_send_fn fn, void *ctx);
void sn_client_set_on_msg(sn_client *c, sn_client_msg_fn fn, void *ctx);

sn_client_state sn_client_get_state(const sn_client *c);

/* Why the last session ended; see sn_client_end_reason. Only meaningful once
 * the client is IDLE again. */
sn_client_end_reason sn_client_get_end_reason(const sn_client *c);

/* One-shot (§7.2): refused unless IDLE. first_msg becomes the promoting PUSH
 * once ADMIT arrives, sent as it is: it MUST be one complete sealed frame,
 * since the first message on the stream is a sealed message (transport 12.2).
 * len 0 is refused with SN_CLIENT_ERR. The _app variants below seal for you
 * and accept an empty body. Returns SN_CLIENT_IN_PROGRESS, or SN_CLIENT_ERR. */
int sn_client_take_control(sn_client *c, const uint8_t *first_msg, size_t len,
                           uint32_t now_ms);

/* One inbound datagram, read from a socket connected to the device (see the
 * top of this file: the connection is the source check of transport 7.2, 8;
 * an ICMP error the socket reports is ignored, transport 9.4 item 4).
 * Returns SN_CLIENT_IN_PROGRESS while the attempt runs,
 * SN_CLIENT_OK once ESTABLISHED, SN_CLIENT_FAILED if the attempt just ended.
 * A datagram that fails any check is discarded and the state is unchanged --
 * §7.3 keeps waiting rather than failing the attempt. */
int sn_client_input(sn_client *c, const uint8_t *datagram, size_t len, uint32_t now_ms);

/* Drives retransmission and the phase deadlines. Same return values. */
int sn_client_tick(sn_client *c, uint32_t now_ms);

/* Application write; only valid once ESTABLISHED. Returns SN_CS_* from the
 * session, so SN_CS_QUEUE_FULL is §9.5's refusal, which a retry can get past
 * once the queue drains. A message that could never fit -- above SN_CS_MSG_MAX,
 * or whose whole KCP segments exceed SN_SEND_QUEUE_MAX (message layer 7.3) --
 * is refused at once with SN_CS_ERR, nothing queued and the session intact. A failed send that may
 * have queued part of the message (KCP out of memory) is fatal instead: the
 * session is ended, the client is IDLE on return, and a fresh take-control
 * is the only way on -- retrying would put those bytes in the stream twice.
 * The same holds for the sn_client_send_app variants below. */
int sn_client_send(sn_client *c, const uint8_t *msg, size_t len, uint32_t now_ms);

/* Whether §7.2's liveness timer expired on the last session: no authenticated
 * datagram for SESSION_DEAD_MS while data was outstanding. Cleared by the next
 * take-control. Mirrors goshieldnet's Client.SessionDead. */
int sn_client_session_dead(const sn_client *c);

/* End the current session and return to IDLE, keeping the client usable: the
 * static keys derived from the PSK survive, so a take-control can follow
 * without re-initialising from the PSK.
 *
 * This is the difference between "the device rebooted, reconnect" and "throw
 * the client away". Without it, and without the liveness rule above, an
 * ESTABLISHED client whose device vanished could never leave that state --
 * take-control refuses unless IDLE -- and was wedged for good. */
void sn_client_close(sn_client *c);

/* ── the app layer ───────────────────────────────────────────────────────
 *
 * Buffers are caller-owned and must outlive the client, mirroring
 * sn_agent_init: carry reassembles the KCP stream across datagrams, raw holds
 * one frame's ciphertext, dec/decomp the plaintext, enc the outbound
 * ciphertext. Size dec/decomp/enc for the largest message you will exchange.
 * Without this the client still carries raw bytes; only the app layer is off.
 *
 * Minimum sizes: the device pads its responses to §13's class (message layer
 * 6.3), so even a short STATUS can arrive as a 512-octet class. raw_size MUST
 * be at least SN_PAD_MAX_CLASS + CRYPTO_OVERHEAD (528) and dec_size at least
 * SN_PAD_MAX_CLASS (512), plus whatever larger messages you exchange; carry_size
 * at least PROTOCOL_HEADER_SIZE + raw_size. A frame larger than raw_size ends
 * the session with a desync. These sizes are not checked here.
 *
 * MUST be called while the client is IDLE, before take-control. The app keys
 * are derived at ADMIT and only if the buffers are already bound, so binding
 * them afterwards leaves the tx key all zero and the stream callback pointed
 * at the raw path: every send is sealed under a zero key and dropped by the
 * device, and nothing is ever delivered to the app callback. Returns
 * SN_CLIENT_OK, or SN_CLIENT_ERR when the client is not IDLE (in which case
 * nothing is bound). */
int sn_client_set_app_buffers(sn_client *c,
                              uint8_t *carry, size_t carry_size,
                              uint8_t *raw, size_t raw_size,
                              uint8_t *dec, size_t dec_size,
                              uint8_t *decomp, size_t decomp_size,
                              uint8_t *enc, size_t enc_size);
void sn_client_set_on_app(sn_client *c, sn_client_app_fn fn, void *ctx);

/* Frame and send one application message. Only valid once ESTABLISHED.
 *
 * A controller MUST NOT send a private kind (the top 32 command kinds, sled 3.1)
 * to a device that does not advertise the `x-` capability it belongs to, and
 * never as a probe: two vendors may give the same value different meanings
 * (sled 7.8). */
int sn_client_send_app(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                       uint32_t now_ms);

/* As above, padded to §13's smallest size class. Opt-in per message, as in Go:
 * §13 permits padding for control and configuration, forbids it on a pixel
 * frame, and cannot combine it with compression. Bodies above
 * SN_PAD_MAX_CLASS are sent unpadded, never refused (message layer 6.2 item 2). */
int sn_client_send_app_padded(sn_client *c, uint8_t kind, const uint8_t *body, size_t len,
                              uint32_t now_ms);

/* The MessageNum of the last app message sealed, 0 while none has been (before
 * ADMIT). The promoting message is #1, so this is 1 in AWAIT_PUSH_ACK and the
 * first send_app after it makes it 2. A seal that the send queue then refuses
 * with SN_CS_QUEUE_FULL STILL consumes its number: a gap is legal, since the
 * receiver only requires strictly increasing numbers. Read it right after a send
 * that returned SN_CS_OK to learn that message's number. */
uint64_t sn_client_last_tx_num(const sn_client *c);

/* The largest app-message body sn_client_send_app and its variants accept on an
 * empty send queue: the queue cap in whole segments, less the 20-byte frame
 * header and the 16-byte tag. 0 before ADMIT. 32508 at the default constants.
 * A longer body is refused at once with SN_CS_ERR (message layer 7.3), nothing
 * queued and the session intact. */
size_t sn_client_max_app_body(const sn_client *c);

/* Where sn_client_send_app_compressed puts LZ4 output. Caller-owned, must
 * outlive the client, and should be at least SN_CLIENT_COMPRESS_BUF_MIN. MUST be
 * called while the client is IDLE, like sn_client_set_app_buffers. Returns
 * SN_CLIENT_OK, or SN_CLIENT_ERR when the client is not IDLE. */
int sn_client_set_compress_buffer(sn_client *c, uint8_t *buf, size_t size);

/* As sn_client_send_app, but LZ4-compressed when that makes the body shorter
 * (§13: for pixel frames and bulk content, never for control messages), in which
 * case the MessageType's compression flag is set before the AEAD's AAD is built.
 * An incompressible body, or one that does not fit the compress buffer, goes out
 * exactly as sn_client_send_app would send it. SN_CLIENT_ERR when no compress
 * buffer is set. */
int sn_client_send_app_compressed(sn_client *c, uint8_t kind, const uint8_t *body,
                                  size_t len, uint32_t now_ms);

/* take_control whose promoting PUSH is a framed application message rather
 * than raw bytes -- what a real controller sends, since the device's app layer
 * is what reads it. Requires the app buffers to be set first.
 *
 * body may be NULL with len 0: the payload-free kinds (PING, GET_STATUS,
 * GET_DEVICE_INFO) are the ones a controller usually opens with, and they still
 * produce a frame. */
int sn_client_take_control_app(sn_client *c, uint8_t kind,
                               const uint8_t *body, size_t len, uint32_t now_ms);

/* take_control_app with the promoting message padded (§13). The promoting
 * message of §8.5(c) is control in every use this API has. */
int sn_client_take_control_app_padded(sn_client *c, uint8_t kind,
                                      const uint8_t *body, size_t len, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_CLIENT_H */
