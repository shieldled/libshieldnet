/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet device control path — §6 of shieldnet-protocol design/transport.md. Byte-for-byte
 * with goshieldnet/v1/device.go. Steps 2–3: the stateless §6.1 INIT -> RETRY and
 * the stateful §6.2 FINISH -> ADMIT with the §6.3 tuple-keyed pending table.
 * Promotion (§8.5), the §9.2 tick and §10 locks arrive in later steps. Until the
 * lock step a sn_device is used from one thread.
 */
#ifndef SHIELDNET_DEVICE_H
#define SHIELDNET_DEVICE_H

#include <stddef.h>
#include <stdint.h>

#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_source.h"
#include "shieldnet/sn_wire.h"
#include "shieldnet_os.h"
#include "ikcp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SN_COOKIE_EPOCH_MS 4000u /* COOKIE_EPOCH_MS (§2) */
/* Deployment constants (transport 4.2): a build may define each of them.
 * SN_WIRE_MTU MUST be the same on both parties.
 *
 * SN_PENDING_SLOTS and SN_WIRE_MTU size arrays in public structs (sn_device,
 * sn_agent), so each of these MUST be defined identically for every
 * translation unit that includes this header: set it on the compile target,
 * never in one source file. */
#ifndef SN_PENDING_TTL_MS
#define SN_PENDING_TTL_MS  5000u /* PENDING_TTL_MS (§2) */
#endif
#ifndef SN_PENDING_SLOTS
#define SN_PENDING_SLOTS   2     /* PENDING_SLOTS (§2, §14.0a default) */
#endif
#ifndef SN_WIRE_MTU
#define SN_WIRE_MTU        1400  /* WIRE_MTU default (§2) */
#endif
/* §9.5: a hard byte cap on snd_queue + snd_buf, so a vanished peer cannot grow
 * the send side without bound. The check runs under kcp_lock together with
 * ikcp_send, as §10.1 requires.
 *
 * This is a DEPLOYMENT constant: §2's default is 32 KiB, which matches the
 * controller's (goshieldnet clamps snd_wnd to 23 segments for the same cap).
 * §11 recommends 6144 for a constrained board — an ESP32 target SHOULD define
 * it down, which is why this is overridable rather than fixed. */
#ifndef SN_SEND_QUEUE_MAX
#define SN_SEND_QUEUE_MAX  32768
#endif

#ifdef __cplusplus
#define SN_DEVICE_STATIC_ASSERT(c, m) static_assert(c, m)
#else
#define SN_DEVICE_STATIC_ASSERT(c, m) _Static_assert(c, m)
#endif
/* KCP's MTU is SN_WIRE_MTU - 20 (the envelope), and ikcp_setmtu refuses below
 * 50 with a -1 nobody checks: KCP would stay at 1400 and the output callbacks,
 * which seal into SN_WIRE_MTU + 20 bytes, would write past their buffer. So the
 * floor is 70, above the spec's KCP_OVERHEAD + ENVELOPE_LEN (44). */
SN_DEVICE_STATIC_ASSERT(SN_WIRE_MTU - 20 >= 50, "SN_WIRE_MTU must be at least 70");
SN_DEVICE_STATIC_ASSERT(SN_PENDING_SLOTS >= 1, "SN_PENDING_SLOTS must be at least 1");
SN_DEVICE_STATIC_ASSERT(SN_PENDING_TTL_MS > 0, "SN_PENDING_TTL_MS must be above 0");
/* At least one whole segment, or every write is refused. */
SN_DEVICE_STATIC_ASSERT(SN_SEND_QUEUE_MAX >= SN_WIRE_MTU - 44,
                        "SN_SEND_QUEUE_MAX must hold one segment (SN_WIRE_MTU - 44)");
/* How long a blocked application write waits for the queue to drain before it is
 * refused. Mirrors the controller's SEND_BLOCKED_MS so both roles apply the same
 * backpressure: §9.5 requires the device to resume accepting writes once the
 * total falls below the cap, so a transient full queue must not be fatal. */
#define SN_SEND_BLOCKED_MS 2000

/* One §6.3 pending slot. Fixed-size, never heap-allocated per admission; the four
 * keys are wiped whenever generation advances (§6.3 invariant). The slot also
 * carries an empty c2s replay window (§8). */
typedef struct {
    int used;
    uint8_t tuple[18]; /* source_tuple = canonical_source */
    uint8_t finish[SN_FINISH_LEN];
    uint8_t admit[SN_ADMIT_LEN];
    uint8_t k_c2s[32], k_s2c[32], k_kcp_c2s[32], k_kcp_s2c[32];
    uint32_t generation; /* device-wide-monotonic (§6.3) */
    uint32_t expiry;     /* now_ms(32) + PENDING_TTL_MS; smallest = oldest */
    sn_replay_window c2s_window; /* empty c2s replay window (§6.3) */
} sn_pending;

/* The single primary session (§8.5(c), §8.6). The device holds at most one. */
typedef struct {
    int active;
    ikcpcb *kcp;
    uint8_t k_c2s[32], k_s2c[32], k_kcp_c2s[32], k_kcp_s2c[32];
    uint8_t tuple[18];
    uint32_t generation;        /* device-wide promotion generation (§8.5(a)5) */
    sn_replay_window c2s_window; /* the marked window installed at promotion */
    sn_sender s2c_seq;          /* outbound s2c seq_full allocator (§8.4) */
    uint32_t conv;              /* bound from the first PUSH (§8.5(c)) */
    int quiesced;               /* §9.1/§9.4: dead-link latched, output stopped */
    /* Next s2c app MessageNum (§13), the app-layer nonce under k_s2c. It lives
     * here, not in the agent, so that it belongs to the key: an agent re-bound
     * to the same primary must continue the sequence, never restart it at 1 --
     * that would seal two messages under one (key, nonce). rec_lock state; set
     * to 1 at promotion (c), handed out by sn_primary_next_s2c_msgnum. */
    uint64_t app_s2c_next;
} sn_primary;

/* The §8.5(a)4 promotion buffer: everything (c) installs, copied out under the
 * continuous kcp_lock. Per-device (not a global static) so multiple responders in
 * one host process are safe; still "not the stack" per §11. */
typedef struct {
    uint8_t k_c2s[32], k_s2c[32], k_kcp_c2s[32], k_kcp_s2c[32];
    uint8_t tuple[18];
    sn_replay_window window; /* the just-marked c2s window (hwm AND bitmap) */
    uint32_t generation;     /* the claimed pending_generation */
    int filled;
} sn_promo_buf;

/* KCP transport tuning (§8.4/§11). Defaults are the RFC §11 recommendation, sized
 * so two worst-case sessions fit an ESP32 (rcv_wnd x WIRE_MTU per session). A board
 * with more memory or a streaming data plane raises rcv_wnd against its measured
 * heap; see goshieldnet's docs/tuning.md. */
typedef struct {
    int snd_wnd;  /* KCP send window (segments) */
    int rcv_wnd;  /* KCP recv window (segments) — the per-session buffer ceiling */
    int nodelay;  /* ikcp_nodelay flag */
    int interval; /* flush interval (ms) */
    int resend;   /* fast-resend threshold */
    int nc;       /* disable congestion control */
} sn_kcp_tuning;

#define SN_KCP_TUNING_DEFAULT { 32, 8, 1, 20, 2, 1 } /* §11: rcv_wnd 8 */

typedef struct {
    uint8_t device_id[8];
    uint8_t k_dev[32]; /* needed by sn_master (§4.5) */
    uint8_t k_req[32];
    uint8_t k_resp[32];
    uint8_t cookie_secret[32];
    uint8_t admission_epoch[8]; /* per boot, top-8-bits-clear nonzero (§4.2) */
    const sn_prefix *local;
    size_t n_local;

    /* §4.3 source rejection in the handlers themselves. Non-zero only for a
     * loopback test harness, via sn_device_set_source_check. */
    int source_check_off;
    /* Set by sn_device_init_kdev when libsodium could not be initialised or
     * k_dev is all zero: the device then admits nobody (every handler drops). */
    int init_failed;

    /* rec_lock state (§10.1). A cache of §4.4's tags, rolled by the §9.2 tick so
     * the common path costs no HMAC. It is never trusted for validity: INIT and
     * FINISH take the epoch from their own now_ms and use a cached tag only if
     * it is for exactly that epoch (or the one before), computing it otherwise.
     * prev_epoch names the epoch prev_epoch_tag belongs to. */
    uint32_t cookie_epoch;
    uint8_t epoch_tag[8];
    uint32_t prev_epoch;
    uint8_t prev_epoch_tag[8];
    int have_prev;
    int have_epoch;

    sn_pending pending[SN_PENDING_SLOTS];
    uint32_t gen_ctr;   /* device-wide pending_generation source (§6.3) */
    /* Device-wide primary generation source (§8.5(a)5). Every value it hands out
     * is used once: a retired primary and its successor never share one. */
    uint32_t promo_gen;

    sn_primary primary;
    sn_promo_buf promo;
    /* §10: kcp_lock is a mutex (held across a flush), rec_lock a critical section
     * (short, record/primary metadata). NULL/uninit until sn_device_locks_init. */
    shieldnet_mutex_t *kcp_lock;
    shieldnet_crit_t rec_lock;
    shieldnet_signal_t *data_ready; /* posted when the primary delivers app bytes */
    int locks_ready;

    /* Send seam: the caller-provided sink (the board's UDP loop or a test)
     * transmits a sealed datagram. Called from the KCP output callback only;
     * RETRY and ADMIT are returned to the caller. send_dgram_to receives the
     * primary's canonical_source as the destination and is preferred when set;
     * send_dgram is the older destination-less form. */
    void (*send_dgram)(void *ctx, const uint8_t *buf, size_t len);
    void (*send_dgram_to)(void *ctx, const uint8_t *buf, size_t len,
                          const uint8_t dst[18]);
    void *send_ctx;

    sn_kcp_tuning tuning; /* KCP window/interval; SN_KCP_TUNING_DEFAULT at init */

    /* Ephemeral-key source (§6.2 step 6). Defaults to randombytes_buf; tests may
     * replace it for a deterministic e_s. Randomness is the caller's, not this
     * unit's (§4.2). */
    void (*rand_fill)(void *ctx, uint8_t *buf, size_t n);
    void *rand_ctx;
} sn_device;

/* Starts a device from k_dev (spec transport 3.2): a device is given k_dev, never
 * the PSK. A device that is handed the PSK once (a configuration portal) derives
 * k_dev with the provisioning helper in shieldnet/sn_kdf.h, stores only k_dev and
 * passes it here at every start.
 *
 * k_dev is bound to the device_id it was derived for: pass that same device_id
 * (store the two together). A different one -- e.g. a MAC read that fell back to
 * another interface -- admits nobody, with no error.
 *
 * Calls sodium_init itself (idempotent, thread-safe). Returns 0 when the device is
 * ready, or -1 with the device left fail-closed (it logs, holds no derived keys,
 * and every handler drops: init_failed) when libsodium could not be initialised,
 * k_dev is all zero (what a failed provisioning leaves, and what an unwritten
 * store slot may read as), or admission_epoch is zero or has any of its top 8
 * bits set (transport 3.4). A store erased to 0xFF is the caller's to detect. The
 * caller MUST check the result and not serve on -1.
 *
 * What the integrator must provide (README.md, "Integrator obligations"):
 *   - cookie_secret and admission_epoch drawn from a ready CSPRNG at every
 *     start; the epoch non-zero with its top 8 bits clear; neither persisted
 *     (transport 3.4, transport 3.5). Only k_dev is stored, never the
 *     pre-shared key.
 *   - an interface that emits no ICMP echo replies or unreachables, and a
 *     socket that inbound ICMP does not affect (transport 9.4 items 3-4);
 *   - a socket bound to one interface, and `local` kept current: an empty
 *     prefix table silently skips the own-address and broadcast checks
 *     (transport 7.2, transport 7.3);
 *   - IP reassembly off on the socket's path where the platform allows it
 *     (transport 5.7, a SHOULD);
 *   - no priority for session output over RETRY/ADMIT (transport 9.4 item 6);
 *   - sn_agent_end called when a step ends the session (message layer 8). */
int sn_device_init_kdev(sn_device *d, const uint8_t k_dev[32], const uint8_t device_id[8],
                        const uint8_t cookie_secret[32], const uint8_t admission_epoch[8],
                        const sn_prefix *local, size_t n_local, uint64_t now_ms);

/* §4.3 is enforced by sn_handle_init / sn_handle_finish themselves (against
 * `local`), not only by sn_classify, so a board that demuxes with
 * sn_classify_datagram still drops a rejected source. enforce=0 turns that off
 * and exists ONLY for a loopback harness (host/sn_host.c), whose 127.0.0.1 peer
 * §4.3 rejects. Default: enforced. */
void sn_device_set_source_check(sn_device *d, int enforce);

void sn_device_roll_epoch(sn_device *d, uint64_t now_ms);

/* §6.1 INIT -> RETRY. Returns SN_RETRY_LEN and writes RETRY to out, or 0 to drop.
 * (src_a16, src_port) is the datagram's UDP source; a §4.3-rejected source drops
 * (see sn_device_set_source_check). No state is created. now_ms is the same
 * 64-bit monotonic clock sn_handle_finish and the §9.2 tick take: the cookie is
 * issued under the epoch it falls in (§4.4), whatever the tick has cached. */
size_t sn_handle_init(sn_device *d, const uint8_t *datagram, size_t len,
                      const uint8_t src_a16[16], uint16_t src_port, uint64_t now_ms,
                      uint8_t out[SN_RETRY_LEN]);

/* §6.2 FINISH -> ADMIT in the mandated order. Returns SN_ADMIT_LEN and writes the
 * ADMIT to out, or 0 to drop. now_ms is a monotonic-ms reading for expiry;
 * (src_a16, src_port) is the UDP source (its canonical_source is the tuple
 * binding, §6.2 step 3); a §4.3-rejected source drops. now_ms also bounds the
 * cookie (§4.4): it is accepted only if issued in now_ms's epoch or the one
 * before, whatever the tick has cached -- 4-8 s, stalled tick or not. */
size_t sn_handle_finish(sn_device *d, const uint8_t *datagram, size_t len,
                        const uint8_t src_a16[16], uint16_t src_port, uint64_t now_ms,
                        uint8_t out[SN_ADMIT_LEN]);

/* §10 locks: create kcp_lock and init rec_lock. Must be called before any
 * envelope/promotion path. sn_device_locks_free releases kcp_lock. */
/* Index of the pending slot holding tuple, or -1. Shared by the handshake and
 * envelope paths. */
int sn_find_pending_index(const sn_device *d, const uint8_t tuple[18]);

void sn_device_locks_init(sn_device *d);
void sn_device_locks_free(sn_device *d);

/* Override the KCP tuning (§8.4/§11). Must be set before any promotion; applies
 * to sessions promoted after the call. See goshieldnet's docs/tuning.md. */
void sn_device_set_tuning(sn_device *d, sn_kcp_tuning tuning);

/* The sink that transmits a fully-sealed datagram (the board's UDP loop or a
 * test). Called from the KCP output callback (§8.4) under kcp_lock.
 *
 * Prefer sn_device_set_send_to: dst is the primary's canonical_source (a16 ||
 * port_be, §4.3), the tuple the session was promoted on. A sink that instead
 * remembers "the last source that sent an envelope" is steered by any
 * unauthenticated datagram that classifies as an envelope -- one junk datagram
 * per KCP interval from an off-path host redirects every ACK and retransmit
 * until the session dies. */
void sn_device_set_send(sn_device *d,
                        void (*fn)(void *ctx, const uint8_t *buf, size_t len),
                        void *ctx);
void sn_device_set_send_to(sn_device *d,
                           void (*fn)(void *ctx, const uint8_t *buf, size_t len,
                                      const uint8_t dst[18]),
                           void *ctx);

/* §8.1 envelope path. Called for a datagram §5 classified as envelope. Returns
 * SN_ENV_ESTABLISHED if consumed by the primary, SN_ENV_PROMOTED if it drove a
 * promotion, SN_ENV_DROP if dropped. */
typedef enum { SN_ENV_DROP = 0, SN_ENV_ESTABLISHED = 1, SN_ENV_PROMOTED = 2 } sn_env_result;
sn_env_result sn_handle_envelope(sn_device *d, const uint8_t *datagram, size_t len,
                                 const uint8_t src_a16[16], uint16_t src_port,
                                 uint64_t now_ms);

/* Read decrypted application bytes from the established primary's KCP stream.
 * Returns the number of bytes written to buf (<=cap), 0 if none ready, <0 on
 * error / no primary. */
int sn_primary_recv(sn_device *d, uint8_t *buf, int cap);
/* As sn_primary_recv, but consumes only while the primary still carries `gen`.
 * A caller bound to one session must use this: see the note in sn_session.c. */
int sn_primary_recv_gen(sn_device *d, uint32_t gen, uint8_t *buf, int cap);

/* Queue application bytes on the primary and flush (seals via send_dgram, §8.4).
 * Returns len on success; SN_SEND_QUEUE_FULL if §9.5's cap would be exceeded
 * (nothing was queued: the caller MUST drop or retry); or -1 if there is no
 * session, the primary changed during the call, or KCP failed after possibly
 * queuing part of the message -- the stream may then hold a partial message,
 * so a caller framing messages must end the session, never retry. */
#define SN_SEND_QUEUE_FULL (-2)
int sn_primary_send(sn_device *d, const uint8_t *msg, int len, uint32_t now_ms);
/* As sn_primary_send, but queues only while the primary still carries `gen`
 * (-1 otherwise). A caller bound to one session must use this: a retiring
 * agent writing mid-promotion would otherwise put bytes sealed under the old
 * keys into the new session's stream. A send that fails for any reason other
 * than SN_SEND_QUEUE_FULL may have queued part of the message, so the session
 * must end -- never retry it. */
int sn_primary_send_gen(sn_device *d, uint32_t gen, const uint8_t *msg, int len,
                        uint32_t now_ms);

/* Bind an app layer to the current primary: copies its generation and its
 * k_c2s/k_s2c in ONE rec_lock section, so the keys always belong to the
 * generation (promotion wipes them in (a)5 and rewrites them in (c)). Returns 0,
 * or -1 if there is no active primary (*gen is then still written, and matches
 * no live session). The caller wipes the key copies. */
int sn_primary_bind_app(sn_device *d, uint32_t *gen, uint8_t k_c2s[32], uint8_t k_s2c[32]);

/* Allocate the next s2c app MessageNum for the primary carrying `gen`. Returns
 * 0 and writes *msgnum, or -1 if that session is gone or the space is exhausted
 * (rekey required). Each value is handed out once per primary. */
int sn_primary_next_s2c_msgnum(sn_device *d, uint32_t gen, uint64_t *msgnum);

/* End the primary carrying `gen`: what an agent's "<0: end the session" means.
 * Detaches and wipes it and frees its KCP object; a no-op if `gen` is no longer
 * the primary (a promotion already replaced it). The client sees silence and
 * re-admits. Must not be called from inside a send sink. */
void sn_device_end_primary(sn_device *d, uint32_t gen);

/* Drive KCP timers for the primary (the §9.2 tick calls this). */
void sn_primary_update(sn_device *d, uint32_t now_ms);

/* §9.2 maintenance tick: roll the cached epoch_tag on a boundary, sweep pending
 * expiry, drive the primary's KCP (and latch §9.4 quiesce on dead-link). now_ms is
 * the 64-bit clock (§2); now_ms_lo its low-32 KCP timebase. Safe in every state. */
void sn_device_tick(sn_device *d, uint32_t now_ms_lo, uint64_t now_ms);

/* Run sn_device_tick on a background thread every interval_ms (shieldnet_os).
 * One tick per process on the host. Returns 0 on success. */
int sn_device_start_tick(sn_device *d, uint32_t interval_ms);
void sn_device_stop_tick(void);

/* Capture the current primary generation after a promotion, and test whether the
 * primary is still that same session — the generation-aware end condition an agent
 * loop uses (both read under rec_lock). */
/* Release the primary KCP object and wipe its keys at teardown (promotion frees the
 * OLD primary, so the last one would otherwise leak). Call once, after the tick and
 * agent are stopped. Safe when there is no primary. */
void sn_device_release_primary(sn_device *d);

/* Wipe every key the device holds -- k_dev, k_req, k_resp, cookie_secret and the
 * keys of any pending slot -- at teardown. Call after sn_device_release_primary
 * and before sn_device_locks_free; nothing may be admitting. */
void sn_device_wipe(sn_device *d);

uint32_t sn_device_current_gen(sn_device *d);
int sn_device_session_active(sn_device *d, uint32_t gen);

#ifdef SN_TEST_HOOKS
/* Test-only (compiled only with -DSN_TEST_HOOKS; absent from every real build).
 * When set, §8.5 promotion calls it once per successful claim, between (a) and
 * (b): kcp_lock held, rec_lock released, the outgoing primary already retired
 * and the new one not yet installed. It lets a test park a promotion in that
 * window and observe what another thread sees there. It must not take kcp_lock
 * (the promoting thread holds it); rec_lock-only calls are fine. */
extern void (*sn_test_promote_hook)(sn_device *d);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_DEVICE_H */
