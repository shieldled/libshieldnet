/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * sn_client_fuzz — sequence fuzzing for the §7 client state machine.
 *
 * The mirror of sn_state_fuzz.c, which does this for the device. The differential oracle compares single datagrams; this compares
 * nothing — it drives ORDERINGS, which is where a state machine breaks. A
 * client that admits twice, or frees a session it is still reading from, or
 * keeps a secret after returning to IDLE, fails here and nowhere else.
 *
 * A real device runs alongside, so the RETRY and ADMIT the client sees are
 * genuine: forgery is what the differential fuzzer covers, and using junk here
 * would only ever exercise the rejection paths. What varies is the ORDER —
 * dropped datagrams, duplicates, replays out of phase, ticks between anything.
 *
 * Programs are (op, arg) pairs on stdin. SHIELDNET_FUZZ_STATS=1 reports what a
 * program actually reached, so a seed that exercises nothing is visible.
 *
 * Ops (op % 13):
 *   0  take-control (app mode: framed PING-ish kind; raw mode: raw first msg)
 *   1  device answers whatever the client last sent (INIT/FINISH/envelope)
 *   2  deliver the device's last handshake/ACK datagram to the client
 *   3  clock advances by arg*8+1 ms, client tick
 *   4  replay a stashed device datagram, out of phase
 *   5  junk datagram, length chosen by arg (see junk_len)
 *   6  clock jump: near 0 / near UINT32_MAX / across the wrap / ~SESSION_DEAD
 *   7  arm a re-entrant callback: on_app / on_msg calls close, free, or both
 *   8  sn_client_free + re-init the client, in app mode or raw mode
 *   9  the device pushes s2c app data (whole, split, garbage header, ...)
 *  10  the device pushes the pending tail of a split frame, or raw stream bytes
 *  11  deliver the device's queued s2c data datagrams (drop/reorder/duplicate)
 *  12  device tick (KCP retransmissions) and drain of c2s bytes
 *
 * Clock mapping. One 64-bit monotonic millisecond counter, now64, is the only
 * clock. The device takes it as is wherever it wants 64 bits (INIT, FINISH,
 * envelope, the tick's now_ms) and its low 32 bits wherever it wants 32 (KCP,
 * the tick's now_ms_lo, sn_primary_send). The client only ever sees
 * (uint32_t)now64. Clock jumps only move now64 FORWARD, so the device stays
 * monotonic; "jump near 0" therefore means "advance to the next 2^32 boundary
 * plus a little", which the client sees as its 32-bit clock wrapping -- the
 * thing the (int32_t)(now - t) comparisons and liveness_armed exist for.
 */
#include "shieldnet/sn_client.h"
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_source.h"
#include "shieldnet/crypto.h"
#include "protocol.h"
#include "lz4.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1, 2, 3, 4, 5, 6, 7, 8};
#define PORT 5000

static void v4m(uint8_t a[16], uint8_t d) {
    memset(a, 0, 16); a[10] = 0xff; a[11] = 0xff;
    a[12] = 192; a[13] = 168; a[14] = 4; a[15] = d;
}
static void fixed_rand(void *c, uint8_t *b, size_t n) { (void)c; memset(b, 0x42, n); }

/* The client's randomness is a splitmix64 stream seeded from the program, so
 * successive attempts within one run draw distinct nonces, ephemerals and
 * jitter, and the whole run still replays exactly from its input. */
static uint64_t g_rng;
static uint64_t splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}
static void cli_rand(void *c, uint8_t *b, size_t n) {
    (void)c;
    while (n) {
        uint64_t v = splitmix64(&g_rng);
        for (int i = 0; i < 8 && n; i++, n--) { *b++ = (uint8_t)v; v >>= 8; }
    }
}

/* One-slot mailboxes each way for the handshake and ACKs; the program decides
 * what is delivered. */
static uint8_t g_to_dev[2048]; static size_t g_to_dev_len;
static uint8_t g_to_cli[2048]; static size_t g_to_cli_len;

/* While the device is pushing app data (or ticking), what it emits is queued
 * instead, so a frame that spans several datagrams is not lost to the
 * one-slot mailbox. Op 11 delivers the queue. */
#define QN 8
static uint8_t g_q[QN][2048]; static size_t g_q_len[QN]; static unsigned g_q_n;
static int g_capture;

static void cli_send(void *c, const uint8_t *d, size_t l) {
    (void)c; if (l <= sizeof g_to_dev) { memcpy(g_to_dev, d, l); g_to_dev_len = l; }
}
static void dev_send(void *c, const uint8_t *d, size_t l) {
    (void)c;
    if (l > sizeof g_to_cli) return;
    if (g_capture) {
        if (g_q_n == QN) { /* full: drop the oldest, as a congested link would */
            memmove(g_q[0], g_q[1], sizeof g_q[0] * (QN - 1));
            memmove(g_q_len, g_q_len + 1, sizeof g_q_len[0] * (QN - 1));
            g_q_n--;
        }
        memcpy(g_q[g_q_n], d, l); g_q_len[g_q_n] = l; g_q_n++;
        return;
    }
    memcpy(g_to_cli, d, l); g_to_cli_len = l;
}

/* ── re-entrant callbacks ──────────────────────────────────────────────────
 * Op 7 arms an action that the Nth app message (on_app) or raw stream chunk
 * (on_msg) performs on the client from inside the callback: close, free, or
 * close-then-free. The documented contract (sn_client.h) is that nothing after
 * the callback touches the wiped state, the rest of the datagram is dropped,
 * and sn_client_input returns SN_CLIENT_FAILED; deliver() checks all three. */
#define CB_CLOSE 1
#define CB_FREE  2
static int      g_cb_action;     /* 0, CB_CLOSE, CB_FREE, CB_CLOSE|CB_FREE */
static unsigned g_cb_countdown;
static int      g_cb_acted;      /* what the callback did during this input */
static unsigned n_cb_app, n_cb_msg, n_cb_close, n_cb_free;

static void cb_common(sn_client *c) {
    if (g_cb_acted) {
        /* The client ended inside an earlier callback of this same input, and
         * was still delivering. That is a use of wiped state. */
        fprintf(stderr, "callback delivered after the client was closed/freed\n");
        abort();
    }
    if (!g_cb_action) return;
    if (g_cb_countdown) { g_cb_countdown--; return; }
    int a = g_cb_action;
    g_cb_action = 0;   /* one-shot */
    if (a & CB_CLOSE) { sn_client_close(c); n_cb_close++; }
    if (a & CB_FREE)  { sn_client_free(c);  n_cb_free++; }
    g_cb_acted = a;
}
static void on_app(void *ctx, uint32_t k, const uint8_t *b, size_t l) {
    (void)k; (void)b; (void)l;
    n_cb_app++;
    cb_common(ctx);
}
static void on_msg(void *ctx, const uint8_t *b, size_t l) {
    (void)b; (void)l;
    n_cb_msg++;
    cb_common(ctx);
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* ── client setup ──────────────────────────────────────────────────────── */
static sn_client_config g_cfg;
static int g_raw_mode;   /* 1: no app buffers, raw on_msg path */
static uint8_t carry[4096], raw_buf[2048], dec[2048], decomp[2048], enc[2048];

static void client_setup(sn_client *c) {
    sn_client_init(c, &g_cfg);
    sn_client_set_send(c, cli_send, NULL);
    if (!g_raw_mode) {
        sn_client_set_app_buffers(c, carry, sizeof carry, raw_buf, sizeof raw_buf,
                                  dec, sizeof dec, decomp, sizeof decomp, enc, sizeof enc);
    }
    sn_client_set_on_app(c, on_app, c);
    sn_client_set_on_msg(c, on_msg, c);
}

/* After sn_client_free, everything long-lived must be gone too. */
static void check_freed(const sn_client *c) {
    if (sn_client_get_state(c) != SN_CLIENT_IDLE || c->sess_live ||
        !all_zero(c->k_dev, 32) || !all_zero(c->k_req, 32) ||
        !all_zero(c->k_resp, 32) || !all_zero(c->cfg.psk, 32) ||
        !all_zero(c->ec_priv, 32) || !all_zero(c->nonce, 24)) {
        fprintf(stderr, "sn_client_free left state or keys behind\n");
        abort();
    }
}

static unsigned n_reinit, n_desync_close, n_input_failed;

/* Every datagram reaches the client through here, so the callback contract is
 * checked on every path that can run a callback. */
static int deliver(sn_client *c, const uint8_t *dg, size_t len, uint32_t now) {
    sn_client_state before = sn_client_get_state(c);
    g_cb_acted = 0;
    int rc = sn_client_input(c, dg, len, now);
    if (g_cb_acted) {
        if (rc != SN_CLIENT_FAILED || sn_client_get_state(c) != SN_CLIENT_IDLE ||
            c->sess_live) {
            fprintf(stderr, "callback ended the client but input returned %d, state %d\n",
                    rc, (int)sn_client_get_state(c));
            abort();
        }
        if (g_cb_acted & CB_FREE) {
            check_freed(c);
            /* The struct is still ours (free only wipes); it must be
             * re-initialised before anything else touches it. */
            client_setup(c);
            n_reinit++;
        }
        g_cb_acted = 0;
        n_input_failed++;
    } else if ((before == SN_CLIENT_AWAIT_PUSH_ACK || before == SN_CLIENT_ESTABLISHED) &&
               sn_client_get_state(c) == SN_CLIENT_IDLE) {
        /* The only way input leaves a session for IDLE without a callback is
         * app_drain losing the stream position. */
        if (rc != SN_CLIENT_FAILED) {
            fprintf(stderr, "session ended in input but rc=%d\n", rc);
            abort();
        }
        n_desync_close++;
    }
    return rc;
}

/* Feed whatever the client last emitted to the device, and let the device
 * answer. The device is not under test here; it is the source of real messages. */
static void pump_device(sn_device *d, uint8_t src_last, uint64_t now64) {
    if (!g_to_dev_len) return;
    uint8_t src[16]; v4m(src, src_last);
    sn_class cls = sn_classify_datagram(SN_ROLE_DEVICE, g_to_dev, g_to_dev_len);
    if (cls == SN_CLASS_INIT) {
        uint8_t retry[SN_RETRY_LEN];
        if (sn_handle_init(d, g_to_dev, g_to_dev_len, src, PORT, now64, retry) == SN_RETRY_LEN) {
            dev_send(NULL, retry, SN_RETRY_LEN);
        }
    } else if (cls == SN_CLASS_FINISH) {
        uint8_t admit[SN_ADMIT_LEN];
        if (sn_handle_finish(d, g_to_dev, g_to_dev_len, src, PORT, now64, admit) == SN_ADMIT_LEN) {
            dev_send(NULL, admit, SN_ADMIT_LEN);
        }
    } else {
        sn_handle_envelope(d, g_to_dev, g_to_dev_len, src, PORT, now64);
    }
    g_to_dev_len = 0;
}

/* ── the device as an s2c app sender ───────────────────────────────────────
 * Bound to the current primary with sn_primary_bind_app, exactly as an agent
 * is; a new generation re-binds and restarts MessageNum at 1. Frames are
 * written into the primary's KCP stream with sn_primary_send_gen. */
#define FRAME_MAX 2200
static struct {
    int      bound;
    uint32_t gen;
    sn_app_tx tx;
    uint8_t  enc[2048];
    uint8_t  tail[FRAME_MAX]; size_t tail_len;   /* rest of a split frame */
    uint8_t  last[FRAME_MAX]; size_t last_len;   /* last whole frame, for replay */
    unsigned split_sel;
} g_dv;

static unsigned n_dev_whole, n_dev_split, n_dev_tail, n_dev_garbage, n_dev_double,
                n_dev_padded, n_dev_authodd, n_dev_replay, n_dev_twowrite, n_dev_rawbytes,
                n_dev_qfull, n_dev_end, n_dev_nobind, n_q_deliver, n_dev_tick;

static int dev_bind(sn_device *d) {
    if (g_dv.bound && sn_device_session_active(d, g_dv.gen)) return 1;
    uint32_t gen = 0;
    uint8_t kc[32], ks[32];
    int ok = sn_primary_bind_app(d, &gen, kc, ks) == 0;
    if (ok && (!g_dv.bound || gen != g_dv.gen)) {
        sn_app_tx_init(&g_dv.tx, ks, g_dv.enc, sizeof g_dv.enc);
        g_dv.tail_len = 0;
        g_dv.last_len = 0;
    }
    sodium_memzero(kc, 32); sodium_memzero(ks, 32);
    g_dv.bound = ok;
    g_dv.gen = gen;
    if (!ok) n_dev_nobind++;
    return ok;
}

/* sn_primary_send queues and calls ikcp_update, but at an unchanged timestamp
 * KCP does not flush until its next interval: a real device's tick is what
 * sends the data. So every device write op ends with this -- the clock moves
 * one KCP interval (device and client alike, per the mapping at the top) and
 * the device flushes into the capture queue. */
static void dev_flush(sn_device *d, uint64_t *now64) {
    *now64 += d->tuning.interval > 0 ? (uint64_t)d->tuning.interval : 1u;
    g_capture = 1;
    sn_primary_update(d, (uint32_t)*now64);
    g_capture = 0;
}

static void dev_write(sn_device *d, const uint8_t *buf, size_t len, uint32_t now) {
    if (!len) return;
    g_capture = 1;
    int r = sn_primary_send_gen(d, g_dv.gen, buf, (int)len, now);
    g_capture = 0;
    if (r == (int)len) return;
    if (r == SN_SEND_QUEUE_FULL) { n_dev_qfull++; return; }
    /* Anything else may have queued part of it: end the session, as an agent
     * must. The client sees silence. */
    sn_device_end_primary(d, g_dv.gen);
    g_dv.bound = 0;
    n_dev_end++;
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static void put_hdr(uint8_t *p, uint32_t size, uint32_t orig, uint32_t type, uint64_t num) {
    put_be32(p, size); put_be32(p + 4, orig); put_be32(p + 8, type);
    for (int i = 0; i < 8; i++) p[12 + i] = (uint8_t)(num >> (56 - 8 * i));
}

/* A conforming frame: header || sn_app_seal(_padded) ciphertext. */
static size_t build_frame(uint8_t *out, uint8_t kind, const uint8_t *body, size_t len, int pad) {
    uint32_t type = 0, original = 0; uint64_t num = 0; size_t ct = 0;
    int rc = pad ? sn_app_seal_padded(&g_dv.tx, kind, body, len, &type, &num, &original, &ct)
                 : sn_app_seal(&g_dv.tx, kind, body, len, &type, &num, &original, &ct);
    if (rc != 0 || PROTOCOL_HEADER_SIZE + ct > FRAME_MAX) return 0;
    put_hdr(out, (uint32_t)ct, original, type, num);
    memcpy(out + PROTOCOL_HEADER_SIZE, g_dv.enc, ct);
    return PROTOCOL_HEADER_SIZE + ct;
}

/* An AUTHENTIC frame whose header does not conform: the compressed flag over a
 * real or bogus LZ4 body, or an original_size that disagrees with the
 * plaintext. It passes the AEAD, so it reaches sn_app_open's post-decrypt
 * checks from the client side. */
static size_t build_odd_frame(uint8_t *out, uint8_t kind, const uint8_t *body, size_t len,
                              unsigned variant) {
    uint8_t pt[1100];
    size_t pt_len = len;
    uint32_t type = kind, orig = (uint32_t)len;
    switch (variant % 5) {
    case 0: { /* genuinely compressed */
        int n = LZ4_compress_default((const char *)body, (char *)pt, (int)len, (int)sizeof pt);
        if (n <= 0) return 0;
        pt_len = (size_t)n; type |= PROTOCOL_FLAG_COMPRESSED; break;
    }
    case 1: /* compressed flag over bytes that are not LZ4 */
        memcpy(pt, body, len); type |= PROTOCOL_FLAG_COMPRESSED; orig = (uint32_t)len * 3 + 1; break;
    case 2: /* original_size larger than the plaintext */
        memcpy(pt, body, len); orig = (uint32_t)len + 1 + (uint32_t)(variant >> 3); break;
    case 3: /* original_size smaller, plaintext not a padding class */
        memcpy(pt, body, len); orig = len ? (uint32_t)len / 2 : 0; if (len == 64) { pt[64] = 0; pt_len = 65; } break;
    default: /* huge original_size: the ladder bound */
        memcpy(pt, body, len); orig = 0x80000000u | (uint32_t)len; break;
    }
    if (g_dv.tx.next_msgnum == UINT64_MAX) return 0;
    uint64_t num = g_dv.tx.next_msgnum++;
    uint32_t ct_len = (uint32_t)(pt_len + CRYPTO_OVERHEAD);
    if (PROTOCOL_HEADER_SIZE + ct_len > FRAME_MAX) return 0;
    uint8_t aad[PROTOCOL_HEADER_SIZE], nonce[CRYPTO_NONCE_SIZE];
    protocol_marshal_aad(ct_len, orig, type, num, aad);
    protocol_nonce_from_msgnum(num, nonce);
    size_t ol = 0;
    if (crypto_encrypt(g_dv.tx.key, nonce, pt, pt_len, aad, sizeof aad,
                       out + PROTOCOL_HEADER_SIZE, &ol) != 0 || ol != ct_len) return 0;
    memcpy(out, aad, PROTOCOL_HEADER_SIZE);
    return PROTOCOL_HEADER_SIZE + ct_len;
}

/* Header sizes that must make the client desync (or wait), never overflow:
 * all-ones, top bit, one past raw (2048), one past what carry can hold after a
 * header (4096 - 20), exactly raw, and the sub-tag sizes the AEAD refuses. */
static const uint32_t GARBAGE_SIZES[8] = {
    0xFFFFFFFFu, 0x80000000u, 2049u, 4077u, 2048u, 0u, 15u, 16u,
};

static void dev_push(sn_device *d, uint8_t arg, uint64_t *now64) {
    if (!dev_bind(d)) return;
    uint32_t now = (uint32_t)*now64;
    /* Never start a new frame in the middle of a split one: that is a sender
     * bug, not a network event. Op 10 (raw bytes) is the deliberate version. */
    if (g_dv.tail_len) {
        dev_write(d, g_dv.tail, g_dv.tail_len, now);
        g_dv.tail_len = 0;
        n_dev_tail++;
        if (!g_dv.bound) return;
        dev_flush(d, now64);
        now = (uint32_t)*now64;
    }
    unsigned mode = arg & 7;
    size_t blen = (size_t)(arg >> 3) * 32u;           /* 0..992 */
    uint8_t kind = (uint8_t)(arg * 31u + 7u);
    uint8_t body[1024];
    for (size_t i = 0; i < blen; i++) body[i] = (uint8_t)(i * 13u + arg);
    if (mode == 4 || mode == 5) { if (blen > 512) blen = 512; }

    static uint8_t f[2 * FRAME_MAX];
    size_t n = 0;
    switch (mode) {
    case 0: /* one whole frame */
        n = build_frame(f, kind, body, blen, 0);
        if (n) { dev_write(d, f, n, now); n_dev_whole++; }
        break;
    case 1: { /* split: head now, tail by op 10 (or the next push) */
        n = build_frame(f, kind, body, blen, 0);
        if (n < 2) break;
        static const size_t cuts[6] = {1, 19, 20, 21, 0, 0};
        size_t sel = g_dv.split_sel++ % 6;
        size_t cut = sel == 4 ? n / 2 : sel == 5 ? n - 1 : cuts[sel];
        if (cut >= n) cut = n - 1;
        dev_write(d, f, cut, now);
        if (!g_dv.bound) break;
        memcpy(g_dv.tail, f + cut, n - cut);
        g_dv.tail_len = n - cut;
        n_dev_split++;
        break;
    }
    case 2: { /* garbage header: size field from the table, junk after it */
        put_hdr(f, GARBAGE_SIZES[(arg >> 3) & 7], (uint32_t)arg * 0x01010101u,
                arg, (uint64_t)arg << 8 | 1u);
        size_t extra = (size_t)(arg >> 6) * 16u;
        memset(f + PROTOCOL_HEADER_SIZE, arg ^ 0x5a, extra);
        dev_write(d, f, PROTOCOL_HEADER_SIZE + extra, now);
        n_dev_garbage++;
        break;
    }
    case 3: { /* two frames in one write: several messages per datagram */
        size_t b = blen > 400 ? 400 : blen;
        size_t a = build_frame(f, kind, body, b, 0);
        size_t c2 = a ? build_frame(f + a, (uint8_t)(kind + 1), body, b / 2, 0) : 0;
        if (a && c2) { dev_write(d, f, a + c2, now); n_dev_double++; }
        break;
    }
    case 4: /* padded to a §13 class */
        n = build_frame(f, kind, body, blen, 1);
        if (n) { dev_write(d, f, n, now); n_dev_padded++; }
        break;
    case 5: /* authentic, non-conforming header */
        n = build_odd_frame(f, kind, body, blen, arg >> 3);
        if (n) { dev_write(d, f, n, now); n_dev_authodd++; }
        break;
    case 6: /* re-send the last whole frame: a stale MessageNum */
        if (g_dv.last_len) { dev_write(d, g_dv.last, g_dv.last_len, now); n_dev_replay++; }
        break;
    case 7: /* header and body as separate writes, so separate segments */
        n = build_frame(f, kind, body, blen, 0);
        if (n) {
            dev_write(d, f, PROTOCOL_HEADER_SIZE, now);
            dev_flush(d, now64);   /* header and body in different datagrams */
            now = (uint32_t)*now64;
            if (g_dv.bound) dev_write(d, f + PROTOCOL_HEADER_SIZE, n - PROTOCOL_HEADER_SIZE, now);
            n_dev_twowrite++;
        }
        break;
    }
    if (n && n <= FRAME_MAX && (mode == 0 || mode == 4 || mode == 7)) {
        memcpy(g_dv.last, f, n); g_dv.last_len = n;
    }
    if (g_dv.bound) dev_flush(d, now64);
}

/* Junk lengths around every boundary the classifier and envelope path have. */
static size_t junk_len(uint8_t arg) {
    static const size_t lens[] = {
        96, 0, 1, 7, 8, 9, 10, 19, 20, 43, 44, 45, 63, 64,
        SN_ADMIT_LEN - 1, SN_ADMIT_LEN, SN_ADMIT_LEN + 1,
        SN_RETRY_LEN - 1, SN_RETRY_LEN, SN_RETRY_LEN + 1,
        SN_INIT_LEN, SN_FINISH_LEN + 1, 512,
        SN_WIRE_MTU - 1, SN_WIRE_MTU, SN_WIRE_MTU + 1, 1500,
    };
    return lens[(arg >> 2) % (sizeof lens / sizeof lens[0])];
}

int sn_client_run_program(const uint8_t *prog, size_t n) {
    if (sodium_init() < 0) return 0;
    memset(PSK, 0x11, 32);

    /* Everything static is per run: libFuzzer calls this repeatedly. */
    g_to_dev_len = g_to_cli_len = 0;
    g_q_n = 0; g_capture = 0;
    g_cb_action = 0; g_cb_countdown = 0; g_cb_acted = 0;
    memset(&g_dv, 0, sizeof g_dv);
    g_raw_mode = 0;
    n_cb_app = n_cb_msg = n_cb_close = n_cb_free = 0;
    n_reinit = n_desync_close = n_input_failed = 0;
    n_dev_whole = n_dev_split = n_dev_tail = n_dev_garbage = n_dev_double = 0;
    n_dev_padded = n_dev_authodd = n_dev_replay = n_dev_twowrite = n_dev_rawbytes = 0;
    n_dev_qfull = n_dev_end = n_dev_nobind = n_q_deliver = n_dev_tick = 0;
    g_rng = 0xcbf29ce484222325ull;   /* FNV-1a over the program */
    for (size_t i = 0; i < n; i++) { g_rng ^= prog[i]; g_rng *= 0x100000001b3ull; }

    sn_device d; sn_prefix local;
    memset(&local, 0, sizeof local);
    v4m(local.a16, 1); local.is_v4 = 1; local.bits = 24;
    uint8_t cookie[32]; memset(cookie, 0x22, 32);
    uint8_t ae[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&d, kd, DEVICE_ID, cookie, ae, &local, 1, 8000);
    d.rand_fill = fixed_rand;
    sn_device_locks_init(&d);
    sn_device_set_send(&d, dev_send, NULL);

    memset(&g_cfg, 0, sizeof g_cfg);
    memcpy(g_cfg.psk, PSK, 32);
    memcpy(g_cfg.device_id, DEVICE_ID, 8);
    uint8_t src[16]; v4m(src, 2);
    sn_canonical_source(src, PORT, g_cfg.own_source);
    g_cfg.conv = 0xC11E27u;
    g_cfg.rand_fill = cli_rand;

    sn_client c;
    client_setup(&c);

    /* Kept so a replay can be delivered out of phase later. */
    static uint8_t stash[2048]; size_t stash_len = 0;

    unsigned n_take = 0, n_deliver = 0, n_tick = 0, n_estab = 0, n_replay = 0, n_junk = 0;
    unsigned n_clk_near0 = 0, n_clk_nearmax = 0, n_clk_cross = 0, n_clk_dead = 0;
    unsigned n_wrap_seen = 0, n_live_wrap = 0, n_dead = 0, n_raw_take = 0, n_raw_reinit = 0;
    uint64_t now64 = 20000;
#define NOW ((uint32_t)now64)

    /* Every client tick goes through here so wrap-sensitive outcomes count. */
#define CLIENT_TICK() do {                                                        \
        if (sn_client_get_state(&c) == SN_CLIENT_ESTABLISHED && c.liveness_armed && \
            NOW < c.last_rx_ms) n_live_wrap++; /* 32-bit clock wrapped since rx */ \
        int trc_ = sn_client_tick(&c, NOW);                                       \
        if (trc_ == SN_CLIENT_FAILED && sn_client_session_dead(&c)) n_dead++;    \
        n_tick++;                                                                 \
    } while (0)

    for (size_t i = 0; i + 1 < n; i += 2) {
        uint8_t op = prog[i], arg = prog[i + 1];
        uint32_t prev_now = NOW;
        switch (op % 13) {
        case 0: /* start an attempt; refused unless IDLE, which is the point */
            if (g_raw_mode) {
                uint8_t first[64];
                size_t fl = arg & 0x3f;
                memset(first, arg, fl);
                if (sn_client_take_control(&c, fl ? first : NULL, fl, NOW)
                        == SN_CLIENT_IN_PROGRESS) { n_take++; n_raw_take++; }
            } else if (sn_client_take_control_app(&c, arg ? arg : 0x07, NULL, 0, NOW)
                    == SN_CLIENT_IN_PROGRESS) n_take++;
            break;
        case 1: /* let the device answer whatever the client last sent */
            pump_device(&d, 2, now64);
            break;
        case 2: /* deliver what the device produced */
            if (g_to_cli_len) {
                if (stash_len == 0 || (arg & 1)) {
                    memcpy(stash, g_to_cli, g_to_cli_len);
                    stash_len = g_to_cli_len;
                }
                size_t l = g_to_cli_len;
                g_to_cli_len = 0;
                deliver(&c, g_to_cli, l, NOW);
                n_deliver++;
            }
            break;
        case 3: /* time advances: retransmissions and phase caps */
            now64 += (uint64_t)arg * 8u + 1u;
            CLIENT_TICK();
            break;
        case 4: /* replay something the device sent earlier, out of phase */
            if (stash_len) {
                deliver(&c, stash, stash_len, NOW);
                n_replay++;
            }
            break;
        case 5: /* junk at whatever state the client is in */
            {
                static uint8_t junk[1500];
                size_t jl = junk_len(arg);
                memset(junk, arg, jl);
                if ((arg & 1) && jl >= 10) { /* sometimes wear a valid header */
                    static const uint8_t magic[8] = {'S','L','D','1','Z','0','0','1'};
                    memcpy(junk, magic, 8);
                    junk[8] = (arg & 2) ? 0x02 : 0x06;
                    junk[9] = 0x01;
                }
                deliver(&c, junk, jl, NOW);
                n_junk++;
            }
            break;
        case 6: /* clock jumps; now64 only ever moves forward (see top) */
            {
                uint32_t k = arg >> 2;               /* 0..63 */
                uint64_t hi = now64 >> 32;
                uint32_t lo = NOW;
                uint32_t target;
                switch (arg & 3) {
                case 0: /* client clock near 0 */
                    target = k * 16u;
                    now64 = ((lo < target ? hi : hi + 1) << 32) | target;
                    n_clk_near0++;
                    CLIENT_TICK();
                    break;
                case 1: /* client clock near UINT32_MAX */
                    target = UINT32_MAX - k * 16u;
                    now64 = ((lo < target ? hi : hi + 1) << 32) | target;
                    n_clk_nearmax++;
                    CLIENT_TICK();
                    break;
                case 2: /* just below the wrap, tick, then just past it, tick */
                    target = UINT32_MAX - k * 8u;
                    now64 = ((lo < target ? hi : hi + 1) << 32) | target;
                    CLIENT_TICK();
                    now64 += (uint64_t)k * 16u + 16u;
                    n_clk_cross++;
                    CLIENT_TICK();
                    break;
                default: /* straddle SESSION_DEAD_MS in one step */
                    now64 += SN_SESSION_DEAD_MS - 512u + k * 16u;
                    n_clk_dead++;
                    CLIENT_TICK();
                    break;
                }
            }
            break;
        case 7: /* arm a re-entrant callback */
            {
                static const int acts[4] = {0, CB_CLOSE, CB_FREE, CB_CLOSE | CB_FREE};
                g_cb_action = acts[arg & 3];
                g_cb_countdown = (arg >> 2) & 3;
            }
            break;
        case 8: /* free the client and bring it back, app or raw mode */
            sn_client_free(&c);
            check_freed(&c);
            g_raw_mode = arg & 1;
            client_setup(&c);
            if (g_raw_mode) n_raw_reinit++;
            n_reinit++;
            break;
        case 9: /* the device sends s2c app data */
            dev_push(&d, arg, &now64);
            break;
        case 10: /* the rest of a split frame, or raw bytes into the stream */
            if (!dev_bind(&d)) break;
            if (g_dv.tail_len) {
                dev_write(&d, g_dv.tail, g_dv.tail_len, NOW);
                g_dv.tail_len = 0;
                n_dev_tail++;
            } else {
                uint8_t b[256];
                size_t bl = (size_t)arg + 1u;
                for (size_t j = 0; j < bl; j++) b[j] = (uint8_t)(arg + j * 7u);
                dev_write(&d, b, bl, NOW);
                n_dev_rawbytes++;
            }
            if (g_dv.bound) dev_flush(&d, &now64);
            break;
        case 11: /* deliver queued device data: maybe drop one, reverse, duplicate */
            {
                static uint8_t q[QN][2048]; size_t ql[QN]; unsigned qn = g_q_n;
                for (unsigned j = 0; j < qn; j++) { memcpy(q[j], g_q[j], g_q_len[j]); ql[j] = g_q_len[j]; }
                g_q_n = 0;   /* the client's answers must not land in this copy */
                unsigned drop = (arg & 1) ? (unsigned)(arg >> 4) % (qn ? qn : 1) : QN;
                for (unsigned j = 0; j < qn; j++) {
                    unsigned idx = (arg & 2) ? qn - 1 - j : j;
                    if (idx == drop) continue;
                    deliver(&c, q[idx], ql[idx], NOW);
                    if (arg & 4) deliver(&c, q[idx], ql[idx], NOW);
                    n_q_deliver++;
                    if (ql[idx] <= sizeof stash && (arg & 8)) {
                        memcpy(stash, q[idx], ql[idx]); stash_len = ql[idx];
                    }
                }
            }
            break;
        case 12: /* device tick: KCP retransmits; drain what the client sent */
            {
                g_capture = 1;
                sn_device_tick(&d, NOW, now64);
                g_capture = 0;
                uint8_t sink[2048];
                for (int j = 0; j < 8; j++) {
                    if (sn_primary_recv(&d, sink, (int)sizeof sink) <= 0) break;
                }
                n_dev_tick++;
            }
            break;
        default: break;
        }
        if (NOW < prev_now) n_wrap_seen++;

        /* Invariants, after every step.
         *
         * IDLE must hold no attempt secrets: the client puts the wipe on the failure
         * path precisely because that is the branch least likely to run it, and
         * a fuzzer reaching IDLE by an unusual route is how that gets tested. */
        if (sn_client_get_state(&c) == SN_CLIENT_IDLE) {
            if (!all_zero(c.ec_priv, 32) || !all_zero(c.nonce, 24)) {
                fprintf(stderr, "IDLE with attempt secrets still set\n");
                abort();
            }
            if (c.sess_live) {
                fprintf(stderr, "IDLE with a live session\n");
                abort();
            }
        }
        if (sn_client_get_state(&c) == SN_CLIENT_ESTABLISHED) {
            n_estab++;
            /* An established client must have a session; anything else is a
             * dangling pointer waiting to be dereferenced by the next send. */
            if (!c.sess_live || c.sess.kcp == NULL) {
                fprintf(stderr, "ESTABLISHED without a live session\n");
                abort();
            }
            if (g_raw_mode) {
                static const uint8_t one = 0x07;
                sn_client_send(&c, &one, 1, NOW);
            } else {
                sn_client_send_app(&c, 0x07, NULL, 0, NOW);
            }
        }
    }
#undef CLIENT_TICK
#undef NOW

    if (getenv("SHIELDNET_FUZZ_STATS")) {
        fprintf(stderr, "take=%u deliver=%u tick=%u estab=%u replay=%u junk=%u steps=%zu\n",
                n_take, n_deliver, n_tick, n_estab, n_replay, n_junk, n / 2);
        fprintf(stderr, "cb: app=%u msg=%u close=%u free=%u input_failed=%u reinit=%u "
                        "raw_reinit=%u raw_take=%u\n",
                n_cb_app, n_cb_msg, n_cb_close, n_cb_free, n_input_failed, n_reinit,
                n_raw_reinit, n_raw_take);
        fprintf(stderr, "clock: near0=%u nearmax=%u cross=%u deadjump=%u wrap_seen=%u "
                        "live_wrap=%u dead=%u\n",
                n_clk_near0, n_clk_nearmax, n_clk_cross, n_clk_dead, n_wrap_seen,
                n_live_wrap, n_dead);
        fprintf(stderr, "dev: whole=%u split=%u tail=%u garbage=%u double=%u padded=%u "
                        "authodd=%u replay=%u twowrite=%u rawbytes=%u qfull=%u end=%u "
                        "nobind=%u qdeliver=%u tick=%u desync_close=%u\n",
                n_dev_whole, n_dev_split, n_dev_tail, n_dev_garbage, n_dev_double,
                n_dev_padded, n_dev_authodd, n_dev_replay, n_dev_twowrite, n_dev_rawbytes,
                n_dev_qfull, n_dev_end, n_dev_nobind, n_q_deliver, n_dev_tick,
                n_desync_close);
    }

    sn_client_free(&c);
    sodium_memzero(&g_dv.tx, sizeof g_dv.tx);
    sn_device_release_primary(&d);
    sn_device_locks_free(&d);
    return 0;
}

#ifndef SN_CLIENT_LIBFUZZER
int main(void) {
    uint8_t prog[4096];
    size_t n = fread(prog, 1, sizeof prog, stdin);
    return sn_client_run_program(prog, n);
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 256) size = 256;
    sn_client_run_program(data, size);
    return 0;
}
#endif
