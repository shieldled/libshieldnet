/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* The §7 client state machine against the real C device.
 *
 * Both ends in one process, wired to each other's inputs rather than a socket,
 * and the clock is a variable the test advances so retransmissions
 * fire without anything sleeping. */
#include "shieldnet/sn_agent_dispatch.h"
#include "shieldnet/sn_client.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_source.h"
#include "shieldnet/sn_app_frame.h"
#include "ikcp.h"
#include "protocol.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
static const uint16_t PORT = 5000;

static void v4mapped(uint8_t a[16], uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    memset(a, 0, 16); a[10]=0xff; a[11]=0xff; a[12]=b; a[13]=c; a[14]=d; a[15]=e;
}
static void dev_rand(void *ctx, uint8_t *buf, size_t n) { (void)ctx; memset(buf, 0x42, n); }
/* The client's randomness is fixed too, so a failure replays exactly. */
static void cli_rand(void *ctx, uint8_t *buf, size_t n) { (void)ctx; memset(buf, 0x07, n); }

/* ── the wire: a small queue each way ── */
#define QMAX 8
static uint8_t g_dev_in[QMAX][2048]; static size_t g_dev_in_len[QMAX]; static int g_dev_in_n;
static uint8_t g_cli_in[QMAX][2048]; static size_t g_cli_in_len[QMAX]; static int g_cli_in_n;

static void to_device(void *ctx, const uint8_t *dg, size_t len) {
    (void)ctx;
    if (g_dev_in_n < QMAX && len <= 2048) {
        memcpy(g_dev_in[g_dev_in_n], dg, len); g_dev_in_len[g_dev_in_n] = len; g_dev_in_n++;
    }
}
static void to_client(void *ctx, const uint8_t *dg, size_t len) {
    (void)ctx;
    if (g_cli_in_n < QMAX && len <= 2048) {
        memcpy(g_cli_in[g_cli_in_n], dg, len); g_cli_in_len[g_cli_in_n] = len; g_cli_in_n++;
    }
}

static uint8_t g_msg[2048]; static size_t g_msg_len; static int g_msg_count;
static void on_msg(void *ctx, const uint8_t *m, size_t n) {
    (void)ctx;
    if (n <= sizeof g_msg) { memcpy(g_msg, m, n); g_msg_len = n; }
    g_msg_count++;
}

/* the device's app-layer agent, for the 2.4 case */
static sn_agent *g_ag; static uint32_t g_now_dev;
static int dev_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx;
    return sn_agent_respond(g_ag, g_now_dev, kind, body, len);
}
static uint8_t g_app_kind; static int g_app_count;
static void on_app(void *ctx, uint32_t message_type, const uint8_t *body, size_t len) {
    (void)ctx; (void)body; (void)len;
    g_app_kind = (uint8_t)message_type; g_app_count++;
}

static sn_device dev;
static sn_prefix local[1];
static uint8_t src[16];

static void device_pump(uint32_t now) {
    for (int i = 0; i < g_dev_in_n; i++) {
        const uint8_t *dg = g_dev_in[i]; size_t len = g_dev_in_len[i];
        /* Dispatch on the type byte, not the length: INIT and FINISH are both
         * REQUEST_LEN (256), so a length switch feeds FINISH to sn_handle_init
         * and the admission silently never completes. */
        sn_class cls = sn_classify_datagram(SN_ROLE_DEVICE, dg, len);
        if (cls == SN_CLASS_INIT) {
            uint8_t retry[SN_RETRY_LEN];
            if (sn_handle_init(&dev, dg, len, src, PORT, now, retry) == SN_RETRY_LEN) {
                to_client(NULL, retry, SN_RETRY_LEN);
            }
        } else if (cls == SN_CLASS_FINISH) {
            uint8_t admit[SN_ADMIT_LEN];
            if (sn_handle_finish(&dev, dg, len, src, PORT, now, admit) == SN_ADMIT_LEN) {
                to_client(NULL, admit, SN_ADMIT_LEN);
            }
        } else {
            sn_handle_envelope(&dev, dg, len, src, PORT, now);
        }
    }
    g_dev_in_n = 0;
    sn_primary_update(&dev, now);
}

static int client_pump(sn_client *c, uint32_t now) {
    int rc = SN_CLIENT_IN_PROGRESS;
    for (int i = 0; i < g_cli_in_n; i++) {
        rc = sn_client_input(c, g_cli_in[i], g_cli_in_len[i], now);
    }
    g_cli_in_n = 0;
    return rc;
}

static void make_device(void) {
    memset(PSK, 0x11, 32);
    uint8_t cookie_secret[32]; memset(cookie_secret, 0x22, 32);
    uint8_t ae[8] = {0,1,2,3,4,5,6,7};
    v4mapped(local[0].a16, 192,168,4,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&dev, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
    dev.rand_fill = dev_rand;
    sn_device_locks_init(&dev);
    sn_device_set_send(&dev, to_client, NULL);
}

static void make_client(sn_client *c) {
    sn_client_config cfg; memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.psk, PSK, 32);
    memcpy(cfg.device_id, DEVICE_ID, 8);
    sn_canonical_source(src, PORT, cfg.own_source);
    cfg.conv = 0x11223344u;
    cfg.rand_fill = cli_rand;
    CHECK(sn_client_init(c, &cfg) == SN_CLIENT_OK, "client init");
    sn_client_set_send(c, to_device, NULL);
    sn_client_set_on_msg(c, on_msg, NULL);
}

static int all_zero(const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

/* ikcp's allocator seam, failing after a budget (see test_sn_client_session). */
static int g_alloc_budget = -1;
static void *budget_malloc(size_t n) {
    if (g_alloc_budget == 0) return NULL;
    if (g_alloc_budget > 0) g_alloc_budget--;
    return malloc(n);
}

/* Raw-mode admission to ESTABLISHED, starting at *t and stepping by 20 ms. */
static void establish(sn_client *c, uint32_t *t) {
    g_dev_in_n = 0; g_cli_in_n = 0;
    sn_client_take_control(c, (const uint8_t *)"hi", 2, *t);
    device_pump(*t); client_pump(c, *t);
    device_pump(*t); client_pump(c, *t);
    uint8_t got[64];
    for (int i = 0; i < 40 && sn_client_get_state(c) != SN_CLIENT_ESTABLISHED; i++) {
        *t += 20;
        device_pump(*t);
        (void)sn_primary_recv(&dev, got, (int)sizeof got);
        client_pump(c, *t);
        sn_client_tick(c, *t);
    }
}

/* App-mode admission to ESTABLISHED. The device side needs no agent: the test
 * reads the device's KCP stream itself, and one byte from the primary is what
 * confirms the promotion (the first accepted s2c envelope). */
#define APP_BUF (SN_CS_MSG_MAX + 64)
static uint8_t a_carry[2 * (APP_BUF + 20)], a_raw[APP_BUF], a_dec[APP_BUF],
               a_decomp[APP_BUF], a_enc[APP_BUF], a_comp[SN_CLIENT_COMPRESS_BUF_MIN];

static void bind_app(sn_client *c) {
    CHECK(sn_client_set_app_buffers(c, a_carry, sizeof a_carry, a_raw, sizeof a_raw,
                                    a_dec, sizeof a_dec, a_decomp, sizeof a_decomp,
                                    a_enc, sizeof a_enc) == SN_CLIENT_OK, "app buffers bound");
    CHECK(sn_client_set_compress_buffer(c, a_comp, sizeof a_comp) == SN_CLIENT_OK,
          "compress buffer bound");
    sn_client_set_on_app(c, on_app, NULL);
}

static void establish_app(sn_client *c, uint32_t *t) {
    g_dev_in_n = 0; g_cli_in_n = 0;
    bind_app(c);
    sn_client_take_control_app(c, 0x07, NULL, 0, *t);
    device_pump(*t); client_pump(c, *t);
    device_pump(*t); client_pump(c, *t);
    int told = 0;
    for (int i = 0; i < 60 && sn_client_get_state(c) != SN_CLIENT_ESTABLISHED; i++) {
        *t += 20;
        device_pump(*t);
        if (!told && dev.primary.active) {
            sn_primary_send(&dev, (const uint8_t *)"k", 1, *t);
            told = 1;
        }
        device_pump(*t);
        client_pump(c, *t);
        sn_client_tick(c, *t);
    }
}

/* What the device's KCP stream holds after pumping: bytes, drained. */
static int dev_stream(uint8_t *buf, int cap, uint32_t now) {
    device_pump(now);
    int total = 0, n;
    while (total < cap && (n = sn_primary_recv(&dev, buf + total, cap - total)) > 0) total += n;
    return total;
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Parse the one frame in `stream` and open it under the client's c2s key, which
 * is app_tx.key. Returns the header's type, original size and the opened
 * payload, so a test sees the flag on the wire and the bytes a conforming
 * receiver would deliver. */
static int open_frame(const sn_client *c, const uint8_t *stream, int n, uint32_t *type,
                      uint32_t *original, uint32_t *size, uint8_t *out, size_t *out_len) {
    if (n < PROTOCOL_HEADER_SIZE) return -1;
    protocol_msg_header_t h;
    h.size = be32(stream);
    h.original_size = be32(stream + 4);
    h.message_type = be32(stream + 8);
    h.message_num = ((uint64_t)be32(stream + 12) << 32) | be32(stream + 16);
    if ((int)(PROTOCOL_HEADER_SIZE + h.size) != n) return -1;
    static sn_app_rx rx;
    static uint8_t rdec[APP_BUF], rdecomp[APP_BUF];
    sn_app_rx_init(&rx, c->app_tx.key, rdec, sizeof rdec, rdecomp, sizeof rdecomp);
    const uint8_t *pl; size_t pl_len;
    if (sn_app_open(&rx, &h, stream + PROTOCOL_HEADER_SIZE, &pl, &pl_len) != SN_APP_OK) return -2;
    memcpy(out, pl, pl_len);
    *out_len = pl_len;
    *type = h.message_type; *original = h.original_size; *size = h.size;
    return 0;
}

static void fresh_device(void) {
    g_dev_in_n = 0; g_cli_in_n = 0;
    sn_device_release_primary(&dev);
    sn_device_locks_free(&dev);
    make_device();
}

/* App-mode take-control to ESTABLISHED with nothing sent s2c but KCP's own
 * acknowledgement of the promoting PUSH, so carry stays empty (establish_app
 * leaves its "k" there). */
static int establish_app_quiet(sn_client *c, uint32_t *t) {
    g_dev_in_n = 0; g_cli_in_n = 0;
    sn_client_take_control_app(c, 0x07, NULL, 0, *t);
    device_pump(*t); client_pump(c, *t);
    device_pump(*t); client_pump(c, *t);
    for (int i = 0; i < 100 && sn_client_get_state(c) != SN_CLIENT_ESTABLISHED; i++) {
        *t += 20;
        device_pump(*t);
        client_pump(c, *t);
        sn_client_tick(c, *t);
    }
    return sn_client_get_state(c) == SN_CLIENT_ESTABLISHED && c->carry_len == 0;
}

/* One pump step of 20 ms; returns the client's state after the tick. */
static sn_client_state step(sn_client *c, uint32_t *t) {
    *t += 20;
    device_pump(*t);
    client_pump(c, *t);
    sn_client_tick(c, *t);
    return sn_client_get_state(c);
}

/* A 20-octet header declaring a 100-octet body, then 50 body octets. */
static void partial_frame(uint8_t out[70]) {
    memset(out, 0x5a, 70);
    protocol_marshal_aad(100, 84, 0x42, 1, out);
}

int main(void) {
    /* ── sn_client_init brings libsodium up itself ──
     *
     * Before anything else in this process touches libsodium: if
     * sn_client_init did not call sodium_init, this sodium_init would be the
     * first and return 0 rather than 1. */
    {
        sn_client t0; sn_client_config z; memset(&z, 0, sizeof z);
        CHECK(sn_client_init(&t0, &z) == SN_CLIENT_OK, "init with libsodium not yet initialised");
        CHECK(sodium_init() == 1, "sn_client_init already initialised libsodium");
        sn_client_free(&t0);
    }
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }
    v4mapped(src, 192,168,4,2);
    make_device();

    sn_client c;
    make_client(&c);

    /* ── the happy path ── */
    uint32_t now = 9000;
    const char *first = "hello-device";
    CHECK(sn_client_take_control(&c, (const uint8_t *)first, strlen(first), now)
              == SN_CLIENT_IN_PROGRESS, "take_control returns IN_PROGRESS, never blocks");
    CHECK(sn_client_get_state(&c) == SN_CLIENT_AWAIT_RETRY, "AWAIT_RETRY");
    CHECK(g_dev_in_n == 1 && g_dev_in_len[0] == SN_INIT_LEN, "INIT emitted");

    device_pump(now);
    client_pump(&c, now);
    CHECK(sn_client_get_state(&c) == SN_CLIENT_AWAIT_ADMIT, "RETRY -> AWAIT_ADMIT");
    CHECK(g_dev_in_n == 1 && g_dev_in_len[0] == SN_FINISH_LEN, "FINISH emitted");

    device_pump(now);
    client_pump(&c, now);
    CHECK(sn_client_get_state(&c) == SN_CLIENT_AWAIT_PUSH_ACK, "ADMIT -> AWAIT_PUSH_ACK");

    /* KCP flushes on its interval, not on send, so the promoting PUSH and its
     * ack both need the clock stepped. Pump to the condition rather than
     * asserting on one update -- the same lesson 2.2 recorded. */
    uint8_t got[256]; int got_n = 0;
    for (int i = 0; i < 40 && sn_client_get_state(&c) != SN_CLIENT_ESTABLISHED; i++) {
        now += 20;
        device_pump(now);
        if (got_n == 0) got_n = sn_primary_recv(&dev, got, (int)sizeof got);
        client_pump(&c, now);
        sn_client_tick(&c, now);
    }
    CHECK(dev.primary.active, "device promoted on the first PUSH");
    CHECK(got_n == (int)strlen(first) && memcmp(got, first, strlen(first)) == 0,
          "device got the promoting message");
    CHECK(sn_client_get_state(&c) == SN_CLIENT_ESTABLISHED, "ESTABLISHED");

    /* ── the ephemeral private key is gone on the success path too ── */
    {
        uint8_t zero[32] = {0};
        CHECK(memcmp(c.ec_priv, zero, 32) == 0, "ephemeral private key wiped on success");
        /* And the rest of the attempt: none of it is read once the promoting
         * PUSH is queued, and `first` is up to 512 bytes of plaintext. */
        CHECK(all_zero(c.nonce, sizeof c.nonce), "nonce wiped on success");
        CHECK(all_zero(c.e_c, sizeof c.e_c), "e_c wiped on success");
        CHECK(all_zero(c.init, sizeof c.init), "INIT datagram wiped on success");
        CHECK(all_zero(c.finish, sizeof c.finish), "FINISH datagram wiped on success");
        CHECK(all_zero(c.context, sizeof c.context), "context wiped on success");
        CHECK(all_zero(c.sent_ae, sizeof c.sent_ae), "sent admission_epoch wiped on success");
        CHECK(all_zero(c.first, sizeof c.first) && c.first_len == 0,
              "first-message plaintext wiped on success");
        CHECK(all_zero(c.cached_es, sizeof c.cached_es) && all_zero(c.cached_dh, sizeof c.cached_dh),
              "dh cache wiped on success");
    }

    /* ── application traffic both ways ── */
    {
        const char *up = "up";
        CHECK(sn_client_send(&c, (const uint8_t *)up, 2, now) == SN_CS_OK, "client send");
        uint8_t g2[64]; int n = 0;
        for (int i = 0; i < 20 && n <= 0; i++) {
            now += 20;
            device_pump(now);
            n = sn_primary_recv(&dev, g2, (int)sizeof g2);
            sn_client_tick(&c, now);
        }
        CHECK(n == 2 && memcmp(g2, up, 2) == 0, "device received it");

        const char *down = "down";
        g_msg_count = 0;
        sn_primary_send(&dev, (const uint8_t *)down, 4, now);
        for (int i = 0; i < 20 && g_msg_count == 0; i++) {
            now += 20; device_pump(now); client_pump(&c, now); sn_client_tick(&c, now);
        }
        CHECK(g_msg_count == 1 && g_msg_len == 4 && memcmp(g_msg, down, 4) == 0,
              "client received the device's reply");
    }

    /* ── §7.2 is one-shot ── */
    CHECK(sn_client_take_control(&c, (const uint8_t *)"x", 1, now) == SN_CLIENT_ERR,
          "take_control on a live client is refused");

    /* ── sn_client_send's len bound: refused, nothing queued, still alive ── */
    {
        static uint8_t over[SN_CS_MSG_MAX + 1];
        CHECK(sn_client_send(&c, over, sizeof over, now) == SN_CS_ERR,
              "a send above SN_CS_MSG_MAX is refused");
        CHECK(sn_client_get_state(&c) == SN_CLIENT_ESTABLISHED,
              "and the session survives a refusal that queued nothing");
    }

    /* ── a send that may have queued part of itself ends the session ── */
    {
        static uint8_t three[3000]; memset(three, 'y', sizeof three);
        g_alloc_budget = 1;
        ikcp_allocator(budget_malloc, free);
        int rc = sn_client_send(&c, three, sizeof three, now);
        ikcp_allocator(NULL, NULL);
        g_alloc_budget = -1;
        CHECK(rc == SN_CS_ERR, "OOM inside ikcp_send is an error");
        CHECK(sn_client_get_state(&c) == SN_CLIENT_IDLE,
              "and fatal: the client is IDLE, not ESTABLISHED with a torn stream");
        CHECK(sn_client_send(&c, three, 1, now) == SN_CS_ERR, "no retry onto it");
    }
    sn_client_free(&c);

    /* ── INIT retransmission: 3 transmissions, then the attempt ends ── */
    {
        g_dev_in_n = 0; g_cli_in_n = 0;
        sn_client c2; make_client(&c2);
        uint32_t t = 20000;
        CHECK(sn_client_take_control(&c2, (const uint8_t *)"z", 1, t) == SN_CLIENT_IN_PROGRESS,
              "second client starts");
        int emitted = 1;              /* the first INIT */
        int rc = SN_CLIENT_IN_PROGRESS;
        for (int i = 0; i < 40 && rc == SN_CLIENT_IN_PROGRESS; i++) {
            t += 200;                 /* nothing answers: only the tick runs */
            g_dev_in_n = 0;
            rc = sn_client_tick(&c2, t);
            emitted += g_dev_in_n;
        }
        CHECK(emitted == (int)SN_INIT_TRANSMISSIONS, "INIT sent exactly 3 times");
        CHECK(rc == SN_CLIENT_FAILED, "attempt ends after the third");
        CHECK(sn_client_get_state(&c2) == SN_CLIENT_IDLE, "back to IDLE");
        {
            uint8_t zero[32] = {0};
            CHECK(memcmp(c2.ec_priv, zero, 32) == 0, "ephemeral key wiped on failure");
            CHECK(memcmp(c2.nonce, zero, 24) == 0, "nonce wiped on failure");
        }
        /* One-shot is per attempt, not per lifetime: IDLE accepts a new one. */
        CHECK(sn_client_take_control(&c2, (const uint8_t *)"z", 1, t) == SN_CLIENT_IN_PROGRESS,
              "a new attempt is allowed once IDLE");
        sn_client_free(&c2);
    }

    /* ── FINISH resends are byte-identical (§6.2 step 2) ── */
    {
        g_dev_in_n = 0; g_cli_in_n = 0;
        sn_device_release_primary(&dev);
        sn_device_locks_free(&dev);
        make_device();
        sn_client c3; make_client(&c3);
        uint32_t t = 30000;
        sn_client_take_control(&c3, (const uint8_t *)"q", 1, t);
        device_pump(t);
        client_pump(&c3, t);
        CHECK(sn_client_get_state(&c3) == SN_CLIENT_AWAIT_ADMIT, "reached AWAIT_ADMIT");
        uint8_t first_finish[SN_FINISH_LEN];
        memcpy(first_finish, g_dev_in[0], SN_FINISH_LEN);
        g_dev_in_n = 0;
        /* Nothing answers the FINISH, so the resend timer fires. */
        for (int i = 0; i < 10 && g_dev_in_n == 0; i++) {
            t += 200;
            sn_client_tick(&c3, t);
        }
        CHECK(g_dev_in_n == 1, "FINISH resent");
        CHECK(memcmp(first_finish, g_dev_in[0], SN_FINISH_LEN) == 0,
              "the resend is byte-identical");
        /* And the FINISH phase is capped at 1500 ms. */
        int rc = SN_CLIENT_IN_PROGRESS;
        for (int i = 0; i < 40 && rc == SN_CLIENT_IN_PROGRESS; i++) {
            t += 200; g_dev_in_n = 0;
            rc = sn_client_tick(&c3, t);
        }
        CHECK(rc == SN_CLIENT_FAILED && sn_client_get_state(&c3) == SN_CLIENT_IDLE,
              "FINISH phase capped, attempt ends");
        sn_client_free(&c3);
    }

    /* ── a forged RETRY must not end someone else's attempt (§7.3) ── */
    {
        g_dev_in_n = 0; g_cli_in_n = 0;
        sn_device_release_primary(&dev);
        sn_device_locks_free(&dev);
        make_device();
        sn_client c4; make_client(&c4);
        uint32_t t = 40000;
        sn_client_take_control(&c4, (const uint8_t *)"w", 1, t);
        device_pump(t);
        /* Corrupt the RETRY the device produced. */
        CHECK(g_cli_in_n == 1, "one RETRY in flight");
        g_cli_in[0][68] ^= 1; /* retry_mac */
        client_pump(&c4, t);
        CHECK(sn_client_get_state(&c4) == SN_CLIENT_AWAIT_RETRY,
              "forged RETRY discarded, still AWAIT_RETRY");
        sn_client_free(&c4);
    }

    /* ── the app layer end to end (2.4): a framed PING against the device's
     *    real dispatcher, and the ACK decoded back ── */
    {
        g_dev_in_n = 0; g_cli_in_n = 0;
        sn_device_release_primary(&dev);
        sn_device_locks_free(&dev);
        make_device();
        /* The device needs its app layer too, which is what answers a PING. */
        static uint8_t d_raw[2048], d_dec[2048], d_decomp[2048], d_enc[2048];
        static sn_agent ag;
        static shieldnet_device_ops_t ops;
        memset(&ops, 0, sizeof ops);
        ops.send_response = dev_send_response;
        g_ag = &ag;

        sn_client c5; make_client(&c5);
        static uint8_t carry[4096], craw[2048], cdec[2048], cdecomp[2048], cenc[2048];
        sn_client_set_app_buffers(&c5, carry, sizeof carry, craw, sizeof craw,
                                  cdec, sizeof cdec, cdecomp, sizeof cdecomp,
                                  cenc, sizeof cenc);
        sn_client_set_on_app(&c5, on_app, NULL);

        uint32_t t = 50000;
        /* PING (0x07) is payload-free; §13 pads it, which the device strips. */
        CHECK(sn_client_take_control_app(&c5, 0x07, NULL, 0, t) == SN_CLIENT_IN_PROGRESS,
              "take_control_app starts");
        device_pump(t); client_pump(&c5, t);       /* RETRY */
        device_pump(t); client_pump(&c5, t);       /* ADMIT -> promoting PUSH */
        CHECK(dev.primary.active || sn_client_get_state(&c5) == SN_CLIENT_AWAIT_PUSH_ACK,
              "app-mode admission reached the PUSH");

        /* Bind the device's agent to the promoted primary and let it answer. */
        int bound = 0;
        g_app_count = 0;
        for (int i = 0; i < 60 && g_app_count == 0; i++) {
            t += 20;
            device_pump(t);
            if (!bound && dev.primary.active) {
                sn_agent_init(&ag, &dev, &ops, d_raw, sizeof d_raw, d_dec, sizeof d_dec,
                              d_decomp, sizeof d_decomp, d_enc, sizeof d_enc);
                bound = 1;
            }
            if (bound) { g_now_dev = t; sn_agent_step(&ag, t, 1); }
            device_pump(t);
            client_pump(&c5, t);
            sn_client_tick(&c5, t);
        }
        CHECK(bound, "device agent bound to the primary");
        CHECK(g_app_count == 1, "client decoded exactly one app response");
        CHECK(g_app_kind == 0x80, "and it is an ACK (0x80)");
        sn_client_free(&c5);
    }

    /* ── §7.2 liveness with the clock at 0 and across the wrap ──
     *
     * 0 is an ordinary uint32 millisecond reading. The timer used to treat
     * last_rx_ms == 0 as "never armed", so an envelope accepted at exactly 0
     * switched dead-session detection off for the rest of the session. */
    {
        fresh_device();
        sn_client c6; make_client(&c6);
        uint32_t t = 0u - 2000u;            /* a multiple of 20 short of the wrap */
        establish(&c6, &t);
        CHECK(sn_client_get_state(&c6) == SN_CLIENT_ESTABLISHED && (int32_t)t < 0,
              "established just before the uint32 wrap");
        /* The device answers; the client takes it in at exactly t == 0. */
        sn_primary_send(&dev, (const uint8_t *)"down", 4, t);
        while (t != 0) { t += 20; device_pump(t); }
        CHECK(g_cli_in_n > 0, "the device's reply is waiting");
        client_pump(&c6, 0);
        CHECK(c6.liveness_armed && c6.last_rx_ms == 0, "an envelope accepted at now_ms == 0");
        CHECK(sn_client_send(&c6, (const uint8_t *)"up", 2, 0) == SN_CS_OK,
              "a write goes outstanding");
        int rc = SN_CLIENT_OK;
        uint32_t ended = 0;
        for (t = 100; t <= 12000 && rc == SN_CLIENT_OK; t += 100) {
            g_dev_in_n = 0; g_cli_in_n = 0;   /* the device is gone */
            rc = sn_client_tick(&c6, t);
            if (rc != SN_CLIENT_OK) ended = t;
        }
        CHECK(rc == SN_CLIENT_FAILED && sn_client_session_dead(&c6),
              "the dead-session timer still fires after a 0 timestamp");
        CHECK(ended == SN_SESSION_DEAD_MS, "and exactly at SESSION_DEAD_MS");
        sn_client_free(&c6);
    }
    {
        /* The timeout window itself straddling the wrap. */
        fresh_device();
        sn_client c7; make_client(&c7);
        uint32_t t = 0u - 6000u;
        establish(&c7, &t);
        CHECK(sn_client_get_state(&c7) == SN_CLIENT_ESTABLISHED, "established 6 s before the wrap");
        uint32_t armed = c7.last_rx_ms;
        CHECK(sn_client_send(&c7, (const uint8_t *)"up", 2, t) == SN_CS_OK, "a write goes outstanding");
        int rc = SN_CLIENT_OK;
        uint32_t ended = 0;
        for (int i = 0; i < 200 && rc == SN_CLIENT_OK; i++) {
            t += 100;
            g_dev_in_n = 0; g_cli_in_n = 0;
            rc = sn_client_tick(&c7, t);
            if (rc != SN_CLIENT_OK) ended = t;
        }
        CHECK(rc == SN_CLIENT_FAILED && sn_client_session_dead(&c7),
              "the dead-session timer fires across the wrap");
        CHECK((int32_t)(ended - armed) >= (int32_t)SN_SESSION_DEAD_MS &&
              (int32_t)(ended - armed) < (int32_t)SN_SESSION_DEAD_MS + 100 && (int32_t)ended > 0,
              "after SESSION_DEAD_MS, not before, on the far side of the wrap");
        sn_client_free(&c7);
    }
    {
        /* §7.2: the first write after an idle spell gets the full
         * SESSION_DEAD_MS. The timer used to run from last_rx_ms, so once the
         * session had been quiet for longer than that, the first tick after a
         * write declared it dead before the device could possibly answer. */
        fresh_device();
        sn_client c8; make_client(&c8);
        uint32_t t = 100000;
        establish(&c8, &t);
        CHECK(sn_client_get_state(&c8) == SN_CLIENT_ESTABLISHED && !c8.outstanding,
              "established with nothing outstanding");
        /* Idle well past SESSION_DEAD_MS: nothing outstanding, so it lives. */
        int rc = SN_CLIENT_OK;
        uint32_t idle_end = t + SN_SESSION_DEAD_MS + 5000;
        while ((int32_t)(t - idle_end) < 0 && rc == SN_CLIENT_OK) {
            t += 100;
            g_dev_in_n = 0; g_cli_in_n = 0;
            rc = sn_client_tick(&c8, t);
        }
        CHECK(rc == SN_CLIENT_OK && !sn_client_session_dead(&c8),
              "an idle session outlives SESSION_DEAD_MS");
        CHECK((int32_t)(t - c8.last_rx_ms) > (int32_t)SN_SESSION_DEAD_MS,
              "and its last rx is now older than SESSION_DEAD_MS");
        uint32_t sent = t;
        CHECK(sn_client_send(&c8, (const uint8_t *)"up", 2, sent) == SN_CS_OK,
              "a write after the idle spell goes outstanding");
        /* No rx at all: alive for every tick short of SESSION_DEAD_MS. */
        int alive = 1;
        while ((int32_t)(t + 100 - (sent + SN_SESSION_DEAD_MS)) < 0) {
            t += 100;
            g_dev_in_n = 0; g_cli_in_n = 0;
            if (sn_client_tick(&c8, t) != SN_CLIENT_OK || sn_client_session_dead(&c8)) {
                alive = 0;
                break;
            }
        }
        CHECK(alive && sn_client_get_state(&c8) == SN_CLIENT_ESTABLISHED,
              "the write waits the full SESSION_DEAD_MS, not dead on the next tick");
        /* A second write while the first is unanswered must not push the
         * deadline out. */
        CHECK(!alive || sn_client_send(&c8, (const uint8_t *)"up", 2, t) == SN_CS_OK,
              "a second write while the first is outstanding");
        t = sent + SN_SESSION_DEAD_MS;
        g_dev_in_n = 0; g_cli_in_n = 0;
        rc = sn_client_tick(&c8, t);
        CHECK(rc == SN_CLIENT_FAILED && sn_client_session_dead(&c8),
              "dead at SESSION_DEAD_MS after the first unanswered write");
        sn_client_free(&c8);
    }

    /* ── last_tx_num ── */
    {
        fresh_device();
        sn_client c9; make_client(&c9);
        CHECK(sn_client_last_tx_num(&c9) == 0, "last_tx_num: 0 before ADMIT");
        uint32_t t = 200000;
        establish_app(&c9, &t);
        CHECK(sn_client_get_state(&c9) == SN_CLIENT_ESTABLISHED, "app-mode client established");
        CHECK(sn_client_last_tx_num(&c9) == 1, "last_tx_num: the promoting message is #1");
        uint64_t got[3];
        for (int i = 0; i < 3; i++) {
            CHECK(sn_client_send_app_padded(&c9, 0x07, NULL, 0, t) == SN_CS_OK, "padded send");
            got[i] = sn_client_last_tx_num(&c9);
        }
        CHECK(got[0] == 2 && got[1] == 3 && got[2] == 4,
              "last_tx_num: 2, 3, 4 after three padded sends");
        sn_client_free(&c9);
    }

    /* ── max_app_body ── */
    {
        fresh_device();
        sn_client c10; make_client(&c10);
        CHECK(sn_client_max_app_body(&c10) == 0, "max_app_body: 0 before ADMIT");
        uint32_t t = 210000;
        establish_app(&c10, &t);
        /* Whole segments of the send queue, less the 20-byte header and 16-byte
         * tag: 24 * 1356 - 36 = 32508 at the defaults. */
        size_t mss10 = SN_WIRE_MTU - 44;
        size_t segs10 = (size_t)SN_SEND_QUEUE_MAX / mss10;
        if (segs10 > 127) segs10 = 127;   /* ikcp_send refuses 128 fragments */
        size_t max10 = segs10 * mss10 - 36;
        CHECK(sn_client_max_app_body(&c10) == max10, "max_app_body: whole segments of the queue, less the frame");
        static uint8_t big[APP_BUF];
        memset(big, 'x', sizeof big);
        int before = ikcp_waitsnd(c10.sess.kcp);
        int rc = sn_client_send_app(&c10, 0x00, big, max10 + 1, t);
        CHECK(rc != SN_CS_OK && ikcp_waitsnd(c10.sess.kcp) == before,
              "max_app_body: one byte over is refused and queues nothing");
        CHECK(sn_client_get_state(&c10) == SN_CLIENT_ESTABLISHED,
              "max_app_body: the refusal leaves the session intact");
        rc = sn_client_send_app(&c10, 0x00, big, max10, t);
        CHECK(rc == SN_CS_OK && ikcp_waitsnd(c10.sess.kcp) == before + (int)segs10,
              "max_app_body: a body of exactly that size is queued, in whole segments");
        sn_client_free(&c10);
    }

    /* ── compressed send ── */
    {
        fresh_device();
        sn_client c11; make_client(&c11);
        uint32_t t = 220000;
        establish_app(&c11, &t);
        static uint8_t stream[APP_BUF], opened[APP_BUF], body[4096];
        (void)dev_stream(stream, sizeof stream, t);   /* the promoting PING */

        memset(body, 'A', 2000);
        CHECK(sn_client_send_app_compressed(&c11, 0x00, body, 2000, t) == SN_CS_OK,
              "compressible send accepted");
        t += 20; sn_client_tick(&c11, t);   /* KCP flushes on the next interval */
        int n = dev_stream(stream, sizeof stream, t);
        uint32_t type = 0, original = 0, size = 0; size_t olen = 0;
        int orc = open_frame(&c11, stream, n, &type, &original, &size, opened, &olen);
        CHECK(orc == 0, "compressed_shrinks: the device side opens the frame under k_c2s, flag in the AAD");
        CHECK(type == (0x00u | PROTOCOL_FLAG_COMPRESSED), "compressed_shrinks: the flag is set");
        CHECK(original == 2000 && olen == 2000 && memcmp(opened, body, 2000) == 0,
              "compressed_shrinks: original_size and the original bytes arrive");
        CHECK(size < 200, "compressed_shrinks: the ciphertext is far shorter than the body");

        randombytes_buf_deterministic(body, 1000, (const uint8_t *)"0123456789abcdef0123456789abcdef");
        CHECK(sn_client_send_app_compressed(&c11, 0x00, body, 1000, t) == SN_CS_OK,
              "incompressible send accepted");
        t += 20; sn_client_tick(&c11, t);
        n = dev_stream(stream, sizeof stream, t);
        orc = open_frame(&c11, stream, n, &type, &original, &size, opened, &olen);
        CHECK(orc == 0, "compressed_incompressible: the frame opens");
        CHECK(type == 0x00u, "compressed_incompressible: the flag is clear");
        CHECK(original == 1000 && size == 1000 + 16 && olen == 1000 && memcmp(opened, body, 1000) == 0,
              "compressed_incompressible: sent at its own length, bytes intact");
        sn_client_free(&c11);

        sn_client c12; make_client(&c12);
        fresh_device();
        t = 230000;
        /* No compress buffer: refused, nothing sealed. */
        g_dev_in_n = 0; g_cli_in_n = 0;
        CHECK(sn_client_set_app_buffers(&c12, a_carry, sizeof a_carry, a_raw, sizeof a_raw,
                                        a_dec, sizeof a_dec, a_decomp, sizeof a_decomp,
                                        a_enc, sizeof a_enc) == SN_CLIENT_OK, "buffers without comp");
        sn_client_take_control_app(&c12, 0x07, NULL, 0, t);
        device_pump(t); client_pump(&c12, t);
        device_pump(t); client_pump(&c12, t);
        int told = 0;
        for (int i = 0; i < 60 && sn_client_get_state(&c12) != SN_CLIENT_ESTABLISHED; i++) {
            t += 20;
            device_pump(t);
            if (!told && dev.primary.active) { sn_primary_send(&dev, (const uint8_t *)"k", 1, t); told = 1; }
            device_pump(t); client_pump(&c12, t); sn_client_tick(&c12, t);
        }
        uint64_t before = sn_client_last_tx_num(&c12);
        CHECK(sn_client_send_app_compressed(&c12, 0x00, body, 100, t) == SN_CLIENT_ERR &&
              sn_client_last_tx_num(&c12) == before,
              "send_app_compressed without a compress buffer is SN_CLIENT_ERR and seals nothing");
        sn_client_free(&c12);
    }

    /* ── end_reason ── */
    {
        sn_client e0; make_client(&e0);
        CHECK(sn_client_get_end_reason(&e0) == SN_CLIENT_END_NONE, "end_reason: NONE before any session");
        sn_client_free(&e0);

        /* _DEAD: liveness expiry. */
        fresh_device();
        sn_client e1; make_client(&e1);
        uint32_t t = 300000;
        establish(&e1, &t);
        CHECK(sn_client_send(&e1, (const uint8_t *)"up", 2, t) == SN_CS_OK, "write goes outstanding");
        uint32_t sent = t;
        int rc = SN_CLIENT_OK;
        while (rc == SN_CLIENT_OK && (int32_t)(t - (sent + SN_SESSION_DEAD_MS + 200)) < 0) {
            t += 100; g_dev_in_n = 0; g_cli_in_n = 0;
            rc = sn_client_tick(&e1, t);
        }
        CHECK(rc == SN_CLIENT_FAILED && sn_client_get_end_reason(&e1) == SN_CLIENT_END_DEAD,
              "end_reason: liveness expiry gives DEAD");
        sn_client_free(&e1);

        /* _DESYNC: a corrupt stream header reaches the app layer. */
        fresh_device();
        sn_client e3; make_client(&e3);
        t = 320000;
        g_dev_in_n = 0; g_cli_in_n = 0;
        bind_app(&e3);
        sn_client_take_control_app(&e3, 0x07, NULL, 0, t);
        device_pump(t); client_pump(&e3, t);
        device_pump(t); client_pump(&e3, t);
        int sent_junk = 0;
        for (int i = 0; i < 60 && sn_client_get_state(&e3) != SN_CLIENT_IDLE; i++) {
            t += 20;
            device_pump(t);
            if (!sent_junk && dev.primary.active) {
                /* A length of 0xFFFFFFFF: far above raw_size, so unrecoverable. */
                uint8_t junk[24]; memset(junk, 0xFF, sizeof junk);
                sn_primary_send(&dev, junk, sizeof junk, t);
                sent_junk = 1;
            }
            device_pump(t);
            client_pump(&e3, t);
            sn_client_tick(&e3, t);
        }
        CHECK(sent_junk && sn_client_get_state(&e3) == SN_CLIENT_IDLE &&
              sn_client_get_end_reason(&e3) == SN_CLIENT_END_DESYNC,
              "end_reason: a corrupt stream gives DESYNC");
        sn_client_free(&e3);

        /* Message layer 8 item 2: a message left partly read is bounded. */
        {
            fresh_device();
            sn_client p1; make_client(&p1);
            bind_app(&p1);
            t = 400000;
            CHECK(establish_app_quiet(&p1, &t), "stall: ESTABLISHED with an empty carry");
            uint8_t part[70]; partial_frame(part);
            sn_primary_send(&dev, part, sizeof part, t);
            uint32_t T = 0; int held = 0;
            for (int i = 0; i < 100 && !held; i++) {
                step(&p1, &t);
                if (p1.carry_len > 0) { held = 1; T = t; }
            }
            CHECK(held && p1.carry_len == 70, "stall: the client holds the partial frame");
            int alive_before = 1;
            sn_client_state st = sn_client_get_state(&p1);
            while ((int32_t)(t - (T + SN_MID_FRAME_BUDGET_MS + 20)) < 0) {
                st = step(&p1, &t);
                if ((int32_t)(t - (T + SN_MID_FRAME_BUDGET_MS)) < 0 && st != SN_CLIENT_ESTABLISHED)
                    alive_before = 0;
            }
            CHECK(held && alive_before, "stall: ESTABLISHED at every tick before the budget");
            CHECK(st == SN_CLIENT_IDLE && sn_client_get_end_reason(&p1) == SN_CLIENT_END_DESYNC,
                  "stall: IDLE with DESYNC once the budget has passed");

            /* Reuse after a stall: the same client, a fresh device. Only
             * wipe_attempt can clear the stale timer here. */
            fresh_device();
            t += 1000;
            CHECK(establish_app_quiet(&p1, &t), "stall reuse: ESTABLISHED again");
            uint32_t until = t + 2000;
            int alive = 1;
            while ((int32_t)(t - until) < 0) {
                if (step(&p1, &t) != SN_CLIENT_ESTABLISHED) alive = 0;
            }
            CHECK(alive, "stall reuse: stays ESTABLISHED with nothing partial");
            sn_client_free(&p1);

            /* A peer trickling one octet every 500 ms never completes the
             * frame, and the budget still runs from the first octet. */
            {
                fresh_device();
                sn_client p3; make_client(&p3);
                bind_app(&p3);
                t += 1000;
                CHECK(establish_app_quiet(&p3, &t), "trickle setup: ESTABLISHED with an empty carry");
                sn_primary_send(&dev, part, sizeof part, t);
                uint32_t T3 = 0; int held3 = 0;
                for (int i = 0; i < 100 && !held3; i++) {
                    step(&p3, &t);
                    if (p3.carry_len > 0) { held3 = 1; T3 = t; }
                }
                uint32_t last_send = T3;
                int alive3 = held3;
                sn_client_state st3 = sn_client_get_state(&p3);
                while ((int32_t)(t - (T3 + SN_MID_FRAME_BUDGET_MS + 20)) < 0) {
                    if ((uint32_t)(t - last_send) >= 500) {
                        sn_primary_send(&dev, (const uint8_t *)"z", 1, t);
                        last_send = t;
                    }
                    st3 = step(&p3, &t);
                    if ((int32_t)(t - (T3 + SN_MID_FRAME_BUDGET_MS)) < 0 && st3 != SN_CLIENT_ESTABLISHED)
                        alive3 = 0;
                }
                CHECK(alive3 && st3 == SN_CLIENT_IDLE &&
                      sn_client_get_end_reason(&p3) == SN_CLIENT_END_DESYNC,
                      "stall trickle: IDLE with DESYNC at the budget from the first octet");
                sn_client_free(&p3);
            }

            /* The stall and the dead-session limits expire on one tick. Both
             * clocks start on the same accepted envelope; the session is
             * dead, which is what sn_client_session_dead reports. */
            {
                fresh_device();
                sn_client p4; make_client(&p4);
                bind_app(&p4);
                t += 1000;
                CHECK(establish_app_quiet(&p4, &t), "both-timers setup: ESTABLISHED with an empty carry");
                t += 20;   /* past both KCPs' flush interval */
                static const uint8_t body4[4] = {1, 2, 3, 4};
                int sent4 = sn_client_send_app(&p4, 0x42, body4, 4, t);
                g_dev_in_n = 0;   /* the device never sees it, so it is never acknowledged */
                sn_primary_send(&dev, part, sizeof part, t); sn_primary_update(&dev, t);
                client_pump(&p4, t);
                CHECK(sent4 == SN_CS_OK && p4.carry_len == 70 && p4.outstanding &&
                      p4.outstanding_since_ms == p4.partial_since_ms,
                      "transport 10.3: both timers start on one envelope");
                uint32_t T4 = t;
                while (sn_client_get_state(&p4) != SN_CLIENT_IDLE &&
                       (int32_t)(t - (T4 + SN_SESSION_DEAD_MS + 40)) < 0) {
                    t += 20; g_dev_in_n = 0; g_cli_in_n = 0;
                    sn_client_tick(&p4, t);
                }
                CHECK(sn_client_get_state(&p4) == SN_CLIENT_IDLE &&
                      sn_client_get_end_reason(&p4) == SN_CLIENT_END_DEAD &&
                      sn_client_session_dead(&p4) == 1,
                      "transport 10.3: stall and dead session together end DEAD");
                sn_client_free(&p4);
            }

            /* The same partial frame, completed at about T + 5000: delivered,
             * and the timer is cleared. */
            fresh_device();
            sn_client p2; make_client(&p2);
            bind_app(&p2);
            t = 450000;
            CHECK(establish_app_quiet(&p2, &t), "completed: ESTABLISHED with an empty carry");
            uint8_t sbuf[256], body[84], frame[20 + 100];
            memset(body, 0x33, sizeof body);
            sn_app_tx stx;
            sn_app_tx_init(&stx, dev.primary.k_s2c, sbuf, sizeof sbuf);
            stx.next_msgnum = dev.primary.app_s2c_next;
            uint32_t ty = 0, orig = 0; uint64_t num = 0; size_t ct = 0;
            CHECK(sn_app_seal(&stx, 0x42, body, sizeof body, &ty, &num, &orig, &ct) == 0 && ct == 100,
                  "completed: a 100-octet ciphertext sealed under k_s2c");
            protocol_marshal_aad((uint32_t)ct, orig, ty, num, frame);
            memcpy(frame + 20, sbuf, ct);
            int apps = g_app_count;
            sn_primary_send(&dev, frame, 70, t);
            T = 0; held = 0;
            for (int i = 0; i < 100 && !held; i++) {
                step(&p2, &t);
                if (p2.carry_len > 0) { held = 1; T = t; }
            }
            CHECK(held, "completed: the client holds the first 70 octets");
            while ((int32_t)(t - (T + 5000)) < 0) step(&p2, &t);
            sn_primary_send(&dev, frame + 70, sizeof frame - 70, t);
            st = sn_client_get_state(&p2);
            while ((int32_t)(t - (T + 12000)) < 0) st = step(&p2, &t);
            CHECK(g_app_count == apps + 1 && g_app_kind == 0x42, "completed: on_app received it");
            CHECK(st == SN_CLIENT_ESTABLISHED && p2.carry_len == 0,
                  "completed: still ESTABLISHED past the budget");
            sn_client_free(&p2);
        }

        /* _USER: sn_client_close. */
        fresh_device();
        sn_client e4; make_client(&e4);
        t = 330000;
        establish(&e4, &t);
        sn_client_close(&e4);
        CHECK(sn_client_get_end_reason(&e4) == SN_CLIENT_END_USER, "end_reason: close gives USER");
        /* ...and the next take-control clears it. */
        g_dev_in_n = 0; g_cli_in_n = 0;
        sn_client_take_control(&e4, (const uint8_t *)"hi", 2, t);
        CHECK(sn_client_get_end_reason(&e4) == SN_CLIENT_END_NONE,
              "end_reason: cleared by the next take-control");
        sn_client_free(&e4);

        /* _ATTEMPT_FAILED: a wrong PSK is never answered. */
        fresh_device();
        {
            sn_client_config cfg; memset(&cfg, 0, sizeof cfg);
            memset(cfg.psk, 0x99, 32);
            memcpy(cfg.device_id, DEVICE_ID, 8);
            sn_canonical_source(src, PORT, cfg.own_source);
            cfg.rand_fill = cli_rand;
            sn_client e6;
            CHECK(sn_client_init(&e6, &cfg) == SN_CLIENT_OK, "wrong-PSK client init");
            sn_client_set_send(&e6, to_device, NULL);
            t = 340000;
            g_dev_in_n = 0; g_cli_in_n = 0;
            sn_client_take_control(&e6, (const uint8_t *)"hi", 2, t);
            int rc2 = SN_CLIENT_IN_PROGRESS;
            for (int i = 0; i < 400 && rc2 == SN_CLIENT_IN_PROGRESS; i++) {
                t += 20;
                device_pump(t); client_pump(&e6, t);
                rc2 = sn_client_tick(&e6, t);
            }
            CHECK(rc2 == SN_CLIENT_FAILED &&
                  sn_client_get_end_reason(&e6) == SN_CLIENT_END_ATTEMPT_FAILED,
                  "end_reason: a wrong-PSK attempt gives ATTEMPT_FAILED");
            sn_client_free(&e6);
        }
    }

    /* ── transport 12.2: the first message is a sealed message ── */
    {
        sn_client z; make_client(&z);
        uint32_t tz = 400000;
        CHECK(sn_client_take_control(&z, NULL, 0, tz) == SN_CLIENT_ERR &&
              sn_client_take_control(&z, (const uint8_t *)"x", 0, tz) == SN_CLIENT_ERR &&
              sn_client_get_state(&z) == SN_CLIENT_IDLE,
              "transport 12.2: raw take-control with length 0 is refused");
        bind_app(&z);
        CHECK(sn_client_take_control_app(&z, 0x07, NULL, 0, tz) == SN_CLIENT_IN_PROGRESS,
              "transport 12.2: app take-control with an empty body is accepted");
        sn_client_free(&z);
    }

    sn_device_release_primary(&dev);

    sn_device_locks_free(&dev);
    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("all §7 client state machine cases pass\n");
    return 0;
}
