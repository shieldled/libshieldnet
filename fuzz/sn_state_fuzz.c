/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * sn_state_fuzz — sequence fuzzing for the admission and promotion state
 * machine.
 *
 * Single-datagram fuzzing cannot reach this. Both of the worst defects found on
 * hardware were sequence bugs: a retiring session consuming the incoming
 * session's stream (fixed by binding reads to a generation), and a promotion
 * over a live primary leaving a freed kcp pointer behind. Neither is expressible
 * as one malformed packet — they need admit, promote, re-admit, drain, expire in
 * a particular order.
 *
 * Random bytes will not produce a valid FINISH: it carries a cookie the device
 * only issues in a RETRY, and a MAC keyed by the PSK. A fuzzer that cannot get
 * past admission never reaches promotion, which is where the state lives. So the
 * input is read as a small program over protocol *operations*, and the harness
 * builds the cryptographically valid steps itself. The fuzzer chooses the
 * order, the sources, the timing and the payloads.
 *
 *   step := [u8 op][u8 arg]
 *
 * Invariants are checked after every step, so a violation is attributed to the
 * operation that caused it rather than to the end of the run.
 */
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_wire.h"
#include "shieldnet/sn_kdf.h"

#include "client_helper.h"
#include "ikcp.h"

#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1, 2, 3, 4, 5, 6, 7, 8};

static void v4(uint8_t a[16], uint8_t last) {
    memset(a, 0, 16);
    a[10] = 0xff; a[11] = 0xff;
    a[12] = 192; a[13] = 168; a[14] = 4; a[15] = last;
}

/* Deterministic "randomness": the device draws its ephemeral key and cookie
 * secret through this, so a failing sequence replays identically. */
static uint8_t g_fill = 0x42;
static void fixed_rand(void *ctx, uint8_t *buf, size_t n) {
    (void)ctx; memset(buf, g_fill, n);
}

/* Allocation-failure injection. The §8.5 branch that retires a live primary and
 * then fails to build its replacement is only reachable when ikcp_create returns
 * NULL, so without this the fuzzer cannot reach it at all -- verified by
 * reintroducing the dangling-kcp bug, which a run without injection did not
 * catch and a run with it does. */
static int g_fail_next_alloc;
/* Armed by op 7 and consumed immediately before the device's promoting
 * ikcp_create. Arming the raw allocator instead is wrong: do_admit builds the
 * *client's* kcp first, so the failure lands there, admission simply does not
 * happen, and §8.5's retire-then-fail branch is never entered. */
static int g_fail_promote;
static void *maybe_fail_malloc(size_t n) {
    if (g_fail_next_alloc) { g_fail_next_alloc = 0; return NULL; }
    return malloc(n);
}

static uint8_t g_sent[4096];
static size_t  g_sent_len;
static void capture_send(void *ctx, const uint8_t *b, size_t n) {
    (void)ctx;
    g_sent_len = n > sizeof(g_sent) ? sizeof(g_sent) : n;
    memcpy(g_sent, b, g_sent_len);
}

/* A client that can complete admission and drive a real ikcp stream. */
typedef struct {
    uint8_t  k_kcp_c2s[32], k_kcp_s2c[32];
    sn_sender c2s_seq;
    ikcpcb   *kcp;
    int       admitted;
} client_t;

static client_t *g_active;
static uint8_t g_c2s[4096];
static size_t  g_c2s_len;

static int client_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    (void)kcp; (void)user;
    if (!g_active) return 0;
    uint64_t seq;
    if (!sn_sender_alloc(&g_active->c2s_seq, &seq)) return 0;
    size_t out_len = 0;
    if (sn_seal(g_active->k_kcp_c2s, 1, seq, (const uint8_t *)buf, (size_t)len,
                g_c2s, &out_len) != 0) return 0;
    g_c2s_len = out_len;
    return 0;
}

/* Run a full, valid admission from `src_last` and promote. Returns 1 on
 * promotion. Everything here is real crypto -- the fuzzer cannot synthesise it,
 * so the harness must. */
static int do_admit(sn_device *d, client_t *cl, uint8_t src_last, uint16_t port,
                    uint64_t now, uint32_t conv) {
    uint8_t src[16]; v4(src, src_last);
    uint8_t nonce[24]; memset(nonce, 0xAB, 24);

    uint8_t init[SN_INIT_LEN];
    ch_init(PSK, DEVICE_ID, nonce, init);
    uint8_t retry[SN_RETRY_LEN];
    if (sn_handle_init(d, init, SN_INIT_LEN, src, port, now, retry) != SN_RETRY_LEN) return 0;

    uint8_t ec_priv[32]; memset(ec_priv, 0x07, 32);
    uint8_t fin[SN_FINISH_LEN];
    ch_finish(PSK, DEVICE_ID, nonce, retry, ec_priv, fin, NULL);
    uint8_t admit[SN_ADMIT_LEN];
    if (sn_handle_finish(d, fin, SN_FINISH_LEN, src, port, now, admit) != SN_ADMIT_LEN) return 0;

    uint8_t a[32], b[32];
    memset(cl, 0, sizeof(*cl));
    ch_session_from(PSK, DEVICE_ID, nonce, retry, ec_priv, admit,
                    a, b, cl->k_kcp_c2s, cl->k_kcp_s2c);
    sn_sender_init(&cl->c2s_seq);
    cl->kcp = ikcp_create(conv, NULL);
    if (!cl->kcp) return 0;
    ikcp_setoutput(cl->kcp, client_output);
    ikcp_setmtu(cl->kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    ikcp_nodelay(cl->kcp, 1, 20, 2, 1);
    cl->kcp->stream = 1;

    g_active = cl;
    g_c2s_len = 0;
    ikcp_send(cl->kcp, "p", 1);
    ikcp_update(cl->kcp, (IUINT32)now);
    if (g_c2s_len == 0) return 0;
    if (g_fail_promote) { g_fail_promote = 0; g_fail_next_alloc = 1; }
    int promoted = sn_handle_envelope(d, g_c2s, g_c2s_len, src, port, now) == SN_ENV_PROMOTED;
    cl->admitted = promoted;
    return promoted;
}

/* Invariants that must hold after every operation. */
static const char *check(sn_device *d) {
    if (d->primary.active && d->primary.kcp == NULL)
        return "primary active with a NULL kcp";
    if (!d->primary.active && d->primary.kcp != NULL)
        return "inactive primary still holds a kcp pointer";
    size_t used = 0;
    for (size_t i = 0; i < SN_PENDING_SLOTS; i++) if (d->pending[i].used) used++;
    if (used > SN_PENDING_SLOTS) return "pending table over capacity";
    if (d->primary.active && d->primary.kcp->rcv_wnd == 0)
        return "primary kcp has a zero receive window";
    return NULL;
}

/* One program against one freshly constructed device. Split out of main so
 * libFuzzer can call it in-process: every run must start from a clean device,
 * because state carried between programs both hides real faults and invents
 * ones that do not exist outside the harness. */
int sn_state_run_program(const uint8_t *prog, size_t n) {
    if (sodium_init() < 0) return 1;
    memset(PSK, 0x11, 32);
    g_fail_next_alloc = 0;
    g_fail_promote = 0;
    g_active = NULL;
    g_c2s_len = 0;
    g_sent_len = 0;

    sn_device d;
    sn_prefix local; memset(&local, 0, sizeof(local));
    v4(local.a16, 1); local.is_v4 = 1; local.bits = 24;
    uint8_t cookie[32]; memset(cookie, 0x22, 32);
    uint8_t ae[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&d, kd, DEVICE_ID, cookie, ae, &local, 1, 8000);
    d.rand_fill = fixed_rand;
    sn_device_locks_init(&d);
    sn_device_set_send(&d, capture_send, NULL);
    { extern void ikcp_allocator(void *(*)(size_t), void (*)(void *));
      ikcp_allocator(maybe_fail_malloc, free); }

    unsigned n_promote = 0, n_env = 0, n_junk = 0, n_drain = 0, n_release = 0, n_oom = 0;
    client_t clients[4];
    memset(clients, 0, sizeof(clients));
    uint64_t now = 10000;
    uint8_t scratch[2048];

    for (size_t i = 0; i + 1 < n; i += 2) {
        uint8_t op = prog[i], arg = prog[i + 1];
        int ci = arg & 3;
        switch (op % 8) {
        case 0: /* valid admission + promotion from one of four sources */
            if (clients[ci].kcp) { ikcp_release(clients[ci].kcp); clients[ci].kcp = NULL; }
            if (do_admit(&d, &clients[ci], (uint8_t)(2 + ci), (uint16_t)(5000 + ci),
                         now, 0x1000u + ci)) n_promote++;
            break;
        case 1: { /* app data on an admitted session */
            client_t *cl = &clients[ci];
            if (!cl->kcp) break;
            g_active = cl; g_c2s_len = 0;
            char msg[64]; memset(msg, (int)arg, sizeof(msg));
            ikcp_send(cl->kcp, msg, (int)(1 + (arg % 63)));
            ikcp_update(cl->kcp, (IUINT32)now);
            if (g_c2s_len) {
                uint8_t src[16]; v4(src, (uint8_t)(2 + ci));
                sn_handle_envelope(&d, g_c2s, g_c2s_len, src, (uint16_t)(5000 + ci), now);
                n_env++;
            }
            break;
        }
        case 2: { /* arbitrary bytes at the envelope path */
            uint8_t src[16]; v4(src, (uint8_t)(2 + ci));
            size_t l = 20u + (arg % 200u);
            uint8_t junk[224];
            memset(junk, arg, l);
            sn_handle_envelope(&d, junk, l, src, (uint16_t)(5000 + ci), now);
            n_junk++;
            break;
        }
        case 3: /* drain */
            sn_primary_recv(&d, scratch, (int)sizeof(scratch));
            n_drain++;
            break;
        case 4: /* time advances, driving §6.3 expiry and retransmits */
            now += 1u + (uint64_t)arg * 137u;
            sn_device_tick(&d, (uint32_t)now, now);
            break;
        case 5: /* the epoch rolls under an active session */
            sn_device_roll_epoch(&d, now);
            break;
        case 6: /* the application drops the session */
            sn_device_release_primary(&d);
            n_release++;
            break;
        case 7: /* the next promotion fails to allocate: §8.5's failure branch */
            g_fail_promote = 1;
            n_oom++;
            break;
        }
        const char *bad = check(&d);
        if (bad) {
            fprintf(stderr, "INVARIANT VIOLATED after op=%u arg=%u (step %zu): %s\n",
                    op % 7, arg, i / 2, bad);
            abort();
        }
    }

    /* A run that never promotes exercises none of the state this exists to test.
     * SHIELDNET_FUZZ_STATS=1 prints what a program actually reached. */
    if (getenv("SHIELDNET_FUZZ_STATS")) {
        fprintf(stderr, "promote=%u env=%u junk=%u drain=%u release=%u oom=%u steps=%zu\n",
                n_promote, n_env, n_junk, n_drain, n_release, n_oom, n / 2);
    }
    for (int i = 0; i < 4; i++) if (clients[i].kcp) ikcp_release(clients[i].kcp);
    g_active = NULL;
    sn_device_release_primary(&d);
    sn_device_locks_free(&d);
    return 0;
}

#ifndef SN_STATE_LIBFUZZER
int main(void) {
    uint8_t prog[4096];
    size_t n = fread(prog, 1, sizeof(prog), stdin);
    return sn_state_run_program(prog, n);
}
#else
/* Coverage-guided entry point. The Go driver forks a process per program and
 * gets no signal from this code; libFuzzer instruments it directly, so mutation
 * is actually steered by which protocol orderings reach new branches. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 256) size = 256; /* programs are steps; long ones only cost time */
    sn_state_run_program(data, size);
    return 0;
}
#endif
