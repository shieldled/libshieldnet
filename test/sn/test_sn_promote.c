/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * §8.5 promotion + §8.6 established, C device over raw ikcp.
 * Drives a full admission, builds a real promoting KCP PUSH sn=0 via a client-side
 * ikcp, promotes, exchanges app data over the established session, checks the
 * duplicate promoting datagram is a replay-drop, and forces the allocation-failure
 * branch via the ikcp allocator hook.
 *
 * The concurrent double-promotion race is a threaded/TSan concern (§10) and is not
 * exercised here; this is the single-threaded logic + the sequential duplicate.
 */
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_wire.h"

#include "client_helper.h"
#include "ikcp.h"
#include "sn_vectors.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static void *fail_malloc(size_t n){ (void)n; return NULL; }

/* Allocation accounting for the session-churn leak check below. Installed only
 * around that loop, and every ikcp object created under it is released under it. */
static size_t churn_live = 0;
static void *churn_malloc(size_t n) {
    void *p = malloc(n + sizeof(size_t));
    if (!p) return NULL;
    *(size_t *)p = n; churn_live += n;
    return (char *)p + sizeof(size_t);
}
static void churn_free(void *p) {
    if (!p) return;
    char *b = (char *)p - sizeof(size_t);
    churn_live -= *(size_t *)b;
    free(b);
}
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};

static void v4mapped(uint8_t a[16], uint8_t b, uint8_t c, uint8_t dd, uint8_t e) {
    memset(a, 0, 16); a[10]=0xff; a[11]=0xff; a[12]=b; a[13]=c; a[14]=dd; a[15]=e;
}

static uint8_t g_fill = 0x42;
static void fixed_rand(void *ctx, uint8_t *buf, size_t n) { (void)ctx; memset(buf, g_fill, n); }

/* device send sink: capture the last sealed datagram */
static uint8_t g_sent[2048];
static size_t g_sent_len = 0;
static int g_sent_count = 0;
static void capture_send(void *ctx, const uint8_t *buf, size_t len) {
    (void)ctx;
    memcpy(g_sent, buf, len); g_sent_len = len; g_sent_count++;
}

/* ── a minimal client: static session keys + its own ikcp for the c2s stream ── */
typedef struct {
    uint8_t k_kcp_c2s[32], k_kcp_s2c[32];
    sn_sender c2s_seq;
    sn_replay_window s2c_window;
    ikcpcb *kcp;
} client_t;

/* client's ikcp output → seal under k_kcp_c2s with a fresh c2s seq → deliver to
 * the device. We capture into a buffer the test then feeds to sn_handle_envelope. */
static client_t *g_active_client = NULL;
static uint8_t g_c2s[2048]; static size_t g_c2s_len = 0; static int g_c2s_count = 0;
static int client_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    (void)kcp; (void)user;
    client_t *c = g_active_client;
    uint64_t seq; sn_sender_alloc(&c->c2s_seq, &seq);
    size_t out_len;
    sn_seal(c->k_kcp_c2s, 1, seq, (const uint8_t*)buf, (size_t)len, g_c2s, &out_len);
    g_c2s_len = out_len; g_c2s_count++;
    return 0;
}

static int null_output(const char *b, int l, ikcpcb *k, void *u) {
    (void)b; (void)l; (void)k; (void)u; return 0;
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium_init failed\n"); return 1; }
    memset(PSK, 0x11, 32);

    sn_device dev; sn_prefix local[1];
    v4mapped(local[0].a16, 192,168,4,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t cookie_secret[32]; memset(cookie_secret, 0x22, 32);
    uint8_t ae[8] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&dev, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
    dev.rand_fill = fixed_rand;
    sn_device_locks_init(&dev);
    sn_device_set_send(&dev, capture_send, NULL);

    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16]; v4mapped(src, 192,168,4,2);
    uint16_t port = 5000;

    /* ── admission: INIT → RETRY → FINISH → ADMIT ── */
    uint8_t init[SN_INIT_LEN], mac[16];
    sn_init_mac(dev.k_req, nonce, DEVICE_ID, mac);
    sn_encode_init(nonce, DEVICE_ID, mac, init);
    uint8_t retry[SN_RETRY_LEN];
    sn_handle_init(&dev, init, SN_INIT_LEN, src, port, 8000, retry);

    uint8_t ec_priv[32]; memset(ec_priv, 0x07, 32);
    uint8_t ec_pub[32];
    uint8_t fin[SN_FINISH_LEN];
    ch_finish(PSK, DEVICE_ID, nonce, retry, ec_priv, fin, ec_pub);
    uint8_t admit[SN_ADMIT_LEN];
    size_t an = sn_handle_finish(&dev, fin, SN_FINISH_LEN, src, port, 8000, admit);
    CHECK(an == SN_ADMIT_LEN, "admission produced ADMIT");

    /* client derives the same session keys from ADMIT */
    client_t cli; memset(&cli, 0, sizeof(cli));
    uint8_t kc2s[32], ks2c[32];
    ch_session_from(PSK, DEVICE_ID, nonce, retry, ec_priv, admit,
                    kc2s, ks2c, cli.k_kcp_c2s, cli.k_kcp_s2c);
    sn_sender_init(&cli.c2s_seq);

    /* ── build the promoting PUSH sn=0 via a client ikcp ── */
    cli.kcp = ikcp_create(0x11223344u, NULL); /* client chooses conv */
    ikcp_setoutput(cli.kcp, client_output);
    ikcp_setmtu(cli.kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    ikcp_nodelay(cli.kcp, 1, 20, 2, 1);
    g_active_client = &cli;
    const char *first = "hello-device";
    ikcp_send(cli.kcp, first, (int)strlen(first));
    g_c2s_count = 0;
    ikcp_update(cli.kcp, 1000); /* flushes → client_output seals the PUSH into g_c2s */
    CHECK(g_c2s_count >= 1, "client emitted a promoting PUSH");

    /* ── promote ── */
    sn_env_result r = sn_handle_envelope(&dev, g_c2s, g_c2s_len, src, port, 8100);
    CHECK(r == SN_ENV_PROMOTED, "promoting datagram promotes");
    CHECK(dev.primary.active, "primary is active");
    CHECK(dev.primary.conv == 0x11223344u, "conv bound from the first PUSH");
    CHECK(sn_find_pending_index(&dev, dev.primary.tuple) < 0, "pending record cleared");

    /* device receives the app bytes over the established stream */
    uint8_t app[128];
    int got = sn_primary_recv(&dev, app, sizeof(app));
    CHECK(got == (int)strlen(first) && memcmp(app, first, got) == 0, "device recv'd first message");

    /* ── duplicate promoting datagram → replay-drop at the primary, no 2nd session ── */
    uint32_t gen_before = dev.primary.generation;
    ikcpcb *kcp_before = dev.primary.kcp;
    sn_env_result rd = sn_handle_envelope(&dev, g_c2s, g_c2s_len, src, port, 8150);
    CHECK(rd == SN_ENV_DROP, "duplicate promoting datagram dropped");
    CHECK(dev.primary.generation == gen_before && dev.primary.kcp == kcp_before,
          "no second session created by the duplicate");

    /* ── device → client app data over the established session ── */
    g_sent_count = 0;
    const char *reply = "ack-from-device";
    sn_primary_send(&dev, (const uint8_t*)reply, (int)strlen(reply), 8200);
    CHECK(g_sent_count >= 1, "device emitted a sealed s2c datagram");
    /* client opens it under k_kcp_s2c and feeds its ikcp */
    uint8_t cpt[2048]; size_t cpt_len;
    uint64_t cand_seq = (uint64_t)sn_reconstruct(
        ((uint32_t)g_sent[g_sent_len-20]<<24)|((uint32_t)g_sent[g_sent_len-19]<<16)|
        ((uint32_t)g_sent[g_sent_len-18]<<8)|(uint32_t)g_sent[g_sent_len-17], cli.s2c_window.hwm);
    int oo = sn_open(cli.k_kcp_s2c, 0, cand_seq, g_sent, g_sent_len, cpt, &cpt_len);
    CHECK(oo == 0, "client opens the s2c datagram");
    ikcp_input(cli.kcp, (const char*)cpt, (long)cpt_len);
    uint8_t cbuf[128];
    int cgot = ikcp_recv(cli.kcp, (char*)cbuf, sizeof(cbuf));
    CHECK(cgot == (int)strlen(reply) && memcmp(cbuf, reply, cgot) == 0, "client recv'd the reply");

    /* ── an out-of-memory send must report, not abort the device ─────────────
     * Upstream ikcp asserts on segment allocation failure in ikcp_send. On a
     * device that is remotely reachable, a peer streaming faster than the
     * application drains exhausts the heap and the assert turns that into a
     * panic and reboot -- observed on the ESP32 as
     * "assert failed: ikcp_send ikcp.c:493 (seg)" followed by SW_CPU_RESET.
     * The -2 return path already existed underneath the assert; every ShieldNet
     * caller propagates it (sn_primary_send -> io_write). */
    {
        extern void ikcp_allocator(void* (*)(size_t), void (*)(void*));
        CHECK(dev.primary.active, "oom-send: a primary is live to send on");
        ikcp_allocator(fail_malloc, free);   /* every segment allocation fails */
        int rc = sn_primary_send(&dev, (const uint8_t *)"payload", 7, 9000);
        ikcp_allocator(malloc, free);
        /* Reaching this line at all is the point: with the upstream assert the
         * process aborts inside the call above and the test never returns. */
        CHECK(rc < 0, "oom-send: allocation failure reported as an error");
        /* ...and as a fatal one. ikcp_send's OOM return is -2, which is also
         * SN_SEND_QUEUE_FULL, the one code io_write retries -- after the failed
         * send may already have queued part of the message, so a retry put
         * those bytes in the stream twice. */
        CHECK(rc == -1, "oom-send: reported as fatal (-1), not as a retryable queue-full");
    }

    /* ── stream mode ignores the peer's fragment count ─────────────────────
     * The fork lowers rcv_wnd below 128 on the premise that frg is always 0 in
     * stream mode. That held for what this side sends, but ikcp_input stored
     * the peer's frg as received: a PUSH with frg >= rcv_wnd made ikcp_peeksize
     * wait for more segments than the window can hold, and the stream wedged
     * with ikcp_recv returning -1 forever. */
    {
        ikcpcb *rx = ikcp_create(0x0F0F0F0Fu, NULL);
        rx->stream = 1;
        ikcp_wndsize(rx, 32, 8);
        uint8_t seg[24 + 5];
        memset(seg, 0, sizeof seg);
        seg[0] = 0x0F; seg[1] = 0x0F; seg[2] = 0x0F; seg[3] = 0x0F; /* conv, LE */
        seg[4] = 81;                    /* IKCP_CMD_PUSH */
        seg[5] = 9;                     /* frg: more than rcv_wnd can ever hold */
        seg[6] = 8;                     /* wnd */
        /* ts, sn = 0, una = 0 */
        seg[20] = 5;                    /* len, LE */
        memcpy(&seg[24], "hello", 5);
        CHECK(ikcp_input(rx, (const char *)seg, (long)sizeof seg) == 0,
              "frg: a PUSH with frg 9 is accepted");
        char out[64];
        int n = ikcp_recv(rx, out, sizeof out);
        CHECK(n == 5 && memcmp(out, "hello", 5) == 0,
              "frg: stream mode delivers it rather than waiting for 9 more fragments");
        ikcp_release(rx);
    }

    /* ── a peer-chosen ACK timestamp cannot overflow the RTT estimator ───────
     * rtt is current - ts with ts taken from the peer's ACK. Upstream fed a
     * near-2^31 sample straight into 4 * rx_rttval, an int overflow (undefined
     * behaviour; the sanitizer build aborts on it). Found by fuzz/sn_app_fuzz.c. */
    {
        ikcpcb *k = ikcp_create(0x0E0E0E0Eu, NULL);
        ikcp_setoutput(k, null_output);
        k->stream = 1;
        ikcp_send(k, "x", 1);
        ikcp_update(k, 0x70000000u);   /* sn 0 into snd_buf; current = 0x70000000 */
        uint8_t ack[24];
        memset(ack, 0, sizeof ack);
        ack[0] = 0x0E; ack[1] = 0x0E; ack[2] = 0x0E; ack[3] = 0x0E; /* conv, LE */
        ack[4] = 82;                   /* IKCP_CMD_ACK */
        ack[6] = 32;                   /* wnd */
        /* ts = 0, sn = 0, una = 0, len = 0: an rtt sample of 0x70000000 */
        CHECK(ikcp_input(k, (const char *)ack, (long)sizeof ack) == 0,
              "rtt: an ACK with a far-past ts is processed");
        CHECK(k->rx_rto > 0 && k->rx_rto <= 60000,
              "rtt: the RTO stays inside [minrto, IKCP_RTO_MAX]");
        ikcp_release(k);
    }




    /* ── session-lifecycle churn: leak and exhaustion check ──────────────────
     * The suite's other cases each build one session and exit, so LeakSanitizer
     * only ever sees a single lifecycle. Devices in the field admit, promote and
     * lose sessions continuously; anything retained per cycle accumulates until
     * the heap is gone. Run many full cycles and require the allocator to return
     * to its starting point. */
    {
        extern void ikcp_allocator(void* (*)(size_t), void (*)(void*));
        const int CYCLES = 200;
        size_t live_after_first = 0;
        int ok_cycles = 0;

        churn_live = 0;
        ikcp_allocator(churn_malloc, churn_free);

        for (int c = 0; c < CYCLES; c++) {
            sn_device d; 
            uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
            sn_device_init_kdev(&d, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
            d.rand_fill = fixed_rand;
            sn_device_locks_init(&d);
            sn_device_set_send(&d, capture_send, NULL);

            uint8_t i3[SN_INIT_LEN], m3[16];
            sn_init_mac(d.k_req, nonce, DEVICE_ID, m3);
            sn_encode_init(nonce, DEVICE_ID, m3, i3);
            uint8_t r3[SN_RETRY_LEN];
            sn_handle_init(&d, i3, SN_INIT_LEN, src, port, 8000, r3);

            uint8_t f3[SN_FINISH_LEN];
            ch_finish(PSK, DEVICE_ID, nonce, r3, ec_priv, f3, NULL);
            uint8_t a3[SN_ADMIT_LEN];
            size_t an3 = sn_handle_finish(&d, f3, SN_FINISH_LEN, src, port, 8000, a3);
            if (an3 != SN_ADMIT_LEN) {
                sn_device_locks_free(&d);
                continue;
            }

            /* promote with a fresh client ikcp, then drop the session */
            client_t cl; memset(&cl, 0, sizeof(cl));
            uint8_t a_k[32], b_k[32];
            ch_session_from(PSK, DEVICE_ID, nonce, r3, ec_priv, a3,
                            a_k, b_k, cl.k_kcp_c2s, cl.k_kcp_s2c);
            sn_sender_init(&cl.c2s_seq);
            cl.kcp = ikcp_create(0x51EED000u + (IUINT32)c, NULL);
            ikcp_setoutput(cl.kcp, client_output);
            ikcp_setmtu(cl.kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN);
            ikcp_nodelay(cl.kcp, 1, 20, 2, 1); /* nc=1: first flush may emit */
            g_active_client = &cl;
            g_c2s_count = 0; g_c2s_len = 0;
            ikcp_send(cl.kcp, "churn", 5);
            ikcp_update(cl.kcp, 1000);
            sn_env_result er3 = (g_c2s_len > 0)
                ? sn_handle_envelope(&d, g_c2s, g_c2s_len, src, port, 1100)
                : (sn_env_result)(-1);
            if (er3 == SN_ENV_PROMOTED) {
                ok_cycles++;
                if (c == 0) live_after_first = churn_live; /* while the session is up */
            }

            sn_device_release_primary(&d);
            ikcp_release(cl.kcp);
            g_active_client = NULL;
            sn_device_locks_free(&d);


        }
        ikcp_allocator(malloc, free);
        g_active_client = &cli; /* restore: later blocks seal through this client */

        printf("     [churn] cycles=%d promoted=%d ikcp_live_after_first=%zu ikcp_live_end=%zu\n",
               CYCLES, ok_cycles, live_after_first, churn_live);
        CHECK(ok_cycles > CYCLES / 2, "most churn cycles actually promoted");
        CHECK(live_after_first > 0, "a session actually allocated (else zero-at-end is vacuous)");
        CHECK(churn_live == 0, "no ikcp memory retained after releasing every session");
    }

    /* ── §11: the configured rcv_wnd must actually reach the session ─────────
     * ikcp_wndsize only honours an rcv_wnd below IKCP_WND_RCV (128) when
     * kcp->stream is already set, and clamps upward otherwise. Setting stream
     * after the window setter left every session committed to 128 segments
     * (~179 KB at MTU) regardless of configuration -- invisible except by
     * reading the window back off a live session. */
    {
        CHECK(dev.primary.kcp != NULL, "primary session exists to inspect");
        if (dev.primary.kcp) {
            printf("     [wndsize] stream=%d rcv_wnd=%u (configured %d) snd_wnd=%u\n",
                   (int)dev.primary.kcp->stream, dev.primary.kcp->rcv_wnd,
                   dev.tuning.rcv_wnd, dev.primary.kcp->snd_wnd);
            CHECK(dev.primary.kcp->stream != 0, "session is in stream mode");
            CHECK(dev.primary.kcp->rcv_wnd == (IUINT32)dev.tuning.rcv_wnd,
                  "configured rcv_wnd reached the session (not clamped to 128)");
        }
    }

    /* ── §8.6: the device's receive queue stays bounded when the app stalls ──
     * A peer may stream faster than the application drains. What the *device*
     * retains must then be capped by rcv_wnd, so a slow app cannot be turned
     * into heap exhaustion by a fast sender. The sender's own snd_que is a
     * separate matter and legitimately grows while nothing ACKs -- measuring
     * total allocation conflates the two and says nothing about the device. */
    {
        const int N = 400;                    /* >> rcv_wnd */
        int delivered = 0;
        for (int i = 0; i < N; i++) {
            char msg[64];
            snprintf(msg, sizeof(msg), "undrained-%d", i);
            g_c2s_count = 0; g_c2s_len = 0;
            ikcp_send(cli.kcp, msg, (int)strlen(msg));
            ikcp_update(cli.kcp, (IUINT32)(2000 + i * 20));
            if (g_c2s_len == 0) continue;
            /* deliberately never call sn_primary_recv: the app is not draining */
            sn_handle_envelope(&dev, g_c2s, g_c2s_len, src, port, 8200 + i * 20);
            delivered++;
        }

        IUINT32 rq  = dev.primary.kcp ? dev.primary.kcp->nrcv_que : 0;
        IUINT32 rb  = dev.primary.kcp ? dev.primary.kcp->nrcv_buf : 0;
        IUINT32 wnd = dev.primary.kcp ? dev.primary.kcp->rcv_wnd  : 0;
        printf("     [undrained] delivered=%d dev nrcv_que=%u nrcv_buf=%u rcv_wnd=%u\n",
               delivered, rq, rb, wnd);

        CHECK(delivered > 32, "enough undrained messages delivered to be meaningful");
        CHECK(rq <= wnd, "device receive queue capped at rcv_wnd");
        CHECK(rb <= wnd, "device out-of-order buffer capped at rcv_wnd");
        CHECK(rq + rb < (IUINT32)delivered,
              "device retention does not scale with messages sent");
    }

    /* ── §3.6 envelope size bounds, from the vector file ──────────────────────
     * Each length is a validly sealed datagram for this primary, carrying a KCP
     * datagram on its conv that ikcp_input accepts: a data-less WASK for 44, one
     * PUSH at the client's next sn filling the rest for the longer ones. Only
     * the size bound can then tell accepted from dropped (an AEAD failure would
     * drop too, so drops alone would prove nothing). 43 is 23 octets of KCP,
     * shorter than a KCP header, so it would be refused regardless. */
    {
        /* The 1400 and 1401 vectors are the bounds of WIRE_MTU 1400 and do not
         * apply to another SN_WIRE_MTU (the constants CI leg); 43 and 44 do. */
        int vectors_fit = sn_envelope_size_wire_mtu == SN_WIRE_MTU;
        if (vectors_fit) CHECK(sn_envelope_size_wire_mtu == SN_WIRE_MTU, "envelope_size: the vectors' WIRE_MTU is ours");
        else printf("ok   envelope_size: the vectors' WIRE_MTU is ours (skipped: needs SN_WIRE_MTU %u)\n",
                    (unsigned)sn_envelope_size_wire_mtu);
        IUINT32 next_sn = cli.kcp->snd_nxt;
        for (size_t i = 0; i < SN_ENVELOPE_SIZE_N; i++) {
            size_t L = sn_envelope_size_len[i], plen = L - SN_ENVELOPE_LEN;
            if (!vectors_fit && L > 44) {
                printf("ok   envelope_size: a sealed %zu-octet datagram (skipped: needs SN_WIRE_MTU %u)\n",
                       L, (unsigned)sn_envelope_size_wire_mtu);
                continue;
            }
            uint8_t seg[SN_WIRE_MTU + 8];
            memset(seg, 0x65, sizeof seg);
            uint32_t conv = dev.primary.conv;
            for (int b = 0; b < 4; b++) seg[b] = (uint8_t)(conv >> (8 * b));
            if (plen >= 24) {
                uint32_t data = (uint32_t)(plen - 24);
                uint32_t f[4] = { 20000u, next_sn, cli.kcp->rcv_nxt, data }; /* ts sn una len */
                seg[4] = data ? 81 : 83;      /* IKCP_CMD_PUSH, or IKCP_CMD_WASK */
                seg[5] = 0;                   /* frg */
                seg[6] = (uint8_t)cli.kcp->rcv_wnd; seg[7] = (uint8_t)(cli.kcp->rcv_wnd >> 8);
                for (int k = 0; k < 4; k++)
                    for (int b = 0; b < 4; b++) seg[8 + 4 * k + b] = (uint8_t)(f[k] >> (8 * b));
            }
            uint64_t seq; sn_sender_alloc(&cli.c2s_seq, &seq);
            uint8_t dg[SN_WIRE_MTU + 64]; size_t dl = 0;
            int sealed = sn_seal(cli.k_kcp_c2s, 1, seq, seg, plen, dg, &dl) == 0 && dl == L;
            sn_env_result er = sn_handle_envelope(&dev, dg, dl, src, port, 20000 + (uint64_t)i * 20);
            sn_env_result want = sn_envelope_size_accept[i] ? SN_ENV_ESTABLISHED : SN_ENV_DROP;
            char label[96];
            snprintf(label, sizeof label, "envelope_size: a sealed %zu-octet datagram is %s",
                     L, sn_envelope_size_accept[i] ? "accepted" : "dropped");
            CHECK(sealed && er == want, label);
            if (er == SN_ENV_ESTABLISHED && plen > 24) next_sn++;
        }
    }

    ikcp_release(cli.kcp);
    ikcp_release(dev.primary.kcp);
    sn_device_locks_free(&dev);

    /* ── allocation-failure branch: force ikcp_create to fail via the allocator ── */
    /* Fresh device, admit a client, then make the next ikcp malloc fail. */
    {
        sn_device d2; sn_prefix l2[1];
        v4mapped(l2[0].a16, 192,168,4,1); l2[0].is_v4=1; l2[0].bits=24;
        uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
        sn_device_init_kdev(&d2, kd, DEVICE_ID, cookie_secret, ae, l2, 1, 8000);
        d2.rand_fill = fixed_rand;
        sn_device_locks_init(&d2);
        sn_device_set_send(&d2, capture_send, NULL);
        uint8_t i2[SN_INIT_LEN], m2[16];
        sn_init_mac(d2.k_req, nonce, DEVICE_ID, m2);
        sn_encode_init(nonce, DEVICE_ID, m2, i2);
        uint8_t r2[SN_RETRY_LEN];
        sn_handle_init(&d2, i2, SN_INIT_LEN, src, port, 8000, r2);
        uint8_t f2[SN_FINISH_LEN];
        ch_finish(PSK, DEVICE_ID, nonce, r2, ec_priv, f2, NULL);
        uint8_t a2[SN_ADMIT_LEN];
        sn_handle_finish(&d2, f2, SN_FINISH_LEN, src, port, 8000, a2);

        extern void ikcp_allocator(void* (*)(size_t), void (*)(void*));
        ikcp_allocator(fail_malloc, free); /* malloc returns NULL → ikcp_create fails */
        sn_env_result rf = sn_handle_envelope(&d2, g_c2s, g_c2s_len, src, port, 8100);
        ikcp_allocator(malloc, free); /* restore */
        CHECK(rf == SN_ENV_DROP, "allocation failure drops");
        CHECK(!d2.primary.active, "allocation failure leaves no primary");
        /* NB: the pending record SURVIVES a failed promotion here (index 0 is
         * still found). The §8.5 allocation-failure branch only discards it when
         * r->generation still equals the claim, and this path does not reach
         * that branch. The record ages out via the §6.3 expiry sweep instead.
         * This line previously read `... < 0 || 1` -- unconditionally true -- so
         * it asserted nothing and hid the difference between the comment and the
         * behaviour. Assert what actually holds; whether immediate discard is
         * wanted is a spec question, not something to infer from a test. */
        CHECK(sn_find_pending_index(&d2, dev.primary.tuple) >= 0,
              "pending record survives a failed promotion (ages out via §6.3)");
        sn_device_locks_free(&d2);
    }

    /* ── an undrained session's retention is bounded by rcv_wnd ──────────────
     * The ESP32's free heap fell 27752 -> ~2300 once a session was up. What
     * bounds device-side retention is rcv_wnd: ikcp caps the ordered queue and
     * the out-of-order buffer at rcv_wnd *each*, so the ceiling is 2 * rcv_wnd
     * segments. The configure_kcp ordering bug clamped rcv_wnd up to 128,
     * raising that ceiling to ~296 KB on a board with ~27 KB free.
     *
     * The sender's window must exceed the device's, or the *client* is the
     * binding constraint and the device ceiling is never reached -- an earlier
     * version of this test left the client at the default snd_wnd 32 and so
     * measured the client's backlog while claiming to measure the device's.
     * The device ACKs here too (as the real RX path does), or the client stalls
     * at its window and never applies pressure.
     *
     * Self-contained: the blocks above leave cli/dev with large queues and a
     * swapped allocator history. */
    {
        sn_device hd;
        uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
        sn_device_init_kdev(&hd, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
        hd.rand_fill = fixed_rand;
        sn_device_locks_init(&hd);
        sn_device_set_send(&hd, capture_send, NULL);

        uint8_t ih[SN_INIT_LEN], mh[16];
        sn_init_mac(hd.k_req, nonce, DEVICE_ID, mh);
        sn_encode_init(nonce, DEVICE_ID, mh, ih);
        uint8_t rh[SN_RETRY_LEN];
        sn_handle_init(&hd, ih, SN_INIT_LEN, src, port, 8000, rh);
        uint8_t fh[SN_FINISH_LEN];
        ch_finish(PSK, DEVICE_ID, nonce, rh, ec_priv, fh, NULL);
        uint8_t ah[SN_ADMIT_LEN];
        CHECK(sn_handle_finish(&hd, fh, SN_FINISH_LEN, src, port, 8000, ah) == SN_ADMIT_LEN,
              "retention: admission produced ADMIT");

        client_t hc; memset(&hc, 0, sizeof(hc));
        uint8_t ka[32], kb[32];
        ch_session_from(PSK, DEVICE_ID, nonce, rh, ec_priv, ah,
                        ka, kb, hc.k_kcp_c2s, hc.k_kcp_s2c);
        sn_sender_init(&hc.c2s_seq);
        hc.kcp = ikcp_create(0x40100000u, NULL);
        ikcp_setoutput(hc.kcp, client_output);
        ikcp_setmtu(hc.kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN);
        ikcp_nodelay(hc.kcp, 1, 20, 2, 1);
        hc.kcp->stream = 1;
        ikcp_wndsize(hc.kcp, 512, 512); /* must exceed the device's, or the client binds */
        client_t *saved = g_active_client;
        g_active_client = &hc;

        g_c2s_count = 0; g_c2s_len = 0;
        ikcp_send(hc.kcp, "promote", 7);
        ikcp_update(hc.kcp, 1000);
        CHECK(g_c2s_len > 0 &&
              sn_handle_envelope(&hd, g_c2s, g_c2s_len, src, port, 1100) == SN_ENV_PROMOTED,
              "retention: session promoted");

        IUINT32 wnd = hd.primary.kcp ? hd.primary.kcp->rcv_wnd : 0;
        int delivered = 0;
        for (int i = 0; i < 800; i++) {
            char msg[1200];
            memset(msg, 'h', sizeof(msg));
            g_c2s_count = 0; g_c2s_len = 0;
            ikcp_send(hc.kcp, msg, (int)sizeof(msg));
            ikcp_update(hc.kcp, (IUINT32)(2000 + i * 20));
            if (g_c2s_len == 0) continue;
            /* deliberately never call sn_primary_recv: the app is not draining */
            sn_handle_envelope(&hd, g_c2s, g_c2s_len, src, port, 2100 + i * 20);
            if (hd.primary.kcp) ikcp_update(hd.primary.kcp, (IUINT32)(2100 + i * 20));
            delivered++;
        }

        IUINT32 rb = hd.primary.kcp ? hd.primary.kcp->nrcv_buf : 0;
        IUINT32 rq = hd.primary.kcp ? hd.primary.kcp->nrcv_que : 0;
        IUINT32 held = rb + rq;
        printf("     [retention] delivered=%d rcv_wnd=%u nrcv_buf=%u nrcv_que=%u"
               " held=%u (~%u B at 1156 B/seg)\n",
               delivered, wnd, rb, rq, held, (unsigned)(held * 1156));

        /* The client's window is 512, so anything below that is the device
         * bounding itself rather than the sender running out of room. */
        CHECK(delivered > 200, "retention: enough segments delivered to fill the window");
        CHECK(held < 512u, "retention: device bounded itself, not the sender's window");
        CHECK(rb <= wnd && rq <= wnd, "retention: each receive buffer capped at rcv_wnd");
        CHECK(held * 1156u < 32768u,
              "retention: stays inside an ESP32-sized heap budget");

        g_active_client = saved;
        sn_device_release_primary(&hd);
        ikcp_release(hc.kcp);
        sn_device_locks_free(&hd);
    }


    /* ── a failed promotion over a LIVE primary must not leave a freed pointer ─
     * §8.5(a)5 retires the outgoing primary and the allocation-failure branch
     * releases it. The pointer has to be detached with the `active` flag: every
     * reader gates on `active` today, but sn_device_release_primary and the tick
     * both dereference d->primary.kcp under that flag alone, so a stale pointer
     * is one refactor from a use-after-free.
     *
     * This needs an existing primary. Checking it on a device that never
     * promoted is vacuous -- primary.kcp is NULL from init, so the assertion
     * holds whether or not the code detaches anything. */
    {
        sn_device dd;
        uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
        sn_device_init_kdev(&dd, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
        dd.rand_fill = fixed_rand;
        sn_device_locks_init(&dd);
        sn_device_set_send(&dd, capture_send, NULL);

        client_t *saved = g_active_client;
        client_t ca, cb;
        ikcpcb *ka_kcp = NULL, *kb_kcp = NULL;
        uint32_t live_gen = 0;

        /* two admissions from different source ports -> two pending records */
        for (int pass = 0; pass < 2; pass++) {
            uint16_t p2 = (uint16_t)(6000 + pass);
            uint8_t i2[SN_INIT_LEN], m2[16];
            sn_init_mac(dd.k_req, nonce, DEVICE_ID, m2);
            sn_encode_init(nonce, DEVICE_ID, m2, i2);
            uint8_t r2[SN_RETRY_LEN];
            sn_handle_init(&dd, i2, SN_INIT_LEN, src, p2, 8000, r2);
            uint8_t f2[SN_FINISH_LEN];
            ch_finish(PSK, DEVICE_ID, nonce, r2, ec_priv, f2, NULL);
            uint8_t a2[SN_ADMIT_LEN];
            if (sn_handle_finish(&dd, f2, SN_FINISH_LEN, src, p2, 8000, a2) != SN_ADMIT_LEN) continue;

            client_t *cx = pass ? &cb : &ca;
            memset(cx, 0, sizeof(*cx));
            uint8_t x1[32], x2[32];
            ch_session_from(PSK, DEVICE_ID, nonce, r2, ec_priv, a2,
                            x1, x2, cx->k_kcp_c2s, cx->k_kcp_s2c);
            sn_sender_init(&cx->c2s_seq);
            cx->kcp = ikcp_create(0x7A000000u + (IUINT32)pass, NULL);
            ikcp_setoutput(cx->kcp, client_output);
            ikcp_setmtu(cx->kcp, SN_WIRE_MTU - SN_ENVELOPE_LEN);
            ikcp_nodelay(cx->kcp, 1, 20, 2, 1);
            if (pass) kb_kcp = cx->kcp; else ka_kcp = cx->kcp;

            g_active_client = cx;
            g_c2s_count = 0; g_c2s_len = 0;
            ikcp_send(cx->kcp, "p", 1);
            ikcp_update(cx->kcp, (IUINT32)(1000 + pass * 100));

            if (pass == 0) {
                /* first: promote for real, so a primary exists to retire */
                CHECK(g_c2s_len > 0 &&
                      sn_handle_envelope(&dd, g_c2s, g_c2s_len, src, p2, 1100) == SN_ENV_PROMOTED,
                      "dangling: first promotion establishes a primary");
                CHECK(dd.primary.active && dd.primary.kcp != NULL,
                      "dangling: primary is live before the failing promotion");
                live_gen = dd.primary.generation;
            } else {
                /* second: fail the allocation while a primary is live */
                extern void ikcp_allocator(void* (*)(size_t), void (*)(void*));
                ikcp_allocator(fail_malloc, free);
                sn_env_result r3 = sn_handle_envelope(&dd, g_c2s, g_c2s_len, src, p2, 1200);
                ikcp_allocator(malloc, free);
                CHECK(r3 == SN_ENV_DROP, "dangling: failing promotion drops");
                CHECK(!dd.primary.active, "dangling: no primary after the failure");
                CHECK(dd.primary.kcp == NULL,
                      "dangling: retired kcp pointer detached, not left freed-but-set");
                /* (a)5 used to bump the retired generation to exactly the value
                 * the new session then took from promo_gen, so a reader between
                 * (a) and (c) paired the NEW generation with the wiped keys.
                 * The failure branch stops after (a), which makes the two
                 * values observable: the retired one and the one (b) consumed. */
                CHECK(dd.primary.generation != live_gen,
                      "generation: the retired primary no longer carries its generation");
                CHECK(dd.primary.generation != dd.promo_gen,
                      "generation: the retired value is not the one the new session took");
            }
        }

        g_active_client = saved;
        if (ka_kcp) ikcp_release(ka_kcp);
        if (kb_kcp) ikcp_release(kb_kcp);
        sn_device_release_primary(&dd);
        sn_device_locks_free(&dd);
    }


    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all promotion §8.5/§8.6 cases pass\n");
    return 0;
}
