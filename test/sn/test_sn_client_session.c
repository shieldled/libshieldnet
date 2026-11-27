/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* The client session against the real C device, in one process.
 *
 * The session is tested on its own, without the §7 state machine, so the
 * state machine is built on something already known to carry bytes. The
 * admission is driven with client_helper.h, and the two ends are wired to
 * each other's inputs rather than to a socket. */
#include "shieldnet/sn_client_session.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"

#include "client_helper.h"

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
static void fixed_rand(void *ctx, uint8_t *buf, size_t n) { (void)ctx; memset(buf, 0x42, n); }

/* ── the wire between the two ends, as two one-slot mailboxes ── */
static uint8_t g_to_device[2048]; static size_t g_to_device_len;
static uint8_t g_to_client[2048]; static size_t g_to_client_len;

static void client_sends(void *ctx, const uint8_t *dg, size_t len) {
    (void)ctx;
    if (len <= sizeof g_to_device) { memcpy(g_to_device, dg, len); g_to_device_len = len; }
}
static void device_sends(void *ctx, const uint8_t *dg, size_t len) {
    (void)ctx;
    if (len <= sizeof g_to_client) { memcpy(g_to_client, dg, len); g_to_client_len = len; }
}

static uint8_t g_got[2048]; static size_t g_got_len; static int g_got_count;
static void on_msg(void *ctx, const uint8_t *msg, size_t len) {
    (void)ctx;
    if (len <= sizeof g_got) { memcpy(g_got, msg, len); g_got_len = len; }
    g_got_count++;
}

/* ikcp's allocator seam, failing after a budget: how ikcp_send's OOM return
 * (-2 after part of the message is queued) is reached without a real OOM. */
static int g_alloc_budget = -1;   /* < 0: unlimited */
static void *budget_malloc(size_t n) {
    if (g_alloc_budget == 0) return NULL;
    if (g_alloc_budget > 0) g_alloc_budget--;
    return malloc(n);
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }

    /* ── admission, so the two ends share §4.5 keys ── */
    sn_device dev; sn_prefix local[1];
    memset(PSK, 0x11, 32);
    uint8_t cookie_secret[32]; memset(cookie_secret, 0x22, 32);
    uint8_t ae[8] = {0,1,2,3,4,5,6,7};
    v4mapped(local[0].a16, 192,168,4,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&dev, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
    dev.rand_fill = fixed_rand;
    sn_device_locks_init(&dev);
    sn_device_set_send(&dev, device_sends, NULL);

    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16];   v4mapped(src, 192,168,4,2);
    uint8_t init[SN_INIT_LEN]; ch_init(PSK, DEVICE_ID, nonce, init);
    uint8_t retry[SN_RETRY_LEN];
    CHECK(sn_handle_init(&dev, init, SN_INIT_LEN, src, PORT, 8000, retry) == SN_RETRY_LEN, "RETRY");
    uint8_t ec_priv[32]; memset(ec_priv, 0x07, 32);
    uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK, DEVICE_ID, nonce, retry, ec_priv, fin, NULL);
    uint8_t admit[SN_ADMIT_LEN];
    CHECK(sn_handle_finish(&dev, fin, SN_FINISH_LEN, src, PORT, 8000, admit) == SN_ADMIT_LEN, "ADMIT");

    uint8_t kc2s[32], ks2c[32], kkc2s[32], kks2c[32];
    ch_session_from(PSK, DEVICE_ID, nonce, retry, ec_priv, admit, kc2s, ks2c, kkc2s, kks2c);

    /* ── the session under test ── */
    sn_client_session cs;
    CHECK(sn_client_session_init(&cs, 0x11223344u, kkc2s, kks2c) == SN_CS_OK, "session init");
    sn_client_session_set_send(&cs, client_sends, NULL);
    sn_client_session_set_on_msg(&cs, on_msg, NULL);

    /* ── the promoting PUSH (§8.5): first client datagram promotes the pending ── */
    uint32_t now = 8100;
    const char *first = "hello-device";
    CHECK(sn_client_session_send(&cs, (const uint8_t *)first, strlen(first), now) == SN_CS_OK,
          "client send accepted");
    CHECK(g_to_device_len > 0, "client emitted a sealed datagram");
    CHECK(sn_handle_envelope(&dev, g_to_device, g_to_device_len, src, PORT, now) == SN_ENV_PROMOTED,
          "device accepted the promoting PUSH");
    CHECK(dev.primary.active, "device has a primary");
    {
        uint8_t got[256];
        int n = sn_primary_recv(&dev, got, (int)sizeof got);
        CHECK(n == (int)strlen(first) && memcmp(got, first, strlen(first)) == 0,
              "device received the client's bytes");
    }

    /* ── device → client ── */
    const char *reply = "hello-client";
    g_to_client_len = 0; g_got_count = 0;
    CHECK(sn_primary_send(&dev, (const uint8_t *)reply, (int)strlen(reply), now) >= 0,
          "device send accepted");
    /* KCP flushes on its interval, not on send, so step past one. */
    for (uint32_t t = now; t <= now + 200 && g_to_client_len == 0; t += 20) {
        sn_primary_update(&dev, t);
    }
    CHECK(g_to_client_len > 0, "device emitted a sealed datagram");
    CHECK(sn_client_session_input(&cs, g_to_client, g_to_client_len, now + 200) == 1,
          "client delivered one message");
    CHECK(g_got_len == strlen(reply) && memcmp(g_got, reply, g_got_len) == 0,
          "client received the device's bytes");

    /* ── §8.2: the same datagram twice is a replay ── */
    g_got_count = 0;
    CHECK(sn_client_session_input(&cs, g_to_client, g_to_client_len, now + 20) == 0 &&
          g_got_count == 0, "replayed datagram dropped");

    /* ── §8.1: a forged datagram is indistinguishable from noise ── */
    {
        uint8_t bad[2048]; memcpy(bad, g_to_client, g_to_client_len);
        bad[0] ^= 1;
        g_got_count = 0;
        CHECK(sn_client_session_input(&cs, bad, g_to_client_len, now + 30) == 0 &&
              g_got_count == 0, "tampered datagram dropped");
    }

    /* ── a len no message can have is refused before any arithmetic ──
     *
     * It used to be cast to int for the segment count, multiplied by mss in
     * int (signed overflow, UB), and truncated to int for ikcp_send, so 2^32+4
     * went out as 4 bytes and reported success. Refused before anything reads
     * the buffer, so the small one here is enough. */
    {
        uint8_t small[8] = {0};
        int waitsnd = ikcp_waitsnd(cs.kcp);
        size_t huge = (size_t)0x100000004ULL;   /* > INT_MAX, and 4 when cast */
        CHECK(sn_client_session_send(&cs, small, huge, now + 35) == SN_CS_ERR,
              "a len above INT_MAX is refused, not truncated");
        CHECK(sn_client_session_send(&cs, small, (size_t)-1, now + 35) == SN_CS_ERR,
              "SIZE_MAX is refused");
        static uint8_t over[SN_CS_MSG_MAX + 1];
        CHECK(sn_client_session_send(&cs, over, sizeof over, now + 35) == SN_CS_ERR,
              "a message larger than the whole §9.5 cap is an error, not QUEUE_FULL");
        CHECK(ikcp_waitsnd(cs.kcp) == waitsnd && !cs.broken,
              "and nothing was queued: the session is intact");
    }

    /* ── message layer 7.3: a message that can never fit is an error at once ── */
    {
        sn_client_session cs3;
        CHECK(sn_client_session_init(&cs3, 0x99aabbccu, kkc2s, kks2c) == SN_CS_OK,
              "third session init");
        sn_client_session_set_send(&cs3, client_sends, NULL);
        size_t mss = cs3.kcp->mss;
        size_t cap = (SN_SEND_QUEUE_MAX / mss) * mss;
        static uint8_t big[SN_SEND_QUEUE_MAX]; memset(big, 'z', sizeof big);
        printf("     (mss %zu, whole-segment cap %zu)\n", mss, cap);
        CHECK(cap + 1 <= SN_CS_MSG_MAX && ikcp_waitsnd(cs3.kcp) == 0 &&
              sn_client_session_send(&cs3, big, cap + 1, now + 70) == SN_CS_ERR &&
              ikcp_waitsnd(cs3.kcp) == 0 && !cs3.broken,
              "message layer 7.3: a message one byte over the whole-segment cap is SN_CS_ERR");
        CHECK(sn_client_session_send(&cs3, big, cap, now + 70) == SN_CS_OK,
              "message layer 7.3: a message of exactly the cap is accepted");
        sn_client_session_free(&cs3);
    }

    /* ── §9.5: the send cap refuses rather than growing without a peer ── */
    {
        uint8_t blob[1024]; memset(blob, 'x', sizeof blob);
        int rc = SN_CS_OK, sent = 0;
        /* Nothing drains the far side now, so the queue only grows. */
        for (int i = 0; i < 4096 && rc == SN_CS_OK; i++) {
            rc = sn_client_session_send(&cs, blob, sizeof blob, now + 40);
            if (rc == SN_CS_OK) sent++;
        }
        CHECK(rc == SN_CS_QUEUE_FULL, "send refused at the §9.5 cap, not queued forever");
        CHECK(sent > 0, "the cap is not so low that nothing sends");
        printf("     (cap reached after %d writes of %zu bytes)\n", sent, sizeof blob);
    }

    /* ── ikcp_send failing mid-message is fatal, never a retry ──
     *
     * A fresh session so the queue is empty: one 3-segment message, with the
     * allocator allowing exactly one segment. ikcp_send returns -2 having
     * queued the first; a retry would then put those bytes in the stream
     * twice, so the session must refuse everything after. */
    {
        sn_client_session cs2;
        CHECK(sn_client_session_init(&cs2, 0x55667788u, kkc2s, kks2c) == SN_CS_OK,
              "second session init");
        int sent_dgrams = 0;
        g_to_device_len = 0;
        sn_client_session_set_send(&cs2, client_sends, NULL);
        static uint8_t three[3000]; memset(three, 'y', sizeof three);
        g_alloc_budget = 1;
        ikcp_allocator(budget_malloc, free);
        int rc = sn_client_session_send(&cs2, three, sizeof three, now + 50);
        ikcp_allocator(NULL, NULL);
        g_alloc_budget = -1;
        CHECK(rc == SN_CS_ERR, "an OOM mid-fragmentation is an error, not QUEUE_FULL");
        CHECK(cs2.broken, "and the session is marked broken");
        CHECK(sn_client_session_send(&cs2, three, sizeof three, now + 60) == SN_CS_ERR,
              "a retry is refused rather than duplicating the queued part");
        for (uint32_t t = now + 60; t <= now + 400; t += 20) {
            sn_client_session_update(&cs2, t);
            if (g_to_device_len) { sent_dgrams++; g_to_device_len = 0; }
        }
        CHECK(sent_dgrams == 0, "the partial message never reaches the wire");
        sn_client_session_free(&cs2);
    }

    sn_client_session_free(&cs);
    CHECK(cs.kcp == NULL, "free is idempotent-safe");
    sn_client_session_free(&cs);

    sn_device_release_primary(&dev);

    sn_device_locks_free(&dev);
    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("all client-session cases pass\n");
    return 0;
}
