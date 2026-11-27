/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §6.2 FINISH -> ADMIT: mirrors goshieldnet/v1/device_finish_test.go. Full
 * admission with client/device key agreement, verbatim resend, rejections,
 * replace + oldest-slot eviction. */
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"

#include "client_helper.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};

static void v4mapped(uint8_t a[16], uint8_t b, uint8_t c, uint8_t dd, uint8_t e) {
    memset(a, 0, 16); a[10]=0xff; a[11]=0xff; a[12]=b; a[13]=c; a[14]=dd; a[15]=e;
}

/* deterministic ephemeral source */
static uint8_t g_fill = 0x42;
static void fixed_rand(void *ctx, uint8_t *buf, size_t n) { (void)ctx; memset(buf, g_fill, n); }

static void make_device(sn_device *dev, sn_prefix *local) {
    memset(PSK, 0x11, 32);
    uint8_t cookie_secret[32]; memset(cookie_secret, 0x22, 32);
    uint8_t ae[8] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    v4mapped(local[0].a16, 192,168,4,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(dev, kd, DEVICE_ID, cookie_secret, ae, local, 1, 8000);
    dev->rand_fill = fixed_rand;
}

/* Build the FINISH a client would send after this RETRY with e_c private key.
 * Was a local copy of the admission sequence; now the shared helper. */
static void client_finish(const uint8_t nonce[24], const uint8_t ec_priv[32],
                          const uint8_t retry[SN_RETRY_LEN],
                          uint8_t fin[SN_FINISH_LEN], uint8_t ec_pub_out[32]) {
    ch_finish(PSK, DEVICE_ID, nonce, retry, ec_priv, fin, ec_pub_out);
}

static void make_init(const sn_device *dev, const uint8_t nonce[24], uint8_t init[SN_INIT_LEN]) {
    (void)dev;
    ch_init(PSK, DEVICE_ID, nonce, init);
}

/* run INIT->RETRY->FINISH from a given source port; returns admit len */
static size_t admit_from(sn_device *dev, uint16_t port, uint8_t ec_fill, uint64_t now,
                         uint8_t admit[SN_ADMIT_LEN]) {
    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16]; v4mapped(src, 192,168,4,2);
    uint8_t init[SN_INIT_LEN]; make_init(dev, nonce, init);
    uint8_t retry[SN_RETRY_LEN];
    sn_handle_init(dev, init, SN_INIT_LEN, src, port, now, retry);
    uint8_t ec_priv[32]; memset(ec_priv, ec_fill, 32);
    uint8_t fin[SN_FINISH_LEN];
    client_finish(nonce, ec_priv, retry, fin, NULL);
    return sn_handle_finish(dev, fin, SN_FINISH_LEN, src, port, now, admit);
}

static int find_tuple(const sn_device *d, uint16_t port) {
    uint8_t src[16]; v4mapped(src, 192,168,4,2);
    uint8_t tuple[18]; sn_canonical_source(src, port, tuple);
    for (int i = 0; i < SN_PENDING_SLOTS; i++)
        if (d->pending[i].used && memcmp(d->pending[i].tuple, tuple, 18) == 0) return i;
    return -1;
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium_init failed\n"); return 1; }
    sn_device dev; sn_prefix local[1];
    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16]; v4mapped(src, 192,168,4,2);
    uint16_t port = 5000;

    /* ── full admission + client/device key agreement ── */
    make_device(&dev, local);
    uint8_t init[SN_INIT_LEN]; make_init(&dev, nonce, init);
    uint8_t retry[SN_RETRY_LEN]; sn_handle_init(&dev, init, SN_INIT_LEN, src, port, 8000, retry);
    uint8_t ec_priv[32]; memset(ec_priv, 0x07, 32);
    uint8_t fin[SN_FINISH_LEN], ec_pub[32];
    client_finish(nonce, ec_priv, retry, fin, ec_pub);
    uint8_t admit[SN_ADMIT_LEN];
    size_t n = sn_handle_finish(&dev, fin, SN_FINISH_LEN, src, port, 8000, admit);
    CHECK(n == SN_ADMIT_LEN, "valid FINISH produces ADMIT");

    /* ADMIT admission_epoch is the presented value (retry's) */
    CHECK(memcmp(admit + 10, retry + 34, 8) == 0, "ADMIT admission_epoch is presented value");

    /* client re-derives and checks admit_pre / admit_tag / keys */
    const uint8_t *es = admit + 18;
    uint8_t context[65];
    sn_context(nonce, retry+10, retry+18, retry+34, DEVICE_ID, context);
    uint8_t context2[129]; sn_context2(context, ec_pub, es, context2);
    uint8_t k_dev[32], k_req[32], k_resp[32];
    sn_derive_kdev(PSK, DEVICE_ID, k_dev); sn_derive_static(k_dev, k_req, k_resp);
    uint8_t want_pre[16]; sn_admit_pre(k_resp, context2, want_pre);
    CHECK(memcmp(want_pre, admit + 50, 16) == 0, "admit_pre verifies at client");
    uint8_t dh[32]; int rc = sn_dh(ec_priv, es, dh);
    CHECK(rc == 0, "client DH ok");
    uint8_t master[32]; sn_master(context2, k_dev, dh, master);
    uint8_t want_atag[16]; sn_admit_tag(master, want_atag);
    CHECK(memcmp(want_atag, admit + 66, 16) == 0, "admit_tag verifies at client");
    uint8_t ck_c2s[32], ck_s2c[32], ck_kc[32], ck_ks[32];
    sn_session_keys(master, ck_c2s, ck_s2c, ck_kc, ck_ks);
    int slot = find_tuple(&dev, port);
    CHECK(slot >= 0, "pending record installed");
    CHECK(memcmp(ck_c2s, dev.pending[slot].k_c2s, 32) == 0 &&
          memcmp(ck_ks, dev.pending[slot].k_kcp_s2c, 32) == 0,
          "client and device agree on session keys");
    CHECK(memcmp(dev.admission_epoch, retry + 34, 8) != 0, "admission_epoch advanced");

    /* ── verbatim resend: same ADMIT, no epoch advance ── */
    uint8_t ae_after[8]; memcpy(ae_after, dev.admission_epoch, 8);
    uint8_t admit2[SN_ADMIT_LEN];
    size_t n2 = sn_handle_finish(&dev, fin, SN_FINISH_LEN, src, port, 8100, admit2);
    CHECK(n2 == SN_ADMIT_LEN && memcmp(admit, admit2, SN_ADMIT_LEN) == 0, "verbatim resend");
    CHECK(memcmp(dev.admission_epoch, ae_after, 8) == 0, "resend does not advance epoch");

    /* ── replay from a different tuple → cookie mismatch → drop ── */
    {
        sn_device d2; sn_prefix l2[1]; make_device(&d2, l2);
        uint8_t r2[SN_RETRY_LEN], i2[SN_INIT_LEN]; make_init(&d2, nonce, i2);
        sn_handle_init(&d2, i2, SN_INIT_LEN, src, port, 8000, r2);
        uint8_t f2[SN_FINISH_LEN]; client_finish(nonce, ec_priv, r2, f2, NULL);
        uint8_t elsewhere[16]; v4mapped(elsewhere, 192,168,4,9);
        uint8_t a2[SN_ADMIT_LEN];
        CHECK(sn_handle_finish(&d2, f2, SN_FINISH_LEN, elsewhere, port, 8000, a2) == 0,
              "replay from other tuple dropped");
    }

    /* ── bad client_tag → drop, no state ── */
    {
        sn_device d3; sn_prefix l3[1]; make_device(&d3, l3);
        uint8_t r3[SN_RETRY_LEN], i3[SN_INIT_LEN]; make_init(&d3, nonce, i3);
        sn_handle_init(&d3, i3, SN_INIT_LEN, src, port, 8000, r3);
        uint8_t f3[SN_FINISH_LEN]; client_finish(nonce, ec_priv, r3, f3, NULL);
        f3[98] ^= 0xFF;
        uint8_t ae_before[8]; memcpy(ae_before, d3.admission_epoch, 8);
        uint8_t a3[SN_ADMIT_LEN];
        CHECK(sn_handle_finish(&d3, f3, SN_FINISH_LEN, src, port, 8000, a3) == 0, "bad client_tag dropped");
        CHECK(memcmp(d3.admission_epoch, ae_before, 8) == 0, "bad client_tag: no epoch change");
    }

    /* ── all-zero DH: e_c a low-order (all-zero) point → drop ── */
    {
        sn_device d4; sn_prefix l4[1]; make_device(&d4, l4);
        uint8_t r4[SN_RETRY_LEN], i4[SN_INIT_LEN]; make_init(&d4, nonce, i4);
        sn_handle_init(&d4, i4, SN_INIT_LEN, src, port, 8000, r4);
        /* A raw e_c no keypair can produce, which is why ch_finish_from takes
         * the point rather than a private key. */
        uint8_t low[32]; memset(low, 0, 32);
        uint8_t flow[SN_FINISH_LEN];
        ch_finish_from(PSK, DEVICE_ID, nonce, r4, low, flow);
        uint8_t a4[SN_ADMIT_LEN];
        CHECK(sn_handle_finish(&d4, flow, SN_FINISH_LEN, src, port, 8000, a4) == 0, "all-zero DH dropped");
    }

    /* ── §4.3 in sn_handle_finish: a rejected source drops even with a cookie
     *    that is valid for it (obtained with the check off) ── */
    {
        sn_device d6; sn_prefix l6[1]; make_device(&d6, l6);
        uint8_t bcast[16]; v4mapped(bcast, 192,168,4,255);
        sn_device_set_source_check(&d6, 0);
        uint8_t r6[SN_RETRY_LEN], i6[SN_INIT_LEN]; make_init(&d6, nonce, i6);
        CHECK(sn_handle_init(&d6, i6, SN_INIT_LEN, bcast, port, 8000, r6) == SN_RETRY_LEN,
              "check off: RETRY to the broadcast source");
        sn_device_set_source_check(&d6, 1);
        uint8_t f6[SN_FINISH_LEN]; client_finish(nonce, ec_priv, r6, f6, NULL);
        uint8_t a6[SN_ADMIT_LEN];
        uint8_t ae_before[8]; memcpy(ae_before, d6.admission_epoch, 8);
        CHECK(sn_handle_finish(&d6, f6, SN_FINISH_LEN, bcast, port, 8000, a6) == 0,
              "FINISH from subnet broadcast dropped");
        CHECK(memcmp(d6.admission_epoch, ae_before, 8) == 0 &&
              !d6.pending[0].used && !d6.pending[1].used,
              "rejected-source FINISH: no state");
        sn_device_set_source_check(&d6, 0);
        CHECK(sn_handle_finish(&d6, f6, SN_FINISH_LEN, bcast, port, 8000, a6) == SN_ADMIT_LEN,
              "same FINISH admitted with the check off (the drop was the source)");
    }

    /* ── replace + oldest-slot eviction ── */
    {
        sn_device d5; sn_prefix l5[1]; make_device(&d5, l5);
        uint8_t a[SN_ADMIT_LEN];
        /* Fill every pending slot, oldest first: ports 5000 .. 5000 + N - 1. */
        int filled = 0;
        for (int i = 0; i < SN_PENDING_SLOTS; i++)
            filled += admit_from(&d5, (uint16_t)(5000 + i), (uint8_t)(0x07 + i), 8000 + i, a) == SN_ADMIT_LEN;
        CHECK(filled == SN_PENDING_SLOTS, "admit one source per pending slot");
        uint32_t g0 = d5.pending[find_tuple(&d5, 5000)].generation;
        CHECK(admit_from(&d5, 5000, 0x40, 8000 + SN_PENDING_SLOTS, a) == SN_ADMIT_LEN, "re-admit :5000");
        CHECK(d5.pending[find_tuple(&d5, 5000)].generation != g0, "replace advances generation");
        int used = 0;
        for (int i = 0; i < SN_PENDING_SLOTS; i++) if (d5.pending[i].used) used++;
        CHECK(used == SN_PENDING_SLOTS, "still every slot used after replace");
        /* :5000 is now the newest, so :5001 is the oldest. */
        uint16_t extra = (uint16_t)(5000 + SN_PENDING_SLOTS);
        CHECK(admit_from(&d5, extra, 0x41, 8001 + SN_PENDING_SLOTS, a) == SN_ADMIT_LEN,
              "admit one more source (evicts oldest)");
        CHECK(find_tuple(&d5, 5001) < 0, "oldest :5001 evicted");
        CHECK(find_tuple(&d5, extra) >= 0, "the new source is installed");
    }

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all FINISH §6.2/§6.3 cases pass\n");
    return 0;
}
