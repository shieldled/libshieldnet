/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §6.1 INIT -> RETRY: mirrors goshieldnet/v1/device_test.go. A valid INIT yields
 * a RETRY whose fields recompute/verify; the rejection paths drop. */
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "../sn_vectors.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static void v4mapped(uint8_t a[16], uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    memset(a, 0, 16); a[10]=0xff; a[11]=0xff; a[12]=b; a[13]=c; a[14]=d; a[15]=e;
}

static void make_device(sn_device *dev, sn_prefix *local) {
    uint8_t psk[32]; memset(psk, 0x11, 32);
    uint8_t device_id[8] = {1,2,3,4,5,6,7,8};
    uint8_t cookie_secret[32]; memset(cookie_secret, 0x22, 32);
    uint8_t admission_epoch[8] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    v4mapped(local[0].a16, 192,168,4,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(psk, device_id, kd);
    sn_device_init_kdev(dev, kd, device_id, cookie_secret, admission_epoch, local, 1, 8000);
}

static void valid_init(const sn_device *dev, const uint8_t nonce[24],
                       const uint8_t device_id[8], uint8_t out[SN_INIT_LEN]) {
    uint8_t mac[16];
    sn_init_mac(dev->k_req, nonce, device_id, mac);
    sn_encode_init(nonce, device_id, mac, out);
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium_init failed\n"); return 1; }
    sn_device dev; sn_prefix local[1];
    make_device(&dev, local);
    uint8_t device_id[8] = {1,2,3,4,5,6,7,8};
    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16]; v4mapped(src, 192,168,4,2);
    uint16_t port = 5000;

    /* valid INIT -> verifiable RETRY */
    uint8_t init[SN_INIT_LEN]; valid_init(&dev, nonce, device_id, init);
    uint8_t retry[SN_RETRY_LEN];
    size_t n = sn_handle_init(&dev, init, SN_INIT_LEN, src, port, 8000, retry);
    CHECK(n == SN_RETRY_LEN, "valid INIT produces RETRY");

    /* decode RETRY layout and re-derive */
    uint8_t cs[18]; sn_canonical_source(src, port, cs);
    CHECK(memcmp(retry + 50, cs, 18) == 0, "observed_source == canonical_source");
    CHECK(memcmp(retry + 10, dev.epoch_tag, 8) == 0, "epoch_tag is device's");
    CHECK(memcmp(retry + 34, dev.admission_epoch, 8) == 0, "admission_epoch is device's");
    CHECK(memcmp(retry + 42, device_id, 8) == 0, "device_id echoed");
    uint8_t want_cookie[16];
    sn_cookie(dev.cookie_secret, dev.epoch_tag, cs, nonce, want_cookie);
    CHECK(memcmp(retry + 18, want_cookie, 16) == 0, "cookie recomputes");
    uint8_t want_mac[16];
    sn_retry_mac(dev.k_resp, nonce, retry+10, retry+18, retry+34, retry+42, retry+50, want_mac);
    CHECK(memcmp(retry + 68, want_mac, 16) == 0, "retry_mac verifies");

    /* wrong device_id -> drop */
    uint8_t other[8] = {9,9,9,9,9,9,9,9};
    uint8_t init2[SN_INIT_LEN]; valid_init(&dev, nonce, other, init2);
    CHECK(sn_handle_init(&dev, init2, SN_INIT_LEN, src, port, 8000, retry) == 0, "wrong device_id drops");

    /* bad init_mac -> drop */
    uint8_t init3[SN_INIT_LEN]; valid_init(&dev, nonce, device_id, init3);
    init3[42] ^= 0xFF;
    CHECK(sn_handle_init(&dev, init3, SN_INIT_LEN, src, port, 8000, retry) == 0, "bad init_mac drops");

    /* wrong length -> drop */
    uint8_t small[100]; memset(small, 0, 100);
    CHECK(sn_handle_init(&dev, small, 100, src, port, 8000, retry) == 0, "short INIT drops");

    /* non-zero padding -> drop */
    uint8_t init4[SN_INIT_LEN]; valid_init(&dev, nonce, device_id, init4);
    init4[200] = 0x01;
    CHECK(sn_handle_init(&dev, init4, SN_INIT_LEN, src, port, 8000, retry) == 0, "nonzero padding drops");

    /* roll epoch keeps previous */
    uint8_t first[8]; memcpy(first, dev.epoch_tag, 8);
    sn_device_roll_epoch(&dev, 8500); /* same epoch */
    CHECK(memcmp(dev.epoch_tag, first, 8) == 0 && !dev.have_prev, "roll within epoch is a no-op");
    sn_device_roll_epoch(&dev, 12000); /* epoch 3 */
    CHECK(memcmp(dev.epoch_tag, first, 8) != 0, "epoch_tag advances");
    CHECK(dev.have_prev && memcmp(dev.prev_epoch_tag, first, 8) == 0, "previous epoch_tag retained");
    CHECK(dev.prev_epoch == 2, "previous epoch_tag is epoch 2's");
    sn_device_roll_epoch(&dev, 24000); /* epoch 6: a gap of three */
    CHECK(!dev.have_prev, "roll across a gap keeps no previous (epoch 3 is not 5)");

    /* §4.3 in the handler itself, not only in sn_classify: a board that demuxes
     * with sn_classify_datagram must still never answer these sources. */
    {
        sn_device d2; sn_prefix l2[1]; make_device(&d2, l2);
        uint8_t in[SN_INIT_LEN]; valid_init(&d2, nonce, device_id, in);
        uint8_t bad[16];
        v4mapped(bad, 192,168,4,1);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from own address drops");
        v4mapped(bad, 192,168,4,255);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from subnet broadcast drops");
        v4mapped(bad, 255,255,255,255);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from limited broadcast drops");
        v4mapped(bad, 224,0,0,1);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from v4 multicast drops");
        v4mapped(bad, 127,0,0,1);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from loopback drops");
        v4mapped(bad, 0,0,0,0);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from 0.0.0.0 drops");
        memset(bad, 0, 16); bad[0] = 0xff; bad[1] = 0x02; bad[15] = 1;
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from ff02::1 drops");
        memset(bad, 0, 16); bad[15] = 1;
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0, "INIT from ::1 drops");
        memset(bad, 0, 16); bad[0] = 0xfe; bad[1] = 0x80; bad[15] = 7;
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == SN_RETRY_LEN,
              "INIT from fe80::7 answered");
        /* the loopback-harness opt-out, and only it */
        sn_device_set_source_check(&d2, 0);
        v4mapped(bad, 127,0,0,1);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == SN_RETRY_LEN,
              "source check off: loopback answered");
        sn_device_set_source_check(&d2, 1);
        CHECK(sn_handle_init(&d2, in, SN_INIT_LEN, bad, port, 8000, retry) == 0,
              "source check back on: loopback drops");
    }

    /* Spec transport 3.2 / Appendix C.1: a device given k_dev and device_id
     * derives the vector k_req and k_resp. */
    {
        uint8_t cookie_secret[32]; memset(cookie_secret, 0x22, 32);
        uint8_t admission_epoch[8] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
        sn_prefix l3[1];
        v4mapped(l3[0].a16, 192,168,4,1); l3[0].is_v4=1; l3[0].bits=24;

        sn_device kd;
        int rc = sn_device_init_kdev(&kd, sn_want_k_dev, sn_in_device_id, cookie_secret,
                                     admission_epoch, l3, 1, 8000);
        CHECK(rc == 0, "init_kdev_vector: returns 0");
        CHECK(kd.init_failed == 0, "init_kdev_vector: init_failed is 0");
        CHECK(memcmp(kd.k_dev, sn_want_k_dev, 32) == 0, "init_kdev_vector: k_dev");
        CHECK(memcmp(kd.k_req, sn_want_k_req, 32) == 0, "init_kdev_vector: k_req");
        CHECK(memcmp(kd.k_resp, sn_want_k_resp, 32) == 0, "init_kdev_vector: k_resp");

        /* An all-zero k_dev leaves the device fail-closed. */
        uint8_t zero[32]; memset(zero, 0, 32);
        sn_device zd;
        rc = sn_device_init_kdev(&zd, zero, sn_in_device_id, cookie_secret,
                                 admission_epoch, l3, 1, 8000);
        CHECK(rc == -1, "init_kdev_zero_key_fails_closed: returns -1");
        CHECK(zd.init_failed == 1, "init_kdev_zero_key_fails_closed: init_failed is 1");
        uint8_t zreq[32], zresp[32];
        sn_derive_static(zero, zreq, zresp);
        uint8_t zmac[16], zin[SN_INIT_LEN];
        sn_init_mac(zreq, nonce, sn_in_device_id, zmac);
        sn_encode_init(nonce, sn_in_device_id, zmac, zin);
        CHECK(sn_handle_init(&zd, zin, SN_INIT_LEN, src, port, 8000, retry) == 0,
              "init_kdev_zero_key_fails_closed: INIT under the zero key drops");

        /* Transport 3.4: the admission epoch is non-zero, top 8 bits clear. */
        uint8_t ep0[8] = {0};
        uint8_t ep_top[8] = {0x01,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
        sn_device ed;
        rc = sn_device_init_kdev(&ed, sn_want_k_dev, sn_in_device_id, cookie_secret,
                                 ep0, l3, 1, 8000);
        CHECK(rc == -1 && ed.init_failed == 1 && sodium_is_zero(ed.k_dev, 32),
              "transport 3.4: epoch 0 returns -1 and init_failed");
        rc = sn_device_init_kdev(&ed, sn_want_k_dev, sn_in_device_id, cookie_secret,
                                 ep_top, l3, 1, 8000);
        CHECK(rc == -1 && ed.init_failed == 1 && sodium_is_zero(ed.k_dev, 32),
              "transport 3.4: epoch with top byte 0x01 returns -1 and init_failed");

        /* A device with the wrong k_dev drops a valid INIT; with the right one it
         * answers. The INIT is built from the right k_dev's k_req, not from
         * either device's own state. */
        uint8_t req[32], resp[32];
        sn_derive_static(sn_want_k_dev, req, resp);
        uint8_t mac[16], in[SN_INIT_LEN];
        sn_init_mac(req, nonce, sn_in_device_id, mac);
        sn_encode_init(nonce, sn_in_device_id, mac, in);
        sn_device right, wrong;
        sn_prefix l4[1];
        v4mapped(l4[0].a16, 192,168,4,1); l4[0].is_v4=1; l4[0].bits=24;
        int init_right = sn_device_init_kdev(&right, sn_want_k_dev, sn_in_device_id, cookie_secret,
                                             admission_epoch, l3, 1, 8000);
        int init_wrong = sn_device_init_kdev(&wrong, sn_want_k_dev_psk2, sn_in_device_id, cookie_secret,
                                             admission_epoch, l4, 1, 8000);
        CHECK(init_right == 0 && init_wrong == 0,
              "init_kdev_wrong_key_drops: both devices initialised");
        CHECK(sn_handle_init(&right, in, SN_INIT_LEN, src, port, 8000, retry) == SN_RETRY_LEN,
              "init_kdev_wrong_key_drops: the right k_dev answers");
        CHECK(sn_handle_init(&wrong, in, SN_INIT_LEN, src, port, 8000, retry) == 0,
              "init_kdev_wrong_key_drops: the wrong k_dev drops");
    }

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all device §6.1 cases pass\n");
    return 0;
}
