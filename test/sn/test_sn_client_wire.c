/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §3.5 / §7.3 / §7.4 client receive path.
 *
 * No golden vector covers a rejection, so every rejection path gets its own
 * case here. The admissions are built with client_helper.h and then corrupted
 * one field at a time, which is exactly why that helper stays test-local: the
 * client's own API must never offer a way to build these. */
#include "shieldnet/sn_client_wire.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_source.h"

#include "client_helper.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
static const uint16_t PORT = 5000;

static void v4mapped(uint8_t a[16], uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    memset(a, 0, 16); a[10]=0xff; a[11]=0xff; a[12]=b; a[13]=c; a[14]=d; a[15]=e;
}
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

int main(void) {
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }

    sn_device dev; sn_prefix local[1]; make_device(&dev, local);
    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16];   v4mapped(src, 192,168,4,2);
    uint8_t own_cs[18]; sn_canonical_source(src, PORT, own_cs);

    uint8_t k_dev[32], k_req[32], k_resp[32];
    ch_static_keys(PSK, DEVICE_ID, k_dev, k_req, k_resp);

    uint8_t init[SN_INIT_LEN]; ch_init(PSK, DEVICE_ID, nonce, init);
    uint8_t retry[SN_RETRY_LEN];
    CHECK(sn_handle_init(&dev, init, SN_INIT_LEN, src, PORT, 8000, retry) == SN_RETRY_LEN,
          "device produced RETRY");

    /* ── §3.5: length before any field ───────────────────────────────── */
    sn_retry_msg rm;
    CHECK(sn_decode_retry(retry, SN_RETRY_LEN, &rm) == SN_CW_OK, "RETRY decodes");
    /* The datagram §3.5 names: MAGIC||0x02||0x03, 10 octets. Reading
     * observed_source at 50 and retry_mac at 68 would run ~70 past the end. */
    uint8_t stub[10]; memcpy(stub, retry, 10); stub[9] = 0x03;
    CHECK(sn_decode_retry(stub, sizeof stub, &rm) == SN_CW_BAD_LEN,
          "10-octet RETRY refused on length, not version");
    CHECK(sn_decode_retry(retry, SN_RETRY_LEN - 1, &rm) == SN_CW_BAD_LEN, "short RETRY refused");
    CHECK(sn_decode_retry(retry, SN_RETRY_LEN + 1, &rm) == SN_CW_BAD_LEN, "long RETRY refused");
    {
        uint8_t bad[SN_RETRY_LEN]; memcpy(bad, retry, sizeof bad); bad[0] ^= 1;
        CHECK(sn_decode_retry(bad, sizeof bad, &rm) == SN_CW_BAD_HEADER, "bad magic refused");
        /* Type and version are reported apart from a bad magic, as Go does:
         * "not for me" and "I do not speak this" are different answers. */
        memcpy(bad, retry, sizeof bad); bad[8] = 0x06;
        CHECK(sn_decode_retry(bad, sizeof bad, &rm) == SN_CW_BAD_TYPE, "wrong type refused");
        memcpy(bad, retry, sizeof bad); bad[9] = 0x02;
        CHECK(sn_decode_retry(bad, sizeof bad, &rm) == SN_CW_BAD_TYPE, "wrong version refused");
    }

    /* ── §7.3 steps 2-4 ──────────────────────────────────────────────── */
    sn_decode_retry(retry, SN_RETRY_LEN, &rm);
    CHECK(sn_check_retry(&rm, k_resp, nonce, own_cs, DEVICE_ID) == SN_CW_OK, "RETRY accepted");
    {
        uint8_t other_cs[18]; sn_canonical_source(src, (uint16_t)(PORT + 1), other_cs);
        CHECK(sn_check_retry(&rm, k_resp, nonce, other_cs, DEVICE_ID) == SN_CW_BAD_SOURCE,
              "observed_source mismatch refused (step 2)");
    }
    {
        sn_retry_msg t = rm; t.retry_mac[0] ^= 1;
        CHECK(sn_check_retry(&t, k_resp, nonce, own_cs, DEVICE_ID) == SN_CW_BAD_MAC,
              "forged retry_mac refused (step 3)");
    }
    {
        /* A field covered by the MAC: the MAC check must fire first. */
        sn_retry_msg t = rm; t.cookie[0] ^= 1;
        CHECK(sn_check_retry(&t, k_resp, nonce, own_cs, DEVICE_ID) == SN_CW_BAD_MAC,
              "tampered cookie caught by the MAC");
    }
    {
        /* A RETRY genuinely from a sibling device: its own device_id, MAC'd
         * under its own k_resp. Our k_resp cannot verify it, so step 3 stops
         * it and step 4 never runs -- which is what makes step 4 "defence in
         * depth" rather than the only thing tying a RETRY to the device we
         * addressed. */
        uint8_t other[8]; memcpy(other, DEVICE_ID, 8); other[0] ^= 1;
        uint8_t o_dev[32], o_req[32], o_resp[32];
        ch_static_keys(PSK, other, o_dev, o_req, o_resp);
        sn_retry_msg t = rm; memcpy(t.device_id, other, 8);
        sn_retry_mac(o_resp, nonce, t.epoch_tag, t.cookie, t.admission_epoch,
                     other, t.observed_source, t.retry_mac);
        CHECK(sn_check_retry(&t, k_resp, nonce, own_cs, DEVICE_ID) == SN_CW_BAD_MAC,
              "sibling's RETRY fails our k_resp at step 3");

        /* And step 4 is what catches the case the MAC no longer covers: the
         * MAC is computed over the device_id we ADDRESSED, so an on-path
         * attacker can rewrite the wire field of a genuine RETRY without
         * breaking it. Step 3 passes; step 4 is the only thing left. */
        sn_retry_msg t2 = rm;
        t2.device_id[0] ^= 1;
        CHECK(sn_check_retry(&t2, k_resp, nonce, own_cs, DEVICE_ID) == SN_CW_BAD_DEVICE_ID,
              "a rewritten device_id on a genuine RETRY is refused (step 4)");
    }

    /* ── §7.4: drive a real ADMIT ────────────────────────────────────── */
    uint8_t ec_priv[32]; memset(ec_priv, 0x07, 32);
    uint8_t e_c[32]; crypto_scalarmult_base(e_c, ec_priv);
    uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK, DEVICE_ID, nonce, retry, ec_priv, fin, NULL);
    uint8_t admit[SN_ADMIT_LEN];
    CHECK(sn_handle_finish(&dev, fin, SN_FINISH_LEN, src, PORT, 8000, admit) == SN_ADMIT_LEN,
          "device produced ADMIT");

    uint8_t context[65];
    sn_context(nonce, rm.epoch_tag, rm.cookie, rm.admission_epoch, DEVICE_ID, context);

    sn_admit_msg am;
    CHECK(sn_decode_admit(admit, SN_ADMIT_LEN, &am) == SN_CW_OK, "ADMIT decodes");
    CHECK(sn_decode_admit(admit, 10, &am) == SN_CW_BAD_LEN, "10-octet ADMIT refused");
    CHECK(sn_decode_admit(admit, SN_ADMIT_LEN - 1, &am) == SN_CW_BAD_LEN, "short ADMIT refused");
    sn_decode_admit(admit, SN_ADMIT_LEN, &am);

    uint8_t master[32];
    CHECK(sn_check_admit(&am, k_dev, k_resp, context, rm.admission_epoch,
                         e_c, ec_priv, master) == SN_CW_OK, "ADMIT accepted");
    {
        /* The client's master must equal the device's session keys. */
        uint8_t c2s[32], s2c[32], kc[32], ks[32];
        sn_session_keys(master, c2s, s2c, kc, ks);
        uint8_t hc2s[32], hs2c[32], hkc[32], hks[32];
        ch_session_from(PSK, DEVICE_ID, nonce, retry, ec_priv, admit, hc2s, hs2c, hkc, hks);
        CHECK(memcmp(c2s, hc2s, 32) == 0 && memcmp(ks, hks, 32) == 0,
              "master agrees with the helper's derivation");
    }
    {
        sn_admit_msg t = am; t.admission_epoch[0] ^= 1;
        uint8_t m[32];
        CHECK(sn_check_admit(&t, k_dev, k_resp, context, rm.admission_epoch,
                             e_c, ec_priv, m) == SN_CW_BAD_EPOCH, "wrong epoch refused (step 2)");
    }
    {
        sn_admit_msg t = am; t.admit_pre[0] ^= 1;
        uint8_t m[32];
        CHECK(sn_check_admit(&t, k_dev, k_resp, context, rm.admission_epoch,
                             e_c, ec_priv, m) == SN_CW_BAD_PRE, "forged admit_pre refused (step 3)");
    }
    {
        /* The replay §7.4 warns about: a genuine ADMIT with one flipped tag
         * octet. admit_pre still verifies, so only step 4 catches it. */
        sn_admit_msg t = am; t.admit_tag[15] ^= 1;
        uint8_t m[32];
        CHECK(sn_check_admit(&t, k_dev, k_resp, context, rm.admission_epoch,
                             e_c, ec_priv, m) == SN_CW_BAD_TAG, "flipped admit_tag refused (step 4)");
        CHECK(sodium_is_zero(m, 32), "master wiped on the failure path");
    }
    {
        /* A low-order e_s. admit_pre covers e_s, so it must be recomputed for
         * this to reach step 4 at all -- which is the point: the DH check is
         * not reachable by tampering alone. */
        sn_admit_msg t = am; memset(t.e_s, 0, 32);
        uint8_t c2[129]; sn_context2(context, e_c, t.e_s, c2);
        sn_admit_pre(k_resp, c2, t.admit_pre);
        uint8_t m[32];
        CHECK(sn_check_admit(&t, k_dev, k_resp, context, rm.admission_epoch,
                             e_c, ec_priv, m) == SN_CW_BAD_POINT, "low-order e_s refused (step 4)");
        CHECK(sodium_is_zero(m, 32), "master wiped after a rejected point");
    }

    {
        /* Ordering, not just outcome: §7.4 puts admit_pre before the X25519 so a
         * forged ADMIT costs an HMAC rather than a scalar multiplication. An
         * ADMIT that would fail BOTH must report the cheap check, or the order
         * has been inverted. */
        sn_admit_msg t = am; memset(t.e_s, 0, 32); t.admit_pre[0] ^= 1;
        uint8_t m[32];
        CHECK(sn_check_admit(&t, k_dev, k_resp, context, rm.admission_epoch,
                             e_c, ec_priv, m) == SN_CW_BAD_PRE,
              "admit_pre is checked before the X25519");
    }
    {
        /* The cached-dh entry point agrees with the computing one. */
        uint8_t dh[32];
        CHECK(sn_dh(ec_priv, am.e_s, dh) == 0, "dh for the cache");
        uint8_t m1[32], m2[32];
        sn_cw_result r1 = sn_check_admit(&am, k_dev, k_resp, context, rm.admission_epoch,
                                         e_c, ec_priv, m1);
        sn_cw_result r2 = sn_check_admit_dh(&am, k_dev, k_resp, context, rm.admission_epoch,
                                            e_c, dh, m2);
        CHECK(r1 == SN_CW_OK && r2 == SN_CW_OK && memcmp(m1, m2, 32) == 0,
              "cached-dh path agrees with the computing path");
    }

    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("all §3.5/§7.3/§7.4 client receive cases pass\n");
    return 0;
}
