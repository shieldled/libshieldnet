/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet on-device performance/bandwidth benchmark.
 *
 * Runs entirely on the ESP32 with no network peer: it exercises the real
 * library (envelope AEAD, admission crypto, KCP, and the full inbound RX path)
 * against an in-process client, and reports throughput/latency over UART. This is
 * the device's *processing ceiling* — the wire will be slower, but this bounds what
 * the CPU can do.
 *
 * Build: source $IDF_PATH/export.sh; idf.py set-target esp32; idf.py build flash monitor
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_task_wdt.h"
#include <sodium.h>

#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_wire.h"
#include "ikcp.h"
/* The library's own Xtensa-tuned ChaCha20, Poly1305 and AEAD (src/arch/), the
 * code sn_wire.c uses on Xtensa, timed against libsodium below. */
#include "arch/sn_aead_xtensa.h"

#define TAG "v3bench"
static uint64_t now_us(void) { return (uint64_t)esp_timer_get_time(); }

/* ── fixed test material ─────────────────────────────────────────────────── */
static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1, 2, 3, 4, 5, 6, 7, 8};

static void v4m(uint8_t a[16], uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    memset(a, 0, 16); a[10] = 0xff; a[11] = 0xff; a[12] = b; a[13] = c; a[14] = d; a[15] = e;
}
static void frand(void *x, uint8_t *b, size_t n) { (void)x; memset(b, 0x42, n); }

/* ── 1. envelope AEAD throughput (the per-byte bandwidth ceiling) ─────────── */
static void bench_aead(void) {
    printf("\n[1] Envelope AEAD (ChaCha20-Poly1305) seal+open throughput\n");
    static uint8_t key[32], msg[1400], env[1500], out[1500];
    memset(key, 0x5A, 32);
    memset(msg, 0x11, sizeof(msg));
    const size_t sizes[] = {64, 256, 1024, 1380};
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        const int iters = 300;
        uint64_t t0 = now_us();
        size_t elen, olen;
        for (int i = 0; i < iters; i++) {
            sn_seal(key, 1, (uint64_t)(i + 1), msg, n, env, &elen);
            sn_open(key, 1, (uint64_t)(i + 1), env, elen, out, &olen);
        }
        uint64_t dt = now_us() - t0;
        vTaskDelay(1); /* let IDLE run: these loops are deliberately CPU-bound */
        double mbps = (double)iters * n / (double)dt; /* bytes/us == MB/s */
        double perop = (double)dt / iters;
        printf("    %4u B: %8.2f MB/s  (%.2f us/seal+open)\n", (unsigned)n, mbps, perop);
    }
}

/* ── 1b. split the AEAD cost: ChaCha20 stream vs Poly1305 MAC vs the AEAD call ── */
static void bench_primitives(void) {
    printf("\n[1b] AEAD component costs at 1024 B\n");
    static uint8_t key[32], nonce[12], msg[1024], out[1024], mac[16];
    memset(key, 0x5A, 32); memset(nonce, 0x11, 12); memset(msg, 0x22, sizeof(msg));
    const int iters = 300;
    uint64_t t0, dt;

    t0 = now_us();
    for (int i = 0; i < iters; i++) {
        crypto_stream_chacha20_ietf_xor(out, msg, sizeof(msg), nonce, key);
    }
    dt = now_us() - t0; vTaskDelay(1);
    printf("    chacha20 xor  : %7.2f us  (%.2f MB/s)\n",
           (double)dt/iters, (double)iters*sizeof(msg)/(double)dt);

    /* our Xtensa-tuned ChaCha20 core, same work as the libsodium call above */
    t0 = now_us();
    for (int i = 0; i < iters; i++) {
        chacha20_xor_opt(key, nonce, 1, msg, sizeof(msg), out);
    }
    dt = now_us() - t0; vTaskDelay(1);
    printf("    chacha20 OPT  : %7.2f us  (%.2f MB/s)\n",
           (double)dt/iters, (double)iters*sizeof(msg)/(double)dt);
    /* correctness: must match libsodium's keystream exactly */
    {
        static uint8_t a[256], b[256], zero[256];
        memset(zero, 0, sizeof(zero));
        crypto_stream_chacha20_ietf_xor_ic(a, zero, sizeof(zero), nonce, 1, key);
        chacha20_xor_opt(key, nonce, 1, zero, sizeof(zero), b);
        printf("    OPT keystream matches libsodium: %s\n",
               memcmp(a, b, sizeof(a)) == 0 ? "YES" : "NO *** MISMATCH ***");
    }

    t0 = now_us();
    for (int i = 0; i < iters; i++) {
        crypto_onetimeauth_poly1305(mac, msg, sizeof(msg), key);
    }
    dt = now_us() - t0; vTaskDelay(1);
    printf("    poly1305      : %7.2f us  (%.2f MB/s)\n",
           (double)dt/iters, (double)iters*sizeof(msg)/(double)dt);

    t0 = now_us();
    for (int i = 0; i < iters; i++) {
        poly1305_opt(mac, msg, sizeof(msg), key);
    }
    dt = now_us() - t0; vTaskDelay(1);
    printf("    poly1305 OPT  : %7.2f us  (%.2f MB/s)\n",
           (double)dt/iters, (double)iters*sizeof(msg)/(double)dt);
    {
        uint8_t a[16], b[16];
        crypto_onetimeauth_poly1305(a, msg, sizeof(msg), key);
        poly1305_opt(b, msg, sizeof(msg), key);
        printf("    OPT poly1305 matches libsodium: %s\n",
               memcmp(a, b, 16) == 0 ? "YES" : "NO *** MISMATCH ***");
    }

    unsigned long long clen = 0;
    t0 = now_us();
    for (int i = 0; i < iters; i++) {
        crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, msg, sizeof(msg) - 16,
                                                  NULL, 0, NULL, nonce, key);
    }
    dt = now_us() - t0; vTaskDelay(1);
    printf("    aead encrypt  : %7.2f us  (%.2f MB/s)\n",
           (double)dt/iters, (double)iters*(sizeof(msg)-16)/(double)dt);

    /* the full optimized AEAD, same construction */
    {
        static uint8_t ct[1024], tag[16], ad[4] = {1,2,3,4};
        t0 = now_us();
        for (int i = 0; i < iters; i++) {
            aead_opt_encrypt(ct, tag, msg, sizeof(msg), ad, 4, nonce, key);
        }
        dt = now_us() - t0; vTaskDelay(1);
        printf("    aead OPT enc  : %7.2f us  (%.2f MB/s)\n",
               (double)dt/iters, (double)iters*sizeof(msg)/(double)dt);
        /* correctness vs libsodium detached, and round-trip */
        static uint8_t lct[1024], ltag[16], back[1024];
        unsigned long long ltl = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt_detached(lct, ltag, &ltl, msg,
                sizeof(msg), ad, 4, NULL, nonce, key);
        int ok_ct  = memcmp(ct, lct, sizeof(msg)) == 0;
        int ok_tag = memcmp(tag, ltag, 16) == 0;
        int ok_rt  = aead_opt_decrypt(back, ct, sizeof(msg), tag, ad, 4, nonce, key) == 0
                     && memcmp(back, msg, sizeof(msg)) == 0;
        printf("    OPT AEAD vs libsodium: ct=%s tag=%s roundtrip=%s\n",
               ok_ct?"OK":"BAD", ok_tag?"OK":"BAD", ok_rt?"OK":"BAD");
    }
}

/* ── 1c. candidate AEADs: what could replace ChaCha20-Poly1305 on this part? ──
 * The ESP32 has a hardware AES accelerator but no ChaCha hardware. mbedtls 4.x
 * exposes crypto through PSA, which routes AES to that hardware. Measure before
 * proposing any protocol change. NOTE: the ESP32 has no GCM acceleration (only the
 * P4 does), so AES-GCM here is HW-AES + software GHASH. */
#include "psa/crypto.h"

static void psa_aead_bench(const char *label, psa_algorithm_t alg,
                           psa_key_type_t ktype, size_t kbits) {
    static uint8_t msg[1024], out[1088];
    memset(msg, 0x22, sizeof(msg));
    uint8_t key[32]; memset(key, 0x5A, sizeof(key));
    uint8_t nonce[12]; memset(nonce, 0x11, sizeof(nonce));

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_type(&attr, ktype);
    psa_set_key_bits(&attr, kbits);
    psa_key_id_t kid = 0;
    if (psa_import_key(&attr, key, kbits / 8, &kid) != PSA_SUCCESS) {
        printf("    %-22s: unavailable\n", label);
        return;
    }
    const int iters = 300;
    size_t olen = 0;
    uint64_t t0 = now_us();
    for (int i = 0; i < iters; i++) {
        psa_aead_encrypt(kid, alg, nonce, sizeof(nonce), NULL, 0,
                         msg, sizeof(msg), out, sizeof(out), &olen);
    }
    uint64_t dt = now_us() - t0;
    vTaskDelay(1);
    psa_destroy_key(kid);
    printf("    %-22s: %7.2f us  (%.2f MB/s)\n", label,
           (double)dt / iters, (double)iters * sizeof(msg) / (double)dt);
}

static void bench_alternatives(void) {
    printf("\n[1c] Alternative AEADs at 1024 B (encrypt)\n");
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("    psa_crypto_init failed\n");
        return;
    }
    psa_aead_bench("AES-128-GCM [HW AES]", PSA_ALG_GCM, PSA_KEY_TYPE_AES, 128);
    psa_aead_bench("AES-256-GCM [HW AES]", PSA_ALG_GCM, PSA_KEY_TYPE_AES, 256);
    psa_aead_bench("AES-128-CCM [HW AES]", PSA_ALG_CCM, PSA_KEY_TYPE_AES, 128);
    psa_aead_bench("AES-256-CCM [HW AES]", PSA_ALG_CCM, PSA_KEY_TYPE_AES, 256);
    psa_aead_bench("ChaCha20-Poly1305(SW)", PSA_ALG_CHACHA20_POLY1305,
                   PSA_KEY_TYPE_CHACHA20, 256);
}

/* ── 0. golden-vector gate: sn_seal/sn_open (now the Xtensa AEAD) must still
 * produce exactly what the §15 vectors and libsodium say. */
static void bench_vectors(void) {
    printf("\n[0] Envelope correctness with the Xtensa AEAD path\n");
    uint8_t key[32], msg[300], env[512], back[512], lenv[512];
    size_t elen = 0, blen = 0, llen = 0;
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 7 + 3);

    int all_ok = 1;
    for (int c2s = 0; c2s <= 1; c2s++) {
        for (size_t n = 0; n <= sizeof(msg); n += 97) {
            uint64_t seq = 1 + n + (uint64_t)c2s * 1000;
            if (sn_seal(key, c2s, seq, msg, n, env, &elen) != 0) { all_ok = 0; continue; }
            /* libsodium reference for the same input */
            uint8_t nonce[12], sw[4], tag[16];
            unsigned long long tl = 0;
            memset(nonce, 0, 12);
            memcpy(nonce, c2s ? "C2S" : "S2C", 3);
            for (int b = 0; b < 8; b++) nonce[4 + b] = (uint8_t)(seq >> (56 - 8 * b));
            uint32_t sq = (uint32_t)seq;
            sw[0]=(uint8_t)(sq>>24); sw[1]=(uint8_t)(sq>>16); sw[2]=(uint8_t)(sq>>8); sw[3]=(uint8_t)sq;
            crypto_aead_chacha20poly1305_ietf_encrypt_detached(lenv, tag, &tl, msg, n,
                                                               sw, 4, NULL, nonce, key);
            memcpy(lenv + n, sw, 4);
            memcpy(lenv + n + 4, tag, 16);
            llen = n + 20;
            if (elen != llen || memcmp(env, lenv, elen) != 0) all_ok = 0;
            if (sn_open(key, c2s, seq, env, elen, back, &blen) != 0) all_ok = 0;
            if (blen != n || (n && memcmp(back, msg, n) != 0)) all_ok = 0;
        }
    }
    /* a tampered tag must fail */
    sn_seal(key, 1, 42, msg, 64, env, &elen);
    env[elen - 1] ^= 0x01;
    if (sn_open(key, 1, 42, env, elen, back, &blen) == 0) all_ok = 0;

    printf("    seal/open vs libsodium over sizes+directions, tamper-reject: %s\n",
           all_ok ? "ALL OK" : "*** FAILURE ***");
}

/* ── 2. admission crypto (X25519 DH + the §4.5 key schedule) ──────────────── */
static void bench_admission_crypto(void) {
    printf("\n[2] Admission crypto: X25519 DH + §4.5 derivation (per FINISH)\n");
    uint8_t kd[32], kr[32], ks[32];
    sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_derive_static(kd, kr, ks);
    uint8_t es_priv[32], es_pub[32], ec_pub[32];
    memset(es_priv, 0x07, 32); crypto_scalarmult_base(es_pub, es_priv);
    memset(ec_pub, 0x09, 32);  /* a peer public */
    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t etag[8] = {0}, cookie[16] = {0}, ae[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    const int iters = 20;
    uint64_t t0 = now_us();
    for (int i = 0; i < iters; i++) {
        uint8_t ctx[65]; sn_context(nonce, etag, cookie, ae, DEVICE_ID, ctx);
        uint8_t dh[32];
        if (sn_dh(es_priv, ec_pub, dh) != 0) { /* accept low-order for timing */ }
        uint8_t c2[129]; sn_context2(ctx, ec_pub, es_pub, c2);
        uint8_t master[32]; sn_master(c2, kd, dh, master);
        uint8_t a1[32], a2[32], a3[32], a4[32]; sn_session_keys(master, a1, a2, a3, a4);
        uint8_t atag[16]; sn_admit_tag(master, atag);
    }
    uint64_t dt = now_us() - t0;
    vTaskDelay(1);
    printf("    %.1f us/admission  (~%.0f admissions/s)\n",
           (double)dt / iters, 1e6 * iters / (double)dt);
}

/* ── 3. replay window test-and-mark ──────────────────────────────────────── */
static void bench_replay(void) {
    printf("\n[3] Replay window test-and-mark\n");
    sn_replay_window w; memset(&w, 0, sizeof(w));
    const int iters = 20000;
    uint64_t t0 = now_us();
    for (int i = 0; i < iters; i++) sn_replay_test_and_mark(&w, (uint64_t)(i + 1));
    uint64_t dt = now_us() - t0;
    vTaskDelay(1);
    printf("    %.3f Mops/s  (%.3f us/op)\n", (double)iters / (double)dt, (double)dt / iters);
}

/* ── 4. full inbound RX throughput (demux + AEAD open + replay + KCP) ─────── */
/* A full bidirectional in-process loop: the client streams c2s to the device,
 * the device processes it AND ACKs over s2c, and those ACKs are routed back to the
 * client so its send window keeps opening — otherwise it stalls after rcv_wnd. */
static uint8_t g_kc2s[32];      /* client seals c2s under this */
static sn_sender g_seq;         /* client's c2s seq */
static uint8_t g_env[2048];     /* client's last sealed c2s datagram */
static size_t g_envlen;
static ikcpcb *g_client;        /* the client KCP, for s2c ACK routing */
static uint8_t g_kks2c[32];     /* client opens s2c under this */
static sn_replay_window g_s2cw; /* client's s2c replay window */

static int cli_out(const char *buf, int len, ikcpcb *k, void *u) {
    (void)k; (void)u;
    uint64_t s; sn_sender_alloc(&g_seq, &s);
    size_t o; sn_seal(g_kc2s, 1, s, (const uint8_t *)buf, (size_t)len, g_env, &o);
    g_envlen = o;
    return 0;
}

/* device send sink: the device's s2c datagrams (ACKs) — open under k_kcp_s2c and
 * feed the client so its window advances. */
static void dev_s2c_sink(void *ctx, const uint8_t *buf, size_t len) {
    (void)ctx;
    uint8_t pt[1600]; size_t pl; uint64_t seq;
    if (g_client && sn_replay_open(&g_s2cw, g_kks2c, 0, buf, len, pt, &pl, &seq)) {
        ikcp_input(g_client, (const char *)pt, (long)pl);
    }
}

static void bench_inbound(void) {
    printf("\n[4] Full inbound RX: demux + AEAD open + replay + ikcp_input + recv\n");
    sn_device dev; sn_prefix loc[1];
    v4m(loc[0].a16, 192, 168, 4, 1); loc[0].is_v4 = 1; loc[0].bits = 24;
    uint8_t cs[32]; memset(cs, 0x22, 32); uint8_t ae[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint8_t kdev[32]; sn_derive_kdev(PSK, DEVICE_ID, kdev); /* the device holds k_dev, never the PSK */
    if (sn_device_init_kdev(&dev, kdev, DEVICE_ID, cs, ae, loc, 1, shieldnet_os_now_ms64()) != 0) {
        printf("    sn_device_init_kdev failed\n");
        return;
    }
    dev.rand_fill = frand;
    sn_device_locks_init(&dev);
    sn_device_set_send(&dev, dev_s2c_sink, NULL);
    { /* large window so throughput reflects the crypto ceiling, not rcv_wnd=8 */
        sn_kcp_tuning t = SN_KCP_TUNING_DEFAULT;
        t.snd_wnd = 64; t.rcv_wnd = 64; t.interval = 10; /* ESP32-sized (§11) */
        sn_device_set_tuning(&dev, t);
    }

    uint8_t nonce[24]; memset(nonce, 0xAB, 24);
    uint8_t src[16]; v4m(src, 192, 168, 4, 2);
    /* admission */
    uint8_t init[SN_INIT_LEN], mac[16];
    sn_init_mac(dev.k_req, nonce, DEVICE_ID, mac);
    sn_encode_init(nonce, DEVICE_ID, mac, init);
    uint8_t r[SN_RETRY_LEN];
    sn_handle_init(&dev, init, SN_INIT_LEN, src, 5000, 8000, r);
    uint8_t ecp[32]; memset(ecp, 7, 32); uint8_t ecpub[32]; crypto_scalarmult_base(ecpub, ecp);
    uint8_t kd[32], kr[32], krs[32]; sn_derive_kdev(PSK, DEVICE_ID, kd); sn_derive_static(kd, kr, krs);
    uint8_t ctx[65]; sn_context(nonce, r + 10, r + 18, r + 34, DEVICE_ID, ctx);
    uint8_t ct[16]; sn_client_tag(kr, ctx, ecpub, ct);
    uint8_t fin[SN_FINISH_LEN]; sn_encode_finish(nonce, r + 10, r + 18, r + 34, ecpub, ct, fin);
    uint8_t adm[SN_ADMIT_LEN]; sn_handle_finish(&dev, fin, SN_FINISH_LEN, src, 5000, 8000, adm);
    uint8_t c2[129]; sn_context2(ctx, ecpub, adm + 18, c2);
    uint8_t dh[32]; sn_dh(ecp, adm + 18, dh);
    uint8_t master[32]; sn_master(c2, kd, dh, master);
    uint8_t a1[32], a2[32], kkc2s[32], kks2c[32]; sn_session_keys(master, a1, a2, kkc2s, kks2c);
    memcpy(g_kc2s, kkc2s, 32); memcpy(g_kks2c, kks2c, 32); sn_sender_init(&g_seq);
    memset(&g_s2cw, 0, sizeof(g_s2cw));
    /* client ikcp + promote */
    ikcpcb *ck = ikcp_create(0xABCD1234u, NULL);
    g_client = ck;
    ikcp_setoutput(ck, cli_out); ikcp_setmtu(ck, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    ikcp_nodelay(ck, 1, 10, 2, 1); ck->stream = 1;
    ikcp_wndsize(ck, 64, 64);
    const char *first = "go";
    ikcp_send(ck, first, 2); ikcp_update(ck, 1000);
    if (sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8100) != SN_ENV_PROMOTED) {
        printf("    PROMOTION FAILED — skipping\n");
        goto done;
    }
    g_envlen = 0;
    uint8_t drain[1500]; sn_primary_recv(&dev, drain, sizeof(drain));

    /* Pump a stream client->device. Each virtual-clock tick: the client may emit a
     * c2s segment (fed to the device), the device is updated to flush its ACKs
     * (routed back to the client by dev_s2c_sink), and the client is updated to
     * consume ACKs and open its window. Measures the device's full RX-path bytes/s. */
    const size_t MSG = 1024;
    static uint8_t payload[1024];
    memset(payload, 0x5A, MSG);
    const int msgs = 400;
    const uint64_t target = (uint64_t)msgs * MSG;
    uint32_t t = 8100;
    uint64_t bytes = 0;
    uint64_t t0 = now_us();
    int sent = 0;
    uint64_t t_cli = 0, t_dev = 0, t_upd = 0, n_env = 0;
    int iters_run = 0;
    for (int i = 0; i < 200000 && bytes < target; i++) {
        iters_run++;
        if ((i & 0x3ff) == 0) vTaskDelay(1); /* feed the watchdog */
        /* keep the client's send queue fed but bounded (window-limited) */
        if (sent < msgs && ikcp_waitsnd(ck) < 48) {
            if (ikcp_send(ck, (const char *)payload, (int)MSG) < 0) break; /* OOM */
            sent++;
        }
        t += 10; /* == the KCP interval: every pass can emit */
        uint64_t m0 = now_us();
        ikcp_update(ck, t);                 /* client emits (into g_env) */
        uint64_t m1 = now_us();
        if (g_envlen > 0) {
            size_t e = g_envlen; g_envlen = 0;
            n_env++;
            sn_handle_envelope(&dev, g_env, e, src, 5000, t); /* device RX + input */
            int got; while ((got = sn_primary_recv(&dev, drain, sizeof(drain))) > 0) bytes += got;
        }
        uint64_t m2 = now_us();
        sn_primary_update(&dev, t);         /* device flushes ACKs -> dev_s2c_sink -> client */
        uint64_t m3 = now_us();
        t_cli += m1 - m0; t_dev += m2 - m1; t_upd += m3 - m2;
    }
    uint64_t dt = now_us() - t0;
    printf("    processed %llu KB in %.1f ms => %.2f MB/s (inbound app payload,\n"
           "              full RX path incl. AEAD open + KCP reliability)\n",
           (unsigned long long)(bytes / 1024), dt / 1000.0, (double)bytes / (double)dt);
    printf("    loop iters=%d  datagrams=%llu  |  client_update %.1f ms  device_rx %.1f ms"
           "  device_update %.1f ms\n",
           iters_run, (unsigned long long)n_env,
           t_cli / 1000.0, t_dev / 1000.0, t_upd / 1000.0);
    if (n_env) {
        printf("    per-datagram: device_rx %.1f us\n", (double)t_dev / n_env);
        /* The wall-clock figure above is dominated by the virtual-clock stepping of
         * this in-process simulation (KCP only emits once per `interval`), NOT by
         * the device. The honest number is the device's own RX work: */
        printf("    DEVICE RX THROUGHPUT: %.2f MB/s (%llu B of payload in %.1f ms of\n"
               "              actual sn_handle_envelope + recv work)\n",
               (double)bytes / (double)t_dev, (unsigned long long)bytes, t_dev / 1000.0);
    }
    g_client = NULL;
    ikcp_release(ck);
done:
    if (dev.primary.active) ikcp_release(dev.primary.kcp);
    sn_device_locks_free(&dev);
}

void app_main(void) {
    if (sodium_init() < 0) { printf("sodium_init failed\n"); return; }
    memset(PSK, 0x11, 32);
    printf("\n=== ShieldNet on-device benchmark ===\n");
    printf("CPU: %d MHz, %d cores\n", (int)(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ),
           (int)portNUM_PROCESSORS);
    bench_vectors();
    bench_aead();
    bench_primitives();
    bench_alternatives();
    bench_admission_crypto();
    bench_replay();
    bench_inbound();
    printf("\n=== done ===\n");
    for (;;) vTaskDelay(pdMS_TO_TICKS(10000));
}
