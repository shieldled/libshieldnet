/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Host benchmark for the C client. The device already has one on hardware
 * (shieldled_esp32/benchmark/shieldnet-esp32); this is the client half, on the
 * machine a controller actually runs on.
 *
 * What it measures, and why each is here:
 *   admission   — one X25519 plus the §4.5 schedule. This is what a reconnect
 *                 costs, and a controller talking to many devices pays it per
 *                 device, so it bounds how fast a fleet comes up.
 *   RETRY/ADMIT — the §7.3/§7.4 checks. An attacker can make a client run these
 *                 at line rate, which is why §7.4 puts admit_pre before the
 *                 X25519 and requires the dh cache; both effects are visible
 *                 here as separate numbers.
 *   app frame   — seal and open at four sizes, the per-message floor.
 *   round trip  — the whole stack against a real device in-process: what an
 *                 application actually gets.
 */
#include "shieldnet/sn_app_frame.h"
#include "shieldnet/sn_client.h"
#include "shieldnet/sn_client_wire.h"
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_source.h"
#include "shieldnet_os.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
#define PORT 5000

static void v4m(uint8_t a[16], uint8_t d) {
    memset(a,0,16); a[10]=0xff; a[11]=0xff; a[12]=192; a[13]=168; a[14]=4; a[15]=d;
}
static void frand(void*c,uint8_t*b,size_t n){(void)c;memset(b,0x42,n);}
static void crand(void*c,uint8_t*b,size_t n){(void)c;memset(b,0x07,n);}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static void report(const char *name, double secs, long iters, size_t bytes) {
    double per = secs / (double)iters;
    if (bytes) {
        printf("  %-34s %9.2f us/op  %8.2f MB/s\n", name, per * 1e6,
               (double)bytes * (double)iters / secs / 1e6);
    } else {
        printf("  %-34s %9.2f us/op  %10.0f op/s\n", name, per * 1e6, 1.0 / per);
    }
}

/* ── shared fixtures ─────────────────────────────────────────────────── */
static uint8_t q_dev[64][2048]; static size_t q_dev_len[64]; static int q_dev_n;
static uint8_t q_cli[64][2048]; static size_t q_cli_len[64]; static int q_cli_n;
static void to_dev(void*c,const uint8_t*d,size_t l){(void)c;
    if(q_dev_n<64&&l<=2048){memcpy(q_dev[q_dev_n],d,l);q_dev_len[q_dev_n]=l;q_dev_n++;}}
static void to_cli(void*c,const uint8_t*d,size_t l){(void)c;
    if(q_cli_n<64&&l<=2048){memcpy(q_cli[q_cli_n],d,l);q_cli_len[q_cli_n]=l;q_cli_n++;}}
static void on_app(void*c,uint32_t k,const uint8_t*b,size_t l){(void)c;(void)k;(void)b;(void)l;}

static void make_device(sn_device *d, sn_prefix *local) {
    memset(PSK,0x11,32);
    uint8_t cs[32]; memset(cs,0x22,32);
    uint8_t ae[8]={0,1,2,3,4,5,6,7};
    v4m(local[0].a16,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(d, kd, DEVICE_ID,cs,ae,local,1,8000);
    d->rand_fill=frand;
    sn_device_locks_init(d);
    sn_device_set_send(d,to_cli,NULL);
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }
    printf("ShieldNet C client benchmark (host)\n");
    printf("===================================\n");

    sn_device dev; sn_prefix local[1];
    make_device(&dev, local);
    uint8_t src[16]; v4m(src,2);
    uint8_t own_cs[18]; sn_canonical_source(src,PORT,own_cs);

    uint8_t nonce[24]; memset(nonce,0xAB,24);
    uint8_t ec_priv[32]; memset(ec_priv,0x07,32);
    uint8_t e_c[32]; crypto_scalarmult_base(e_c,ec_priv);
    uint8_t k_dev[32],k_req[32],k_resp[32];
    sn_derive_kdev(PSK,DEVICE_ID,k_dev);
    sn_derive_static(k_dev,k_req,k_resp);

    /* One real RETRY and ADMIT to check against. */
    uint8_t init[SN_INIT_LEN], mac[16];
    sn_init_mac(k_req,nonce,DEVICE_ID,mac);
    sn_encode_init(nonce,DEVICE_ID,mac,init);
    uint8_t retry[SN_RETRY_LEN];
    sn_handle_init(&dev,init,SN_INIT_LEN,src,PORT,8000,retry);
    uint8_t context[65];
    sn_context(nonce,retry+10,retry+18,retry+34,DEVICE_ID,context);
    uint8_t ctag[16]; sn_client_tag(k_req,context,e_c,ctag);
    uint8_t fin[SN_FINISH_LEN];
    sn_encode_finish(nonce,retry+10,retry+18,retry+34,e_c,ctag,fin);
    uint8_t admit[SN_ADMIT_LEN];
    sn_handle_finish(&dev,fin,SN_FINISH_LEN,src,PORT,8000,admit);

    sn_retry_msg rm; sn_decode_retry(retry,SN_RETRY_LEN,&rm);
    sn_admit_msg am; sn_decode_admit(admit,SN_ADMIT_LEN,&am);

    printf("\n[1] Client receive checks (§7.3, §7.4)\n");
    {
        long n = 200000;
        double t0 = now_s();
        for (long i=0;i<n;i++) {
            sn_retry_msg m; sn_decode_retry(retry,SN_RETRY_LEN,&m);
            sn_check_retry(&m,k_resp,nonce,own_cs,DEVICE_ID);
        }
        report("RETRY decode + §7.3 checks", now_s()-t0, n, 0);
    }
    {
        /* The uncached path: this is what a client pays per forged ADMIT
         * without §7.4's dh cache. */
        long n = 20000;
        uint8_t master[32];
        double t0 = now_s();
        for (long i=0;i<n;i++) sn_check_admit(&am,k_dev,k_resp,context,rm.admission_epoch,
                                              e_c,ec_priv,master);
        report("ADMIT checks, X25519 each time", now_s()-t0, n, 0);
    }
    {
        /* With the cache: the X25519 is gone and only the HMACs remain, which
         * is the whole point of the requirement. */
        long n = 200000;
        uint8_t dh[32]; sn_dh(ec_priv,am.e_s,dh);
        uint8_t master[32];
        double t0 = now_s();
        for (long i=0;i<n;i++) sn_check_admit_dh(&am,k_dev,k_resp,context,rm.admission_epoch,
                                                 e_c,dh,master);
        report("ADMIT checks, dh cached (§7.4)", now_s()-t0, n, 0);
    }
    {
        /* A forgery that fails admit_pre never reaches the X25519 at all. */
        long n = 200000;
        sn_admit_msg bad = am; bad.admit_pre[0] ^= 1;
        uint8_t master[32];
        double t0 = now_s();
        for (long i=0;i<n;i++) sn_check_admit(&bad,k_dev,k_resp,context,rm.admission_epoch,
                                              e_c,ec_priv,master);
        report("ADMIT forgery rejected at admit_pre", now_s()-t0, n, 0);
    }

    printf("\n[2] App frame seal and open\n");
    {
        static uint8_t body[1400], enc[2048], dec[2048], decomp[2048];
        memset(body,0x5a,sizeof body);
        const size_t sizes[] = { 64, 256, 1024, 1400 };
        for (size_t s = 0; s < 4; s++) {
            sn_app_tx tx; sn_app_tx_init(&tx,k_dev,enc,sizeof enc);
            long n = 200000;
            char label[64];
            snprintf(label,sizeof label,"seal %4zu B",sizes[s]);
            uint32_t ty,orig; uint64_t mn; size_t ol;
            double t0 = now_s();
            for (long i=0;i<n;i++) sn_app_seal(&tx,0x07,body,sizes[s],&ty,&mn,&orig,&ol);
            report(label, now_s()-t0, n, sizes[s]);

            /* Open the last one repeatedly: rebuilding rx each time keeps the
             * strictly-increasing MessageNum check from rejecting the replay. */
            sn_app_tx tx2; sn_app_tx_init(&tx2,k_dev,enc,sizeof enc);
            sn_app_seal(&tx2,0x07,body,sizes[s],&ty,&mn,&orig,&ol);
            protocol_msg_header_t hdr = { .size=(uint32_t)ol, .original_size=orig,
                                          .message_type=ty, .message_num=mn };
            snprintf(label,sizeof label,"open %4zu B",sizes[s]);
            const uint8_t *pl; size_t pll;
            t0 = now_s();
            for (long i=0;i<n;i++) {
                sn_app_rx rx; sn_app_rx_init(&rx,k_dev,dec,sizeof dec,decomp,sizeof decomp);
                sn_app_open(&rx,&hdr,enc,&pl,&pll);
            }
            report(label, now_s()-t0, n, sizes[s]);
        }
    }

    printf("\n[3] Full stack against a real device, in process\n");
    {
        sn_device_locks_free(&dev);
        make_device(&dev, local);
        q_dev_n = q_cli_n = 0;

        sn_client_config cfg; memset(&cfg,0,sizeof cfg);
        memcpy(cfg.psk,PSK,32); memcpy(cfg.device_id,DEVICE_ID,8);
        memcpy(cfg.own_source,own_cs,18);
        cfg.conv = 0xBEEFu; cfg.rand_fill = crand;
        sn_client c;
        sn_client_init(&c,&cfg);
        sn_client_set_send(&c,to_dev,NULL);
        static uint8_t carry[16384], raw[8192], dec[8192], dcmp[8192], enc[8192];
        sn_client_set_app_buffers(&c,carry,sizeof carry,raw,sizeof raw,
                                  dec,sizeof dec,dcmp,sizeof dcmp,enc,sizeof enc);
        sn_client_set_on_app(&c,on_app,NULL);

        uint32_t t = 100000;
        double t0 = now_s();
        sn_client_take_control_app(&c,0x07,NULL,0,t);
        /* Drive the admission to completion. */
        for (int i=0;i<80 && sn_client_get_state(&c)!=SN_CLIENT_ESTABLISHED;i++) {
            t += 20;
            uint8_t s2[16]; v4m(s2,2);
            for (int k2=0;k2<q_dev_n;k2++) {
                const uint8_t *d=q_dev[k2]; size_t l=q_dev_len[k2];
                sn_class cls = sn_classify_datagram(SN_ROLE_DEVICE,d,l);
                if (cls==SN_CLASS_INIT) { uint8_t r[SN_RETRY_LEN];
                    if (sn_handle_init(&dev,d,l,s2,PORT,t,r)==SN_RETRY_LEN) to_cli(NULL,r,SN_RETRY_LEN); }
                else if (cls==SN_CLASS_FINISH) { uint8_t a[SN_ADMIT_LEN];
                    if (sn_handle_finish(&dev,d,l,s2,PORT,t,a)==SN_ADMIT_LEN) to_cli(NULL,a,SN_ADMIT_LEN); }
                else sn_handle_envelope(&dev,d,l,s2,PORT,t);
            }
            q_dev_n = 0;
            sn_primary_update(&dev,t);
            for (int k2=0;k2<q_cli_n;k2++) sn_client_input(&c,q_cli[k2],q_cli_len[k2],t);
            q_cli_n = 0;
            sn_client_tick(&c,t);
        }
        double admit_s = now_s() - t0;
        if (sn_client_get_state(&c) == SN_CLIENT_ESTABLISHED) {
            printf("  %-34s %9.2f us      (one X25519 + §4.5)\n",
                   "admission, client side", admit_s * 1e6);
        } else {
            printf("  admission did not complete\n");
        }

        /* Client -> device application throughput. */
        static uint8_t body[1024];
        memset(body,0x33,sizeof body);
        long sent = 0, n = 20000;
        t0 = now_s();
        for (long i=0;i<n;i++) {
            if (sn_client_send_app(&c,0x07,body,sizeof body,t) != SN_CS_OK) {
                /* §9.5's cap: drain and continue, which is what a real caller
                 * does rather than treating backpressure as an error. */
                t += 20;
                uint8_t s2[16]; v4m(s2,2);
                for (int k2=0;k2<q_dev_n;k2++)
                    sn_handle_envelope(&dev,q_dev[k2],q_dev_len[k2],s2,PORT,t);
                q_dev_n = 0;
                sn_primary_update(&dev,t);
                uint8_t got[2048];
                while (sn_primary_recv(&dev,got,(int)sizeof got) > 0) { }
                continue;
            }
            sent++;
        }
        double secs = now_s() - t0;
        /* This figure includes the §9.5 drain cycles above, which is the point:
         * it is what an application sending flat out actually gets, not the
         * seal cost from [2]. The two differ by nearly three orders of
         * magnitude, and quoting the seal rate as throughput would be a lie. */
        report("send_app 1024 B incl. §9.5 drain", secs, sent ? sent : 1, sizeof body);
    }

    sn_device_locks_free(&dev);
    printf("\ndone\n");
    return 0;
}
