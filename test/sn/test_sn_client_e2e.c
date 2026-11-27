/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* End to end: the C client and the C device, full stack, in one process.
 *
 * The other suites each hold one layer still. This holds none of them: a real
 * admission, then real application traffic through the real app layer in both
 * directions, including the paths only volume reaches.
 *
 * The case that matters most here is a message larger than one KCP segment.
 * sn_client's reassembly exists because the session hands over whatever KCP
 * delivered, which is not frame-aligned -- but until this test nothing had ever
 * sent a frame big enough to be split, so the carry buffer was carrying nothing.
 */
#include "shieldnet/sn_agent_dispatch.h"
#include "shieldnet/sn_client.h"
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_source.h"
#include "crypto.h"
#include "lz4.h"
#include "protocol.h"
#include "shieldnet_os.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
#define PORT 5000

static void v4m(uint8_t a[16], uint8_t d) {
    memset(a,0,16); a[10]=0xff; a[11]=0xff; a[12]=192; a[13]=168; a[14]=4; a[15]=d;
}
static void dev_rand(void*c,uint8_t*b,size_t n){(void)c;memset(b,0x42,n);}
static void cli_rand(void*c,uint8_t*b,size_t n){(void)c;memset(b,0x07,n);}

/* A queue each way; both ends are pumped by hand so the ordering is explicit. */
#define QMAX 64
static uint8_t q_dev[QMAX][2048]; static size_t q_dev_len[QMAX]; static int q_dev_n;
static uint8_t q_cli[QMAX][2048]; static size_t q_cli_len[QMAX]; static int q_cli_n;
static void to_dev(void*c,const uint8_t*d,size_t l){(void)c;
    if(q_dev_n<QMAX&&l<=2048){memcpy(q_dev[q_dev_n],d,l);q_dev_len[q_dev_n]=l;q_dev_n++;}}
static void to_cli(void*c,const uint8_t*d,size_t l){(void)c;
    if(q_cli_n<QMAX&&l<=2048){memcpy(q_cli[q_cli_n],d,l);q_cli_len[q_cli_n]=l;q_cli_n++;}}

static sn_device dev;
static sn_prefix local[1];
static sn_agent  ag;
static uint32_t  g_now;
static int       g_bound;

/* The device answers a PING with an ACK, which is all we need to see the app
 * layer working in the device->client direction. */
static int dev_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx;
    return sn_agent_respond(&ag, g_now, kind, body, len);
}

/* What the client decoded. */
static uint8_t last_kind; static uint32_t last_type; static size_t last_len; static int app_count;
static uint8_t last_body[8192];
/* Set to have on_app end the client from inside the callback: 1 closes, 2
 * frees. The obvious "the device said goodbye" handler. */
static sn_client *g_end_me; static int g_end_mode; static int g_ended;
static void on_app(void *ctx, uint32_t message_type, const uint8_t *body, size_t len) {
    (void)ctx;
    last_kind = (uint8_t)message_type; last_type = message_type; last_len = len; app_count++;
    if (len <= sizeof last_body) memcpy(last_body, body, len);
    if (g_end_me) {
        sn_client *c = g_end_me;
        g_end_me = NULL;
        g_ended = 1;
        if (g_end_mode == 1) sn_client_close(c);
        else                 sn_client_free(c);
    }
}

static void make_device(void) {
    memset(PSK,0x11,32);
    uint8_t cs[32]; memset(cs,0x22,32);
    uint8_t ae[8]={0,1,2,3,4,5,6,7};
    v4m(local[0].a16,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&dev, kd, DEVICE_ID,cs,ae,local,1,8000);
    dev.rand_fill=dev_rand;
    sn_device_locks_init(&dev);
    sn_device_set_send(&dev,to_cli,NULL);
    g_bound = 0;
}

/* Loss, for the transport 10.3 cases: how many datagrams each direction still
 * lets through (-1: all), and how many c2s datagrams one pump_device lets
 * through (-1: no limit). What is not let through is dropped. */
static int g_c2s_budget = -1, g_c2s_per_pump = -1, g_s2c_budget = -1;
static int drop_c2s(int i) {
    if (g_c2s_per_pump >= 0 && i >= g_c2s_per_pump) return 1;
    if (g_c2s_budget == 0) return 1;
    if (g_c2s_budget > 0) g_c2s_budget--;
    return 0;
}
static int drop_s2c(void) {
    if (g_s2c_budget == 0) return 1;
    if (g_s2c_budget > 0) g_s2c_budget--;
    return 0;
}

static void pump_device(uint32_t now) {
    uint8_t src[16]; v4m(src,2);
    g_now = now;
    for (int i=0;i<q_dev_n;i++) {
        const uint8_t *d=q_dev[i]; size_t l=q_dev_len[i];
        if (drop_c2s(i)) continue;
        sn_class cls = sn_classify_datagram(SN_ROLE_DEVICE,d,l);
        if (cls==SN_CLASS_INIT) {
            uint8_t r[SN_RETRY_LEN];
            if (sn_handle_init(&dev,d,l,src,PORT,now,r)==SN_RETRY_LEN) to_cli(NULL,r,SN_RETRY_LEN);
        } else if (cls==SN_CLASS_FINISH) {
            uint8_t a[SN_ADMIT_LEN];
            if (sn_handle_finish(&dev,d,l,src,PORT,now,a)==SN_ADMIT_LEN) to_cli(NULL,a,SN_ADMIT_LEN);
        } else {
            sn_handle_envelope(&dev,d,l,src,PORT,now);
        }
    }
    q_dev_n=0;
    sn_primary_update(&dev,now);
}

/* What sn_client_input returned for the datagram whose callback ended it. */
static int g_end_rc;
static void pump_client(sn_client *c, uint32_t now) {
    for (int i=0;i<q_cli_n;i++) {
        if (drop_s2c()) continue;
        int was = g_ended;
        int rc = sn_client_input(c,q_cli[i],q_cli_len[i],now);
        if (!was && g_ended) g_end_rc = rc;
    }
    q_cli_n=0;
}

/* One round: both ends move, and the device's app layer runs once bound. */
static void step(sn_client *c, uint32_t *now, shieldnet_device_ops_t *ops,
                 uint8_t *raw, uint8_t *dec, uint8_t *dcmp, uint8_t *enc) {
    *now += 20;
    pump_device(*now);
    if (!g_bound && dev.primary.active) {
        sn_agent_init(&ag,&dev,ops,raw,8192,dec,8192,dcmp,8192,enc,8192);
        g_bound = 1;
    }
    if (g_bound) { g_now = *now; sn_agent_step(&ag,*now,1); }
    pump_device(*now);
    pump_client(c,*now);
    sn_client_tick(c,*now);
}

/* A fresh device and a client admitted to it, with every queue drained: nothing
 * unacknowledged either way, so the next c2s datagram is the next write. */
static uint8_t s_carry[16384], s_raw[8192], s_dec[8192], s_dcmp[8192], s_enc[8192];
static void open_session(sn_client *cx, uint32_t conv, uint32_t *t, shieldnet_device_ops_t *ops,
                         uint8_t *raw, uint8_t *dec, uint8_t *dcmp, uint8_t *enc) {
    sn_device_release_primary(&dev);
    sn_device_locks_free(&dev);
    make_device();
    q_dev_n = q_cli_n = 0;
    g_c2s_budget = g_c2s_per_pump = g_s2c_budget = -1;
    sn_client_config cf; memset(&cf,0,sizeof cf);
    memcpy(cf.psk,PSK,32); memcpy(cf.device_id,DEVICE_ID,8);
    uint8_t src[16]; v4m(src,2);
    sn_canonical_source(src,PORT,cf.own_source);
    cf.conv = conv; cf.rand_fill = cli_rand;
    sn_client_init(cx,&cf);
    sn_client_set_send(cx,to_dev,NULL);
    sn_client_set_app_buffers(cx,s_carry,sizeof s_carry,s_raw,sizeof s_raw,s_dec,sizeof s_dec,
                              s_dcmp,sizeof s_dcmp,s_enc,sizeof s_enc);
    sn_client_set_on_app(cx,on_app,NULL);
    sn_client_take_control_app(cx,0x07,NULL,0,*t);
    for (int i=0;i<80 && sn_client_get_state(cx)!=SN_CLIENT_ESTABLISHED;i++)
        step(cx,t,ops,raw,dec,dcmp,enc);
    for (int i=0;i<40;i++) step(cx,t,ops,raw,dec,dcmp,enc);
}

int main(void) {
    if (sodium_init()<0) { printf("sodium\n"); return 1; }
    make_device();

    static shieldnet_device_ops_t ops;
    memset(&ops,0,sizeof ops);
    ops.send_response = dev_send_response;
    static uint8_t d_raw[8192], d_dec[8192], d_dcmp[8192], d_enc[8192];

    sn_client_config cfg; memset(&cfg,0,sizeof cfg);
    memcpy(cfg.psk,PSK,32); memcpy(cfg.device_id,DEVICE_ID,8);
    uint8_t src[16]; v4m(src,2);
    sn_canonical_source(src,PORT,cfg.own_source);
    cfg.conv = 0xE2EC11u;
    cfg.rand_fill = cli_rand;

    sn_client c;
    CHECK(sn_client_init(&c,&cfg)==SN_CLIENT_OK,"client init");
    sn_client_set_send(&c,to_dev,NULL);
    static uint8_t carry[16384], c_raw[8192], c_dec[8192], c_dcmp[8192], c_enc[8192];
    sn_client_set_app_buffers(&c,carry,sizeof carry,c_raw,sizeof c_raw,
                              c_dec,sizeof c_dec,c_dcmp,sizeof c_dcmp,c_enc,sizeof c_enc);
    sn_client_set_on_app(&c,on_app,NULL);

    /* Five seconds behind the OS clock: inside KCP's ten-second resync window,
     * so a device write stamped with shieldnet_os_now_ms() instead of this
     * clock would push the next flush seconds past every later update. */
    uint32_t now = shieldnet_os_now_ms() - 5000;
    CHECK(sn_client_take_control_app(&c,0x07,NULL,0,now)==SN_CLIENT_IN_PROGRESS,"take control");
    for (int i=0;i<80 && sn_client_get_state(&c)!=SN_CLIENT_ESTABLISHED;i++)
        step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
    CHECK(sn_client_get_state(&c)==SN_CLIENT_ESTABLISHED,"established end to end");
    /* The ACK leaves at the device's next KCP flush, a step or two later. */
    for (int i=0;i<10;i++) step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
    CHECK(app_count==1 && last_kind==0x80,"the opening PING was answered with an ACK");

    /* ── volume: many small messages, each answered ── */
    {
        int before = app_count;
        int sent = 0;
        for (int i=0;i<20;i++) {
            if (sn_client_send_app(&c,0x07,NULL,0,now)==SN_CS_OK) sent++;
            for (int k=0;k<6;k++) step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        }
        for (int k=0;k<40;k++) step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(sent==20,"20 app messages accepted");
        CHECK(app_count-before==20,"and 20 answers decoded");
    }

    /* ── the path only volume reaches: a frame larger than one KCP segment.
     *
     * KCP's mss here is WIRE_MTU minus the envelope minus its own header, so a
     * 3 KiB body is several segments. The client's reassembly is what makes
     * that arrive as one message; before this case nothing had ever sent a
     * frame big enough to be split, so the carry buffer carried nothing. ── */
    {
        int before = app_count;
        static uint8_t big[3072];
        for (size_t i=0;i<sizeof big;i++) big[i] = (uint8_t)(i*7+3);
        /* Kind 0x20, which the device in this test does not know (an unassigned
         * kind): it answers ERR_UNKNOWN_KIND, and the ACK is what proves the
         * whole 3 KiB frame arrived and reassembled. */
        CHECK(sn_client_send_app(&c,0x20,big,sizeof big,now)==SN_CS_OK,
              "a 3 KiB app message is accepted");
        for (int k=0;k<120 && app_count==before;k++)
            step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(app_count>before,"a multi-segment frame crossed and was answered");
    }

    /* ── device -> client, larger than one segment, exercising the client's
     *    own reassembly rather than the device's ── */
    {
        int before = app_count;
        static uint8_t body[2600];
        for (size_t i=0;i<sizeof body;i++) body[i] = (uint8_t)(i ^ 0x5a);
        /* Let the client acknowledge what the device last sent: sn_agent_respond
         * blocks on a full send queue with nothing pumping, and at a small
         * SN_SEND_QUEUE_MAX the unacknowledged leftovers plus this response
         * do not fit. */
        for (int k=0;k<10;k++) step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(sn_agent_respond(&ag,now,0x84,body,sizeof body)==0,
              "device sends a 2600-byte response");
        for (int k=0;k<120 && app_count==before;k++)
            step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(app_count>before,"client reassembled it");
        CHECK(last_len==sizeof body && memcmp(last_body,body,sizeof body)==0,
              "and every byte survived the trip");
    }

    /* ── message layer 4.1: on_app receives MessageType bits 0-30.
     *
     * No public seal takes a 32-bit type (sn_app_seal takes the kind byte), so
     * the frame is built here the way sn_agent_respond builds one: the next
     * s2c MessageNum from the primary, the 20-byte header as AAD, the body
     * sealed under the counter nonce, header + ciphertext written on the
     * agent's io. ── */
    {
        int before = app_count;
        const uint32_t type = 0x00112281u;
        /* Drain the device's send queue first (see the 2600-byte case). */
        for (int k=0;k<10;k++) step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        static const uint8_t hi[2] = { 'h', 'i' };
        uint8_t ct[2 + CRYPTO_OVERHEAD], nonce[CRYPTO_NONCE_SIZE], aad[PROTOCOL_HEADER_SIZE];
        size_t ol = 0;
        int ok = sn_primary_next_s2c_msgnum(ag.io_st.dev, ag.io_st.gen, &ag.tx.next_msgnum) == 0;
        uint64_t mn = ag.tx.next_msgnum++;
        protocol_nonce_from_msgnum(mn, nonce);
        protocol_marshal_aad((uint32_t)sizeof ct, (uint32_t)sizeof hi, type, mn, aad);
        ok = ok && crypto_encrypt(ag.tx.key, nonce, hi, sizeof hi, aad, sizeof aad, ct, &ol) == 0 &&
             ol == sizeof ct;
        sn_agent_set_now(&ag.io_st, now);
        ok = ok && protocol_write_message(&ag.io, type, mn, ct, (uint32_t)sizeof ct,
                                          (uint32_t)sizeof hi) == 0;
        for (int k=0;k<60 && app_count==before;k++)
            step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        printf("     on_app saw 0x%08x\n", (unsigned)last_type);
        CHECK(ok && app_count == before + 1 && last_type == type && last_len == sizeof hi &&
              memcmp(last_body, hi, sizeof hi) == 0,
              "message layer 4.1: on_app receives bits 0-30");
    }

    /* ── message layer 4.1: a compressed frame's type reaches on_app without
     * bit 31 (PROTOCOL_FLAG_COMPRESSED). Built by hand as above, and the body
     * is compressed here first: sn_app_seal_compressed seals a block that is
     * already LZ4 output. ── */
    {
        int before = app_count;
        const uint32_t type = PROTOCOL_FLAG_COMPRESSED | 0x42u;
        for (int k=0;k<10;k++) step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        uint8_t plain[200]; memset(plain, 'A', sizeof plain);
        uint8_t comp[256];
        int cl = LZ4_compress_default((const char *)plain, (char *)comp, (int)sizeof plain, (int)sizeof comp);
        uint8_t ct[256 + CRYPTO_OVERHEAD], nonce[CRYPTO_NONCE_SIZE], aad[PROTOCOL_HEADER_SIZE];
        size_t ol = 0;
        int ok = cl > 0 && sn_primary_next_s2c_msgnum(ag.io_st.dev, ag.io_st.gen, &ag.tx.next_msgnum) == 0;
        uint64_t mn = ag.tx.next_msgnum++;
        protocol_nonce_from_msgnum(mn, nonce);
        if (ok) {
            protocol_marshal_aad((uint32_t)(cl + CRYPTO_OVERHEAD), (uint32_t)sizeof plain, type, mn, aad);
            ok = crypto_encrypt(ag.tx.key, nonce, comp, (size_t)cl, aad, sizeof aad, ct, &ol) == 0 &&
                 ol == (size_t)(cl + CRYPTO_OVERHEAD);
        }
        sn_agent_set_now(&ag.io_st, now);
        ok = ok && protocol_write_message(&ag.io, type, mn, ct, (uint32_t)(cl + CRYPTO_OVERHEAD),
                                          (uint32_t)sizeof plain) == 0;
        for (int k=0;k<60 && app_count==before;k++)
            step(&c,&now,&ops,d_raw,d_dec,d_dcmp,d_enc);
        printf("     on_app saw 0x%08x, %zu octets\n", (unsigned)last_type, last_len);
        CHECK(ok && app_count == before + 1 && last_type == 0x42u && last_len == sizeof plain &&
              memcmp(last_body, plain, sizeof plain) == 0,
              "message layer 4.1: a compressed frame's type reaches on_app without bit 31");
    }

    /* ── §7.2 liveness: outstanding data plus silence ends the session ── */
    {
        /* A write with nothing answering: SESSION_DEAD_MS later the client must
         * leave ESTABLISHED rather than wait forever for a device that is gone. */
        CHECK(sn_client_send_app(&c,0x07,NULL,0,now)==SN_CS_OK,"a write goes outstanding");
        uint32_t t = now;
        int rc = SN_CLIENT_OK;
        for (int i=0;i<400 && rc==SN_CLIENT_OK;i++) {
            t += 100;                    /* nothing is delivered to the client */
            rc = sn_client_tick(&c,t);
        }
        CHECK(rc==SN_CLIENT_FAILED,"silence with data outstanding ends the session");
        CHECK(sn_client_get_state(&c)==SN_CLIENT_IDLE,"back to IDLE, not wedged");
        CHECK(sn_client_session_dead(&c),"and it reports the session as dead");
        /* The whole point: a client whose device rebooted can re-admit. Before
         * §7.2's rule existed there was no exit from ESTABLISHED at all, and
         * take_control refuses unless IDLE -- so this was unreachable. */
        CHECK(sn_client_take_control_app(&c,0x07,NULL,0,t)==SN_CLIENT_IN_PROGRESS,
              "and a fresh attempt is allowed");
        sn_client_close(&c);
        CHECK(sn_client_get_state(&c)==SN_CLIENT_IDLE,"close returns to IDLE");
    }

    /* ── transport 10.3: data is outstanding until all of it is acknowledged.
     *
     * Every write here is one PIXEL_FRAME (kind 0x00, never answered, so the
     * only s2c traffic is KCP's acknowledgements) that fills exactly one KCP
     * segment: KCP is in stream mode and the device's agent waits on a message
     * it has seen only part of, so a write split across segments would stall
     * it. ── */
    {
        /* (a) the first of three writes is acknowledged, then the device goes
         * silent: the session is dead SESSION_DEAD_MS after that ACK. */
        sn_client ca; uint32_t t = 600000;
        open_session(&ca,0xE2EC31u,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        size_t seg = (size_t)ca.sess.kcp->mss - 36;
        static uint8_t body[2048]; memset(body,0x33,sizeof body);
        int setup = sn_client_get_state(&ca)==SN_CLIENT_ESTABLISHED &&
                    ikcp_waitsnd(ca.sess.kcp)==0 && ca.sess.kcp->ackcount==0;
        for (int i=0;i<3;i++) setup &= sn_client_send_app(&ca,0x00,body,seg,t)==SN_CS_OK;
        g_c2s_budget = 1;                    /* the first write's datagram only */
        uint32_t sent = t;
        for (int i=0;i<50 && (int32_t)(ca.last_rx_ms - sent) <= 0;i++)
            step(&ca,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        uint32_t t_ack = ca.last_rx_ms;
        g_s2c_budget = 0;                    /* and from here the device is silent */
        setup &= (int32_t)(t_ack - sent) > 0 && ikcp_waitsnd(ca.sess.kcp) > 0;
        uint32_t t_end = 0;
        for (int i=0;i<700 && sn_client_get_state(&ca)==SN_CLIENT_ESTABLISHED;i++) {
            step(&ca,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
            if (sn_client_get_state(&ca)!=SN_CLIENT_ESTABLISHED) t_end = t;
        }
        printf("     (a) waitsnd after the ACK > 0: %d; ended %ld ms after it\n", setup,
               t_end ? (long)(t_end - t_ack) : -1L);
        CHECK(setup && t_end != 0 &&
              sn_client_get_end_reason(&ca)==SN_CLIENT_END_DEAD &&
              t_end - t_ack >= SN_SESSION_DEAD_MS && t_end - t_ack <= SN_SESSION_DEAD_MS + 20,
              "transport 10.3: partly acknowledged data goes dead");
        sn_client_free(&ca);
    }
    {
        /* (b) a long transfer acknowledged throughout: the queue stays
         * non-empty at every ACK, one c2s datagram crosses per tick, and the
         * session outlives 2 x SESSION_DEAD_MS from its first write. */
        sn_client cb; uint32_t t = 700000;
        open_session(&cb,0xE2EC32u,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        size_t seg = (size_t)cb.sess.kcp->mss - 36;
        static uint8_t body[2048]; memset(body,0x44,sizeof body);
        int ok = sn_client_get_state(&cb)==SN_CLIENT_ESTABLISHED && ikcp_waitsnd(cb.sess.kcp)==0;
        g_c2s_per_pump = 1;
        uint32_t start = t;
        int writes = 0, acks = 0;
        for (int i=0;i<1100 && (int32_t)(t - start) < (int32_t)(2 * SN_SESSION_DEAD_MS);i++) {
            while (sn_client_send_app(&cb,0x00,body,seg,t)==SN_CS_OK) writes++;
            uint32_t before = cb.last_rx_ms;
            step(&cb,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
            if (cb.last_rx_ms != before && sn_client_get_state(&cb)==SN_CLIENT_ESTABLISHED) {
                acks++;
                if (ikcp_waitsnd(cb.sess.kcp) == 0) ok = 0;   /* the old code's case */
            }
            if (sn_client_get_state(&cb)!=SN_CLIENT_ESTABLISHED) break;
        }
        printf("     (b) %d writes, %d ACKs, %ld ms\n", writes, acks, (long)(t - start));
        CHECK(ok && acks > 0 && writes > 24 && sn_client_get_state(&cb)==SN_CLIENT_ESTABLISHED &&
              (int32_t)(t - start) >= (int32_t)(2 * SN_SESSION_DEAD_MS),
              "transport 10.3: a transfer acknowledged throughout stays up");
        g_c2s_per_pump = -1;
        sn_client_free(&cb);
    }
    {
        /* (c) nothing written, nothing outstanding: idle is not dead. */
        sn_client cc; uint32_t t = 800000;
        open_session(&cc,0xE2EC33u,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        uint32_t start = t;
        for (int i=0;i<1600 && (int32_t)(t - start) < (int32_t)(3 * SN_SESSION_DEAD_MS);i++)
            step(&cc,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(sn_client_get_state(&cc)==SN_CLIENT_ESTABLISHED &&
              (int32_t)(t - start) >= (int32_t)(3 * SN_SESSION_DEAD_MS),
              "transport 10.3: idle with nothing outstanding stays up");
        sn_client_free(&cc);
    }

    /* ── §13 padding: a padded control message is stripped back ── */
    {
        sn_device_release_primary(&dev);
        sn_device_locks_free(&dev);
        make_device();
        q_dev_n = q_cli_n = 0;
        sn_client c6;
        sn_client_config cfg6; memset(&cfg6,0,sizeof cfg6);
        memcpy(cfg6.psk,PSK,32); memcpy(cfg6.device_id,DEVICE_ID,8);
        sn_canonical_source(src,PORT,cfg6.own_source);
        cfg6.conv = 0xE2ECAAu; cfg6.rand_fill = cli_rand;
        sn_client_init(&c6,&cfg6);
        sn_client_set_send(&c6,to_dev,NULL);
        static uint8_t k2[16384], r2[8192], d2[8192], p2[8192], e2[8192];
        sn_client_set_app_buffers(&c6,k2,sizeof k2,r2,sizeof r2,d2,sizeof d2,
                                  p2,sizeof p2,e2,sizeof e2);
        sn_client_set_on_app(&c6,on_app,NULL);
        uint32_t t = 200000;
        CHECK(sn_client_take_control_app_padded(&c6,0x07,NULL,0,t)==SN_CLIENT_IN_PROGRESS,
              "padded take-control starts");
        for (int i=0;i<80 && sn_client_get_state(&c6)!=SN_CLIENT_ESTABLISHED;i++)
            step(&c6,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(sn_client_get_state(&c6)==SN_CLIENT_ESTABLISHED,
              "a padded promoting message admits: the device stripped it");
        int before = app_count;
        CHECK(sn_client_send_app_padded(&c6,0x07,(const uint8_t*)"hi",2,t)==SN_CS_OK,
              "a padded app message is accepted");
        for (int k=0;k<60 && app_count==before;k++)
            step(&c6,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(app_count>before,"and the device answered it");
        sn_client_free(&c6);
    }

    /* ── ending the client from inside on_app ──
     *
     * app_drain used to carry on after the callback: to_idle zeroed carry_len,
     * and the memmove that consumes the frame then ran with carry_len - need
     * wrapped to nearly SIZE_MAX. Two responses are queued back to back so the
     * drain has a second frame waiting when the first one's callback closes.
     * Mode 1 is sn_client_close, mode 2 sn_client_free. */
    for (int mode = 1; mode <= 2; mode++) {
        sn_device_release_primary(&dev);
        sn_device_locks_free(&dev);
        make_device();
        q_dev_n = q_cli_n = 0;
        sn_client c8;
        sn_client_config cfg8; memset(&cfg8,0,sizeof cfg8);
        memcpy(cfg8.psk,PSK,32); memcpy(cfg8.device_id,DEVICE_ID,8);
        sn_canonical_source(src,PORT,cfg8.own_source);
        cfg8.conv = 0xE2EC08u; cfg8.rand_fill = cli_rand;
        sn_client_init(&c8,&cfg8);
        sn_client_set_send(&c8,to_dev,NULL);
        static uint8_t k8[16384], r8[8192], d8[8192], p8[8192], e8[8192];
        sn_client_set_app_buffers(&c8,k8,sizeof k8,r8,sizeof r8,d8,sizeof d8,
                                  p8,sizeof p8,e8,sizeof e8);
        sn_client_set_on_app(&c8,on_app,NULL);
        uint32_t t = 300000 + 100000u * (uint32_t)mode;
        sn_client_take_control_app(&c8,0x07,NULL,0,t);
        for (int i=0;i<80 && sn_client_get_state(&c8)!=SN_CLIENT_ESTABLISHED;i++)
            step(&c8,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(sn_client_get_state(&c8)==SN_CLIENT_ESTABLISHED, "re-entry case established");
        /* Let the opening ACK land first, so the next callback is ours. */
        for (int k=0;k<20;k++) step(&c8,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);

        int before = app_count;
        unsigned gen = c8.gen;
        sn_agent_respond(&ag,t,0x84,(const uint8_t*)"one",3);
        sn_agent_respond(&ag,t,0x84,(const uint8_t*)"two",3);
        g_end_me = &c8; g_end_mode = mode; g_ended = 0; g_end_rc = 0;
        for (int k=0;k<60 && app_count==before;k++)
            step(&c8,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        g_end_me = NULL;
        for (int k=0;k<10;k++) step(&c8,&t,&ops,d_raw,d_dec,d_dcmp,d_enc);
        CHECK(app_count==before+1,
              mode==1 ? "close from on_app: the frame after it is not delivered"
                      : "free from on_app: the frame after it is not delivered");
        CHECK(sn_client_get_state(&c8)==SN_CLIENT_IDLE && c8.gen!=gen && c8.carry_len==0 &&
              !c8.sess_live && c8.sess.kcp==NULL,
              mode==1 ? "close from on_app leaves a clean IDLE client"
                      : "free from on_app leaves a clean IDLE client");
        CHECK(g_ended && g_end_rc==SN_CLIENT_FAILED,
              "and that sn_client_input reported the attempt ended");
        if (mode == 1) {
            CHECK(sn_client_take_control_app(&c8,0x07,NULL,0,t)==SN_CLIENT_IN_PROGRESS,
                  "and the closed client takes control again");
        }
        sn_client_free(&c8);
    }

    sn_client_free(&c);
    sn_device_release_primary(&dev);
    sn_device_locks_free(&dev);
    if (failures) { printf("%d FAILURES\n",failures); return 1; }
    printf("all end-to-end cases pass\n");
    return 0;
}
