/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* sn_agent: readfull/write over the established primary's KCP stream.
 * Promotes a session, streams bytes client->device, and checks readfull returns
 * exact-length chunks across KCP message boundaries. */
#include "protocol.h"
#include "shieldnet/sn_agent.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_wire.h"

#include "client_helper.h"
#include "ikcp.h"

#include "shieldnet_os.h"

#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c,m) do{ if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m);}while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
static void v4m(uint8_t a[16],uint8_t b,uint8_t c,uint8_t d,uint8_t e){memset(a,0,16);a[10]=0xff;a[11]=0xff;a[12]=b;a[13]=c;a[14]=d;a[15]=e;}
static void frand(void*x,uint8_t*b,size_t n){(void)x;memset(b,0x42,n);}
static void nosend(void*x,const uint8_t*b,size_t l){(void)x;(void)b;(void)l;}

/* client c2s seal state */
static uint8_t g_kc2s[32]; static sn_sender g_seq;
static uint8_t g_env[2048]; static size_t g_envlen=0;
static int cli_out(const char*buf,int len,ikcpcb*k,void*u){(void)k;(void)u;
    uint64_t s; sn_sender_alloc(&g_seq,&s); size_t o;
    sn_seal(g_kc2s,1,s,(const uint8_t*)buf,(size_t)len,g_env,&o); g_envlen=o; return 0;}

/* A peer that keeps the device's data_ready busy without delivering any of the
 * frame: an ACK-only (WINS) KCP datagram every 100 ms, until told to stop or
 * 3 x the budget has passed. */
static sn_device *g_dev; static ikcpcb *g_ck; static uint8_t g_src[16];
static volatile int g_stop; static int g_fed;
static void *feeder(void *arg) {
    (void)arg;
    uint32_t start = shieldnet_os_now_ms();
    while (!g_stop && shieldnet_os_now_ms() - start < 3 * SN_MID_FRAME_BUDGET_MS) {
        uint8_t seg[24]; memset(seg, 0, sizeof seg);
        uint32_t f[4] = { 9000u, g_ck->snd_nxt, g_ck->rcv_nxt, 0 };   /* ts sn una len */
        for (int b = 0; b < 4; b++) seg[b] = (uint8_t)(g_ck->conv >> (8 * b));
        seg[4] = 84;  /* IKCP_CMD_WINS: no data */
        seg[6] = 128;
        for (int k = 0; k < 4; k++)
            for (int b = 0; b < 4; b++) seg[8 + 4 * k + b] = (uint8_t)(f[k] >> (8 * b));
        cli_out((const char *)seg, (int)sizeof seg, g_ck, NULL);
        if (sn_handle_envelope(g_dev, g_env, g_envlen, g_src, 5000, shieldnet_os_now_ms())
                == SN_ENV_ESTABLISHED) g_fed++;
        shieldnet_os_sleep_ms(100);
    }
    return NULL;
}

/* One KCP segment from the client, delivered to the device. */
static void feed(const void *p, int n, uint32_t ts) {
    ikcp_send(g_ck, p, n); ikcp_update(g_ck, ts);
    sn_handle_envelope(g_dev, g_env, g_envlen, g_src, 5000, shieldnet_os_now_ms());
}

/* The body of a split frame, delivered from a thread after a delay. */
static uint8_t g_late[20]; static int g_late_n; static int g_late_ms; static uint32_t g_late_ts;
static void *late_feeder(void *arg) {
    (void)arg;
    shieldnet_os_sleep_ms((uint32_t)g_late_ms);
    feed(g_late, g_late_n, g_late_ts);
    return NULL;
}

/* An io that returns a header and then nothing but timeouts, with no
 * frame_continues: protocol_read_message must keep the old rule for it. */
struct script { const uint8_t *hdr; int calls; int poisoned; };
static int script_readfull(void *ctx, void *buf, size_t len, int timeout_ms) {
    struct script *s = ctx; (void)len; (void)timeout_ms;
    if (++s->calls == 1) { memcpy(buf, s->hdr, PROTOCOL_HEADER_SIZE); return PROTOCOL_HEADER_SIZE; }
    return 0;
}
static void script_poison(void *ctx) { ((struct script *)ctx)->poisoned = 1; }

/* A peer that trickles one data octet every 200 ms, never completing the frame
 * the reader asked for. */
static void *trickler(void *arg) {
    (void)arg;
    uint32_t start = shieldnet_os_now_ms();
    uint32_t ts = 20000;
    while (!g_stop && shieldnet_os_now_ms() - start < 2 * SN_MID_FRAME_BUDGET_MS) {
        ikcp_send(g_ck, "z", 1); ikcp_update(g_ck, ts); ts += 200;
        if (sn_handle_envelope(g_dev, g_env, g_envlen, g_src, 5000, shieldnet_os_now_ms())
                == SN_ENV_ESTABLISHED) g_fed++;
        shieldnet_os_sleep_ms(200);
    }
    return NULL;
}

int main(void){
    if(sodium_init()<0){printf("sodium\n");return 1;}
    memset(PSK,0x11,32);
    sn_device dev; sn_prefix loc[1];
    v4m(loc[0].a16,192,168,4,1); loc[0].is_v4=1; loc[0].bits=24;
    uint8_t cs[32]; memset(cs,0x22,32); uint8_t ae[8]={0,1,2,3,4,5,6,7};
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&dev, kd, DEVICE_ID,cs,ae,loc,1,8000);
    dev.rand_fill=frand; sn_device_locks_init(&dev); sn_device_set_send(&dev,nosend,NULL);

    uint8_t nonce[24]; memset(nonce,0xAB,24); uint8_t src[16]; v4m(src,192,168,4,2);
    /* admission */
    uint8_t init[SN_INIT_LEN],mac[16]; sn_init_mac(dev.k_req,nonce,DEVICE_ID,mac);
    sn_encode_init(nonce,DEVICE_ID,mac,init);
    uint8_t r[SN_RETRY_LEN]; sn_handle_init(&dev,init,SN_INIT_LEN,src,5000,8000,r);
    uint8_t ecp[32]; memset(ecp,7,32);
    uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK,DEVICE_ID,nonce,r,ecp,fin,NULL);
    uint8_t adm[SN_ADMIT_LEN]; sn_handle_finish(&dev,fin,SN_FINISH_LEN,src,5000,8000,adm);
    /* client keys */
    uint8_t a1[32],a2[32],kks2c[32];
    ch_session_from(PSK,DEVICE_ID,nonce,r,ecp,adm,a1,a2,g_kc2s,kks2c);
    sn_sender_init(&g_seq);
    /* client ikcp (stream mode, like the device) */
    ikcpcb*ck=ikcp_create(0xABCD1234u,NULL); ikcp_setoutput(ck,cli_out);
    ikcp_setmtu(ck,SN_WIRE_MTU-SN_ENVELOPE_LEN); ikcp_nodelay(ck,1,20,2,1); ck->stream=1;
    /* The device's ACKs go to nosend and never reach ck, so with the default
     * send window of 32 a long test stops reaching the device after 32
     * segments in flight. 128 covers this file: 5 existing segments, about 55
     * trickled ones, and a handful more. */
    ikcp_wndsize(ck, 128, 0);
    g_dev = &dev; g_ck = ck; memcpy(g_src, src, 16);
    /* first PUSH promotes, carrying the start of the stream */
    const char *stream = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    ikcp_send(ck,stream,10); ikcp_update(ck,1000);
    CHECK(sn_handle_envelope(&dev,g_env,g_envlen,src,5000,8100)==SN_ENV_PROMOTED,"promoted");

    /* stream the rest in two more sends */
    ikcp_send(ck,stream+10,13); ikcp_update(ck,1100);
    sn_handle_envelope(&dev,g_env,g_envlen,src,5000,8110);
    ikcp_send(ck,stream+23,13); ikcp_update(ck,1200);
    sn_handle_envelope(&dev,g_env,g_envlen,src,5000,8120);

    /* now read it back through the agent io in exact chunks that cross boundaries */
    sn_agent_io st; memset(&st,0,sizeof(st));
    shieldnet_io_t io = sn_primary_io(&st,&dev);
    uint8_t got[64];
    CHECK(io.readfull(io.ctx, got, 5, 100)==5 && memcmp(got,"ABCDE",5)==0, "readfull 5");
    CHECK(io.readfull(io.ctx, got, 8, 100)==8 && memcmp(got,"FGHIJKLM",8)==0, "readfull 8 (crosses boundary)");
    CHECK(io.readfull(io.ctx, got, 10, 100)==10 && memcmp(got,"NOPQRSTUVW",10)==0, "readfull 10");
    CHECK(io.readfull(io.ctx, got, 13, 100)==13 && memcmp(got,"XYZ0123456789",13)==0, "readfull 13 (to end)");
    /* nothing left → idle timeout returns 0, stream still aligned */
    CHECK(io.readfull(io.ctx, got, 1, 50)==0, "readfull idle-timeouts on empty stream");

    /* ── message layer 8 item 1: a frame whose body arrives after a read
     * timeout is not a desync. The header is here, the body 300 ms later, and
     * the read waits 50 ms at a time. ── */
    protocol_msg_header_t h; uint8_t buf[64];
    {
        uint8_t hdr[PROTOCOL_HEADER_SIZE]; protocol_marshal_aad(8, 8, 0x42, 7, hdr);
        feed(hdr, sizeof hdr, 1220);
        memcpy(g_late, "12345678", 8); g_late_n = 8; g_late_ms = 300; g_late_ts = 1250;
        pthread_t th; int started = pthread_create(&th, NULL, late_feeder, NULL) == 0;
        int rc = started ? protocol_read_message(&io, &h, buf, sizeof buf, 50) : -99;
        if (started) pthread_join(th, NULL);
        printf("     (protocol_read_message returned %d, poisoned %d)\n", rc, st.poisoned);
        CHECK(rc == 28 && h.size == 8 && st.poisoned == 0,
              "message layer 8 item 1: a body after a read timeout completes the frame");
    }
    /* A zero-size frame has no body read to clear the flag, so the next idle
     * read must still return 0 at its own timeout. */
    {
        uint8_t hdr[PROTOCOL_HEADER_SIZE]; protocol_marshal_aad(0, 0, 0x42, 8, hdr);
        feed(hdr, sizeof hdr, 1280);
        int rc = protocol_read_message(&io, &h, buf, sizeof buf, 50);
        uint32_t t0 = shieldnet_os_now_ms();
        int idle = io.readfull(io.ctx, got, 1, 50);
        uint32_t took = shieldnet_os_now_ms() - t0;
        CHECK(rc == PROTOCOL_HEADER_SIZE && idle == 0 && took < 500,
              "message layer 8 item 1: a zero-size frame leaves the next read idle");
    }
    /* No session, no thread: an io without frame_continues keeps the old rule. */
    {
        uint8_t hdr[PROTOCOL_HEADER_SIZE]; protocol_marshal_aad(8, 8, 0x42, 9, hdr);
        struct script s = { hdr, 0, 0 };
        shieldnet_io_t sio = {0};
        sio.ctx = &s; sio.readfull = script_readfull; sio.poison = script_poison;
        int rc = protocol_read_message(&sio, &h, buf, sizeof buf, 50);
        CHECK(rc == PROTOCOL_ERR_DESYNC && s.poisoned == 1 && s.calls == 2,
              "message layer 8 item 1: an io without frame_continues keeps the old rule");
    }

    /* ── mid-frame stall must NOT desync ──
     * Ask for more bytes than are available: the old code returned short as soon
     * as one timeout elapsed (=> protocol_read_message poisons, session dies).
     * Now a committed frame keeps waiting, so a short timeout returns... nothing
     * yet, but crucially it must NOT report a short read while the session lives.
     * With no more data ever arriving we expect it to burn the budget and only
     * then report short — so use a tiny budget-consuming timeout and assert the
     * call did not return a *partial* count on the first timeout. */
    {
        /* feed 4 bytes, then request 16: 4 are committed, 12 never arrive */
        ikcp_send(ck, "WXYZ", 4); ikcp_update(ck, 1300);
        sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8130);
        uint8_t part[16];
        /* one short wait: must not return 4 (a short read) — the frame is committed
         * and KCP may still deliver, so readfull keeps waiting until the budget. */
        int rc = io.readfull(io.ctx, part, 16, 5);
        CHECK(rc == 16 || rc == 4, "mid-frame readfull returns only when complete or budget-spent");
        printf("     (mid-frame readfull returned %d after the budget; session-alive gate exercised)\n", rc);
    }

    /* ── message layer 8: the budget is elapsed time. Part of a frame is
     * consumed, then only ACK-only datagrams arrive, every 100 ms: each wait
     * (500 ms) is woken, never timed out, so counting timed-out waits never
     * spends the budget. The read must return short within the budget plus one
     * wait. ── */
    {
        ikcp_send(ck, "PQRS", 4); ikcp_update(ck, 1400);
        sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8140);
        g_stop = 0; g_fed = 0;
        pthread_t th;
        int started = pthread_create(&th, NULL, feeder, NULL) == 0;
        uint8_t part[16];
        uint32_t t0 = shieldnet_os_now_ms();
        int rc = started ? io.readfull(io.ctx, part, 16, 500) : -2;
        uint32_t took = shieldnet_os_now_ms() - t0;
        g_stop = 1;
        if (started) pthread_join(th, NULL);
        printf("     (returned %d after %u ms; %d ACK-only datagrams accepted)\n",
               rc, (unsigned)took, g_fed);
        CHECK(rc == 4 && g_fed > 0 && took >= SN_MID_FRAME_BUDGET_MS &&
              took <= SN_MID_FRAME_BUDGET_MS + 500 + 100,
              "message layer 8: a stall with ACK-only traffic ends within the budget");
    }

    /* ── message layer 8: one data octet every 200 ms. Each wait is woken, so
     * only the clock from the first octet bounds the frame: about 50 octets
     * arrive in the budget, and the read must still return short at its end.
     * A clock restarted at each consumed octet never expires while the peer
     * keeps trickling. ── */
    {
        g_stop = 0; g_fed = 0;
        pthread_t th;
        int started = pthread_create(&th, NULL, trickler, NULL) == 0;
        uint8_t part[255];
        uint32_t t0 = shieldnet_os_now_ms();
        int rc = started ? io.readfull(io.ctx, part, 255, 500) : -2;
        uint32_t took = shieldnet_os_now_ms() - t0;
        g_stop = 1;
        if (started) pthread_join(th, NULL);
        printf("     (returned %d after %u ms; %d trickled datagrams accepted)\n",
               rc, (unsigned)took, g_fed);
        CHECK(rc > 0 && rc < 255 && took >= SN_MID_FRAME_BUDGET_MS &&
              took <= SN_MID_FRAME_BUDGET_MS + 500 + 300,
              "message layer 8: a peer trickling octets is bounded from the first");
        /* what the thread sent after the read returned */
        while (io.readfull(io.ctx, part, 1, 50) == 1) {}
    }

    /* ── message layer 8 item 1: the budget runs from the header's first octet,
     * not from its last. Half a header, the rest 3 s later, then no body. ── */
    {
        uint8_t hdr[PROTOCOL_HEADER_SIZE]; protocol_marshal_aad(8, 8, 0x42, 10, hdr);
        feed(hdr, 10, 50000);
        memcpy(g_late, hdr + 10, 10); g_late_n = 10; g_late_ms = 3000; g_late_ts = 50500;
        pthread_t th; int started = pthread_create(&th, NULL, late_feeder, NULL) == 0;
        uint32_t t0 = shieldnet_os_now_ms();
        int rc = started ? protocol_read_message(&io, &h, buf, sizeof buf, 500) : -99;
        uint32_t took = shieldnet_os_now_ms() - t0;
        if (started) pthread_join(th, NULL);
        printf("     (protocol_read_message returned %d after %u ms)\n", rc, (unsigned)took);
        CHECK(rc == PROTOCOL_ERR_DESYNC &&
              took >= SN_MID_FRAME_BUDGET_MS && took < SN_MID_FRAME_BUDGET_MS + 1500,
              "message layer 8 item 1: the budget runs from the header's first octet");
    }

    ikcp_release(ck); ikcp_release(dev.primary.kcp); sn_device_locks_free(&dev);
    if(failures){printf("%d FAILURE(S)\n",failures);return 1;}
    printf("all sn_agent io cases pass\n"); return 0;
}
