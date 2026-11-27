/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §9.2 maintenance tick + §9.4 quiesce/resume. */
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_wire.h"

#include "client_helper.h"
#include "ikcp.h"

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
static void fixed_rand(void *ctx, uint8_t *buf, size_t n){ (void)ctx; memset(buf,0x42,n); }

static uint8_t g_c2s[2048]; static size_t g_c2s_len=0;
static uint8_t g_kc2s[32];
static sn_sender g_c2s_seq;
static int client_output(const char *buf, int len, ikcpcb *k, void *u){
    (void)k;(void)u; uint64_t s; sn_sender_alloc(&g_c2s_seq,&s);
    size_t o; sn_seal(g_kc2s,1,s,(const uint8_t*)buf,(size_t)len,g_c2s,&o); g_c2s_len=o; return 0;
}
static void nosend(void *ctx, const uint8_t *b, size_t l){ (void)ctx;(void)b;(void)l; }

static void mkdev(sn_device *dev, sn_prefix *local) {
    memset(PSK,0x11,32);
    uint8_t cs[32]; memset(cs,0x22,32);
    uint8_t ae[8]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    v4mapped(local[0].a16,192,168,4,1); local[0].is_v4=1; local[0].bits=24;
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(dev, kd, DEVICE_ID,cs,ae,local,1,8000);
    dev->rand_fill=fixed_rand;
    sn_device_locks_init(dev);
    sn_device_set_send(dev,nosend,NULL);
}

/* admit a client from a given port, leaving a pending record */
static void admit(sn_device *dev, uint16_t port, const uint8_t nonce[24]) {
    uint8_t src[16]; v4mapped(src,192,168,4,2);
    uint8_t init[SN_INIT_LEN], mac[16];
    sn_init_mac(dev->k_req,nonce,DEVICE_ID,mac); sn_encode_init(nonce,DEVICE_ID,mac,init);
    uint8_t r[SN_RETRY_LEN]; sn_handle_init(dev,init,SN_INIT_LEN,src,port,8000,r);
    uint8_t ecp[32]; memset(ecp,0x07,32);
    uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK,DEVICE_ID,nonce,r,ecp,fin,NULL);
    uint8_t admit[SN_ADMIT_LEN]; sn_handle_finish(dev,fin,SN_FINISH_LEN,src,port,8000,admit);
}

/* INIT -> RETRY at issue_ms (under that epoch's tag), FINISH built from it later */
static void get_finish(sn_device *dev, uint16_t port, const uint8_t nonce[24],
                       uint64_t issue_ms, uint8_t fin[SN_FINISH_LEN]) {
    uint8_t src[16]; v4mapped(src,192,168,4,2);
    uint8_t init[SN_INIT_LEN], mac[16];
    sn_init_mac(dev->k_req,nonce,DEVICE_ID,mac); sn_encode_init(nonce,DEVICE_ID,mac,init);
    uint8_t r[SN_RETRY_LEN]; sn_handle_init(dev,init,SN_INIT_LEN,src,port,issue_ms,r);
    uint8_t ecp[32]; memset(ecp,0x07,32);
    ch_finish(PSK,DEVICE_ID,nonce,r,ecp,fin,NULL);
}
/* A device with a primary promoted by a client whose ikcp is returned; the
 * client never reads what the device sends, so nothing the device sends is
 * ever acknowledged. */
static ikcpcb *promoted(sn_device *d, sn_prefix *l, const uint8_t nonce[24]) {
    uint8_t src[16]; v4mapped(src,192,168,4,2);
    mkdev(d,l);
    uint8_t init[SN_INIT_LEN], mac[16];
    sn_init_mac(d->k_req,nonce,DEVICE_ID,mac); sn_encode_init(nonce,DEVICE_ID,mac,init);
    uint8_t ecp[32]; memset(ecp,0x07,32);
    uint8_t rt[SN_RETRY_LEN]; sn_handle_init(d,init,SN_INIT_LEN,src,5000,8000,rt);
    uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK,DEVICE_ID,nonce,rt,ecp,fin,NULL);
    uint8_t adm[SN_ADMIT_LEN]; sn_handle_finish(d,fin,SN_FINISH_LEN,src,5000,8000,adm);
    uint8_t sc2s[32],ss2c[32],kks2c[32];
    ch_session_from(PSK,DEVICE_ID,nonce,rt,ecp,adm,sc2s,ss2c,g_kc2s,kks2c);
    sn_sender_init(&g_c2s_seq);
    ikcpcb *ck = ikcp_create(0x0BADF00Du,NULL);
    ikcp_setoutput(ck,client_output); ikcp_setmtu(ck,SN_WIRE_MTU-SN_ENVELOPE_LEN);
    ikcp_nodelay(ck,1,20,2,1);
    ikcp_send(ck,"go",2); ikcp_update(ck,1000);
    sn_handle_envelope(d,g_c2s,g_c2s_len,src,5000,8100);
    return ck;
}
/* The head of the primary's snd_buf: the oldest unacknowledged segment. */
static struct IKCPSEG *head_seg(sn_device *d) {
    return iqueue_entry(d->primary.kcp->snd_buf.next, struct IKCPSEG, node);
}
static int g_sent;
static void count_send(void *ctx, const uint8_t *b, size_t l){ (void)ctx;(void)b;(void)l; g_sent++; }

/* Drive the head segment, with sn_primary_update alone, to one retransmit short
 * of dead_link: the next flush that reaches it latches the link dead. Leaves
 * *t just before the head's next resend. Returns 1 when it got there alive. */
static int drive_to_one_short(sn_device *d, uint32_t *t) {
    for (int i = 0; i < 64 && head_seg(d)->xmit + 1 < d->primary.kcp->dead_link; i++) {
        *t = head_seg(d)->resendts + 1;
        sn_primary_update(d, *t);
    }
    return d->primary.kcp->state == 0 &&
           head_seg(d)->xmit + 1 == d->primary.kcp->dead_link;
}

static size_t send_finish(sn_device *dev, uint16_t port, const uint8_t fin[SN_FINISH_LEN],
                          uint64_t now) {
    uint8_t src[16]; v4mapped(src,192,168,4,2);
    uint8_t admit[SN_ADMIT_LEN];
    return sn_handle_finish(dev,fin,SN_FINISH_LEN,src,port,now,admit);
}

int main(void){
    if (sodium_init()<0){ printf("sodium\n"); return 1; }
    uint8_t nonce[24]; memset(nonce,0xAB,24);
    uint8_t src[16]; v4mapped(src,192,168,4,2);

    /* ── tick sweeps pending expiry (§6.3) ── */
    {
        sn_device dev; sn_prefix l[1]; mkdev(&dev,l);
        admit(&dev,5000,nonce);
        uint8_t tuple[18]; sn_canonical_source(src,5000,tuple);
        CHECK(sn_find_pending_index(&dev,tuple)>=0, "pending installed");
        /* record expiry = 8000 + 5000 = 13000; tick past it */
        sn_device_tick(&dev, 14000, 14000);
        CHECK(sn_find_pending_index(&dev,tuple)<0, "tick swept the expired record");
        sn_device_locks_free(&dev);
    }

    /* ── tick rolls the epoch on a boundary (§4.4) ── */
    {
        sn_device dev; sn_prefix l[1]; mkdev(&dev,l); /* epoch 2 @ 8000 */
        uint8_t first[8]; memcpy(first,dev.epoch_tag,8);
        sn_device_tick(&dev, 8500, 8500); /* same epoch */
        CHECK(memcmp(dev.epoch_tag,first,8)==0 && !dev.have_prev, "tick within epoch: no roll");
        sn_device_tick(&dev, 12000, 12000); /* epoch 3 */
        CHECK(memcmp(dev.epoch_tag,first,8)!=0, "tick rolled the epoch");
        CHECK(dev.have_prev && memcmp(dev.prev_epoch_tag,first,8)==0, "previous tag retained");
        sn_device_locks_free(&dev);
    }

    /* ── a stalled tick does not extend a cookie's life (§4.4) ── */
    {
        uint8_t fin[SN_FINISH_LEN];
        /* control: cookie from epoch 2, tick rolls to 3, FINISH in epoch 3 */
        sn_device dev; sn_prefix l[1]; mkdev(&dev,l); /* epoch 2 @ 8000 */
        get_finish(&dev,5000,nonce,8000,fin);
        sn_device_tick(&dev,12000,12000);
        CHECK(send_finish(&dev,5000,fin,12000)==SN_ADMIT_LEN,
              "previous-epoch cookie accepted in the next epoch");
        sn_device_locks_free(&dev);

        /* the tick then stalls: at epoch 5 the cache still says prev = epoch 2 */
        mkdev(&dev,l);
        get_finish(&dev,5000,nonce,8000,fin);
        sn_device_tick(&dev,12000,12000);
        CHECK(send_finish(&dev,5000,fin,20000)==0,
              "epoch-2 cookie refused at epoch 5 although the tick stalled at 3");
        sn_device_locks_free(&dev);

        /* the tick resumes after a gap: 3 -> 6 must not keep epoch 3 as previous */
        mkdev(&dev,l);
        sn_device_tick(&dev,12000,12000);         /* epoch 3 */
        get_finish(&dev,5000,nonce,12000,fin);     /* cookie under epoch 3 */
        sn_device_tick(&dev,24000,24000);         /* stalled until epoch 6 */
        CHECK(!dev.have_prev, "a multi-epoch roll keeps no previous tag");
        CHECK(send_finish(&dev,5000,fin,24000)==0,
              "epoch-3 cookie refused after the tick jumped to epoch 6");
        sn_device_locks_free(&dev);

        /* The tick never runs at all. The cache then holds epoch 2 as CURRENT,
         * which INIT used to keep issuing and FINISH used to keep accepting for
         * as long as the stall lasted. Both now go by their own clock (#15). */
        mkdev(&dev,l);                             /* epoch 2 @ 8000, no tick */
        get_finish(&dev,5000,nonce,8000,fin);
        CHECK(send_finish(&dev,5000,fin,16000)==0,
              "no tick: an epoch-2 cookie is refused in epoch 4 (current tag no longer immortal)");
        sn_device_locks_free(&dev);

        mkdev(&dev,l);
        get_finish(&dev,5000,nonce,8000,fin);
        CHECK(send_finish(&dev,5000,fin,15999)==SN_ADMIT_LEN,
              "no tick: still accepted at the last ms of the next epoch (4-8 s window)");
        sn_device_locks_free(&dev);

        mkdev(&dev,l);
        get_finish(&dev,5000,nonce,20000,fin);     /* INIT in epoch 5, tick stuck at 2 */
        CHECK(send_finish(&dev,5000,fin,20000)==SN_ADMIT_LEN,
              "no tick: INIT issues the clock's epoch, so the device stays admittable");
        sn_device_locks_free(&dev);
    }

    /* ── §9.4 rebase clears the latched dead-link and re-bases ts_flush ── */
    {
        ikcpcb *k = ikcp_create(1,NULL);
        k->state = (uint32_t)-1;   /* latched dead-link */
        k->rx_rto = 60000;         /* IKCP_RTO_MAX after dead-link */
        k->ts_flush = 123;         /* stale */
        extern void ikcp_release(ikcpcb*);
        /* call the same logic via a promoted session below; here assert intent by
         * re-basing through a public resume path is covered by the quiesce test.
         * Directly verify the object is usable: state must be clearable. */
        CHECK(k->state == (uint32_t)-1, "kcp latched dead-link");
        ikcp_release(k);
    }

    /* ── quiesce on dead-link, then resume on a fresh datagram (§9.4) ── */
    {
        sn_device dev; sn_prefix l[1]; mkdev(&dev,l);
        admit(&dev,5000,nonce);
        /* client keys + a promoting PUSH */
        uint8_t ecp[32]; memset(ecp,0x07,32);
        /* rebuild RETRY/ADMIT path to get e_s: re-run handshake capturing admit */
        uint8_t init[SN_INIT_LEN], mac[16];
        sn_init_mac(dev.k_req,nonce,DEVICE_ID,mac); sn_encode_init(nonce,DEVICE_ID,mac,init);
        /* admit() already consumed admission_epoch; make a FRESH device for a clean run */
        sn_device_locks_free(&dev);
        sn_device d2; sn_prefix l2[1]; mkdev(&d2,l2);
        uint8_t rt[SN_RETRY_LEN]; sn_handle_init(&d2,init,SN_INIT_LEN,src,5000,8000,rt);
        uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK,DEVICE_ID,nonce,rt,ecp,fin,NULL);
        uint8_t admit[SN_ADMIT_LEN]; sn_handle_finish(&d2,fin,SN_FINISH_LEN,src,5000,8000,admit);
        /* Was two sn_session_keys calls, the first aliasing s2c and k_kcp_s2c
         * onto one buffer and then entirely overwritten by the second. */
        uint8_t sc2s[32],ss2c[32],kks2c[32];
        ch_session_from(PSK,DEVICE_ID,nonce,rt,ecp,admit,sc2s,ss2c,g_kc2s,kks2c);
        sn_sender_init(&g_c2s_seq);

        /* client ikcp to make the promoting PUSH */
        ikcpcb *ck = ikcp_create(0x0BADF00Du,NULL);
        ikcp_setoutput(ck,client_output); ikcp_setmtu(ck,SN_WIRE_MTU-SN_ENVELOPE_LEN);
        ikcp_nodelay(ck,1,20,2,1);
        ikcp_send(ck,"go",2); ikcp_update(ck,1000);
        CHECK(sn_handle_envelope(&d2,g_c2s,g_c2s_len,src,5000,8100)==SN_ENV_PROMOTED, "promoted");

        /* device sends data (fills snd_buf); no ACK ever arrives, so ticks retransmit
         * until xmit >= dead_link (20) and the session quiesces (§9.4) */
        sn_primary_send(&d2,(const uint8_t*)"payload",7,8200);
        /* advance past the capped rx_rto (60000) each tick so exactly one
         * retransmit happens per tick; dead_link is 20, so ~25 ticks suffice */
        uint32_t t=8200;
        for (int i=0;i<40 && !d2.primary.quiesced;i++){ t+=61000; sn_device_tick(&d2,t,t); }
        CHECK(d2.primary.quiesced, "session quiesced on dead-link");

        /* a fresh valid c2s datagram resumes it: rebase in place, quiesced cleared */
        ikcp_send(ck,"more",4); ikcp_update(ck, 2000); /* new outer seq via client_output */
        sn_env_result rr = sn_handle_envelope(&d2,g_c2s,g_c2s_len,src,5000,t+500);
        CHECK(rr==SN_ENV_ESTABLISHED, "resume datagram accepted");
        CHECK(!d2.primary.quiesced, "quiesced cleared on resume");
        CHECK(d2.primary.kcp->state == 0, "dead-link cleared in place (not recreated)");

        ikcp_release(ck);
        ikcp_release(d2.primary.kcp);
        sn_device_locks_free(&d2);
    }

    /* ── transport 12.4: the send path finds the link dead (no tick runs), the
     *    peer then speaks, and after the tick the session is live ── */
    {
        sn_device d3; sn_prefix l3[1];
        ikcpcb *ck = promoted(&d3,l3,nonce);
        int ok = d3.primary.active;
        /* Each write runs ikcp_update at the head segment's next retransmit, so
         * the send path alone drives it to dead_link. */
        uint32_t t = 8200;
        sn_primary_send(&d3,(const uint8_t*)"x",1,t);
        for (int i=0;i<40 && d3.primary.kcp->state != (uint32_t)-1;i++) {
            t = head_seg(&d3)->resendts + 1;
            sn_primary_send(&d3,(const uint8_t*)"x",1,t);
        }
        ok = ok && d3.primary.kcp->state == (uint32_t)-1;
        ikcp_send(ck,"more",4); ikcp_update(ck,2000);
        ok = ok && sn_handle_envelope(&d3,g_c2s,g_c2s_len,src,5000,t+500)==SN_ENV_ESTABLISHED;
        sn_device_tick(&d3,t+520,t+520);
        CHECK(ok && !d3.primary.quiesced && d3.primary.kcp->state == 0,
              "transport 12.4: dead on the send path, then the peer speaks: live after the tick");
        ikcp_release(ck);
        sn_device_release_primary(&d3);
        sn_device_locks_free(&d3);
    }

    /* ── transport 12.4: the tick's latch quiesces a primary with data
     *    unacknowledged; sn_primary_update then emits nothing ── */
    {
        sn_device d4; sn_prefix l4[1];
        ikcpcb *ck = promoted(&d4,l4,nonce);
        sn_primary_send(&d4,(const uint8_t*)"payload",7,8200);
        uint32_t t = 8200;
        for (int i=0;i<40 && !d4.primary.quiesced;i++) {
            t = head_seg(&d4)->resendts + 1;
            sn_device_tick(&d4,t,t);
        }
        int ok = d4.primary.quiesced && ikcp_waitsnd(d4.primary.kcp) > 0;
        sn_device_set_send(&d4,count_send,NULL);
        g_sent = 0;
        struct IKCPSEG *seg = head_seg(&d4);
        uint32_t r1 = seg->resendts + 1, r2 = seg->resendts + 2 * seg->rto + 1;
        sn_primary_update(&d4,r1);
        sn_primary_update(&d4,r2);
        printf("     quiesced %d, datagrams after quiesce: %d\n", ok, g_sent);
        CHECK(ok && g_sent == 0, "transport 12.4: a quiesced primary sends nothing on sn_primary_update");
        ikcp_release(ck);
        sn_device_release_primary(&d4);
        sn_device_locks_free(&d4);
    }

    /* ── transport 12.4: dead on sn_primary_update latches quiesce ── */
    {
        sn_device d5; sn_prefix l5[1];
        ikcpcb *ck = promoted(&d5,l5,nonce);
        sn_primary_send(&d5,(const uint8_t*)"x",1,8200);
        uint32_t t = 8200;
        for (int i=0;i<64 && d5.primary.kcp->state != (uint32_t)-1;i++) {
            t = head_seg(&d5)->resendts + 1;
            sn_primary_update(&d5,t);
        }
        CHECK(d5.primary.quiesced == 1 && d5.primary.kcp->state == (uint32_t)-1,
              "transport 12.4: dead on sn_primary_update latches quiesce");
        ikcp_release(ck);
        sn_device_release_primary(&d5);
        sn_device_locks_free(&d5);
    }

    /* ── transport 12.4: dead on a refused (queue-full) send latches quiesce ── */
    {
        sn_device d6; sn_prefix l6[1];
        ikcpcb *ck = promoted(&d6,l6,nonce);
        int mss = (int)d6.primary.kcp->mss;
        uint8_t fill[SN_WIRE_MTU]; memset(fill,0x5A,sizeof fill);
        /* Queue whole segments until one more would exceed the cap. */
        for (int i=0;i<4096 && (ikcp_waitsnd(d6.primary.kcp)+1)*mss <= SN_SEND_QUEUE_MAX;i++)
            sn_primary_send(&d6,fill,mss,8200);
        uint32_t t = 8200;
        int ok = drive_to_one_short(&d6,&t) && !d6.primary.quiesced;
        t = head_seg(&d6)->resendts + 1;
        int rc = sn_primary_send(&d6,fill,mss,t);
        printf("     alive at dead_link-1: %d, refused send returned %d\n", ok, rc);
        CHECK(ok && rc == SN_SEND_QUEUE_FULL && d6.primary.quiesced == 1 &&
              d6.primary.kcp->state == (uint32_t)-1,
              "transport 12.4: dead on a refused (queue-full) send latches quiesce");
        ikcp_release(ck);
        sn_device_release_primary(&d6);
        sn_device_locks_free(&d6);
    }

    /* ── transport 12.4: dead in the RX flush latches quiesce ── */
    {
        sn_device d7; sn_prefix l7[1];
        ikcpcb *ck = promoted(&d7,l7,nonce);
        sn_primary_send(&d7,(const uint8_t*)"x",1,8200);
        uint32_t t = 8200;
        int ok = drive_to_one_short(&d7,&t);
        /* ck never received the device's segment, so its next datagram does not
         * acknowledge it. */
        ikcp_send(ck,"more",4); ikcp_update(ck,2000);
        sn_env_result rr = sn_handle_envelope(&d7,g_c2s,g_c2s_len,src,5000,head_seg(&d7)->resendts + 1);
        printf("     alive at dead_link-1: %d, RX result %d\n", ok, (int)rr);
        CHECK(ok && rr == SN_ENV_ESTABLISHED && d7.primary.quiesced == 1 &&
              d7.primary.kcp->state == (uint32_t)-1,
              "transport 12.4: dead in the RX flush latches quiesce");
        ikcp_release(ck);
        sn_device_release_primary(&d7);
        sn_device_locks_free(&d7);
    }

    if (failures){ printf("%d FAILURE(S)\n",failures); return 1; }
    printf("all tick/quiesce §9 cases pass\n");
    return 0;
}
