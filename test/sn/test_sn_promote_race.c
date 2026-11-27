/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * An agent binding in the middle of a §8.5 promotion.
 *
 * promote() runs (a) claim + retire under rec_lock, (b) build the new KCP object
 * under kcp_lock only, (c) install under rec_lock. Between (a) and (c) rec_lock
 * is free, so another task can read the primary there: it is inactive, its keys
 * are wiped, and its generation is whatever (a)5 left. A bare generation++ in
 * (a)5 left exactly the value (c) installs for the NEW session, so an agent
 * bound in the window held the new session's generation next to wiped keys --
 * and once (c) ran, that generation was live again: its respond took the new
 * session's MessageNum 1 and sealed under an all-zero key.
 *
 * The window is a few instructions wide, so a plain race would almost never
 * land in it. SN_TEST_HOOKS (sn_device.h) parks the promoting thread there:
 *
 *   thread A  sn_handle_envelope(second session's first PUSH) -> promote()
 *             -> (a) retires the first session -> hook: signal B, wait
 *   thread B  sn_agent_init while A is parked, then release A
 *   thread A  (b), (c): the second session is installed
 *
 * Then B's agent must be bound to no live session: its respond and step fail,
 * and the new session's MessageNum counter is untouched until the new session's
 * own agent responds. Built twice: plain/ASan, and with -fsanitize=thread.
 */
#define _POSIX_C_SOURCE 200809L

#include "shieldnet/sn_agent_dispatch.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"

#include "client_helper.h"
#include "ikcp.h"

#include <errno.h>
#include <pthread.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef SN_TEST_HOOKS
#error "test_sn_promote_race.c needs -DSN_TEST_HOOKS"
#endif

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
static void v4m(uint8_t a[16],uint8_t b,uint8_t c,uint8_t d,uint8_t e){
    memset(a,0,16);a[10]=0xff;a[11]=0xff;a[12]=b;a[13]=c;a[14]=d;a[15]=e;}
static void frand(void*x,uint8_t*b,size_t n){(void)x;memset(b,0x42,n);}

/* ── the client end: seal each KCP datagram as a c2s envelope ── */
static uint8_t g_kkcp_c2s[32];
static sn_sender g_seq;
static uint8_t g_env[4096]; static size_t g_envlen;
static int cli_out(const char*buf,int len,ikcpcb*k,void*u){
    (void)k;(void)u;
    uint64_t s; if(!sn_sender_alloc(&g_seq,&s)) return 0;
    size_t o=0; sn_seal(g_kkcp_c2s,1,s,(const uint8_t*)buf,(size_t)len,g_env,&o);
    g_envlen=o; return 0;}
static void dev_send(void*x,const uint8_t*b,size_t l){(void)x;(void)b;(void)l;}

/* Admit one client on `port` and leave its promoting PUSH (sn=0) in g_env. */
static ikcpcb *admit_and_push(sn_device *dev, const uint8_t src[16], uint16_t port,
                              uint8_t fill, uint32_t conv, uint8_t app_s2c[32]) {
    uint8_t nn[24]; memset(nn, fill, sizeof nn);
    uint8_t ecp[32]; memset(ecp, 7, sizeof ecp);
    uint8_t in[SN_INIT_LEN]; ch_init(PSK, DEVICE_ID, nn, in);
    uint8_t rr[SN_RETRY_LEN];
    CHECK(sn_handle_init(dev, in, SN_INIT_LEN, src, port, 9000, rr) == SN_RETRY_LEN, "RETRY");
    uint8_t fi[SN_FINISH_LEN]; ch_finish(PSK, DEVICE_ID, nn, rr, ecp, fi, NULL);
    uint8_t ad[SN_ADMIT_LEN];
    CHECK(sn_handle_finish(dev, fi, SN_FINISH_LEN, src, port, 9000, ad) == SN_ADMIT_LEN, "ADMIT");
    uint8_t kc[32], ks[32];
    ch_session_from(PSK, DEVICE_ID, nn, rr, ecp, ad, kc, app_s2c, g_kkcp_c2s, ks);
    sn_sender_init(&g_seq);
    ikcpcb *ck = ikcp_create(conv, NULL);
    ikcp_setoutput(ck, cli_out);
    ikcp_setmtu(ck, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    ikcp_nodelay(ck, 1, 20, 2, 1);
    ck->stream = 1;
    ikcp_send(ck, "p", 1);
    g_envlen = 0;
    ikcp_update(ck, 2000);
    CHECK(g_envlen > 0, "client emitted its promoting PUSH");
    return ck;
}

/* ── the rendezvous between the parked promotion (A) and the binder (B) ── */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_paused, g_released, g_hook_calls;

/* Wait on g_cv until *flag, at most 10 s: a broken build must fail, not hang. */
static int wait_flag(int *flag) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 10;
    int rc = 0;
    pthread_mutex_lock(&g_mu);
    while (!*flag && rc != ETIMEDOUT) rc = pthread_cond_timedwait(&g_cv, &g_mu, &dl);
    int ok = *flag;
    pthread_mutex_unlock(&g_mu);
    return ok;
}
static void set_flag(int *flag) {
    pthread_mutex_lock(&g_mu);
    *flag = 1;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

/* Runs on A between (a) and (b): kcp_lock held, rec_lock released. */
static void park_promotion(sn_device *d) {
    (void)d;
    pthread_mutex_lock(&g_mu);
    g_hook_calls++;
    pthread_mutex_unlock(&g_mu);
    set_flag(&g_paused);
    wait_flag(&g_released);
}

static sn_device g_dev;
static uint8_t g_src[16];

/* thread A: deliver the second session's promoting PUSH */
static sn_env_result g_a_result = SN_ENV_DROP;
static void *thread_a(void *arg) {
    (void)arg;
    g_a_result = sn_handle_envelope(&g_dev, g_env, g_envlen, g_src, 5003, 9100);
    return NULL;
}

/* thread B: bind an agent while A is parked inside the promotion */
static shieldnet_device_ops_t g_ops;
static uint8_t b_raw[2048], b_dec[2048], b_decomp[2048], b_enc[2048];
static sn_agent g_agB;
static int g_b_paused_seen, g_b_rc = 99, g_b_active_in_window = -1;
static void *thread_b(void *arg) {
    (void)arg;
    g_b_paused_seen = wait_flag(&g_paused);
    if (g_b_paused_seen) {
        g_b_rc = sn_agent_init(&g_agB, &g_dev, &g_ops, b_raw, sizeof b_raw,
                               b_dec, sizeof b_dec, b_decomp, sizeof b_decomp,
                               b_enc, sizeof b_enc);
        g_b_active_in_window = sn_device_session_active(&g_dev, g_agB.io_st.gen);
    }
    set_flag(&g_released);
    return NULL;
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }
    memset(PSK, 0x11, 32);

    sn_prefix loc[1];
    v4m(loc[0].a16,192,168,4,1); loc[0].is_v4=1; loc[0].bits=24;
    uint8_t cs[32]; memset(cs,0x22,32); uint8_t ae[8]={0,1,2,3,4,5,6,7};
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&g_dev, kd, DEVICE_ID,cs,ae,loc,1,8000);
    g_dev.rand_fill=frand; sn_device_locks_init(&g_dev);
    sn_device_set_send(&g_dev, dev_send, NULL);
    v4m(g_src,192,168,4,2);
    memset(&g_ops, 0, sizeof g_ops);

    /* ── the live primary: session 1, promoted, with its own agent ── */
    uint8_t s2c1[32], s2c2[32];
    ikcpcb *ck1 = admit_and_push(&g_dev, g_src, 5002, 0xC0, 0x0A0A0A00u, s2c1);
    CHECK(sn_handle_envelope(&g_dev, g_env, g_envlen, g_src, 5002, 9100) == SN_ENV_PROMOTED,
          "session 1 promoted");
    uint32_t gen1 = sn_device_current_gen(&g_dev);
    static uint8_t raw[2048], dec[2048], decomp[2048], enc[2048];
    sn_agent ag1;
    CHECK(sn_agent_init(&ag1, &g_dev, &g_ops, raw, sizeof raw, dec, sizeof dec,
                        decomp, sizeof decomp, enc, sizeof enc) == 0 && ag1.io_st.gen == gen1,
          "agent 1 binds session 1");

    /* ── session 2 admitted; its first PUSH will promote over session 1 ── */
    ikcpcb *ck2 = admit_and_push(&g_dev, g_src, 5003, 0xC1, 0x0A0A0A01u, s2c2);

    sn_test_promote_hook = park_promotion;
    pthread_t ta, tb;
    CHECK(pthread_create(&tb, NULL, thread_b, NULL) == 0, "thread B started");
    CHECK(pthread_create(&ta, NULL, thread_a, NULL) == 0, "thread A started");
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    sn_test_promote_hook = NULL;

    CHECK(g_hook_calls == 1, "the promotion reached the window between (a) and (c) once");
    CHECK(g_b_paused_seen, "B ran while A was parked there");
    CHECK(g_a_result == SN_ENV_PROMOTED, "A's promotion completed after the release");
    uint32_t gen2 = sn_device_current_gen(&g_dev);
    CHECK(sn_device_session_active(&g_dev, gen2) && gen2 != gen1,
          "session 2 is the primary, with its own generation");

    /* What B bound in the window. */
    uint32_t bgen = g_agB.io_st.gen;
    printf("     [race] gen1=%u gen2=%u B: rc=%d gen=%u\n",
           (unsigned)gen1, (unsigned)gen2, g_b_rc, (unsigned)bgen);
    CHECK(g_b_rc == -1 || g_b_rc == 0, "B's sn_agent_init returned");
    CHECK(g_b_active_in_window == 0, "in the window, B's generation named no live session");
    CHECK(g_b_rc == -1, "B's bind in the window reports -1 (no active primary)");
    CHECK(bgen != gen2, "B is NOT bound to the new session's generation");
    CHECK(bgen != gen1, "nor to the retired one's");
    CHECK(!sn_device_session_active(&g_dev, bgen), "B's generation matches no live session");
    CHECK(g_b_rc != 0 || !sodium_is_zero(g_agB.tx.key, 32),
          "a successful bind never carries wiped keys");

    /* ── after the install: B's agent must not touch session 2 ── */
    ikcpcb *nk = g_dev.primary.kcp;
    int waitsnd_before = ikcp_waitsnd(nk);
    uint64_t next_before = g_dev.primary.app_s2c_next;
    CHECK(next_before == 1, "session 2's MessageNum counter starts at 1");
    CHECK(sn_agent_respond(&g_agB, 9100, 0x80, (const uint8_t *)"stale", 5) < 0,
          "B's respond fails");
    CHECK(g_dev.primary.app_s2c_next == 1,
          "B took no MessageNum from session 2 (app_s2c_next still 1)");
    CHECK(ikcp_waitsnd(nk) == waitsnd_before, "nothing of B's reached session 2's stream");
    CHECK(sn_agent_step(&g_agB, 9100, 1) < 0, "B's step fails");
    CHECK(sn_agent_respond(&ag1, 9100, 0x80, (const uint8_t *)"old", 3) < 0,
          "session 1's agent is refused too");
    CHECK(sn_device_session_active(&g_dev, gen2), "none of it disturbed session 2");

    /* ── session 2's own agent takes MessageNum 1 ── */
    sn_agent ag2;
    CHECK(sn_agent_init(&ag2, &g_dev, &g_ops, raw, sizeof raw, dec, sizeof dec,
                        decomp, sizeof decomp, enc, sizeof enc) == 0 && ag2.io_st.gen == gen2,
          "session 2's agent binds it");
    CHECK(memcmp(ag2.tx.key, s2c2, 32) == 0, "under session 2's k_s2c");
    CHECK(sn_agent_respond(&ag2, 9100, 0x80, (const uint8_t *)"fresh", 5) == 0,
          "session 2's agent responds");
    CHECK(ag2.tx.next_msgnum == 2 && g_dev.primary.app_s2c_next == 2,
          "with MessageNum 1, the first the session handed out");
    CHECK(ikcp_waitsnd(nk) > waitsnd_before, "and its frame is on session 2's stream");

    sn_agent_end(&ag2);
    sn_app_rx_wipe(&g_agB.rx, 1); sn_app_tx_wipe(&g_agB.tx, 1);
    sn_app_rx_wipe(&ag1.rx, 1); sn_app_tx_wipe(&ag1.tx, 1);
    ikcp_release(ck1);
    ikcp_release(ck2);
    sn_device_release_primary(&g_dev);
    sn_device_wipe(&g_dev);
    sn_device_locks_free(&g_dev);
    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("all sn_promote_race cases pass\n");
    return 0;
}
