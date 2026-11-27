/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Characterisation of the device's app layer — sn_agent_dispatch.c.
 *
 * Written BEFORE the direction-symmetric half moved out to sn_app_frame.c, and
 * that is the point. That factoring took the device's existing tests passing
 * unmodified as its safety net. It is not one: sn_agent_step
 * and sn_agent_respond had no direct test at all. test_sn_agent.c covers
 * sn_agent.c's io seam (partial reads, carry boundaries, the mid-frame budget)
 * and never calls either of them, and the firmware suites cover the pure policy
 * headers and command.c rather than this loop. A factoring could have broken
 * read -> decrypt -> decompress -> dispatch outright and every existing test
 * would still have passed.
 *
 * So this pins the behaviour that must survive: what dispatches, what is
 * dropped survivably, what ends the session, and what goes back on the wire.
 * It asserts on the CURRENT behaviour, including the parts that look odd, and
 * a change to any expected value here is a behaviour change whatever the
 * commit message says.
 */
#include "shieldnet/sn_agent_dispatch.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"

#include "client_helper.h"
#include "crypto.h"
#include "protocol.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static uint8_t PSK[32];
static uint8_t DEVICE_ID[8] = {1,2,3,4,5,6,7,8};
static void v4m(uint8_t a[16],uint8_t b,uint8_t c,uint8_t d,uint8_t e){
    memset(a,0,16);a[10]=0xff;a[11]=0xff;a[12]=b;a[13]=c;a[14]=d;a[15]=e;}
static void frand(void*x,uint8_t*b,size_t n){(void)x;memset(b,0x42,n);}

/* ── the client end of the session ── */
static uint8_t g_kc2s[32], g_ks2c[32];
static sn_sender g_seq;
static uint8_t g_env[4096]; static size_t g_envlen;
static int cli_out(const char*buf,int len,ikcpcb*k,void*u){
    (void)k;(void)u;
    uint64_t s; if(!sn_sender_alloc(&g_seq,&s)) return 0;
    size_t o=0; sn_seal(g_kc2s,1,s,(const uint8_t*)buf,(size_t)len,g_env,&o);
    g_envlen=o; return 0;}
/* The device's outbound envelopes, so responses can be checked. */
static uint8_t g_dev_env[4096]; static size_t g_dev_envlen;
static void dev_send(void*x,const uint8_t*b,size_t l){
    (void)x; if(l<=sizeof g_dev_env){memcpy(g_dev_env,b,l); g_dev_envlen=l;}}

/* ── the s2c stream as it actually went out ──
 *
 * The client in this test never acknowledges the device's output, so the
 * device's KCP still holds every s2c byte since promotion: snd_buf in sequence
 * order, then snd_queue. Walk both, cut the bytes into app frames, and
 * AEAD-open each one under k_s2c with the nonce its own header carries --
 * which checks the MessageNums on the wire, not a counter that is supposed
 * to produce them. Returns the number of frames, or -1 if one fails to open. */
/* The last frame wire_s2c_msgnums parsed: its header and ciphertext. */
static protocol_msg_header_t g_last_hdr; static uint8_t g_last_raw[4096];
static int wire_s2c_msgnums(ikcpcb *k, const uint8_t k_s2c[32],
                            uint64_t *nums, int max) {
    static uint8_t stream[65536];
    size_t len = 0;
    struct IQUEUEHEAD *queues[2] = { &k->snd_buf, &k->snd_queue };
    for (int q = 0; q < 2; q++) {
        for (struct IQUEUEHEAD *p = queues[q]->next; p != queues[q]; p = p->next) {
            struct IKCPSEG *seg = iqueue_entry(p, struct IKCPSEG, node);
            if (len + seg->len > sizeof stream) return -1;
            memcpy(stream + len, seg->data, seg->len);
            len += seg->len;
        }
    }
    int n = 0;
    size_t off = 0;
    while (off + PROTOCOL_HEADER_SIZE <= len && n < max) {
        const uint8_t *h = stream + off;
        uint32_t size = ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
                        ((uint32_t)h[2] << 8) | (uint32_t)h[3];
        uint32_t orig = ((uint32_t)h[4] << 24) | ((uint32_t)h[5] << 16) |
                        ((uint32_t)h[6] << 8) | (uint32_t)h[7];
        uint32_t type = ((uint32_t)h[8] << 24) | ((uint32_t)h[9] << 16) |
                        ((uint32_t)h[10] << 8) | (uint32_t)h[11];
        uint64_t num = 0;
        for (int i = 0; i < 8; i++) num = (num << 8) | h[12 + i];
        if (off + PROTOCOL_HEADER_SIZE + size > len) return -1;
        uint8_t aad[PROTOCOL_HEADER_SIZE], nn[CRYPTO_NONCE_SIZE], pt[4096];
        protocol_marshal_aad(size, orig, type, num, aad);
        protocol_nonce_from_msgnum(num, nn);
        size_t ptl = 0;
        if (size > sizeof pt ||
            crypto_decrypt(k_s2c, nn, h + PROTOCOL_HEADER_SIZE, size, aad, sizeof aad,
                           pt, &ptl) != 0) {
            return -1;
        }
        nums[n++] = num;
        g_last_hdr.size = size; g_last_hdr.original_size = orig;
        g_last_hdr.message_type = type; g_last_hdr.message_num = num;
        memcpy(g_last_raw, h + PROTOCOL_HEADER_SIZE, size);
        off += PROTOCOL_HEADER_SIZE + size;
    }
    return off == len ? n : -1;
}

/* ── what the dispatcher saw ── */
static uint8_t g_kind; static uint8_t g_body[512]; static size_t g_body_len;
static int g_dispatched;
static sn_agent *g_agent; static uint32_t g_now;

/* A response queued by a step leaves at the device's next KCP flush, one
 * interval after the step's clock (the agent writes on the caller's clock). */
static void flush_device(sn_device *d, uint32_t step_now) {
    sn_primary_update(d, step_now + d->primary.kcp->interval);
}

/* PING needs no op of its own: command.c answers it with an ACK, so
 * send_response is the only hook, and it is where the dispatch is observed. */
static int op_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx;
    g_kind = kind;
    if (len <= sizeof g_body) { memcpy(g_body, body, len); g_body_len = len; }
    g_dispatched++;
    return sn_agent_respond(g_agent, g_now, kind, body, len);
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }
    memset(PSK, 0x11, 32);

    sn_device dev; sn_prefix loc[1];
    v4m(loc[0].a16,192,168,4,1); loc[0].is_v4=1; loc[0].bits=24;
    uint8_t cs[32]; memset(cs,0x22,32); uint8_t ae[8]={0,1,2,3,4,5,6,7};
    uint8_t kd[32]; sn_derive_kdev(PSK, DEVICE_ID, kd);
    sn_device_init_kdev(&dev, kd, DEVICE_ID,cs,ae,loc,1,8000);
    dev.rand_fill=frand; sn_device_locks_init(&dev);
    sn_device_set_send(&dev, dev_send, NULL);

    uint8_t nonce[24]; memset(nonce,0xAB,24); uint8_t src[16]; v4m(src,192,168,4,2);
    uint8_t init[SN_INIT_LEN]; ch_init(PSK,DEVICE_ID,nonce,init);
    uint8_t r[SN_RETRY_LEN];
    CHECK(sn_handle_init(&dev,init,SN_INIT_LEN,src,5000,8000,r)==SN_RETRY_LEN,"RETRY");
    uint8_t ecp[32]; memset(ecp,7,32);
    uint8_t fin[SN_FINISH_LEN]; ch_finish(PSK,DEVICE_ID,nonce,r,ecp,fin,NULL);
    uint8_t adm[SN_ADMIT_LEN];
    CHECK(sn_handle_finish(&dev,fin,SN_FINISH_LEN,src,5000,8000,adm)==SN_ADMIT_LEN,"ADMIT");

    uint8_t k_c2s[32], k_s2c[32];
    ch_session_from(PSK,DEVICE_ID,nonce,r,ecp,adm,k_c2s,k_s2c,g_kc2s,g_ks2c);
    sn_sender_init(&g_seq);

    ikcpcb *ck = ikcp_create(0xABCD1234u, NULL);
    ikcp_setoutput(ck, cli_out);
    ikcp_setmtu(ck, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    ikcp_nodelay(ck, 1, 20, 2, 1);
    ck->stream = 1;

    /* Frame one app message the way a client would: 20-byte header, then the
     * body sealed under k_c2s with the header as AAD. */
    uint8_t frame[1024];
    size_t frame_len = 0;
    uint64_t msgnum = 1;
#define BUILD_FRAME(kind_, num_, body_, blen_, orig_)                              \
    do {                                                                           \
        uint32_t ct_len = (uint32_t)(blen_) + CRYPTO_OVERHEAD;                      \
        uint8_t aad[PROTOCOL_HEADER_SIZE];                                          \
        protocol_marshal_aad(ct_len, (orig_), (kind_), (num_), aad);                \
        memcpy(frame, aad, PROTOCOL_HEADER_SIZE);                                    \
        uint8_t nn[CRYPTO_NONCE_SIZE];                                              \
        protocol_nonce_from_msgnum((num_), nn);                                      \
        size_t ol = 0;                                                              \
        crypto_encrypt(k_c2s, nn, (body_), (blen_), aad, sizeof aad,                \
                       frame + PROTOCOL_HEADER_SIZE, &ol);                           \
        frame_len = PROTOCOL_HEADER_SIZE + ol;                                       \
    } while (0)

    /* PING (0x07) is payload-free, and §13 pads a control message up to the
     * 64-byte floor, so the sealed plaintext is 64 with original_size 0. */
    uint8_t padded[64]; memset(padded, 0, sizeof padded);
    BUILD_FRAME(0x07, msgnum, padded, sizeof padded, 0);

    /* Promote and deliver the frame in one PUSH. */
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1000);
    CHECK(sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8100) == SN_ENV_PROMOTED,
          "promoted, carrying the frame");

    shieldnet_device_ops_t ops; memset(&ops, 0, sizeof ops);
    ops.send_response = op_send_response;

    /* enc holds the largest response this build sends, sealed. */
    enum { ENC_SIZE = SHIELDNET_MAX_RESPONSE_BODY + 64 > 2048 ? SHIELDNET_MAX_RESPONSE_BODY + 64 : 2048 };
    static uint8_t raw[2048], dec[2048], decomp[2048], enc[ENC_SIZE];
    sn_agent ag;
    sn_agent_init(&ag, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                  decomp, sizeof decomp, enc, sizeof enc);
    g_agent = &ag; g_now = 8100;

    CHECK(ag.tx.next_msgnum == 1, "tx MessageNum starts at 1");
    CHECK(ag.rx.last_msgnum == 0, "rx high-water starts at 0");

    /* ── a well-formed message dispatches, and the ack goes back sealed ── */
    g_dispatched = 0; g_dev_envlen = 0;
    int rc = sn_agent_step(&ag, 8100, 50);
    flush_device(&dev, 8100);
    CHECK(rc == 1, "step returns 1 for a dispatched frame");
    CHECK(g_dispatched == 1, "the op ran");
    CHECK(ag.rx.last_msgnum == 1, "rx high-water advanced");
    CHECK(g_dev_envlen > 0, "a response was written");
    CHECK(ag.tx.next_msgnum == 2, "tx MessageNum advanced past the response");

    /* ── message layer 6.3: responses go out padded ── */
    {
        uint64_t nums[8];
        int n = wire_s2c_msgnums(dev.primary.kcp, k_s2c, nums, 8);
        static uint8_t odec[1024], odecomp[1024];
        sn_app_rx orx; sn_app_rx_init(&orx, k_s2c, odec, sizeof odec, odecomp, sizeof odecomp);
        const uint8_t *pl = NULL; size_t pll = 0;
        int opened = n == 1 && sn_app_open(&orx, &g_last_hdr, g_last_raw, &pl, &pll) == SN_APP_OK;
        printf("     (ACK frame: Size %u, OriginalSize %u)\n",
               (unsigned)g_last_hdr.size, (unsigned)g_last_hdr.original_size);
        CHECK(opened && g_last_hdr.size == 80 && g_last_hdr.original_size == 14 &&
              pll == 14 && g_body_len == 14 && memcmp(pl, g_body, 14) == 0,
              "message layer 6.3: a 14-byte ACK goes out padded");

        /* An enc buffer too small for the 256 class (+16 = 272): unpadded. */
        static uint8_t senc[250];
        sn_agent ags;
        sn_agent_init(&ags, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                      decomp, sizeof decomp, senc, sizeof senc);
        uint8_t b200[200]; memset(b200, 0x5c, sizeof b200);
        int rs = sn_agent_respond(&ags, 8100, 0x84, b200, sizeof b200);
        n = wire_s2c_msgnums(dev.primary.kcp, k_s2c, nums, 8);
        opened = n == 2 && sn_app_open(&orx, &g_last_hdr, g_last_raw, &pl, &pll) == SN_APP_OK;
        printf("     (200-byte body, enc 250: rc %d, Size %u)\n", rs, (unsigned)g_last_hdr.size);
        CHECK(rs == 0 && opened && g_last_hdr.size == 216 && g_last_hdr.original_size == 200 &&
              pll == 200 && memcmp(pl, b200, 200) == 0,
              "message layer 6.3: a small enc buffer sends unpadded");
        g_agent = &ag;
    }

    /* ── replay: a MessageNum at or below the high-water is dropped, but the
     *    session survives and the frame is consumed ── */
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1100);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8200);
    g_dispatched = 0;
    rc = sn_agent_step(&ag, 8200, 50);
    CHECK(rc == 1 && g_dispatched == 0, "replayed MessageNum dropped, session survives");

    /* ── MessageNum 0 is reserved for the handshake tag nonce ── */
    BUILD_FRAME(0x07, 0, padded, sizeof padded, 0);
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1200);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8300);
    g_dispatched = 0;
    rc = sn_agent_step(&ag, 8300, 50);
    CHECK(rc == 1 && g_dispatched == 0, "MessageNum 0 dropped, session survives");

    /* ── an authentication failure drops the frame, not the session ── */
    msgnum = 5;
    BUILD_FRAME(0x07, msgnum, padded, sizeof padded, 0);
    frame[PROTOCOL_HEADER_SIZE] ^= 1;   /* corrupt the ciphertext */
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1300);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8400);
    g_dispatched = 0;
    rc = sn_agent_step(&ag, 8400, 50);
    CHECK(rc == 1 && g_dispatched == 0, "AEAD failure drops the frame, session survives");
    CHECK(ag.rx.last_msgnum == 1, "a failed frame does not advance the high-water");

    /* ── §13 padding: original_size below the class is stripped, not rejected ── */
    msgnum = 6;
    {
        uint8_t body[64]; memset(body, 0, sizeof body);
        memcpy(body, "ping", 4);
        BUILD_FRAME(0x07, msgnum, body, sizeof body, 4);
    }
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1400);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8500);
    g_dispatched = 0;
    rc = sn_agent_step(&ag, 8500, 50);
    CHECK(rc == 1 && g_dispatched == 1, "a padded frame dispatches with the padding stripped");

    /* ── a header/body length disagreement is dropped ── */
    msgnum = 7;
    {
        uint8_t body[64]; memset(body, 0, sizeof body);
        /* original_size larger than the sealed plaintext: the bound that stops
         * the power-of-two ladder wrapping on a 32-bit size_t. */
        BUILD_FRAME(0x07, msgnum, body, sizeof body, 0x7fffffffu);
    }
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1500);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8600);
    g_dispatched = 0;
    rc = sn_agent_step(&ag, 8600, 50);
    CHECK(rc == 1 && g_dispatched == 0,
          "original_size beyond the plaintext is dropped, and does not hang");

    /* ── a command whose op the board never populated ──
     *
     * command.c used to call the ops table unconditionally, so this jumped
     * through a null pointer: an authenticated peer rebooting the device, and
     * from the wire indistinguishable from a crash bug in the protocol. Every
     * known firmware populates every entry, so it was an unstated contract
     * rather than a live defect -- and an unstated contract is what the next
     * board gets wrong. It is now refused like an unknown kind. */
    msgnum = 8;
    {
        uint8_t body[64]; memset(body, 0, sizeof body);
        body[0] = 30;
        BUILD_FRAME(0x02 /* SET_FPS; ops.set_fps is NULL here */,
                    msgnum, body, sizeof body, 1);
    }
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1600);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8700);
    g_dispatched = 0; g_dev_envlen = 0;
    rc = sn_agent_step(&ag, 8700, 50);
    flush_device(&dev, 8700);
    CHECK(rc == 1, "a missing op is survivable, not a crash and not a teardown");
    CHECK(g_dev_envlen > 0 && g_kind == 0x80,
          "and the peer gets an ACK rather than silence");

    /* GET_MODE calls dev->get_status, which this table leaves NULL. The first
     * version of the guard above asserted in a comment that GET_MODE needed no
     * op, so this exact command still crashed after the "fix". */
    msgnum = 9;
    {
        uint8_t body[64]; memset(body, 0, sizeof body);
        BUILD_FRAME(0x09 /* GET_MODE */, msgnum, body, sizeof body, 0);
    }
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1700);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8800);
    g_dev_envlen = 0;
    rc = sn_agent_step(&ag, 8800, 50);
    flush_device(&dev, 8800);
    CHECK(rc == 1 && g_dev_envlen > 0,
          "GET_MODE with a NULL get_status is refused, not a crash");

    /* An unrecognised kind. Its branch calls emit_event before the ACK, and the
     * kind byte is entirely the peer's choice, so this was the widest way to
     * reach a null op -- and the first two versions of the guard both let it
     * through as a fallthrough. */
    msgnum = 10;
    {
        uint8_t body[64]; memset(body, 0, sizeof body);
        BUILD_FRAME(0xEE /* no such kind */, msgnum, body, sizeof body, 0);
    }
    ikcp_send(ck, (const char *)frame, (int)frame_len);
    ikcp_update(ck, 1800);
    sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 8900);
    g_dev_envlen = 0;
    rc = sn_agent_step(&ag, 8900, 50);
    flush_device(&dev, 8900);
    CHECK(rc == 1 && g_dev_envlen > 0,
          "an unknown kind with a NULL emit_event is refused, not a crash");

    /* ── idle: no data, stream still aligned ── */
    rc = sn_agent_step(&ag, 8700, 1);
    CHECK(rc == 0, "idle timeout returns 0 with the stream aligned");

    /* ── re-binding an agent to the same primary must not restart MessageNum ──
     *
     * The s2c MessageNum is the AEAD nonce under k_s2c. It used to live only in
     * the agent and restart at 1 in sn_agent_init, while k_s2c came from the
     * primary -- so a firmware loop that answered a step error by re-binding
     * sealed new responses under (k_s2c, 1), (k_s2c, 2), ... again: XChaCha20
     * nonce reuse, which leaks plaintext XORs and the Poly1305 key. */
    {
        uint64_t next_before = dev.primary.app_s2c_next;
        CHECK(next_before > 1, "the first agent consumed s2c MessageNums");
        sn_agent ag2;
        CHECK(sn_agent_init(&ag2, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                            decomp, sizeof decomp, enc, sizeof enc) == 0,
              "re-bind to the live primary succeeds");
        CHECK(ag2.io_st.gen == ag.io_st.gen, "and serves the same generation");
        g_agent = &ag2;
        CHECK(sn_agent_respond(&ag2, 8900, 0x80, (const uint8_t *)"x", 1) == 0,
              "the re-bound agent can respond");
        CHECK(ag2.tx.next_msgnum == next_before + 1,
              "its response used the primary's next MessageNum, not 1");
        CHECK(dev.primary.app_s2c_next == next_before + 1,
              "and the primary's counter advanced past it");
        CHECK(sn_agent_respond(&ag, 8900, 0x80, (const uint8_t *)"y", 1) == 0 &&
              dev.primary.app_s2c_next == next_before + 2,
              "the first agent continues the same sequence too");

        /* The same claim, read off the wire: every frame either agent sent
         * opens under k_s2c, and no MessageNum appears twice. */
        {
            uint64_t nums[64];
            int n = wire_s2c_msgnums(dev.primary.kcp, k_s2c, nums, 64);
            printf("     [wire] %d s2c frames, MessageNums", n);
            for (int i = 0; i < n; i++) printf(" %llu", (unsigned long long)nums[i]);
            printf("\n");
            CHECK(n >= 3, "wire: every s2c frame parsed and opened under k_s2c");
            int seq_ok = n > 0 && nums[0] == 1;
            for (int i = 1; i < n; i++) seq_ok = seq_ok && nums[i] == nums[i - 1] + 1;
            CHECK(seq_ok, "wire: MessageNums run 1, 2, 3, ... with no repeat across the re-bind");
            CHECK(n >= 2 && nums[n - 2] == next_before && nums[n - 1] == next_before + 1,
                  "wire: the re-bound agent's frame carries the primary's next number");
        }

        /* ── a body longer than SHIELDNET_MAX_RESPONSE_BODY is refused before
         *    anything is written or a message number is spent ── */
        {
            static uint8_t big[SHIELDNET_MAX_RESPONSE_BODY + 1];
            memset(big, 0x5a, sizeof big);
            uint64_t nums2[8];
            uint64_t next_before = ag.tx.next_msgnum;
            int queued_before = ikcp_waitsnd(dev.primary.kcp);
            int n_before = wire_s2c_msgnums(dev.primary.kcp, k_s2c, nums2, 8);
            int r_over = sn_agent_respond(&ag, 8900, 0x84, big, sizeof big);
            CHECK(r_over < 0 && ag.tx.next_msgnum == next_before &&
                  ikcp_waitsnd(dev.primary.kcp) == queued_before &&
                  wire_s2c_msgnums(dev.primary.kcp, k_s2c, nums2, 8) == n_before &&
                  !ag.io_st.poisoned,
                  "a body over SHIELDNET_MAX_RESPONSE_BODY is refused, nothing written");
        }

        /* ── a response refused whole keeps the session; a partial one ends it ──
         *
         * §9.4/§9.5: a full send queue -- what a quiesced session produces -- is a
         * refusal, not a broken session. Telling callers to end the session on
         * every step error would tear down exactly the session those sections
         * keep. What decides it is whether any part of the frame reached the
         * stream: the agent's io latches `poisoned` when one did. */
        {
            ikcpcb *dk = dev.primary.kcp;
            int mss = (int)dk->mss;
            static uint8_t fill[SHIELDNET_MAX_RESPONSE_BODY > 2048 ? SHIELDNET_MAX_RESPONSE_BODY : 2048];
            memset(fill, 0xEE, sizeof fill);
            /* One segment short of the cap (23 at the defaults, 32768 / 1356 - 1):
             * the 20-byte header still fits under SN_SEND_QUEUE_MAX, a
             * body, which is at least one segment, does not. */
            const int target = SN_SEND_QUEUE_MAX / mss - 1;
            for (int i = 0; i < 4096 && ikcp_waitsnd(dk) < target; i++) {
                CHECK(sn_primary_send(&dev, fill, mss, 8900) == mss, "fill: queued");
                if (ikcp_waitsnd(dk) > target) break;
            }
            /* Stream mode appends a write to a partly filled last segment (the
             * small responses above may still be queued): fill it, so the
             * header below starts a segment of its own. */
            if (dk->nsnd_que > 0) {
                /* Read the room first: the append frees and replaces the tail. */
                int room = mss - (int)iqueue_entry(dk->snd_queue.prev, struct IKCPSEG, node)->len;
                if (room > 0)
                    CHECK(sn_primary_send(&dev, fill, room, 8900) == room,
                          "fill: the last segment topped up");
            }
            CHECK(ikcp_waitsnd(dk) == target, "fill: queue one segment short of the cap");
            CHECK((ikcp_waitsnd(dk) + 1) * mss <= SN_SEND_QUEUE_MAX &&
                  (ikcp_waitsnd(dk) + 2) * mss > SN_SEND_QUEUE_MAX,
                  "fill: a header fits and a body does not");
            g_agent = &ag;
            CHECK(sn_agent_respond(&ag, 8900, 0x80, fill, SHIELDNET_MAX_RESPONSE_BODY) < 0,
                  "partial: header queued, body refused -> respond fails");
            CHECK(ag.io_st.poisoned, "partial: the agent's stream is marked poisoned");

            /* Now full: even a header is refused, whole. A fresh agent (ag has a
             * poisoned stream and must not be stepped again) serves a PING. */
            for (int i = 0; i < 4096 && sn_primary_send(&dev, fill, mss, 8900) == mss; i++) {}
            sn_agent ag4;
            CHECK(sn_agent_init(&ag4, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                                decomp, sizeof decomp, enc, sizeof enc) == 0,
                  "refused: a fresh agent binds");
            BUILD_FRAME(0x07, 1, padded, sizeof padded, 0);
            ikcp_send(ck, (const char *)frame, (int)frame_len);
            ikcp_update(ck, 1900);
            sn_handle_envelope(&dev, g_env, g_envlen, src, 5000, 9000);
            g_agent = &ag4; g_dispatched = 0;
            rc = sn_agent_step(&ag4, 9000, 50);
            CHECK(g_dispatched == 1, "refused: the command ran");
            CHECK(rc == SN_AGENT_REFUSED,
                  "refused: step reports SN_AGENT_REFUSED, not -1");
            CHECK(!ag4.io_st.poisoned, "refused: nothing reached the stream");
            CHECK(sn_device_session_active(&dev, ag4.io_st.gen),
                  "refused: the session is still there");
            CHECK(sn_agent_step(&ag4, 9000, 1) == 0,
                  "refused: the stream is still aligned (next step idles)");
            g_agent = &ag2;
        }

        /* ── a write bound to a stale generation is refused ── */
        uint32_t gen = ag.io_st.gen;
        CHECK(sn_primary_send_gen(&dev, gen + 1, (const uint8_t *)"z", 1, 8900) == -1,
              "send on a generation that is not the primary's is refused");
        uint64_t mn = 0;
        CHECK(sn_primary_next_s2c_msgnum(&dev, gen + 1, &mn) == -1,
              "and so is a MessageNum for it");

        /* ── sn_agent_end ends exactly the agent's session ── */
        sn_agent_end(&ag2);
        CHECK(!sn_device_session_active(&dev, gen), "sn_agent_end ended the primary");
        CHECK(dev.primary.kcp == NULL, "and released its KCP object");
        CHECK(sodium_is_zero(dev.primary.k_s2c, 32) && sodium_is_zero(ag2.tx.key, 32),
              "and wiped the primary's and the agent's keys");
        CHECK(sn_device_current_gen(&dev) != gen,
              "the ended generation is never the primary's again");
        CHECK(sn_agent_respond(&ag, 8900, 0x80, (const uint8_t *)"w", 1) < 0,
              "a respond on the ended session fails");
        CHECK(sn_agent_step(&ag, 8900, 1) < 0, "a step on the ended session fails");
        sn_agent ag3;
        CHECK(sn_agent_init(&ag3, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                            decomp, sizeof decomp, enc, sizeof enc) == -1,
              "binding with no active primary reports -1");
        sn_device_end_primary(&dev, gen); /* already ended: a no-op */
        CHECK(sn_device_current_gen(&dev) == ag3.io_st.gen, "a repeat end is a no-op");
    }

    /* ── an agent replaced by a real promotion cannot touch the new session ──
     *
     * Two fresh admissions, each promoted, the second replacing the first. The
     * first session's agent is still bound to its generation: everything it
     * tries afterwards -- a raw io write, a response, a step -- must fail
     * without reaching the new session's stream or its MessageNum counter. */
    {
        sn_agent agA, agB;
        ikcpcb *cks[2] = { NULL, NULL };
        uint32_t gens[2] = { 0, 0 };
        uint8_t app_s2c[2][32];
        for (int pass = 0; pass < 2; pass++) {
            uint16_t port = (uint16_t)(5002 + pass);
            uint8_t nn[24]; memset(nn, 0xC0 + pass, sizeof nn);
            uint8_t in[SN_INIT_LEN]; ch_init(PSK, DEVICE_ID, nn, in);
            uint8_t rr[SN_RETRY_LEN];
            CHECK(sn_handle_init(&dev, in, SN_INIT_LEN, src, port, 9000, rr) == SN_RETRY_LEN,
                  "re-promotion: RETRY");
            uint8_t fi[SN_FINISH_LEN]; ch_finish(PSK, DEVICE_ID, nn, rr, ecp, fi, NULL);
            uint8_t ad[SN_ADMIT_LEN];
            CHECK(sn_handle_finish(&dev, fi, SN_FINISH_LEN, src, port, 9000, ad) == SN_ADMIT_LEN,
                  "re-promotion: ADMIT");
            uint8_t kc[32];
            ch_session_from(PSK, DEVICE_ID, nn, rr, ecp, ad, kc, app_s2c[pass], g_kc2s, g_ks2c);
            sn_sender_init(&g_seq);
            cks[pass] = ikcp_create(0x0A0A0A00u + (IUINT32)pass, NULL);
            ikcp_setoutput(cks[pass], cli_out);
            ikcp_setmtu(cks[pass], SN_WIRE_MTU - SN_ENVELOPE_LEN);
            ikcp_nodelay(cks[pass], 1, 20, 2, 1);
            cks[pass]->stream = 1;
            ikcp_send(cks[pass], "p", 1);
            ikcp_update(cks[pass], 2000);
            CHECK(sn_handle_envelope(&dev, g_env, g_envlen, src, port, 9100) == SN_ENV_PROMOTED,
                  "re-promotion: promoted");
            gens[pass] = sn_device_current_gen(&dev);
            if (pass == 0) {
                CHECK(sn_agent_init(&agA, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                                    decomp, sizeof decomp, enc, sizeof enc) == 0,
                      "re-promotion: agent A binds the first session");
            }
        }
        CHECK(gens[0] != gens[1], "re-promotion: the second session has its own generation");
        ikcpcb *nk = dev.primary.kcp;
        int waitsnd_before = ikcp_waitsnd(nk);
        uint64_t next_before = dev.primary.app_s2c_next;

        CHECK(agA.io.write(agA.io.ctx, "stale", 5) < 0,
              "re-promotion: A's raw io write is refused");
        g_agent = &agA;
        CHECK(sn_agent_respond(&agA, 9100, 0x80, (const uint8_t *)"stale", 5) < 0,
              "re-promotion: A's response is refused");
        CHECK(ikcp_waitsnd(nk) == waitsnd_before,
              "re-promotion: nothing of A's reached the new session's stream");
        CHECK(dev.primary.app_s2c_next == next_before && next_before == 1,
              "re-promotion: A took no MessageNum from the new session");
        CHECK(sn_agent_step(&agA, 9100, 1) < 0, "re-promotion: A's step fails");
        CHECK(sn_device_session_active(&dev, gens[1]),
              "re-promotion: and none of it disturbed the new session");

        /* The new session's own agent starts its own sequence at 1, under its
         * own key: the stale agent above consumed nothing from it. */
        CHECK(sn_agent_init(&agB, &dev, &ops, raw, sizeof raw, dec, sizeof dec,
                            decomp, sizeof decomp, enc, sizeof enc) == 0 &&
              agB.io_st.gen == gens[1], "re-promotion: agent B binds the new session");
        g_agent = &agB;
        CHECK(sn_agent_respond(&agB, 9100, 0x80, (const uint8_t *)"fresh", 5) == 0,
              "re-promotion: B responds");
        uint64_t nums[8];
        int n = wire_s2c_msgnums(nk, app_s2c[1], nums, 8);
        CHECK(n == 1 && nums[0] == 1,
              "re-promotion: the new stream holds exactly B's frame, MessageNum 1, under B's key");

        for (int i = 0; i < 2; i++) if (cks[i]) ikcp_release(cks[i]);
    }

    ikcp_release(ck);
    sn_device_release_primary(&dev);
    sn_device_locks_free(&dev);
    if (failures) { printf("%d FAILURES\n", failures); return 1; }
    printf("all sn_agent_dispatch characterisation cases pass\n");
    return 0;
}
