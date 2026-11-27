/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* sn_primary_send must report a short send as fatal.
 *
 * ikcp_send has one success-shaped partial return: in stream mode, when the
 * message is appended to a partly filled tail segment and the remainder would
 * need IKCP_WND_RCV (128) or more segments, it returns the bytes it appended
 * and drops the rest. sn_primary_send used to pass that count straight back,
 * and io_write treats any rc >= 0 as "written whole" -- so the stream carried
 * the front of a frame and the caller reported success.
 *
 * The default SN_SEND_QUEUE_MAX refuses such a message before ikcp_send sees
 * it, which is why this target is built with the cap raised: it is the one
 * configuration in which the path is reachable, and a deployment is free to
 * choose it (sn_device.h makes the cap overridable).
 */
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

static int null_output(const char *buf, int len, ikcpcb *kcp, void *user) {
    (void)buf; (void)len; (void)kcp; (void)user;
    return 0;
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium\n"); return 1; }
    CHECK(SN_SEND_QUEUE_MAX > 130 * 1400, "built with the cap raised past 128 segments");

    uint8_t psk[32], id[8] = {1,2,3,4,5,6,7,8}, cs[32], ae[8] = {0,1,2,3,4,5,6,7};
    memset(psk, 0x11, 32); memset(cs, 0x22, 32);
    sn_device dev;
    uint8_t kd[32]; sn_derive_kdev(psk, id, kd);
    sn_device_init_kdev(&dev, kd, id, cs, ae, NULL, 0, 8000);
    sn_device_locks_init(&dev);

    /* A primary by hand: the send path needs only the KCP object, the flags
     * and the generation. Quiesced, so nothing flushes and the queue holds
     * exactly what ikcp_send left in it. */
    ikcpcb *k = ikcp_create(0x5E5E5E5Eu, &dev);
    ikcp_setoutput(k, null_output);
    ikcp_setmtu(k, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    k->stream = 1;
    dev.primary.kcp = k;
    dev.primary.active = 1;
    dev.primary.generation = 7;
    dev.primary.quiesced = 1;

    /* A partly filled tail segment for the next message to append to. */
    CHECK(sn_primary_send(&dev, (const uint8_t *)"ab", 2, 9000) == 2,
          "a small send is queued whole and reports its length");

    int mss = (int)k->mss;
    int len = 130 * mss;
    static uint8_t big[130 * 1400];
    memset(big, 0x5A, sizeof big);
    int direct_probe = mss - 2; /* what ikcp_send appends before giving up */
    int rc = sn_primary_send(&dev, big, len, 9000);
    printf("     [short] len=%d appended-then-dropped=%d rc=%d\n", len, direct_probe, rc);
    CHECK(rc == -1, "a short send is fatal (-1), not a byte count the caller takes as success");
    CHECK(rc != SN_SEND_QUEUE_FULL, "and not the retryable queue-full code");

    sn_device_release_primary(&dev);
    sn_device_locks_free(&dev);
    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all short-send cases pass\n");
    return 0;
}
