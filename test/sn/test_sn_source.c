/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §4.3 source predicate: the same accept/reject sets as goshieldnet/v1's
 * source_test.go, hardcoded as 16-octet addresses. No golden vector — the sets
 * themselves are the spec, and both implementations must agree on every case. */
#include "shieldnet/sn_source.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

/* v4-mapped 16-octet address from a.b.c.d */
static void v4(uint8_t out[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    memset(out, 0, 16);
    out[10] = 0xff; out[11] = 0xff;
    out[12] = a; out[13] = b; out[14] = c; out[15] = d;
}

static void expect(const char *name, int is_v4, const uint8_t a16[16],
                   const sn_prefix *local, size_t n, int want_reject) {
    int got = sn_source_rejected(is_v4, a16, local, n) ? 1 : 0;
    if (got != want_reject) {
        printf("FAIL %s: got reject=%d want %d\n", name, got, want_reject);
        failures++;
    } else {
        printf("ok   %s (%s)\n", name, want_reject ? "reject" : "accept");
    }
}

int main(void) {
    /* Interface: 192.168.4.1/24 and a v6 ULA fd00::abcd/64. */
    sn_prefix local[2];
    v4(local[0].a16, 192, 168, 4, 1); local[0].is_v4 = 1; local[0].bits = 24;
    memset(local[1].a16, 0, 16);
    local[1].a16[0] = 0xfd; local[1].a16[14] = 0xab; local[1].a16[15] = 0xcd;
    local[1].is_v4 = 0; local[1].bits = 64;

    uint8_t a[16];

    /* canonical_source layout */
    v4(a, 192, 168, 4, 2);
    uint8_t cs[18];
    sn_canonical_source(a, 0x1234, cs);
    if (cs[10] != 0xff || cs[11] != 0xff || cs[12] != 192 || cs[16] != 0x12 || cs[17] != 0x34) {
        printf("FAIL canonical_source layout\n"); failures++;
    } else { printf("ok   canonical_source\n"); }

    /* Accept set. */
    v4(a,192,168,4,2);   expect("192.168.4.2", 1, a, local, 2, 0);
    v4(a,10,0,0,5);      expect("10.0.0.5", 1, a, local, 2, 0);
    v4(a,172,16,0,5);    expect("172.16.0.5", 1, a, local, 2, 0);
    v4(a,169,254,1,1);   expect("169.254.1.1", 1, a, local, 2, 0);
    v4(a,100,64,0,1);    expect("100.64.0.1", 1, a, local, 2, 0);
    memset(a,0,16); a[0]=0xfe; a[1]=0x80; a[15]=1; expect("fe80::1", 0, a, local, 2, 0);
    memset(a,0,16); a[0]=0xfd; a[15]=1;            expect("fd00::1", 0, a, local, 2, 0);
    memset(a,0,16); a[0]=0x20; a[1]=0x01; a[2]=0x0d; a[3]=0xb8; a[15]=1;
                                                    expect("2001:db8::1", 0, a, local, 2, 0);

    /* Reject set. */
    v4(a,224,0,0,1);     expect("224.0.0.1", 1, a, local, 2, 1);
    v4(a,239,1,1,1);     expect("239.1.1.1", 1, a, local, 2, 1);
    v4(a,255,255,255,255); expect("255.255.255.255", 1, a, local, 2, 1);
    v4(a,192,168,4,255); expect("192.168.4.255 (subnet bcast)", 1, a, local, 2, 1);
    v4(a,0,0,0,0);       expect("0.0.0.0", 1, a, local, 2, 1);
    v4(a,127,0,0,1);     expect("127.0.0.1", 1, a, local, 2, 1);
    v4(a,192,168,4,1);   expect("192.168.4.1 (own addr)", 1, a, local, 2, 1);
    memset(a,0,16); a[0]=0xff; a[1]=0x02; a[15]=1; expect("ff02::1", 0, a, local, 2, 1);
    memset(a,0,16);                                 expect("::", 0, a, local, 2, 1);
    memset(a,0,16); a[15]=1;                        expect("::1", 0, a, local, 2, 1);
    /* ::ffff:1.2.3.4 as a genuine v6 source (is_v4=0) */
    v4(a,1,2,3,4);                                   expect("::ffff:1.2.3.4 as v6", 0, a, local, 2, 1);
    /* ::0.0.1.2 IPv4-compatible */
    memset(a,0,16); a[14]=1; a[15]=2;                expect("::0.0.1.2", 0, a, local, 2, 1);
    /* device's own v6 */
    memset(a,0,16); a[0]=0xfd; a[14]=0xab; a[15]=0xcd; expect("fd00::abcd (own)", 0, a, local, 2, 1);

    /* Prefix length bounds. /31 is RFC 3021 point-to-point and /32 a host
     * route: neither has a broadcast, so the all-ones host (the peer) is a
     * legitimate source. The interface's own address is still rejected. */
    {
        sn_prefix p31[1];
        v4(p31[0].a16, 10, 0, 0, 0); p31[0].is_v4 = 1; p31[0].bits = 31;
        v4(a,10,0,0,1);  expect("/31 peer 10.0.0.1", 1, a, p31, 1, 0);
        v4(a,10,0,0,0);  expect("/31 own 10.0.0.0", 1, a, p31, 1, 1);
        sn_prefix p32[1];
        v4(p32[0].a16, 10, 0, 0, 7); p32[0].is_v4 = 1; p32[0].bits = 32;
        v4(a,10,0,0,8);  expect("/32 other 10.0.0.8", 1, a, p32, 1, 0);
        v4(a,10,0,0,7);  expect("/32 own 10.0.0.7", 1, a, p32, 1, 1);
        sn_prefix p30[1];
        v4(p30[0].a16, 10, 0, 0, 1); p30[0].is_v4 = 1; p30[0].bits = 30;
        v4(a,10,0,0,3);  expect("/30 bcast 10.0.0.3", 1, a, p30, 1, 1);
        v4(a,10,0,0,2);  expect("/30 peer 10.0.0.2", 1, a, p30, 1, 0);

        /* Out of range: the old mask loop indexed below a16 (ASan stack
         * overflow) for a negative prefix. A misconfigured table fails closed. */
        sn_prefix bad[1];
        v4(bad[0].a16, 10, 0, 0, 1); bad[0].is_v4 = 1;
        bad[0].bits = -200; v4(a,10,0,0,2); expect("bits -200: v4 fails closed", 1, a, bad, 1, 1);
        bad[0].bits = -1;                   expect("bits -1: v4 fails closed", 1, a, bad, 1, 1);
        bad[0].bits = 33;                   expect("bits 33: v4 fails closed", 1, a, bad, 1, 1);
        /* a v6 source is not judged against a v4 prefix's length */
        memset(a,0,16); a[0]=0xfd; a[15]=1; expect("bits -200: v6 source unaffected", 0, a, bad, 1, 0);
    }

    /* sn_source_rejected_a16 derives the family from the mapped form */
    v4(a,192,168,4,255);
    if (!sn_source_rejected_a16(a, local, 2)) { printf("FAIL a16: v4 bcast\n"); failures++; }
    else printf("ok   a16: mapped bcast rejected as v4\n");
    v4(a,192,168,4,2);
    if (sn_source_rejected_a16(a, local, 2)) { printf("FAIL a16: v4 host\n"); failures++; }
    else printf("ok   a16: mapped host accepted as v4\n");
    memset(a,0,16); a[14]=1; a[15]=2;
    if (!sn_source_rejected_a16(a, local, 2)) { printf("FAIL a16: v4-compat\n"); failures++; }
    else printf("ok   a16: ::0.0.1.2 rejected as v6\n");

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all source cases agree\n");
    return 0;
}
