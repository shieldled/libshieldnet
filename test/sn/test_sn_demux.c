/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §5 demux: the same routing cases as goshieldnet/v1/demux_test.go. Pure
 * classifier — no golden vector; the cases are the spec, both sides must agree. */
#include "shieldnet/sn_demux.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static const uint8_t MAGIC[8] = { 'S','L','D','1','Z','0','0','1' };

/* device interface 192.168.4.1/24 + fd00::abcd/64 (as in test_sn_source.c) */
static void local_prefixes(sn_prefix out[2]) {
    memset(out, 0, 2 * sizeof(sn_prefix));
    out[0].a16[10] = 0xff; out[0].a16[11] = 0xff;
    out[0].a16[12] = 192; out[0].a16[13] = 168; out[0].a16[14] = 4; out[0].a16[15] = 1;
    out[0].is_v4 = 1; out[0].bits = 24;
    out[1].a16[0] = 0xfd; out[1].a16[14] = 0xab; out[1].a16[15] = 0xcd;
    out[1].is_v4 = 0; out[1].bits = 64;
}

static void v4(uint8_t a[16], uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    memset(a, 0, 16); a[10] = 0xff; a[11] = 0xff;
    a[12] = b; a[13] = c; a[14] = d; a[15] = e;
}

static void ctrl(uint8_t *buf, size_t n, uint8_t type) {
    memset(buf, 0, n);
    memcpy(buf, MAGIC, 8);
    buf[8] = type;
    buf[9] = 0x01; /* VERSION */
}

static void expect(const char *name, sn_class got, sn_class want) {
    if (got != want) { printf("FAIL %s: got %d want %d\n", name, got, want); failures++; }
    else { printf("ok   %s\n", name); }
}

int main(void) {
    sn_prefix local[2];
    local_prefixes(local);
    uint8_t good[16]; v4(good, 192, 168, 4, 2);
    uint8_t buf[256];

    /* step 0: rejected source drops before magic/type is examined */
    uint8_t mcast[16]; v4(mcast, 224, 0, 0, 1);
    ctrl(buf, 256, 0x01);
    expect("rejected source drops", sn_classify(SN_ROLE_DEVICE, 1, mcast, local, 2, buf, 256), SN_CLASS_DROP);

    /* direction filtering */
    ctrl(buf, 256, 0x01); expect("device INIT",   sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 256), SN_CLASS_INIT);
    ctrl(buf, 256, 0x05); expect("device FINISH", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 256), SN_CLASS_FINISH);
    ctrl(buf, 84,  0x02); expect("device RETRY drop", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 84), SN_CLASS_DROP);
    ctrl(buf, 82,  0x06); expect("device ADMIT drop", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 82), SN_CLASS_DROP);
    ctrl(buf, 84,  0x02); expect("client RETRY",  sn_classify(SN_ROLE_CLIENT, 1, good, local, 2, buf, 84), SN_CLASS_RETRY);
    ctrl(buf, 82,  0x06); expect("client ADMIT",  sn_classify(SN_ROLE_CLIENT, 1, good, local, 2, buf, 82), SN_CLASS_ADMIT);
    ctrl(buf, 256, 0x01); expect("client INIT drop",   sn_classify(SN_ROLE_CLIENT, 1, good, local, 2, buf, 256), SN_CLASS_DROP);
    ctrl(buf, 256, 0x05); expect("client FINISH drop", sn_classify(SN_ROLE_CLIENT, 1, good, local, 2, buf, 256), SN_CLASS_DROP);

    /* reserved / unknown types drop */
    uint8_t reserved[] = {0x00, 0x03, 0x04, 0x07, 0xff};
    for (size_t i = 0; i < sizeof(reserved); i++) {
        ctrl(buf, 256, reserved[i]);
        char nm[32]; snprintf(nm, sizeof(nm), "reserved type %#x drop", reserved[i]);
        expect(nm, sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 256), SN_CLASS_DROP);
    }

    /* envelope fallthrough */
    memset(buf, 0, 100);
    expect("non-magic 100B envelope", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 100), SN_CLASS_ENVELOPE);
    expect("3B envelope", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 3), SN_CLASS_ENVELOPE);
    memcpy(buf, MAGIC, 8); /* 8B magic-only, no type octet readable */
    expect("8B magic-only envelope", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 8), SN_CLASS_ENVELOPE);

    /* wrong-length control still routes by type (decoder checks length) */
    ctrl(buf, 100, 0x01);
    expect("short INIT routes to INIT", sn_classify(SN_ROLE_DEVICE, 1, good, local, 2, buf, 100), SN_CLASS_INIT);

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all demux cases agree\n");
    return 0;
}
