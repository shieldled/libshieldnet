/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_demux.h"

#include <string.h>

static const uint8_t MAGIC[8] = { 'S','L','D','1','Z','0','0','1' };
#define HEADER_LEN 10
#define TYPE_INIT  0x01
#define TYPE_RETRY 0x02
#define TYPE_FIN   0x05
#define TYPE_ADMIT 0x06

sn_class sn_classify_datagram(sn_role role, const uint8_t *datagram, size_t len) {
    if (len >= HEADER_LEN && memcmp(datagram, MAGIC, 8) == 0) { /* §5 step 1 */
        switch (datagram[8]) {
        case TYPE_INIT:
            if (role == SN_ROLE_DEVICE) return SN_CLASS_INIT;
            break;
        case TYPE_RETRY:
            if (role == SN_ROLE_CLIENT) return SN_CLASS_RETRY;
            break;
        case TYPE_FIN:
            if (role == SN_ROLE_DEVICE) return SN_CLASS_FINISH;
            break;
        case TYPE_ADMIT:
            if (role == SN_ROLE_CLIENT) return SN_CLASS_ADMIT;
            break;
        default:
            break;
        }
        return SN_CLASS_DROP; /* wrong-direction, reserved, or out-of-range type */
    }
    return SN_CLASS_ENVELOPE; /* §5 step 2 */
}

sn_class sn_classify(sn_role role, int src_is_v4, const uint8_t src_a16[16],
                     const sn_prefix *local, size_t n_local,
                     const uint8_t *datagram, size_t len) {
    if (sn_source_rejected(src_is_v4, src_a16, local, n_local)) { /* §5 step 0 */
        return SN_CLASS_DROP;
    }
    return sn_classify_datagram(role, datagram, len);
}
