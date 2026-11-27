/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Forces the linker to resolve libshieldnet (root CMakeLists.txt).
 *
 * A static archive is not evidence its source list is complete: nothing
 * resolves symbols until something links it, so a missing .c file builds
 * perfectly and fails in a consumer's tree instead. src/frame.c was missing
 * from shieldnet.cmake exactly that way.
 *
 * One symbol from each layer that has ever been reached only indirectly, plus
 * frame_parse itself -- the one that was actually absent. */
#include "shieldnet/sn_client_wire.h"
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_kdf.h"

#include "frame.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    /* No real work: the point is that these resolve at link time. */
    uint8_t psk[32] = {0}, dev_id[8] = {0}, k_dev[32];
    sn_derive_kdev(psk, dev_id, k_dev);

    uint8_t dg[10] = { 'S','L','D','1','Z','0','0','1', 0x02, 0x01 };
    (void)sn_classify_datagram(SN_ROLE_CLIENT, dg, sizeof dg);

    sn_retry_msg r;
    if (sn_decode_retry(dg, sizeof dg, &r) != SN_CW_BAD_LEN) {
        printf("FAIL: a 10-octet RETRY was not refused on length\n");
        return 1;
    }

    frame_t f;
    (void)frame_parse((const uint8_t *)"", 0, &f);

    printf("link check ok\n");
    return 0;
}
