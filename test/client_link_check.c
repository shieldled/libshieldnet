/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Links the client role on its own (root CMakeLists.txt, shieldnet_client_link_check).
 *
 * This target gets SHIELDNET_CLIENT_SOURCES + the vendor sources + libsodium and
 * nothing else: no sn_device.c, no OS port. A client source that quietly starts
 * to need a device source, or an OS call, fails to link here, where
 * shieldnet_link_check (which links the union) would never notice.
 *
 * It calls every sn_client_* function. Nothing is expected to succeed beyond
 * init and the argument checks: the point is that each symbol resolves. */
#include "shieldnet/sn_client.h"

#include <stdio.h>
#include <string.h>

static void sink(void *ctx, const uint8_t *dg, size_t len) { (void)ctx; (void)dg; (void)len; }
static void on_msg(void *ctx, const uint8_t *m, size_t n) { (void)ctx; (void)m; (void)n; }
static void on_app(void *ctx, uint32_t k, const uint8_t *b, size_t n) { (void)ctx; (void)k; (void)b; (void)n; }

static uint8_t carry[2 * (SN_CS_MSG_MAX + 64 + 20)], raw[SN_CS_MSG_MAX + 64],
               dec[SN_CS_MSG_MAX + 64], decomp[SN_CS_MSG_MAX + 64], enc[SN_CS_MSG_MAX + 64],
               comp[SN_CLIENT_COMPRESS_BUF_MIN];

int main(void) {
    sn_client c;
    sn_client_config cfg;
    memset(&cfg, 0, sizeof cfg);
    if (sn_client_init(&c, &cfg) != SN_CLIENT_OK) { printf("FAIL: init\n"); return 1; }

    sn_client_set_send(&c, sink, NULL);
    sn_client_set_on_msg(&c, on_msg, NULL);
    sn_client_set_on_app(&c, on_app, NULL);
    if (sn_client_set_app_buffers(&c, carry, sizeof carry, raw, sizeof raw, dec, sizeof dec,
                                  decomp, sizeof decomp, enc, sizeof enc) != SN_CLIENT_OK ||
        sn_client_set_compress_buffer(&c, comp, sizeof comp) != SN_CLIENT_OK) {
        printf("FAIL: buffers\n");
        return 1;
    }

    /* IDLE: every sender refuses, and the accessors report their pre-ADMIT values. */
    static const uint8_t b[1] = {0};
    int bad = 0;
    bad |= sn_client_get_state(&c) != SN_CLIENT_IDLE;
    bad |= sn_client_get_end_reason(&c) != SN_CLIENT_END_NONE;
    bad |= sn_client_last_tx_num(&c) != 0;
    bad |= sn_client_max_app_body(&c) != 0;
    bad |= sn_client_session_dead(&c) != 0;
    bad |= sn_client_send(&c, b, 1, 0) != SN_CLIENT_ERR;
    bad |= sn_client_send_app(&c, 0, b, 1, 0) != SN_CLIENT_ERR;
    bad |= sn_client_send_app_padded(&c, 0, b, 1, 0) != SN_CLIENT_ERR;
    bad |= sn_client_send_app_compressed(&c, 0, b, 1, 0) != SN_CLIENT_ERR;
    bad |= sn_client_input(&c, b, 1, 0) != SN_CLIENT_FAILED;
    bad |= sn_client_tick(&c, 0) != SN_CLIENT_FAILED;
    if (bad) { printf("FAIL: IDLE client did not refuse\n"); return 1; }

    if (sn_client_take_control(&c, NULL, 0, 0) != SN_CLIENT_ERR) {
        printf("FAIL: take_control accepted an empty first message\n");
        return 1;
    }
    if (sn_client_take_control(&c, b, sizeof b, 0) != SN_CLIENT_IN_PROGRESS) {
        printf("FAIL: take_control\n");
        return 1;
    }
    sn_client_close(&c);
    if (sn_client_get_end_reason(&c) != SN_CLIENT_END_USER) {
        printf("FAIL: close did not record SN_CLIENT_END_USER\n");
        return 1;
    }
    if (sn_client_take_control_app(&c, 0x07, NULL, 0, 0) != SN_CLIENT_IN_PROGRESS) {
        printf("FAIL: take_control_app\n");
        return 1;
    }
    sn_client_close(&c);
    if (sn_client_take_control_app_padded(&c, 0x07, NULL, 0, 0) != SN_CLIENT_IN_PROGRESS) {
        printf("FAIL: take_control_app_padded\n");
        return 1;
    }
    sn_client_free(&c);

    printf("client link check ok\n");
    return 0;
}
