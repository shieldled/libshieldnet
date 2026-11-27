/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* A log line a peer can trigger is written once, not once per request:
 * the pts warning (GET_DEVICE_INFO) and the uncounted dropped PIXEL_FRAME.
 * Built with SHIELDNET_LOG_ESP_IDF against a fake esp_log.h that counts
 * ESP_LOGE calls, and with CONFIG_SLED_PTS. Each case compares the count's
 * delta across its own calls, since other code paths log too. */
#include "command.h"
#include "protocol.h"
#include "shieldnet_device.h"

#include <stdio.h>
#include <string.h>

int g_esp_loge_count;

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

/* ── a device whose every op is a stub ── */
static uint8_t g_scratch[1024];
static uint16_t g_strips = 4, g_leds = 64;

static int op_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx; (void)kind; (void)body; (void)len;
    return 0;
}
static void op_get_geometry(void *ctx, shieldnet_device_geometry_t *out) {
    (void)ctx;
    out->num_strips = g_strips; out->leds_per_strip = g_leds; out->led_bpp = 3;
    out->max_payload = 32768;
}
static void op_u8(void *ctx, uint8_t v) { (void)ctx; (void)v; }
static int op_set_mode(void *ctx, uint8_t m) { (void)ctx; (void)m; return 0; }
static int op_set_output_enabled(void *ctx, bool on) { (void)ctx; (void)on; return 0; }
static bool op_publish(void *ctx, const uint8_t *px, int n) { (void)ctx; (void)px; (void)n; return true; }
static void op_set_ntp_server(void *ctx, const shieldnet_ntp_server_req_t *req) { (void)ctx; (void)req; }
static void op_void(void *ctx) { (void)ctx; }
static void op_get_status(void *ctx, shieldnet_device_status_t *out) { (void)ctx; (void)out; }
static void op_get_tx_scratch(void *ctx, uint8_t **buf, size_t *cap) {
    (void)ctx; *buf = g_scratch; *cap = sizeof g_scratch;
}
static void op_emit_event(void *ctx, shieldnet_device_event_t ev, uint8_t arg) {
    (void)ctx; (void)ev; (void)arg;
}

/* Every op except publish_pixel_frame_at, as in test_sn_command.c. */
static void full_ops(shieldnet_device_ops_t *ops) {
    memset(ops, 0, sizeof *ops);
    ops->get_geometry = op_get_geometry;
    ops->set_brightness = op_u8;
    ops->set_fps = op_u8;
    ops->set_mode = op_set_mode;
    ops->set_output_enabled = op_set_output_enabled;
    ops->publish_pixel_frame = op_publish;
    ops->set_ntp_server = op_set_ntp_server;
    ops->note_frame_dropped = op_void;
    ops->get_status = op_get_status;
    ops->get_tx_scratch = op_get_tx_scratch;
    ops->emit_event = op_emit_event;
    ops->send_response = op_send_response;
}

static int ext_handle(void *ctx, const shieldnet_device_ops_t *dev, uint8_t kind,
                      uint64_t msgnum, const uint8_t *p, size_t n) {
    (void)ctx; (void)dev; (void)kind; (void)msgnum; (void)p; (void)n;
    return SHIELDNET_EXT_UNHANDLED;
}

static void dispatch(const shieldnet_device_ops_t *ops, uint32_t kind, uint64_t mn) {
    protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
    hdr.message_type = kind; hdr.message_num = mn;
    shieldnet_command_dispatch(ops, &hdr, NULL, 0);
}

int main(void)
{
    shieldnet_device_ops_t ops;

    /* Full ops without publish_pixel_frame_at: CONFIG_SLED_PTS cannot be
     * honoured, so every caps derivation would log. This runs first: the guard
     * is process-wide. */
    full_ops(&ops);
    int before = g_esp_loge_count;
    dispatch(&ops, SLED_CMD_GET_DEVICE_INFO, 1);
    dispatch(&ops, SLED_CMD_GET_DEVICE_INFO, 2);
    CHECK(g_esp_loge_count - before == 1, "logging: the pts warning is written once");

    /* No pixel output and no way to count the dropped frames. */
    full_ops(&ops);
    ops.publish_pixel_frame = NULL;
    ops.note_frame_dropped = NULL;
    before = g_esp_loge_count;
    dispatch(&ops, SLED_CMD_PIXEL_FRAME, 3);
    dispatch(&ops, SLED_CMD_PIXEL_FRAME, 4);
    dispatch(&ops, SLED_CMD_PIXEL_FRAME, 5);
    CHECK(g_esp_loge_count - before == 1, "logging: an uncounted dropped frame is logged once");

    /* An invalid entry of the extension's: skipped, and logged once rather than
     * once per request. */
    {
        static const char *const caps[] = { "Bad", "x-ok" };
        static shieldnet_device_ext_t ext;
        full_ops(&ops);
        ext.caps = caps; ext.cap_count = 2;
        ext.handle = ext_handle;
        ops.ext = &ext;
        before = g_esp_loge_count;
        dispatch(&ops, SLED_CMD_GET_DEVICE_INFO, 6);
        dispatch(&ops, SLED_CMD_GET_DEVICE_INFO, 7);
        CHECK(g_esp_loge_count - before == 1, "logging: an invalid extension entry is logged once");
    }

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    return 0;
}
