/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* The command core without an extension, and the hook a device plugs one
 * into (shieldnet_device_ext_t): forwarding of kinds the core does not
 * implement, the extension's DEVICE_INFO entries, its STATUS block and modes,
 * and the core's own handling of brightness and modes.
 *
 * One fake device built from op_* stubs; each case rebuilds the ops table and
 * the extension it needs. Assertions are on the bytes the device sends (ACK
 * status and detail, DEVICE_INFO fields, STATUS offsets), not only on which
 * stub ran. */
#include "command.h"
#include "payload_encode_policy.h"
#include "protocol.h"
#include "response_decode.h"
#include "shieldnet_device.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

/* ── a minimal pixel device ── */
static int g_send_calls;
static int g_ack_count; static uint8_t g_ack[160]; static size_t g_ack_len;
static uint8_t g_ack_kind, g_ack_status;
static uint8_t g_devinfo[1024]; static size_t g_devinfo_len;
static uint8_t g_status[SLED_STATUS_RESP_SIZE]; static size_t g_status_len;
static uint8_t g_scratch[2048];

static int op_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx;
    g_send_calls++;
    if (kind == SLED_RESP_ACK && len >= 2) {
        g_ack_kind = body[0]; g_ack_status = body[1]; g_ack_count++;
        g_ack_len = len <= sizeof g_ack ? len : sizeof g_ack;
        memcpy(g_ack, body, g_ack_len);
    }
    if (kind == SLED_RESP_DEVICE_INFO && len <= sizeof g_devinfo) {
        memcpy(g_devinfo, body, len); g_devinfo_len = len;
    }
    if (kind == SLED_RESP_STATUS && len == sizeof g_status) {
        memcpy(g_status, body, len); g_status_len = len;
    }
    return 0;
}
static void op_get_tx_scratch(void *ctx, uint8_t **buf, size_t *cap) {
    (void)ctx; *buf = g_scratch; *cap = sizeof g_scratch;
}
static void op_get_geometry(void *ctx, shieldnet_device_geometry_t *out) {
    (void)ctx;
    out->num_strips = 4; out->leds_per_strip = 64; out->led_bpp = 3;
    out->max_payload = 32768;
}
static int g_events;
static void op_emit_event(void *ctx, shieldnet_device_event_t ev, uint8_t arg) {
    (void)ctx; (void)ev; (void)arg; g_events++;
}
static bool op_publish_pixel_frame(void *ctx, const uint8_t *px, int n) {
    (void)ctx; (void)px; (void)n; return true;
}
static void op_note_frame_dropped(void *ctx) { (void)ctx; }

static shieldnet_device_status_t g_st;
static void op_get_status(void *ctx, shieldnet_device_status_t *out) { (void)ctx; *out = g_st; }

static int g_brightness_calls; static uint8_t g_brightness;
static void op_set_brightness(void *ctx, uint8_t v) {
    (void)ctx; g_brightness_calls++; g_brightness = v;
}
static int g_set_mode_calls; static uint8_t g_set_mode_arg; static int g_set_mode_ret;
static int op_set_mode(void *ctx, uint8_t m) {
    (void)ctx; g_set_mode_calls++; g_set_mode_arg = m; return g_set_mode_ret;
}

/* A pixel device with the core ops a command needs and no extension. */
static void base_ops(shieldnet_device_ops_t *ops) {
    memset(ops, 0, sizeof *ops);
    ops->get_geometry = op_get_geometry;
    ops->set_brightness = op_set_brightness;
    ops->set_mode = op_set_mode;
    ops->publish_pixel_frame = op_publish_pixel_frame;
    ops->note_frame_dropped = op_note_frame_dropped;
    ops->get_status = op_get_status;
    ops->get_tx_scratch = op_get_tx_scratch;
    ops->emit_event = op_emit_event;
    ops->send_response = op_send_response;
}

static void reset_counters(void) {
    g_send_calls = 0; g_ack_count = 0; g_ack_len = 0; g_ack_kind = 0xEE; g_ack_status = 0xEE;
    g_devinfo_len = 0; g_status_len = 0;
}

/* Dispatches one command and returns its ACK status, or -1 unless exactly one
 * ACK for that kind went out. */
static int send_cmd(const shieldnet_device_ops_t *ops, uint8_t kind, uint64_t mn,
                    const uint8_t *p, size_t n) {
    protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
    hdr.message_type = kind; hdr.message_num = mn;
    reset_counters();
    shieldnet_command_dispatch(ops, &hdr, p, n);
    return (g_ack_count == 1 && g_ack_kind == kind) ? g_ack_status : -1;
}
/* GET_DEVICE_INFO's ACK status; the body is in g_devinfo. */
static int send_devinfo(const shieldnet_device_ops_t *ops) {
    return send_cmd(ops, SLED_CMD_GET_DEVICE_INFO, 50, NULL, 0);
}
/* GET_STATUS's ACK status; the body is in g_status. */
static int send_status(const shieldnet_device_ops_t *ops) {
    return send_cmd(ops, SLED_CMD_GET_STATUS, 51, NULL, 0);
}

/* The detail of the last ACK, or NULL. */
static int ack_detail_is(const char *text) {
    sled_ack_t a;
    if (!sled_decode_ack(g_ack, g_ack_len, &a)) return 0;
    size_t n = strlen(text);
    return a.detail_len == n && (n == 0 || memcmp(a.detail, text, n) == 0);
}

/* GET_MODE: the reported mode byte, or -1 unless it answered OK with the
 * two-byte detail. *enabled is the second byte. */
static int get_mode(const shieldnet_device_ops_t *ops, int *enabled) {
    int st = send_cmd(ops, SLED_CMD_GET_MODE, 52, NULL, 0);
    sled_ack_t a;
    if (st != SLED_ACK_OK || !sled_decode_ack(g_ack, g_ack_len, &a) || a.detail_len != 2) return -1;
    if (enabled) *enabled = a.detail[1];
    return a.detail[0];
}
/* SET_MODE with one mode byte: the ACK status. */
static int set_mode_cmd(const shieldnet_device_ops_t *ops, uint8_t mode) {
    g_set_mode_calls = 0;
    return send_cmd(ops, SLED_CMD_SET_MODE, 53, &mode, 1);
}

/* How many fields of the last DEVICE_INFO carry this name. */
static int devinfo_count(const char *name) {
    size_t off = 0; int n = 0;
    sled_device_info_field_t f;
    while (sled_device_info_next(g_devinfo, g_devinfo_len, &off, &f)) {
        if (sled_device_info_name_is(&f, name)) n++;
    }
    return n;
}
/* Whether the last DEVICE_INFO has a field `name` with exactly this value. */
static int devinfo_value_is(const char *name, const char *value) {
    size_t off = 0;
    sled_device_info_field_t f;
    while (sled_device_info_next(g_devinfo, g_devinfo_len, &off, &f)) {
        if (sled_device_info_name_is(&f, name)) {
            size_t n = strlen(value);
            return f.value_len == n && memcmp(f.value, value, n) == 0;
        }
    }
    return 0;
}

/* ── extensions ── */
static int g_h_calls; static uint8_t g_h_kind; static uint64_t g_h_msgnum;
static uint8_t g_h_payload[16]; static size_t g_h_len;
static void note_call(uint8_t kind, uint64_t mn, const uint8_t *p, size_t n) {
    g_h_calls++; g_h_kind = kind; g_h_msgnum = mn;
    g_h_len = n;
    if (p != NULL && n <= sizeof g_h_payload) memcpy(g_h_payload, p, n);
}
/* Answers every kind it is given with an OK ACK. */
static int h_ack(void *ctx, const shieldnet_device_ops_t *dev, uint8_t kind,
                 uint64_t mn, const uint8_t *p, size_t n) {
    (void)ctx;
    note_call(kind, mn, p, n);
    return shieldnet_send_ack(dev, kind, mn, SLED_ACK_OK, NULL, 0);
}
/* Owns nothing. */
static int h_unhandled(void *ctx, const shieldnet_device_ops_t *dev, uint8_t kind,
                       uint64_t mn, const uint8_t *p, size_t n) {
    (void)ctx; (void)dev;
    note_call(kind, mn, p, n);
    return SHIELDNET_EXT_UNHANDLED;
}
static bool hm_0(void *ctx, uint8_t m) { (void)ctx; return m == 0; }
static bool hm_0_and_7(void *ctx, uint8_t m) { (void)ctx; return m == 0 || m == 7; }
static bool hm_2(void *ctx, uint8_t m) { (void)ctx; return m == 2; }
static void fs_11(void *ctx, uint8_t out[SHIELDNET_STATUS_EXT_SIZE]) {
    (void)ctx;
    for (size_t i = 0; i < SHIELDNET_STATUS_EXT_SIZE; i++) out[i] = (uint8_t)(0x11 + i);
}

static char g_big[258];

int main(void) {
    shieldnet_device_ops_t ops;
    shieldnet_device_ext_t ext;

    /* ── dispatch to the extension ── */
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_ack;
        ops.ext = &ext;
        const uint8_t payload[3] = { 1, 2, 3 };
        g_h_calls = 0;
        int st = send_cmd(&ops, 0x60, 7, payload, sizeof payload);
        sled_ack_t a;
        int ok = sled_decode_ack(g_ack, g_ack_len, &a);
        CHECK(st == SLED_ACK_OK && g_h_calls == 1 && g_h_kind == 0x60 && g_h_msgnum == 7 &&
              g_h_len == 3 && memcmp(g_h_payload, payload, 3) == 0 &&
              ok && a.orig_kind == 0x60 && a.orig_message_num == 7,
              "ext: an extension kind reaches handle, and its ACK goes out");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled;
        ops.ext = &ext;
        g_h_calls = 0;
        int st = send_cmd(&ops, 0x61, 8, NULL, 0);
        CHECK(g_h_calls == 1 && st == SLED_ACK_ERR_UNKNOWN_KIND && g_send_calls == 1,
              "ext: UNHANDLED is answered ERR_UNKNOWN_KIND");
    }
    {
        base_ops(&ops);
        ops.emit_event = NULL;
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled;
        ops.ext = &ext;
        g_h_calls = 0;
        int st = send_cmd(&ops, 0x61, 9, NULL, 0);
        CHECK(g_h_calls == 1 && st == SLED_ACK_ERR_UNKNOWN_KIND && g_send_calls == 1,
              "ext: UNHANDLED with emit_event NULL");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_ack;
        ops.ext = &ext;
        g_h_calls = 0;
        int s1 = send_cmd(&ops, 0x82, 10, NULL, 0);
        int s2 = send_cmd(&ops, 0xE0, 11, NULL, 0);
        CHECK(s1 == SLED_ACK_ERR_UNKNOWN_KIND && s2 == SLED_ACK_ERR_UNKNOWN_KIND && g_h_calls == 0,
              "ext: response kinds never reach handle");
    }
    {
        static const char *const caps[] = { "x-a" };
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.caps = caps; ext.cap_count = 1;
        ext.handle = NULL;
        ext.has_mode = hm_0;
        ext.fill_status = fs_11;
        ops.ext = &ext;
        int st = send_cmd(&ops, 0x60, 12, NULL, 0);
        int di = send_devinfo(&ops);
        int has_xa = devinfo_count("x-a");
        char buf[64];
        bool cs = shieldnet_device_caps_str(&ops, &(shieldnet_device_geometry_t){ .num_strips = 4, .leds_per_strip = 64, .led_bpp = 3 },
                                            buf, sizeof buf);
        int sm = set_mode_cmd(&ops, 0);
        int sm_detail = ack_detail_is("mode not supported");
        int sst = send_status(&ops);
        int zero = g_status_len == SLED_STATUS_RESP_SIZE;
        for (size_t i = SHIELDNET_STATUS_EXT_OFFSET; zero && i < SHIELDNET_STATUS_EXT_OFFSET + SHIELDNET_STATUS_EXT_SIZE; i++) {
            if (g_status[i] != 0) zero = 0;
        }
        CHECK(st == SLED_ACK_ERR_UNKNOWN_KIND && di == SLED_ACK_OK && has_xa == 0 &&
              cs && strstr(buf, "x-a") == NULL && sst == SLED_ACK_OK && zero &&
              sm == SLED_ACK_ERR_INVALID_ARG && sm_detail && g_set_mode_calls == 0,
              "ext: handle NULL is no extension");
    }
    {
        static const char *const caps[] = { NULL, "Bad", "x-a", "x-b", "x-c", "x-d", "x-e" };
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.caps = caps; ext.cap_count = sizeof caps / sizeof caps[0];
        ext.handle = h_unhandled;
        ops.ext = &ext;
        int di = send_devinfo(&ops);
        char buf[64];
        shieldnet_device_geometry_t geo = { .num_strips = 4, .leds_per_strip = 64, .led_bpp = 3 };
        bool cs = shieldnet_device_caps_str(&ops, &geo, buf, sizeof buf);
        CHECK(di == SLED_ACK_OK && devinfo_count("x-a") == 1 && devinfo_count("x-d") == 1 &&
              devinfo_count("x-e") == 0 && devinfo_count("Bad") == 0 &&
              cs && strcmp(buf, "pixel,x-a,x-b,x-c,x-d") == 0,
              "ext: entries beyond the cap");
    }
    {
        memset(g_big, 'a', 256); g_big[256] = '\0';
        static const shieldnet_device_field_t fields[] = { { "x-big", g_big }, { "x-n", "7" } };
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.fields = fields; ext.field_count = 2;
        ext.handle = h_unhandled;
        ops.ext = &ext;
        int di = send_devinfo(&ops);
        CHECK(di == SLED_ACK_OK && g_devinfo_len > 0 && devinfo_count("x-big") == 0 &&
              devinfo_value_is("x-n", "7"),
              "ext: an over-long field is skipped");
    }
    {
        static const char *const caps[] = { NULL, "", "pixel", "Bad", "x-ok" };
        static const shieldnet_device_field_t fields[] = { { "leds", "9" }, { "x-n", "7" } };
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.caps = caps; ext.cap_count = 5;
        ext.fields = fields; ext.field_count = 2;
        ext.handle = h_unhandled;
        ops.ext = &ext;
        int di = send_devinfo(&ops);
        sled_geometry_t g;
        int dec = sled_decode_geometry(g_devinfo, g_devinfo_len, &g);
        char buf[64];
        shieldnet_device_geometry_t geo = { .num_strips = 4, .leds_per_strip = 64, .led_bpp = 3 };
        bool cs = shieldnet_device_caps_str(&ops, &geo, buf, sizeof buf);
        CHECK(di == SLED_ACK_OK && dec && g.leds == 64 && devinfo_count("leds") == 1 &&
              devinfo_count("x-ok") == 1 && devinfo_value_is("x-n", "7") &&
              devinfo_count("pixel") == 1 && devinfo_count("Bad") == 0 &&
              cs && strcmp(buf, "pixel,x-ok") == 0,
              "ext: invalid or core-named entries are skipped");
    }
    {
        base_ops(&ops);
        int s30 = send_cmd(&ops, 0x30, 13, NULL, 0);
        int s60 = send_cmd(&ops, 0x60, 14, NULL, 0);
        int s82 = send_cmd(&ops, 0x82, 15, NULL, 0);
        /* The values the spec reserves for an extension (sled 9) are unassigned
         * to the core: 0x03 and 0x20 - 0x28. */
        int s03 = send_cmd(&ops, 0x03, 16, NULL, 0);
        int s20 = send_cmd(&ops, 0x20, 17, NULL, 0);
        int s28 = send_cmd(&ops, 0x28, 18, NULL, 0);
        CHECK(s30 == SLED_ACK_ERR_UNKNOWN_KIND && s60 == SLED_ACK_ERR_UNKNOWN_KIND &&
              s82 == SLED_ACK_ERR_UNKNOWN_KIND && s03 == SLED_ACK_ERR_UNKNOWN_KIND &&
              s20 == SLED_ACK_ERR_UNKNOWN_KIND && s28 == SLED_ACK_ERR_UNKNOWN_KIND,
              "ext: no ext, an unassigned kind is ERR_UNKNOWN_KIND");
    }
    {
        base_ops(&ops);
        reset_counters();
        int r0 = shieldnet_send_ack(&ops, SLED_CMD_PIXEL_FRAME, 1, SLED_ACK_OK, NULL, 0);
        int r1 = shieldnet_send_ack(&ops, SLED_CMD_NTP_SERVER, 2, SLED_ACK_OK, NULL, 0);
        int gated = g_send_calls;
        int r2 = shieldnet_send_ack_text(&ops, SLED_CMD_PING, 3, SLED_ACK_OK, "x");
        CHECK(r0 == 0 && r1 == 0 && gated == 0 && r2 == 0 && g_send_calls == 1 &&
              g_ack_kind == SLED_CMD_PING && ack_detail_is("x"),
              "ext: shieldnet_send_ack honours the response-free gate");
    }
    {
        static const char *const caps[] = { "x-a", "x-b" };
        static const shieldnet_device_field_t fields[] = { { "x-n", "7" } };
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.caps = caps; ext.cap_count = 2;
        ext.fields = fields; ext.field_count = 1;
        ext.handle = h_unhandled;
        ops.ext = &ext;
        int di = send_devinfo(&ops);
        char buf[64];
        shieldnet_device_geometry_t geo = { .num_strips = 4, .leds_per_strip = 64, .led_bpp = 3 };
        bool cs = shieldnet_device_caps_str(&ops, &geo, buf, sizeof buf);
        size_t l = strlen(buf);
        CHECK(di == SLED_ACK_OK && devinfo_count("x-a") == 1 && devinfo_count("x-b") == 1 &&
              devinfo_value_is("x-n", "7") && cs && l >= 8 && strcmp(buf + l - 8, ",x-a,x-b") == 0,
              "ext: caps and fields appear in DEVICE_INFO and the mDNS caps");
    }

    /* ── brightness and modes are core ── */
    {
        base_ops(&ops);
        uint8_t b = 0x55;
        g_brightness_calls = 0;
        int sb = send_cmd(&ops, SLED_CMD_SET_BRIGHTNESS, 20, &b, 1);
        int sbv = g_brightness == 0x55 && g_brightness_calls == 1;
        int sm = set_mode_cmd(&ops, 1);
        int smv = g_set_mode_calls == 1 && g_set_mode_arg == 1;
        memset(&g_st, 0, sizeof g_st); g_st.mode = 1; g_st.output_enabled = true;
        int en = 0;
        int gm = get_mode(&ops, &en);
        CHECK(sb == SLED_ACK_OK && sbv && sm == SLED_ACK_OK && smv && gm == 1 && en == 1,
              "core: SET_BRIGHTNESS, SET_MODE 1 and GET_MODE work on a pixel device without an extension");
    }
    {
        base_ops(&ops);
        int st = set_mode_cmd(&ops, 0);
        CHECK(st == SLED_ACK_ERR_INVALID_ARG && ack_detail_is("mode not supported") &&
              g_set_mode_calls == 0,
              "core: SET_MODE 0 refused without an extension");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled; ext.has_mode = hm_0;
        ops.ext = &ext;
        int st = set_mode_cmd(&ops, 0);
        CHECK(st == SLED_ACK_OK && g_set_mode_calls == 1 && g_set_mode_arg == 0,
              "core: SET_MODE 0 accepted when ext->has_mode(0)");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled; ext.has_mode = hm_0_and_7;
        ops.ext = &ext;
        int yes = set_mode_cmd(&ops, 7);
        int yes_ok = g_set_mode_calls == 1 && g_set_mode_arg == 7;
        shieldnet_device_ops_t ops2; shieldnet_device_ext_t ext2;
        base_ops(&ops2);
        memset(&ext2, 0, sizeof ext2);
        ext2.handle = h_unhandled; ext2.has_mode = hm_0;
        ops2.ext = &ext2;
        int no = set_mode_cmd(&ops2, 7);
        CHECK(yes == SLED_ACK_OK && yes_ok && no == SLED_ACK_ERR_INVALID_ARG &&
              ack_detail_is("mode not supported") && g_set_mode_calls == 0,
              "core: SET_MODE 7 accepted when ext->has_mode(7), refused when not");
    }
    {
        base_ops(&ops);
        ops.publish_pixel_frame = NULL;
        int st = set_mode_cmd(&ops, 1);
        CHECK(st == SLED_ACK_ERR_INVALID_ARG && ack_detail_is("no pixel output") &&
              g_set_mode_calls == 0,
              "core: SET_MODE 1 refused without pixel output");
    }
    {
        base_ops(&ops);
        ops.publish_pixel_frame = NULL;
        memset(&g_st, 0, sizeof g_st); g_st.mode = 5;
        int gm = get_mode(&ops, NULL);
        int sst = send_status(&ops);
        CHECK(gm == 1 && sst == SLED_ACK_OK && g_status[28] == 1,
              "core: a device with no mode reports 1");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled; ext.has_mode = hm_0;
        ops.ext = &ext;
        memset(&g_st, 0, sizeof g_st); g_st.mode = 0;
        int gm = get_mode(&ops, NULL);
        int sst = send_status(&ops);
        CHECK(gm == 0 && sst == SLED_ACK_OK && g_status[28] == 0,
              "core: a device's own mode is reported");
    }
    {
        base_ops(&ops);
        memset(&g_st, 0, sizeof g_st); g_st.mode = 0;
        int gm = get_mode(&ops, NULL);
        int sst = send_status(&ops);
        CHECK(gm == 1 && sst == SLED_ACK_OK && g_status[28] == 1,
              "core: a mode the device does not have is reported as 1");
    }
    {
        base_ops(&ops);
        memset(&g_st, 0, sizeof g_st); g_st.brightness = 0x40;
        int a = send_status(&ops);
        int a_ok = g_status[76] == 0x40;
        ops.set_brightness = NULL;
        memset(&g_st, 0, sizeof g_st);
        int b = send_status(&ops);
        CHECK(a == SLED_ACK_OK && a_ok && b == SLED_ACK_OK && g_status[76] == 0xff,
              "core: brightness is the device's");
    }
    {
        base_ops(&ops);
        ops.set_mode = NULL;
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled; ext.has_mode = hm_2;
        ops.ext = &ext;
        int st = set_mode_cmd(&ops, 2);
        CHECK(st == SLED_ACK_ERR_INVALID_ARG, "core: ext mode with set_mode NULL");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled;   /* has_mode NULL */
        ops.ext = &ext;
        int st = set_mode_cmd(&ops, 0);
        int det = ack_detail_is("mode not supported");
        shieldnet_device_ops_t ops2 = ops;
        ops2.publish_pixel_frame = NULL;
        memset(&g_st, 0, sizeof g_st); g_st.mode = 0;
        int gm = get_mode(&ops2, NULL);
        CHECK(st == SLED_ACK_ERR_INVALID_ARG && det && gm == 1,
              "core: ext with has_mode NULL");
    }
    {
        base_ops(&ops);
        ops.publish_pixel_frame = NULL;
        ops.set_mode = NULL;
        int a = set_mode_cmd(&ops, 0);
        base_ops(&ops);
        ops.set_mode = NULL;
        int b = set_mode_cmd(&ops, 1);
        CHECK(a == SLED_ACK_ERR_INVALID_ARG && b == SLED_ACK_OK,
              "core: SET_MODE without a set_mode op");
    }

    /* ── the STATUS extension block ── */
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled; ext.fill_status = fs_11;
        ops.ext = &ext;
        memset(&g_st, 0, sizeof g_st); g_st.brightness = 0x33; g_st.target_fps = 25;
        int st = send_status(&ops);
        int blk = g_status_len == SLED_STATUS_RESP_SIZE;
        for (size_t i = 0; blk && i < SHIELDNET_STATUS_EXT_SIZE; i++) {
            if (g_status[SHIELDNET_STATUS_EXT_OFFSET + i] != (uint8_t)(0x11 + i)) blk = 0;
        }
        CHECK(st == SLED_ACK_OK && blk && g_status[SHIELDNET_STATUS_EXT_OFFSET - 1] == 0 &&
              g_status[76] == 0x33 && g_status[77] == 25,
              "ext: STATUS bytes 32-75 come from fill_status");
    }
    {
        base_ops(&ops);
        memset(&ext, 0, sizeof ext);
        ext.handle = h_unhandled;   /* fill_status NULL */
        ops.ext = &ext;
        memset(&g_st, 0, sizeof g_st);
        int st = send_status(&ops);
        int zero = g_status_len == SLED_STATUS_RESP_SIZE;
        for (size_t i = SHIELDNET_STATUS_EXT_OFFSET; zero && i < 76; i++) {
            if (g_status[i] != 0) zero = 0;
        }
        CHECK(st == SLED_ACK_OK && zero, "ext: no fill_status sends zero");
    }

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    return 0;
}
