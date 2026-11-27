/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* The command core's bounds on values it hands to device ops, and its golden
 * vectors (spec/application.md Appendix A).
 *
 * These pin the zeroing of the structs an op fills -- whose unfilled bytes
 * otherwise go on the wire --, the encoders that mirror the parsers, the
 * timing and NTP_SERVER paths, and the exact bytes of the STATUS, ACK and
 * DEVICE_INFO vectors.
 */
#include "command.h"
#include "command_encode.h"
#include "command_parse.h"
#include "command_response_policy.h"
#include "frame.h"
#include "payload_encode_policy.h"
#include "protocol.h"
#include "response_decode.h"
#include "shieldnet_device.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

/* ── a minimal device ── */
static int g_geo_saw_zeroed;
static uint8_t g_scratch[2048];

static uint8_t g_status[SLED_STATUS_RESP_SIZE]; static size_t g_status_len;
static int g_send_calls;
static uint8_t g_devinfo[256]; static size_t g_devinfo_len;
static uint8_t g_ack_kind, g_ack_status; static int g_ack_count;
static uint8_t g_ack[64]; static size_t g_ack_len;   /* the last ACK's bytes */
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
static int all_zero(const void *p, size_t n) {
    const uint8_t *b = p; for (size_t i = 0; i < n; i++) if (b[i]) return 0; return 1;
}
static uint16_t g_geo_strips = 4, g_geo_leds = 64;
static uint32_t g_geo_envelope; static uint8_t g_geo_bpp;   /* 0 unless a case sets them */
static void op_get_geometry(void *ctx, shieldnet_device_geometry_t *out) {
    (void)ctx;
    g_geo_saw_zeroed = all_zero(out, sizeof *out);
    out->num_strips = g_geo_strips; out->leds_per_strip = g_geo_leds; /* leaves the rest unset */
    out->max_payload = g_geo_envelope; out->led_bpp = g_geo_bpp;
}
/* Dispatch one command and report its ACK status, or -1 if no single ACK for
 * that kind went out. */
static int send_cmd(const shieldnet_device_ops_t *ops, uint8_t kind, const uint8_t *p, size_t n) {
    protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
    hdr.message_type = kind; hdr.message_num = 103;
    g_ack_count = 0;
    shieldnet_command_dispatch(ops, &hdr, p, n);
    return (g_ack_count == 1 && g_ack_kind == kind) ? g_ack_status : -1;
}
static int g_commands;
static void op_note_command(void *ctx) { (void)ctx; g_commands++; }
/* What GET_STATUS reports for `commands`, read when get_status runs. */
static int g_commands_at_status;
static shieldnet_device_status_t g_st;
static void op_get_status(void *ctx, shieldnet_device_status_t *out) {
    (void)ctx; *out = g_st; g_commands_at_status = g_commands;
}
static int g_published, g_dropped;
static bool op_publish_pixel_frame(void *ctx, const uint8_t *px, int n) {
    (void)ctx; (void)px; (void)n; g_published++; return true;
}
static int g_published_at; static int64_t g_at_fn, g_at_nb, g_at_na;
static bool op_publish_pixel_frame_at(void *ctx, const uint8_t *px, int n,
                                      int64_t fn, int64_t nb, int64_t na) {
    (void)ctx; (void)px; (void)n; g_published_at++;
    g_at_fn = fn; g_at_nb = nb; g_at_na = na; return true;
}
static void op_note_frame_dropped(void *ctx) { (void)ctx; g_dropped++; }
static int g_events;
static void op_emit_event(void *ctx, shieldnet_device_event_t ev, uint8_t arg) {
    (void)ctx; (void)ev; (void)arg; g_events++;
}
static int g_ntp_calls; static shieldnet_ntp_server_req_t g_ntp; static uint8_t g_ntp_addr[256];
static void op_set_ntp_server(void *ctx, const shieldnet_ntp_server_req_t *req) {
    (void)ctx;
    g_ntp_calls++; g_ntp = *req;
    memcpy(g_ntp_addr, req->addr, req->addr_len); g_ntp.addr = g_ntp_addr;
}
/* What op_set_output_enabled returns: 0 unless a case sets it. */
static int g_op_err;
static void op_set_brightness(void *ctx, uint8_t v) { (void)ctx; (void)v; }
static void op_set_fps(void *ctx, uint8_t v) { (void)ctx; (void)v; }
static int g_set_mode_calls;
static int op_set_mode(void *ctx, uint8_t m) { (void)ctx; (void)m; g_set_mode_calls++; return 0; }
static int op_set_output_enabled(void *ctx, bool on) { (void)ctx; (void)on; return g_op_err; }
/* Every op except publish_pixel_frame_at: with it set, PIXEL_FRAME would go
 * there instead of to publish_pixel_frame, which the cases below count. */
static void full_ops(shieldnet_device_ops_t *ops) {
    memset(ops, 0, sizeof *ops);
    ops->get_geometry = op_get_geometry;
    ops->set_brightness = op_set_brightness;
    ops->set_fps = op_set_fps;
    ops->set_mode = op_set_mode;
    ops->set_output_enabled = op_set_output_enabled;
    ops->publish_pixel_frame = op_publish_pixel_frame;
    ops->set_ntp_server = op_set_ntp_server;
    ops->note_frame_dropped = op_note_frame_dropped;
    ops->get_status = op_get_status;
    ops->get_tx_scratch = op_get_tx_scratch;
    ops->emit_event = op_emit_event;
    ops->send_response = op_send_response;
}

/* noinline, or the frame folds into main's and dirties nothing below it. */
__attribute__((noinline)) static void dirty_stack(void) {
    volatile uint8_t junk[16384];
    for (size_t i = 0; i < sizeof junk; i++) junk[i] = 0xA5;
}

int main(void) {
    /* ── through dispatch: zeroed op outputs ── */
    {
        shieldnet_device_ops_t ops; full_ops(&ops);

        /* Dirty the stack the handler's locals will occupy: a call at the same
         * depth as the dispatch below, so its frame overlaps the handler's.
         * ASan's stack layout hides this (the checks then pass either way);
         * the plain build is the one that catches a missing memset. */
        dirty_stack();

        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        /* Every get_geometry call site, not just one: each handler has its own. */
        dirty_stack(); g_geo_saw_zeroed = 0;
        hdr.message_type = SLED_CMD_GET_DEVICE_INFO; hdr.message_num = 4;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_geo_saw_zeroed, "geometry: GET_DEVICE_INFO hands the op a zeroed struct");

        uint8_t sm[4] = { 1, 0, 0, 0 };   /* mode 1, so the pixel check runs */
        dirty_stack(); g_geo_saw_zeroed = 0;
        hdr.message_type = SLED_CMD_SET_MODE; hdr.message_num = 44;
        shieldnet_command_dispatch(&ops, &hdr, sm, sizeof sm);
        CHECK(g_geo_saw_zeroed, "geometry: SET_MODE hands the op a zeroed struct");
        /* A frame frame_parse refuses (under 28 bytes): the handler's own fetch
         * never runs, so this sees the dispatch-level fetch alone. */
        uint8_t bad_pf[8] = {0};
        dirty_stack(); g_geo_saw_zeroed = 0;
        hdr.message_type = SLED_CMD_PIXEL_FRAME; hdr.message_num = 46;
        shieldnet_command_dispatch(&ops, &hdr, bad_pf, sizeof bad_pf);
        CHECK(g_geo_saw_zeroed, "geometry: PIXEL_FRAME dispatch hands the op a zeroed struct");

        uint8_t pf[28 + 4] = {0};
        pf[27] = 4;   /* buffer_length = one pixel */
        dirty_stack(); g_geo_saw_zeroed = 0;
        hdr.message_type = SLED_CMD_PIXEL_FRAME; hdr.message_num = 5;
        shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf);
        CHECK(g_geo_saw_zeroed, "geometry: PIXEL_FRAME hands the op a zeroed struct");

        /* Capacity in 64 bits: 32768 x 32768 x 4 is exactly 2^32, which a 32-bit
         * size_t (the ESP32's) wraps to 0 and then refuses every frame. On a
         * 64-bit host size_t cannot wrap, so this pins the behaviour rather than
         * reproducing the ESP32 failure. */
        g_geo_strips = 32768; g_geo_leds = 32768; g_published = g_dropped = 0;
        hdr.message_type = SLED_CMD_PIXEL_FRAME; hdr.message_num = 6;
        shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf);
        CHECK(g_published == 1 && g_dropped == 0,
              "pixel_frame: a 2^32-byte geometry accepts a one-pixel frame");
        g_geo_strips = 65535; g_geo_leds = 65535; g_published = g_dropped = 0;
        shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf);
        CHECK(g_published == 1 && g_dropped == 0,
              "pixel_frame: the largest geometry accepts a one-pixel frame");
        g_geo_strips = 4; g_geo_leds = 64;
    }

    /* ── the 28-byte PIXEL_FRAME header (shared golden vector, 32 bytes) ── */
    {
        static const uint8_t v[32] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
            0x17,0x97,0x9c,0xfe,0x3d,0x85,0xcd,0x15,
            0x17,0x97,0x9c,0xfe,0x3e,0x1e,0x63,0x95,
            0x00,0x00,0x00,0x04,0x01,0x02,0x03,0x04 };
        frame_t f; memset(&f, 0, sizeof f);
        CHECK(frame_parse(v, sizeof v, &f) == 0, "frame: the golden vector parses");
        CHECK(f.frame_number == 1, "frame: frame_number");
        CHECK(f.not_before_ns == INT64_C(1700000000123456789), "frame: not_before_ns");
        CHECK(f.not_after_ns == INT64_C(1700000000133456789), "frame: not_after_ns");
        CHECK(f.buffer_length == 4, "frame: buffer_length");
        CHECK(f.pixels == v + 28 && f.pixels[0] == 1 && f.pixels[1] == 2 &&
              f.pixels[2] == 3 && f.pixels[3] == 4, "frame: pixels");

        /* What the old 20-byte layout would have accepted: be32 7 at offset 16. */
        uint8_t old[27] = {0};
        old[19] = 7;
        CHECK(frame_parse(old, sizeof old, &f) != 0, "frame: a 27-byte old-layout frame is refused");

        uint8_t eb[64];
        const char *caps[] = { "pixel" };
        sled_device_info_fields_t di = { .envelope = 79, .strips = 1, .leds = 1, .bpp = 3,
                                         .capabilities = caps, .capability_count = 1 };
        size_t out_len = 0;
        CHECK(!sled_encode_device_info(&di, eb, sizeof eb, &out_len),
              "device_info: envelope 79 refused");
        di.envelope = 80;
        CHECK(sled_encode_device_info(&di, eb, sizeof eb, &out_len),
              "device_info: envelope 80 accepted");
    }

    /* ── spec/application.md Appendix A.5: DEVICE_INFO (47 bytes), and the same with
     *    pts appended (52 bytes). ── */
    {
        static const uint8_t a5[47] = {
            0x08,'e','n','v','e','l','o','p','e', 0x05,'3','2','7','6','8',
            0x06,'s','t','r','i','p','s', 0x01,'4',
            0x04,'l','e','d','s', 0x04,'1','0','2','4',
            0x03,'b','p','p', 0x01,'3',
            0x05,'p','i','x','e','l', 0x00 };
        static const uint8_t a5_pts[52] = {
            0x08,'e','n','v','e','l','o','p','e', 0x05,'3','2','7','6','8',
            0x06,'s','t','r','i','p','s', 0x01,'4',
            0x04,'l','e','d','s', 0x04,'1','0','2','4',
            0x03,'b','p','p', 0x01,'3',
            0x05,'p','i','x','e','l', 0x00,
            0x03,'p','t','s', 0x00 };
        uint8_t eb[64]; size_t n = 0;
        const char *caps[] = { "pixel" };
        const char *caps_pts[] = { "pixel", "pts" };
        sled_device_info_fields_t di = { .envelope = 32768, .strips = 4, .leds = 1024, .bpp = 3,
                                         .capabilities = caps, .capability_count = 1 };
        int ok1 = sled_encode_device_info(&di, eb, sizeof eb, &n) &&
                  n == sizeof a5 && memcmp(eb, a5, sizeof a5) == 0;
        di.capabilities = caps_pts; di.capability_count = 2;
        int ok2 = sled_encode_device_info(&di, eb, sizeof eb, &n) &&
                  n == sizeof a5_pts && memcmp(eb, a5_pts, sizeof a5_pts) == 0;
        CHECK(ok1 && ok2, "sled A.5: the encoder gives the 47-byte and 52-byte vectors");
        sled_geometry_t g;
        CHECK(sled_decode_geometry(a5, sizeof a5, &g) && g.envelope == 32768 &&
              g.strips == 4 && g.leds == 1024 && g.bpp == 3 &&
              sled_device_info_has(a5, sizeof a5, "pixel") &&
              !sled_device_info_has(a5, sizeof a5, "pts"),
              "sled A.5: the 47-byte vector decodes");
    }

    /* ── spec/application.md Appendix A.4: STATUS (78 bytes) ── */
    {
        static const char a41[] =
            "0102030405060708111213141516171821222324252627283132333401010100"
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            "c0c1c2c3c4c5c6c7c8c9cacb901e";
        static const char a42[] =
            "0102030405060708111213141516171821222324252627283132333401010100"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "000000000000000000000000901e";
        uint8_t want[SLED_STATUS_RESP_SIZE], want0[SLED_STATUS_RESP_SIZE];
        for (size_t i = 0; i < sizeof want; i++) {
            unsigned a, b;
            sscanf(&a41[2 * i], "%2x", &a); want[i] = (uint8_t)a;
            sscanf(&a42[2 * i], "%2x", &b); want0[i] = (uint8_t)b;
        }
        sled_status_resp_fields_t f; memset(&f, 0, sizeof f);
        f.frame_count = UINT64_C(0x0102030405060708);
        f.command_count = UINT64_C(0x1112131415161718);
        f.pixel_frames_dropped = UINT64_C(0x2122232425262728);
        f.led_refresh_errors = 0x31323334;
        f.mode = 1; f.connected = true; f.output_enabled = true;
        for (size_t i = 0; i < SLED_STATUS_EXT_SIZE; i++) f.ext[i] = (uint8_t)(0xa0 + i);
        f.brightness = 0x90; f.target_fps = 0x1e;
        uint8_t got[SLED_STATUS_RESP_SIZE];
        sled_encode_status_resp(&f, got);
        CHECK(memcmp(got, want, sizeof got) == 0, "sled A.4.1: the encoder gives the 78-byte vector");
        sled_status_resp_fields_t d;
        CHECK(sled_decode_status_resp(want, sizeof want, &d) &&
              d.frame_count == f.frame_count && d.command_count == f.command_count &&
              d.pixel_frames_dropped == f.pixel_frames_dropped &&
              d.led_refresh_errors == f.led_refresh_errors && d.mode == 1 && d.connected &&
              d.output_enabled && memcmp(d.ext, f.ext, sizeof d.ext) == 0 &&
              d.brightness == 0x90 && d.target_fps == 0x1e,
              "sled A.4.1: the vector decodes to its fields");

        /* A.4.2, through dispatch: a device with no extension. */
        shieldnet_device_ops_t ops; full_ops(&ops);
        memset(&g_st, 0, sizeof g_st);
        g_st.frame_count = f.frame_count; g_st.command_count = f.command_count;
        g_st.pixel_frames_dropped = f.pixel_frames_dropped;
        g_st.led_refresh_errors = f.led_refresh_errors;
        g_st.mode = 1; g_st.connected = true; g_st.output_enabled = true;
        g_st.brightness = 0x90; g_st.target_fps = 0x1e;
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = SLED_CMD_GET_STATUS; hdr.message_num = 8;
        g_status_len = 0;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_status_len == SLED_STATUS_RESP_SIZE && memcmp(g_status, want0, sizeof want0) == 0,
              "sled A.4.2: a device with no extension sends the zero block");
        memset(&g_st, 0, sizeof g_st);
    }

    /* ── spec/application.md Appendix A.3: ACK (36 bytes). The dispatcher's own
     *    SET_FPS refusal carries no detail, so this is an encoder test. ── */
    {
        static const char a3[] =
            "0201000001020304050607080016667073206f7574206f662072616e676520312d323535";
        uint8_t want[36];
        for (size_t i = 0; i < sizeof want; i++) {
            unsigned a; sscanf(&a3[2 * i], "%2x", &a); want[i] = (uint8_t)a;
        }
        static const char detail[] = "fps out of range 1-255";
        uint8_t got[SLED_ACK_MAX_SIZE]; size_t n = 0;
        CHECK(sled_encode_ack(SLED_CMD_SET_FPS, SLED_ACK_ERR_INVALID_ARG, UINT64_C(0x0102030405060708),
                              (const uint8_t *)detail, strlen(detail), got, sizeof got, &n) &&
              n == sizeof want && memcmp(got, want, sizeof want) == 0,
              "sled A.3: the encoder gives the 36-byte ACK vector");
        sled_ack_t a;
        CHECK(sled_decode_ack(want, sizeof want, &a) && a.orig_kind == SLED_CMD_SET_FPS &&
              a.status == SLED_ACK_ERR_INVALID_ARG &&
              a.orig_message_num == UINT64_C(0x0102030405060708) &&
              a.detail_len == strlen(detail) && memcmp(a.detail, detail, a.detail_len) == 0,
              "sled A.3: the ACK vector decodes to its fields");
    }

    /* ── DEVICE_INFO bytes through dispatch: the 47-byte vector (spec A.5), plus the
     *    pts field when compiled with CONFIG_SLED_PTS (the 52-byte vector) ── */
    {
        static const uint8_t base[47] = {
            0x08,'e','n','v','e','l','o','p','e', 0x05,'3','2','7','6','8',
            0x06,'s','t','r','i','p','s', 0x01,'4',
            0x04,'l','e','d','s', 0x04,'1','0','2','4',
            0x03,'b','p','p', 0x01,'3',
            0x05,'p','i','x','e','l', 0x00 };
        static const uint8_t pts[5] = { 0x03,'p','t','s', 0x00 };
        uint8_t want[64]; size_t want_len = sizeof base;
        memcpy(want, base, sizeof base);
#ifdef CONFIG_SLED_PTS
        memcpy(want + sizeof base, pts, sizeof pts); want_len += sizeof pts;
#else
        (void)pts;
#endif
        shieldnet_device_ops_t ops; full_ops(&ops);
#ifdef CONFIG_SLED_PTS
        ops.publish_pixel_frame_at = op_publish_pixel_frame_at;   /* pts needs it (sled 6.5) */
#endif
        g_geo_strips = 4; g_geo_leds = 1024; g_geo_envelope = 32768; g_geo_bpp = 3;
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = SLED_CMD_GET_DEVICE_INFO; hdr.message_num = 9;
        g_devinfo_len = 0; g_send_calls = 0;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_devinfo_len == want_len && memcmp(g_devinfo, want, want_len) == 0,
#ifdef CONFIG_SLED_PTS
              "device_info: the 52-byte vector with pts"
#else
              "device_info: the 47-byte vector"
#endif
              );
        g_geo_strips = 4; g_geo_leds = 64; g_geo_envelope = 0; g_geo_bpp = 0;
    }

    /* ── no pixel output: frames dropped and counted, no PIXEL mode (sled 1.4, 4.3) ── */
    {
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        shieldnet_device_ops_t ops; full_ops(&ops);
        ops.publish_pixel_frame = NULL;   /* pixel goes */
        uint8_t pf[28 + 4] = {0};
        pf[27] = 4;   /* buffer_length = one pixel */
        hdr.message_type = SLED_CMD_PIXEL_FRAME; hdr.message_num = 300;
        g_dropped = g_send_calls = g_published = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf) == 0 &&
              g_dropped == 1 && g_send_calls == 0 && g_published == 0,
              "sled 1.4: PIXEL_FRAME without pixel is dropped and counted");

        uint8_t sm[4] = { 1, 0, 0, 0 };
        hdr.message_type = SLED_CMD_SET_MODE; hdr.message_num = 301;
        g_ack_count = 0; g_set_mode_calls = 0;
        shieldnet_command_dispatch(&ops, &hdr, sm, sizeof sm);
        CHECK(g_ack_count == 1 && g_ack_kind == SLED_CMD_SET_MODE &&
              g_ack_status == SLED_ACK_ERR_INVALID_ARG && g_set_mode_calls == 0,
              "sled 4.3: SET_MODE 1 without pixel is ERR_INVALID_ARG");
        sm[0] = 0;
        g_ack_count = 0; g_set_mode_calls = 0;
        shieldnet_command_dispatch(&ops, &hdr, sm, sizeof sm);
        CHECK(g_ack_count == 1 && g_ack_status == SLED_ACK_ERR_INVALID_ARG &&
              g_set_mode_calls == 0,
              "sled 4.3: SET_MODE 0 without pixel and without an extension is refused");

        /* The op reports PIXEL; the device has no pixel output. ACK detail is
         * [mode][output_enabled] at offset 14. */
        memset(&g_st, 0, sizeof g_st);
        g_st.mode = 1; g_st.output_enabled = true;
        hdr.message_type = SLED_CMD_GET_MODE; hdr.message_num = 302;
        g_ack_count = 0; g_ack_len = 0;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_ack_count == 1 && g_ack_status == SLED_ACK_OK && g_ack_len == 16 &&
              g_ack[14] == 1 && g_ack[15] == 1,
              "sled 4.3: GET_MODE without pixel reports 1");
        hdr.message_type = SLED_CMD_GET_STATUS; hdr.message_num = 303;
        g_status_len = 0;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_status_len == SLED_STATUS_RESP_SIZE && g_status[28] == 1,
              "sled 4.3: STATUS without pixel reports 1");

        /* With pixel output the op's mode goes out as it is. */
        full_ops(&ops);
        hdr.message_type = SLED_CMD_GET_MODE; hdr.message_num = 304;
        g_ack_count = 0; g_ack_len = 0;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_ack_count == 1 && g_ack_len == 16 && g_ack[14] == 1,
              "sled 4.3: GET_MODE with pixel reports the op's mode");
        memset(&g_st, 0, sizeof g_st);
    }

    /* ── DEVICE_INFO decode: geometry optional without pixel, capabilities
     *    by presence (sled 5.3.1, 5.3.3) ── */
    {
        static const uint8_t env_cap[] = { 8,'e','n','v','e','l','o','p','e', 4,'1','4','0','0',
                                           3,'x','-','a', 0 };
        static const uint8_t px_noleds[] = { 8,'e','n','v','e','l','o','p','e', 4,'1','4','0','0',
                                             6,'s','t','r','i','p','s', 1,'4',
                                             3,'b','p','p', 1,'3',
                                             5,'p','i','x','e','l', 0 };
        static const uint8_t px_nogeo[] = { 8,'e','n','v','e','l','o','p','e', 4,'1','4','0','0',
                                            5,'p','i','x','e','l', 0 };
        static const uint8_t strips_only[] = { 8,'e','n','v','e','l','o','p','e', 4,'1','4','0','0',
                                               6,'s','t','r','i','p','s', 1,'4' };
        static const uint8_t px_valued[] = { 8,'e','n','v','e','l','o','p','e', 4,'1','4','0','0',
                                             5,'p','i','x','e','l', 1,'1' };
        sled_geometry_t g;
        memset(&g, 0xA5, sizeof g);
        CHECK(sled_decode_geometry(env_cap, sizeof env_cap, &g) && g.envelope == 1400 &&
              g.strips == 0 && g.leds == 0 && g.bpp == 0,
              "sled 5.3.3: envelope and a private capability only decodes, geometry zero");
        CHECK(!sled_decode_geometry(px_noleds, sizeof px_noleds, &g),
              "sled 5.3.3: pixel without leds is refused");
        CHECK(!sled_decode_geometry(px_nogeo, sizeof px_nogeo, &g),
              "sled 5.3.3: pixel with no geometry is refused");
        CHECK(!sled_decode_geometry(strips_only, sizeof strips_only, &g),
              "sled 5.3.3: strips alone, without pixel, is refused");
        CHECK(sled_device_info_has(px_valued, sizeof px_valued, "pixel"),
              "sled 5.3.1: a pixel field with a value is present");
        CHECK(!sled_device_info_has(px_valued, sizeof px_valued, "x-absent"),
              "sled 5.3.1: a name not in the payload is absent");
    }

    /* ── the core's status selection, row by row (sled 5.1) ── */
    {
        shieldnet_device_ops_t ops; full_ops(&ops);
        uint8_t z[64] = {0};
        uint8_t mode2[4] = { 2, 0, 0, 0 };
        g_op_err = 0;
        CHECK(send_cmd(&ops, 0x30, z, 8) == SLED_ACK_ERR_UNKNOWN_KIND,
              "sled 5.1: unknown kind -> ERR_UNKNOWN_KIND");
        CHECK(send_cmd(&ops, SLED_CMD_SET_BRIGHTNESS, z, 0) == SLED_ACK_ERR_INVALID_ARG,
              "sled 5.1: short payload (SET_BRIGHTNESS, 0 bytes) -> ERR_INVALID_ARG");
        CHECK(send_cmd(&ops, SLED_CMD_SET_MODE, mode2, 1) == SLED_ACK_ERR_INVALID_ARG,
              "sled 5.1: SET_MODE 2: mode not supported -> ERR_INVALID_ARG");
        g_op_err = -5;
        CHECK(send_cmd(&ops, SLED_CMD_ON, NULL, 0) == SLED_ACK_ERR_INVALID_ARG,
              "sled 5.1: valid command the device could not carry out (ON) -> ERR_INVALID_ARG");
        g_op_err = 0;
    }

    /* ── PIXEL_FRAME: at least one pixel, and within the envelope (sled 6.1, 6.2) ── */
    {
        shieldnet_device_geometry_t geo; memset(&geo, 0, sizeof geo);
        geo.num_strips = 64; geo.leds_per_strip = 1024; geo.max_payload = 65536;
        CHECK(!shieldnet_pixel_frame_valid(0, &geo) && shieldnet_pixel_frame_valid(4, &geo),
              "sled 6.1: encoder refuses 0 bytes");
        CHECK(!sled_pixel_frame_buffer_valid(0, SLED_PIXEL_WIRE_BPP, 1024) &&
              sled_pixel_frame_buffer_valid(4, SLED_PIXEL_WIRE_BPP, 1024),
              "sled 6.1: validator refuses 0 bytes");
        geo.max_payload = 80;
        CHECK(shieldnet_pixel_frame_valid(36, &geo), "sled 6.2: 36 bytes fit envelope 80");
        CHECK(!shieldnet_pixel_frame_valid(40, &geo), "sled 6.2: 40 bytes exceed envelope 80");

        shieldnet_device_ops_t ops; full_ops(&ops);
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = SLED_CMD_PIXEL_FRAME; hdr.message_num = 600;
        uint8_t pf[28] = {0};   /* buffer_length 0 */
        g_dropped = g_published = g_send_calls = 0;
        shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf);
        CHECK(g_dropped == 1 && g_published == 0 && g_send_calls == 0,
              "sled 6.1: a zero-pixel frame is dropped and counted");
    }

    /* ── response and private kinds are unknown to a device (sled 3.1, 7.8);
     *    bits 8-30 of MessageType do not change dispatch ── */
    {
        /* A table with only send_response and emit_event: any other op the
         * core reached would be a NULL call. The full table must answer the
         * same. */
        shieldnet_device_ops_t bare; memset(&bare, 0, sizeof bare);
        bare.send_response = op_send_response; bare.emit_event = op_emit_event;
        shieldnet_device_ops_t ops; full_ops(&ops);
        static const struct { uint8_t kind; const char *m; } k[4] = {
            { 0x80, "sled 3.1: kind 0x80 (a response kind) sent to a device is ERR_UNKNOWN_KIND" },
            { 0x84, "sled 3.1: kind 0x84 (a response kind) sent to a device is ERR_UNKNOWN_KIND" },
            { 0xE0, "sled 3.1: kind 0xE0 (a private response kind) sent to a device is ERR_UNKNOWN_KIND" },
            { 0x60, "sled 7.8: private kind 0x60 without its extension is ERR_UNKNOWN_KIND" },
        };
        uint8_t z[16] = {0};
        for (int i = 0; i < 4; i++) {
            g_events = 0; g_send_calls = 0;
            int bare_st = send_cmd(&bare, k[i].kind, z, sizeof z);
            int bare_ev = g_events, bare_sends = g_send_calls;
            int full_st = send_cmd(&ops, k[i].kind, z, sizeof z);
            CHECK(bare_st == SLED_ACK_ERR_UNKNOWN_KIND && bare_ev == 1 && bare_sends == 1 &&
                  full_st == SLED_ACK_ERR_UNKNOWN_KIND, k[i].m);
        }

        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = 0x7FFFFF00u | SLED_CMD_PING; hdr.message_num = 700;
        g_ack_count = 0;
        shieldnet_command_dispatch(&bare, &hdr, NULL, 0);
        CHECK(g_ack_count == 1 && g_ack_kind == SLED_CMD_PING && g_ack_status == SLED_ACK_OK,
              "sled 3.1: bits 8-30 set on PING do not change dispatch");
        hdr.message_type = 0x7FFFFF00u | SLED_CMD_GET_STATUS; hdr.message_num = 701;
        g_ack_count = 0; g_status_len = 0;
        shieldnet_command_dispatch(&ops, &hdr, NULL, 0);
        CHECK(g_ack_count == 1 && g_ack_kind == SLED_CMD_GET_STATUS && g_ack_status == SLED_ACK_OK &&
              g_status_len == SLED_STATUS_RESP_SIZE,
              "sled 3.1: bits 8-30 set on GET_STATUS do not change dispatch");
    }

    /* ── DEVICE_INFO decode: at most 32 fields (sled 5.3.3 rule 5) ── */
    {
        /* envelope 80, then capabilities x0, x1, ... until n fields. */
        uint8_t b[256]; size_t o = 0;
        sled_geometry_t g;
        static const uint8_t env[] = { 8,'e','n','v','e','l','o','p','e', 2,'8','0' };
        memcpy(b, env, sizeof env); o = sizeof env;
        for (int i = 1; i < 32; i++) {
            b[o++] = 3; b[o++] = 'x'; b[o++] = (uint8_t)('A' + i / 26); b[o++] = (uint8_t)('a' + i % 26);
            b[o++] = 0;
        }
        CHECK(o <= SLED_DEVICE_INFO_MAX_BYTES && sled_decode_geometry(b, o, &g) && g.envelope == 80,
              "sled 5.3.3 rule 5: 32 fields accepted");
        b[o++] = 3; b[o++] = 'x'; b[o++] = 'Z'; b[o++] = 'z'; b[o++] = 0;
        CHECK(o <= SLED_DEVICE_INFO_MAX_BYTES && !sled_decode_geometry(b, o, &g),
              "sled 5.3.3 rule 5: 33 fields rejected");
    }

    /* ── the frame number and timestamps reach the device ── */
    {
        uint8_t pf[28 + 4] = {0};
        static const uint8_t fn[8] = { 0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03 };
        memcpy(pf, fn, 8);
        static const uint8_t nb[8] = { 0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF };
        static const uint8_t na[8] = { 0x0F,0xED,0xCB,0xA9,0x87,0x65,0x43,0x21 };
        memcpy(pf + 8, nb, 8); memcpy(pf + 16, na, 8);
        pf[27] = 4;   /* buffer_length = one pixel */

        shieldnet_device_ops_t ops; memset(&ops, 0, sizeof ops);
        ops.send_response = op_send_response;
        ops.get_geometry = op_get_geometry;
        ops.note_frame_dropped = op_note_frame_dropped;
        ops.emit_event = op_emit_event;
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = SLED_CMD_PIXEL_FRAME; hdr.message_num = 20;

        ops.publish_pixel_frame = op_publish_pixel_frame;
        ops.publish_pixel_frame_at = op_publish_pixel_frame_at;
        g_published = g_published_at = g_dropped = g_send_calls = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf) == 0, "pts op: dispatch returns 0");
        CHECK(g_published_at == 1 && g_at_nb == INT64_C(0x0123456789ABCDEF) &&
              g_at_na == INT64_C(0x0FEDCBA987654321),
              "pts op: both ops set, the new one gets not_before then not_after");
        CHECK(g_at_fn == INT64_C(0x010203), "pts op: the new op gets the frame number");
        CHECK(g_published == 0, "pts op: both ops set, the old one is not called");

        ops.publish_pixel_frame = NULL;
        g_published = g_published_at = 0;
        shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf);
        CHECK(g_published_at == 1 && g_dropped == 0, "pts op: the new op alone receives the frame");

        ops.publish_pixel_frame = op_publish_pixel_frame; ops.publish_pixel_frame_at = NULL;
        g_published = g_published_at = 0;
        shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf);
        CHECK(g_published == 1 && g_published_at == 0, "pts op: the old op alone is unchanged");

        ops.publish_pixel_frame = NULL;
        g_published = g_published_at = g_send_calls = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, pf, sizeof pf) == 0,
              "pts op: neither op, dispatch returns 0");
        CHECK(g_published == 0 && g_published_at == 0 && g_send_calls == 0,
              "pts op: neither op, nothing runs and nothing is sent");
    }

    /* ── NTP_SERVER ── */
    {
        static const uint8_t v1[8]  = { 0x04,0x04,0x00,0x7b,0x0a,0x00,0x00,0x05 };
        static const uint8_t v2[8]  = { 0x04,0x04,0x1f,0xbb,0xc0,0xa8,0x01,0x0a };
        static const uint8_t v3[14] = { 0x01,0x0a,0x00,0x7b,'t','i','m','e','.','l','o','c','a','l' };
        static const uint8_t v4[20] = { 0x06,0x10,0x00,0x7b,0xfd,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01 };
        const uint8_t *vec[4] = { v1, v2, v3, v4 };
        const size_t   vlen[4] = { 8, 8, 14, 20 };
        const uint16_t vport[4] = { 123, 8123, 123, 123 };
        const uint8_t  vtype[4] = { 4, 4, 1, 6 };
        shieldnet_ntp_server_req_t r;

        for (int i = 0; i < 4; i++) {
            memset(&r, 0xA5, sizeof r);
            int ok = shieldnet_parse_ntp_server(vec[i], vlen[i], &r) &&
                     r.addr_type == vtype[i] && r.port == vport[i] &&
                     r.addr_len == vlen[i] - 4 && memcmp(r.addr, vec[i] + 4, r.addr_len) == 0;
            CHECK(ok, "ntp_server: a golden vector parses");
            uint8_t eb[64];
            CHECK(shieldnet_encode_ntp_server(&r, eb, sizeof eb) == vlen[i] &&
                  memcmp(eb, vec[i], vlen[i]) == 0, "ntp_server: the encoder reproduces the vector");
            CHECK(shieldnet_encode_ntp_server(&r, eb, vlen[i] - 1) == 0,
                  "ntp_server: the encoder refuses a buffer one byte short");
        }

        uint8_t padded[8 + 56] = {0};
        memcpy(padded, v1, 8);
        CHECK(shieldnet_parse_ntp_server(padded, sizeof padded, &r) && r.addr_type == 4 &&
              r.addr_len == 4 && r.port == 123 && memcmp(r.addr, v1 + 4, 4) == 0,
              "ntp_server: trailing bytes are ignored");

        uint8_t nm[4 + 253];
        nm[0] = 1; nm[1] = 8; nm[2] = 0; nm[3] = 0x7b; memcpy(nm + 4, "AZaz09.-", 8);
        CHECK(shieldnet_parse_ntp_server(nm, 12, &r), "ntp_server: the name AZaz09.- parses");
        nm[1] = 253; memset(nm + 4, 'a', 253);
        CHECK(shieldnet_parse_ntp_server(nm, sizeof nm, &r), "ntp_server: a 253-byte name parses");

        /* refused, leaving *out zeroed */
        static const uint8_t bad3[]  = { 0x04,0x04,0x00 };
        static const uint8_t bad7[]  = { 0x04,0x04,0x00,0x7b,0x0a,0x00,0x00 };
        static const uint8_t badty[] = { 0x09,0x04,0x00,0x7b,0x0a,0x00,0x00,0x05 };
        static const uint8_t bad0[]  = { 0x00,0x00,0x00,0x7b };
        static const uint8_t bad4l5[] = { 0x04,0x05,0x00,0x7b,0x0a,0x00,0x00,0x05,0x00 };
        static const uint8_t bad4l3[] = { 0x04,0x03,0x00,0x7b,0x0a,0x00,0x00 };
        static const uint8_t bad6l4[] = { 0x06,0x04,0x00,0x7b,0x0a,0x00,0x00,0x05 };
        static const uint8_t badnl0[] = { 0x01,0x00,0x00,0x7b };
        static const uint8_t badp0[]  = { 0x04,0x04,0x00,0x00,0x0a,0x00,0x00,0x05 };
        struct { const uint8_t *p; size_t n; const char *what; } bad[] = {
            { NULL, 0, "NULL" }, { bad3, sizeof bad3, "3 bytes" },
            { bad7, sizeof bad7, "one address byte missing" },
            { badty, sizeof badty, "unknown type" }, { bad0, sizeof bad0, "type 0" },
            { bad4l5, sizeof bad4l5, "type 4 len 5" }, { bad4l3, sizeof bad4l3, "type 4 len 3" },
            { bad6l4, sizeof bad6l4, "type 6 len 4" }, { badnl0, sizeof badnl0, "empty name" },
            { badp0, sizeof badp0, "port 0" },
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            memset(&r, 0xA5, sizeof r);
            CHECK(!shieldnet_parse_ntp_server(bad[i].p, bad[i].n, &r) && all_zero(&r, sizeof r),
                  bad[i].what);
        }
        uint8_t big[4 + 254];
        big[0] = 1; big[1] = 254; big[2] = 0; big[3] = 0x7b; memset(big + 4, 'a', 254);
        memset(&r, 0xA5, sizeof r);
        CHECK(!shieldnet_parse_ntp_server(big, sizeof big, &r) && all_zero(&r, sizeof r),
              "ntp_server: a 254-byte name is refused");
        const char badc[] = "/:@[_`{ ";
        for (size_t i = 0; i < sizeof badc - 1; i++) {
            uint8_t b[7] = { 1, 3, 0, 0x7b, 'a', (uint8_t)badc[i], 'b' };
            memset(&r, 0xA5, sizeof r);
            CHECK(!shieldnet_parse_ntp_server(b, sizeof b, &r) && all_zero(&r, sizeof r),
                  "ntp_server: a character outside letters, digits, '.' and '-' is refused");
        }

        /* the encoder refuses what the parser refuses */
        uint8_t eb[300];
        static const uint8_t a5[5] = { 1, 2, 3, 4, 5 };
        shieldnet_ntp_server_req_t e = { .addr_type = 9, .addr_len = 4, .port = 123, .addr = v1 + 4 };
        CHECK(shieldnet_encode_ntp_server(&e, eb, sizeof eb) == 0, "ntp_server: encoder refuses addr_type 9");
        e.addr_type = 4; e.addr_len = 5; e.addr = a5;
        CHECK(shieldnet_encode_ntp_server(&e, eb, sizeof eb) == 0, "ntp_server: encoder refuses type 4 with len 5");
        e.addr_len = 4; e.addr = v1 + 4; e.port = 0;
        CHECK(shieldnet_encode_ntp_server(&e, eb, sizeof eb) == 0, "ntp_server: encoder refuses port 0");
        e.addr_type = 1; e.addr_len = 3; e.port = 123; e.addr = (const uint8_t *)"a b";
        CHECK(shieldnet_encode_ntp_server(&e, eb, sizeof eb) == 0, "ntp_server: encoder refuses the name 'a b'");

        /* no ACK, ever */
        CHECK(!sled_command_allows_ack(0x0B), "ntp_server: no ACK for 0x0B");
        CHECK(sled_command_allows_ack(0x07), "ntp_server: PING still gets an ACK");

        /* dispatch, with the kind as the literal 0x0B */
        shieldnet_device_ops_t ops; memset(&ops, 0, sizeof ops);
        ops.send_response = op_send_response;
        ops.emit_event = op_emit_event;
        ops.set_ntp_server = op_set_ntp_server;
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = 0x0B; hdr.message_num = 30;

        g_ntp_calls = g_send_calls = g_events = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, v1, sizeof v1) == 0, "ntp_server: dispatch returns 0");
        CHECK(g_ntp_calls == 1 && g_ntp.addr_type == 4 && g_ntp.addr_len == 4 && g_ntp.port == 123 &&
              memcmp(g_ntp.addr, v1 + 4, 4) == 0, "ntp_server: the op gets the request");
        CHECK(g_send_calls == 0 && g_events == 0, "ntp_server: no response and no event");

        ops.emit_event = NULL;
        g_ntp_calls = g_send_calls = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, v1, sizeof v1) == 0 && g_ntp_calls == 1 &&
              g_send_calls == 0, "ntp_server: reached with emit_event NULL");
        ops.emit_event = op_emit_event;

        ops.set_ntp_server = NULL;
        g_ntp_calls = g_send_calls = g_events = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, v1, sizeof v1) == 0 && g_ntp_calls == 0 &&
              g_send_calls == 0 && g_events == 0, "ntp_server: no op, nothing is called");
        ops.set_ntp_server = op_set_ntp_server;

        g_ntp_calls = g_send_calls = g_events = 0;
        CHECK(shieldnet_command_dispatch(&ops, &hdr, badty, sizeof badty) == 0 && g_ntp_calls == 0 &&
              g_send_calls == 0 && g_events == 0, "ntp_server: an unknown type is not passed on or answered");
        CHECK(shieldnet_command_dispatch(&ops, &hdr, NULL, 0) == 0 && g_ntp_calls == 0 &&
              g_send_calls == 0 && g_events == 0, "ntp_server: an empty payload is not passed on or answered");
    }

    /* ── note_command: STATUS `commands` (sled 5.2) ── */
    {
        shieldnet_device_ops_t ops; full_ops(&ops);
        ops.note_command = op_note_command;
        uint8_t px[28 + 4] = {0}; px[27] = 4;
        g_geo_strips = 1; g_geo_leds = 1;
        g_commands = 0;
        send_cmd(&ops, SLED_CMD_PING, NULL, 0);
        CHECK(g_commands == 1, "note_command: a PING counts");
        send_cmd(&ops, 0x30, NULL, 0);
        CHECK(g_commands == 2, "note_command: an unknown kind counts");
        protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
        hdr.message_type = SLED_CMD_PIXEL_FRAME;
        shieldnet_command_dispatch(&ops, &hdr, px, sizeof px);
        CHECK(g_commands == 2, "note_command: a PIXEL_FRAME does not count");
        send_cmd(&ops, SLED_CMD_GET_STATUS, NULL, 0);
        CHECK(g_commands == 3 && g_commands_at_status == 3,
              "note_command: GET_STATUS is counted before it is answered");
        ops.note_command = NULL;
        send_cmd(&ops, SLED_CMD_PING, NULL, 0);
        CHECK(g_commands == 3, "note_command: NULL, nothing is called");
    }

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all command-core bound cases pass\n");
    return 0;
}
