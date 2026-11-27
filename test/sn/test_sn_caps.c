/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* The advertised capabilities, derived from the device's ops table and
 * geometry (shieldnet_device_caps), with and without CONFIG_SLED_PTS: the
 * DEVICE_INFO list and the mDNS caps string, and the extension's names after
 * the core's. The expectation is selected by the same flag; the target name
 * says which. */
#include "command.h"
#include "payload_encode_policy.h"
#include "protocol.h"
#include "response_decode.h"
#include "shieldnet_device.h"

#include <stdio.h>
#include <string.h>

#ifdef CONFIG_SLED_PTS
#define WANT_STR   "pixel,pts"
#else
#define WANT_STR   "pixel"
#endif

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

/* ── a device whose every op is a stub ── */
static uint8_t g_scratch[1024];
static uint8_t g_devinfo[1024]; static size_t g_devinfo_len;
static uint16_t g_strips = 4, g_leds = 64;

static int op_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx;
    if (kind == SLED_RESP_DEVICE_INFO && len <= sizeof g_devinfo) {
        memcpy(g_devinfo, body, len); g_devinfo_len = len;
    }
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
static bool op_publish_at(void *ctx, const uint8_t *px, int n, int64_t fn,
                          int64_t nb, int64_t na) {
    (void)ctx; (void)px; (void)n; (void)fn; (void)nb; (void)na; return true;
}
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

/* The caps string for this table and the fixture's geometry. */
static const char *caps_str(const shieldnet_device_ops_t *ops) {
    static char buf[64];
    shieldnet_device_geometry_t geo; memset(&geo, 0, sizeof geo);
    if (ops->get_geometry) ops->get_geometry(ops->ctx, &geo);
    if (!shieldnet_device_caps_str(ops, &geo, buf, sizeof buf)) return "(does not fit)";
    return buf;
}

/* GET_DEVICE_INFO through the command core; the body lands in g_devinfo. */
static void devinfo(const shieldnet_device_ops_t *ops) {
    protocol_msg_header_t hdr; memset(&hdr, 0, sizeof hdr);
    hdr.message_type = SLED_CMD_GET_DEVICE_INFO; hdr.message_num = 1;
    g_devinfo_len = 0;
    shieldnet_command_dispatch(ops, &hdr, NULL, 0);
}

/* Whether the last DEVICE_INFO has a field with this name. */
static int has_field(const char *name) {
    size_t off = 0; sled_device_info_field_t f;
    while (sled_device_info_next(g_devinfo, g_devinfo_len, &off, &f)) {
        if (sled_device_info_name_is(&f, name)) return 1;
    }
    return 0;
}

/* The DEVICE_INFO capability names (empty-valued fields) joined by ','. */
static const char *devinfo_caps(void) {
    static char buf[128];
    size_t off = 0, o = 0; sled_device_info_field_t f;
    buf[0] = '\0';
    while (sled_device_info_next(g_devinfo, g_devinfo_len, &off, &f)) {
        if (f.value_len != 0 || o + f.name_len + 2 > sizeof buf) continue;
        if (o) buf[o++] = ',';
        memcpy(&buf[o], f.name, f.name_len); o += f.name_len; buf[o] = '\0';
    }
    return buf;
}

/* Whether a ','-separated list names `name`. */
static int lists(const char *list, const char *name) {
    size_t n = strlen(name);
    for (const char *p = list; *p; ) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && memcmp(p, name, n) == 0) return 1;
        p += l + (e ? 1 : 0);
    }
    return 0;
}

int main(void)
{
    shieldnet_device_ops_t ops;

    /* ── everything set: pixel, plus what the build adds ── */
    full_ops(&ops);
    ops.publish_pixel_frame_at = op_publish_at;   /* pts needs it (sled 6.5) */
    devinfo(&ops);
    CHECK(strcmp(caps_str(&ops), WANT_STR) == 0 && strcmp(devinfo_caps(), WANT_STR) == 0,
          "sled 5.3.3: full ops and geometry advertise pixel, and pts when built with it");
    printf("     caps \"%s\", DEVICE_INFO \"%s\", want \"%s\"\n",
           caps_str(&ops), devinfo_caps(), WANT_STR);
    CHECK(strcmp(caps_str(&ops), devinfo_caps()) == 0 && !has_field("pins"),
          "sled 8: caps string matches the DEVICE_INFO names");

    /* ── the extension's names follow the core's ── */
    {
        static const char *const names[] = { "x-z" };
        static shieldnet_device_ext_t ext;
        full_ops(&ops);
        ops.publish_pixel_frame_at = op_publish_at;
        ext.caps = names; ext.cap_count = 1; ext.handle = ext_handle;
        ops.ext = &ext;
        devinfo(&ops);
        char want[32];
        snprintf(want, sizeof want, "%s,x-z", WANT_STR);
        CHECK(strcmp(caps_str(&ops), want) == 0 && strcmp(devinfo_caps(), want) == 0,
              "caps: ext caps follow the core's");
    }

    /* ── each term of pixel ── */
    {
        shieldnet_device_ops_t o;
        full_ops(&o); o.note_frame_dropped = NULL;
        CHECK(!lists(caps_str(&o), "pixel"), "sled 1.4: note_frame_dropped NULL drops pixel");
        full_ops(&o); o.emit_event = NULL;
        CHECK(!lists(caps_str(&o), "pixel"), "sled 1.4: emit_event NULL drops pixel");
        full_ops(&o); g_leds = 0;
        CHECK(!lists(caps_str(&o), "pixel"), "sled 5.3.3: leds_per_strip 0 drops pixel");
        g_leds = 64;
        full_ops(&o); o.publish_pixel_frame = NULL; o.publish_pixel_frame_at = op_publish_at;
        CHECK(lists(caps_str(&o), "pixel"), "sled 1.4: publish_pixel_frame_at alone keeps pixel");
        /* caps_str cannot isolate get_geometry (a NULL op leaves the geometry
         * zero, which drops pixel on its own), so ask the predicate directly. */
        shieldnet_device_geometry_t g = { .num_strips = 4, .leds_per_strip = 1024, .led_bpp = 3 };
        full_ops(&o); o.get_geometry = NULL;
        CHECK(!shieldnet_device_has_pixel(&o, &g), "sled 1.4: get_geometry NULL drops pixel");
        full_ops(&o);
        CHECK(shieldnet_device_has_pixel(&o, &g), "sled 1.4: has_pixel with every term set");
    }

    /* ── no publish op: no pixel output ── */
    full_ops(&ops);
    ops.publish_pixel_frame = NULL;
    devinfo(&ops);
    CHECK(!lists(caps_str(&ops), "pixel") && !lists(caps_str(&ops), "pts") &&
          !has_field("pixel") && !has_field("pts") && g_devinfo_len > 0,
          "sled 1.4: no publish op drops pixel and pts");

    /* ── no strips: no pixel, and no geometry fields ── */
    full_ops(&ops);
    g_strips = 0;
    devinfo(&ops);
    CHECK(!lists(caps_str(&ops), "pixel") && g_devinfo_len > 0 && has_field("envelope") &&
          !has_field("pixel") && !has_field("strips") && !has_field("leds") &&
          !has_field("bpp"),
          "sled 5.3.3: num_strips 0 drops pixel and the geometry fields");

    /* ── publish_pixel_frame_at set, pixel absent for the geometry alone ── */
    full_ops(&ops);
    ops.publish_pixel_frame_at = op_publish_at;
    g_strips = 0;
    devinfo(&ops);
    CHECK(!lists(caps_str(&ops), "pts") && !lists(caps_str(&ops), "pixel") &&
          !has_field("pts") && g_devinfo_len > 0,
          "sled 5.3.3: pts never without pixel");
    g_strips = 4;

    /* ── only the plain publish op: pixel, but no pts ── */
    full_ops(&ops);
    devinfo(&ops);
    CHECK(lists(caps_str(&ops), "pixel") && !lists(caps_str(&ops), "pts") &&
          has_field("pixel") && !has_field("pts"),
          "sled 6.5: pts needs publish_pixel_frame_at");

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    return 0;
}
