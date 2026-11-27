/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet portable command core.
 *
 * Parses incoming messages (kind from MessageType low 8 bits), calls
 * exactly one shieldnet_device_ops_t entry per command, then sends the
 * ACK (+ typed response for queries). Contains no locking and no RTOS or
 * device SDK. Every device-specific concern (locking, the device's own state)
 * lives on the far side of shieldnet_device_ops_t; an optional extension plugs
 * in through its `ext` member and is the only code that knows what it adds.
 */

#include <string.h>

#include "command.h"
#include "shieldnet_device.h"
#include "command_parse.h"
#include "command_response_policy.h"
#include "frame.h"
#include "mode_decode_policy.h"
#include "pixel_frame_policy.h"
/* Before payload_encode_policy.h and the CONFIG_SLED_* tests below: under
 * SHIELDNET_LOG_ESP_IDF it pulls in esp_log.h and with it sdkconfig.h, so the
 * firmware's DEVICE_INFO and mDNS caps see the same CONFIG_SLED_* values. */
#include "shieldnet_log.h"
#include "payload_encode_policy.h"

static const char *TAG = "shieldnet_cmd";

/* ── Capabilities (sled 1.4, 5.3.3) ──────────────────────────────── */

bool shieldnet_device_has_pixel(const shieldnet_device_ops_t *dev,
                                const shieldnet_device_geometry_t *geo)
{
    return (dev->publish_pixel_frame != NULL || dev->publish_pixel_frame_at != NULL)
        && dev->note_frame_dropped != NULL && dev->emit_event != NULL
        && dev->get_geometry != NULL
        && geo->num_strips > 0 && geo->leds_per_strip > 0;
}

/* ── The extension's DEVICE_INFO entries (sled 5.3.3, 5.3.4) ───── */

/* An extension is in effect only when it has a handle: without one, none of
 * its caps, fields, modes or STATUS block count. */
static const shieldnet_device_ext_t *ext_of(const shieldnet_device_ops_t *dev)
{
    return (dev->ext != NULL && dev->ext->handle != NULL) ? dev->ext : NULL;
}

/* Logs an invalid extension entry once: DEVICE_INFO is requested by the peer,
 * so a per-request line would be the peer's to write. `id` is the entry's
 * address; a table that is full stops logging rather than growing. */
static void log_ext_entry_once(const void *id, const char *what)
{
    static const void *seen[8];
    static size_t nseen;
    (void)what;
    for (size_t i = 0; i < nseen; i++) {
        if (seen[i] == id) return;
    }
    if (nseen == sizeof seen / sizeof seen[0]) return;
    seen[nseen++] = id;
    SHIELDNET_LOG_ERR(TAG, "extension %s entry skipped: not a valid name or value", what);
}

/* A capability or field name: 1 - 255 bytes of [a-z0-9-] (sled 5.3.3), and not
 * a name the core emits, so an extension cannot override the geometry (rule 4:
 * the last value wins). */
static bool ext_name_ok(const char *name)
{
    static const char *const core[] = { "envelope", "strips", "leds", "bpp",
                                        SLED_CAP_PIXEL, SLED_CAP_PTS };
    if (name == NULL || name[0] == '\0') return false;
    size_t n = 0;
    for (; name[n] != '\0'; n++) {
        char c = name[n];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        if (n >= 255) return false;
    }
    for (size_t i = 0; i < sizeof core / sizeof core[0]; i++) {
        if (strcmp(name, core[i]) == 0) return false;
    }
    return true;
}

/* A field value: any text (sled 5.3.4), 1 - 255 bytes. */
static bool ext_value_ok(const char *value)
{
    if (value == NULL || value[0] == '\0') return false;
    size_t n = 0;
    while (value[n] != '\0' && n <= 255) n++;
    return n <= 255;
}

/* Appends the extension's first valid capability names to out[n..max): at most
 * SHIELDNET_EXT_CAPS_MAX of them. Returns the new count. */
static size_t append_ext_caps(const shieldnet_device_ops_t *dev, const char *out[],
                              size_t n, size_t max)
{
    const shieldnet_device_ext_t *ext = ext_of(dev);
    size_t kept = 0;
    if (ext == NULL || ext->caps == NULL) return n;
    for (size_t i = 0; i < ext->cap_count; i++) {
        if (!ext_name_ok(ext->caps[i])) {
            log_ext_entry_once(&ext->caps[i], "capability");
            continue;
        }
        if (kept < SHIELDNET_EXT_CAPS_MAX && n < max) {
            out[n++] = ext->caps[i];
            kept++;
        }
    }
    return n;
}

/* Copies the extension's first valid fields, at most SHIELDNET_EXT_FIELDS_MAX. */
static size_t collect_ext_fields(const shieldnet_device_ops_t *dev,
                                 sled_info_text_field_t out[SHIELDNET_EXT_FIELDS_MAX])
{
    const shieldnet_device_ext_t *ext = ext_of(dev);
    size_t n = 0;
    if (ext == NULL || ext->fields == NULL) return 0;
    for (size_t i = 0; i < ext->field_count; i++) {
        if (!ext_name_ok(ext->fields[i].name) || !ext_value_ok(ext->fields[i].value)) {
            log_ext_entry_once(&ext->fields[i], "field");
            continue;
        }
        if (n < SHIELDNET_EXT_FIELDS_MAX) out[n++] = ext->fields[i];
    }
    return n;
}

size_t shieldnet_device_caps(const shieldnet_device_ops_t *dev,
                             const shieldnet_device_geometry_t *geo,
                             const char *out[], size_t max)
{
    bool pixel = shieldnet_device_has_pixel(dev, geo);
    size_t n = 0;
    if (pixel && n < max) out[n++] = SLED_CAP_PIXEL;
#ifdef CONFIG_SLED_PTS
    /* The plain publish_pixel_frame drops both timestamps, so a device with
     * only that op cannot present on schedule (sled 6.5); and pts never goes
     * without pixel (sled 5.3.3 rule 1). */
    if (pixel && dev->publish_pixel_frame_at != NULL) {
        if (n < max) out[n++] = SLED_CAP_PTS;
    } else {
        /* Once: this runs on every GET_DEVICE_INFO, so a peer could log at will. */
        static bool logged;
        if (!logged) {
            logged = true;
            SHIELDNET_LOG_ERR(TAG, "CONFIG_SLED_PTS without %s: pts not advertised",
                              pixel ? "publish_pixel_frame_at" : "pixel");
        }
    }
#endif
    return append_ext_caps(dev, out, n, max);
}

bool shieldnet_device_caps_str(const shieldnet_device_ops_t *dev,
                               const shieldnet_device_geometry_t *geo,
                               char *buf, size_t cap)
{
    const char *names[SHIELDNET_DEVICE_CAPS_MAX];
    size_t n = shieldnet_device_caps(dev, geo, names, SHIELDNET_DEVICE_CAPS_MAX);
    size_t off = 0;
    if (cap == 0) return false;
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(names[i]);
        if (l + (i ? 1 : 0) >= cap - off) return false;   /* and the terminator */
        if (i) buf[off++] = ',';
        memcpy(&buf[off], names[i], l);
        off += l;
    }
    buf[off] = '\0';
    return true;
}

/* The device's geometry, or all zero when it has no get_geometry op. */
static void fetch_geometry(const shieldnet_device_ops_t *dev,
                           shieldnet_device_geometry_t *geo)
{
    memset(geo, 0, sizeof(*geo)); /* a field the op leaves unset reads as 0, not stack */
    if (dev->get_geometry != NULL) dev->get_geometry(dev->ctx, geo);
}

/* Whether the active extension reports `mode` among the device's modes
 * (sled 4.3). Never asked about PIXEL, which is the core's. */
static bool ext_has_mode(const shieldnet_device_ops_t *dev, uint8_t mode)
{
    const shieldnet_device_ext_t *ext = ext_of(dev);
    return mode != SLED_WIRE_MODE_PIXEL && ext != NULL && ext->has_mode != NULL
        && ext->has_mode(ext->ctx, mode);
}

/* The mode a query reports: the device's own when it has that mode, else
 * PIXEL -- a device with no mode of its own has only PIXEL (sled 4.3). */
static uint8_t reported_mode(const shieldnet_device_ops_t *dev, uint8_t mode)
{
    return ext_has_mode(dev, mode) ? mode : (uint8_t)SLED_WIRE_MODE_PIXEL;
}

/* ── ACK composition + send ───────────────────────────────────── */

/*
 * ACK payload layout:
 *   [u8  orig_kind]
 *   [u8  status]
 *   [u8  rsv x 2]
 *   [be64 orig_message_num]
 *   [be16 detail_len]
 *   [detail bytes]
 */
int shieldnet_send_ack(const shieldnet_device_ops_t *dev,
                       uint8_t        orig_kind,
                       uint64_t       orig_msgnum,
                       uint8_t        status,
                       const uint8_t *detail,
                       size_t         detail_len)
{
    if (!sled_command_allows_ack(orig_kind)) {
        SHIELDNET_LOG_ERR(TAG, "suppressed ACK for response-free command 0x%02x",
                          orig_kind);
        return 0;
    }

    uint8_t body[SLED_ACK_MAX_SIZE];
    size_t  body_len = 0;
    if (!sled_encode_ack(orig_kind, status, orig_msgnum, detail, detail_len,
                         body, sizeof(body), &body_len)) {
        return -1;  /* unreachable: body is SLED_ACK_MAX_SIZE and detail is clamped */
    }

    return dev->send_response(dev->ctx, SLED_RESP_ACK, body, body_len);
}

int shieldnet_send_ack_text(const shieldnet_device_ops_t *dev,
                            uint8_t      orig_kind,
                            uint64_t     orig_msgnum,
                            uint8_t      status,
                            const char  *detail)
{
    return shieldnet_send_ack(dev, orig_kind, orig_msgnum, status,
                              (const uint8_t *)detail, detail ? strlen(detail) : 0);
}

static int send_ack(const shieldnet_device_ops_t *dev,
                    uint8_t      orig_kind,
                    uint64_t     orig_msgnum,
                    uint8_t      status,
                    const char  *detail)
{
    return shieldnet_send_ack_text(dev, orig_kind, orig_msgnum, status, detail);
}

static int send_reject(const shieldnet_device_ops_t *dev, uint8_t kind,
                       uint64_t msgnum, shieldnet_parse_result_t r)
{
    return send_ack(dev, kind, msgnum, r.ack_status, r.ack_detail);
}

/* ── Handlers ─────────────────────────────────────────────────── */
/*
 * Every handler returns 0 on success, negative if any send_response call
 * inside it failed. A failed response send is reported, not treated as a
 * reason to skip a state change or a following response that is not itself
 * an error from the peer's perspective.
 */

static int handle_ping(const shieldnet_device_ops_t *dev, uint64_t msgnum)
{
    return send_ack(dev, SLED_CMD_PING, msgnum, SLED_ACK_OK, NULL);
}

static int handle_set_brightness(const shieldnet_device_ops_t *dev,
                                  uint64_t msgnum,
                                  const uint8_t *p, size_t len)
{
    shieldnet_set_brightness_req_t req;
    shieldnet_parse_result_t r = shieldnet_parse_set_brightness(p, len, &req);
    if (!r.ok) { return send_reject(dev, SLED_CMD_SET_BRIGHTNESS, msgnum, r); }

    dev->set_brightness(dev->ctx, req.value);
    return send_ack(dev, SLED_CMD_SET_BRIGHTNESS, msgnum, SLED_ACK_OK, NULL);
}

static int handle_set_fps(const shieldnet_device_ops_t *dev,
                           uint64_t msgnum,
                           const uint8_t *p, size_t len)
{
    shieldnet_set_fps_req_t req;
    shieldnet_parse_result_t r = shieldnet_parse_set_fps(p, len, &req);
    if (!r.ok) { return send_reject(dev, SLED_CMD_SET_FPS, msgnum, r); }

    dev->set_fps(dev->ctx, req.fps);
    return send_ack(dev, SLED_CMD_SET_FPS, msgnum, SLED_ACK_OK, NULL);
}

static int handle_set_mode(const shieldnet_device_ops_t *dev,
                            uint64_t msgnum,
                            const uint8_t *p, size_t len)
{
    shieldnet_set_mode_req_t req;
    shieldnet_parse_result_t r = shieldnet_parse_set_mode(p, len, &req);
    if (!r.ok) { return send_reject(dev, SLED_CMD_SET_MODE, msgnum, r); }

    /* sled 4.3: PIXEL needs pixel output; any other mode must be one the
     * extension reports. */
    uint8_t mode = req.wire_mode;
    if (mode == SLED_WIRE_MODE_PIXEL) {
        shieldnet_device_geometry_t geo;
        fetch_geometry(dev, &geo);
        if (!shieldnet_device_has_pixel(dev, &geo)) {
            return send_ack(dev, SLED_CMD_SET_MODE, msgnum,
                            SLED_ACK_ERR_INVALID_ARG, "no pixel output");
        }
    } else if (!ext_has_mode(dev, mode)) {
        return send_ack(dev, SLED_CMD_SET_MODE, msgnum,
                        SLED_ACK_ERR_INVALID_ARG, "mode not supported");
    }

    /* Without a set_mode op PIXEL is the device's only mode: already in it. A
     * device that has another mode but cannot switch to it refuses (sled 5.1). */
    int err = dev->set_mode != NULL ? dev->set_mode(dev->ctx, mode)
            : (mode == SLED_WIRE_MODE_PIXEL ? 0 : -1);
    uint8_t ack = (err == 0) ? SLED_ACK_OK : SLED_ACK_ERR_INVALID_ARG;
    return send_ack(dev, SLED_CMD_SET_MODE, msgnum, ack, NULL);
}

static int handle_on(const shieldnet_device_ops_t *dev, uint64_t msgnum)
{
    int err = dev->set_output_enabled(dev->ctx, true);
    uint8_t ack = (err == 0) ? SLED_ACK_OK : SLED_ACK_ERR_INVALID_ARG;
    return send_ack(dev, SLED_CMD_ON, msgnum, ack, NULL);
}

static int handle_off(const shieldnet_device_ops_t *dev, uint64_t msgnum)
{
    int err = dev->set_output_enabled(dev->ctx, false);
    uint8_t ack = (err == 0) ? SLED_ACK_OK : SLED_ACK_ERR_INVALID_ARG;
    return send_ack(dev, SLED_CMD_OFF, msgnum, ack, NULL);
}

static int handle_pixel_frame(const shieldnet_device_ops_t *dev,
                               const uint8_t *payload, size_t len)
{
    /* PIXEL_FRAME is the high-rate, fire-and-forget data path. Rejections
     * are observable through the dropped-frame counter (and, for malformed
     * frames, a FRAME_ERROR event); this handler never sends a response. */
    frame_t frame;
    if (frame_parse(payload, len, &frame) < 0) {
        dev->note_frame_dropped(dev->ctx);
        dev->emit_event(dev->ctx, SHIELDNET_EVT_FRAME_ERROR, 0);
        return 0;
    }

    shieldnet_device_geometry_t geo;
    memset(&geo, 0, sizeof(geo)); /* a field the op leaves unset reads as 0, not stack */
    dev->get_geometry(dev->ctx, &geo);

    /* Capacity is a wire figure: frames arrive at SLED_PIXEL_WIRE_BPP whatever
     * the strip is, and the W byte is dropped on ingest for an RGB strip. */
    /* In 64 bits: 65535 x 65535 x 4 exceeds a 32-bit size_t (the ESP32's), and
     * a wrapped capacity -- 32768 x 32768 x 4 is exactly 0 -- would refuse every
     * frame. buffer_length is a uint32_t, so clamping to UINT32_MAX loses nothing. */
    uint64_t capacity64 = (uint64_t)geo.num_strips
                        * (uint64_t)geo.leds_per_strip
                        * (uint64_t)SLED_PIXEL_WIRE_BPP;
    size_t capacity_bytes = capacity64 > UINT32_MAX ? (size_t)UINT32_MAX
                                                    : (size_t)capacity64;
    if (!sled_pixel_frame_buffer_valid(frame.buffer_length, SLED_PIXEL_WIRE_BPP,
                                       capacity_bytes)) {
        dev->note_frame_dropped(dev->ctx);
        dev->emit_event(dev->ctx, SHIELDNET_EVT_FRAME_ERROR, 0);
        return 0;
    }

    int num_pixels = (int)(frame.buffer_length / SLED_PIXEL_WIRE_BPP);
    bool ok = dev->publish_pixel_frame_at
        ? dev->publish_pixel_frame_at(dev->ctx, frame.pixels, num_pixels,
                                      frame.frame_number,
                                      frame.not_before_ns, frame.not_after_ns)
        : dev->publish_pixel_frame(dev->ctx, frame.pixels, num_pixels);
    if (!ok) {
        dev->note_frame_dropped(dev->ctx);
    }
    return 0;
}

/* ── Query handlers ───────────────────────────────────────────── */

static int handle_get_mode(const shieldnet_device_ops_t *dev, uint64_t msgnum)
{
    /* Detail bytes: [u8 mode][u8 output_enabled]. Routed through the shared
     * helper so this ACK passes the same response-free gate as every other. */
    shieldnet_device_status_t st;
    memset(&st, 0, sizeof(st));
    dev->get_status(dev->ctx, &st);

    uint8_t detail[2];
    detail[0] = reported_mode(dev, st.mode);
    detail[1] = st.output_enabled ? 1 : 0;
    return shieldnet_send_ack(dev, SLED_CMD_GET_MODE, msgnum, SLED_ACK_OK,
                           detail, sizeof(detail));
}

static int handle_get_status(const shieldnet_device_ops_t *dev, uint64_t msgnum)
{
    /* Fixed 78-byte STATUS_RESP payload, encoded through payload_encode_policy.h
     * so the host test covers the exact bytes sent on the wire. */
    shieldnet_device_status_t st;
    memset(&st, 0, sizeof(st));
    dev->get_status(dev->ctx, &st);

    sled_status_resp_fields_t f = {
        .frame_count            = st.frame_count,
        .command_count          = st.command_count,
        .pixel_frames_dropped   = st.pixel_frames_dropped,
        .led_refresh_errors     = st.led_refresh_errors,
        .mode                   = reported_mode(dev, st.mode),
        .connected              = st.connected,
        .output_enabled         = st.output_enabled,
        /* A device without set_brightness outputs at full brightness (sled 4.1). */
        .brightness             = dev->set_brightness != NULL ? st.brightness : 255,
        .target_fps             = st.target_fps,
    };
    /* Bytes 32-75 are the extension's, or zero (sled 5.2). */
    const shieldnet_device_ext_t *ext = ext_of(dev);
    if (ext != NULL && ext->fill_status != NULL) {
        ext->fill_status(ext->ctx, f.ext);
    }

    uint8_t body[SLED_STATUS_RESP_SIZE];
    sled_encode_status_resp(&f, body);

    int rc1 = dev->send_response(dev->ctx, SLED_RESP_STATUS, body, sizeof(body));
    int rc2 = send_ack(dev, SLED_CMD_GET_STATUS, msgnum, SLED_ACK_OK, NULL);
    return (rc1 < 0) ? rc1 : rc2;
}

static int handle_get_device_info(const shieldnet_device_ops_t *dev, uint64_t msgnum)
{
    /* Advertise the payload envelope, geometry and capabilities of the
     * live device -- never a boot-time snapshot for anything that can
     * drift (bpp comes from geometry.led_bpp, not a config struct). */
    shieldnet_device_geometry_t geo;
    fetch_geometry(dev, &geo);

    const char *caps[SHIELDNET_DEVICE_CAPS_MAX];
    size_t ncaps = shieldnet_device_caps(dev, &geo, caps, SHIELDNET_DEVICE_CAPS_MAX);
    sled_info_text_field_t xfields[SHIELDNET_EXT_FIELDS_MAX];
    size_t nxfields = collect_ext_fields(dev, xfields);
    /* The geometry fields go out only for a device with strips and LEDs; a
     * device may send them without pixel (sled 5.3.3 rule 1). */
    bool geometry = geo.num_strips > 0 && geo.leds_per_strip > 0;
    sled_device_info_fields_t info = {
        .envelope          = geo.max_payload,
        .strips            = geometry ? geo.num_strips : 0,
        .leds              = geometry ? geo.leds_per_strip : 0,
        .bpp               = geometry ? geo.led_bpp : 0,
        .capabilities      = caps,
        .capability_count  = ncaps,
        .extra_fields      = xfields,
        .extra_field_count = nxfields,
    };

    uint8_t *buf = NULL;
    size_t   cap = 0;
    dev->get_tx_scratch(dev->ctx, &buf, &cap);

    size_t body_len = 0;
    if (!sled_encode_device_info(&info, buf, cap, &body_len)) {
        SHIELDNET_LOG_ERR(TAG, "DEVICE_INFO encode refused (strips=%u leds=%u bpp=%u)",
                          (unsigned)geo.num_strips, (unsigned)geo.leds_per_strip,
                          (unsigned)geo.led_bpp);
        return send_ack(dev, SLED_CMD_GET_DEVICE_INFO, msgnum,
                        SLED_ACK_ERR_INVALID_ARG, "device info encode failed");
    }

    int rc1 = dev->send_response(dev->ctx, SLED_RESP_DEVICE_INFO, buf, body_len);
    int rc2 = send_ack(dev, SLED_CMD_GET_DEVICE_INFO, msgnum, SLED_ACK_OK, NULL);
    return (rc1 < 0) ? rc1 : rc2;
}

/* ── Top-level dispatch ───────────────────────────────────────── */

/*
 * Returns 0 if every response for this message was sent successfully,
 * negative if any send_response call failed (see shieldnet_device.h). The
 * core reports the failure; whether it ends the session is a device
 * decision made by the caller.
 */
/* Whether every op a kind's handler will call is populated.
 *
 * The handlers call the shieldnet_device_ops_t entries unconditionally, and
 * nothing -- not this file, not shieldnet_device.h -- says the table has to be
 * fully populated. A board that leaves one entry NULL therefore jumps through a
 * null pointer on the first command that reaches it, from an authenticated
 * peer: a reboot on an ESP32, and from the wire indistinguishable from a crash
 * bug in the protocol. Every known firmware populates every entry, so this is
 * an unstated contract rather than a live defect -- but an unstated contract is
 * exactly what the next board gets wrong.
 *
 * Every op the handler touches is checked, not just the obvious one. Several
 * handlers call two or three: the auxiliary ops (emit_event, get_geometry,
 * get_tx_scratch, note_frame_dropped) are called unconditionally as well, so a
 * guard that only covered the primary op would still crash on the second call.
 * An earlier version of this function did exactly that, and claimed in a
 * comment that GET_MODE needed no op at all -- it calls get_status.
 *
 * A missing op is ERR_UNKNOWN_KIND: from the controller's point of view a
 * device that cannot do a thing and a device that does not know the command are
 * the same answer, and it is the answer the client already handles. */
#define OPS1(a)        ((dev->a) != NULL)
#define OPS2(a,b)      (OPS1(a) && (dev->b) != NULL)
#define OPS3(a,b,c)    (OPS2(a,b) && (dev->c) != NULL)
#define OPS4(a,b,c,d)  (OPS3(a,b,c) && (dev->d) != NULL)

static int ops_ready_for_kind(const shieldnet_device_ops_t *dev, uint8_t kind)
{
    switch (kind) {
    case SLED_CMD_PIXEL_FRAME:
        return (dev->publish_pixel_frame != NULL || dev->publish_pixel_frame_at != NULL)
            && OPS3(get_geometry, note_frame_dropped, emit_event);
    case SLED_CMD_SET_BRIGHTNESS:  return OPS1(set_brightness);
    case SLED_CMD_SET_FPS:         return OPS1(set_fps);
    /* Every device understands SET_MODE (sled 4.3): it needs no op, since a
     * pixel device without set_mode is in its only mode already. */
    case SLED_CMD_SET_MODE:        return 1;
    case SLED_CMD_ON:
    case SLED_CMD_OFF:             return OPS1(set_output_enabled);
    case SLED_CMD_GET_STATUS:      return OPS1(get_status);
    case SLED_CMD_GET_MODE:        return OPS1(get_status);
    case SLED_CMD_GET_DEVICE_INFO: return OPS2(get_geometry, get_tx_scratch);
    case SLED_CMD_PING:            return 1; /* answered from this file alone */
    /* Response-free and optional: with the op unset it is ignored, with no
     * emit_event it is still ignored -- never refused with an ACK. */
    case SLED_CMD_NTP_SERVER:      return 1;
    /* The unknown-kind branch below may call emit_event before its ACK, and the
     * kind byte is entirely the peer's choice -- so this is the widest door of
     * the lot, not a fallthrough. The guard's own rejection sends the same
     * ERR_UNKNOWN_KIND, so a fully populated table sees no difference. An
     * extension's handle does not need emit_event: the branch calls it only
     * when it is set. */
    default:                       return OPS1(emit_event) || ext_of(dev) != NULL;
    }
}

int shieldnet_command_dispatch(const shieldnet_device_ops_t *dev,
                               const protocol_msg_header_t *hdr,
                               const uint8_t *payload, size_t payload_len)
{
    uint8_t  kind   = (uint8_t)(hdr->message_type & SLED_CMD_KIND_MASK);
    uint64_t msgnum = hdr->message_num;

    /* Nothing can be answered without this one, so it is checked first and
     * separately: refusing to answer is the only option left. */
    if (dev->send_response == NULL) {
        SHIELDNET_LOG_ERR(TAG, "device ops has no send_response");
        return -1;
    }
    /* STATUS's `commands`: every message but PIXEL_FRAME, counted before it is
     * handled so the GET_STATUS being answered includes itself (sled 5.2). */
    if (kind != SLED_CMD_PIXEL_FRAME && dev->note_command != NULL) {
        dev->note_command(dev->ctx);
    }
    /* sled 1.4: a device without pixel output discards every PIXEL_FRAME and
     * counts it. Before the op guard, which would turn the frame away without
     * counting it. */
    if (kind == SLED_CMD_PIXEL_FRAME) {
        shieldnet_device_geometry_t geo;
        fetch_geometry(dev, &geo);
        if (!shieldnet_device_has_pixel(dev, &geo)) {
            if (dev->note_frame_dropped != NULL) {
                dev->note_frame_dropped(dev->ctx);
            } else {
                /* Once: a controller streaming frames would log at its frame rate. */
                static bool logged;
                if (!logged) {
                    logged = true;
                    SHIELDNET_LOG_ERR(TAG, "PIXEL_FRAME dropped and not counted: no note_frame_dropped");
                }
            }
            return 0;
        }
    }
    if (!ops_ready_for_kind(dev, kind)) {
        SHIELDNET_LOG_ERR(TAG, "device ops has no handler for command 0x%02x", kind);
        return send_ack(dev, kind, msgnum, SLED_ACK_ERR_UNKNOWN_KIND, NULL);
    }

    switch (kind) {
    case SLED_CMD_PIXEL_FRAME:
        return handle_pixel_frame(dev, payload, payload_len);

    case SLED_CMD_SET_BRIGHTNESS:
        return handle_set_brightness(dev, msgnum, payload, payload_len);

    case SLED_CMD_SET_FPS:
        return handle_set_fps(dev, msgnum, payload, payload_len);

    case SLED_CMD_SET_MODE:
        return handle_set_mode(dev, msgnum, payload, payload_len);

    case SLED_CMD_ON:
        return handle_on(dev, msgnum);

    case SLED_CMD_OFF:
        return handle_off(dev, msgnum);

    case SLED_CMD_PING:
        return handle_ping(dev, msgnum);

    case SLED_CMD_GET_STATUS:
        return handle_get_status(dev, msgnum);

    case SLED_CMD_GET_MODE:
        return handle_get_mode(dev, msgnum);

    case SLED_CMD_GET_DEVICE_INFO:
        return handle_get_device_info(dev, msgnum);

    case SLED_CMD_NTP_SERVER: {
        /* Never answered: no ACK and no event, also for a payload that does
         * not parse or a device that has no op. */
        shieldnet_ntp_server_req_t req;
        if (shieldnet_parse_ntp_server(payload, payload_len, &req) &&
            dev->set_ntp_server != NULL) {
            dev->set_ntp_server(dev->ctx, &req);
        }
        return 0;
    }

    default: {
        /* A response kind (>= 0x80) is refused without asking the extension
         * (sled 3.1); any other kind the core does not implement is the
         * extension's to answer, or to decline with SHIELDNET_EXT_UNHANDLED. */
        const shieldnet_device_ext_t *ext = ext_of(dev);
        if (kind < 0x80 && ext != NULL) {
            int rc = ext->handle(ext->ctx, dev, kind, msgnum, payload, payload_len);
            if (rc != SHIELDNET_EXT_UNHANDLED) return rc;
        }
        SHIELDNET_LOG_ERR(TAG, "unknown command kind 0x%02x", kind);
        if (dev->emit_event != NULL) {
            dev->emit_event(dev->ctx, SHIELDNET_EVT_COMMAND_ERROR, 0);
        }
        return send_ack(dev, kind, msgnum, SLED_ACK_ERR_UNKNOWN_KIND, "unknown kind");
    }
    }
}
