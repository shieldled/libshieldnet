/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_device — the command core's device seam.
 *
 * Same idea as shieldnet_io_t (see shieldnet_io.h — read that first): one
 * const function table plus an opaque ctx, passed down, never stored in a
 * global. shieldnet_command_dispatch (src/command.c) takes one of these and
 * never touches the RTOS or the device SDK directly.
 *
 * The core never takes a lock. Every op implementation locks *inside* itself
 * around whatever device state it touches, and releases before returning. An
 * op that must perform a whole documented sequence atomically does so under
 * one critical section: splitting it into two ops (or two separate device
 * calls in the caller) reintroduces the race.
 *
 * No allocation on this table: the core never calls malloc/free.
 *
 * What the core does not implement -- an optional layer above it, such as a
 * program extension -- plugs in through the one hook, ops.ext
 * (shieldnet_device_ext_t below).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "command.h"
#include "payload_encode_policy.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Device geometry the core needs where validation is not a pure function of
 * the payload alone: PIXEL_FRAME's buffer-size bound and GET_DEVICE_INFO's
 * geometry fields. */
typedef struct {
    uint16_t num_strips;
    uint16_t leds_per_strip;
    uint8_t  led_bpp;
    /* GET_DEVICE_INFO's envelope field — the device's maximum payload, a
     * device build constant the core cannot reference directly. */
    uint32_t max_payload;
} shieldnet_device_geometry_t;

/* NTP_SERVER's address types (spec/application.md 10.4). */
#define SLED_NTP_ADDR_NAME  1
#define SLED_NTP_ADDR_IPV4  4
#define SLED_NTP_ADDR_IPV6  6

typedef struct {
    uint8_t        addr_type;  /* SLED_NTP_ADDR_* */
    uint8_t        addr_len;   /* 1..253, 4 or 16 */
    uint16_t       port;       /* 1..65535 */
    const uint8_t *addr;       /* points into the payload; not NUL-terminated */
} shieldnet_ntp_server_req_t;

/* Device-level event: a small closed set, only what a handler actually
 * raises. The values are fixed. */
typedef enum {
    SHIELDNET_EVT_FRAME_ERROR = 2,
    SHIELDNET_EVT_COMMAND_ERROR = 3,
} shieldnet_device_event_t;

/* Portable snapshot for GET_STATUS and GET_MODE (spec/application.md 4.3,
 * 5.2): the core's own fields, which the device fills in get_status. */
typedef struct {
    uint64_t frame_count;
    uint64_t command_count;
    uint64_t pixel_frames_dropped;
    uint32_t led_refresh_errors;
    uint8_t  mode;
    bool     connected;
    bool     output_enabled;
    uint8_t  brightness;
    uint8_t  target_fps;
} shieldnet_device_status_t;

/* ── The extension hook (sled 1.4, 5.2, 5.3, 4.3, 7.8) ───────────
 *
 * A device that implements a program extension -- or any other optional layer
 * above the core -- plugs it in through one shieldnet_device_ext_t, referenced
 * by shieldnet_device_ops_t.ext. The core knows nothing about what the
 * extension does: it forwards the command kinds it does not implement, the
 * extension's DEVICE_INFO entries, its STATUS block and its modes through the
 * hook. */

/* STATUS bytes 32-75: the extension block (sled 5.2). */
#define SHIELDNET_STATUS_EXT_OFFSET 32
#define SHIELDNET_STATUS_EXT_SIZE   44
#ifdef __cplusplus
static_assert(SHIELDNET_STATUS_EXT_OFFSET == SLED_STATUS_EXT_OFFSET &&
              SHIELDNET_STATUS_EXT_SIZE == SLED_STATUS_EXT_SIZE,
              "the device header and the STATUS encoder disagree on the extension block");
#else
_Static_assert(SHIELDNET_STATUS_EXT_OFFSET == SLED_STATUS_EXT_OFFSET &&
               SHIELDNET_STATUS_EXT_SIZE == SLED_STATUS_EXT_SIZE,
               "the device header and the STATUS encoder disagree on the extension block");
#endif
/* At most this many capability names, and this many valued fields, an
 * extension adds to DEVICE_INFO. */
#define SHIELDNET_EXT_CAPS_MAX      4
#define SHIELDNET_EXT_FIELDS_MAX    4
/* An extension's handle() returns this for a kind it does not own. */
#define SHIELDNET_EXT_UNHANDLED     1
/* The largest response body this device sends (default: DEVICE_INFO's
 * maximum). An extension whose replies are larger defines it on the compile
 * target, identically for every translation unit (like SN_SEND_QUEUE_MAX).
 * Must be >= SLED_DEVICE_INFO_MAX_BYTES (src/sn_agent_dispatch.c asserts it). */
#ifndef SHIELDNET_MAX_RESPONSE_BODY
#define SHIELDNET_MAX_RESPONSE_BODY SLED_DEVICE_INFO_MAX_BYTES
#endif

struct shieldnet_device_ops;                                   /* defined below */
typedef struct shieldnet_device_ops shieldnet_device_ops_t;   /* the only typedef of it */

/* A valued DEVICE_INFO field: name and value as text, neither NULL nor empty
 * (a capability goes in caps). Defined in payload_encode_policy.h as
 * sled_info_text_field_t { const char *name; const char *value; }, which this
 * header includes. */
typedef sled_info_text_field_t shieldnet_device_field_t;

typedef struct {
    void *ctx;
    /* Capability names the device advertises because it has this extension,
     * appended to DEVICE_INFO and the mDNS caps after the core's. A name is
     * [a-z0-9-], at most 255 bytes, and not one of the core's (envelope,
     * strips, leds, bpp, pixel, pts). */
    const char *const *caps;
    size_t cap_count;      /* the core scans all and keeps the first SHIELDNET_EXT_CAPS_MAX valid ones */
    /* Valued DEVICE_INFO fields, sent after the geometry. Names follow the
     * same rule as caps; a value is any non-empty text of at most 255 bytes
     * (sled 5.3.4). */
    const shieldnet_device_field_t *fields;
    size_t field_count;    /* the core scans all and keeps the first SHIELDNET_EXT_FIELDS_MAX valid ones */
    /* Called for every command kind below 0x80 that the core does not
     * implement (response kinds 0x80-0xFF are answered ERR_UNKNOWN_KIND by
     * the core and never reach it, sled 3.1). Returns SHIELDNET_EXT_UNHANDLED,
     * having sent nothing, for a kind that is not the extension's; the core
     * then answers ERR_UNKNOWN_KIND. Otherwise it sends any typed responses
     * with dev->send_response, then exactly one ACK with shieldnet_send_ack for
     * an answered command (none for a kind the extension defines as
     * response-free), and returns 0 or the first negative send result.
     * payload may be NULL when len is 0. Of dev's ops only send_response is
     * guaranteed non-NULL: handle checks any other op it calls (get_geometry,
     * get_tx_scratch, emit_event, ...) and answers ERR_UNKNOWN_KIND through
     * shieldnet_send_ack when one it needs is NULL. Required when the struct
     * is given; an ext whose handle is NULL is treated as absent everywhere
     * (no caps, fields, modes or STATUS block). */
    int (*handle)(void *ctx, const shieldnet_device_ops_t *dev, uint8_t kind,
                  uint64_t msgnum, const uint8_t *payload, size_t len);
    /* Optional. Fills STATUS bytes 32-75; NULL sends them as zero. Only the
     * program extension (the one advertising `vm`) may set it: the block is
     * that extension's (sled 5.2). */
    void (*fill_status)(void *ctx, uint8_t out[SHIELDNET_STATUS_EXT_SIZE]);
    /* Optional. Whether the device has mode `mode` (any value but 1, PIXEL,
     * which is the core's) through this extension (sled 4.3). NULL: none.
     * Only the program extension may claim mode 0; any other extension uses
     * modes 2-255, tied to its own capability. */
    bool (*has_mode)(void *ctx, uint8_t mode);
} shieldnet_device_ext_t;

/* Sends the ACK for (orig_kind, msgnum) through dev->send_response, applying
 * the response-free gate (no ACK for PIXEL_FRAME or NTP_SERVER). detail may
 * be NULL with detail_len 0; it is truncated to 128 bytes (sled 5.1). */
int shieldnet_send_ack(const shieldnet_device_ops_t *dev, uint8_t orig_kind,
                       uint64_t msgnum, uint8_t status,
                       const uint8_t *detail, size_t detail_len);
/* The same with a NUL-terminated text detail (NULL = none). */
int shieldnet_send_ack_text(const shieldnet_device_ops_t *dev, uint8_t orig_kind,
                            uint64_t msgnum, uint8_t status, const char *detail);

/*
 * What a device advertises follows from this table and its geometry
 * (shieldnet_device_caps below), so what it advertises and what it answers
 * cannot disagree:
 *
 *   - `pixel` needs publish_pixel_frame or publish_pixel_frame_at, plus
 *     note_frame_dropped, emit_event and get_geometry, and a geometry with
 *     num_strips > 0 and leds_per_strip > 0.
 *   - `pts` as shieldnet_device_caps below describes.
 *   - An extension advertises its own capabilities through ext->caps.
 */
struct shieldnet_device_ops {
    void *ctx;

    /* ── Device geometry ───────────────────────────────────────── */
    /* Required in practice: GET_DEVICE_INFO, which every controller sends
     * first, needs it. A device without it answers GET_DEVICE_INFO
     * ERR_UNKNOWN_KIND. */
    void (*get_geometry)(void *ctx, shieldnet_device_geometry_t *out);

    /* ── Output ────────────────────────────────────────────────── */
    /* SET_BRIGHTNESS (spec/application.md 4.1): scales every channel the device
     * outputs by value / 255, in every mode, and the device reports it live in
     * STATUS. Optional: a device without it outputs at full brightness, and
     * the core reports 255 and answers SET_BRIGHTNESS ERR_UNKNOWN_KIND. */
    void (*set_brightness)(void *ctx, uint8_t value);
    /* Also writes the device's live target_fps field (an op owns agent-field
     * writes too). */
    void (*set_fps)(void *ctx, uint8_t fps);

    /* Puts the device in `mode`: 1 (PIXEL) when the device has pixel output, or
     * a value `ext->has_mode` accepted -- already validated by the core
     * (spec/application.md 4.3). Returns 0 on success, nonzero on failure,
     * which the core answers ERR_INVALID_ARG. Optional: with it NULL the
     * core accepts only mode 1 (a pixel device whose only mode is PIXEL) and
     * refuses every other mode. */
    int (*set_mode)(void *ctx, uint8_t mode);
    int (*set_output_enabled)(void *ctx, bool enabled);

    /* PIXEL_FRAME's data-plane publish. Returns true on success. */
    bool (*publish_pixel_frame)(void *ctx, const uint8_t *pixels, int num_pixels);
    /* Optional. The same publish, with the frame's frame_number (identity and
     * logging only, spec/application.md 6.1) and its two timestamps (Frame
     * timing, spec/application.md 6.4), passed on unmodified. When set the core
     * calls it instead of publish_pixel_frame; a device needs one of the two.
     * Returns false only for what publish_pixel_frame rejects (the core then
     * calls note_frame_dropped); a frame the device discards under 6.4.2
     * returns true. `pixels` is valid only during the call: a device that holds
     * the frame copies it, and one that discards it does not read it. */
    bool (*publish_pixel_frame_at)(void *ctx, const uint8_t *pixels, int num_pixels,
                                   int64_t frame_number,
                                   int64_t not_before_ns, int64_t not_after_ns);
    /* Optional. The controller named a time server (NTP_SERVER). Called only for
     * a payload that parses; req->addr is valid only during the call. The
     * message is never answered, whatever the device does with it. */
    void (*set_ntp_server)(void *ctx, const shieldnet_ntp_server_req_t *req);
    /* Increments the device's pixel_frames_dropped counter. Required of every
     * device: one without pixel output discards each PIXEL_FRAME and MUST count
     * it (sled 1.4). With it NULL the core logs instead of counting. */
    void (*note_frame_dropped)(void *ctx);
    /* Optional. Increments the device's command_count, which STATUS reports:
     * the core calls it once for every message it dispatches other than
     * PIXEL_FRAME, before handling it, so a GET_STATUS counts itself
     * (spec/application.md 5.2). With it NULL the device counts nothing and
     * STATUS reports whatever get_status fills in. */
    void (*note_command)(void *ctx);

    /* ── Status / device info scratch ─────────────────────────── */
    /* Fills the portable status snapshot behind GET_STATUS and GET_MODE
     * (spec/application.md 4.3, 5.2). It MUST fill `mode` and `brightness`, as
     * well as the counters and the two live fields connected/output_enabled
     * and target_fps. The core reports `mode` only if it is a mode the device
     * has (1 with pixel output, or one `ext->has_mode` accepts), else 1; and
     * `brightness` only if the device has set_brightness, else 255. It encodes
     * the STATUS body itself (payload_encode_policy.h), so the encoding stays
     * in the core and host-tested. */
    void (*get_status)(void *ctx, shieldnet_device_status_t *out);

    /* A response scratch buffer the core serialises DEVICE_INFO into. *cap
     * bounds what the core may write; the core never allocates. Its capacity
     * must be at least SLED_DEVICE_INFO_MAX_BYTES, and at least the largest
     * reply an installed extension writes there. */
    void (*get_tx_scratch)(void *ctx, uint8_t **buf, size_t *cap);

    /* ── Events + response path ───────────────────────────────── */
    /* Optional. Told of a malformed PIXEL_FRAME (FRAME_ERROR) or an unknown
     * command kind (COMMAND_ERROR). `arg` is always 0. */
    void (*emit_event)(void *ctx, shieldnet_device_event_t ev, uint8_t arg);
    /* Returns 0 on success, <0 on error. */
    int (*send_response)(void *ctx, uint8_t kind, const uint8_t *body, size_t len);

    /* ── Extension ─────────────────────────────────────────────── */
    /* Optional: NULL = no extension. The core forwards every kind it does not
     * implement, the extension's DEVICE_INFO entries, its STATUS block and its
     * modes through it (see shieldnet_device_ext_t). Must outlive the ops. */
    const shieldnet_device_ext_t *ext;
};

/*
 * Dispatch an already-decrypted-and-decompressed message payload
 * (src/command.c). `hdr` is the 20-byte header as received (needed for ACK
 * correlation). `payload` is the plaintext, post-decompression when
 * applicable. Contains no locking and no RTOS or device SDK references.
 *
 * Returns 0 if every response for this message was sent successfully,
 * negative if any send_response call failed. The core only reports the
 * failure; it never decides whether that ends the session -- that policy
 * belongs to the port, since handlers are shared across every device. A port
 * that ignores this return degrades rather than breaks.
 */
int shieldnet_command_dispatch(const shieldnet_device_ops_t *dev,
                               const protocol_msg_header_t *hdr,
                               const uint8_t *payload, size_t payload_len);

/*
 * The device's capabilities, derived from its ops table and geometry
 * (src/command.c). `geo` is what get_geometry reports, or all zero when
 * get_geometry is NULL.
 *
 * shieldnet_device_has_pixel: a publish op, note_frame_dropped, emit_event and
 * get_geometry are set, and the geometry has strips and LEDs.
 */
bool shieldnet_device_has_pixel(const shieldnet_device_ops_t *dev,
                                const shieldnet_device_geometry_t *geo);

/* The most names shieldnet_device_caps writes: the core's two and the
 * extension's. */
#define SHIELDNET_DEVICE_CAPS_MAX (2 + SHIELDNET_EXT_CAPS_MAX)

/*
 * Writes the advertised capability names to out[] in this order and returns
 * how many it wrote (at most `max`): "pixel" if has_pixel; "pts" if
 * has_pixel, CONFIG_SLED_PTS and publish_pixel_frame_at is set (sled 5.3.3
 * rule 1, 6.5); then the active extension's valid capability names, at most
 * SHIELDNET_EXT_CAPS_MAX of them (ext->caps). The DEVICE_INFO list.
 */
size_t shieldnet_device_caps(const shieldnet_device_ops_t *dev,
                             const shieldnet_device_geometry_t *geo,
                             const char *out[], size_t max);

/* The same names joined by ',' -- the mDNS `caps` value. False if it does not
 * fit in `cap` bytes with its terminator. */
bool shieldnet_device_caps_str(const shieldnet_device_ops_t *dev,
                               const shieldnet_device_geometry_t *geo,
                               char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
