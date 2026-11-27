/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Pure payload encoders shared by firmware and host regression tests.
 *
 * Covers the response payloads whose layout is fixed by
 * spec/application.md: STATUS_RESP (0x81, 78 bytes), DEVICE_INFO (0x84, a
 * sequence of [namelen][name][vallen][value] text fields) and ACK (0x80).
 * Nothing here touches ESP-IDF or FreeRTOS, which is what makes them testable
 * on the host.
 *
 * Every encoder here refuses rather than truncating when the output would not
 * fit, and none of them writes past `cap`. The one exception is ACK's detail
 * string, which the wire format itself bounds at 128 bytes: an over-long
 * detail is clamped, because a diagnostic is not worth failing a response
 * over. That asymmetry is the protocol's, not this file's.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── ACK (0x80) ────────────────────────────────────────────────────
 *
 *   [u8 orig_kind][u8 status][u8 rsv x2][be64 orig_message_num]
 *   [be16 detail_len][detail bytes]
 *
 * orig_message_num is what correlates a response to the command that caused
 * it — the spec's "Query framing" section requires correlation by that field
 * and never by message order, so a device MUST echo the number it was asked
 * with.
 *
 * Callers must consult sled_command_allows_ack() (command_response_policy.h)
 * BEFORE calling this: PIXEL_FRAME is response-free, and a controller that
 * blocks waiting for its ACK waits forever — once per frame at 30 fps. This
 * encoder deliberately does not check that itself, because suppressing a
 * response is a dispatch decision, not an encoding one.
 */

#define SLED_ACK_HEADER_SIZE  14
#define SLED_ACK_MAX_DETAIL   128
#define SLED_ACK_MAX_SIZE     (SLED_ACK_HEADER_SIZE + SLED_ACK_MAX_DETAIL)

/* Encodes into out (capacity cap) and sets *out_len. detail_len is clamped to
 * SLED_ACK_MAX_DETAIL. Returns false, writing nothing usable, if cap cannot
 * hold the result. */
static inline bool sled_encode_ack(uint8_t orig_kind, uint8_t status,
                                    uint64_t orig_message_num,
                                    const uint8_t *detail, size_t detail_len,
                                    uint8_t *out, size_t cap, size_t *out_len)
{
    if (detail_len > SLED_ACK_MAX_DETAIL) detail_len = SLED_ACK_MAX_DETAIL;
    size_t need = SLED_ACK_HEADER_SIZE + detail_len;
    if (cap < need) return false;

    out[0] = orig_kind;
    out[1] = status;
    out[2] = 0;   /* rsv: zero on send, ignored on receive (R4) */
    out[3] = 0;
    for (int i = 0; i < 8; i++) out[4 + i] = (uint8_t)(orig_message_num >> (56 - 8 * i));
    out[12] = (uint8_t)(detail_len >> 8);
    out[13] = (uint8_t)detail_len;
    if (detail_len > 0) memcpy(&out[SLED_ACK_HEADER_SIZE], detail, detail_len);

    *out_len = need;
    return true;
}

/* ── DEVICE_INFO capability names ──
 *
 * Which of these a device advertises is not fixed at build time: it follows
 * from the device's ops table and geometry. shieldnet_device_caps
 * (port/shieldnet_device.h) gives the DEVICE_INFO list and
 * shieldnet_device_caps_str the mDNS `caps=` TXT value, from one derivation,
 * so the two carriers cannot disagree.
 */
#define SLED_CAP_PIXEL          "pixel"

/* Advertised by an image that keeps an NTP-synced clock and implements
 * spec/application.md's Frame timing (CONFIG_SLED_PTS). */
#define SLED_CAP_PTS            "pts"

/* ── DEVICE_INFO bounds (spec/application.md R7 "Bounded") ──────────── */

#define SLED_DEVICE_INFO_MAX_BYTES  1024
/* strips x leds x bpp ceiling, matching spec/application.md and goshieldnet's
 * decoder. Equal to the transport's MaxPayloadSize: a capacity above the
 * largest possible envelope can never be the binding term in a client's
 * derived frame limit. */
#define SLED_DEVICE_INFO_MAX_CAPACITY 16777216u

#define SLED_DEVICE_INFO_MAX_FIELDS 32

/*
 * Append one [namelen][name][vallen][value] field to buf at *off, refusing
 * (and leaving *off unchanged) rather than overflowing cap. An empty or
 * NULL value writes vallen 0 with no value bytes -- how a capability is
 * emitted.
 */
static inline bool sled_field_put(uint8_t *buf, size_t cap, size_t *off,
                                   const char *name, const char *value)
{
    size_t namelen = name ? strlen(name) : 0;
    size_t vallen  = value ? strlen(value) : 0;
    if (namelen > 255 || vallen > 255) return false;

    size_t needed = 1 + namelen + 1 + vallen;
    if (*off > cap || needed > cap - *off) return false;

    size_t o = *off;
    buf[o++] = (uint8_t)namelen;
    if (namelen) { memcpy(&buf[o], name, namelen); o += namelen; }
    buf[o++] = (uint8_t)vallen;
    if (vallen) { memcpy(&buf[o], value, vallen); o += vallen; }

    *off = o;
    return true;
}

/* A valued DEVICE_INFO field as text: neither name nor value is NULL or empty
 * (a capability is a name alone). Not sled_device_info_field_t, which
 * response_decode.h defines for the decoded form. */
typedef struct {
    const char *name;
    const char *value;
} sled_info_text_field_t;

/* ── DEVICE_INFO (0x84) ────────────────────────────────────────────
 *
 * envelope/strips/leds/bpp are the four required fields (spec/application.md
 * R1); capabilities is the list of empty-valued fields (pixel, pts, ...).
 * Ranges below are spec/application.md's, restated because two independent
 * implementations cannot each invent their own.
 */
typedef struct {
    uint32_t envelope;   /* CONFIG_SLED_MAX_PAYLOAD; 80 - 16777216 (sled 5.3.1) */
    uint32_t strips;     /* num_strips; 1 - 65535, or 0 with leds and bpp 0 */
    uint32_t leds;       /* leds_per_strip; 1 - 65535 */
    uint8_t  bpp;        /* 3 (RGB) or 4 (RGBW) -- an enum, nothing else */
    const char * const *capabilities;
    size_t   capability_count;
    /* Extra valued fields, sent after the geometry. Each is
     * counted against SLED_DEVICE_INFO_MAX_FIELDS; a NULL or empty name or
     * value refuses the encoding. NULL with count 0 for none. */
    const sled_info_text_field_t *extra_fields;
    size_t   extra_field_count;
} sled_device_info_fields_t;

/*
 * Encode DEVICE_INFO into buf (capacity cap), table order: envelope,
 * strips, leds, bpp, each extra field, then each capability in array order. strips = leds = bpp = 0 omits those three fields; all three non-zero
 * emits them; any other mix is refused. Refuses --
 * returns false, writes nothing usable to *out_len -- if any field is out
 * of its stated range, or the payload would exceed SLED_DEVICE_INFO_MAX_BYTES
 * / SLED_DEVICE_INFO_MAX_FIELDS. An out-of-range value is a self-inflicted
 * disconnect if shipped, so this is where it is caught instead.
 */
static inline bool sled_encode_device_info(const sled_device_info_fields_t *f,
                                            uint8_t *buf, size_t cap,
                                            size_t *out_len)
{
    if (f->envelope < 80 || f->envelope > 16777216) return false;
    /* strips = leds = bpp = 0 omits the three (a device without pixel output
     * need not send them, sled 5.3.3 rule 1); all three set is validated; any
     * other mix is refused. */
    bool emit_geometry = f->strips != 0 || f->leds != 0 || f->bpp != 0;
    if (emit_geometry) {
        if (f->strips < 1 || f->strips > 65535) return false;
        if (f->leds < 1 || f->leds > 65535) return false;
        if (f->bpp != 3 && f->bpp != 4) return false;
        /* The capacity the geometry implies is bounded too, not just each
         * field: spec/application.md requires a receiver to reject a geometry
         * whose strips x leds x bpp exceeds SLED_DEVICE_INFO_MAX_CAPACITY. At
         * the per-field maxima the product reaches ~1.7e10, so it is computed
         * in 64 bits -- and refused here, at the boundary this device
         * controls, rather than shipped for the controller to reject and tear
         * the session down. */
        if ((uint64_t)f->strips * (uint64_t)f->leds * (uint64_t)f->bpp
            > SLED_DEVICE_INFO_MAX_CAPACITY) return false;
    }

    for (size_t i = 0; i < f->extra_field_count; i++) {
        const sled_info_text_field_t *x = &f->extra_fields[i];
        if (!x->name || !x->name[0] || !x->value || !x->value[0]) return false;
    }

    size_t field_count = 1 + (emit_geometry ? 3 : 0)
                       + f->extra_field_count + f->capability_count;
    if (field_count > SLED_DEVICE_INFO_MAX_FIELDS) return false;
    if (cap > SLED_DEVICE_INFO_MAX_BYTES) cap = SLED_DEVICE_INFO_MAX_BYTES;

    char envelope_str[11];
    char strips_str[6];
    char leds_str[6];
    char bpp_str[4];
    snprintf(envelope_str, sizeof envelope_str, "%u", (unsigned)f->envelope);
    snprintf(strips_str, sizeof strips_str, "%u", (unsigned)f->strips);
    snprintf(leds_str, sizeof leds_str, "%u", (unsigned)f->leds);
    snprintf(bpp_str, sizeof bpp_str, "%u", (unsigned)f->bpp);

    size_t off = 0;
    if (!sled_field_put(buf, cap, &off, "envelope", envelope_str)) return false;
    if (emit_geometry) {
        if (!sled_field_put(buf, cap, &off, "strips", strips_str)) return false;
        if (!sled_field_put(buf, cap, &off, "leds", leds_str)) return false;
        if (!sled_field_put(buf, cap, &off, "bpp", bpp_str)) return false;
    }
    for (size_t i = 0; i < f->extra_field_count; i++) {
        if (!sled_field_put(buf, cap, &off, f->extra_fields[i].name,
                            f->extra_fields[i].value)) return false;
    }
    for (size_t i = 0; i < f->capability_count; i++) {
        if (!sled_field_put(buf, cap, &off, f->capabilities[i], NULL)) return false;
    }

    *out_len = off;
    return true;
}

/* ── STATUS_RESP (0x81) — fixed 78-byte layout ───────────────────
 *
 * Bytes 0-31 and 76-77 are the core's. Bytes 32-75 are the extension block
 * (sled 5.2): the core sends and receives them verbatim and gives them no
 * meaning, zero when the device has no extension. */

#define SLED_STATUS_RESP_SIZE 78
#define SLED_STATUS_EXT_OFFSET 32
#define SLED_STATUS_EXT_SIZE   44

typedef struct {
    uint64_t frame_count;
    uint64_t command_count;
    uint64_t pixel_frames_dropped;
    uint32_t led_refresh_errors;
    uint8_t  mode;
    bool     connected;
    bool     output_enabled;
    uint8_t  ext[SLED_STATUS_EXT_SIZE];   /* bytes 32-75, verbatim */
    uint8_t  brightness;   /* live a->brightness, not cfg->default_brightness */
    uint8_t  target_fps;   /* live a->target_fps, not cfg->target_fps */
} sled_status_resp_fields_t;

static inline void sled_enc_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void sled_enc_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void sled_enc_put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static inline void sled_encode_status_resp(
    const sled_status_resp_fields_t *f,
    uint8_t out[SLED_STATUS_RESP_SIZE])
{
    memset(out, 0, SLED_STATUS_RESP_SIZE);

    sled_enc_put_be64(&out[0],  f->frame_count);
    sled_enc_put_be64(&out[8],  f->command_count);
    sled_enc_put_be64(&out[16], f->pixel_frames_dropped);
    sled_enc_put_be32(&out[24], f->led_refresh_errors);
    out[28] = f->mode;
    out[29] = f->connected ? 1 : 0;
    out[30] = f->output_enabled ? 1 : 0;
    /* rsv at [31] */
    memcpy(&out[SLED_STATUS_EXT_OFFSET], f->ext, SLED_STATUS_EXT_SIZE);
    out[76] = f->brightness;
    out[77] = f->target_fps;
}

#ifdef __cplusplus
}
#endif
