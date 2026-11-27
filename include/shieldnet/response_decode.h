/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Response decoders — the client half of the sled layer, and the inverse of
 * payload_encode_policy.h.
 *
 * Every decoder is total: it takes a length and refuses rather than reading
 * past it. That is the whole job. A response arrives from the network, and the
 * layer above has already authenticated it but has not checked that a device
 * running different firmware sent a payload this build understands.
 *
 * Forward compatibility, per the spec's R2/R3/R6:
 *
 *   R3  Trailing bytes beyond a known layout are IGNORED, never an error. A
 *       decoder therefore checks `len >= minimum`, never `len == expected`.
 *   R6  A later revision may add a tier above a fixed-size response, which is
 *       the same rule seen from the other side.
 *   R2  An unrecognised response KIND is skipped by the caller, not decoded
 *       here — there is deliberately no dispatch function in this header.
 *
 * The one place that rule inverts is a payload shorter than its documented
 * minimum: that is malformed, not an older peer, and it is refused.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "command.h"
#include "payload_encode_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline uint16_t sled_dec_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t sled_dec_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static inline uint64_t sled_dec_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* ── ACK (0x80) ────────────────────────────────────────────────── */

typedef struct {
    uint8_t        orig_kind;
    uint8_t        status;
    uint64_t       orig_message_num;
    const uint8_t *detail;      /* points into the caller's buffer */
    uint16_t       detail_len;
} sled_ack_t;

/*
 * `detail` aliases the input buffer rather than copying: the caller owns the
 * bytes and knows their lifetime, and an ACK is consumed immediately. A caller
 * that retains it past the buffer must copy.
 *
 * detail_len is checked against the payload, so a device claiming more detail
 * than it sent is refused instead of handing back a pointer to nothing.
 */
static inline bool sled_decode_ack(const uint8_t *p, size_t len, sled_ack_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len < SLED_ACK_HEADER_SIZE) return false;

    uint16_t detail_len = sled_dec_be16(&p[12]);
    if (len - SLED_ACK_HEADER_SIZE < detail_len) return false;

    out->orig_kind        = p[0];
    out->status           = p[1];
    out->orig_message_num = sled_dec_be64(&p[4]);
    out->detail           = detail_len ? &p[SLED_ACK_HEADER_SIZE] : NULL;
    out->detail_len       = detail_len;
    return true;
}

/* ── STATUS_RESP (0x81) ────────────────────────────────────────── */

static inline bool sled_decode_status_resp(const uint8_t *p, size_t len,
                                            sled_status_resp_fields_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len < SLED_STATUS_RESP_SIZE) return false;   /* short is malformed */

    out->frame_count          = sled_dec_be64(&p[0]);
    out->command_count        = sled_dec_be64(&p[8]);
    out->pixel_frames_dropped = sled_dec_be64(&p[16]);
    out->led_refresh_errors   = sled_dec_be32(&p[24]);
    out->mode                 = p[28];
    out->connected            = p[29] != 0;
    out->output_enabled       = p[30] != 0;
    memcpy(out->ext, &p[SLED_STATUS_EXT_OFFSET], SLED_STATUS_EXT_SIZE);
    out->brightness           = p[76];
    out->target_fps           = p[77];
    return true;
}

/* ── DEVICE_INFO (0x84) ────────────────────────────────────────── */

/*
 * A sequence of [u8 namelen][name][u8 vallen][value] pairs with no count
 * prefix: a receiver reads pairs until the payload ends. Values are decimal
 * ASCII, and a capability is a field with an EMPTY value.
 *
 * This is an iterator rather than a decode-into-struct, because the payload is
 * open-ended by design (R7) — a build that decoded only the four required
 * fields into a struct would silently drop every capability and every field
 * added later, which is the opposite of what R7 asks for.
 *
 * Returns false at the end of the payload or on a truncated field. Distinguish
 * the two with *off == len: a clean end leaves the offset at the payload's end.
 *
 * It bounds the payload's size but does not count fields: sled 5.3.3 rule 5's
 * limit of SLED_DEVICE_INFO_MAX_FIELDS is checked by sled_decode_geometry, so a
 * receiver validates a DEVICE_INFO with sled_decode_geometry before iterating.
 */
typedef struct {
    const char *name;
    uint8_t     name_len;
    const char *value;      /* NULL when the field is a capability */
    uint8_t     value_len;
} sled_device_info_field_t;

static inline bool sled_device_info_next(const uint8_t *p, size_t len, size_t *off,
                                          sled_device_info_field_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len > SLED_DEVICE_INFO_MAX_BYTES) return false; /* rule 5, as Go */
    if (*off >= len) return false;

    size_t o = *off;
    if (len - o < 1) return false;
    uint8_t namelen = p[o++];
    if (len - o < namelen) return false;
    const uint8_t *name = &p[o];
    o += namelen;

    if (len - o < 1) return false;
    uint8_t vallen = p[o++];
    if (len - o < vallen) return false;
    const uint8_t *value = &p[o];
    o += vallen;

    out->name      = (const char *)name;
    out->name_len  = namelen;
    out->value     = vallen ? (const char *)value : NULL;
    out->value_len = vallen;
    *off = o;
    return true;
}

/* Convenience: match a field's name without needing it NUL-terminated. */
static inline bool sled_device_info_name_is(const sled_device_info_field_t *f,
                                             const char *name)
{
    size_t n = strlen(name);
    return n == f->name_len && memcmp(f->name, name, n) == 0;
}

/*
 * Whether DEVICE_INFO has a field with this name, whatever its value. A
 * capability is advertised by the field's presence (sled 5.3.1): a receiver
 * does not require its value to be empty.
 */
static inline bool sled_device_info_has(const uint8_t *p, size_t len, const char *name)
{
    size_t off = 0;
    sled_device_info_field_t f;
    while (sled_device_info_next(p, len, &off, &f)) {
        if (sled_device_info_name_is(&f, name)) return true;
    }
    return false;
}

/*
 * Parse a decimal-ASCII value. DEVICE_INFO carries numbers as text, so every
 * consumer needs this and none should hand-roll it: an implementation using
 * atoi on a non-terminated slice reads past the field.
 */
static inline bool sled_device_info_value_u32(const sled_device_info_field_t *f,
                                               uint32_t *out)
{
    if (f->value_len == 0 || f->value_len > 10) return false;
    /* "no leading zeros" is a protocol error in the spec and in Go's Uint32. */
    if (f->value_len > 1 && f->value[0] == '0') return false;
    uint32_t v = 0;
    for (uint8_t i = 0; i < f->value_len; i++) {
        char c = f->value[i];
        if (c < '0' || c > '9') return false;
        uint32_t d = (uint32_t)(c - '0');
        if (v > (UINT32_MAX - d) / 10u) return false;   /* overflow */
        v = v * 10u + d;
    }
    *out = v;
    return true;
}

/*
 * The DEVICE_INFO size and geometry fields, validated. A port of goshieldnet's
 * DecodeGeometry (sled/response.go): envelope MUST be present; strips, leds and
 * bpp MUST be present when the device advertises `pixel` (sled 5.3.3 rule 1).
 * Without `pixel` they are optional as a group: all three absent gives
 * strips = leds = bpp = 0, all three present are validated as with `pixel`, and
 * one or two of them is refused. A repeated name takes its LAST value (rule 4)
 * and that value is the one checked, each value is canonical decimal within its
 * range (bpp exactly 3 or 4), and strips x leds x bpp must not exceed
 * SLED_GEOMETRY_CAPACITY_MAX. More than SLED_DEVICE_INFO_MAX_FIELDS fields (sled
 * 5.3.3 rule 5), any other violation, or a truncated field, returns false
 * and leaves *out untouched; a caller MUST reject the DEVICE_INFO rather than
 * substitute a default.
 */
#define SLED_GEOMETRY_CAPACITY_MAX 16777216u

typedef struct {
    uint32_t envelope;
    /* All three 0 when a device without `pixel` sends none of them. */
    uint32_t strips;
    uint32_t leds;
    uint8_t  bpp;
} sled_geometry_t;

static inline bool sled_decode_geometry(const uint8_t *p, size_t len, sled_geometry_t *out)
{
    static const char *const names[4] = { "envelope", "strips", "leds", "bpp" };
    static const uint32_t lo[4] = { 80u, 1u, 1u, 3u };
    static const uint32_t hi[4] = { 16777216u, 65535u, 65535u, 4u };
    sled_device_info_field_t last[4];
    bool have[4] = { false, false, false, false };
    uint32_t v[4];
    bool pixel = false;
    size_t off = 0;
    size_t fields = 0;
    sled_device_info_field_t f;

    while (sled_device_info_next(p, len, &off, &f)) {
        /* sled 5.3.3 rule 5: at most SLED_DEVICE_INFO_MAX_FIELDS fields. */
        if (++fields > SLED_DEVICE_INFO_MAX_FIELDS) return false;
        for (int i = 0; i < 4; i++) {
            if (sled_device_info_name_is(&f, names[i])) {
                last[i] = f;
                have[i] = true;
            }
        }
        if (sled_device_info_name_is(&f, "pixel")) pixel = true;
    }
    if (off != len) return false; /* truncated field, or over the size cap */

    /* strips, leds, bpp: required with pixel; without it all or none. */
    int geometry_fields = (int)have[1] + (int)have[2] + (int)have[3];
    if (pixel && geometry_fields != 3) return false;
    if (geometry_fields != 0 && geometry_fields != 3) return false;
    v[1] = v[2] = v[3] = 0;
    for (int i = 0; i < 4; i++) {
        if (!have[i]) {
            if (i == 0) return false;   /* envelope, always */
            continue;
        }
        if (!sled_device_info_value_u32(&last[i], &v[i])) return false;
        if (v[i] < lo[i] || v[i] > hi[i]) return false;
    }
    if ((uint64_t)v[1] * v[2] * v[3] > SLED_GEOMETRY_CAPACITY_MAX) return false;

    out->envelope = v[0];
    out->strips = v[1];
    out->leds = v[2];
    out->bpp = (uint8_t)v[3];
    return true;
}

#ifdef __cplusplus
}
#endif
