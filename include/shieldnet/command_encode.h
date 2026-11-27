/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Pure command encoders — the exact inverse of command_parse.h, over the same
 * request structs.
 *
 * Sharing the structs is what makes the pair testable: the property
 *
 *     parse_g(encode(req)) == req
 *
 * is stronger than any table of expected bytes, and it makes the encoder's
 * correctness the parser's definition of correct, which is the definition the
 * device actually applies. A parallel set of request types would destroy that,
 * so there is deliberately none.
 *
 * Every function returns the number of bytes written, or 0 if the request
 * cannot be encoded — either because `cap` is too small or because the request
 * is one the parser would reject. **An encoder never emits bytes the parser
 * refuses** (R5: an unrecognised enum is refused, never guessed at), so a
 * caller cannot build an undeliverable command by accident.
 *
 * The 6 payload-free kinds (ON, OFF, PING, GET_STATUS, GET_MODE,
 * GET_DEVICE_INFO) have no encoder: they are a kind byte and an
 * empty payload. Use the SLED_CMD_* constants directly.
 *
 * PIXEL_FRAME is the one payload-carrying kind with no request struct — it is
 * validated as a raw buffer by pixel_frame_policy.h, not parsed into fields —
 * so its helper below is shaped differently on purpose.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "command.h"
#include "command_parse.h"
#include "pixel_frame_policy.h"
#include "shieldnet_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Big-endian helpers (inverses of command_parse.h's getters) ── */

static inline void shieldnet_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void shieldnet_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void shieldnet_put_be64(uint8_t *p, uint64_t v)
{
    shieldnet_put_be32(&p[0], (uint32_t)(v >> 32));
    shieldnet_put_be32(&p[4], (uint32_t)v);
}

/* ── SET_BRIGHTNESS (0x01) — [u8 value] ─────────────────────── */

static inline size_t shieldnet_encode_set_brightness(
    const shieldnet_set_brightness_req_t *req, uint8_t *buf, size_t cap)
{
    if (cap < 1) return 0;
    buf[0] = req->value;
    return 1;
}

/* ── SET_FPS (0x02) — [u8 fps] ────────────────────────────────
 *
 * fps == 0 is refused here because the parser refuses it. Encoding it would
 * produce a command guaranteed to come back as ERR_INVALID_ARG.
 */
static inline size_t shieldnet_encode_set_fps(
    const shieldnet_set_fps_req_t *req, uint8_t *buf, size_t cap)
{
    if (cap < 1 || req->fps == 0) return 0;
    buf[0] = req->fps;
    return 1;
}

/* ── SET_MODE (0x04) — [u8 mode] ──────────────────────────────
 *
 * Any byte, as the parser accepts any byte: which modes exist is the device's
 * (sled 4.3), so there is nothing to refuse here.
 */
static inline size_t shieldnet_encode_set_mode(
    const shieldnet_set_mode_req_t *req, uint8_t *buf, size_t cap)
{
    if (cap < 1) return 0;
    buf[0] = req->wire_mode;
    return 1;
}

/* ── NTP_SERVER (0x0B) — [u8 addr_type][u8 len][be16 port][address] ──
 *
 * Writes the four fields as given and returns 4 + addr_len, or 0 when cap is
 * too small or shieldnet_parse_ntp_server would refuse what was written. */
static inline size_t shieldnet_encode_ntp_server(
    const shieldnet_ntp_server_req_t *req, uint8_t *buf, size_t cap)
{
    size_t need = (size_t)4 + req->addr_len;
    if (cap < need || (req->addr_len > 0 && req->addr == NULL)) return 0;
    buf[0] = req->addr_type;
    buf[1] = req->addr_len;
    buf[2] = (uint8_t)(req->port >> 8);
    buf[3] = (uint8_t)req->port;
    if (req->addr_len > 0) memmove(&buf[4], req->addr, req->addr_len);
    shieldnet_ntp_server_req_t chk;
    if (!shieldnet_parse_ntp_server(buf, need, &chk)) return 0;
    return need;
}

/* ── PIXEL_FRAME (0x00) ─────────────────────────────────────────
 *
 * Not a struct-shaped command: the payload is the raw frame, and the device
 * validates it as a buffer.
 *
 * **The wire stride is 4 bytes per pixel, unconditionally** — an RGB strip's
 * frame still carries the W byte and the device ignores it. DEVICE_INFO's
 * `bpp` describes the STRIP, for colour handling; deriving the stride from it
 * would make an RGB unit reject every frame a 4bpp controller sends. See
 * pixel_frame_policy.h.
 *
 * Returns the frame length, or 0 if the buffer is not a whole number of
 * 4-byte pixels or does not fit the device's geometry — the same predicate the
 * device applies, so a frame this accepts is one the device accepts.
 *
 * shieldnet_pixel_frame_valid also requires at least one pixel (sled 6.1) and
 * a frame that fits the device's envelope with the 28-byte header and the
 * 16-byte tag, in whole pixels (sled 6.2): frame_len <= (max_payload - 44)
 * rounded down to a multiple of 4. An envelope below 44 fits no frame.
 */
static inline size_t shieldnet_pixel_frame_len(uint32_t pixel_count)
{
    return (size_t)pixel_count * SLED_PIXEL_WIRE_BPP;
}

static inline bool shieldnet_pixel_frame_valid(
    uint32_t frame_len, const shieldnet_device_geometry_t *geo)
{
    /* Capacity is in BYTES, so the wire stride is a factor here too — the
     * device computes it the same way (command.c). Passing the geometry's
     * pixel counts straight through would compile silently, every argument
     * being integral, and accept frames four times too large. */
    /* In 64 bits, as command.c does: on a 32-bit size_t (ESP32, or a 32-bit
     * client using DEVICE_INFO's geometry) the product can wrap to a small
     * capacity. frame_len is 32-bit, so clamping there loses nothing. */
    uint64_t cap64 = (uint64_t)geo->num_strips * geo->leds_per_strip * SLED_PIXEL_WIRE_BPP;
    size_t capacity_bytes = cap64 > UINT32_MAX ? (size_t)UINT32_MAX : (size_t)cap64;
    if (geo->max_payload < 28u + 16u) return false;
    if (frame_len > ((geo->max_payload - 28u - 16u) & ~3u)) return false;
    return sled_pixel_frame_buffer_valid(frame_len, SLED_PIXEL_WIRE_BPP,
                                         capacity_bytes);
}

/* The fixed prefix of a PIXEL_FRAME payload (goshieldnet sled.PixelFrameHeader):
 * [be64 frame_number][be64 not_before][be64 not_after][be32 pixel_len], the
 * pixel bytes follow. The three leading fields are signed on the wire. Writes
 * exactly 28 bytes; the caller appends pixel_len bytes of pixels. */
#define SHIELDNET_PIXEL_FRAME_HEADER_LEN 28

static inline void shieldnet_encode_pixel_frame_header(
    uint64_t frame_no, int64_t not_before, int64_t not_after,
    uint32_t pixel_len, uint8_t out[SHIELDNET_PIXEL_FRAME_HEADER_LEN])
{
    shieldnet_put_be64(&out[0], frame_no);
    shieldnet_put_be64(&out[8], (uint64_t)not_before);
    shieldnet_put_be64(&out[16], (uint64_t)not_after);
    shieldnet_put_be32(&out[24], pixel_len);
}

#ifdef __cplusplus
}
#endif
