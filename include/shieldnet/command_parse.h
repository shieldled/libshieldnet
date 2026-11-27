/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Pure command parsers shared by firmware and host regression tests. One
 * function per payload-carrying core command (SET_BRIGHTNESS, SET_FPS,
 * SET_MODE, NTP_SERVER -- see command.h; PIXEL_FRAME is validated as a raw
 * buffer by pixel_frame_policy.h).
 *
 * Each parser is: bytes in, a validated request struct out, no I/O, no
 * allocation, no locking. Follows pixel_frame_policy.h's style: static inline,
 * usable from both the firmware build and a bare host compiler.
 *
 * Every parser zero-initialises *out before validating and never writes it on
 * rejection. A caller that ignores the result gets zeroes, not garbage, and it
 * keeps -Wmaybe-uninitialized from firing under -Werror when a rejected result
 * feeds a struct built through this file.
 *
 * R5 (spec/application.md 7.5): an unrecognised enum is refused, never guessed
 * at. SET_MODE's mode byte is not validated here: which modes exist is the
 * device's (sled 4.3), so the command core checks it against the device.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "command.h"
#include "shieldnet_device.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Big-endian helpers ───────────────────────────────────────── */

static inline uint16_t shieldnet_get_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t shieldnet_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* ── Parse result ──────────────────────────────────────────────
 *
 * ok == true: *out was written, ack_status/ack_detail are unused.
 * ok == false: *out was left zeroed. ack_status is the SLED_ACK_* the
 * caller sends; ack_detail is NULL or a static string (never freed).
 */
typedef struct {
    bool        ok;
    uint8_t     ack_status;
    const char *ack_detail;
} shieldnet_parse_result_t;

static inline shieldnet_parse_result_t shieldnet_parse_ok(void)
{
    shieldnet_parse_result_t r = { true, 0, NULL };
    return r;
}

static inline shieldnet_parse_result_t shieldnet_parse_reject(uint8_t status,
                                                               const char *detail)
{
    shieldnet_parse_result_t r = { false, status, detail };
    return r;
}

/* ── SET_BRIGHTNESS (0x01) ──────────────────────────────────────
 * [u8 value], min 1 byte. */
typedef struct { uint8_t value; } shieldnet_set_brightness_req_t;

static inline shieldnet_parse_result_t shieldnet_parse_set_brightness(
    const uint8_t *p, size_t len, shieldnet_set_brightness_req_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len < 1) return shieldnet_parse_reject(SLED_ACK_ERR_INVALID_ARG, NULL);
    out->value = p[0];
    return shieldnet_parse_ok();
}

/* ── SET_FPS (0x02) ─────────────────────────────────────────────
 * [u8 fps], min 1 byte, fps == 0 is rejected. */
typedef struct { uint8_t fps; } shieldnet_set_fps_req_t;

static inline shieldnet_parse_result_t shieldnet_parse_set_fps(
    const uint8_t *p, size_t len, shieldnet_set_fps_req_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len < 1 || p[0] == 0) {
        return shieldnet_parse_reject(SLED_ACK_ERR_INVALID_ARG, NULL);
    }
    out->fps = p[0];
    return shieldnet_parse_ok();
}

/* ── SET_MODE (0x04) ────────────────────────────────────────────
 * [u8 mode], min 1 byte. Any byte parses: the modes a device has are its own
 * (sled 4.3), and the command core refuses one it does not have. */
typedef struct { uint8_t wire_mode; } shieldnet_set_mode_req_t;

static inline shieldnet_parse_result_t shieldnet_parse_set_mode(
    const uint8_t *p, size_t len, shieldnet_set_mode_req_t *out)
{
    memset(out, 0, sizeof(*out));
    if (len < 1) return shieldnet_parse_reject(SLED_ACK_ERR_INVALID_ARG, NULL);
    out->wire_mode = p[0];
    return shieldnet_parse_ok();
}

/* ── NTP_SERVER (0x0B) — [u8 addr_type][u8 len][be16 port][address] ──
 *
 * Response-free: a caller that gets false ignores the message and sends
 * nothing, so this returns a bool, not a shieldnet_parse_result_t. True only
 * when len >= 4 + p[1], the port is not 0, (addr_type, addr_len) is one of the
 * spec's rows, and a name holds only ASCII letters, digits, '.' and '-'. Bytes
 * after the address are ignored (R3). out->addr points into p. */
static inline bool shieldnet_parse_ntp_server(const uint8_t *p, size_t len,
                                              shieldnet_ntp_server_req_t *out)
{
    memset(out, 0, sizeof(*out));
    if (p == NULL || len < 4) return false;
    uint8_t type = p[0];
    uint8_t alen = p[1];
    uint16_t port = shieldnet_get_be16(p + 2);
    if (len < (size_t)4 + alen) return false;
    if (port == 0) return false;
    switch (type) {
    case SLED_NTP_ADDR_IPV4: if (alen != 4) return false; break;
    case SLED_NTP_ADDR_IPV6: if (alen != 16) return false; break;
    case SLED_NTP_ADDR_NAME:
        if (alen < 1 || alen > 253) return false;
        for (size_t i = 0; i < alen; i++) {
            uint8_t c = p[4 + i];
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '.' || c == '-';
            if (!ok) return false;
        }
        break;
    default: return false;
    }
    out->addr_type = type;
    out->addr_len = alen;
    out->port = port;
    out->addr = p + 4;
    return true;
}

#ifdef __cplusplus
}
#endif
