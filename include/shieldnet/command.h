/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Sled wire protocol — command kinds, response kinds and ACK status codes.
 *
 * The kind is encoded in the low 8 bits of the 20-byte protocol header's
 * MessageType field. Bit 31 stays FlagCompressed (inherited from shieldled).
 * Bits 8..30 are reserved (ignored on receive).
 *
 * Only the core's values are here. The values spec/application.md Section 9
 * reserves for an extension are not defined by the library; a device that has
 * one handles them through shieldnet_device_ext_t (port/shieldnet_device.h).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Command kinds (client → server) ──────────────────────────── */

/* The pixel data plane. 0x00 and nothing else. */
#define SLED_CMD_PIXEL_FRAME      0x00

/* Device and output control. 0x03 is reserved for the program extension
 * (sled 9), as are 0x20 - 0x28; dispatch is on the exact kind, never on a
 * range or a bit. */
#define SLED_CMD_SET_BRIGHTNESS   0x01
#define SLED_CMD_SET_FPS          0x02
#define SLED_CMD_SET_MODE         0x04
#define SLED_CMD_ON               0x05
#define SLED_CMD_OFF              0x06
#define SLED_CMD_PING             0x07
#define SLED_CMD_GET_STATUS       0x08
#define SLED_CMD_GET_MODE         0x09
#define SLED_CMD_GET_DEVICE_INFO  0x0A
#define SLED_CMD_NTP_SERVER       0x0B

/* ── Response kinds (server → client) ─────────────────────────── */

#define SLED_RESP_ACK             0x80
#define SLED_RESP_STATUS          0x81
#define SLED_RESP_DEVICE_INFO     0x84

/* ── ACK status codes ─────────────────────────────────────────── */

#define SLED_ACK_OK               0
#define SLED_ACK_ERR_INVALID_ARG  1
/* 2, 3, 4 and 8 are reserved for the program extension (sled 9). */
#define SLED_ACK_ERR_OOM          5
#define SLED_ACK_ERR_UNKNOWN_KIND 6
#define SLED_ACK_ERR_MODE_MISMATCH 7

#define SLED_CMD_KIND_MASK        0xFFu

#ifdef __cplusplus
}
#endif
