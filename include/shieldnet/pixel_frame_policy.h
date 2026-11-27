/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Pure pixel-frame validation shared by firmware and host regression tests. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A frame may update fewer than all configured pixels, but it must contain at
 * least one pixel (sled 6.1), whole device-native pixels, and must never exceed
 * the configured geometry. */
/*
 * PIXEL_FRAME is carried at a fixed 4 bytes per pixel regardless of the strip.
 * On an RGB strip the device drops the fourth (W) byte on ingest. Sizing frames
 * from the strip's bpp instead would make an RGB unit reject every frame a
 * conformant controller sends (8192 % 3 != 0, and 8192 > strips*leds*3).
 *
 * DEVICE_INFO's `bpp` therefore describes the STRIP, for colour handling — it is
 * not the wire stride and must not be used to size a frame.
 */
#define SLED_PIXEL_WIRE_BPP 4u

static inline bool sled_pixel_frame_buffer_valid(
    uint32_t buffer_length, uint8_t bytes_per_pixel, size_t capacity_bytes)
{
    return bytes_per_pixel > 0
        && buffer_length >= bytes_per_pixel
        && (buffer_length % bytes_per_pixel) == 0
        && (size_t)buffer_length <= capacity_bytes;
}
