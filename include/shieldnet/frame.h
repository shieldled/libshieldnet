/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Frame Parsing
 *
 * Parses the 28-byte PIXEL_FRAME header from decrypted/decompressed payload.
 *
 * Wire format (big-endian):
 *   Offset  Size  Field
 *   0       8     FrameNumber  (int64)
 *   8       8     NotBefore    (int64, Unix nanoseconds)
 *   16      8     NotAfter     (int64, Unix nanoseconds)
 *   24      4     BufferLength (int32, pixel data size)
 *   28      N     Pixel data   (4 bytes per pixel: R, G, B, W)
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FRAME_HEADER_SIZE  28

typedef struct {
    int64_t       frame_number;
    int64_t       not_before_ns;  /* Unix nanoseconds; 0 = off */
    int64_t       not_after_ns;   /* Unix nanoseconds; 0 = off */
    int32_t       buffer_length;
    const uint8_t *pixels;        /* Pointer into payload (zero-copy) */
} frame_t;

/*
 * Parse a frame from the decrypted/decompressed message payload.
 *
 * frame->pixels points into the payload buffer (no copy).
 * The caller must keep payload valid while using frame->pixels.
 *
 * Returns 0 on success, -1 on error (truncated, length mismatch, etc).
 */
int frame_parse(const uint8_t *payload, size_t payload_len, frame_t *frame);

#ifdef __cplusplus
}
#endif
