/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * LZ4 Block Decompression
 *
 * Wraps LZ4_decompress_safe() for compressed messages (message layer).
 * goshieldnet compresses with raw LZ4 blocks (github.com/pierrec/lz4/v4).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decompress an LZ4-compressed payload.
 *
 * compressed:      input compressed data (raw LZ4 block, no framing)
 * compressed_len:  length of compressed data
 * out_buf:         output buffer for decompressed data
 * original_size:   expected decompressed size (from protocol header OriginalSize)
 * out_len:         on success, set to actual decompressed length
 *
 * out_buf must be at least original_size bytes.
 * Returns 0 on success, -1 on error.
 */
int decompress_lz4(const uint8_t *compressed, size_t compressed_len,
                   uint8_t *out_buf, size_t original_size,
                   size_t *out_len);

#ifdef __cplusplus
}
#endif
