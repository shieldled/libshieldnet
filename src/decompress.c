/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * LZ4 Block Decompression — implementation
 */

#include "decompress.h"
#include "lz4.h"

#include <limits.h>

#include "shieldnet_log.h"

static const char *TAG = "decompress";

int decompress_lz4(const uint8_t *compressed, size_t compressed_len,
                   uint8_t *out_buf, size_t original_size,
                   size_t *out_len)
{
    if (!compressed || !out_buf || !out_len) return -1;
    if (compressed_len == 0 || original_size == 0) return -1;
    /* LZ4's API is int-sized. A length past INT_MAX would arrive as a
     * negative count, which LZ4_decompress_safe reads as a malformed input on
     * a good day and as something worse on a bad one. */
    if (compressed_len > INT_MAX || original_size > INT_MAX) return -1;

    int n = LZ4_decompress_safe((const char *)compressed,
                                (char *)out_buf,
                                (int)compressed_len,
                                (int)original_size);
    if (n < 0) {
        SHIELDNET_LOG_ERR(TAG, "LZ4_decompress_safe failed: %d", n);
        return -1;
    }
    /* A short decompression means the block did not encode the length the
     * header declared; accepting it would dispatch a truncated payload. */
    if ((size_t)n != original_size) {
        SHIELDNET_LOG_ERR(TAG, "LZ4 size mismatch: got %d, expected %zu", n, original_size);
        return -1;
    }

    *out_len = (size_t)n;
    return 0;
}
