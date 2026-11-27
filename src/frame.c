/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Frame Parsing — implementation
 */

#include "frame.h"

#include "shieldnet_log.h"

#include <string.h>

static const char *TAG = "frame";

static inline int64_t get_be64_signed(const uint8_t *src)
{
    uint64_t v = ((uint64_t)src[0] << 56) |
                 ((uint64_t)src[1] << 48) |
                 ((uint64_t)src[2] << 40) |
                 ((uint64_t)src[3] << 32) |
                 ((uint64_t)src[4] << 24) |
                 ((uint64_t)src[5] << 16) |
                 ((uint64_t)src[6] << 8)  |
                 ((uint64_t)src[7]);
    return (int64_t)v;
}

static inline int32_t get_be32_signed(const uint8_t *src)
{
    uint32_t v = ((uint32_t)src[0] << 24) |
                 ((uint32_t)src[1] << 16) |
                 ((uint32_t)src[2] << 8)  |
                 ((uint32_t)src[3]);
    return (int32_t)v;
}

int frame_parse(const uint8_t *payload, size_t payload_len, frame_t *frame)
{
    if (!payload || !frame) return -1;

    if (payload_len < FRAME_HEADER_SIZE) {
        SHIELDNET_LOG_ERR(TAG, "payload too short: %zu < %d", payload_len, FRAME_HEADER_SIZE);
        return -1;
    }

    frame->frame_number  = get_be64_signed(payload + 0);
    frame->not_before_ns = get_be64_signed(payload + 8);
    frame->not_after_ns  = get_be64_signed(payload + 16);
    frame->buffer_length = get_be32_signed(payload + 24);

    if (frame->buffer_length < 0) {
        SHIELDNET_LOG_ERR(TAG, "negative buffer_length: %d", frame->buffer_length);
        return -1;
    }

    size_t expected = FRAME_HEADER_SIZE + (size_t)frame->buffer_length;
    if (payload_len != expected) {
        SHIELDNET_LOG_ERR(TAG, "payload length mismatch: %zu != %zu (header + %d)",
                 payload_len, expected, frame->buffer_length);
        return -1;
    }

    frame->pixels = payload + FRAME_HEADER_SIZE;
    return 0;
}
