/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet Protocol — message framing + handshake
 */

#include "protocol.h"

#include "shieldnet_log.h"

#include <sodium.h>
#include <string.h>

static const char *TAG = "protocol";

/* ------------------------------------------------------------------ */
/*  Big-endian helpers                                                 */
/* ------------------------------------------------------------------ */

static inline void put_be32(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
}

static inline uint32_t get_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) |
           ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |
           ((uint32_t)src[3]);
}

static inline void put_be64(uint8_t *dst, uint64_t v)
{
    dst[0] = (uint8_t)(v >> 56);
    dst[1] = (uint8_t)(v >> 48);
    dst[2] = (uint8_t)(v >> 40);
    dst[3] = (uint8_t)(v >> 32);
    dst[4] = (uint8_t)(v >> 24);
    dst[5] = (uint8_t)(v >> 16);
    dst[6] = (uint8_t)(v >> 8);
    dst[7] = (uint8_t)(v);
}

static inline uint64_t get_be64(const uint8_t *src)
{
    return ((uint64_t)src[0] << 56) |
           ((uint64_t)src[1] << 48) |
           ((uint64_t)src[2] << 40) |
           ((uint64_t)src[3] << 32) |
           ((uint64_t)src[4] << 24) |
           ((uint64_t)src[5] << 16) |
           ((uint64_t)src[6] << 8)  |
           ((uint64_t)src[7]);
}

/* ------------------------------------------------------------------ */
/*  Handshake                                                          */
/* ------------------------------------------------------------------ */



void protocol_nonce_from_msgnum(uint64_t message_num, uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    memset(nonce, 0, CRYPTO_NONCE_SIZE);
    put_be64(nonce + 8, message_num);
}

/* ------------------------------------------------------------------ */
/*  Message I/O                                                        */
/* ------------------------------------------------------------------ */

int protocol_read_message(const shieldnet_io_t *io,
                          protocol_msg_header_t *header,
                          uint8_t *payload_buf, size_t payload_buf_size,
                          int timeout_ms)
{
    uint8_t hdr[PROTOCOL_HEADER_SIZE];

    int n = io->readfull(io->ctx, hdr, PROTOCOL_HEADER_SIZE, timeout_ms);
    if (n == 0) return 0;               /* idle: nothing consumed, still aligned */
    if (n < 0)  return PROTOCOL_ERR_IO; /* read failed before any byte arrived */
    if (n != PROTOCOL_HEADER_SIZE) {    /* header torn in half */
        SHIELDNET_LOG_ERR(TAG, "header: short read (%d/%d)", n, PROTOCOL_HEADER_SIZE);
        io->poison(io->ctx);
        return PROTOCOL_ERR_DESYNC;
    }

    /* Parse big-endian fields */
    header->size          = get_be32(hdr + 0);
    header->original_size = get_be32(hdr + 4);
    header->message_type  = get_be32(hdr + 8);
    header->message_num   = get_be64(hdr + 12);

    /* The header is consumed but its body is not, so an oversized frame
     * leaves the stream misaligned just as a torn read does. */
    if (header->size > payload_buf_size) {
        SHIELDNET_LOG_ERR(TAG, "payload too large: %u > %zu", header->size, payload_buf_size);
        io->poison(io->ctx);
        return PROTOCOL_ERR_DESYNC;
    }

    if (header->size > 0) {
        if (io->frame_continues) io->frame_continues(io->ctx);
        n = io->readfull(io->ctx, payload_buf, header->size, timeout_ms);
        if (n < 0 || (uint32_t)n != header->size) {
            SHIELDNET_LOG_ERR(TAG, "payload: short read (%d/%u)", n, header->size);
            io->poison(io->ctx);
            return PROTOCOL_ERR_DESYNC;
        }
    }

    return PROTOCOL_HEADER_SIZE + (int)header->size;
}

int protocol_write_message(const shieldnet_io_t *io,
                           uint32_t message_type, uint64_t message_num,
                           const uint8_t *payload, uint32_t payload_len,
                           uint32_t original_size)
{
    if (payload_len > 0 && payload == NULL) {
        /* Writing the header alone would promise bytes that never follow and
         * desynchronise the stream while reporting success. */
        return -1;
    }
    uint8_t hdr[PROTOCOL_HEADER_SIZE];
    put_be32(hdr + 0,  payload_len);    /* Size (on wire) */
    put_be32(hdr + 4,  original_size);  /* OriginalSize (pre-encryption/compression) */
    put_be32(hdr + 8,  message_type);   /* MessageType */
    put_be64(hdr + 12, message_num);    /* MessageNum */

    if (io->write(io->ctx, hdr, PROTOCOL_HEADER_SIZE) < 0) {
        SHIELDNET_LOG_ERR(TAG, "write header failed");
        return -1;
    }

    /* Header write failure is clean: nothing was consumed by the peer and the
     * stream is still frame aligned, so no poison here. */
    if (payload_len > 0) {
        if (io->write(io->ctx, payload, payload_len) < 0) {
            SHIELDNET_LOG_ERR(TAG, "write payload failed");
            io->poison(io->ctx);
            return -1;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  AAD serialization                                                  */
/* ------------------------------------------------------------------ */

void protocol_marshal_aad(uint32_t size, uint32_t original_size,
                          uint32_t message_type, uint64_t message_num,
                          uint8_t *aad)
{
    put_be32(aad + 0,  size);
    put_be32(aad + 4,  original_size);
    put_be32(aad + 8,  message_type);
    put_be64(aad + 12, message_num);
}
