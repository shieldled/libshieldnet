/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet Protocol — message framing
 *
 * Wire format (over the KCP byte stream). Admission is not here: the v2
 * ClientHello/ServerHello/ClientConfirm exchange was removed in the v1
 * migration, and §6/§7 admission lives in sn_device.c and sn_client.c.
 *
 *   Message header (20 bytes, big-endian):
 *     Offset  Size  Field
 *     0       4     Size          — payload length on wire (after encryption)
 *     4       4     OriginalSize  — pre-compression payload size
 *     8       4     MessageType   — bit 31 = FlagCompressed
 *     12      8     MessageNum    — sequential message number
 *
 *   Payload: Size bytes following the header
 *
 *   AAD for AEAD encryption: the 20-byte header serialized as big-endian
 *
 * protocol_read_message, protocol_write_message and protocol_marshal_aad
 * are shared between every consumer over the shieldnet_io_t seam (see
 * shieldnet_io.h) — they differ between the device and the client only in
 * which handle they read and write through.
 *
 * protocol_read_message reports three outcomes rather than two — nothing
 * consumed (idle, stream still frame-aligned), a whole frame consumed and
 * rejected (survivable), and a partial frame consumed (unrecoverable, the
 * seam's poison() is called). See the return contract below.
 */

#pragma once

#include "shieldnet_io.h"
#include "crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOCOL_HEADER_SIZE       20
#define PROTOCOL_FLAG_COMPRESSED   0x80000000U

/* Smallest padding size class (transport §13). Classes are powers of two from
 * here up; a control or configuration message pads to the smallest that holds it,
 * and the receiver strips back to original_size. */
#define SN_PAD_FLOOR               64u

/* protocol_read_message outcomes. A positive value is the number of bytes
 * consumed (header + payload). The two negative codes differ in whether the
 * stream survives: see the function's contract below. */
#define PROTOCOL_ERR_DESYNC (-2)   /* partial frame consumed; stream unusable */
#define PROTOCOL_ERR_IO     (-1)   /* nothing consumed; stream still aligned */

typedef struct {
    uint32_t size;           /* Payload size on wire (ciphertext+tag) */
    uint32_t original_size;  /* Pre-compression size */
    uint32_t message_type;   /* Flags (bit 31 = compressed) */
    uint64_t message_num;    /* Sequential message number */
} protocol_msg_header_t;



/* Deterministic counter nonce: 8 zero | MessageNum(BE) | 8 zero. */
void protocol_nonce_from_msgnum(uint64_t message_num,
                                uint8_t nonce[CRYPTO_NONCE_SIZE]);

/*
 * Read one complete protocol message from the stream.
 *
 * 1. Reads 20-byte header via io->readfull
 * 2. Parses big-endian fields
 * 3. Reads header.size bytes of payload via io->readfull
 *
 * payload_buf must be at least header->size bytes.
 *
 * Returns the byte count consumed (>= PROTOCOL_HEADER_SIZE) on success, 0
 * when the read timed out without consuming anything (idle: the stream is
 * still on a frame boundary and may be read again), PROTOCOL_ERR_IO when
 * nothing was consumed but the read failed, and PROTOCOL_ERR_DESYNC when
 * part of a frame was consumed and could not be finished — io->poison() is
 * called before returning in that case.
 */
int protocol_read_message(const shieldnet_io_t *io,
                          protocol_msg_header_t *header,
                          uint8_t *payload_buf, size_t payload_buf_size,
                          int timeout_ms);

/*
 * Write one protocol message to the stream.
 *
 * Serializes the 20-byte header (big-endian) and payload.
 * original_size is the pre-compression/pre-encryption payload size
 * (set equal to payload_len when not using encryption/compression).
 * Returns 0 on success, -1 on error.
 */
int protocol_write_message(const shieldnet_io_t *io,
                           uint32_t message_type, uint64_t message_num,
                           const uint8_t *payload, uint32_t payload_len,
                           uint32_t original_size);

/*
 * Serialize protocol header fields as 20 big-endian bytes for AEAD AAD.
 *
 * aad must be at least PROTOCOL_HEADER_SIZE (20) bytes.
 */
void protocol_marshal_aad(uint32_t size, uint32_t original_size,
                          uint32_t message_type, uint64_t message_num,
                          uint8_t *aad);

#ifdef __cplusplus
}
#endif
