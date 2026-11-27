/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * The direction-symmetric half of the app layer, shared by device and client.
 *
 * The device reads app messages under k_c2s and answers under k_s2c; the client
 * does exactly the same with the keys swapped. The 20-byte header, the AAD, the
 * nonce from MessageNum, the AEAD, MessageNum-starts-at-1, the
 * strictly-increasing receive check, the §13 compression path and the padding
 * class strip are identical in both directions and are here, once.
 *
 * **What is NOT here is how bytes are obtained.** The device pulls through a
 * blocking shieldnet_io_t (sn_agent.c's io_readfull waits on data_ready); the
 * client has no thread to block and is fed by sn_client_session_input.
 * So this takes a buffer and a length, never an io table, and each role keeps
 * its own thin wrapper for the reading and writing.
 */
#ifndef SHIELDNET_APP_FRAME_H
#define SHIELDNET_APP_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SN_APP_OK = 0,    /* payload/payload_len are set */
    SN_APP_DROP,      /* this frame is discarded; the session survives */
    SN_APP_FATAL      /* the session must end */
} sn_app_result;

/* Receive side of one direction. Buffers are caller-owned and must outlive it,
 * as the device's already are. */
typedef struct {
    uint8_t  key[32];
    uint64_t last_msgnum;   /* strictly-increasing replay guard; starts at 0 */
    uint8_t *dec;    size_t dec_size;
    uint8_t *decomp; size_t decomp_size;
} sn_app_rx;

/* Send side of the other direction. */
typedef struct {
    uint8_t  key[32];
    uint64_t next_msgnum;   /* §13: starts at 1 */
    uint8_t *enc; size_t enc_size;
} sn_app_tx;

/* The largest class sn_app_seal_padded will pad up to. §13's padding is for
 * control and configuration messages, which are small; bulk content is the
 * category §13 lets you compress instead, and padding it would cost more than
 * it hides. A body above this is sealed unpadded (message layer 6.2 item 2:
 * a payload above the sender's top class is sent unpadded, never refused). */
#define SN_PAD_MAX_CLASS 512u

void sn_app_rx_init(sn_app_rx *rx, const uint8_t key[32],
                    uint8_t *dec, size_t dec_size, uint8_t *decomp, size_t decomp_size);
void sn_app_tx_init(sn_app_tx *tx, const uint8_t key[32], uint8_t *enc, size_t enc_size);

/* Verify and unwrap one message whose header has already been read and whose
 * `hdr.size` ciphertext bytes are in `raw`. On SN_APP_OK, *payload points into
 * rx's dec or decomp buffer and is valid until the next call.
 *
 * Only a MessageNum that verifies advances the high-water: a frame that fails
 * the AEAD must not let an attacker retire a sequence number. */
sn_app_result sn_app_open(sn_app_rx *rx, const protocol_msg_header_t *hdr,
                          const uint8_t *raw,
                          const uint8_t **payload, size_t *payload_len);

/* Seal one outbound message. Writes the ciphertext into tx's enc buffer and
 * hands back the header fields the caller must write in front of it. Responses
 * carry no compression flag, so message_type is the kind. Returns 0, or -1 if
 * the MessageNum space is exhausted (rekey required) or enc is too small. */
int sn_app_seal(sn_app_tx *tx, uint8_t kind, const uint8_t *body, size_t body_len,
                uint32_t *out_type, uint64_t *out_msgnum,
                uint32_t *out_original, size_t *out_len);

/* sn_app_seal, padding the plaintext up to §13's smallest power-of-two class
 * from SN_PAD_FLOOR. original_size stays the true length, so the receiver
 * strips it back -- which sn_app_open already does.
 *
 * Padding is opt-in per message, as it is in Go: §13 permits it for control and
 * configuration only, forbids it on a pixel frame, and cannot combine it with
 * compression (that needs three lengths and the header carries two). Sealing
 * every message at its true length, which is what this implementation did until
 * now, is exactly the leak the carve-out exists to close: a control message's
 * own length identifies which message it is.
 *
 * A body above SN_PAD_MAX_CLASS is sealed unpadded, as sn_app_seal would
 * (message layer 6.2 item 2). */
int sn_app_seal_padded(sn_app_tx *tx, uint8_t kind, const uint8_t *body, size_t body_len,
                       uint32_t *out_type, uint64_t *out_msgnum,
                       uint32_t *out_original, size_t *out_len);

/* Seal an already LZ4-compressed body. `comp` is the block, `original_len` the
 * uncompressed length the header carries as original_size. The compression flag
 * goes into message_type BEFORE the AAD is built, so the receiver's AAD (which
 * is the header it read) matches; a flag OR-ed in afterwards would pass any test
 * whose two ends share the bug and fail against a conforming peer. Same as Go's
 * frameAppWith. Padding and compression cannot combine (§13), so there is no
 * padded variant. Returns -1 for original_len 0 or above UINT32_MAX, or as
 * sn_app_seal. */
int sn_app_seal_compressed(sn_app_tx *tx, uint8_t kind,
                           const uint8_t *comp, size_t comp_len, size_t original_len,
                           uint32_t *out_type, uint64_t *out_msgnum,
                           uint32_t *out_original, size_t *out_len);

/* Wipes the directional key (and, if the caller says so, the plaintext buffers
 * it was given). The keys otherwise live for the whole process: nothing in
 * sn_client_free or the agent reaches into these structs. */
void sn_app_rx_wipe(sn_app_rx *rx, int wipe_buffers);
void sn_app_tx_wipe(sn_app_tx *tx, int wipe_buffers);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_APP_FRAME_H */
