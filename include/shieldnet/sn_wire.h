/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet wire messages and transport envelope — §3 of shieldnet-protocol design/transport.md.
 * Byte-exact with goshieldnet/v1. This unit provides the encoders, the envelope
 * seal/open, and sequence reconstruction; the length-checked decoders (§3.5) live
 * with the receive path.
 */
#ifndef SHIELDNET_WIRE_H
#define SHIELDNET_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define SN_INIT_LEN     256
#define SN_RETRY_LEN    84
#define SN_FINISH_LEN   256
#define SN_ADMIT_LEN    82
#define SN_ENVELOPE_LEN 20 /* seq_wire[4] || tag[16] */

/* Encoders: out is caller-allocated to the corresponding *_LEN. */
void sn_encode_init(const uint8_t client_nonce[24], const uint8_t device_id[8],
                    const uint8_t init_mac[16], uint8_t out[SN_INIT_LEN]);
void sn_encode_retry(const uint8_t epoch_tag[8], const uint8_t cookie[16],
                     const uint8_t admission_epoch[8], const uint8_t device_id[8],
                     const uint8_t observed_source[18], const uint8_t retry_mac[16],
                     uint8_t out[SN_RETRY_LEN]);
void sn_encode_finish(const uint8_t client_nonce[24], const uint8_t epoch_tag[8],
                      const uint8_t cookie[16], const uint8_t admission_epoch[8],
                      const uint8_t e_c[32], const uint8_t client_tag[16],
                      uint8_t out[SN_FINISH_LEN]);
void sn_encode_admit(const uint8_t admission_epoch[8], const uint8_t e_s[32],
                     const uint8_t admit_pre[16], const uint8_t admit_tag[16],
                     uint8_t out[SN_ADMIT_LEN]);

/* §8.3 reconstruction: returns the signed 64-bit candidate for a received seq_wire
 * against the current high-water mark. Caller applies the window/wrap checks. */
int64_t sn_reconstruct(uint32_t seq_wire, uint64_t hwm);

/* Envelope §3.6. c2s selects the direction label ("C2S\0"/"S2C\0"); seq_full builds
 * the nonce (dir||seq_full BE) and its low 32 bits are seq_wire and the AD. Seal
 * writes ciphertext||seq_wire||tag to out (msg_len + SN_ENVELOPE_LEN) and sets
 * *out_len. Open reverses it using the reconstructed seq_full for the nonce; returns
 * 0 on success, -1 on AEAD failure or a too-short envelope. */
int sn_seal(const uint8_t key[32], int c2s, uint64_t seq_full,
            const uint8_t *msg, size_t msg_len, uint8_t *out, size_t *out_len);
int sn_open(const uint8_t key[32], int c2s, uint64_t seq_full,
            const uint8_t *envelope, size_t env_len, uint8_t *out, size_t *out_len);

#endif
