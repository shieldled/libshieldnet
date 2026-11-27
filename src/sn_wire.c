/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_wire.h"

#include <sodium.h>

/* On Xtensa (ESP32) the portable libsodium AEAD is the throughput wall: measured
 * 2.53 MB/s at 1024 B on an ESP32 @240MHz vs 4.01 MB/s for the tuned core below
 * (1.58x). Same RFC 8439 construction, verified byte-identical to libsodium
 * on-device (ciphertext, tag, round-trip) and pinned by the §15 golden vectors.
 * Every other target keeps libsodium. */
/*
 * AEAD backend selection, in one place.
 *
 * SN_AEAD_BACKEND is a *value*, not a definedness flag: 0 is libsodium (the
 * reference), 1 is the Xtensa-tuned build. The default follows the target, but
 * a build can override it, which the previous `#ifdef SN_AEAD_XTENSA` could not
 * -- -DSN_AEAD_XTENSA=0 still selected the optimised path, so the two could not
 * be compared on device without editing this file. An optimisation is only
 * trustworthy while it can be A/B'd against the implementation it replaced.
 */
#define SN_AEAD_SODIUM 0
#define SN_AEAD_XTENSA 1

#ifndef SN_AEAD_BACKEND
#  if defined(__XTENSA__)
#    define SN_AEAD_BACKEND SN_AEAD_XTENSA
#  else
#    define SN_AEAD_BACKEND SN_AEAD_SODIUM
#  endif
#endif

#if SN_AEAD_BACKEND == SN_AEAD_XTENSA
#  include "arch/sn_aead_xtensa.h"
#endif
#include <string.h>

/*
 * The one seam. Both call sites below are unconditional; adding a backend means
 * adding a case here rather than another pair of #ifdefs inside function bodies.
 */
static inline int sn_aead_seal(uint8_t *ct, uint8_t tag[16],
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t nonce[12], const uint8_t key[32]) {
#if SN_AEAD_BACKEND == SN_AEAD_XTENSA
    aead_opt_encrypt(ct, tag, msg, msg_len, ad, ad_len, nonce, key);
    return 0;
#else
    unsigned long long tag_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ct, tag, &tag_len, msg, msg_len, ad, ad_len, NULL, nonce, key) != 0)
        return -1;
    return tag_len == 16 ? 0 : -1;
#endif
}

static inline int sn_aead_open(uint8_t *msg, const uint8_t *ct, size_t ct_len,
                               const uint8_t tag[16],
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t nonce[12], const uint8_t key[32]) {
#if SN_AEAD_BACKEND == SN_AEAD_XTENSA
    return aead_opt_decrypt(msg, ct, ct_len, tag, ad, ad_len, nonce, key);
#else
    return crypto_aead_chacha20poly1305_ietf_decrypt_detached(
               msg, NULL, ct, ct_len, tag, ad, ad_len, nonce, key);
#endif
}

static const uint8_t MAGIC[8] = { 'S','L','D','1','Z','0','0','1' };
#define VERSION 0x01

static void put_hdr(uint8_t *b, uint8_t type) {
    memcpy(b, MAGIC, 8);
    b[8] = type;
    b[9] = VERSION;
}

void sn_encode_init(const uint8_t client_nonce[24], const uint8_t device_id[8],
                    const uint8_t init_mac[16], uint8_t out[SN_INIT_LEN]) {
    memset(out, 0, SN_INIT_LEN);
    put_hdr(out, 0x01);
    memcpy(out + 10, client_nonce, 24);
    memcpy(out + 34, device_id, 8);
    memcpy(out + 42, init_mac, 16);
}

void sn_encode_retry(const uint8_t epoch_tag[8], const uint8_t cookie[16],
                     const uint8_t admission_epoch[8], const uint8_t device_id[8],
                     const uint8_t observed_source[18], const uint8_t retry_mac[16],
                     uint8_t out[SN_RETRY_LEN]) {
    put_hdr(out, 0x02);
    memcpy(out + 10, epoch_tag, 8);
    memcpy(out + 18, cookie, 16);
    memcpy(out + 34, admission_epoch, 8);
    memcpy(out + 42, device_id, 8);
    memcpy(out + 50, observed_source, 18);
    memcpy(out + 68, retry_mac, 16);
}

void sn_encode_finish(const uint8_t client_nonce[24], const uint8_t epoch_tag[8],
                      const uint8_t cookie[16], const uint8_t admission_epoch[8],
                      const uint8_t e_c[32], const uint8_t client_tag[16],
                      uint8_t out[SN_FINISH_LEN]) {
    memset(out, 0, SN_FINISH_LEN);
    put_hdr(out, 0x05);
    memcpy(out + 10, client_nonce, 24);
    memcpy(out + 34, epoch_tag, 8);
    memcpy(out + 42, cookie, 16);
    memcpy(out + 58, admission_epoch, 8);
    memcpy(out + 66, e_c, 32);
    memcpy(out + 98, client_tag, 16);
}

void sn_encode_admit(const uint8_t admission_epoch[8], const uint8_t e_s[32],
                     const uint8_t admit_pre[16], const uint8_t admit_tag[16],
                     uint8_t out[SN_ADMIT_LEN]) {
    put_hdr(out, 0x06);
    memcpy(out + 10, admission_epoch, 8);
    memcpy(out + 18, e_s, 32);
    memcpy(out + 50, admit_pre, 16);
    memcpy(out + 66, admit_tag, 16);
}

int64_t sn_reconstruct(uint32_t seq_wire, uint64_t hwm) {
    uint32_t d32 = seq_wire - (uint32_t)(hwm & 0xFFFFFFFFu);
    int64_t delta = (d32 < 0x80000000u) ? (int64_t)d32
                                        : (int64_t)d32 - 0x100000000LL;
    /* Add in unsigned and reinterpret. (int64_t)hwm + delta overflows for an hwm
     * with its top bit set, which is undefined in C -- UBSan flags it -- while
     * the Go side's int64(hwm) + delta is defined to wrap. §15 requires the two
     * to agree, so the C has to wrap the same way rather than invoke UB and
     * hope the compiler picks two's complement. */
    return (int64_t)(hwm + (uint64_t)delta);
}

static void nonce_of(int c2s, uint64_t seq_full, uint8_t n[12]) {
    memcpy(n, c2s ? "C2S\0" : "S2C\0", 4);
    for (int i = 0; i < 8; i++)
        n[4 + i] = (uint8_t)(seq_full >> (56 - 8 * i)); /* big-endian */
}

static void seq_wire_be(uint64_t seq_full, uint8_t sw[4]) {
    uint32_t low = (uint32_t)(seq_full & 0xFFFFFFFFu);
    sw[0] = (uint8_t)(low >> 24); sw[1] = (uint8_t)(low >> 16);
    sw[2] = (uint8_t)(low >> 8);  sw[3] = (uint8_t)low;
}

int sn_seal(const uint8_t key[32], int c2s, uint64_t seq_full,
            const uint8_t *msg, size_t msg_len, uint8_t *out, size_t *out_len) {
    uint8_t nonce[12], sw[4], tag[16];
    nonce_of(c2s, seq_full, nonce);
    seq_wire_be(seq_full, sw);
    /* detached: ciphertext into out[0..msg_len), tag separate, ad = sw */
    if (sn_aead_seal(out, tag, msg, msg_len, sw, 4, nonce, key) != 0)
        return -1;
    memcpy(out + msg_len, sw, 4);
    memcpy(out + msg_len + 4, tag, 16);
    *out_len = msg_len + SN_ENVELOPE_LEN;
    return 0;
}

int sn_open(const uint8_t key[32], int c2s, uint64_t seq_full,
            const uint8_t *envelope, size_t env_len, uint8_t *out, size_t *out_len) {
    if (env_len < SN_ENVELOPE_LEN)
        return -1;
    size_t ct_len = env_len - SN_ENVELOPE_LEN;
    const uint8_t *ct = envelope;
    const uint8_t *sw = envelope + ct_len;
    const uint8_t *tag = envelope + ct_len + 4;
    uint8_t nonce[12];
    nonce_of(c2s, seq_full, nonce);
    if (sn_aead_open(out, ct, ct_len, tag, sw, 4, nonce, key) != 0)
        return -1;
    *out_len = ct_len;
    return 0;
}
