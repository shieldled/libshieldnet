/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet key schedule and MACs — §0, §4.4, §4.5 of shieldnet-protocol design/transport.md.
 *
 * Pure functions over libsodium, byte-exact with goshieldnet/v1. No state, no
 * sockets, no timers. All outputs are caller-allocated. type/version bytes are
 * inserted by the functions that carry them; callers pass only variable fields.
 */
#ifndef SHIELDNET_KDF_H
#define SHIELDNET_KDF_H

#include <stddef.h>
#include <stdint.h>

/* --- §0 / §4.1: the derivation chain --- */

/* k_dev (32) from PSK (32) and device_id (8). */
void sn_derive_kdev(const uint8_t psk[32], const uint8_t device_id[8],
                    uint8_t k_dev_out[32]);

/* One-shot provisioning (spec transport 3.2, second way): for a device's
 * configuration interface, or an off-device tool, that is handed the PSK once.
 * Returns 0 with k_dev in k_dev_out, or -1 with k_dev_out zeroed: the device must
 * then stay unprovisioned. The psk buffer is wiped either way (hence not const);
 * psk and k_dev_out may be the same buffer. The caller must store only k_dev,
 * must not store k_dev_out on -1, and is responsible for every other copy of the
 * PSK it made (an HTTP request buffer, a form field, a parsed string, a log line),
 * which it must erase before handling anything else. sn_derive_kdev stays the
 * plain derivation a client uses. */
int sn_provision_kdev(uint8_t psk[32], const uint8_t device_id[8], uint8_t k_dev_out[32]);

/* k_req (32) and k_resp (32) from k_dev (32). */
void sn_derive_static(const uint8_t k_dev[32],
                      uint8_t k_req_out[32], uint8_t k_resp_out[32]);

/* HMAC/128: leading 16 octets of HMAC-SHA-256(key, msg). */
void sn_hmac128(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len, uint8_t out16[16]);

/* --- §4.4: request/response MACs --- */

/* init_mac (16) = HMAC/128(k_req, L("init")||type||version||client_nonce||device_id). */
void sn_init_mac(const uint8_t k_req[32], const uint8_t client_nonce[24],
                 const uint8_t device_id[8], uint8_t out16[16]);

/* epoch_tag (8) = HMAC-SHA-256(cookie_secret, L("epoch")||cookie_epoch_be)[0:8]. */
void sn_epoch_tag(const uint8_t cookie_secret[32], const uint8_t cookie_epoch_be[4],
                  uint8_t out8[8]);

/* cookie (16) = HMAC/128(cookie_secret, L("cookie")||epoch_tag||canonical_source||client_nonce). */
void sn_cookie(const uint8_t cookie_secret[32], const uint8_t epoch_tag[8],
               const uint8_t canonical_source[18], const uint8_t client_nonce[24],
               uint8_t out16[16]);

/* retry_mac (16) = HMAC/128(k_resp, L("retry")||type||version||client_nonce||epoch_tag||
 * cookie||admission_epoch||device_id||observed_source). */
void sn_retry_mac(const uint8_t k_resp[32], const uint8_t client_nonce[24],
                  const uint8_t epoch_tag[8], const uint8_t cookie[16],
                  const uint8_t admission_epoch[8], const uint8_t device_id[8],
                  const uint8_t observed_source[18], uint8_t out16[16]);

/* --- §4.5: transcript, agreement, session keys --- */

/* context (65) = version||client_nonce||epoch_tag||cookie||admission_epoch||device_id. */
void sn_context(const uint8_t client_nonce[24], const uint8_t epoch_tag[8],
                const uint8_t cookie[16], const uint8_t admission_epoch[8],
                const uint8_t device_id[8], uint8_t out65[65]);

/* context2 (129) = context (65) || e_c (32) || e_s (32). */
void sn_context2(const uint8_t context[65], const uint8_t e_c[32],
                 const uint8_t e_s[32], uint8_t out129[129]);

/* client_tag (16) = HMAC/128(k_req, L("finish")||type||version||context||e_c). */
void sn_client_tag(const uint8_t k_req[32], const uint8_t context[65],
                   const uint8_t e_c[32], uint8_t out16[16]);

/* admit_pre (16) = HMAC/128(k_resp, L("admit-pre")||type||version||context2). */
void sn_admit_pre(const uint8_t k_resp[32], const uint8_t context2[129],
                  uint8_t out16[16]);

/* dh (32) = X25519(own_priv, peer_pub); returns 0 on success, -1 if the output is
 * all zero (a low-order peer point), which §4.5 requires both sides to reject. */
int sn_dh(const uint8_t own_priv[32], const uint8_t peer_pub[32], uint8_t out32[32]);

/* master (32) = HKDF-Extract(salt = L("master")||context2, ikm = k_dev||dh). The
 * salt is 149 octets, so Extract pre-hashes it (RFC 2104) — the path both sides take. */
void sn_master(const uint8_t context2[129], const uint8_t k_dev[32],
               const uint8_t dh[32], uint8_t out32[32]);

/* The four session keys (each 32) and admit_tag (16) from master. */
void sn_session_keys(const uint8_t master[32],
                     uint8_t k_c2s[32], uint8_t k_s2c[32],
                     uint8_t k_kcp_c2s[32], uint8_t k_kcp_s2c[32]);
void sn_admit_tag(const uint8_t master[32], uint8_t out16[16]);

#endif
