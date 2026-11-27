/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Client-side receive path — the RETRY and ADMIT decoders and their §7.3/§7.4
 * checks.
 *
 * sn_wire.h says "the length-checked decoders (§3.5) live with the receive
 * path"; until now the only receive path was the device's, so nothing here
 * existed. sn_retry_mac and sn_admit_tag were computed but never used as a
 * *rejection*, which is why this is new security-relevant code rather than
 * de-duplication.
 *
 * §3.5 is a memory-safety rule, not a policy one, and it names this decoder as
 * its example: a 10-octet MAGIC||0x02||0x03 passes the demux and the header
 * check and reaches a RETRY handler that reads observed_source at offset 50 and
 * retry_mac at 68 -- ~70 octets out of bounds, from any spoofed source, before
 * any cryptographic check, because §7.3 step 2 compares observed_source first.
 * So every function here takes a length and validates it before touching a
 * field, and the decode step is separate from the check step so that ordering
 * is visible rather than implied.
 *
 * These are pure: no state, no clock, no allocation. The §7 state machine
 * (2.3) owns the attempt state and calls these.
 */
#ifndef SHIELDNET_CLIENT_WIRE_H
#define SHIELDNET_CLIENT_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "shieldnet/sn_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Decoded RETRY (§3.2). Fields are copies: §7.3 step 5 retains
 * (epoch_tag, cookie, admission_epoch) past the lifetime of the read buffer,
 * and aliasing it is one of the three defects §7.2 carries across from Go. */
typedef struct {
    uint8_t epoch_tag[8];
    uint8_t cookie[16];
    uint8_t admission_epoch[8];
    uint8_t device_id[8];
    uint8_t observed_source[18];
    uint8_t retry_mac[16];
} sn_retry_msg;

/* Decoded ADMIT (§3.4). */
typedef struct {
    uint8_t admission_epoch[8];
    uint8_t e_s[32];
    uint8_t admit_pre[16];
    uint8_t admit_tag[16];
} sn_admit_msg;

/* Rejection reasons. Distinct values because the tests assert on which check
 * fired, and a client that cannot tell "not for me" from "forged" cannot log
 * usefully either. */
typedef enum {
    SN_CW_OK = 0,
    SN_CW_BAD_LEN,        /* §3.5: not exactly 84 / 82 */
    SN_CW_BAD_HEADER,     /* magic, type or version wrong */
    SN_CW_BAD_SOURCE,     /* §7.3 step 2: observed_source is not ours */
    SN_CW_BAD_MAC,        /* §7.3 step 3: retry_mac */
    SN_CW_BAD_DEVICE_ID,  /* §7.3 step 4: not the device we addressed */
    SN_CW_BAD_EPOCH,      /* §7.4 step 2: not the admission_epoch we sent */
    SN_CW_BAD_PRE,        /* §7.4 step 3: admit_pre */
    SN_CW_BAD_POINT,      /* §7.4 step 4: low-order e_s, all-zero DH */
    SN_CW_BAD_TAG,        /* §7.4 step 4: admit_tag */
    /* Appended, not inserted: fuzz/sn_oracle.c emits these values. */
    SN_CW_BAD_TYPE        /* right magic, wrong message type or version */
} sn_cw_result;

/* Structure only: length, header, and field extraction. No cryptography, so a
 * caller MUST NOT act on the contents until the matching check passes. */
sn_cw_result sn_decode_retry(const uint8_t *datagram, size_t len, sn_retry_msg *out);
sn_cw_result sn_decode_admit(const uint8_t *datagram, size_t len, sn_admit_msg *out);

/* §7.3 steps 2-4, in that order: observed_source (free, so first), then
 * retry_mac, then device_id. own_source is the client's own canonical_source
 * (§4.3), 18 octets, which §7.2 requires as an input rather than something
 * discovered by opening a socket. */
sn_cw_result sn_check_retry(const sn_retry_msg *r, const uint8_t k_resp[32],
                            const uint8_t client_nonce[24],
                            const uint8_t own_source[18],
                            const uint8_t device_id[8]);

/* §7.4 steps 2-4: admission_epoch equality, then admit_pre -- which comes from
 * the static schedule and so is checkable *before* the X25519 -- then the DH,
 * master, and admit_tag. sent_ae is the admission_epoch presented in FINISH.
 *
 * On SN_CW_OK, master holds the §4.5 master secret. On any failure master is
 * zeroed before returning: §7.4 step 4 requires wiping every derived key on the
 * failure path, which is the branch least likely to clean up.
 *
 * **The caller owes the dh cache, and it is required rather than an
 * optimisation (§7.4 step 4).** admit_tag is covered by nothing, so an attacker
 * who captures one genuine ADMIT can flip one of its last 16 octets and replay
 * at line rate: every copy carries a genuine admit_pre and so reaches the
 * X25519 here, costing a scalar multiplication plus six HKDF operations each
 * time, on a client that may itself be an ESP32. §2 refuses count caps, so the
 * cache is what bounds it -- one scalar multiplication per distinct e_s, and
 * e_s cannot be varied without breaking admit_pre.
 *
 * This function stays pure and does no caching: the cache is per-attempt state,
 * which the §7 state machine (sn_client.c) owns. It keeps the cache and
 * calls sn_check_admit_dh below; a caller that drives sn_check_admit in a loop
 * without one has reintroduced the flood. */
sn_cw_result sn_check_admit(const sn_admit_msg *a,
                            const uint8_t k_dev[32], const uint8_t k_resp[32],
                            const uint8_t context[65],
                            const uint8_t sent_ae[8],
                            const uint8_t e_c[32], const uint8_t ec_priv[32],
                            uint8_t master[32]);

/* sn_check_admit, plus the dh it computed, so a caller can populate the cache
 * below WITHOUT hoisting the X25519 above admit_pre.
 *
 * dh_out is written only when the DH actually ran -- that is, when the epoch
 * and admit_pre checks passed -- and *dh_valid says whether it did. A caller
 * that computed the DH itself in order to cache it would run it before
 * admit_pre and lose the property that check order exists to buy: a forged
 * ADMIT costing an HMAC instead of a scalar multiplication. */
sn_cw_result sn_check_admit_caching(const sn_admit_msg *a,
                                    const uint8_t k_dev[32], const uint8_t k_resp[32],
                                    const uint8_t context[65],
                                    const uint8_t sent_ae[8],
                                    const uint8_t e_c[32], const uint8_t ec_priv[32],
                                    uint8_t master[32],
                                    uint8_t dh_out[32], int *dh_valid);

/* sn_check_admit with the X25519 already done: dh is the cached shared secret
 * for this exact e_s. This is the entry point the cache uses -- the caller must
 * key it on e_s, because a dh from a different e_s would silently derive the
 * wrong master rather than fail. sn_check_admit is this with the DH computed
 * and the low-order check applied first. */
sn_cw_result sn_check_admit_dh(const sn_admit_msg *a,
                               const uint8_t k_dev[32], const uint8_t k_resp[32],
                               const uint8_t context[65],
                               const uint8_t sent_ae[8],
                               const uint8_t e_c[32], const uint8_t dh[32],
                               uint8_t master[32]);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_CLIENT_WIRE_H */
