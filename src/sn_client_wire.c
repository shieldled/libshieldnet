/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_client_wire.h"

#include "shieldnet/sn_kdf.h"

#include <sodium.h>
#include <string.h>

static const uint8_t MAGIC[8] = { 'S','L','D','1','Z','0','0','1' };
#define VERSION     0x01
#define TYPE_RETRY  0x02
#define TYPE_ADMIT  0x06

/* Constant-time compare for anything an attacker can vary. sodium_memcmp
 * returns 0 on equal. */
static int ct_eq(const void *a, const void *b, size_t n) {
    return sodium_memcmp(a, b, n) == 0;
}

/* §3.5, before any field access: exact length, then magic/type/version. */
static sn_cw_result check_frame(const uint8_t *dg, size_t len,
                                size_t want_len, uint8_t want_type) {
    if (len != want_len) return SN_CW_BAD_LEN;
    /* MAGIC is public, so a plain memcmp is right here and matches Go. */
    if (memcmp(dg, MAGIC, 8) != 0) return SN_CW_BAD_HEADER;
    if (dg[8] != want_type || dg[9] != VERSION) return SN_CW_BAD_TYPE;
    return SN_CW_OK;
}

sn_cw_result sn_decode_retry(const uint8_t *datagram, size_t len, sn_retry_msg *out) {
    if (!datagram || !out) return SN_CW_BAD_LEN;
    sn_cw_result r = check_frame(datagram, len, SN_RETRY_LEN, TYPE_RETRY);
    if (r != SN_CW_OK) return r;
    /* Copies, not pointers into the read buffer (§7.3 step 5). */
    memcpy(out->epoch_tag,       datagram + 10, 8);
    memcpy(out->cookie,          datagram + 18, 16);
    memcpy(out->admission_epoch, datagram + 34, 8);
    memcpy(out->device_id,       datagram + 42, 8);
    memcpy(out->observed_source, datagram + 50, 18);
    memcpy(out->retry_mac,       datagram + 68, 16);
    return SN_CW_OK;
}

sn_cw_result sn_decode_admit(const uint8_t *datagram, size_t len, sn_admit_msg *out) {
    if (!datagram || !out) return SN_CW_BAD_LEN;
    sn_cw_result r = check_frame(datagram, len, SN_ADMIT_LEN, TYPE_ADMIT);
    if (r != SN_CW_OK) return r;
    memcpy(out->admission_epoch, datagram + 10, 8);
    memcpy(out->e_s,             datagram + 18, 32);
    memcpy(out->admit_pre,       datagram + 50, 16);
    memcpy(out->admit_tag,       datagram + 66, 16);
    return SN_CW_OK;
}

sn_cw_result sn_check_retry(const sn_retry_msg *r, const uint8_t k_resp[32],
                            const uint8_t client_nonce[24],
                            const uint8_t own_source[18],
                            const uint8_t device_id[8]) {
    if (!r || !k_resp || !client_nonce || !own_source || !device_id) return SN_CW_BAD_LEN;
    /* step 2: our own socket address. Free, so it runs before any MAC. */
    if (!ct_eq(r->observed_source, own_source, 18)) return SN_CW_BAD_SOURCE;

    /* step 3: retry_mac, over the device_id we ADDRESSED rather than the one on
     * the wire. Go does the same (client.go's checkRETRY passes c.deviceID), and
     * the difference is the whole force of step 4 below: fed the wire value, the
     * MAC binds whatever the datagram claims and step 4 becomes the only thing
     * tying the RETRY to the device we asked -- which is not what "defence in
     * depth" means. Both orders reject today, so this is a divergence in what is
     * bound, not a live hole. */
    uint8_t want[16];
    sn_retry_mac(k_resp, client_nonce, r->epoch_tag, r->cookie,
                 r->admission_epoch, device_id, r->observed_source, want);
    int mac_ok = ct_eq(want, r->retry_mac, 16);
    sodium_memzero(want, sizeof want);
    if (!mac_ok) return SN_CW_BAD_MAC;

    /* step 4: the device we addressed. Defence in depth now that device_id is
     * bound into init_mac -- a foreign device will not answer at all -- but a
     * client MUST NOT accept a RETRY from one it did not address. */
    if (!ct_eq(r->device_id, device_id, 8)) return SN_CW_BAD_DEVICE_ID;

    return SN_CW_OK;
}

/* §7.4 steps 2 and 3, which both precede the X25519 and must keep doing so:
 * admit_pre comes from the static schedule, so a forged ADMIT costs an HMAC
 * here rather than a scalar multiplication. On SN_CW_OK, context2 is filled in
 * for the caller to finish with. */
static sn_cw_result admit_precheck(const sn_admit_msg *a, const uint8_t k_resp[32],
                                   const uint8_t context[65], const uint8_t sent_ae[8],
                                   const uint8_t e_c[32], uint8_t context2[129]) {
    /* step 2: the epoch we presented in FINISH, not the device's post-increment
     * value -- the only one the client can reproduce. Free, so it goes first. */
    if (!ct_eq(a->admission_epoch, sent_ae, 8)) return SN_CW_BAD_EPOCH;

    sn_context2(context, e_c, a->e_s, context2);

    /* step 3, before any X25519. */
    uint8_t want_pre[16];
    sn_admit_pre(k_resp, context2, want_pre);
    int pre_ok = ct_eq(want_pre, a->admit_pre, 16);
    sodium_memzero(want_pre, sizeof want_pre);
    if (!pre_ok) {
        sodium_memzero(context2, 129);
        return SN_CW_BAD_PRE;
    }
    return SN_CW_OK;
}

/* §7.4 step 4's second half: master from the agreed dh, then admit_tag.
 * Consumes context2 and wipes it. */
static sn_cw_result admit_finish(const sn_admit_msg *a, const uint8_t k_dev[32],
                                 uint8_t context2[129], const uint8_t dh[32],
                                 uint8_t master[32]) {
    /* §4.5 makes an all-zero shared secret a rejection on both sides. The
     * computing path checks it via sn_dh, but sn_check_admit_dh takes dh on
     * trust from a cache, so checking here makes the invariant local to this
     * function rather than a contract every caller has to remember. */
    if (sodium_is_zero(dh, 32)) {
        sodium_memzero(context2, 129);
        memset(master, 0, 32);
        return SN_CW_BAD_POINT;
    }
    sn_cw_result res = SN_CW_OK;
    uint8_t m[32];
    sn_master(context2, k_dev, dh, m);
    uint8_t want_tag[16];
    sn_admit_tag(m, want_tag);
    if (ct_eq(want_tag, a->admit_tag, 16)) {
        memcpy(master, m, 32);
    } else {
        res = SN_CW_BAD_TAG;
    }
    /* Every derived value goes, on success and on failure alike (§7.4 step 4). */
    sodium_memzero(want_tag, sizeof want_tag);
    sodium_memzero(m, sizeof m);
    sodium_memzero(context2, 129);
    if (res != SN_CW_OK) sodium_memzero(master, 32);
    return res;
}

sn_cw_result sn_check_admit_dh(const sn_admit_msg *a,
                               const uint8_t k_dev[32], const uint8_t k_resp[32],
                               const uint8_t context[65],
                               const uint8_t sent_ae[8],
                               const uint8_t e_c[32], const uint8_t dh[32],
                               uint8_t master[32]) {
    if (!a || !k_dev || !k_resp || !context || !sent_ae || !e_c || !dh || !master) {
        return SN_CW_BAD_LEN;
    }
    memset(master, 0, 32);
    uint8_t context2[129];
    sn_cw_result r = admit_precheck(a, k_resp, context, sent_ae, e_c, context2);
    if (r != SN_CW_OK) return r;
    return admit_finish(a, k_dev, context2, dh, master);
}

sn_cw_result sn_check_admit_caching(const sn_admit_msg *a,
                                    const uint8_t k_dev[32], const uint8_t k_resp[32],
                                    const uint8_t context[65],
                                    const uint8_t sent_ae[8],
                                    const uint8_t e_c[32], const uint8_t ec_priv[32],
                                    uint8_t master[32],
                                    uint8_t dh_out[32], int *dh_valid) {
    if (!a || !k_dev || !k_resp || !context || !sent_ae || !e_c || !ec_priv || !master) {
        return SN_CW_BAD_LEN;
    }
    memset(master, 0, 32);
    if (dh_valid) *dh_valid = 0;

    uint8_t context2[129];
    sn_cw_result r = admit_precheck(a, k_resp, context, sent_ae, e_c, context2);
    if (r != SN_CW_OK) return r;   /* no X25519 has run, which is the point */

    uint8_t dh[32];
    if (sn_dh(ec_priv, a->e_s, dh) != 0) {
        /* Low-order e_s: §4.5 makes both sides reject. */
        sodium_memzero(dh, sizeof dh);
        sodium_memzero(context2, sizeof context2);
        return SN_CW_BAD_POINT;
    }
    if (dh_out) {
        memcpy(dh_out, dh, 32);
        if (dh_valid) *dh_valid = 1;
    }
    r = admit_finish(a, k_dev, context2, dh, master);
    sodium_memzero(dh, sizeof dh);
    return r;
}

sn_cw_result sn_check_admit(const sn_admit_msg *a,
                            const uint8_t k_dev[32], const uint8_t k_resp[32],
                            const uint8_t context[65],
                            const uint8_t sent_ae[8],
                            const uint8_t e_c[32], const uint8_t ec_priv[32],
                            uint8_t master[32]) {
    return sn_check_admit_caching(a, k_dev, k_resp, context, sent_ae, e_c, ec_priv,
                                  master, NULL, NULL);
}
