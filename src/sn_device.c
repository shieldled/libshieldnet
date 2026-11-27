/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_device.h"

#include <sodium.h>
#include <string.h>

#include "shieldnet/sn_kdf.h"
#include "shieldnet_log.h"

static const char *TAG = "sn_device";

static const uint8_t MAGIC[8] = { 'S','L','D','1','Z','0','0','1' };
#define VERSION    0x01
#define TYPE_INIT  0x01
#define TYPE_FIN   0x05

static void be4(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}

static uint64_t be64(const uint8_t b[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)v; v >>= 8; }
}

static void default_rand(void *ctx, uint8_t *buf, size_t n) {
    (void)ctx;
    randombytes_buf(buf, n);
}

/* rec_lock (§10.1): the pending slots, the cached epoch tags and admission_epoch
 * are shared with the tick sweep and promotion, which run on other threads. A
 * device used single-threaded without sn_device_locks_init (the narrow unit
 * tests, the fuzz oracle) has no lock to take. */
static void rec_lock(sn_device *d) {
    if (d->locks_ready) shieldnet_crit_enter(&d->rec_lock);
}
static void rec_unlock(sn_device *d) {
    if (d->locks_ready) shieldnet_crit_exit(&d->rec_lock);
}

void sn_device_roll_epoch(sn_device *d, uint64_t now_ms) {
    uint32_t ep = (uint32_t)(now_ms / SN_COOKIE_EPOCH_MS);
    if (d->have_epoch && ep == d->cookie_epoch) {
        return;
    }
    /* The outgoing tag is "previous" only if it is epoch ep-1. After a gap it is
     * older than §4.4's two-epoch window and is dropped, not carried forward. */
    if (d->have_epoch && ep - d->cookie_epoch == 1) {
        memcpy(d->prev_epoch_tag, d->epoch_tag, 8);
        d->prev_epoch = d->cookie_epoch;
        d->have_prev = 1;
    } else {
        sodium_memzero(d->prev_epoch_tag, 8);
        d->have_prev = 0;
    }
    d->cookie_epoch = ep;
    uint8_t epb[4];
    be4(ep, epb);
    sn_epoch_tag(d->cookie_secret, epb, d->epoch_tag);
    d->have_epoch = 1;
}

int sn_device_init_kdev(sn_device *d, const uint8_t k_dev[32], const uint8_t device_id[8],
                        const uint8_t cookie_secret[32], const uint8_t admission_epoch[8],
                        const sn_prefix *local, size_t n_local, uint64_t now_ms) {
    memset(d, 0, sizeof(*d));
    /* The device path calls libsodium (randombytes, X25519, HMAC) and may be the
     * first thing on the board to do so. sodium_init is idempotent and
     * thread-safe; on failure leave the device keyless and fail-closed (every
     * handler checks init_failed). */
    if (sodium_init() < 0) {
        SHIELDNET_LOG_ERR(TAG, "sodium_init failed: device will admit nobody");
        d->init_failed = 1;
        return -1;
    }
    /* An all-zero k_dev would give public k_req/k_resp: fail closed instead. */
    if (sodium_is_zero(k_dev, 32)) {
        SHIELDNET_LOG_ERR(TAG, "k_dev is all zero: device will admit nobody");
        d->init_failed = 1;
        return -1;
    }
    /* Transport 3.4: the admission epoch is non-zero with its top 8 bits clear
     * (big-endian, so byte 0 is zero). Checked before any key is copied. */
    if (admission_epoch[0] != 0 || sodium_is_zero(admission_epoch, 8)) {
        SHIELDNET_LOG_ERR(TAG, "admission epoch is zero or has its top 8 bits set: device will admit nobody");
        d->init_failed = 1;
        return -1;
    }
    memcpy(d->device_id, device_id, 8);
    memcpy(d->cookie_secret, cookie_secret, 32);
    memcpy(d->admission_epoch, admission_epoch, 8);
    d->local = local;
    d->n_local = n_local;
    d->rand_fill = default_rand;
    d->rand_ctx = NULL;
    sn_kcp_tuning def = SN_KCP_TUNING_DEFAULT;
    d->tuning = def;
    memcpy(d->k_dev, k_dev, 32);
    sn_derive_static(d->k_dev, d->k_req, d->k_resp);
    sn_device_roll_epoch(d, now_ms);
    return 0;
}

void sn_device_set_source_check(sn_device *d, int enforce) {
    d->source_check_off = !enforce;
}

/* §4.3 in the handler itself: sn_classify is not the only demux a board can use
 * (sn_classify_datagram skips the source), and a RETRY reflected to a broadcast
 * or own-address source is exactly what §4.3 exists to prevent. Same predicate
 * as sn_classify, so the two cannot drift. */
static int source_rejected(const sn_device *d, const uint8_t src_a16[16]) {
    return !d->source_check_off && sn_source_rejected_a16(src_a16, d->local, d->n_local);
}

/* ── §6.1 ─────────────────────────────────────────────────────────────────── */

static int parse_request(const uint8_t *b, size_t len, uint8_t type, size_t pad_off) {
    if (len != SN_INIT_LEN) { /* REQUEST_LEN, INIT and FINISH are both 256 */
        return 0;
    }
    if (memcmp(b, MAGIC, 8) != 0 || b[8] != type || b[9] != VERSION) {
        return 0;
    }
    for (size_t i = pad_off; i < SN_INIT_LEN; i++) {
        if (b[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* §4.4's two tags, for the epoch now_ms is in and the one before it, taken from
 * the clock rather than from whatever the §9.2 tick last cached. The cache is a
 * fast path: a tag it holds for the right epoch is used as is. Any other is
 * computed here -- outside rec_lock, since §10.3 forbids the HMAC under it --
 * so a stalled tick can neither keep an old tag alive nor make the device
 * unadmittable. cookie_secret is written only at init and wipe, so reading it
 * unlocked is safe. *have_prev is 0 only in epoch 0, which has no predecessor. */
static void epoch_tags_at(sn_device *d, uint64_t now_ms,
                          uint8_t cur[8], uint8_t prev[8], int *have_prev) {
    uint32_t ep = (uint32_t)(now_ms / SN_COOKIE_EPOCH_MS);
    rec_lock(d);
    int have = d->have_epoch, have_p = d->have_prev;
    uint32_t c_ep = d->cookie_epoch, p_ep = d->prev_epoch;
    uint8_t c_tag[8], p_tag[8];
    memcpy(c_tag, d->epoch_tag, 8);
    memcpy(p_tag, d->prev_epoch_tag, 8);
    rec_unlock(d);

    uint8_t epb[4];
    if (have && c_ep == ep) {
        memcpy(cur, c_tag, 8);
    } else {
        be4(ep, epb);
        sn_epoch_tag(d->cookie_secret, epb, cur);
    }
    *have_prev = ep > 0;
    if (*have_prev) {
        if (have && c_ep == ep - 1) {
            memcpy(prev, c_tag, 8);
        } else if (have_p && p_ep == ep - 1) {
            memcpy(prev, p_tag, 8);
        } else {
            be4(ep - 1, epb);
            sn_epoch_tag(d->cookie_secret, epb, prev);
        }
    }
    sodium_memzero(c_tag, 8);
    sodium_memzero(p_tag, 8);
}

size_t sn_handle_init(sn_device *d, const uint8_t *datagram, size_t len,
                      const uint8_t src_a16[16], uint16_t src_port, uint64_t now_ms,
                      uint8_t out[SN_RETRY_LEN]) {
    if (d->init_failed || source_rejected(d, src_a16)) {
        return 0;
    }
    if (!parse_request(datagram, len, TYPE_INIT, 58)) {
        return 0; /* step 1 */
    }
    const uint8_t *client_nonce = datagram + 10, *device_id = datagram + 34,
                  *init_mac = datagram + 42;
    if (sodium_memcmp(device_id, d->device_id, 8) != 0) {
        return 0; /* step 2 */
    }
    uint8_t want[16]; /* step 3 */
    sn_init_mac(d->k_req, client_nonce, device_id, want);
    if (sodium_memcmp(want, init_mac, 16) != 0) {
        return 0;
    }
    /* The cookie is issued under the tag of the epoch now_ms is in (§4.4),
     * not whatever a late tick last cached. FINISH advances admission_epoch
     * under rec_lock; copy it so the RETRY is internally consistent. */
    uint8_t epoch_tag[8], prev_unused[8], admission_epoch[8];
    int have_prev_unused;
    epoch_tags_at(d, now_ms, epoch_tag, prev_unused, &have_prev_unused);
    sodium_memzero(prev_unused, 8);
    rec_lock(d);
    memcpy(admission_epoch, d->admission_epoch, 8);
    rec_unlock(d);
    uint8_t cs[18]; /* step 4 */
    sn_canonical_source(src_a16, src_port, cs);
    uint8_t cookie[16];
    sn_cookie(d->cookie_secret, epoch_tag, cs, client_nonce, cookie);
    uint8_t retry_mac[16];
    sn_retry_mac(d->k_resp, client_nonce, epoch_tag, cookie, admission_epoch,
                 d->device_id, cs, retry_mac);
    sn_encode_retry(epoch_tag, cookie, admission_epoch, d->device_id, cs,
                    retry_mac, out);
    return SN_RETRY_LEN;
}

/* ── §6.2 / §6.3 ──────────────────────────────────────────────────────────── */

/* §4.4: a cookie is good for the epoch it was issued in and the next one --
 * exactly the two tags epoch_tags_at derives from FINISH's own now_ms. Nothing
 * here depends on how late the §9.2 tick is, so its lifetime is 4-8 s whether
 * the tick runs or not. */
static int epoch_tag_known(const uint8_t cur[8], const uint8_t prev[8], int have_prev,
                           const uint8_t tag[8]) {
    int known = sodium_memcmp(tag, cur, 8) == 0;
    if (have_prev) {
        known = (sodium_memcmp(tag, prev, 8) == 0) || known;
    }
    return known;
}

int sn_find_pending_index(const sn_device *d, const uint8_t tuple[18]) {
    for (int i = 0; i < SN_PENDING_SLOTS; i++) {
        if (d->pending[i].used && sodium_memcmp(d->pending[i].tuple, tuple, 18) == 0) {
            return i;
        }
    }
    return -1;
}

static void wipe_slot_keys(sn_pending *r) {
    sodium_memzero(r->k_c2s, 32);
    sodium_memzero(r->k_s2c, 32);
    sodium_memzero(r->k_kcp_c2s, 32);
    sodium_memzero(r->k_kcp_s2c, 32);
}

/* Choose the slot to write for tuple: same-tuple (replace), else free, else
 * oldest by expiry (evict). Wipes the outgoing keys (§6.3 invariant). */
static int install_slot(sn_device *d, const uint8_t tuple[18]) {
    int i = sn_find_pending_index(d, tuple);
    if (i >= 0) {
        wipe_slot_keys(&d->pending[i]);
        return i;
    }
    for (i = 0; i < SN_PENDING_SLOTS; i++) {
        if (!d->pending[i].used) {
            return i;
        }
    }
    int oldest = 0;
    for (i = 1; i < SN_PENDING_SLOTS; i++) {
        if ((int32_t)(d->pending[i].expiry - d->pending[oldest].expiry) < 0) {
            oldest = i;
        }
    }
    wipe_slot_keys(&d->pending[oldest]);
    return oldest;
}

/* admission_epoch + 1 as 8 BE octets into out; returns 0 if it would leave
 * §4.2's top-8-bits-clear range (fail closed). */
static int inc_admission_epoch(const uint8_t ae[8], uint8_t out[8]) {
    uint64_t v = be64(ae) + 1;
    if (v >= ((uint64_t)1 << 56)) {
        return 0;
    }
    put_be64(v, out);
    return 1;
}

size_t sn_handle_finish(sn_device *d, const uint8_t *datagram, size_t len,
                        const uint8_t src_a16[16], uint16_t src_port, uint64_t now_ms,
                        uint8_t out[SN_ADMIT_LEN]) {
    if (d->init_failed || source_rejected(d, src_a16)) {
        return 0;
    }
    if (!parse_request(datagram, len, TYPE_FIN, 114)) {
        return 0; /* step 1 */
    }
    const uint8_t *client_nonce = datagram + 10, *epoch_tag = datagram + 34,
                  *cookie = datagram + 42, *admission_epoch = datagram + 58,
                  *e_c = datagram + 66, *client_tag = datagram + 98;
    uint8_t tuple[18];
    sn_canonical_source(src_a16, src_port, tuple);
    uint32_t now32 = (uint32_t)now_ms;

    /* step 2: verbatim resend for a matching, unexpired same-tuple record. The
     * slot is rec_lock state (the tick sweeps it, promotion clears it); the
     * memcmp under the lock is 256 bytes, well inside §10.1's budget. */
    rec_lock(d);
    int existing = sn_find_pending_index(d, tuple);
    int resend = existing >= 0 && (int32_t)(d->pending[existing].expiry - now32) > 0 &&
                 sodium_memcmp(d->pending[existing].finish, datagram, SN_FINISH_LEN) == 0;
    if (resend) {
        memcpy(out, d->pending[existing].admit, SN_ADMIT_LEN);
    }
    /* step 4 reads admission_epoch, which this function itself advances. */
    uint8_t cur_ae[8];
    memcpy(cur_ae, d->admission_epoch, 8);
    rec_unlock(d);
    if (resend) {
        return SN_ADMIT_LEN;
    }

    /* step 3: epoch_tag current-or-previous by FINISH's own clock (§4.4), cookie
     * recomputes over THIS tuple */
    uint8_t cur_tag[8], prev_tag[8];
    int have_prev;
    epoch_tags_at(d, now_ms, cur_tag, prev_tag, &have_prev);
    int known = epoch_tag_known(cur_tag, prev_tag, have_prev, epoch_tag);
    sodium_memzero(cur_tag, 8);
    sodium_memzero(prev_tag, 8);
    if (!known) {
        return 0;
    }
    uint8_t want_cookie[16];
    sn_cookie(d->cookie_secret, epoch_tag, tuple, client_nonce, want_cookie);
    if (sodium_memcmp(want_cookie, cookie, 16) != 0) {
        return 0;
    }

    /* step 4: admission_epoch strictly single-use */
    if (sodium_memcmp(admission_epoch, cur_ae, 8) != 0) {
        return 0;
    }

    /* step 5: client_tag proves the PSK; an invalid FINISH alters no state */
    uint8_t context[65];
    sn_context(client_nonce, epoch_tag, cookie, admission_epoch, d->device_id, context);
    uint8_t want_tag[16];
    sn_client_tag(d->k_req, context, e_c, want_tag);
    if (sodium_memcmp(want_tag, client_tag, 16) != 0) {
        return 0;
    }

    /* step 6: ephemeral pair, DH (reject all-zero), derive — outside the lock */
    uint8_t es_priv[32], es_pub[32];
    d->rand_fill(d->rand_ctx, es_priv, 32);
    if (crypto_scalarmult_base(es_pub, es_priv) != 0) { /* fail closed */
        sodium_memzero(es_priv, 32);
        return 0;
    }
    uint8_t dh[32];
    int dh_rc = sn_dh(es_priv, e_c, dh);
    sodium_memzero(es_priv, 32);
    if (dh_rc != 0) { /* all-zero X25519 output (§4.5) */
        sodium_memzero(dh, 32);
        return 0;
    }
    uint8_t context2[129];
    sn_context2(context, e_c, es_pub, context2);
    uint8_t master[32];
    sn_master(context2, d->k_dev, dh, master);
    sodium_memzero(dh, 32);
    uint8_t k_c2s[32], k_s2c[32], k_kcp_c2s[32], k_kcp_s2c[32];
    sn_session_keys(master, k_c2s, k_s2c, k_kcp_c2s, k_kcp_s2c);
    uint8_t admit_pre[16], admit_tag[16];
    sn_admit_pre(d->k_resp, context2, admit_pre);
    sn_admit_tag(master, admit_tag);
    sodium_memzero(master, 32);
    sn_encode_admit(admission_epoch, es_pub, admit_pre, admit_tag, out);

    /* step 7: guarded — re-check admission_epoch, then commit atomically */
    uint8_t next[8];
    rec_lock(d);
    if (sodium_memcmp(admission_epoch, d->admission_epoch, 8) != 0 ||
        !inc_admission_epoch(d->admission_epoch, next)) {
        rec_unlock(d);
        /* aborted or range exhausted: wipe live keys for a session that won't be */
        sodium_memzero(k_c2s, 32); sodium_memzero(k_s2c, 32);
        sodium_memzero(k_kcp_c2s, 32); sodium_memzero(k_kcp_s2c, 32);
        sodium_memzero(out, SN_ADMIT_LEN);
        return 0;
    }
    int i = install_slot(d, tuple);
    sn_pending *r = &d->pending[i];
    r->used = 1;
    memcpy(r->tuple, tuple, 18);
    memcpy(r->finish, datagram, SN_FINISH_LEN);
    memcpy(r->admit, out, SN_ADMIT_LEN);
    memcpy(r->k_c2s, k_c2s, 32);
    memcpy(r->k_s2c, k_s2c, 32);
    memcpy(r->k_kcp_c2s, k_kcp_c2s, 32);
    memcpy(r->k_kcp_s2c, k_kcp_s2c, 32);
    r->generation = d->gen_ctr++;
    r->expiry = now32 + SN_PENDING_TTL_MS;
    memset(&r->c2s_window, 0, sizeof(r->c2s_window)); /* fresh empty window (§6.3) */
    memcpy(d->admission_epoch, next, 8);
    rec_unlock(d);

    sodium_memzero(k_c2s, 32); sodium_memzero(k_s2c, 32);
    sodium_memzero(k_kcp_c2s, 32); sodium_memzero(k_kcp_s2c, 32);
    return SN_ADMIT_LEN; /* transmission outside the guarded region (§10.1) */
}
