/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * client_helper.h — the client half of §6 admission, for tests and fuzzers.
 *
 * Nine sources hand-rolled the same 20-26 line sequence
 * to build a FINISH and derive the session keys a client would hold; nine
 * copies of an offset-indexed key schedule drift silently, and nothing guarded
 * them. This is that sequence, once.
 *
 * **Test-local on purpose.** It is not in include/, ships in nothing, and is not
 * the C client (sn_client.h) — it stays alongside that client, because these
 * tests must build *deliberately malformed* admissions to aim at the real
 * client, and the client's own API must never offer a way to do that.
 *
 * **Every secret is an explicit parameter**. Callers fix their nonce and
 * ephemeral key so a failure replays, and ch_finish_from takes a raw e_c rather
 * than deriving one, because test_sn_finish.c's low-order-point case needs an
 * all-zero e_c that no keypair can produce.
 *
 * test_sn_kdf.c does NOT use this: it is the independent pin on the
 * encoders, and routing it through a helper validated against the same vectors
 * would make the check circular.
 */
#ifndef SN_TEST_CLIENT_HELPER_H
#define SN_TEST_CLIENT_HELPER_H

#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_wire.h"

#include <sodium.h>
#include <stdint.h>
#include <string.h>

/* RETRY field offsets (§3.5). The layout is fixed-length, so these are the only
 * three the client reads back out of it. */
#define CH_RETRY_EPOCH_TAG(r) ((r) + 10)
#define CH_RETRY_COOKIE(r)    ((r) + 18)
#define CH_RETRY_AE(r)        ((r) + 34)

/* k_dev and the two static keys, from the PSK and device id. */
static inline void ch_static_keys(const uint8_t psk[32], const uint8_t device_id[8],
                                  uint8_t k_dev[32], uint8_t k_req[32], uint8_t k_resp[32])
{
    uint8_t kd[32], kr[32], krsp[32];
    sn_derive_kdev(psk, device_id, kd);
    sn_derive_static(kd, kr, krsp);
    if (k_dev)  memcpy(k_dev, kd, 32);
    if (k_req)  memcpy(k_req, kr, 32);
    if (k_resp) memcpy(k_resp, krsp, 32);
}

/* The INIT a client sends for this nonce. */
static inline void ch_init(const uint8_t psk[32], const uint8_t device_id[8],
                           const uint8_t nonce[24], uint8_t out_init[SN_INIT_LEN])
{
    uint8_t k_req[32], mac[16];
    ch_static_keys(psk, device_id, NULL, k_req, NULL);
    sn_init_mac(k_req, nonce, device_id, mac);
    sn_encode_init(nonce, device_id, mac, out_init);
}

/* The FINISH a client sends in reply to `retry`, with a caller-supplied raw
 * e_c. Nothing here checks that e_c is a valid point: passing one that is not
 * is how the low-order rejection is tested. */
static inline void ch_finish_from(const uint8_t psk[32], const uint8_t device_id[8],
                                  const uint8_t nonce[24], const uint8_t *retry,
                                  const uint8_t e_c[32],
                                  uint8_t out_finish[SN_FINISH_LEN])
{
    uint8_t k_req[32];
    ch_static_keys(psk, device_id, NULL, k_req, NULL);
    uint8_t context[65];
    sn_context(nonce, CH_RETRY_EPOCH_TAG(retry), CH_RETRY_COOKIE(retry),
               CH_RETRY_AE(retry), device_id, context);
    uint8_t client_tag[16];
    sn_client_tag(k_req, context, e_c, client_tag);
    sn_encode_finish(nonce, CH_RETRY_EPOCH_TAG(retry), CH_RETRY_COOKIE(retry),
                     CH_RETRY_AE(retry), e_c, client_tag, out_finish);
}

/* ch_finish_from for the ordinary case: derive e_c from a private key. The
 * public key is handed back because the caller needs it again for context2. */
static inline void ch_finish(const uint8_t psk[32], const uint8_t device_id[8],
                             const uint8_t nonce[24], const uint8_t *retry,
                             const uint8_t ec_priv[32],
                             uint8_t out_finish[SN_FINISH_LEN], uint8_t ec_pub_out[32])
{
    uint8_t ec_pub[32];
    crypto_scalarmult_base(ec_pub, ec_priv);
    ch_finish_from(psk, device_id, nonce, retry, ec_pub, out_finish);
    if (ec_pub_out) memcpy(ec_pub_out, ec_pub, 32);
}

/* The four session keys a client derives once its ADMIT arrives. Any of the
 * outputs may be NULL. */
static inline void ch_session_from(const uint8_t psk[32], const uint8_t device_id[8],
                                   const uint8_t nonce[24], const uint8_t *retry,
                                   const uint8_t ec_priv[32], const uint8_t *admit,
                                   uint8_t k_c2s[32], uint8_t k_s2c[32],
                                   uint8_t k_kcp_c2s[32], uint8_t k_kcp_s2c[32])
{
    uint8_t k_dev[32];
    ch_static_keys(psk, device_id, k_dev, NULL, NULL);
    uint8_t ec_pub[32];
    crypto_scalarmult_base(ec_pub, ec_priv);
    uint8_t context[65];
    sn_context(nonce, CH_RETRY_EPOCH_TAG(retry), CH_RETRY_COOKIE(retry),
               CH_RETRY_AE(retry), device_id, context);
    const uint8_t *e_s = admit + 18; /* §3.5: ADMIT carries e_s at 18 */
    uint8_t context2[129];
    sn_context2(context, ec_pub, e_s, context2);
    uint8_t dh[32];
    /* sn_dh returns -1 on an all-zero output, the low-order point §4.5 makes
     * both sides reject. Deriving from it anyway would hand a caller session
     * keys that look fine, so fail loudly instead: no test wants that master,
     * and a helper that lies about it is worse than no helper. */
    if (sn_dh(ec_priv, e_s, dh) != 0) {
        if (k_c2s)     memset(k_c2s, 0, 32);
        if (k_s2c)     memset(k_s2c, 0, 32);
        if (k_kcp_c2s) memset(k_kcp_c2s, 0, 32);
        if (k_kcp_s2c) memset(k_kcp_s2c, 0, 32);
        sodium_memzero(dh, 32);
        return;
    }
    uint8_t master[32];
    sn_master(context2, k_dev, dh, master);
    uint8_t c2s[32], s2c[32], kc[32], ks[32];
    sn_session_keys(master, c2s, s2c, kc, ks);
    if (k_c2s)     memcpy(k_c2s, c2s, 32);
    if (k_s2c)     memcpy(k_s2c, s2c, 32);
    if (k_kcp_c2s) memcpy(k_kcp_c2s, kc, 32);
    if (k_kcp_s2c) memcpy(k_kcp_s2c, ks, 32);
    sodium_memzero(dh, 32);
    sodium_memzero(master, 32);
}

#endif /* SN_TEST_CLIENT_HELPER_H */
