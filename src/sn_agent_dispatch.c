/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_agent_dispatch.h"

#include <sodium.h>
#include <string.h>

#include "shieldnet/sn_app_frame.h"

/* A response goes out as two sn_primary_send calls (transport 9.5): the 20-byte
 * header, then the sealed body, each charged in whole KCP segments of
 * mss = SN_WIRE_MTU - 44 (the envelope, then KCP's own 24-byte overhead). The
 * body is refused when the header's segment plus its own exceed
 * SN_SEND_QUEUE_MAX, and by ikcp_send at 128 fragments or more; either way the
 * header is already in the stream, so the session dies. SHIELDNET_MAX_RESPONSE_BODY
 * is the largest body the device sends, so a build whose constants cannot send
 * it does not compile, and sn_agent_respond refuses a longer body before
 * anything is written. */
/* The largest response, sealed (a body up to SN_PAD_MAX_CLASS is padded to its
 * class first). */
#define SN_RESP_SEALED_MAX ((SHIELDNET_MAX_RESPONSE_BODY > SN_PAD_MAX_CLASS ? \
        (size_t)SHIELDNET_MAX_RESPONSE_BODY : (size_t)SN_PAD_MAX_CLASS) + CRYPTO_OVERHEAD)
#define SN_KCP_MSS ((size_t)(SN_WIRE_MTU - 44))
#define SN_RESP_SEGS ((SN_RESP_SEALED_MAX + SN_KCP_MSS - 1) / SN_KCP_MSS)
_Static_assert(SN_RESP_SEGS < 128,
    "SHIELDNET_MAX_RESPONSE_BODY too large for SN_WIRE_MTU: 128 or more KCP fragments");
_Static_assert((1 + SN_RESP_SEGS) * SN_KCP_MSS <= SN_SEND_QUEUE_MAX,
    "SN_SEND_QUEUE_MAX too small for SHIELDNET_MAX_RESPONSE_BODY");
_Static_assert(SHIELDNET_MAX_RESPONSE_BODY >= SLED_DEVICE_INFO_MAX_BYTES,
    "SHIELDNET_MAX_RESPONSE_BODY below the core's largest response");

/* The device side of the app layer. Everything direction-symmetric moved to
 * sn_app_frame.c; what stays here is the device's half:
 * pulling bytes through the blocking shieldnet_io_t seam, and dispatching to
 * shieldnet_device_ops_t. The client's half is the same core with the keys
 * swapped and a push-driven reader. */

int sn_agent_init(sn_agent *ag, sn_device *dev, const shieldnet_device_ops_t *ops,
                  uint8_t *raw, size_t raw_size, uint8_t *dec, size_t dec_size,
                  uint8_t *decomp, size_t decomp_size, uint8_t *enc, size_t enc_size) {
    memset(ag, 0, sizeof(*ag));
    ag->io = sn_primary_io(&ag->io_st, dev);
    ag->dev = ops;
    /* The device reads c2s and answers s2c. The client passes these the other
     * way round; that swap is the whole difference between the roles. */
    /* The primary's keys are rec_lock state (§10.1): promotion wipes them in
     * (a)5 and rewrites them in (c). The generation the io serves and the keys
     * must come from the SAME locked read, or a bind between (a) and (c) pairs
     * the new session's generation with wiped keys. */
    uint8_t k_c2s[32], k_s2c[32];
    int rc = sn_primary_bind_app(dev, &ag->io_st.gen, k_c2s, k_s2c);
    sn_app_rx_init(&ag->rx, k_c2s, dec, dec_size, decomp, decomp_size);
    sn_app_tx_init(&ag->tx, k_s2c, enc, enc_size);
    sodium_memzero(k_c2s, 32);
    sodium_memzero(k_s2c, 32);
    ag->raw = raw; ag->raw_size = raw_size;
    return rc;
}

void sn_agent_end(sn_agent *ag) {
    sn_device_end_primary(ag->io_st.dev, ag->io_st.gen);
    sn_app_rx_wipe(&ag->rx, 1);
    sn_app_tx_wipe(&ag->tx, 1);
}

int sn_agent_step(sn_agent *ag, uint32_t now_ms, int timeout_ms) {
    sn_agent_set_now(&ag->io_st, now_ms);
    protocol_msg_header_t hdr;
    int n = protocol_read_message(&ag->io, &hdr, ag->raw, ag->raw_size, timeout_ms);
    if (n == 0) {
        return 0; /* idle, stream aligned */
    }
    if (n < 0) {
        return -1; /* io error / desync (protocol_read_message poisoned) */
    }

    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    switch (sn_app_open(&ag->rx, &hdr, ag->raw, &payload, &payload_len)) {
    case SN_APP_DROP:
        return 1; /* survivable: a whole frame consumed and dropped */
    case SN_APP_FATAL:
        return -1;
    case SN_APP_OK:
    default:
        break;
    }

    /* dispatch — the device ops' send_response calls sn_agent_respond */
    if (shieldnet_command_dispatch(ag->dev, &hdr, payload, payload_len) < 0) {
        /* A response could not be sent. If any part of it reached the stream,
         * the peer will read the rest of the stream from inside it: end the
         * session. If it was refused whole -- §9.5's full queue, which is what
         * a quiesced session (§9.4) produces -- the stream is still aligned and
         * the session is one §9.4/§9.5 say to keep. */
        return ag->io_st.poisoned ? -1 : SN_AGENT_REFUSED;
    }
    return 1;
}

int sn_agent_respond(sn_agent *ag, uint32_t now_ms, uint8_t kind,
                     const uint8_t *body, size_t body_len) {
    uint32_t message_type = 0, original = 0;
    uint64_t msgnum = 0;
    size_t out_len = 0;
    /* Refused whole, before a message number is spent: a longer body is one the
     * build's assertions above did not cover. */
    if (body_len > SHIELDNET_MAX_RESPONSE_BODY) {
        return -1;
    }
    /* The MessageNum is the nonce under k_s2c, and k_s2c belongs to the
     * primary, not to this agent: take it from the primary's own counter, so a
     * second agent bound to the same session continues the sequence instead of
     * restarting it at 1 and re-using every nonce already sent. */
    if (sn_primary_next_s2c_msgnum(ag->io_st.dev, ag->io_st.gen, &ag->tx.next_msgnum) != 0) {
        return -1;
    }
    /* Message layer 6.3, sled 3.5: responses go out padded to §13's class.
     * Only when that class fits the enc buffer: a sender may stop at a lower
     * class (message layer 6.2 rule 1), so a small buffer sends unpadded rather
     * than failing. Above SN_PAD_MAX_CLASS the padded seal sends unpadded. */
    int pad = 1;
    if (body_len <= SN_PAD_MAX_CLASS) {
        size_t cls = SN_PAD_FLOOR;
        while (cls < body_len) cls <<= 1;
        pad = cls + CRYPTO_OVERHEAD <= ag->tx.enc_size;
    }
    int sealed = pad
        ? sn_app_seal_padded(&ag->tx, kind, body, body_len,
                             &message_type, &msgnum, &original, &out_len)
        : sn_app_seal(&ag->tx, kind, body, body_len,
                      &message_type, &msgnum, &original, &out_len);
    if (sealed != 0) {
        return -1;
    }
    sn_agent_set_now(&ag->io_st, now_ms);
    return protocol_write_message(&ag->io, message_type, msgnum, ag->tx.enc,
                                  (uint32_t)out_len, original);
}
