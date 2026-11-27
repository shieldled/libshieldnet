/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_app_frame.h"

#include "crypto.h"
#include "decompress.h"

#include <sodium.h>

#include <string.h>

void sn_app_rx_init(sn_app_rx *rx, const uint8_t key[32],
                    uint8_t *dec, size_t dec_size, uint8_t *decomp, size_t decomp_size) {
    memset(rx, 0, sizeof(*rx));
    memcpy(rx->key, key, 32);
    rx->dec = dec; rx->dec_size = dec_size;
    rx->decomp = decomp; rx->decomp_size = decomp_size;
}

void sn_app_tx_init(sn_app_tx *tx, const uint8_t key[32], uint8_t *enc, size_t enc_size) {
    memset(tx, 0, sizeof(*tx));
    memcpy(tx->key, key, 32);
    tx->next_msgnum = 1; /* §13 */
    tx->enc = enc; tx->enc_size = enc_size;
}

sn_app_result sn_app_open(sn_app_rx *rx, const protocol_msg_header_t *hdr,
                          const uint8_t *raw,
                          const uint8_t **payload, size_t *payload_len) {
    /* MessageNum 0 is the reserved handshake-tag nonce; app data is >= 1,
     * strictly increasing (replay guard). */
    if (hdr->message_num == 0 || hdr->message_num <= rx->last_msgnum) {
        return SN_APP_DROP;
    }
    uint8_t aad[PROTOCOL_HEADER_SIZE];
    protocol_marshal_aad(hdr->size, hdr->original_size, hdr->message_type,
                         hdr->message_num, aad);
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    protocol_nonce_from_msgnum(hdr->message_num, nonce);
    if (hdr->size < CRYPTO_OVERHEAD ||
        (size_t)(hdr->size - CRYPTO_OVERHEAD) > rx->dec_size) {
        return SN_APP_DROP; /* plaintext would overflow dec */
    }
    size_t dec_len = 0;
    if (crypto_decrypt(rx->key, nonce, raw, hdr->size, aad, sizeof(aad),
                       rx->dec, &dec_len) != 0) {
        return SN_APP_DROP; /* auth failure: drop this frame, session survives */
    }
    rx->last_msgnum = hdr->message_num;

    const uint8_t *p = rx->dec;
    size_t plen = dec_len;
    if (hdr->message_type & PROTOCOL_FLAG_COMPRESSED) {
        /* §13: padding and compression cannot combine -- that needs three
         * lengths and the header carries two. A compressed frame whose sealed
         * plaintext is a padding class is therefore malformed, not padded. */
        if (hdr->original_size == 0 || hdr->original_size > rx->decomp_size) {
            return SN_APP_DROP;
        }
        size_t d = 0;
        if (decompress_lz4(rx->dec, dec_len, rx->decomp, hdr->original_size, &d) < 0) {
            return SN_APP_DROP;
        }
        p = rx->decomp;
        plen = d;
    } else if (dec_len != hdr->original_size) {
        /* Transport §13: a control or configuration message is padded up to the
         * smallest power-of-two size class from 64 B. The sealed plaintext is
         * then the class and original_size is the true length, so strip rather
         * than reject. Any other length is a header/body disagreement.
         *
         * Bound original_size FIRST. It is authenticated but not conforming, and
         * on a 32-bit size_t the ladder below wraps to 0 at 0x80000000 and never
         * terminates — a watchdog reset driven by one authenticated frame. A
         * padded frame always has dec_len == class >= original_size, so anything
         * larger is a header/body disagreement and never a class we could reach. */
        if (hdr->original_size > dec_len) {
            return SN_APP_DROP;
        }
        size_t cls = SN_PAD_FLOOR;
        while (cls < hdr->original_size) cls <<= 1;
        if (dec_len != cls) {
            return SN_APP_DROP;
        }
        plen = hdr->original_size;
    }

    *payload = p;
    *payload_len = plen;
    return SN_APP_OK;
}

/* seal_len bytes are encrypted; original is what the receiver is told the true
 * length was. They differ only for a padded message. */
static int seal_common(sn_app_tx *tx, uint8_t kind, uint32_t type_flags,
                       const uint8_t *plaintext,
                       size_t seal_len, uint32_t original,
                       uint32_t *out_type, uint64_t *out_msgnum,
                       uint32_t *out_original, size_t *out_len) {
    if (tx->next_msgnum == UINT64_MAX) {
        return -1; /* MessageNum space exhausted; rekey required */
    }
    /* Bound the LENGTH, not the sum: `(uint32_t)seal_len + CRYPTO_OVERHEAD`
     * wraps for a body within 16 bytes of 2^32 and passes a check it should
     * fail. Unreachable on a 32-bit size_t, but the check belongs on the input. */
    if (seal_len > SIZE_MAX - CRYPTO_OVERHEAD ||
        seal_len + CRYPTO_OVERHEAD > tx->enc_size ||
        seal_len > UINT32_MAX - CRYPTO_OVERHEAD) {
        return -1;
    }
    uint64_t msgnum = tx->next_msgnum++;
    /* type_flags is part of message_type before the AAD below is built; only
     * sn_app_seal_compressed passes one. */
    uint32_t message_type = (uint32_t)kind | type_flags;
    uint32_t ciphertext_len = (uint32_t)(seal_len + CRYPTO_OVERHEAD);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    protocol_nonce_from_msgnum(msgnum, nonce);
    uint8_t aad[PROTOCOL_HEADER_SIZE];
    protocol_marshal_aad(ciphertext_len, original, message_type, msgnum, aad);
    size_t ol = 0;
    if (crypto_encrypt(tx->key, nonce, plaintext, seal_len, aad, sizeof(aad),
                       tx->enc, &ol) != 0) {
        return -1;
    }
    /* The AAD was marshalled from the predicted length. They agree today; if
     * they ever did not, sender and receiver would build different AADs and
     * every frame would fail the AEAD with nothing to point at. */
    if (ol != (size_t)ciphertext_len) {
        return -1;
    }
    *out_type = message_type;
    *out_msgnum = msgnum;
    *out_original = original;
    *out_len = ol;
    return 0;
}

int sn_app_seal(sn_app_tx *tx, uint8_t kind, const uint8_t *body, size_t body_len,
                uint32_t *out_type, uint64_t *out_msgnum,
                uint32_t *out_original, size_t *out_len) {
    if (body_len > UINT32_MAX) return -1;
    return seal_common(tx, kind, 0, body, body_len, (uint32_t)body_len,
                       out_type, out_msgnum, out_original, out_len);
}

int sn_app_seal_padded(sn_app_tx *tx, uint8_t kind, const uint8_t *body, size_t body_len,
                       uint32_t *out_type, uint64_t *out_msgnum,
                       uint32_t *out_original, size_t *out_len) {
    /* Otherwise the pad buffer's zeroes go out as the message and the caller
     * is told it succeeded: a different application message, silently. */
    if (body_len && !body) return -1;
    /* Message layer 6.2 item 2: above the top class, send unpadded, never refuse. */
    if (body_len > SN_PAD_MAX_CLASS)
        return sn_app_seal(tx, kind, body, body_len, out_type, out_msgnum, out_original, out_len);
    size_t cls = SN_PAD_FLOOR;
    while (cls < body_len) cls <<= 1;
    uint8_t padded[SN_PAD_MAX_CLASS];
    memset(padded, 0, cls);
    if (body_len && body) memcpy(padded, body, body_len);
    int rc = seal_common(tx, kind, 0, padded, cls, (uint32_t)body_len,
                         out_type, out_msgnum, out_original, out_len);
    sodium_memzero(padded, sizeof padded);
    return rc;
}

int sn_app_seal_compressed(sn_app_tx *tx, uint8_t kind,
                           const uint8_t *comp, size_t comp_len, size_t original_len,
                           uint32_t *out_type, uint64_t *out_msgnum,
                           uint32_t *out_original, size_t *out_len) {
    if (original_len == 0 || original_len > UINT32_MAX) return -1;
    if (comp_len == 0 || !comp) return -1;
    return seal_common(tx, kind, PROTOCOL_FLAG_COMPRESSED, comp, comp_len,
                       (uint32_t)original_len, out_type, out_msgnum, out_original, out_len);
}

void sn_app_rx_wipe(sn_app_rx *rx, int wipe_buffers) {
    if (!rx) return;
    sodium_memzero(rx->key, sizeof rx->key);
    if (wipe_buffers) {
        if (rx->dec)    sodium_memzero(rx->dec, rx->dec_size);
        if (rx->decomp) sodium_memzero(rx->decomp, rx->decomp_size);
    }
}

void sn_app_tx_wipe(sn_app_tx *tx, int wipe_buffers) {
    if (!tx) return;
    sodium_memzero(tx->key, sizeof tx->key);
    if (wipe_buffers && tx->enc) sodium_memzero(tx->enc, tx->enc_size);
}
