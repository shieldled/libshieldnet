/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * App-frame seal/open: the padding classes (message layer 6.2), including a
 * body above the top class, which is sent unpadded rather than refused; and the
 * message-layer vectors (Appendix A, sn_vectors.h).
 */
#include "shieldnet/sn_app_frame.h"
#include "protocol.h"
#include "crypto.h"
#include "sn_vectors.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else { printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); failures++; } \
} while (0)

static const uint8_t key[32] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

static uint8_t enc_a[2048], enc_b[2048], dec[2048], decomp[2048];

/* Open tx's sealed output as a receiver would: header from the seal's outputs. */
static int open_back(const uint8_t *ct, uint32_t type, uint64_t msgnum, uint32_t original,
                     size_t ct_len, const uint8_t *want, size_t want_len) {
    sn_app_rx rx;
    sn_app_rx_init(&rx, key, dec, sizeof dec, decomp, sizeof decomp);
    protocol_msg_header_t h = { (uint32_t)ct_len, original, type, msgnum };
    const uint8_t *pl = NULL;
    size_t pl_len = 0;
    if (sn_app_open(&rx, &h, ct, &pl, &pl_len) != SN_APP_OK) return 0;
    return pl_len == want_len && (want_len == 0 || memcmp(pl, want, want_len) == 0);
}

static void test_over_class(void) {
    uint8_t body[600];
    for (size_t i = 0; i < sizeof body; i++) body[i] = (uint8_t)(i * 7 + 3);

    sn_app_tx tx;
    uint32_t type = 0, original = 0;
    uint64_t msgnum = 0;
    size_t ct_len = 0;

    sn_app_tx_init(&tx, key, enc_a, sizeof enc_a);
    int rc = sn_app_seal_padded(&tx, 0x07, body, 513, &type, &msgnum, &original, &ct_len);
    CHECK(rc == 0, "513 padded: sealed, not refused");
    CHECK(rc == 0 && original == 513 && ct_len == 513 + CRYPTO_OVERHEAD,
          "513 padded: sent unpadded (original 513, size 513+16)");
    CHECK(rc == 0 && open_back(enc_a, type, msgnum, original, ct_len, body, 513),
          "513 padded: opens to the 513 octets");

    /* The same body through sn_app_seal at the same MessageNum: identical. */
    sn_app_tx tx2;
    sn_app_tx_init(&tx2, key, enc_b, sizeof enc_b);
    uint32_t type2 = 0, original2 = 0;
    uint64_t msgnum2 = 0;
    size_t ct_len2 = 0;
    int rc2 = sn_app_seal(&tx2, 0x07, body, 513, &type2, &msgnum2, &original2, &ct_len2);
    CHECK(rc == 0 && rc2 == 0 && msgnum == msgnum2 && type == type2 &&
          original == original2 && ct_len == ct_len2 &&
          memcmp(enc_a, enc_b, ct_len) == 0,
          "513 padded == 513 unpadded (same ciphertext)");

    sn_app_tx_init(&tx, key, enc_a, sizeof enc_a);
    rc = sn_app_seal_padded(&tx, 0x07, body, 512, &type, &msgnum, &original, &ct_len);
    CHECK(rc == 0 && original == 512 && ct_len == 512 + CRYPTO_OVERHEAD,
          "512 padded: top class");
    sn_app_tx_init(&tx, key, enc_a, sizeof enc_a);
    rc = sn_app_seal_padded(&tx, 0x07, body, 65, &type, &msgnum, &original, &ct_len);
    CHECK(rc == 0 && original == 65 && ct_len == 128 + CRYPTO_OVERHEAD,
          "65 padded: class 128");
    CHECK(rc == 0 && open_back(enc_a, type, msgnum, original, ct_len, body, 65),
          "65 padded: opens to the 65 octets");

    sn_app_tx_init(&tx, key, enc_a, sizeof enc_a);
    rc = sn_app_seal_padded(&tx, 0x07, NULL, 600, &type, &msgnum, &original, &ct_len);
    CHECK(rc == -1, "NULL body of 600: refused");
    /* Refused before sealing: crypto_encrypt would refuse it too, but only
     * after seal_common has spent a MessageNum. */
    CHECK(tx.next_msgnum == 1, "NULL body of 600: no MessageNum spent");
}

static int ml_case(const char *name) {
    for (int i = 0; i < SN_ML_CASE_N; i++)
        if (strcmp(sn_ml_name[i], name) == 0) return i;
    return -1;
}

/* padded, padded-45: sn_app_seal_padded reproduces the whole frame. */
static void test_ml_seal(const char *name) {
    char label[96];
    int i = ml_case(name);
    snprintf(label, sizeof label, "vector %s: present", name);
    CHECK(i >= 0, label);
    if (i < 0) return;
    sn_app_tx tx;
    sn_app_tx_init(&tx, sn_ml_key, enc_a, sizeof enc_a);
    tx.next_msgnum = sn_ml_num[i];
    uint32_t type = 0, original = 0;
    uint64_t msgnum = 0;
    size_t ct_len = 0;
    int rc = sn_app_seal_padded(&tx, (uint8_t)sn_ml_type[i],
                                sn_ml_plaintext_blob + sn_ml_plaintext_off[i],
                                sn_ml_plaintext_len[i],
                                &type, &msgnum, &original, &ct_len);
    uint8_t frame[PROTOCOL_HEADER_SIZE + sizeof enc_a];
    int ok = rc == 0 && PROTOCOL_HEADER_SIZE + ct_len == sn_ml_frame_len[i];
    if (ok) {
        protocol_marshal_aad((uint32_t)ct_len, original, type, msgnum, frame);
        memcpy(frame + PROTOCOL_HEADER_SIZE, tx.enc, ct_len);
        ok = memcmp(frame, sn_ml_frame_blob + sn_ml_frame_off[i], sn_ml_frame_len[i]) == 0;
    }
    snprintf(label, sizeof label, "vector %s: sealed frame matches", name);
    CHECK(ok, label);
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Every case opens, from its frame, to its plaintext. */
static void test_ml_open(const char *name) {
    char label[96];
    int i = ml_case(name);
    snprintf(label, sizeof label, "vector %s: present", name);
    CHECK(i >= 0, label);
    if (i < 0) return;
    const uint8_t *f = sn_ml_frame_blob + sn_ml_frame_off[i];
    protocol_msg_header_t h;
    h.size = be32(f);
    h.original_size = be32(f + 4);
    h.message_type = be32(f + 8);
    h.message_num = 0;
    for (int k = 0; k < 8; k++) h.message_num = (h.message_num << 8) | f[12 + k];
    sn_app_rx rx; /* fresh per case: one rx's replay guard would drop a lower MessageNum */
    sn_app_rx_init(&rx, sn_ml_key, dec, sizeof dec, decomp, sizeof decomp);
    const uint8_t *pl = NULL;
    size_t pl_len = 0;
    int ok = PROTOCOL_HEADER_SIZE + h.size == sn_ml_frame_len[i] &&
             sn_app_open(&rx, &h, f + PROTOCOL_HEADER_SIZE, &pl, &pl_len) == SN_APP_OK &&
             pl_len == sn_ml_plaintext_len[i] &&
             (pl_len == 0 || memcmp(pl, sn_ml_plaintext_blob + sn_ml_plaintext_off[i], pl_len) == 0);
    snprintf(label, sizeof label, "vector %s: opens to its plaintext", name);
    CHECK(ok, label);
}

int main(void) {
    if (sodium_init() < 0) {
        printf("sodium_init failed\n");
        return 2;
    }
    test_over_class();
    /* `plain` is open-only: the seal API takes a one-octet kind and cannot emit
     * MessageType 0x00112233 (a sender transmits bits 8-30 as zero). */
    test_ml_seal("padded");
    test_ml_seal("padded-45");
    test_ml_open("plain");
    test_ml_open("padded");
    test_ml_open("padded-45");
    test_ml_open("compressed-decode");
    if (failures) {
        printf("%d failure(s)\n", failures);
        return 1;
    }
    printf("all passed\n");
    return 0;
}
