/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * sn_oracle — the C half of a differential fuzzer.
 *
 * ShieldNet has two independent implementations of one wire format, and the
 * cross-language golden vectors only cover inputs both ends already agree are
 * valid. Divergence on *invalid* input is the interesting case: a datagram one
 * end drops and the other accepts is exactly where a device and its controller
 * stop sharing a view of the protocol.
 *
 * This is a long-lived process, not a per-input exec: the Go fuzzer runs at
 * ~200k executions/second and a fork per input would dominate. It reads
 * length-prefixed requests on stdin and answers with a fixed-size verdict
 * record on stdout.
 *
 * On start the oracle writes a 4-byte banner, "SNO" followed by a protocol
 * version. A stale binary speaking an older framing otherwise leaves the driver
 * blocked on a read that never comes -- a hang rather than an error, which is
 * strictly worse to debug.
 *
 *   banner  : "SNO" [u8 version]
 *   request : [u32be len][u8 mode][len bytes]
 *   response: 16 bytes, fixed size
 *
 * mode 0 (wire): the pure decisions both implementations must make identically.
 *   [0]=class_device [1]=class_client [2]=class_device_src [3..10]=i64be reconstruct
 *
 * mode 1 (command): the post-authentication parsers in command_parse.h, which
 *   have no Go counterpart -- there is nothing to compare against, so this is
 *   crash and UB fuzzing, which is why the sanitizers matter. Each byte is one
 *   parser's verdict (0xFF = accepted, else the rejection status): [7]=SET_BRIGHTNESS
 *   [8]=SET_FPS [10]=SET_MODE [12]=NTP_SERVER (0xFF accepted, 0 rejected). The
 *   other bytes were the positions of parsers the library no longer has; they
 *   stay 0 so the record and the remaining positions do not move. Reaching these
 *   through the real path is impossible for a fuzzer because they sit behind
 *   AEAD; calling them directly is the only way to exercise them at all.
 *
 * mode 2 (client receive): the §3.5/§7.3/§7.4 checks of the C client.
 *   This is where the C client's NEW validation lives, and no golden vector
 *   reaches it: vectors cover inputs both ends already accept, and every
 *   interesting case here is a rejection. Every key and constant below is fixed
 *   and mirrored exactly on the Go side, so a divergence is about the datagram.
 *   [0]=decode_retry [1]=check_retry [2]=decode_admit [3]=check_admit
 *
 * The payload's first 12 bytes, when present, seed sn_reconstruct (seq_wire and
 * hwm) and the source address used for the §4.3-checked classify; the whole
 * payload is also the datagram. One fuzz input therefore drives every pure
 * decision both implementations must make identically.
 */
#include "shieldnet/sn_client_wire.h"
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_wire.h"
#include "shieldnet/command_parse.h"
#include "shieldnet/command_encode.h"

#include <sodium.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_exact(uint8_t *p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(STDIN_FILENO, p + got, n - got);
        if (r <= 0) return 0;
        got += (size_t)r;
    }
    return 1;
}

static void write_exact(const uint8_t *p, size_t n) {
    size_t put = 0;
    while (put < n) {
        ssize_t w = write(STDOUT_FILENO, p + put, n - put);
        if (w <= 0) return;
        put += (size_t)w;
    }
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int main(void) {
    /* Staging only. The payload handed to the code under test is a heap block of
     * exactly len bytes: with a fixed static buffer a read one past the payload
     * is still inside the array, ASan sees nothing, and the sanitizers catch no
     * overread at all. Verified by injecting a one-past-the-end read into a
     * parser -- undetected with the static buffer, caught with this one. */
    static uint8_t staging[70000];
    /* Fixed local prefix, mirrored exactly on the Go side. */
    sn_prefix local;
    memset(&local, 0, sizeof(local));
    local.a16[10] = 0xff; local.a16[11] = 0xff;
    local.a16[12] = 192; local.a16[13] = 168; local.a16[14] = 4; local.a16[15] = 1;
    local.is_v4 = 1;
    local.bits = 24;

    /* Fixed client-side inputs for mode 2, mirrored byte for byte in Go. */
    static uint8_t PSK[32], DEVID[8], NONCE[24], OWNCS[18], ECPRIV[32];
    memset(PSK, 0x11, 32);
    for (int i = 0; i < 8; i++) DEVID[i] = (uint8_t)(i + 1);
    memset(NONCE, 0xAB, 24);
    memset(ECPRIV, 0x07, 32);
    /* canonical_source = a16 || port_be, for 192.168.4.2:5000. */
    memset(OWNCS, 0, 18);
    OWNCS[10] = 0xff; OWNCS[11] = 0xff;
    OWNCS[12] = 192; OWNCS[13] = 168; OWNCS[14] = 4; OWNCS[15] = 2;
    OWNCS[16] = 0x13; OWNCS[17] = 0x88; /* 5000 */
    uint8_t K_DEV[32], K_REQ[32], K_RESP[32];
    sn_derive_kdev(PSK, DEVID, K_DEV);
    sn_derive_static(K_DEV, K_REQ, K_RESP);
    uint8_t E_C[32];
    crypto_scalarmult_base(E_C, ECPRIV);
    /* A fixed context and admission_epoch: §7.4 compares ADMIT against what
     * FINISH presented, and the fuzzer is not driving a real attempt. */
    static uint8_t EPOCH_TAG[8], COOKIE[16], SENT_AE[8];
    memset(EPOCH_TAG, 0x5a, 8);
    memset(COOKIE, 0x6b, 16);
    memset(SENT_AE, 0x7c, 8);
    uint8_t CONTEXT[65];
    sn_context(NONCE, EPOCH_TAG, COOKIE, SENT_AE, DEVID, CONTEXT);

    /* Banner 3: mode 2 exists. A driver written against 2 would otherwise send
     * mode 2 to a binary that treats every unknown mode as the wire mode and
     * compare verdicts that mean different things. */
    { const uint8_t banner[4] = { 'S', 'N', 'O', 3 }; write_exact(banner, 4); }

    for (;;) {
        uint8_t hdr[5];
        if (!read_exact(hdr, 5)) return 0;
        uint32_t len = be32(hdr);
        uint8_t mode = hdr[4];
        if (len > sizeof(staging)) return 1;
        if (len && !read_exact(staging, len)) return 0;

        /* Exact-sized allocation so ASan's redzones bracket the payload. */
        uint8_t *buf = malloc(len ? len : 1);
        if (!buf) return 1;
        if (len) memcpy(buf, staging, len);

        uint8_t out[16];
        memset(out, 0, sizeof(out));

        if (mode == 1) {
            shieldnet_set_brightness_req_t br;
            shieldnet_set_fps_req_t fps;
            shieldnet_set_mode_req_t mode_req;

            /* ok is the verdict; ack_status is only meaningful on rejection, so
             * encode accepted as 0xFF to keep the two apart. */
            #define VERD(expr) ({ shieldnet_parse_result_t r_ = (expr); \
                                  (uint8_t)(r_.ok ? 0xFF : r_.ack_status); })
            out[7] = VERD(shieldnet_parse_set_brightness(buf, len, &br));
            out[8] = VERD(shieldnet_parse_set_fps(buf, len, &fps));
            out[10] = VERD(shieldnet_parse_set_mode(buf, len, &mode_req));
            /* NTP_SERVER returns a bool, which VERD does not fit: 0xFF accepted,
             * 0 rejected. An accepted request must survive encode and re-parse. */
            shieldnet_ntp_server_req_t ntp, ntp2;
            if (shieldnet_parse_ntp_server(buf, len, &ntp)) {
                uint8_t re[4 + 255];
                size_t n = shieldnet_encode_ntp_server(&ntp, re, sizeof re);
                if (n == 0 || !shieldnet_parse_ntp_server(re, n, &ntp2) ||
                    ntp2.addr_type != ntp.addr_type || ntp2.addr_len != ntp.addr_len ||
                    ntp2.port != ntp.port || memcmp(ntp2.addr, ntp.addr, ntp.addr_len) != 0)
                    __builtin_trap();
                out[12] = 0xFF;
            } else {
                out[12] = 0;
            }
            write_exact(out, sizeof(out));
            free(buf);
            continue;
        }

        /* Source address for the §4.3-checked classify: v4-mapped, low octet
         * taken from the payload so it varies with the input. */
        uint8_t src[16];
        memset(src, 0, 16);
        src[10] = 0xff; src[11] = 0xff;
        src[12] = 192; src[13] = 168; src[14] = 4;
        src[15] = len > 0 ? buf[0] : 2;

        uint32_t seq_wire = len >= 4 ? be32(buf) : 0;
        uint64_t hwm = 0;
        if (len >= 12) {
            for (int i = 4; i < 12; i++) hwm = (hwm << 8) | buf[i];
        }

        if (mode == 2) {
            sn_retry_msg rm;
            out[0] = (uint8_t)sn_decode_retry(buf, len, &rm);
            out[1] = (out[0] == SN_CW_OK)
                       ? (uint8_t)sn_check_retry(&rm, K_RESP, NONCE, OWNCS, DEVID)
                       : 0xFF; /* not reached: the decode already refused */
            sn_admit_msg am;
            out[2] = (uint8_t)sn_decode_admit(buf, len, &am);
            if (out[2] == SN_CW_OK) {
                uint8_t master[32];
                out[3] = (uint8_t)sn_check_admit(&am, K_DEV, K_RESP, CONTEXT,
                                                 SENT_AE, E_C, ECPRIV, master);
            } else {
                out[3] = 0xFF;
            }
            write_exact(out, sizeof(out));
            free(buf);
            continue;
        }

        out[0] = (uint8_t)sn_classify_datagram(SN_ROLE_DEVICE, buf, len);
        out[1] = (uint8_t)sn_classify_datagram(SN_ROLE_CLIENT, buf, len);
        out[2] = (uint8_t)sn_classify(SN_ROLE_DEVICE, 1, src, &local, 1, buf, len);
        int64_t rc = sn_reconstruct(seq_wire, hwm);
        for (int i = 0; i < 8; i++) out[3 + i] = (uint8_t)(rc >> (56 - 8 * i));
        write_exact(out, sizeof(out));
        free(buf);
    }
}
