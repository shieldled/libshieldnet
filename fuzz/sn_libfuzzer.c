/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * libFuzzer entry points for the C implementation.
 *
 * The Go-driven harnesses in goshieldnet compare the two implementations and
 * catch memory errors through sanitizers, but they are not coverage-guided for
 * the C: Go's engine instruments the *Go* binary and gets no signal from this
 * side, so for anything without a Go counterpart it is closer to random
 * fuzzing. libFuzzer instruments this code directly, which is what actually
 * drives inputs toward new branches here.
 *
 * FUZZ_TARGET selects the entry point at build time; see CMakeLists.
 *
 * Run with a bounded input length -- protocol datagrams are at most WIRE_MTU and
 * the interesting ones are far shorter, so the default -max_len=4096 spends the
 * budget on sizes the protocol cannot produce. Throughput here is around 1.7k
 * exec/s at -max_len=256 rather than the six figures a trivial target reaches;
 * it degrades as the corpus grows, so long campaigns want a persisted corpus
 * directory rather than one long run.
 *
 *   build/fuzz/sn_fuzz_wire corpus/ -max_len=256
 *   build/fuzz/sn_fuzz_parsers corpus/ -max_len=256
 *   build/fuzz/sn_fuzz_sled corpus/ -max_len=512
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>

#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_wire.h"
#include "shieldnet/command_parse.h"
#include "shieldnet/command_encode.h"
#include "shieldnet/response_decode.h"

static int inited;
static void init_once(void) {
    if (!inited) { (void)sodium_init(); inited = 1; }
}

#if FUZZ_TARGET == 1
/* §5 step 0 and sequence reconstruction: everything an attacker's bytes reach
 * before a MAC is checked. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();
    sn_prefix local;
    memset(&local, 0, sizeof(local));
    local.a16[10] = 0xff; local.a16[11] = 0xff;
    local.a16[12] = 192; local.a16[13] = 168; local.a16[14] = 4; local.a16[15] = 1;
    local.is_v4 = 1;
    local.bits = 24;

    uint8_t src[16];
    memset(src, 0, 16);
    src[10] = 0xff; src[11] = 0xff;
    src[12] = 192; src[13] = 168; src[14] = 4;
    src[15] = size ? data[0] : 2;

    (void)sn_classify_datagram(SN_ROLE_DEVICE, data, size);
    (void)sn_classify_datagram(SN_ROLE_CLIENT, data, size);
    (void)sn_classify(SN_ROLE_DEVICE, 1, src, &local, 1, data, size);

    if (size >= 12) {
        uint32_t seq = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] << 8) | data[3];
        uint64_t hwm = 0;
        for (int i = 4; i < 12; i++) hwm = (hwm << 8) | data[i];
        (void)sn_reconstruct(seq, hwm);
    }
    return 0;
}
#endif

#if FUZZ_TARGET == 2
/* The post-authentication parsers. Unreachable from the wire for a fuzzer --
 * random bytes cannot forge a MAC -- so calling them directly is the only way
 * to cover them at all. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();
    shieldnet_set_brightness_req_t br;
    shieldnet_set_fps_req_t fps;
    shieldnet_set_mode_req_t mode;
    shieldnet_ntp_server_req_t ntp;

    (void)shieldnet_parse_set_brightness(data, size, &br);
    (void)shieldnet_parse_set_fps(data, size, &fps);
    (void)shieldnet_parse_set_mode(data, size, &mode);
    (void)shieldnet_parse_ntp_server(data, size, &ntp);
    return 0;
}
#endif

#if FUZZ_TARGET == 3
/*
 * The sled layer: response decoders on hostile input, and the encode/parse
 * round-trip.
 *
 * The decoders are the half a fuzzer can actually reach usefully. A client
 * decodes a response after the transport has authenticated it, so these bytes
 * come from a device — but "authenticated" is not "same firmware version", and
 * every length field here is attacker- or version-controlled. The
 * command_roundtrip suite sweeps structured values; this covers the shapes a
 * sweep does not think of.
 *
 * The round-trip half asserts the property the suite asserts, but from raw
 * bytes rather than from constructed structs: parse, re-encode, and require the
 * bytes to match. A parser that accepts two encodings of one request, or an
 * encoder that normalises a field the parser preserved, shows up here as a
 * mismatch rather than as a silently different datagram on the wire.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_once();

    /* ── decoders on arbitrary input ── */
    sled_ack_t ack;
    (void)sled_decode_ack(data, size, &ack);

    sled_status_resp_fields_t status;
    (void)sled_decode_status_resp(data, size, &status);

    size_t off = 0;
    sled_device_info_field_t f;
    while (sled_device_info_next(data, size, &off, &f)) {
        uint32_t v;
        (void)sled_device_info_value_u32(&f, &v);
    }
    (void)sled_device_info_has(data, size, "pixel");

    /*
     * Parse, re-encode, and re-parse: the two requests must agree.
     *
     * NOT a byte comparison. R4 makes reserved bytes "zero on send, ignored on
     * receive", so a payload carrying junk in a reserved position parses fine
     * and re-encodes to zeros -- a byte compare calls that a bug when it is the
     * rule working.
     *
     * Re-parsing is the property that actually holds: encoding is canonical,
     * so a second round must land in the same place as the first.
     */
    uint8_t out[2048];

#define ROUNDTRIP(type, parse_call, encode_call, reparse_call)                 \
    do {                                                                       \
        type a, b;                                                             \
        if ((parse_call(data, size, &a)).ok) {                                 \
            size_t n = encode_call(&a, out, sizeof(out));                      \
            if (n == 0) __builtin_trap();                                      \
            if (!(reparse_call(out, n, &b)).ok) __builtin_trap();              \
            if (memcmp(&a, &b, sizeof(a)) != 0) __builtin_trap();              \
        }                                                                      \
    } while (0)

    ROUNDTRIP(shieldnet_set_brightness_req_t, shieldnet_parse_set_brightness,
              shieldnet_encode_set_brightness, shieldnet_parse_set_brightness);
    ROUNDTRIP(shieldnet_set_fps_req_t, shieldnet_parse_set_fps,
              shieldnet_encode_set_fps, shieldnet_parse_set_fps);
    ROUNDTRIP(shieldnet_set_mode_req_t, shieldnet_parse_set_mode,
              shieldnet_encode_set_mode, shieldnet_parse_set_mode);
#undef ROUNDTRIP

    /* NTP_SERVER returns a bool, which ROUNDTRIP's .ok does not fit. addr points
     * into whichever buffer was parsed, so compare the bytes and not the pointer. */
    shieldnet_ntp_server_req_t ntp, ntp2;
    if (shieldnet_parse_ntp_server(data, size, &ntp)) {
        size_t n = shieldnet_encode_ntp_server(&ntp, out, sizeof(out));
        if (n == 0) __builtin_trap();
        if (!shieldnet_parse_ntp_server(out, n, &ntp2)) __builtin_trap();
        if (ntp2.addr_type != ntp.addr_type || ntp2.addr_len != ntp.addr_len ||
            ntp2.port != ntp.port || memcmp(ntp2.addr, ntp.addr, ntp.addr_len) != 0)
            __builtin_trap();
    }
    return 0;
}
#endif
