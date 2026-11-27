/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * sn_app_fuzz — what an ADMITTED peer can make the device do.
 *
 * Every other harness stops at the AEAD: a fuzzer cannot forge a tag, so the
 * code behind it -- KCP's input parser with ShieldNet's lowered rcv_wnd, the
 * app-layer open (padding strip, LZ4), and the whole command core -- was only
 * ever reached by unit tests. But the threat model includes an authenticated
 * peer: it holds the session keys and sends whatever it likes inside them.
 * This harness plays that peer. It seals the fuzzer's bytes itself, so they
 * arrive exactly as an authenticated sender's would.
 *
 * The device ops are stubs that ABORT when the core hands them something its
 * own contract (port/shieldnet_device.h) says it has already checked -- a pixel
 * frame past capacity, a mode the device does not have, a response past the
 * scratch buffer. A stub extension (shieldnet_device_ext_t) is installed when
 * bit 1 of byte 0 is set, and aborts if the core hands it a core kind or a
 * response kind. So a validation hole is a crash here, not a silent pass.
 *
 * Input: byte 0 picks the mode (bit 0) and whether the extension is installed
 * (bit 1).
 *   even: raw KCP. The rest is [u16 len][len bytes] datagrams fed straight to
 *         ikcp_input of a stream-mode, rcv_wnd-8 session (what sn_session.c
 *         builds), draining ikcp_recv into a WIRE_MTU buffer as the agent does.
 *   odd:  app frames. The rest is [u8 kind][u8 flags][u16 len][len bytes]...;
 *         flags bit 0 seals the bytes as a COMPRESSED frame claiming the
 *         original_size in the next two bytes, bit 1 pads them (§13). Each is
 *         opened with sn_app_open and, if it opens, dispatched.
 *
 *   build/fuzz/sn_fuzz_app corpus/ -max_len=2048
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "command.h"
#include "command_parse.h"
#include "crypto.h"
#include "ikcp.h"
#include "protocol.h"
#include "shieldnet/sn_app_frame.h"
#include "shieldnet/sn_device.h"
#include "shieldnet_device.h"

#define STRIPS 2
#define LEDS   64
#define CAP_PIXELS (STRIPS * LEDS)

/* ── stub device: every op checks the contract it was promised ─────────── */

static uint8_t g_scratch[1024];

static void op_get_geometry(void *ctx, shieldnet_device_geometry_t *out) {
    (void)ctx;
    out->num_strips = STRIPS; out->leds_per_strip = LEDS;
    out->led_bpp = 3; out->max_payload = 4096;
}
static void op_u8(void *ctx, uint8_t v) { (void)ctx; (void)v; }
/* The core promised the mode is PIXEL (the device has pixel output) or one the
 * extension reports; ctx is non-NULL only for the table with the extension. */
static bool ext_has_mode(void *ctx, uint8_t m) { (void)ctx; return m == 0 || m == 7; }
static int op_set_mode(void *ctx, uint8_t m) {
    if (m == 1) return 0;
    if (ctx != NULL && ext_has_mode(ctx, m)) return 0;
    abort();
}
static int op_set_output(void *ctx, bool on) { (void)ctx; (void)on; return 0; }
static bool op_publish(void *ctx, const uint8_t *px, int n) {
    (void)ctx;
    if (n < 0 || n > CAP_PIXELS) abort();
    volatile uint8_t sink = 0;
    for (int k = 0; k < n * 4; k++) sink ^= px[k];
    (void)sink;
    return true;
}
static void op_void(void *ctx) { (void)ctx; }
/* The core hands this op only a request its parser accepted: rebuild the bytes
 * from the fields and check the parser agrees. */
static void op_set_ntp_server(void *ctx, const shieldnet_ntp_server_req_t *req) {
    (void)ctx;
    uint8_t b[4 + 255];
    shieldnet_ntp_server_req_t chk;
    if (req->addr == NULL || req->addr_len > 253) abort();
    b[0] = req->addr_type; b[1] = req->addr_len;
    b[2] = (uint8_t)(req->port >> 8); b[3] = (uint8_t)req->port;
    memcpy(&b[4], req->addr, req->addr_len);
    if (!shieldnet_parse_ntp_server(b, 4u + req->addr_len, &chk)) abort();
}
static void op_get_status(void *ctx, shieldnet_device_status_t *out) {
    (void)ctx;
    out->mode = 7;          /* the core reports it only if the extension has it */
    out->brightness = 0x55;
}
static void op_get_tx_scratch(void *ctx, uint8_t **buf, size_t *cap) {
    (void)ctx; *buf = g_scratch; *cap = sizeof g_scratch;
}
static void op_emit_event(void *ctx, shieldnet_device_event_t ev, uint8_t arg) {
    (void)ctx; (void)ev; (void)arg;
}
static int op_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx; (void)kind;
    if (len > sizeof g_scratch && len > 512) abort();
    volatile uint8_t sink = 0;
    for (size_t k = 0; k < len; k++) sink ^= body[k];
    (void)sink;
    return 0;
}

/* ── stub extension ───────────────────────────────────────────────────── */

/* Owns nothing, so every kind it is given is answered ERR_UNKNOWN_KIND. The core
 * must never hand it a kind it implements or a response kind. */
static int g_ext_installed;
static int ext_handle(void *ctx, const shieldnet_device_ops_t *dev, uint8_t kind,
                      uint64_t msgnum, const uint8_t *payload, size_t len) {
    (void)ctx; (void)dev; (void)msgnum;
    if (kind >= 0x80 || (kind <= 0x0B && kind != 0x03)) abort();
    volatile uint8_t sink = 0;
    for (size_t k = 0; k < len; k++) sink ^= payload[k];   /* every byte readable */
    (void)sink;
    return SHIELDNET_EXT_UNHANDLED;
}
static void ext_fill_status(void *ctx, uint8_t out[SHIELDNET_STATUS_EXT_SIZE]) {
    (void)ctx;
    for (size_t k = 0; k < SHIELDNET_STATUS_EXT_SIZE; k++) out[k] = (uint8_t)k;
}
static const char *const EXT_CAPS[] = { "x-fuzz" };
static const shieldnet_device_field_t EXT_FIELDS[] = { { "x-n", "1" } };
static const shieldnet_device_ext_t EXT = {
    .ctx = &g_ext_installed,
    .caps = EXT_CAPS, .cap_count = 1,
    .fields = EXT_FIELDS, .field_count = 1,
    .handle = ext_handle,
    .fill_status = ext_fill_status,
    .has_mode = ext_has_mode,
};

#define COMMON_OPS \
    .get_geometry = op_get_geometry, \
    .set_brightness = op_u8, \
    .set_fps = op_u8, \
    .set_mode = op_set_mode, \
    .set_output_enabled = op_set_output, \
    .publish_pixel_frame = op_publish, \
    .note_frame_dropped = op_void, \
    .set_ntp_server = op_set_ntp_server, \
    .get_status = op_get_status, \
    .get_tx_scratch = op_get_tx_scratch, \
    .emit_event = op_emit_event, \
    .send_response = op_send_response

static const shieldnet_device_ops_t OPS = { .ctx = NULL, COMMON_OPS };
static const shieldnet_device_ops_t OPS_EXT = { .ctx = &g_ext_installed, COMMON_OPS, .ext = &EXT };

/* ── mode: raw KCP ──────────────────────────────────────────────────────── */

static int null_output(const char *b, int l, ikcpcb *k, void *u) {
    (void)b; (void)l; (void)k; (void)u; return 0;
}

static void run_kcp(const uint8_t *p, size_t n) {
    ikcpcb *k = ikcp_create(0, NULL);
    if (!k) return;
    ikcp_setoutput(k, null_output);
    ikcp_setmtu(k, SN_WIRE_MTU - SN_ENVELOPE_LEN);
    ikcp_nodelay(k, 1, 20, 2, 1);
    k->stream = 1;            /* before wndsize, as configure_kcp does */
    ikcp_wndsize(k, 32, 8);
    char out[SN_WIRE_MTU];
    uint32_t now = 0;
    while (n >= 2) {
        size_t len = ((size_t)p[0] << 8) | p[1];
        p += 2; n -= 2;
        if (len > n) len = n;
        (void)ikcp_input(k, (const char *)p, (long)len);
        p += len; n -= len;
        now += 20;
        ikcp_update(k, now);
        while (ikcp_recv(k, out, (int)sizeof out) > 0) {}
    }
    ikcp_release(k);
}

/* ── mode: sealed app frames into the command core ─────────────────────── */

static const uint8_t KEY[32] = {7};

static void run_app(const shieldnet_device_ops_t *ops, const uint8_t *p, size_t n) {
    static uint8_t enc[8192], dec[8192], decomp[8192];
    sn_app_rx rx;
    sn_app_rx_init(&rx, KEY, dec, sizeof dec, decomp, sizeof decomp);
    sn_app_tx tx;
    sn_app_tx_init(&tx, KEY, enc, sizeof enc);

    while (n >= 4) {
        uint8_t kind = p[0], flags = p[1];
        size_t len = ((size_t)p[2] << 8) | p[3];
        p += 4; n -= 4;
        if (len > n) len = n;
        const uint8_t *body = p;
        p += len; n -= len;

        protocol_msg_header_t hdr;
        memset(&hdr, 0, sizeof hdr);
        size_t ct_len = 0;
        if (flags & 1) {
            /* COMPRESSED: the peer chooses the "LZ4 block" and original_size. */
            uint32_t orig = 0;
            if (n >= 2) { orig = ((uint32_t)p[0] << 8) | p[1]; p += 2; n -= 2; }
            uint64_t num = tx.next_msgnum++;
            hdr.message_type = (uint32_t)kind | PROTOCOL_FLAG_COMPRESSED;
            hdr.original_size = orig;
            hdr.message_num = num;
            hdr.size = (uint32_t)(len + CRYPTO_OVERHEAD);
            uint8_t aad[PROTOCOL_HEADER_SIZE], nonce[CRYPTO_NONCE_SIZE];
            protocol_marshal_aad(hdr.size, orig, hdr.message_type, num, aad);
            protocol_nonce_from_msgnum(num, nonce);
            if (crypto_encrypt(KEY, nonce, body, len, aad, sizeof aad, enc, &ct_len) != 0) continue;
        } else {
            uint32_t type = 0, orig = 0;
            uint64_t num = 0;
            int rc = (flags & 2)
                ? sn_app_seal_padded(&tx, kind, body, len, &type, &num, &orig, &ct_len)
                : sn_app_seal(&tx, kind, body, len, &type, &num, &orig, &ct_len);
            if (rc != 0) continue;
            hdr.message_type = type; hdr.original_size = orig;
            hdr.message_num = num; hdr.size = (uint32_t)ct_len;
        }

        const uint8_t *payload = NULL;
        size_t plen = 0;
        if (sn_app_open(&rx, &hdr, enc, &payload, &plen) == SN_APP_OK) {
            (void)shieldnet_command_dispatch(ops, &hdr, payload, plen);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int inited;
    if (!inited) { if (sodium_init() < 0) abort(); inited = 1; }
    if (size < 1) return 0;
    if (data[0] & 1) run_app((data[0] & 2) ? &OPS_EXT : &OPS, data + 1, size - 1);
    else run_kcp(data + 1, size - 1);
    return 0;
}
