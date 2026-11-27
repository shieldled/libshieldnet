/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * led_client: a minimal ShieldNet controller. It takes control of a device,
 * prints its geometry, switches it to PIXEL mode, sends a few frames of one
 * colour, reads STATUS back and exits.
 *
 *   SHIELDNET_PSK_FILE=psk.hex led_client [-same-host] <ipv4> <port> <device-id-hex-16> <rrggbb>
 *
 * The client library owns no thread, no socket and no clock (sn_client.h).
 * This program owns all three: one UDP socket, one poll() loop, and every
 * datagram goes to sn_client_input, every loop turn to sn_client_tick.
 */
#include "shieldnet/sn_client.h"        /* sn_client_*: admission, session, app layer */
#include "shieldnet/command.h"          /* SLED_CMD_*, SLED_RESP_*, SLED_ACK_* */
#include "shieldnet/command_encode.h"   /* shieldnet_encode_*: request payloads */
#include "shieldnet/mode_decode_policy.h" /* SLED_WIRE_MODE_PIXEL */
#include "shieldnet/response_decode.h"  /* sled_decode_*: response payloads */
#include "shieldnet_os.h"               /* shieldnet_os_now_ms: a monotonic clock */
#include "example_util.h"

#include <poll.h>
#include <sys/socket.h>

#define FRAMES     5
#define FRAME_MS   40                  /* 25 frames a second */
#define TIMEOUT_MS 15000
#define APP_BUF    (SN_CS_MSG_MAX + 64) /* the largest message, with framing */

static int g_fd;

/* What the device has told us. on_app only records; the main loop acts on it,
 * because the callback must not call back into the client (sn_client.h). */
static struct {
    int got_info, got_mode_ack, got_status;
    sled_geometry_t geo;
    uint8_t mode_status;
    sled_status_resp_fields_t status;
} rx;

/* The client's send sink: one sealed datagram to the (connected) device. */
static void send_dgram(void *ctx, const uint8_t *dg, size_t len) {
    (void)ctx;
    if (send(g_fd, dg, len, 0) < 0) perror("send"); /* an ICMP error: ignore, keep going */
}

/* One decoded application message from the device. The sled kind is the low
 * byte of message_type; unknown kinds are skipped (forward compatibility). */
static void on_app(void *ctx, uint32_t message_type, const uint8_t *body, size_t len) {
    (void)ctx;
    sled_ack_t ack;
    switch ((uint8_t)message_type) {
    case SLED_RESP_DEVICE_INFO:
        rx.got_info = sled_decode_geometry(body, len, &rx.geo) ? 1 : -1;
        break;
    case SLED_RESP_ACK:
        if (sled_decode_ack(body, len, &ack) && ack.orig_kind == SLED_CMD_SET_MODE) {
            rx.mode_status = ack.status;
            rx.got_mode_ack = 1;
        }
        break;
    case SLED_RESP_STATUS:
        rx.got_status = sled_decode_status_resp(body, len, &rx.status) ? 1 : -1;
        break;
    }
}

int main(int argc, char **argv) {
    int same_host = argc > 1 && strcmp(argv[1], "-same-host") == 0;
    argv += same_host; argc -= same_host;
    struct sockaddr_in dev = { .sin_family = AF_INET };
    sn_client_config cfg;
    memset(&cfg, 0, sizeof cfg); /* conv 0: the library draws a fresh one */
    uint8_t rgb[3];
    uint16_t port;
    if (argc != 5 || inet_pton(AF_INET, argv[1], &dev.sin_addr) != 1 ||
        ex_parse_port(argv[2], 1, &port) != 0 ||
        ex_unhex(argv[3], cfg.device_id, 8) != 0 || ex_unhex(argv[4], rgb, 3) != 0) {
        fprintf(stderr, "usage: SHIELDNET_PSK_FILE=<file> led_client [-same-host] "
                        "<ipv4> <port> <device-id-hex-16> <rrggbb>\n");
        return 2;
    }
    dev.sin_port = htons(port);

    /* Transport 7.2: never talk to loopback, a local subnet's broadcast or
     * this host's own address. -same-host (DEVELOPMENT ONLY) skips the check
     * so both ends can run on one machine. */
    sn_prefix local[32];
    uint8_t dev_a16[16];
    int n_local = ex_local_prefixes(local, 32);
    ex_a16(&dev.sin_addr, dev_a16);
    if (!same_host && (n_local <= 0 || sn_source_rejected(1, dev_a16, local, (size_t)n_local))) {
        fprintf(stderr, "%s is loopback, broadcast or this host (use -same-host to test locally)\n",
                argv[1]);
        return 2;
    }

    /* A connected socket: the kernel then drops datagrams from anyone but the
     * device, which is the source check sn_client_input relies on. getsockname
     * tells us our own address, which admission binds (own_source). */
    struct sockaddr_in me;
    socklen_t mlen = sizeof me;
    g_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (g_fd < 0 || connect(g_fd, (struct sockaddr *)&dev, sizeof dev) != 0 ||
        getsockname(g_fd, (struct sockaddr *)&me, &mlen) != 0) {
        perror("socket");
        return 1;
    }
    uint8_t me_a16[16];
    ex_a16(&me.sin_addr, me_a16);
    sn_canonical_source(me_a16, ntohs(me.sin_port), cfg.own_source);

    /* The client derives its keys from the PSK in sn_client_init, then we wipe ours. */
    if (ex_load_psk(cfg.psk) != 0) return 2;
    sn_client c;
    int rc = sn_client_init(&c, &cfg);
    sodium_memzero(&cfg, sizeof cfg);
    if (rc != SN_CLIENT_OK) { fprintf(stderr, "sn_client_init failed\n"); return 1; }
    sn_client_set_send(&c, send_dgram, NULL);

    /* The app layer's buffers, bound while the client is still IDLE. */
    static uint8_t carry[2 * APP_BUF], raw[APP_BUF], dec[APP_BUF], decomp[APP_BUF], enc[APP_BUF];
    static uint8_t comp[SN_CLIENT_COMPRESS_BUF_MIN];
    if (sn_client_set_app_buffers(&c, carry, sizeof carry, raw, sizeof raw, dec, sizeof dec,
                                  decomp, sizeof decomp, enc, sizeof enc) != SN_CLIENT_OK ||
        sn_client_set_compress_buffer(&c, comp, sizeof comp) != SN_CLIENT_OK) {
        fprintf(stderr, "buffers\n");
        return 1;
    }
    sn_client_set_on_app(&c, on_app, NULL);

    /* Take control. The first message rides on the admission: GET_DEVICE_INFO,
     * which every controller sends first. Control messages go out padded. */
    uint32_t now = shieldnet_os_now_ms(), start = now, next_frame = now;
    if (sn_client_take_control_app_padded(&c, SLED_CMD_GET_DEVICE_INFO, NULL, 0, now) !=
        SN_CLIENT_IN_PROGRESS) {
        fprintf(stderr, "take control failed\n");
        return 1;
    }

    static uint8_t frame[APP_BUF];
    size_t frame_len = 0;
    int mode_sent = 0, frames_sent = 0, status_sent = 0, result = 1;
    while (now - start < TIMEOUT_MS) {
        /* Wait up to 10 ms for a datagram, then feed it in; tick every turn. */
        struct pollfd p = { .fd = g_fd, .events = POLLIN };
        int pr = poll(&p, 1, 10);
        now = shieldnet_os_now_ms();
        if (pr > 0 && (p.revents & POLLIN)) {
            uint8_t buf[2048];
            ssize_t n = recv(g_fd, buf, sizeof buf, 0);
            if (n > 0 && sn_client_input(&c, buf, (size_t)n, now) == SN_CLIENT_FAILED) break;
        }
        if (sn_client_tick(&c, now) == SN_CLIENT_FAILED) break;
        if (sn_client_get_state(&c) != SN_CLIENT_ESTABLISHED) continue; /* still admitting */

        int sent = SN_CS_OK;
        if (rx.got_info < 0 || rx.got_status < 0) { fprintf(stderr, "bad response\n"); break; }
        if (rx.got_info && !mode_sent) {
            /* 1. DEVICE_INFO arrived: print it and ask for PIXEL mode. */
            printf("device: %u strips x %u LEDs, %u bytes per LED, envelope %u\n",
                   (unsigned)rx.geo.strips, (unsigned)rx.geo.leds, (unsigned)rx.geo.bpp,
                   (unsigned)rx.geo.envelope);
            uint8_t pl[1];
            shieldnet_set_mode_req_t req = { .wire_mode = SLED_WIRE_MODE_PIXEL };
            size_t pl_len = shieldnet_encode_set_mode(&req, pl, sizeof pl);
            sent = sn_client_send_app_padded(&c, SLED_CMD_SET_MODE, pl, pl_len, now);
            mode_sent = sent == SN_CS_OK;
        } else if (rx.got_mode_ack && rx.mode_status != SLED_ACK_OK) {
            fprintf(stderr, "SET_MODE refused: status %u\n", rx.mode_status);
            break;
        } else if (rx.got_mode_ack && frames_sent < FRAMES && (int32_t)(now - next_frame) >= 0) {
            /* 2. PIXEL mode: send a frame every FRAME_MS. Every pixel is 4 bytes,
             * R,G,B,W, whatever the strip; fill the device unless it is larger
             * than one message can carry. */
            uint32_t pixels = rx.geo.strips * rx.geo.leds;
            uint32_t fit = (uint32_t)((sn_client_max_app_body(&c) - SHIELDNET_PIXEL_FRAME_HEADER_LEN) / 4);
            if (pixels > fit) pixels = fit;
            /* ...and the device's envelope: 44 of its bytes are message framing. */
            if (rx.geo.envelope < 48) { fprintf(stderr, "envelope too small\n"); break; }
            if (pixels > (rx.geo.envelope - 44) / 4) pixels = (rx.geo.envelope - 44) / 4;
            frame_len = SHIELDNET_PIXEL_FRAME_HEADER_LEN + shieldnet_pixel_frame_len(pixels);
            /* 28-byte header: frame number, not_before = not_after = 0 (show now). */
            shieldnet_encode_pixel_frame_header((uint64_t)frames_sent + 1, 0, 0,
                                                (uint32_t)shieldnet_pixel_frame_len(pixels), frame);
            for (uint32_t i = 0; i < pixels; i++) {
                uint8_t *px = &frame[SHIELDNET_PIXEL_FRAME_HEADER_LEN + 4 * i];
                px[0] = rgb[0]; px[1] = rgb[1]; px[2] = rgb[2]; px[3] = 0;
            }
            /* Pixel frames may be compressed, never padded (message layer 6.3). */
            sent = sn_client_send_app_compressed(&c, SLED_CMD_PIXEL_FRAME, frame, frame_len, now);
            if (sent == SN_CS_OK) {
                frames_sent++;
                next_frame = now + FRAME_MS;
            }
        } else if (frames_sent == FRAMES && !status_sent) {
            /* 3. Ask for STATUS. It is answered after the frames before it. */
            sent = sn_client_send_app_padded(&c, SLED_CMD_GET_STATUS, NULL, 0, now);
            status_sent = sent == SN_CS_OK;
        } else if (rx.got_status) {
            /* 4. Done. */
            printf("sent %d frames of #%02x%02x%02x (%u pixels each); device reports %llu frames, "
                   "%llu dropped, mode %u, brightness %u\n", frames_sent, rgb[0], rgb[1], rgb[2],
                   (unsigned)((frame_len - SHIELDNET_PIXEL_FRAME_HEADER_LEN) / 4),
                   (unsigned long long)rx.status.frame_count,
                   (unsigned long long)rx.status.pixel_frames_dropped,
                   (unsigned)rx.status.mode, (unsigned)rx.status.brightness);
            result = 0;
            break;
        }
        /* A full send queue is back-pressure: try again next turn. */
        if (sent != SN_CS_OK && sent != SN_CS_QUEUE_FULL) {
            fprintf(stderr, "send failed: %d\n", sent);
            break;
        }
    }
    if (result != 0)
        fprintf(stderr, "failed (state %d, end reason %d)\n", (int)sn_client_get_state(&c),
                (int)sn_client_get_end_reason(&c));
    sn_client_close(&c); /* end the session... */
    sn_client_free(&c);  /* ...and wipe every key the client holds */
    close(g_fd);
    return result;
}
