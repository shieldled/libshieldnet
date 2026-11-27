/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * led_device: a minimal ShieldNet LED device over UDP, with an in-memory
 * framebuffer instead of LEDs.
 *
 *   SHIELDNET_PSK_FILE=psk.hex led_device [-same-host] <ipv4> <port> <device-id-hex-16>
 *
 * Two threads share the work:
 *   main thread   receives datagrams and hands them to the transport
 *                 (admission, then the KCP session);
 *   agent thread  reads whole application messages from the session and lets
 *                 the command core answer them through our ops table.
 * A third, started by sn_device_start_tick, drives the transport's timers.
 */
#include "shieldnet/sn_agent_dispatch.h" /* sn_agent_*: the device's app layer */
#include "shieldnet/sn_demux.h"          /* sn_classify: which handler a datagram goes to */
#include "shieldnet/sn_device.h"         /* sn_device_*, sn_handle_*: admission + session */
#include "shieldnet/sn_kdf.h"            /* sn_provision_kdev: PSK -> k_dev */
#include "shieldnet_device.h"            /* shieldnet_device_ops_t: the command core's seam */
#include "shieldnet_os.h"                /* shieldnet_os_now_ms*: the library's clock */
#include "example_util.h"

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/socket.h>

#define STRIPS   4
#define LEDS     16
#define ENVELOPE 4096              /* the largest message we accept (DEVICE_INFO `envelope`) */
#define NET_BUF  (ENVELOPE + 64)   /* each agent buffer: one message plus framing */
_Static_assert(28 + 16 + STRIPS * LEDS * 4 <= ENVELOPE, "a full frame must fit the envelope");

/* The "hardware": a framebuffer and the state STATUS reports. Every op runs on
 * the agent thread, so nothing here needs a lock. A device whose ops touch
 * state shared with other threads locks inside each op (shieldnet_device.h). */
static struct {
    uint8_t  rgb[STRIPS * LEDS][3];
    uint8_t  brightness, fps, mode;
    bool     output_enabled;
    uint64_t frames, commands, dropped;
} fb = { .brightness = 255, .fps = 25, .mode = 1, .output_enabled = true };

static int g_fd;                       /* the UDP socket */
static sn_device g_dev;                /* transport state: admission + the one session */
static sn_agent g_agent;               /* app layer, bound to the current session */
static atomic_int g_want_bind;         /* set by main when a new session is promoted */
static atomic_int g_bound;             /* the agent is serving a session */
static atomic_int g_stop;              /* SIGINT / SIGTERM (lock-free: safe in a handler) */
static uint8_t g_raw[NET_BUF], g_dec[NET_BUF], g_decomp[NET_BUF], g_enc[NET_BUF];
static uint8_t g_scratch[SLED_DEVICE_INFO_MAX_BYTES];

/* ---- shieldnet_device_ops_t: what the command core calls ---------------- */

static void op_get_geometry(void *ctx, shieldnet_device_geometry_t *out) {
    (void)ctx;
    out->num_strips = STRIPS;
    out->leds_per_strip = LEDS;
    out->led_bpp = 3; /* an RGB strip; frames still arrive at 4 bytes a pixel */
    out->max_payload = ENVELOPE;
}
static void op_set_brightness(void *ctx, uint8_t v) { (void)ctx; fb.brightness = v; }
static void op_set_fps(void *ctx, uint8_t v) { (void)ctx; fb.fps = v; }
/* The core only passes modes we have: PIXEL (1) is our only one. */
static int op_set_mode(void *ctx, uint8_t m) { (void)ctx; fb.mode = m; return 0; }
static int op_set_output(void *ctx, bool on) { (void)ctx; fb.output_enabled = on; return 0; }
static void op_note_dropped(void *ctx) { (void)ctx; fb.dropped++; }
/* Every message but PIXEL_FRAME, for STATUS's `commands`. */
static void op_note_command(void *ctx) { (void)ctx; fb.commands++; }

/* PIXEL_FRAME, already validated: num_pixels pixels of R,G,B,W. An RGB strip
 * drops W. This device does not advertise `pts`, so a controller sends both
 * timestamps as 0 and the frame is shown on arrival; the frame number is the
 * controller's, for logging. */
static bool op_publish(void *ctx, const uint8_t *px, int num_pixels,
                       int64_t frame_number, int64_t not_before_ns, int64_t not_after_ns) {
    (void)ctx; (void)not_before_ns; (void)not_after_ns;
    for (int i = 0; i < num_pixels; i++) memcpy(fb.rgb[i], &px[4 * i], 3);
    fb.frames++;
    printf("frame %lld: %d pixels, first #%02x%02x%02x\n", (long long)frame_number,
           num_pixels, fb.rgb[0][0], fb.rgb[0][1], fb.rgb[0][2]);
    return true;
}

static void op_get_status(void *ctx, shieldnet_device_status_t *out) {
    (void)ctx;
    memset(out, 0, sizeof *out);
    out->frame_count = fb.frames;
    out->command_count = fb.commands;
    out->pixel_frames_dropped = fb.dropped;
    out->mode = fb.mode;
    out->connected = atomic_load(&g_bound) != 0;
    out->output_enabled = fb.output_enabled;
    out->brightness = fb.brightness;
    out->target_fps = fb.fps;
}

static void op_get_tx_scratch(void *ctx, uint8_t **buf, size_t *cap) {
    (void)ctx;
    *buf = g_scratch;
    *cap = sizeof g_scratch;
}
static void op_emit_event(void *ctx, shieldnet_device_event_t ev, uint8_t arg) {
    (void)ctx; (void)arg;
    fprintf(stderr, "event %d\n", (int)ev); /* 2 = malformed frame, 3 = unknown command */
}
/* Every response goes out sealed through the agent. */
static int op_send_response(void *ctx, uint8_t kind, const uint8_t *body, size_t len) {
    (void)ctx;
    return sn_agent_respond(&g_agent, shieldnet_os_now_ms(), kind, body, len);
}

static const shieldnet_device_ops_t g_ops = {
    .get_geometry = op_get_geometry,       .set_brightness = op_set_brightness,
    .set_fps = op_set_fps,                 .set_mode = op_set_mode,
    .set_output_enabled = op_set_output,   .publish_pixel_frame_at = op_publish,
    .note_frame_dropped = op_note_dropped, .note_command = op_note_command,
    .get_status = op_get_status,
    .get_tx_scratch = op_get_tx_scratch,   .emit_event = op_emit_event,
    .send_response = op_send_response,
};

/* ---- the agent thread (sn_agent_dispatch.h) ----------------------------- */

static void *agent_main(void *arg) {
    (void)arg;
    while (!g_stop) {
        /* Bind to each newly promoted session, here and only here, so binding
         * and stepping stay on one thread. */
        if (atomic_exchange(&g_want_bind, 0)) {
            if (atomic_load(&g_bound)) sn_agent_end(&g_agent);
            int ok = sn_agent_init(&g_agent, &g_dev, &g_ops, g_raw, sizeof g_raw, g_dec,
                                   sizeof g_dec, g_decomp, sizeof g_decomp, g_enc, sizeof g_enc) == 0;
            atomic_store(&g_bound, ok);
            if (ok) printf("session started\n");
        }
        if (!atomic_load(&g_bound)) { shieldnet_os_sleep_ms(5); continue; }
        /* Read one message and dispatch it (waits up to 100 ms). */
        int r = sn_agent_step(&g_agent, shieldnet_os_now_ms(), 100);
        if (r < 0 && r != SN_AGENT_REFUSED) { /* the stream is lost: end it */
            sn_agent_end(&g_agent);
            atomic_store(&g_bound, 0);
            printf("session ended\n");
        }
    }
    if (atomic_load(&g_bound)) sn_agent_end(&g_agent);
    return NULL;
}

/* The session's output sink: send to the address the session was admitted from. */
static void send_to(void *ctx, const uint8_t *buf, size_t len, const uint8_t dst[18]) {
    (void)ctx;
    struct sockaddr_in to = { .sin_family = AF_INET };
    memcpy(&to.sin_addr.s_addr, dst + 12, 4);
    to.sin_port = htons((uint16_t)((dst[16] << 8) | dst[17]));
    if (sendto(g_fd, buf, len, 0, (struct sockaddr *)&to, sizeof to) < 0) perror("sendto");
}

static void on_signal(int sig) { (void)sig; atomic_store(&g_stop, 1); }

int main(int argc, char **argv) {
    int same_host = argc > 1 && strcmp(argv[1], "-same-host") == 0;
    argv += same_host; argc -= same_host;
    struct sockaddr_in addr = { .sin_family = AF_INET };
    uint8_t device_id[8], psk[32], k_dev[32];
    uint16_t port;
    if (argc != 4 || inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1 ||
        ex_parse_port(argv[2], 0, &port) != 0 || ex_unhex(argv[3], device_id, 8) != 0) {
        fprintf(stderr, "usage: SHIELDNET_PSK_FILE=<file> led_device [-same-host] "
                        "<ipv4> <port> <device-id-hex-16>\n");
        return 2;
    }
    addr.sin_port = htons(port);
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* k_dev, never the PSK (transport 3.2). A real device is provisioned once
     * and stores only k_dev; sn_provision_kdev wipes psk whatever it returns. */
    if (ex_load_psk(psk) != 0) return 2;
    if (sn_provision_kdev(psk, device_id, k_dev) != 0) { fprintf(stderr, "k_dev\n"); return 1; }

    /* Start-up secrets from the CSPRNG, fresh at every start, never stored
     * (transport 3.4, 3.5). The epoch's top 8 bits must be clear. */
    uint8_t cookie_secret[32], epoch[8];
    randombytes_buf(cookie_secret, sizeof cookie_secret);
    do { randombytes_buf(epoch, sizeof epoch); epoch[0] = 0; } while (sodium_is_zero(epoch, 8));

    /* This host's addresses, for transport 7.2's own-address checks. The
     * table must outlive the device. An empty one silently skips the checks. */
    static sn_prefix local[32];
    int n_local = ex_local_prefixes(local, 32);
    if (n_local <= 0) { fprintf(stderr, "no local IPv4 prefixes\n"); return 1; }

    int rc = sn_device_init_kdev(&g_dev, k_dev, device_id, cookie_secret, epoch, local,
                                 (size_t)n_local, shieldnet_os_now_ms64());
    sodium_memzero(k_dev, sizeof k_dev);             /* the device keeps its own copy */
    sodium_memzero(cookie_secret, sizeof cookie_secret);
    if (rc != 0) { fprintf(stderr, "sn_device_init_kdev failed\n"); return 1; }
    sn_device_locks_init(&g_dev);
    /* DEVELOPMENT ONLY: transport 7.2 drops datagrams from loopback and from
     * this host's own addresses, so a client on the same machine is never
     * admitted. -same-host turns that check off. Never ship it. */
    if (same_host) {
        sn_device_set_source_check(&g_dev, 0);
        fprintf(stderr, "warning: -same-host: source checks are OFF (development only)\n");
    }
    sn_device_set_send_to(&g_dev, send_to, NULL);

    /* One socket, bound to one address (not 0.0.0.0). A 200 ms receive timeout
     * lets the loop notice a stop request. */
    struct timeval tv = { 0, 200000 };
    socklen_t alen = sizeof addr;
    g_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (g_fd < 0 || setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0 ||
        bind(g_fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        getsockname(g_fd, (struct sockaddr *)&addr, &alen) != 0) {
        perror("socket");
        return 1;
    }
    printf("listening on %s:%u\n", argv[1], ntohs(addr.sin_port));

    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    pthread_t agent;
    if (sn_device_start_tick(&g_dev, 15) != 0 ||                  /* transport timers */
        pthread_create(&agent, NULL, agent_main, NULL) != 0) {
        fprintf(stderr, "cannot start threads\n");
        return 1;
    }

    /* The receive loop: classify each datagram, hand it to its handler. */
    while (!g_stop) {
        uint8_t buf[2048], a16[16];
        struct sockaddr_in from;
        socklen_t flen = sizeof from;
        ssize_t n = recvfrom(g_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
        if (n <= 0 || from.sin_family != AF_INET) continue; /* timeout, signal or error */
        ex_a16(&from.sin_addr, a16);
        uint16_t sport = ntohs(from.sin_port);
        uint64_t now = shieldnet_os_now_ms64();
        /* sn_classify drops what transport 7.2 rejects; -same-host skips that. */
        sn_class cls = same_host ? sn_classify_datagram(SN_ROLE_DEVICE, buf, (size_t)n)
                                 : sn_classify(SN_ROLE_DEVICE, 1, a16, local, (size_t)n_local,
                                               buf, (size_t)n);
        if (cls == SN_CLASS_INIT) {          /* INIT -> RETRY, stateless */
            uint8_t out[SN_RETRY_LEN];
            if (sn_handle_init(&g_dev, buf, (size_t)n, a16, sport, now, out) == SN_RETRY_LEN)
                sendto(g_fd, out, sizeof out, 0, (struct sockaddr *)&from, flen);
        } else if (cls == SN_CLASS_FINISH) { /* FINISH -> ADMIT */
            uint8_t out[SN_ADMIT_LEN];
            if (sn_handle_finish(&g_dev, buf, (size_t)n, a16, sport, now, out) == SN_ADMIT_LEN)
                sendto(g_fd, out, sizeof out, 0, (struct sockaddr *)&from, flen);
        } else if (cls == SN_CLASS_ENVELOPE) {
            /* Session traffic. PROMOTED: a client just took control; the
             * agent thread binds to the new session. */
            if (sn_handle_envelope(&g_dev, buf, (size_t)n, a16, sport, now) == SN_ENV_PROMOTED)
                atomic_store(&g_want_bind, 1);
        }
    }

    /* Teardown, in this order: timers, the session (which wakes a waiting
     * agent), the agent thread, then every key the device holds. */
    printf("stopping\n");
    sn_device_stop_tick();
    sn_device_end_primary(&g_dev, sn_device_current_gen(&g_dev));
    pthread_join(agent, NULL);
    sn_device_release_primary(&g_dev);
    sn_device_wipe(&g_dev);
    sn_device_locks_free(&g_dev);
    close(g_fd);
    return 0;
}
