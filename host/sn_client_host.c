/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * host client — the C client over real UDP, for mirror-direction interop
 * (C client against a Go server) and as a desktop blocking wrapper around
 * the threadless client. One binary, because they are the same program: a socket, poll(),
 * a tick on timeout, and a wait over SN_CLIENT_IN_PROGRESS.
 *
 * This is what "a consumer that wants Go's blocking shape wraps this" means in
 * practice. The library owns no thread and no socket; everything below is the
 * caller's half, and it is ~100 lines.
 *
 * argv: sn_client_host <host> <port> <device-id-hex-16> [message]
 * The PSK is never taken from argv (ps and /proc/<pid>/cmdline show a command
 * line to every local user): SHIELDNET_PSK_FILE names a file holding its 64 hex
 * chars (trailing whitespace allowed), else SHIELDNET_PSK holds the hex itself.
 * conv is drawn fresh per commit by the library (§8.4); SHIELDNET_CONV=<1..2^32-1>
 * pins it for a harness that needs a deterministic one.
 * SHIELDNET_COMPRESS=1: the message is not the promoting one. The session opens
 * with a PING and, once admitted, the message goes out through
 * sn_client_send_app_compressed (kind 0x00), so a peer can see §13's compression
 * flag on a frame this client sealed.
 * Prints "ADMITTED" once established, then echoes any application message it
 * receives as "RECV <kind> <len>", one per line, until stdin closes.
 */
#include "shieldnet/sn_client.h"
#include "shieldnet/sn_source.h"
#include "shieldnet_os.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fd;
static struct sockaddr_in g_peer;

/* The client's send sink: one sealed datagram to the device. */
static void host_send(void *ctx, const uint8_t *dg, size_t len) {
    (void)ctx;
    sendto(g_fd, dg, len, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
}

static void on_app(void *ctx, uint32_t message_type, const uint8_t *body, size_t len) {
    (void)ctx; (void)body;
    printf("RECV %u %zu\n", (unsigned)(message_type & 0xffu), len);   /* the sled kind */
    fflush(stdout);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly 2*want hex digits, nothing else (no sign, no whitespace, no 0x). */
static int unhex(const char *hex, uint8_t *out, size_t want) {
    if (strlen(hex) != want * 2) return -1;
    for (size_t i = 0; i < want; i++) {
        int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* Strict decimal: the whole string, no sign games, within [lo, hi]. */
static int parse_ulong(const char *s, unsigned long lo, unsigned long hi, unsigned long *out) {
    char *end;
    if (s == NULL || *s < '0' || *s > '9') return -1;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* The 32-byte PSK from SHIELDNET_PSK_FILE (64 hex chars, trailing whitespace
 * allowed) or else SHIELDNET_PSK. Read with read(2), not stdio, so no FILE
 * buffer keeps a copy; the local buffer is wiped on every path. */
static int load_psk(uint8_t psk[32]) {
    char buf[130];
    size_t n = 0;
    int rc = -1;
    const char *path = getenv("SHIELDNET_PSK_FILE");
    if (path != NULL && *path != '\0') {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { perror(path); return -1; }
        struct stat sb;
        if (fstat(fd, &sb) == 0 && (sb.st_mode & 077))
            fprintf(stderr, "warning: %s is accessible to group/other\n", path);
        for (;;) {
            ssize_t r = read(fd, buf + n, sizeof buf - 1 - n);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { if (r < 0) n = sizeof buf; break; } /* read error: reject */
            n += (size_t)r;
            if (n == sizeof buf - 1) break; /* too long for 64 hex + whitespace */
        }
        close(fd);
        while (n > 0 && n < sizeof buf - 1 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                                               buf[n - 1] == ' ' || buf[n - 1] == '\t'))
            n--;
        if (n == 64 && memchr(buf, '\0', n) == NULL) {
            buf[n] = '\0';
            rc = unhex(buf, psk, 32);
        }
    } else {
        const char *v = getenv("SHIELDNET_PSK");
        if (v == NULL || *v == '\0') {
            fprintf(stderr, "no PSK: set SHIELDNET_PSK_FILE (or SHIELDNET_PSK)\n");
            return -1;
        }
        rc = unhex(v, psk, 32);
    }
    sodium_memzero(buf, sizeof buf);
    if (rc != 0) {
        sodium_memzero(psk, 32);
        fprintf(stderr, "bad psk: want exactly 64 hex chars\n");
    }
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "usage: SHIELDNET_PSK_FILE=<file> %s <host> <port> <device-id-hex-16> [message]\n",
                argv[0]);
        return 2;
    }
    /* The old argv shape put the PSK third. Refuse it loudly rather than read it
     * as a (malformed) device id: it is already exposed, and should be rotated. */
    if (strlen(argv[3]) == 64) {
        fprintf(stderr, "a PSK on the command line is no longer accepted; use SHIELDNET_PSK_FILE\n");
        return 2;
    }
    if (sodium_init() < 0) { fprintf(stderr, "sodium\n"); return 1; }

    sn_client_config cfg;
    memset(&cfg, 0, sizeof cfg);
    if (unhex(argv[3], cfg.device_id, 8) != 0) {
        fprintf(stderr, "bad device id: want exactly 16 hex chars\n");
        return 2;
    }
    /* §8.4: leave conv 0 so the library draws a fresh one per commit; a fixed
     * value collides with the device's stale primary on re-admission. */
    const char *conv_env = getenv("SHIELDNET_CONV");
    if (conv_env != NULL && *conv_env != '\0') {
        unsigned long conv;
        if (parse_ulong(conv_env, 1, 0xFFFFFFFFul, &conv) != 0) {
            fprintf(stderr, "bad SHIELDNET_CONV: want 1..4294967295\n");
            return 2;
        }
        cfg.conv = (uint32_t)conv;
    }

    memset(&g_peer, 0, sizeof g_peer);
    g_peer.sin_family = AF_INET;
    unsigned long port;
    if (parse_ulong(argv[2], 1, 65535, &port) != 0) { fprintf(stderr, "bad port: want 1..65535\n"); return 2; }
    g_peer.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, argv[1], &g_peer.sin_addr) != 1) {
        fprintf(stderr, "bad host\n"); return 2;
    }
    g_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_fd < 0) { perror("socket"); return 1; }
    /* §7.2 wants the client's own canonical_source as an INPUT, and connect()
     * is how a caller learns it without the library ever opening a socket.
     * That is the whole reason this lives out here. */
    if (connect(g_fd, (struct sockaddr *)&g_peer, sizeof g_peer) != 0) {
        perror("connect"); return 1;
    }
    struct sockaddr_in me;
    socklen_t melen = sizeof me;
    if (getsockname(g_fd, (struct sockaddr *)&me, &melen) != 0) {
        perror("getsockname"); return 1;
    }
    uint8_t a16[16];
    memset(a16, 0, 16); a16[10] = 0xff; a16[11] = 0xff;
    memcpy(a16 + 12, &me.sin_addr.s_addr, 4);
    sn_canonical_source(a16, ntohs(me.sin_port), cfg.own_source);

    /* The PSK is loaded last, so no exit path above holds it; sn_client_init
     * keeps its own copy, and ours is wiped whether or not init succeeds. */
    if (load_psk(cfg.psk) != 0) return 2;
    sn_client c;
    int irc = sn_client_init(&c, &cfg);
    sodium_memzero(&cfg, sizeof cfg);
    if (irc != SN_CLIENT_OK) { fprintf(stderr, "init\n"); return 1; }
    sn_client_set_send(&c, host_send, NULL);

    static uint8_t carry[8192], raw[4096], dec[4096], decomp[4096], enc[4096];
    static uint8_t comp[SN_CLIENT_COMPRESS_BUF_MIN];
    sn_client_set_app_buffers(&c, carry, sizeof carry, raw, sizeof raw,
                              dec, sizeof dec, decomp, sizeof decomp, enc, sizeof enc);
    sn_client_set_compress_buffer(&c, comp, sizeof comp);
    sn_client_set_on_app(&c, on_app, NULL);

    const char *msg = (argc > 4) ? argv[4] : "";
    const char *cz = getenv("SHIELDNET_COMPRESS");
    int compress_msg = cz != NULL && cz[0] == '1' && msg[0];
    uint32_t now = (uint32_t)shieldnet_os_now_ms();
    /* PING (0x07) opens the session when no message was given. */
    int rc = (msg[0] && !compress_msg)
               ? sn_client_take_control_app(&c, 0x00, (const uint8_t *)msg, strlen(msg), now)
               : sn_client_take_control_app(&c, 0x07, NULL, 0, now);
    if (rc != SN_CLIENT_IN_PROGRESS) {
        fprintf(stderr, "take_control %d\n", rc);
        sn_client_free(&c);
        return 1;
    }

    /* The pump the caller owns. poll() with a timeout is the whole event loop:
     * readable -> input, timeout -> tick. Nothing else drives the client. */
    int admitted = 0, stdin_open = 1;
    for (;;) {
        struct pollfd p[2];
        p[0].fd = g_fd;  p[0].events = POLLIN; p[0].revents = 0;
        p[1].fd = 0;     p[1].events = POLLIN; p[1].revents = 0;
        int pr = poll(p, stdin_open ? 2 : 1, 50);
        now = (uint32_t)shieldnet_os_now_ms();
        if (pr > 0 && (p[0].revents & POLLIN)) {
            uint8_t buf[2048];
            ssize_t n = recv(g_fd, buf, sizeof buf, 0);
            if (n > 0) sn_client_input(&c, buf, (size_t)n, now);
        }
        /* stdin is the harness's "you may stop" channel. It must be polled, not
         * feof()'d: feof only reports EOF after a read has already hit it, so a
         * loop that never reads never notices and runs until it is killed. */
        if (stdin_open && pr > 0 && p[1].revents) {
            /* POLLNVAL matters as much as POLLIN here: a harness that runs this
             * with stdin closed (0<&-) gets neither readable nor hangup, and a
             * loop watching only those two never notices and never exits --
             * a hang in CI, which is worse to diagnose than a failure. */
            if (p[1].revents & (POLLERR | POLLNVAL)) {
                stdin_open = 0;
            } else {
                char line[256];
                ssize_t n = read(0, line, sizeof line);
                if (n <= 0) stdin_open = 0;
            }
        }
        int st = sn_client_tick(&c, now);
        if (!admitted && sn_client_get_state(&c) == SN_CLIENT_ESTABLISHED) {
            admitted = 1;
            printf("ADMITTED\n");
            fflush(stdout);
            if (compress_msg &&
                sn_client_send_app_compressed(&c, 0x00, (const uint8_t *)msg, strlen(msg),
                                              now) != SN_CLIENT_OK) {
                fprintf(stderr, "send_app_compressed failed\n");
                sn_client_free(&c);
                return 1;
            }
        }
        if (st == SN_CLIENT_FAILED) {
            fprintf(stderr, "attempt failed\n");
            sn_client_free(&c);
            return 1;
        }
        if (admitted && !stdin_open) break;
    }
    sn_client_free(&c);
    close(g_fd);
    return 0;
}
