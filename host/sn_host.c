/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * host device — a runnable responder over real UDP, for cross-language
 * C<->Go interop. Links only the library. It admits a client
 * (§6), promotes the first PUSH (§8.5), and echoes every received application
 * message back over the established session. Loopback 127.0.0.1 is on §4.3's
 * rejection list, so it demuxes with sn_classify_datagram (the source predicate is
 * unit-tested separately); a real deployment uses sn_classify.
 *
 * argv: sn_host <port> <device-id-hex-16>
 * The PSK is never taken from argv (ps and /proc/<pid>/cmdline show a command
 * line to every local user): SHIELDNET_PSK_FILE names a file holding its 64 hex
 * chars (trailing whitespace allowed), else SHIELDNET_PSK holds the hex itself.
 * <port> is 0 (ephemeral) or 1..65535.
 * On startup it prints "PORT <n>" so the harness can learn the bound port.
 */
#include "shieldnet/sn_demux.h"
#include "shieldnet/sn_device.h"
#include "shieldnet/sn_kdf.h"
#include "shieldnet/sn_agent.h"
#include "shieldnet/sn_source.h"
#include "shieldnet/protocol.h"
#include "shieldnet/decompress.h"
#include "shieldnet/crypto.h"
#include "shieldnet_os.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static struct {
    int fd;
} g;

/* the device send sink: transmit a fully-sealed datagram to the primary's
 * canonical_source (v4-mapped a16 || port_be), never to "whoever sent last" */
static void host_send(void *ctx, const uint8_t *buf, size_t len, const uint8_t dst[18]) {
    (void)ctx;
    struct sockaddr_in to;
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    memcpy(&to.sin_addr.s_addr, dst + 12, 4);
    to.sin_port = htons((uint16_t)((dst[16] << 8) | dst[17]));
    sendto(g.fd, buf, len, 0, (struct sockaddr *)&to, sizeof(to));
}

/* app-echo agent (SHIELDNET_APP_ECHO=1): runs the real post-admission app
 * message layer over the transport — protocol_read_message + crypto_decrypt(k_c2s), echo via
 * crypto_encrypt(k_s2c) + protocol_write_message. Proves the app layer over the transport. */
static sn_device *g_dev_for_agent;
static shieldnet_signal_t *g_agent_go; /* posted when the primary is established */

static void app_echo_agent(void *arg) {
    (void)arg;
    shieldnet_signal_wait(g_agent_go, SHIELDNET_OS_WAIT_FOREVER); /* wait for promotion */
    sn_device *d = g_dev_for_agent;
    uint8_t k_c2s[32], k_s2c[32];

    sn_agent_io st; memset(&st, 0, sizeof(st));
    shieldnet_io_t io = sn_primary_io(&st, d);
    /* The keys and the generation the io serves come from one locked read: an
     * unlocked copy of the primary's keys can be torn or wiped by a promotion. */
    if (sn_primary_bind_app(d, &st.gen, k_c2s, k_s2c) != 0) return;
    uint64_t tx = 0;
    uint8_t raw[2048], plain[8192], enc[8192], decomp[8192];
    for (;;) {
        protocol_msg_header_t hdr;
        sn_agent_set_now(&st, shieldnet_os_now_ms());
        int n = protocol_read_message(&io, &hdr, raw, sizeof(raw), 1000);
        if (n == 0) continue;        /* idle */
        if (n < 0) break;            /* io error / desync */
        /* decrypt client->server under k_c2s, nonce from message_num */
        uint8_t aad[PROTOCOL_HEADER_SIZE];
        protocol_marshal_aad(hdr.size, hdr.original_size, hdr.message_type, hdr.message_num, aad);
        uint8_t nonce[CRYPTO_NONCE_SIZE];
        protocol_nonce_from_msgnum(hdr.message_num, nonce);
        size_t plen = 0;
        if (crypto_decrypt(k_c2s, nonce, raw, hdr.size, aad, sizeof(aad), plain, &plen) != 0) continue;
        /* A compressed message (transport §13's bulk-content carve-out) must be
         * decompressed against original_size before it means anything, exactly as
         * the real dispatch path does (sn_agent_dispatch.c). Echoing the block back
         * with the flag still set would claim a decompressed length it does not
         * have. The echo therefore returns the *content*, uncompressed. */
        uint32_t out_type = hdr.message_type;
        if (hdr.message_type & PROTOCOL_FLAG_COMPRESSED) {
            if (hdr.original_size > sizeof(decomp)) continue;
            size_t d = 0;
            if (decompress_lz4(plain, plen, decomp, hdr.original_size, &d) < 0) continue;
            memcpy(plain, decomp, d);
            plen = d;
            out_type &= ~PROTOCOL_FLAG_COMPRESSED;
        } else if (plen != hdr.original_size) {
            /* §13 padding: strip back to the true length (sn_agent_dispatch.c). */
            size_t cls = SN_PAD_FLOOR;
            while (cls < hdr.original_size) cls <<= 1;
            if (plen != cls) continue; /* §7: header and body disagree */
            plen = hdr.original_size;
        }
        /* echo: encrypt plaintext under k_s2c with a fresh tx message_num. The
         * MessageNum is the nonce under k_s2c and belongs to the primary, not to
         * this loop, so take it from the primary's counter. */
        if (sn_primary_next_s2c_msgnum(d, st.gen, &tx) != 0) break;
        uint32_t enc_size = (uint32_t)plen + 16; /* + Poly1305 tag */
        uint8_t aad2[PROTOCOL_HEADER_SIZE];
        protocol_marshal_aad(enc_size, (uint32_t)plen, out_type, tx, aad2);
        uint8_t nonce2[CRYPTO_NONCE_SIZE];
        protocol_nonce_from_msgnum(tx, nonce2);
        size_t elen = 0;
        if (crypto_encrypt(k_s2c, nonce2, plain, plen, aad2, sizeof(aad2), enc, &elen) != 0) continue;
        sn_agent_set_now(&st, shieldnet_os_now_ms());
        protocol_write_message(&io, out_type, tx, enc, (uint32_t)elen, (uint32_t)plen);
    }
    sodium_memzero(k_c2s, sizeof k_c2s);
    sodium_memzero(k_s2c, sizeof k_s2c);
}

/* Strict decimal: the whole string, no sign games, within [lo, hi]. */
static int parse_long(const char *s, long lo, long hi, long *out) {
    char *end;
    if (s == NULL || *s < '0' || *s > '9') return -1;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* Read an integer from the environment, or return def if unset/blank. This is the
 * host board's config source (an ESP board would use Kconfig/sdkconfig). A value
 * that is not a plain decimal in [lo, hi] is refused with a warning, not passed
 * on: a negative window or interval becomes a huge unsigned inside KCP. */
static int env_int(const char *name, int def, long lo, long hi) {
    const char *v = getenv(name);
    long r;
    if (v == NULL || *v == '\0') return def;
    if (parse_long(v, lo, hi, &r) != 0) {
        fprintf(stderr, "warning: %s=%s is not in %ld..%ld; using %d\n", name, v, lo, hi, def);
        return def;
    }
    return (int)r;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex2bin(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
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
            ssize_t r = read(fd, buf + n, sizeof(buf) - 1 - n);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { if (r < 0) n = sizeof(buf); break; } /* read error: reject */
            n += (size_t)r;
            if (n == sizeof(buf) - 1) break; /* too long for 64 hex + whitespace */
        }
        close(fd);
        while (n > 0 && n < sizeof(buf) - 1 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                                                buf[n - 1] == ' ' || buf[n - 1] == '\t'))
            n--;
        if (n == 64 && memchr(buf, '\0', n) == NULL) {
            buf[n] = '\0';
            rc = hex2bin(buf, psk, 32);
        }
    } else {
        const char *v = getenv("SHIELDNET_PSK");
        if (v == NULL || *v == '\0') {
            fprintf(stderr, "no PSK: set SHIELDNET_PSK_FILE (or SHIELDNET_PSK)\n");
            return -1;
        }
        rc = hex2bin(v, psk, 32);
    }
    sodium_memzero(buf, sizeof(buf));
    if (rc != 0) {
        sodium_memzero(psk, 32);
        fprintf(stderr, "bad psk: want exactly 64 hex chars\n");
    }
    return rc;
}

/* 127.0.0.1:port -> the 16-octet v4-mapped form + port */
static void src_a16(const struct sockaddr_in *sa, uint8_t a16[16], uint16_t *port) {
    memset(a16, 0, 16);
    a16[10] = 0xff; a16[11] = 0xff;
    memcpy(a16 + 12, &sa->sin_addr.s_addr, 4); /* already network order = big-endian */
    *port = ntohs(sa->sin_port);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        if (argc == 4)
            fprintf(stderr, "a PSK on the command line is no longer accepted; "
                            "use SHIELDNET_PSK_FILE\n");
        fprintf(stderr, "usage: SHIELDNET_PSK_FILE=<file> %s <port> <device-id-hex-16>\n", argv[0]);
        return 2;
    }
    if (sodium_init() < 0) return 1;
    long want_port;
    if (parse_long(argv[1], 0, 65535, &want_port) != 0) {
        fprintf(stderr, "bad port: want 0..65535\n");
        return 2;
    }
    uint8_t psk[32], device_id[8];
    if (hex2bin(argv[2], device_id, 8)) {
        fprintf(stderr, "bad device id: want exactly 16 hex chars\n");
        return 2;
    }
    if (load_psk(psk) != 0) return 2;
    /* Turn the PSK into k_dev at once; sn_provision_kdev wipes psk either way. */
    uint8_t k_dev[32];
    if (sn_provision_kdev(psk, device_id, k_dev) != 0) {
        fprintf(stderr, "k_dev derivation failed\n");
        return 1;
    }

    uint8_t cookie_secret[32], admission_epoch[8];
    randombytes_buf(cookie_secret, 32);
    randombytes_buf(admission_epoch, 8);
    admission_epoch[0] = 0; /* §4.2: top 8 bits clear */

    sn_prefix local[1];
    memset(local, 0, sizeof(local));
    local[0].a16[10] = 0xff; local[0].a16[11] = 0xff;
    local[0].a16[12] = 127; local[0].a16[15] = 1;
    local[0].is_v4 = 1; local[0].bits = 8;

    sn_device dev;
    if (sn_device_init_kdev(&dev, k_dev, device_id, cookie_secret, admission_epoch, local, 1,
                            shieldnet_os_now_ms64()) != 0) {
        sodium_memzero(k_dev, sizeof(k_dev));
        sodium_memzero(cookie_secret, sizeof(cookie_secret));
        fprintf(stderr, "device init failed\n");
        return 1;
    }
    /* sn_device_init_kdev copied k_dev and the secret; drop ours. */
    sodium_memzero(k_dev, sizeof(k_dev));
    sodium_memzero(cookie_secret, sizeof(cookie_secret));
    sn_device_locks_init(&dev);
    /* This harness binds 127.0.0.1 only (below), and §4.3 rejects a loopback
     * source -- which the handlers now enforce themselves, not just
     * sn_classify. Every peer it can ever see is loopback, so the check could
     * only refuse them all; a board on a real interface keeps it on. */
    sn_device_set_source_check(&dev, 0);
    sn_device_set_send_to(&dev, host_send, NULL);

    /* Board config → KCP tuning (§8.4/§11, goshieldnet docs/tuning.md). The board owns these; the
     * library only supplies SN_KCP_TUNING_DEFAULT. This host board reads them from
     * the environment; an ESP board would read Kconfig/sdkconfig and call the same
     * sn_device_set_tuning. rcv_wnd is the per-session buffer ceiling. */
    sn_kcp_tuning t = SN_KCP_TUNING_DEFAULT;
    t.snd_wnd  = env_int("SHIELDNET_SND_WND", t.snd_wnd, 1, 4096);
    t.rcv_wnd  = env_int("SHIELDNET_RCV_WND", t.rcv_wnd, 1, 4096);
    t.interval = env_int("SHIELDNET_KCP_INTERVAL", t.interval, 1, 5000);
    sn_device_set_tuning(&dev, t);
    uint32_t tick_ms = (uint32_t)env_int("SHIELDNET_TICK_MS", 15, 1, 1000);
    fprintf(stderr, "tuning: snd_wnd=%d rcv_wnd=%d interval=%d tick=%u\n",
            t.snd_wnd, t.rcv_wnd, t.interval, tick_ms);

    g.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g.fd < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)want_port);
    if (bind(g.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    socklen_t al = sizeof(addr);
    if (getsockname(g.fd, (struct sockaddr *)&addr, &al) != 0) {
        perror("getsockname");
        return 1;
    }
    printf("PORT %d\n", ntohs(addr.sin_port));
    fflush(stdout);

    int app_echo = env_int("SHIELDNET_APP_ECHO", 0, 0, 1);
    shieldnet_thread_t *agent = NULL;
    if (app_echo) {
        g_dev_for_agent = &dev;
        g_agent_go = shieldnet_signal_create();
        if (g_agent_go == NULL ||
            !shieldnet_thread_create(app_echo_agent, "appecho", 16384, NULL, 5, -1, &agent)) {
            fprintf(stderr, "app-echo agent\n");
            return 1;
        }
    }

    if (sn_device_start_tick(&dev, tick_ms) != 0) {
        fprintf(stderr, "tick\n");
        return 1;
    }

    uint8_t buf[2048];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(g.fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) continue;
        uint8_t a16[16]; uint16_t port;
        src_a16(&from, a16, &port);

        switch (sn_classify_datagram(SN_ROLE_DEVICE, buf, (size_t)n)) {
        case SN_CLASS_INIT: {
            uint8_t retry[SN_RETRY_LEN];
            if (sn_handle_init(&dev, buf, (size_t)n, a16, port, shieldnet_os_now_ms64(), retry) == SN_RETRY_LEN) {
                sendto(g.fd, retry, SN_RETRY_LEN, 0, (struct sockaddr *)&from, fl);
            }
            break;
        }
        case SN_CLASS_FINISH: {
            uint8_t admit[SN_ADMIT_LEN];
            uint64_t now = shieldnet_os_now_ms64();
            if (sn_handle_finish(&dev, buf, (size_t)n, a16, port, now, admit) == SN_ADMIT_LEN) {
                sendto(g.fd, admit, SN_ADMIT_LEN, 0, (struct sockaddr *)&from, fl);
            }
            break;
        }
        case SN_CLASS_ENVELOPE: {
            uint64_t now = shieldnet_os_now_ms64();
            sn_env_result r = sn_handle_envelope(&dev, buf, (size_t)n, a16, port, now);
            if (app_echo) {
                /* the app-echo agent thread drains + dispatches; wake it on promotion */
                if (r == SN_ENV_PROMOTED) {
                    shieldnet_signal_post(g_agent_go);
                }
            } else if (r == SN_ENV_ESTABLISHED || r == SN_ENV_PROMOTED) {
                /* raw echo (default): bytes straight back over the session.
                 *
                 * §9.5: the device refuses application writes once snd_queue +
                 * snd_buf reach SEND_QUEUE_MAX. The refusal must not be dropped
                 * (§9.5 forbids silent dropping) and must not be waited on inline
                 * either: this single-threaded loop is what receives the peer's
                 * acks, so blocking here is what would keep the queue from ever
                 * draining. Hold the one refused message and retry it on later
                 * iterations, and stop draining the receive side until it goes
                 * out — that backpressure is the point of the cap. */
                static uint8_t pend[1500];
                static int pend_len;
                uint8_t app[1500];
                int got;
                if (pend_len > 0) {
                    if (sn_primary_send(&dev, pend, pend_len, shieldnet_os_now_ms()) == SN_SEND_QUEUE_FULL) {
                        break; /* still full: let the loop process more acks */
                    }
                    pend_len = 0;
                }
                while (pend_len == 0 && (got = sn_primary_recv(&dev, app, sizeof(app))) > 0) {
                    if (sn_primary_send(&dev, app, got, shieldnet_os_now_ms()) == SN_SEND_QUEUE_FULL) {
                        memcpy(pend, app, (size_t)got);
                        pend_len = got;
                    }
                }
            }
            break;
        }
        default:
            break;
        }
    }
    return 0;
}
