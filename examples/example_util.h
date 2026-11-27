/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Helpers shared by led_device.c and led_client.c: argument parsing, reading
 * the pre-shared key from a file, and the IPv4 local-prefix table. None of this
 * is ShieldNet; it is the plumbing every POSIX program around the library needs.
 */
#ifndef EXAMPLE_UTIL_H
#define EXAMPLE_UTIL_H

#include "shieldnet/sn_source.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Exactly 2*n hex digits into n bytes. Returns 0, or -1 on anything else. */
static int ex_unhex(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < 2 * n; i++) {
        char c = hex[i];
        int v = (c >= '0' && c <= '9') ? c - '0'
              : (c >= 'a' && c <= 'f') ? c - 'a' + 10
              : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (v < 0) return -1;
        out[i / 2] = (uint8_t)((i % 2) ? (out[i / 2] | v) : (v << 4));
    }
    return 0;
}

/* A decimal port in [lo, 65535]. Returns 0, or -1. */
static int ex_parse_port(const char *s, long lo, uint16_t *out) {
    char *end;
    if (*s < '0' || *s > '9') return -1;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno != 0 || *end != '\0' || v < lo || v > 65535) return -1;
    *out = (uint16_t)v;
    return 0;
}

/* The 32-byte PSK from the file named by SHIELDNET_PSK_FILE: 64 hex digits,
 * trailing whitespace allowed. Never take a key from argv: the command line is
 * visible to every local user (ps, /proc/<pid>/cmdline). read(2), not stdio, so
 * no FILE buffer keeps a copy; our own buffer is wiped on every path. */
static int ex_load_psk(uint8_t psk[32]) {
    const char *path = getenv("SHIELDNET_PSK_FILE");
    char buf[130];
    size_t n = 0;
    int rc = -1;
    if (path == NULL || *path == '\0') {
        fprintf(stderr, "set SHIELDNET_PSK_FILE to a file holding the 64-hex-digit PSK\n");
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { perror(path); return -1; }
    struct stat sb;
    if (fstat(fd, &sb) == 0 && (sb.st_mode & 077))
        fprintf(stderr, "warning: %s is readable by group/other\n", path);
    for (;;) {
        ssize_t r = read(fd, buf + n, sizeof buf - 1 - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) n = sizeof buf;          /* a read error: reject below */
        if (r <= 0) break;
        n += (size_t)r;
        if (n == sizeof buf - 1) break;     /* too long to be a key */
    }
    close(fd);
    while (n > 0 && n < sizeof buf - 1 && strchr(" \t\r\n", buf[n - 1]) != NULL) n--;
    if (n == 64) {
        buf[n] = '\0';
        rc = ex_unhex(buf, psk, 32);
    }
    sodium_memzero(buf, sizeof buf);
    if (rc != 0) {
        sodium_memzero(psk, 32);
        fprintf(stderr, "%s: want exactly 64 hex digits\n", path);
    }
    return rc;
}

/* An IPv4 address as the library's 16-octet form, ::ffff:a.b.c.d. */
static void ex_a16(const struct in_addr *in, uint8_t a16[16]) {
    memset(a16, 0, 16);
    a16[10] = 0xff;
    a16[11] = 0xff;
    memcpy(a16 + 12, &in->s_addr, 4); /* already network (big-endian) order */
}

/* Every IPv4 address of this host with its prefix length: the local-prefix
 * table (sn_source.h) behind transport 7.2's own-address and subnet-broadcast
 * checks. Returns how many it wrote, or -1. A long-running device rebuilds it
 * whenever its addresses change (a DHCP renewal, a cable moved). */
static int ex_local_prefixes(sn_prefix *out, size_t max) {
    struct ifaddrs *list;
    size_t n = 0;
    if (getifaddrs(&list) != 0) { perror("getifaddrs"); return -1; }
    for (struct ifaddrs *i = list; i != NULL && n < max; i = i->ifa_next) {
        if (i->ifa_addr == NULL || i->ifa_netmask == NULL || i->ifa_addr->sa_family != AF_INET)
            continue;
        const struct sockaddr_in *a = (const struct sockaddr_in *)i->ifa_addr;
        const struct sockaddr_in *m = (const struct sockaddr_in *)i->ifa_netmask;
        uint32_t mask = ntohl(m->sin_addr.s_addr);
        int bits = 0;
        while (bits < 32 && (mask & (0x80000000u >> bits))) bits++;
        memset(&out[n], 0, sizeof out[n]);
        ex_a16(&a->sin_addr, out[n].a16);
        out[n].is_v4 = 1;
        out[n].bits = bits;
        n++;
    }
    freeifaddrs(list);
    return (int)n;
}

#endif /* EXAMPLE_UTIL_H */
