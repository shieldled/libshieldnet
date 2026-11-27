/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet canonical source and source-rejection predicate — §4.3.
 * Byte-exact with goshieldnet/v1. Pure functions.
 *
 * Addresses are the 16-octet IPv6 form; an IPv4 source is the mapped
 * ::ffff:a.b.c.d (bytes 10-11 = 0xffff). is_v4 records the ORIGINAL family, since
 * §4.3 tests in the address's own family before canonicalisation.
 */
#ifndef SHIELDNET_SOURCE_H
#define SHIELDNET_SOURCE_H

#include <stddef.h>
#include <stdint.h>

/* An interface prefix: the (address, netmask) table §4.3 needs — the assigned
 * address (a16) and its prefix length (bits), from which the subnet broadcast is
 * derived for the v4 broadcast reject case. */
typedef struct {
    uint8_t a16[16];
    int     is_v4;
    int     bits; /* prefix length in the address's own family (v4: 0..32; a v4
                   * prefix outside that range is a board configuration error and
                   * fails closed -- every v4 source is rejected). Unused for v6. */
} sn_prefix;

/* canonical_source (18) = a16 || port_be. */
void sn_canonical_source(const uint8_t a16[16], uint16_t port, uint8_t out18[18]);

/* Non-zero iff a datagram from (is_v4, a16) MUST be dropped (§4.3). local is the
 * receiving interface's prefixes (§4.3 binds the socket to one interface). */
int sn_source_rejected(int is_v4, const uint8_t a16[16],
                       const sn_prefix *local, size_t n_local);

/* sn_source_rejected for a caller that has only the 16-octet form (the device
 * handlers): is_v4 is taken from the ::ffff:0:0/96 mapped form, the convention
 * every a16 in this library follows. What it cannot see is a GENUINE v6 source
 * carrying a mapped address (§4.3 rejects it); on a dual-stack socket that is
 * indistinguishable from v4 anyway, and sn_classify, which has the real family,
 * still rejects it. Same predicate otherwise, so the two cannot diverge. */
int sn_source_rejected_a16(const uint8_t a16[16], const sn_prefix *local, size_t n_local);

#endif
