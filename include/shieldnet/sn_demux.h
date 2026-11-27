/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet demultiplexing — §5 of shieldnet-protocol design/transport.md. Byte-for-byte with
 * goshieldnet/v1/demux.go. Classify is a pure router that applies §4.3 at §5
 * step 0. The device's INIT and FINISH handlers apply the same predicate again
 * (sn_source_rejected_a16), so a board that demuxes with sn_classify_datagram
 * cannot skip it; envelopes need no check of their own, since they only reach a
 * tuple a FINISH admitted. It does NOT validate a control message's length or
 * version — the decoder does that (§3.5); Classify only routes.
 */
#ifndef SHIELDNET_DEMUX_H
#define SHIELDNET_DEMUX_H

#include <stddef.h>
#include <stdint.h>

#include "shieldnet/sn_source.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SN_ROLE_DEVICE = 0, /* rejects RETRY and ADMIT */
    SN_ROLE_CLIENT = 1  /* rejects INIT and FINISH */
} sn_role;

typedef enum {
    SN_CLASS_DROP = 0,     /* silently dropped (§5); never answered (§9.3) */
    SN_CLASS_ENVELOPE = 1, /* envelope path (§8) */
    SN_CLASS_INIT = 2,     /* control INIT (§6.1), device only */
    SN_CLASS_RETRY = 3,    /* control RETRY (§6.1), client only */
    SN_CLASS_FINISH = 4,   /* control FINISH (§6.2), device only */
    SN_CLASS_ADMIT = 5     /* control ADMIT (§6.2), client only */
} sn_class;

/* Classify one datagram received at (is_v4, src_a16) with the interface's local
 * prefixes for §4.3's own-address / subnet-broadcast checks. */
sn_class sn_classify(sn_role role, int src_is_v4, const uint8_t src_a16[16],
                     const sn_prefix *local, size_t n_local,
                     const uint8_t *datagram, size_t len);

/* §5 steps 1-2 without the §4.3 source check. Exposed so a loopback host
 * harness — whose 127.0.0.1 source §4.3 rejects — can exercise the pipeline; such
 * a harness must also call sn_device_set_source_check(d, 0), since the device
 * handlers enforce §4.3 themselves. Production goes through sn_classify. */
sn_class sn_classify_datagram(sn_role role, const uint8_t *datagram, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_DEMUX_H */
