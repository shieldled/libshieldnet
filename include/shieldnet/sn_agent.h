/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * ShieldNet agent seam — bridges the transport (admission + envelope + KCP,
 * this library) to the post-admission app layer (protocol.c / command.c), which
 * the transport spec leaves out of scope (RFC line 5) and which is transport-agnostic
 * through shieldnet_io_t.
 *
 * sn_primary_io returns a shieldnet_io_t backed by the device's established
 * primary: readfull drains sn_primary_recv (blocking on the device's data_ready
 * signal up to a timeout), write goes through sn_primary_send_gen. The app-layer
 * cipher is keyed by the primary's k_c2s/k_s2c (sn_device.h's sn_primary), which
 * the caller reads directly. Stream mode (kcp->stream=1) makes readfull exact.
 */
#ifndef SHIELDNET_AGENT_H
#define SHIELDNET_AGENT_H

#include "shieldnet/sn_device.h"
#include "shieldnet_io.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque per-session read state. Zero-initialise; one per sn_primary_io. */
typedef struct {
    sn_device *dev;
    /* The caller's clock, refreshed before each write (sn_agent_set_now), and
     * the OS clock when it was set: a write stamps ikcp with now_ms plus the OS
     * time elapsed since, so KCP stays on the caller's timebase and is fresh. */
    uint32_t now_ms;
    uint32_t now_set_os_ms;
    /* carry: this ikcp's stream-mode recv still copies whole segments, so readfull
     * reads a full segment then serves exact bytes from here. */
    uint8_t carry[SN_WIRE_MTU];
    size_t carry_len, carry_pos;
    /* Mid-frame wait budget (message layer 8 item 2): once a frame is
     * committed, readfull keeps waiting across idle timeouts because KCP will
     * deliver the rest. mid_frame_start_ms is when this read first consumed part
     * of the frame (valid while mid_frame_armed); SN_MID_FRAME_BUDGET_MS of
     * elapsed time from it caps the wait, checked after every wait, so a wedged
     * peer cannot block the agent forever even while other traffic keeps waking
     * it. gen is the primary generation this io serves — the wait also ends if
     * the session is superseded. */
    uint32_t mid_frame_start_ms;
    int      mid_frame_armed;
    uint32_t dbg_reads;
    uint32_t gen;
    /* Set once part of a frame may have gone into the stream without the rest
     * (a payload write after its header, or a send that failed after queuing
     * some bytes), or once a read lost frame alignment. Unlike a flag on the
     * device, this lives and dies with the one session `gen` names, which is
     * what shieldnet_io.h requires of a latching poison(). */
    int poisoned;
} sn_agent_io;

/* How long readfull may keep waiting mid-frame before declaring the stream dead.
 * Generous: KCP retransmits with RTO backoff, and a live session must not be torn
 * down for ordinary loss. */
#define SN_MID_FRAME_BUDGET_MS 10000u

/* Build a shieldnet_io_t over the device's established primary. `st` must outlive
 * the returned handle. poison latches st->poisoned, which belongs to this one
 * session, never the device (the device outlives sessions; see shieldnet_io.h).
 * A poisoned stream is dropped by ending the session. */
shieldnet_io_t sn_primary_io(sn_agent_io *st, sn_device *dev);

/* The caller refreshes the clock the write path stamps ikcp with: the same
 * clock it passes to sn_device's calls. Writes advance it by the OS time elapsed
 * since this call, so a caller on shieldnet_os_now_ms() stamps the OS clock. */
void sn_agent_set_now(sn_agent_io *st, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* SHIELDNET_AGENT_H */
