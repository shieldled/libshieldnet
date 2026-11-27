/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Pure receive-drain policy shared by firmware and host regression tests. */
#pragma once

#include <stddef.h>

/* Must be at least the KCP MSS, SN_WIRE_MTU - 44 (1356 at the default
 * SN_WIRE_MTU 1400): a build that raises SN_WIRE_MTU above 1444 must raise this
 * too, or a full segment no longer fits the scratch buffer. */
#ifndef KCP_SERVER_RECV_BUFFER_SIZE
#define KCP_SERVER_RECV_BUFFER_SIZE 1400
#endif

typedef enum {
    KCP_DRAIN_WAIT,
    KCP_DRAIN_RECEIVE,
    KCP_DRAIN_RESET_SESSION,
} kcp_drain_action_t;

/* Decide what to do with the next complete KCP receive item.
 *
 * In the required KCP stream mode, each item is at most one MSS and fits the
 * scratch buffer (KCP_SERVER_RECV_BUFFER_SIZE, at least the MSS). A larger item
 * identifies a message-mode/misconfigured peer. It can never be consumed by
 * the bounded callback buffer, so the only safe recovery is to reset the
 * session rather than wedge its receive queue.
 */
static inline kcp_drain_action_t kcp_drain_policy(
    int peek_size, size_t scratch_size, size_t ring_free, size_t ring_capacity)
{
    if (peek_size < 0) return KCP_DRAIN_WAIT;

    size_t next = (size_t)peek_size;
    if (next > scratch_size || next > ring_capacity) {
        return KCP_DRAIN_RESET_SESSION;
    }
    if (next > ring_free) return KCP_DRAIN_WAIT;
    return KCP_DRAIN_RECEIVE;
}
