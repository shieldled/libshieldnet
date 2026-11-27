/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_io — the transport seam.
 *
 * protocol_read_message/write_message/marshal_aad differ between the device
 * and the client only in which handle they read and write through — same
 * shapes, same protocol. This table lets one protocol.c serve both.
 *
 * Admission does NOT go through this seam: it is inherently role-asymmetric.
 * The v2 protocol_handshake_client/protocol_handshake_server pair this comment
 * used to name was removed in the v1 migration (see protocol.h); protocol.c is
 * framing only. Admission is sn_device.c's §6 INIT->RETRY / FINISH->ADMIT on
 * the device side and sn_client.c's §7 state machine on the client side.
 * See the library README.
 */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* An adapter must zero-initialise its shieldnet_io_t (`shieldnet_io_t io = {0};`)
 * or set every member, so a member added later reads NULL rather than stack
 * garbage. An adapter that sets frame_continues must let a `readfull` that
 * times out with nothing read keep waiting until its own mid-frame budget ends,
 * so after a lone header the caller can block up to that budget
 * (SN_MID_FRAME_BUDGET_MS for sn_primary_io), and with timeout_ms 0 it spins
 * for that long; a caller that steps the agent from the thread that feeds
 * envelopes must not pass 0. */
typedef struct {
    void *ctx;

    /* Returns bytes read: len on success, 0 on idle timeout (nothing
     * consumed, stream still frame-aligned), <0 on error. A short but
     * nonzero return means a partial frame was consumed and the stream is
     * desynchronised — see poison below. */
    int (*readfull)(void *ctx, void *buf, size_t len, int timeout_ms);

    /* Returns 0 on success, <0 on error. */
    int (*write)(void *ctx, const void *data, size_t len);

    /* Mark the stream unusable after a partial frame was consumed and could
     * not be finished — the wire format has no resync marker, so the stream
     * position is unrecoverable. What this does is implementation-defined:
     * a transport that owns exactly one session for its lifetime can poison
     * itself directly; a handle that outlives sessions (like the device's
     * sn_device, one per board across many admissions) must NOT implement
     * this as a flag on the handle, or one desynchronised frame would
     * permanently disable every future session. */
    void (*poison)(void *ctx);

    /* Optional. protocol_read_message calls it after a complete header whose
     * Size is above 0, before reading the body: the body read continues a frame
     * already begun, so a wait that times out with nothing yet read is not an
     * idle (message layer 8 item 1). NULL: no such distinction. */
    void (*frame_continues)(void *ctx);
} shieldnet_io_t;

#ifdef __cplusplus
}
#endif
