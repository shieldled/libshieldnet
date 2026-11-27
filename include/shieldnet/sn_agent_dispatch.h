/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Portable device agent: read->decrypt->decompress->dispatch over
 * the transport. The app-message crypto/framing and command dispatch are the
 * KEPT app layer (protocol.c/command.c); this swaps only the transport and the key
 * source (the primary's k_c2s/k_s2c). The board provides ops + buffers, loops step.
 */
#ifndef SHIELDNET_AGENT_DISPATCH_H
#define SHIELDNET_AGENT_DISPATCH_H

#include "shieldnet/sn_agent.h"
#include "shieldnet/sn_app_frame.h"
#include "protocol.h"
#include "shieldnet_device.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    sn_agent_io io_st;
    shieldnet_io_t io;
    const shieldnet_device_ops_t *dev;
    /* The direction-symmetric core (sn_app_frame.h). The device binds rx to k_c2s
     * and tx to k_s2c; the client binds them the other way round. Keys,
     * MessageNums and the dec/decomp/enc buffers live in these. */
    sn_app_rx rx;
    sn_app_tx tx;
    /* raw is the ciphertext protocol_read_message fills, and stays here: it
     * belongs to the reading half, which is not shared. */
    uint8_t *raw;
    size_t raw_size;
} sn_agent;

/* Bind the agent to the device's established primary (call after promotion;
 * copies the primary's generation and k_c2s/k_s2c in one locked read). Buffers
 * are caller-owned, must outlive it. Returns 0, or -1 if there is no active
 * primary -- the agent is then bound to no session and every step fails.
 *
 * One agent serves a primary at a time, and every call on one agent --
 * sn_agent_step, and sn_agent_respond from inside its ops -- must come from a
 * single task: they share the agent's buffers and tx state. A re-bind after an
 * agent has stopped is nonce-safe (s2c MessageNums come from the primary, so
 * they continue rather than restart), but after a -1 from step the stream is
 * mid-frame: end the session instead. Two agents serving one primary at once
 * would also reorder MessageNums on the wire, and the peer drops the lower.
 *
 * Responses are padded to §13's size class (message layer 6.3), which needs
 * enc_size >= class + 16: 528 bytes pads every response up to SN_PAD_MAX_CLASS.
 * A response whose class does not fit is sent unpadded instead. */
int sn_agent_init(sn_agent *ag, sn_device *dev, const shieldnet_device_ops_t *ops,
                  uint8_t *raw, size_t raw_size, uint8_t *dec, size_t dec_size,
                  uint8_t *decomp, size_t decomp_size, uint8_t *enc, size_t enc_size);

/* Process one inbound message. Returns
 *    1  dispatched (or survivably dropped);
 *    0  idle timeout, stream aligned;
 *   SN_AGENT_REFUSED  the command ran but a response was refused whole (the
 *      send queue stayed full for SN_SEND_BLOCKED_MS, as it does while the
 *      session is quiesced). Nothing of it reached the stream, which is still
 *      aligned: keep stepping. The session is NOT broken (§9.4, §9.5);
 *   -1  the stream can no longer be trusted (desync, a partial write, a fatal
 *      frame, or the session is gone): call sn_agent_end, then wait for the
 *      next promotion before binding again. */
#define SN_AGENT_REFUSED (-2)
int sn_agent_step(sn_agent *ag, uint32_t now_ms, int timeout_ms);

/* End the session this agent is bound to (sn_device_end_primary on its
 * generation; a no-op if a promotion already replaced it) and wipe the agent's
 * keys and plaintext buffers. */
void sn_agent_end(sn_agent *ag);

/* Encrypt a response under k_s2c and write it (the device ops' send_response calls
 * this). Returns 0 on success, <0 on error. */
int sn_agent_respond(sn_agent *ag, uint32_t now_ms, uint8_t kind,
                     const uint8_t *body, size_t body_len);

#ifdef __cplusplus
}
#endif
#endif /* SHIELDNET_AGENT_DISPATCH_H */
