/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
#include "shieldnet/sn_agent.h"

#include <string.h>

#include "shieldnet_os.h"

/* Is the session this io was bound to still the current primary? A promotion
 * supersedes it, and then waiting for more of its stream is pointless. */
static int d_primary_alive(sn_agent_io *st) {
    return sn_device_session_active(st->dev, st->gen);
}

/* Message layer 8 item 2: the mid-frame budget is elapsed time since this read
 * first consumed part of the frame -- not the sum of the waits that timed out,
 * which a peer keeping data_ready busy (ACK-only datagrams) never lets grow. */
static int waited_out(const sn_agent_io *st) {
    return (uint32_t)(shieldnet_os_now_ms() - st->mid_frame_start_ms) >= SN_MID_FRAME_BUDGET_MS;
}

/* readfull: fill exactly len bytes from the primary's KCP stream, or return 0 on
 * idle timeout. Requests exactly the remaining count each time (stream mode, so
 * ikcp_recv returns at most that — no overflow buffer needed), and blocks on the
 * device's data_ready signal when nothing is available. */
static int io_readfull(void *ctx, void *buf, size_t len, int timeout_ms) {
    sn_agent_io *st = ctx;
    uint8_t *out = buf;
    size_t got = 0;
    while (got < len) {
        if (st->carry_pos < st->carry_len) { /* serve from the carry buffer */
            size_t take = st->carry_len - st->carry_pos;
            if (take > len - got) {
                take = len - got;
            }
            memcpy(out + got, st->carry + st->carry_pos, take);
            st->carry_pos += take;
            got += take;
            if (!st->mid_frame_armed) { /* part of the frame is now consumed */
                st->mid_frame_armed = 1;
                st->mid_frame_start_ms = shieldnet_os_now_ms();
            }
            continue;
        }
        /* carry empty: read one whole segment (ikcp_recv needs buf >= segment) */
        int n = sn_primary_recv_gen(st->dev, st->gen, st->carry, (int)sizeof(st->carry));
        if (n < 0) {
            return -1; /* no primary / error */
        }
        if (n > 0) {
            st->carry_len = (size_t)n;
            st->carry_pos = 0;
            continue;
        }
        /* Nothing ready — wait for the RX path to deliver more.
         *
         * The two waits are deliberately different:
         *   - got == 0: nothing consumed, the stream is on a frame boundary. A
         *     timeout is an ordinary idle and returns 0.
         *   - got  > 0: a frame is already committed and KCP *will* deliver the
         *     rest — it is a reliable stream. Returning short here makes
         *     protocol_read_message poison the stream and kill the session, which
         *     turns an ordinary retransmit (loss + RTO on a lossy link) into a
         *     teardown. So keep waiting; only give up when the session itself is
         *     gone or the mid-frame budget expires (a genuinely wedged peer). */
        if (st->dev->data_ready == NULL) {
            st->mid_frame_armed = 0;
            return got == 0 ? 0 : (int)got;
        }
        int woken = shieldnet_signal_wait(st->dev->data_ready, timeout_ms);
        if (got == 0 && !st->mid_frame_armed) {
            if (woken) continue; /* data arrived */
            return 0; /* idle, stream still aligned */
        }
        /* mid-frame, after every wait, woken or timed out: the session must
         * still be alive, and we must not wait forever */
        if (!d_primary_alive(st) || waited_out(st)) {
            st->mid_frame_armed = 0;
            return (int)got; /* short => desync, the caller ends the session */
        }
    }
    st->mid_frame_armed = 0; /* frame complete: reset the mid-frame budget */
    return (int)len;
}

static int io_write(void *ctx, const void *data, size_t len) {
    sn_agent_io *st = ctx;
    uint32_t start = shieldnet_os_now_ms();
    for (;;) {
        uint32_t now = shieldnet_os_now_ms();
        uint32_t waited = now - start;
        /* KCP runs on the caller's clock (st->now_ms, set by sn_agent_step and
         * sn_agent_respond), advanced by the OS time since it was set. Stamping
         * the OS clock itself mixes two timebases whenever the caller's is not
         * the OS clock: less than ten seconds behind it, each write pushes
         * ikcp's ts_flush past every later update and the output stalls. */
        uint32_t kcp_now = st->now_ms + (now - st->now_set_os_ms);
        /* Bound to st->gen like the read side: after a promotion this io's
         * bytes, sealed under the old keys, must not reach the new stream. */
        int rc = sn_primary_send_gen(st->dev, st->gen, data, (int)len, kcp_now);
        if (rc >= 0) {
            return 0;
        }
        if (rc != SN_SEND_QUEUE_FULL) {
            /* No session, or a send that failed after possibly queuing part of
             * the bytes (OOM, short send): either way the stream is no longer
             * one this io can vouch for. */
            st->poisoned = 1;
            return -1;
        }
        /* §9.5: reaching SEND_QUEUE_MAX is a refusal, not a broken session — the
         * device MUST resume once the total falls below the cap. Give it up to
         * SN_SEND_BLOCKED_MS to drain (the peer's acks retire snd_buf) before
         * giving up, so a burst that briefly fills the queue does not end the
         * session. Returning -1 here is what ends it. */
        if (waited >= SN_SEND_BLOCKED_MS) {
            return -1; /* refused whole: nothing of this write was queued */
        }
        /* The port may round this up to one OS tick; `waited` is measured
         * from the clock, so the budget holds either way. */
        uint32_t prev = now;
        shieldnet_os_sleep_until_ms(&prev, 5);
    }
}

/* A complete header with a body to come: the body read continues that frame,
 * so a timed-out wait with nothing yet read is not an idle. The header read
 * armed the budget at its first octet and cleared only the flag at its end;
 * re-arm the flag and leave the start alone, so the budget runs from there. */
static void io_frame_continues(void *ctx) {
    sn_agent_io *st = ctx;
    st->mid_frame_armed = 1;
}

static void io_poison(void *ctx) {
    /* Per-session, not per-device: st is bound to one generation (shieldnet_io.h). */
    sn_agent_io *st = ctx;
    st->poisoned = 1;
}

shieldnet_io_t sn_primary_io(sn_agent_io *st, sn_device *dev) {
    st->dev = dev;
    st->now_ms = shieldnet_os_now_ms();
    st->now_set_os_ms = st->now_ms;
    st->mid_frame_armed = 0;
    st->poisoned = 0;
    st->gen = sn_device_current_gen(dev); /* the session this io serves */
    shieldnet_io_t io = {0};
    io.ctx = st;
    io.readfull = io_readfull;
    io.write = io_write;
    io.poison = io_poison;
    io.frame_continues = io_frame_continues;
    return io;
}

void sn_agent_set_now(sn_agent_io *st, uint32_t now_ms) {
    st->now_ms = now_ms;
    st->now_set_os_ms = shieldnet_os_now_ms();
}
