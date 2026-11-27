/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * Frame timing decision (shieldnet-protocol spec/application.md 6.4.1, 6.4.2 and 6.4.4).
 *
 * Given a PIXEL_FRAME's not_before and not_after and the device's own clock,
 * says whether to present the frame now, hold it, or discard it. Integer-only,
 * no OS call. It decides nothing else: holding one frame, the timer and the
 * refresh are the firmware's.
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SN_PTS_T_MAX        (INT64_C(1) << 62)    /* exclusive bound of a timestamp in use */
#define SN_PTS_MAX_HOLD_NS  INT64_C(1000000000)   /* 6.4.1: 1 s */
#define SN_PTS_MAX_LEAD_NS  INT64_C(1000000000)   /* 6.4.5: sender lead, 1 s */
#define SN_PTS_DISCARD_RUN  3                     /* 6.4.4 */

typedef struct { uint8_t late_run; } sn_pts_state;   /* all-zero is a valid start */

typedef enum {
    SN_PTS_PRESENT = 0,   /* present the frame now */
    SN_PTS_HOLD    = 1,   /* hold it for *hold_us, then present it */
    SN_PTS_DISCARD = 2    /* do not touch the pixels or the output */
} sn_pts_action;

/* now_ns: the device's NTP-synced clock in Unix nanoseconds, or 0 when the
 * clock is not synced (6.4.6). *hold_us is 0 unless the result is HOLD. */
static inline sn_pts_action sn_pts_decide(sn_pts_state *st,
                                          int64_t not_before_ns, int64_t not_after_ns,
                                          int64_t now_ns, uint32_t *hold_us)
{
    *hold_us = 0;

    /* 1. an unsynced or out-of-range clock: present on arrival */
    if (now_ns < 1 || now_ns >= SN_PTS_T_MAX) {
        st->late_run = 0;
        return SN_PTS_PRESENT;
    }

    /* 2. a timestamp outside [1, 2^62) counts as 0; a window that ends before
     *    it begins is no window */
    int64_t nb = (not_before_ns >= 1 && not_before_ns < SN_PTS_T_MAX) ? not_before_ns : 0;
    int64_t na = (not_after_ns >= 1 && not_after_ns < SN_PTS_T_MAX) ? not_after_ns : 0;
    if (na != 0 && nb != 0 && na < nb) na = 0;

    /* 3. past not_after: discard, unless three were discarded in a row */
    if (na != 0 && now_ns > na) {
        if (st->late_run >= SN_PTS_DISCARD_RUN) return SN_PTS_PRESENT;
        st->late_run++;
        return SN_PTS_DISCARD;
    }

    /* 4. a frame that is not discarded ends a run of discards */
    st->late_run = 0;

    /* 5. before not_before: hold, unless it would wait longer than the limit */
    if (nb != 0 && now_ns < nb) {
        int64_t wait = nb - now_ns;
        if (wait > SN_PTS_MAX_HOLD_NS) return SN_PTS_PRESENT;
        *hold_us = (uint32_t)((wait + 999) / 1000);
        return SN_PTS_HOLD;
    }

    /* 6. */
    return SN_PTS_PRESENT;
}

#ifdef __cplusplus
}
#endif
