/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* sn_pts_decide: frame timing, spec/application.md 6.4.1, 6.4.2 and 6.4.4. */
#include "shieldnet/sn_pts.h"

#include <stdio.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)

#define N   INT64_C(1700000000000000000)
#define MS  INT64_C(1000000)
#define S   INT64_C(1000000000)

/* One decision from a zeroed state. hold < 0 means "not HOLD" (hold_us must be 0). */
static int run1(const char *name, int64_t nb, int64_t na, int64_t now,
                sn_pts_action want, long hold)
{
    sn_pts_state st = {0};
    uint32_t h = 0xDEADBEEFu;
    sn_pts_action a = sn_pts_decide(&st, nb, na, now, &h);
    int ok = a == want && (want == SN_PTS_HOLD ? (long)h == hold : h == 0);
    CHECK(ok, name);
    return ok;
}

static void seq(const char *name, sn_pts_state *st, const int64_t (*f)[3], int n,
                const sn_pts_action *want)
{
    int ok = 1;
    for (int i = 0; i < n; i++) {
        uint32_t h = 0xDEADBEEFu;
        sn_pts_action a = sn_pts_decide(st, f[i][0], f[i][1], f[i][2], &h);
        if (a != want[i]) ok = 0;
        if (a != SN_PTS_HOLD && h != 0) ok = 0;
    }
    CHECK(ok, name);
}

int main(void)
{
    const sn_pts_action P = SN_PTS_PRESENT, H_ = SN_PTS_HOLD, D = SN_PTS_DISCARD;

    /* held */
    run1("held: 20 ms",           N + 20 * MS, N + 30 * MS, N, H_, 20000);
    run1("held: 1 ns rounds up",  N + 1, 0, N, H_, 1);
    run1("held: exactly 1 s",     N + S, 0, N, H_, 1000000);
    run1("held: 1 s + 1 ns presents", N + S + 1, 0, N, P, -1);

    /* in time */
    run1("in time: at not_before",   N, N + 10 * MS, N, P, -1);
    run1("in time: inside the window", N - 5 * MS, N + 5 * MS, N, P, -1);
    run1("in time: now == not_after is not after", N - 10 * MS, N, N, P, -1);

    /* discarded */
    run1("discard: 1 ns after not_after", N - 10 * MS - 1, N - 1, N, D, -1);
    run1("discard: not_before 0",   0, N - 1, N, D, -1);
    run1("discard: zero-width window", N - 5 * MS, N - 5 * MS, N, D, -1);
    run1("discard: out-of-range not_before counts as 0", SN_PTS_T_MAX, N - 1, N, D, -1);

    /* zeros */
    run1("zero: not_after 0",       N - S, 0, N, P, -1);
    run1("zero: not_before 0",      0, N + 1, N, P, -1);
    run1("zero: both 0",            0, 0, N, P, -1);

    /* not_after before not_before */
    run1("na < nb: not_after ignored", N + 20 * MS, N - 10 * MS, N, H_, 20000);

    /* out of range counts as zero */
    run1("range: (-1, -1)",         -1, -1, N, P, -1);
    run1("range: (0, -1)",          0, -1, N, P, -1);
    run1("range: (0, INT64_MIN)",   0, INT64_MIN, N, P, -1);
    run1("range: (2^62, 2^62)",     SN_PTS_T_MAX, SN_PTS_T_MAX, N, P, -1);
    run1("range: (INT64_MIN, INT64_MAX)", INT64_MIN, INT64_MAX, N, P, -1);
    run1("range: (N + 20 ms, -1) holds", N + 20 * MS, -1, N, H_, 20000);

    /* clock not synced */
    run1("unsynced: now 0",         N - S, N - S + 10 * MS, 0, P, -1);
    run1("unsynced: now -1",        N - S, N - S + 10 * MS, -1, P, -1);
    run1("unsynced: now 2^62",      N - S, N - S + 10 * MS, SN_PTS_T_MAX, P, -1);
    run1("unsynced: now INT64_MAX", N - S, N - S + 10 * MS, INT64_MAX, P, -1);
    run1("unsynced: now 0, not_before 500 ms", 500 * MS, 0, 0, P, -1);
    run1("unsynced: now -1, not_before 500 ms", 500 * MS, 0, -1, P, -1);
    run1("unsynced: now INT64_MIN", SN_PTS_T_MAX - 1, 0, INT64_MIN, P, -1);

    /* sequences */
    {
        const int64_t L[3] = { N - 100 * MS, N - 90 * MS, N };
        const int64_t Hd[3] = { N + 20 * MS, N + 30 * MS, N };
        const int64_t M[3] = { N - 5 * MS, N + 5 * MS, N };
        const int64_t Z[3] = { 0, 0, N };
        const int64_t Lu[3] = { N - 100 * MS, N - 90 * MS, 0 };

        {
            sn_pts_state st = {0};
            const int64_t f[7][3] = { {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {L[0],L[1],L[2]},
                                      {L[0],L[1],L[2]}, {L[0],L[1],L[2]},
                                      {Hd[0],Hd[1],Hd[2]}, {L[0],L[1],L[2]} };
            const sn_pts_action w[7] = { D, D, D, P, P, H_, D };
            seq("sequence: L L L L L H L", &st, f, 7, w);
        }
        {
            sn_pts_state st = {0};
            const int64_t f[7][3] = { {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {M[0],M[1],M[2]},
                                      {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {L[0],L[1],L[2]},
                                      {L[0],L[1],L[2]} };
            const sn_pts_action w[7] = { D, D, P, D, D, D, P };
            seq("sequence: a frame in time re-arms three discards", &st, f, 7, w);
        }
        {
            sn_pts_state st = {0};
            const int64_t f[7][3] = { {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {Z[0],Z[1],Z[2]},
                                      {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {L[0],L[1],L[2]},
                                      {L[0],L[1],L[2]} };
            const sn_pts_action w[7] = { D, D, P, D, D, D, P };
            seq("sequence: a (0, 0) frame re-arms three discards", &st, f, 7, w);
        }
        {
            sn_pts_state st = {0};
            const int64_t f[7][3] = { {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {Lu[0],Lu[1],Lu[2]},
                                      {L[0],L[1],L[2]}, {L[0],L[1],L[2]}, {L[0],L[1],L[2]},
                                      {L[0],L[1],L[2]} };
            const sn_pts_action w[7] = { D, D, P, D, D, D, P };
            seq("sequence: an unsynced frame re-arms three discards", &st, f, 7, w);
        }
        {
            sn_pts_state st = {0};
            int ok = 1;
            for (int i = 0; i < 300; i++) {
                uint32_t h;
                sn_pts_decide(&st, L[0], L[1], L[2], &h);
                if (st.late_run > SN_PTS_DISCARD_RUN) ok = 0;
            }
            CHECK(ok && st.late_run == SN_PTS_DISCARD_RUN, "late_run never exceeds 3 in 300 late frames");
        }
    }

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all sn_pts cases pass\n");
    return 0;
}
