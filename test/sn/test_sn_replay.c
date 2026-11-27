/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* §8.2–§8.4 replay window, range check, sender — mirrors replay_test.go. */
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_wire.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(c, m) do { if(!(c)){printf("FAIL %s\n",m);failures++;} else printf("ok   %s\n",m); } while(0)


/* Differential fuzz of the sliding window against a straightforward reference
 * model. This is the regression test for the byte-wise shift_up rewrite (26x
 * faster on Xtensa than the original per-bit loop): the optimisation is only
 * safe while it stays behaviourally identical to the obvious implementation,
 * and nothing else in this file exercises a multi-bit slide. */
/* Large enough that hwm does not saturate before the loop ends: the walk
 * advances ~55/iteration, so 60k iterations need >3.3M of range. At 200000 the
 * window stopped sliding after ~3500 iterations and 94% of the run tested
 * nothing. */
#define REF_MAX 4000000u
static uint8_t ref_seen[REF_MAX + 1];

static int ref_accept(uint64_t seq, uint64_t *hwm) {
    if (seq == 0 || seq > REF_MAX) return 0;
    if (*hwm != 0 && seq + SN_REPLAY_WINDOW <= *hwm) return 0; /* aged out */
    if (ref_seen[seq]) return 0;                               /* replay */
    ref_seen[seq] = 1;
    if (seq > *hwm) *hwm = seq;
    return 1;
}

static int fuzz_replay_window(void) {
    sn_replay_window w; memset(&w, 0, sizeof(w));
    memset(ref_seen, 0, sizeof(ref_seen));
    uint64_t ref_hwm = 0;
    uint64_t seq = 1;

    /* Ring of previously-accepted sequences. Re-probing these is what actually
     * exercises shift_up: if a slide loses a mark, the replay is wrongly
     * accepted, and a distribution that only walks forward never notices. */
    enum { ACC_MAX = 4096 };
    static uint64_t accepted[ACC_MAX];
    size_t acc_n = 0, acc_w = 0;

    for (unsigned i = 0; i < 60000u; i++) {
        uint32_t r = randombytes_uniform(100);
        int64_t cand;
        if (r < 40)                        cand = (int64_t)seq + 1 + randombytes_uniform(3);
        else if (r < 58)                   cand = (int64_t)seq + 1 + randombytes_uniform(600);
        else if (r < 72)                   cand = (int64_t)seq - (int64_t)randombytes_uniform(300);
        else if (r < 86 && acc_n > 0)      cand = (int64_t)accepted[randombytes_uniform((uint32_t)acc_n)];
        else if (r < 96)                   cand = (int64_t)ref_hwm - SN_REPLAY_WINDOW
                                                  + (int64_t)randombytes_uniform(3);
        else                               cand = (int64_t)seq;
        if (cand < 1) cand = 1;
        if (cand > (int64_t)REF_MAX) cand = (int64_t)REF_MAX;

        uint64_t c = (uint64_t)cand;
        uint64_t saved_hwm = ref_hwm;
        int want = ref_accept(c, &ref_hwm);
        int got  = sn_replay_test_and_mark(&w, c);
        if (want != got) {
            printf("FAIL fuzz i=%u seq=%llu hwm=%llu want=%d got=%d\n",
                   i, (unsigned long long)c, (unsigned long long)saved_hwm, want, got);
            return 1;
        }
        if (w.hwm != ref_hwm) {
            printf("FAIL fuzz hwm divergence i=%u seq=%llu impl=%llu ref=%llu\n",
                   i, (unsigned long long)c,
                   (unsigned long long)w.hwm, (unsigned long long)ref_hwm);
            return 1;
        }
        if (got) {
            accepted[acc_w] = c;
            acc_w = (acc_w + 1) % ACC_MAX;
            if (acc_n < ACC_MAX) acc_n++;
        }

        /* Compare the entire window against the model, not just this call's
         * verdict. A slide that corrupts a bit is otherwise invisible until a
         * probe happens to land on that exact sequence while it is still in
         * window -- which a random walk almost never does. Bit offset o holds
         * seq = hwm - o. */
        for (unsigned o = 0; o < SN_REPLAY_WINDOW; o++) {
            if (w.hwm <= o) break;               /* seq would be < 1 */
            uint64_t s_at = w.hwm - o;
            int impl_bit = (w.bits[o / 8] >> (o % 8)) & 1;
            int ref_bit  = (s_at <= REF_MAX) ? ref_seen[s_at] : 0;
            if (impl_bit != ref_bit) {
                printf("FAIL fuzz bit divergence i=%u off=%u seq=%llu hwm=%llu impl=%d ref=%d\n",
                       i, o, (unsigned long long)s_at,
                       (unsigned long long)w.hwm, impl_bit, ref_bit);
                return 1;
            }
        }

        if (ref_hwm > seq) seq = ref_hwm;
    }
    return 0;
}

int main(void) {
    if (sodium_init() < 0) { printf("sodium_init failed\n"); return 1; }

    /* accept / advance / backfill / replay */
    sn_replay_window w; memset(&w, 0, sizeof(w));
    CHECK(sn_replay_test_and_mark(&w, 1) && w.hwm == 1, "seq 1 accepted");
    CHECK(!sn_replay_test_and_mark(&w, 1), "seq 1 replay rejected");
    CHECK(sn_replay_test_and_mark(&w, 100) && w.hwm == 100, "seq 100 accepted");
    CHECK(sn_replay_test_and_mark(&w, 50), "backfill 50 accepted");
    CHECK(!sn_replay_test_and_mark(&w, 50), "backfill 50 replay rejected");

    sn_replay_window w2; memset(&w2, 0, sizeof(w2));
    sn_replay_test_and_mark(&w2, 1000);
    CHECK(!sn_replay_test_and_mark(&w2, 1000 - SN_REPLAY_WINDOW), "offset==window aged out");
    CHECK(sn_replay_test_and_mark(&w2, 1000 - SN_REPLAY_WINDOW + 1), "edge-of-window accepted");

    /* range check */
    CHECK(!sn_in_range(0, 10), "candidate 0 rejected");
    CHECK(!sn_in_range(-5, 10), "negative rejected");
    CHECK(sn_in_range(11, 10), "above hwm accepted");
    CHECK(sn_in_range(1000 - SN_REPLAY_WINDOW, 1000), "exactly window below in range");
    CHECK(!sn_in_range(1000 - SN_REPLAY_WINDOW - 1, 1000), "more than window below rejected");

    /* envelope round trip via sender */
    uint8_t key[32]; memset(key, 0x5A, 32);
    sn_sender snd; sn_sender_init(&snd);
    sn_replay_window rw; memset(&rw, 0, sizeof(rw));
    const uint8_t payload[] = "kcp datagram bytes";
    for (int i = 0; i < 5; i++) {
        uint64_t seq; CHECK(sn_sender_alloc(&snd, &seq), "alloc");
        uint8_t env[64]; size_t env_len;
        CHECK(sn_seal(key, 1, seq, payload, sizeof(payload), env, &env_len) == 0, "seal");
        uint8_t pt[64]; size_t pt_len; uint64_t got;
        CHECK(sn_replay_open(&rw, key, 1, env, env_len, pt, &pt_len, &got) == 1, "open accepted");
        CHECK(got == seq && pt_len == sizeof(payload) && memcmp(pt, payload, pt_len) == 0, "round trip");
    }
    /* replay first datagram (seq 1) */
    {
        uint8_t env[64]; size_t env_len;
        sn_seal(key, 1, 1, payload, sizeof(payload), env, &env_len);
        uint8_t pt[64]; size_t pt_len; uint64_t got;
        CHECK(sn_replay_open(&rw, key, 1, env, env_len, pt, &pt_len, &got) == 0, "replay rejected");
    }

    /* wrong key falls through and leaves window untouched */
    {
        uint8_t wrong[32]; memset(wrong, 0x5B, 32);
        sn_replay_window rw2; memset(&rw2, 0, sizeof(rw2));
        uint8_t env[64]; size_t env_len;
        sn_seal(key, 1, 1, (const uint8_t*)"x", 1, env, &env_len);
        uint8_t pt[64]; size_t pt_len; uint64_t got;
        CHECK(sn_replay_open(&rw2, wrong, 1, env, env_len, pt, &pt_len, &got) == 0, "wrong key falls through");
        CHECK(sn_replay_open(&rw2, key, 1, env, env_len, pt, &pt_len, &got) == 1, "failed open didn't mark");
    }

    /* re-admit seq_full=1 against high hwm falls through (§8.3) */
    {
        sn_replay_window rw3; memset(&rw3, 0, sizeof(rw3)); rw3.hwm = 5000;
        uint8_t env[64]; size_t env_len;
        sn_seal(key, 1, 1, (const uint8_t*)"readmit", 7, env, &env_len);
        uint8_t pt[64]; size_t pt_len; uint64_t got;
        CHECK(sn_replay_open(&rw3, key, 1, env, env_len, pt, &pt_len, &got) == 0, "seq 1 vs hwm 5000 falls through");
    }

    /* sender fail-closed on wrap */
    {
        sn_sender s; sn_sender_init(&s);
        atomic_store(&s.next, UINT64_MAX);
        uint64_t last;
        CHECK(sn_sender_alloc(&s, &last) == 1 && last == UINT64_MAX, "last alloc is MAX");
        uint64_t x;
        CHECK(sn_sender_alloc(&s, &x) == 0, "fail closed past limit");
    }

    CHECK(fuzz_replay_window() == 0, "60k-case differential fuzz, full window state compared");

    if (failures) { printf("%d FAILURE(S)\n", failures); return 1; }
    printf("all replay §8.2-8.4 cases pass\n");
    return 0;
}
