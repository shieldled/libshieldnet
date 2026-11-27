/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Vector-driven §4.3 / §8.2 tables.
 *
 * Unlike test_sn_source.c, which hardcodes its own accept/reject sets, this
 * walks the SAME table goshieldnet/v1 walks — generated into sn_vectors.h by
 * test/gen_sn_vectors.py from shieldnet-protocol/vectors/shieldnet-v1-vectors.json.
 * That is what makes it cross-implementation: a divergence between C and Go
 * shows up here rather than on a device.
 *
 * These exist because a source-predicate defect once silently rejected every
 * IPv4 controller and was invisible to the vectors, the Go fuzzer and the
 * differential oracle alike — none of the three ever supplied a v6 or v4-mapped
 * source. */
#include "shieldnet/sn_source.h"
#include "shieldnet/sn_replay.h"
#include "shieldnet/sn_demux.h"
#include "../sn_vectors.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

int main(void) {
    /* §4.3: the receiving interface's prefixes, from the vector file. */
    sn_prefix local[SN_SRC_LOCAL_N];
    for (size_t i = 0; i < SN_SRC_LOCAL_N; i++) {
        memcpy(local[i].a16, sn_src_local_a16[i], 16);
        local[i].is_v4 = sn_src_local_is_v4[i];
        local[i].bits  = sn_src_local_bits[i];
    }

    for (size_t i = 0; i < SN_SRC_CASE_N; i++) {
        int got = sn_source_rejected(sn_src_case_is_v4[i], sn_src_case_a16[i],
                                     local, SN_SRC_LOCAL_N) ? 1 : 0;
        if (got != sn_src_case_rejected[i]) {
            printf("FAIL source[%zu] %s: got reject=%d want %d\n",
                   i, sn_src_case_name[i], got, sn_src_case_rejected[i]);
            failures++;
        } else {
            printf("ok   source %s (%s)\n", sn_src_case_name[i],
                   sn_src_case_rejected[i] ? "reject" : "accept");
        }
    }

    /* §4.3: canonical_source pins RFC 4291 §2.5.5.2's mapped form and the port. */
    uint8_t canon[18];
    sn_canonical_source(sn_src_case_a16[8] /* v4 rfc1918 peer */, 5000, canon);
    if (memcmp(canon, sn_canon_v4, 18) != 0) {
        printf("FAIL canonical_source v4\n");
        failures++;
    } else {
        printf("ok   canonical_source v4\n");
    }
    {
        uint8_t v6[16];
        memset(v6, 0, 16);
        v6[0] = 0xfe; v6[1] = 0x80; v6[15] = 0x02; /* fe80::2 */
        sn_canonical_source(v6, 5000, canon);
        if (memcmp(canon, sn_canon_v6, 18) != 0) {
            printf("FAIL canonical_source v6\n");
            failures++;
        } else {
            printf("ok   canonical_source v6\n");
        }
    }

    /* §8.2: one scripted sequence against a fresh window, including the
     * offset-255/256 boundary. */
    {
        sn_replay_window w;
        memset(&w, 0, sizeof(w));
        for (size_t i = 0; i < SN_REPLAY_N; i++) {
            int got = sn_replay_test_and_mark(&w, sn_replay_seq[i]) ? 1 : 0;
            if (got != sn_replay_accept[i]) {
                printf("FAIL replay[%zu] seq=%llu: got accept=%d want %d\n",
                       i, (unsigned long long)sn_replay_seq[i], got,
                       sn_replay_accept[i]);
                failures++;
            } else {
                printf("ok   replay seq=%llu (%s)\n",
                       (unsigned long long)sn_replay_seq[i],
                       sn_replay_accept[i] ? "accept" : "reject");
            }
        }
    }

    /* §3/§5: classification for malformed and hostile datagrams.
     *
     * ASYMMETRY, deliberate and worth stating: the vector file also carries a
     * "decodes" column, and only goshieldnet asserts it. This library has no
     * standalone length-checked decoders — validation lives inside
     * sn_device_handle_init/finish, which need a live device and mutate state on
     * a valid FINISH. Classification is the part both sides can check against the
     * same table, and it is where §5's direction and reserved-type rules live. */
    for (size_t i = 0; i < SN_WIRE_CASE_N; i++) {
        const uint8_t *d = sn_wire_blob + sn_wire_off[i];
        size_t n = sn_wire_len[i];
        sn_class got = sn_classify_datagram((sn_role)sn_wire_role[i], d, n);
        if ((int)got != sn_wire_cls[i]) {
            printf("FAIL wire[%zu] %s: class=%d want %d\n",
                   i, sn_wire_name[i], (int)got, sn_wire_cls[i]);
            failures++;
        } else {
            printf("ok   wire %s (class %d)\n", sn_wire_name[i], (int)got);
        }
    }

    /* §8.2/§8.3: reconstruct the candidate, then the window range check. */
    for (size_t i = 0; i < SN_RECON_RANGE_N; i++) {
        const struct sn_recon_range_case *rc = &sn_recon_range[i];
        int64_t cand = sn_reconstruct(rc->seq_wire, rc->hwm);
        int in = !!sn_in_range(cand, rc->hwm);
        if (cand != rc->candidate || in != rc->in_range) {
            printf("FAIL reconstruct_range[%zu]: seq_wire=%u hwm=%llu cand=%lld in_range=%d"
                   " want %lld/%d\n", i, rc->seq_wire, rc->hwm, (long long)cand, in,
                   rc->candidate, rc->in_range);
            failures++;
        } else {
            printf("ok   reconstruct_range[%zu] (cand %lld, in_range %d)\n",
                   i, (long long)cand, in);
        }
    }

    printf(failures ? "\n%d FAILURES\n" : "\nall table vectors agree\n", failures);
    return failures ? 1 : 0;
}
