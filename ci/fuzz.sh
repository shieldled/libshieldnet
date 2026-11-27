#!/usr/bin/env bash
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Builds the clang/libFuzzer targets (fuzz/CMakeLists.txt) and runs each for a
# bounded time from an empty corpus. A crash, sanitizer report or timeout fails
# the job; reproducers land in build/ci-fuzz/artifacts/ for upload.
#
#   ci/fuzz.sh [seconds-per-target]     default 60
set -euo pipefail

secs="${1:-60}"
out="build/ci-fuzz"
export LD_LIBRARY_PATH="${HOME}/.local/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

cmake -S fuzz -B "${out}" -DCMAKE_C_COMPILER=clang >/dev/null
cmake --build "${out}" -j"$(nproc)"
mkdir -p "${out}/artifacts"

# target:max_len -- lengths as fuzz/sn_libfuzzer.c and sn_app_fuzz.c recommend.
status=0
for spec in sn_fuzz_app:2048 sn_fuzz_client:256 sn_fuzz_state:256 \
            sn_fuzz_parsers:256 sn_fuzz_sled:512 sn_fuzz_wire:256; do
    t="${spec%%:*}"; len="${spec##*:}"
    mkdir -p "${out}/corpus/${t}"
    echo "== ${t} (${secs}s, max_len=${len})"
    if ! "${out}/${t}" "${out}/corpus/${t}" -max_len="${len}" \
            -max_total_time="${secs}" -timeout=10 -rss_limit_mb=2048 \
            -artifact_prefix="${out}/artifacts/${t}-" -print_final_stats=1 \
            > "${out}/${t}.log" 2>&1; then
        echo "::error::${t} failed"
        tail -40 "${out}/${t}.log"
        status=1
    else
        grep -E 'stat::number_of_executed_units' "${out}/${t}.log" || true
    fi
done
exit "${status}"
