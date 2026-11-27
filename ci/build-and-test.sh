#!/usr/bin/env bash
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# One CI job's build and test, run from the repository root after
# ci/install-deps.sh.
#
#   ci/build-and-test.sh asan    test/sn under ASan + UBSan (abort on UB)
#   ci/build-and-test.sh constants
#                                test/sn at non-default deployment constants
#                                (SN_SEND_QUEUE_MAX, SN_WIRE_MTU, SN_PENDING_SLOTS,
#                                SHIELDNET_MAX_RESPONSE_BODY): tests must derive
#                                their numbers from the constants
#   ci/build-and-test.sh plain   root libraries (shieldnet, shieldnet_client)
#                                + link checks;
#                                test/sn including the TSan targets; host/ and its loopback
#                                test, examples/ and its loopback test, fuzz/ (gcc), bench/
#
# Build trees go under build/ci-<mode>/.
set -euo pipefail

mode="${1:?usage: ci/build-and-test.sh asan|plain|constants}"
out="build/ci-${mode}"
jobs="$(nproc)"
export LD_LIBRARY_PATH="${HOME}/.local/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

# The vendored ikcp.c has four unused-parameter warnings of its own; anything
# else is new and fails the job.
check_warnings() {
    if grep -E 'warning:' "$1" | grep -vE 'vendor/ikcp\.c:[0-9]+:[0-9]+: warning: unused parameter' ; then
        echo "::error::new compiler warnings in $1" >&2
        exit 1
    fi
}

build() { # build <source> <dir> [cmake args...]
    src="$1"; dir="$2"; shift 2
    cmake -S "${src}" -B "${dir}" "$@" >/dev/null
    cmake --build "${dir}" -j"${jobs}" 2>&1 | tee "${dir}.log"
    check_warnings "${dir}.log"
}

case "${mode}" in
asan)
    # The *_tsan targets cannot be built with ASan flags (the two sanitizers
    # are exclusive); the plain job covers them.
    CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g" \
        cmake -S test/sn -B "${out}/test" >/dev/null
    for t in $(cmake --build "${out}/test" --target help | sed -n 's/^\.\.\. //p' \
               | grep -E '_test$' | grep -v tsan); do
        targets="${targets:-} --target ${t}"
    done
    # shellcheck disable=SC2086
    cmake --build "${out}/test" -j"${jobs}" ${targets} 2>&1 | tee "${out}/test.log"
    check_warnings "${out}/test.log"
    ctest --test-dir "${out}/test" -E tsan --output-on-failure
    ;;
constants)
    # One set of values, test/sn only: the root, host/, fuzz/ and bench/ stay at
    # defaults in the plain job. Legal under sn_agent_dispatch.c's assertions
    # (mss 532: a 4096-byte response is 8 segments, 9 x 532 = 4788 <= 6144).
    cmake -S test/sn -B "${out}/test" \
        "-DSN_TEST_DEPLOYMENT_DEFS=SN_SEND_QUEUE_MAX=6144;SN_WIRE_MTU=576;SN_PENDING_SLOTS=4;SHIELDNET_MAX_RESPONSE_BODY=4096" \
        >/dev/null
    for t in $(cmake --build "${out}/test" --target help | sed -n 's/^\.\.\. //p' \
               | grep -E '_test$' | grep -v tsan); do
        targets="${targets:-} --target ${t}"
    done
    # shellcheck disable=SC2086
    cmake --build "${out}/test" -j"${jobs}" ${targets} 2>&1 | tee "${out}/test.log"
    check_warnings "${out}/test.log"
    ctest --test-dir "${out}/test" -E tsan --timeout 120 --output-on-failure
    ;;
plain)
    build . "${out}/root"
    ctest --test-dir "${out}/root" --output-on-failure

    build test/sn "${out}/test"
    ctest --test-dir "${out}/test" -E tsan --output-on-failure
    # TSan maps its shadow memory at fixed addresses, which the 32-bit mmap
    # ASLR of current kernels can collide with ("unexpected memory mapping").
    # Run the TSan targets with randomisation off; the job's container options
    # allow it.
    for t in sn_os_test_tsan sn_promote_race_test_tsan; do
        if setarch "$(uname -m)" -R true 2>/dev/null; then
            setarch "$(uname -m)" -R "${out}/test/${t}"
        else
            "${out}/test/${t}"
        fi
    done

    build host "${out}/host"
    # sn_host <-> sn_client_host over loopback (host/sn_host_loopback.sh)
    ctest --test-dir "${out}/host" --output-on-failure
    build examples "${out}/examples"
    # led_device <-> led_client over loopback (examples/led_loopback.sh)
    ctest --test-dir "${out}/examples" --output-on-failure
    build fuzz "${out}/fuzz"
    build bench "${out}/bench"
    ;;
*)
    echo "unknown mode: ${mode}" >&2
    exit 2
    ;;
esac
