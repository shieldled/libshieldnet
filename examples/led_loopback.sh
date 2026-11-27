#!/bin/sh
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# led_device <-> led_client over loopback. Registered with ctest by
# examples/CMakeLists.txt; runnable by hand too:
#
#   sh examples/led_loopback.sh <path/to/led_device> <path/to/led_client>
#
# Starts led_device -same-host on 127.0.0.1 with a fresh random PSK in a 0600
# file, runs led_client -same-host against it, and checks that the client saw
# the geometry and a STATUS counting every frame, and that the device printed
# each frame with the right colour. Then checks that the default is strict:
# without -same-host the client refuses 127.0.0.1 (exit 2), and a strict device
# never admits a loopback client (the client exits 1). Every child runs under a
# watchdog and the devices are killed on every exit path.
#
# POSIX sh only: no bash, no coreutils timeout(1).
set -u

DEV_BIN=${1:?usage: led_loopback.sh <led_device> <led_client>}
CLI_BIN=${2:?usage: led_loopback.sh <led_device> <led_client>}
ID=0102030405060708

failures=0
pids=
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/led_loopback.XXXXXX") || exit 1

cleanup() {
    for p in ${pids}; do kill "${p}" 2>/dev/null; wait "${p}" 2>/dev/null; done
    rm -rf "${work}"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

ok()   { echo "ok   $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }
check() { # check <message> <command...>
    msg=$1; shift
    if "$@"; then ok "${msg}"; else fail "${msg}"; fi
}
show() { echo "---- $1"; cat "$1"; echo "----"; }

# run_limited <limit-s> <out> <err> <command...>: run it, kill it after
# <limit-s>, set rc to its exit status (>128 if killed). A poll loop in this
# shell, not a background subshell that would inherit the EXIT trap.
run_limited() {
    limit=$1; out=$2; err=$3; shift 3
    "$@" >"${out}" 2>"${err}" </dev/null &
    pid=$!
    ticks=0
    while kill -0 "${pid}" 2>/dev/null; do
        if [ "${ticks}" -ge $((limit * 10)) ]; then
            echo "     (timed out after ${limit}s: $*)"
            kill "${pid}" 2>/dev/null
            break
        fi
        sleep 0.1
        ticks=$((ticks + 1))
    done
    wait "${pid}"
    rc=$?
}

# start_device <name> [-same-host]: start led_device on 127.0.0.1, an ephemeral
# port, and set port to the port it printed.
start_device() {
    name=$1; shift
    SHIELDNET_PSK_FILE="${psk}" "${DEV_BIN}" "$@" 127.0.0.1 0 "${ID}" \
        >"${work}/${name}.out" 2>"${work}/${name}.err" </dev/null &
    pids="${pids} $!"
    port=
    i=0
    while [ "${i}" -lt 100 ] && [ -z "${port}" ]; do
        sleep 0.1
        port=$(sed -n 's/^listening on 127\.0\.0\.1:\([0-9][0-9]*\)$/\1/p' "${work}/${name}.out")
        i=$((i + 1))
    done
    if [ -z "${port}" ]; then
        fail "${name}: led_device printed its port"
        show "${work}/${name}.out"; show "${work}/${name}.err"
        exit 1
    fi
}

psk="${work}/psk"
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' >"${psk}"

# ── the happy path, -same-host on both ends ──
start_device dev -same-host
ok "led_device -same-host listening on 127.0.0.1:${port}"
run_limited 20 "${work}/c.out" "${work}/c.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLI_BIN}" -same-host 127.0.0.1 "${port}" "${ID}" 00ff80
check "client exits 0" test "${rc}" -eq 0
check "client printed the geometry" \
    grep -qx 'device: 4 strips x 16 LEDs, 3 bytes per LED, envelope 4096' "${work}/c.out"
check "client saw STATUS count all 5 frames" \
    grep -q 'device reports 5 frames, 0 dropped, mode 1' "${work}/c.out"
check "device printed 5 frames of #00ff80" \
    test "$(grep -c '^frame [1-5]: 64 pixels, first #00ff80$' "${work}/dev.out")" -eq 5
[ "${rc}" -eq 0 ] || { show "${work}/c.out"; show "${work}/c.err"; show "${work}/dev.out"; }

# ── a second client takes over from the first ──
run_limited 20 "${work}/c2.out" "${work}/c2.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLI_BIN}" -same-host 127.0.0.1 "${port}" "${ID}" 102030
check "second client exits 0" test "${rc}" -eq 0
check "device printed the second client's frames" \
    grep -q '^frame 5: 64 pixels, first #102030$' "${work}/dev.out"

# ── strict by default ──
run_limited 10 "${work}/s.out" "${work}/s.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLI_BIN}" 127.0.0.1 "${port}" "${ID}" ff0000
check "client without -same-host refuses 127.0.0.1 (exit 2)" test "${rc}" -eq 2

start_device strict
run_limited 20 "${work}/s2.out" "${work}/s2.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLI_BIN}" -same-host 127.0.0.1 "${port}" "${ID}" ff0000
check "a strict device never admits a loopback client (client exits 1)" test "${rc}" -eq 1
check "the strict device started no session" test ! -s "${work}/strict.err" -a \
    "$(grep -c 'session started' "${work}/strict.out")" -eq 0

if [ "${failures}" -ne 0 ]; then
    show "${work}/dev.err"
    echo "${failures} FAILURES"
    exit 1
fi
echo "all led_device / led_client loopback cases pass"
exit 0
