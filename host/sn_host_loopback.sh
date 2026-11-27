#!/bin/sh
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# sn_host <-> sn_client_host over loopback. Registered with ctest by
# host/CMakeLists.txt; runnable by hand too:
#
#   sh host/sn_host_loopback.sh <path/to/sn_host> <path/to/sn_client_host>
#
# Starts sn_host on an ephemeral port with a fresh random PSK in a 0600 file and
# the app-echo agent on, then checks that the client is admitted and gets its
# message echoed, that a second client is admitted over the first (re-admission,
# §8.5), and that the tools refuse what they must refuse: a PSK on argv, a
# malformed PSK, an out-of-range port (exit 2), and a wrong PSK (exit 1,
# "attempt failed"). Every child runs under a watchdog and sn_host is killed on
# every exit path, so a regression fails the test instead of hanging it.
#
# POSIX sh only: no bash, no coreutils timeout(1).
set -u

HOST_BIN=${1:?usage: sn_host_loopback.sh <sn_host> <sn_client_host>}
CLIENT_BIN=${2:?usage: sn_host_loopback.sh <sn_host> <sn_client_host>}
DEV=0102030405060708

failures=0
host_pid=
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/sn_host_loopback.XXXXXX") || exit 1

cleanup() {
    if [ -n "${host_pid}" ]; then
        kill "${host_pid}" 2>/dev/null
        wait "${host_pid}" 2>/dev/null
    fi
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
show() { # dump a captured stream after a failure
    echo "---- $1"; cat "$1"; echo "----"
}

# 32 random bytes as 64 lowercase hex chars.
randhex() {
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
}

# run_limited <limit-s> <hold-s> <out> <err> <command...>
# Runs the command with stdin a pipe that stays open <hold-s> seconds (the
# client reads stdin until EOF and only then exits), stdout/stderr captured,
# and kills it after <limit-s>. Sets rc to its exit status (>128 if killed).
# The watchdog is a poll loop in this shell, not a background subshell: a
# forked copy of this shell would carry the EXIT trap, and a signal landing in
# one could run cleanup() -- killing sn_host -- in the middle of the test.
run_limited() {
    limit=$1; hold=$2; out=$3; err=$4; shift 4
    sleep "${hold}" | "$@" >"${out}" 2>"${err}" &
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
    return 0
}

psk="${work}/psk"
randhex >"${psk}"
chmod 600 "${psk}"
check "PSK file is 64 hex chars" test "$(tr -d '\n' <"${psk}" | wc -c | tr -d ' ')" = 64

# ── start the device ──
SHIELDNET_PSK_FILE="${psk}" SHIELDNET_APP_ECHO=1 \
    "${HOST_BIN}" 0 "${DEV}" >"${work}/host.out" 2>"${work}/host.err" </dev/null &
host_pid=$!

port=
i=0
while [ "${i}" -lt 100 ]; do
    port=$(sed -n 's/^PORT \([0-9][0-9]*\)$/\1/p' "${work}/host.out")
    [ -n "${port}" ] && break
    kill -0 "${host_pid}" 2>/dev/null || break
    sleep 0.1
    i=$((i + 1))
done
if [ -z "${port}" ]; then
    fail "sn_host printed PORT <n>"
    show "${work}/host.out"; show "${work}/host.err"
    exit 1
fi
ok "sn_host listening on 127.0.0.1:${port}"

# ── admission + echo ──
run_limited 20 2 "${work}/c1.out" "${work}/c1.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLIENT_BIN}" 127.0.0.1 "${port}" "${DEV}" hello
check "client exits 0" test "${rc}" -eq 0
check "client printed ADMITTED" grep -qx ADMITTED "${work}/c1.out"
check "client got its 5-byte message echoed (RECV 0 5)" grep -qx 'RECV 0 5' "${work}/c1.out"
[ "${rc}" -eq 0 ] && grep -qx 'RECV 0 5' "${work}/c1.out" || { show "${work}/c1.out"; show "${work}/c1.err"; }

# ── a second client replaces the first (re-admission, §8.5) ──
run_limited 20 2 "${work}/c2.out" "${work}/c2.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLIENT_BIN}" 127.0.0.1 "${port}" "${DEV}" hello
check "re-admission: client exits 0" test "${rc}" -eq 0
check "re-admission: client printed ADMITTED" grep -qx ADMITTED "${work}/c2.out"
[ "${rc}" -eq 0 ] || { show "${work}/c2.out"; show "${work}/c2.err"; }

# ── refusals ──
hexpsk=$(cat "${psk}")

run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    "${HOST_BIN}" 0 "${DEV}" "${hexpsk}"
check "sn_host refuses a PSK on argv (exit 2)" test "${rc}" -eq 2

run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    "${CLIENT_BIN}" 127.0.0.1 "${port}" "${hexpsk}"
check "sn_client_host refuses a PSK on argv (exit 2)" test "${rc}" -eq 2

bad="${work}/bad_psk"
printf '%s\n' "zz$(randhex | cut -c3-)" >"${bad}"
chmod 600 "${bad}"
run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    env SHIELDNET_PSK_FILE="${bad}" "${HOST_BIN}" 0 "${DEV}"
check "sn_host refuses a malformed PSK (exit 2)" test "${rc}" -eq 2
run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    env SHIELDNET_PSK_FILE="${bad}" "${CLIENT_BIN}" 127.0.0.1 "${port}" "${DEV}" hello
check "sn_client_host refuses a malformed PSK (exit 2)" test "${rc}" -eq 2

short="${work}/short_psk"
randhex | cut -c2- >"${short}"
chmod 600 "${short}"
run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    env SHIELDNET_PSK_FILE="${short}" "${HOST_BIN}" 0 "${DEV}"
check "sn_host refuses a 63-char PSK (exit 2)" test "${rc}" -eq 2

run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${HOST_BIN}" 65536 "${DEV}"
check "sn_host refuses port 65536 (exit 2)" test "${rc}" -eq 2
run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLIENT_BIN}" 127.0.0.1 65536 "${DEV}" hello
check "sn_client_host refuses port 65536 (exit 2)" test "${rc}" -eq 2
run_limited 10 0 "${work}/n.out" "${work}/n.err" \
    env SHIELDNET_PSK_FILE="${psk}" "${CLIENT_BIN}" 127.0.0.1 0 "${DEV}" hello
check "sn_client_host refuses port 0 (exit 2)" test "${rc}" -eq 2

# ── a wrong PSK: the device drops the INIT, the client gives up ──
wrong="${work}/wrong_psk"
randhex >"${wrong}"
chmod 600 "${wrong}"
run_limited 20 0 "${work}/w.out" "${work}/w.err" \
    env SHIELDNET_PSK_FILE="${wrong}" "${CLIENT_BIN}" 127.0.0.1 "${port}" "${DEV}" hello
check "wrong PSK: client exits 1" test "${rc}" -eq 1
check "wrong PSK: client reports 'attempt failed'" grep -q 'attempt failed' "${work}/w.err"
check "wrong PSK: client never printed ADMITTED" test ! -s "${work}/w.out"
[ "${rc}" -eq 1 ] || { show "${work}/w.out"; show "${work}/w.err"; }

check "sn_host is still running after all of it" kill -0 "${host_pid}"

if [ "${failures}" -ne 0 ]; then
    show "${work}/host.err"
    echo "${failures} FAILURES"
    exit 1
fi
echo "all sn_host loopback cases pass"
exit 0
