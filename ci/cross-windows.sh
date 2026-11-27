#!/bin/sh
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Cross-compiles the library for 64-bit Windows with MinGW-w64 and runs, under
# Wine, the root build's tests (the link checks and the portable encoder test)
# and the whole test suite (test/sn) on the Win32 OS port. Run as root
# in a stock ubuntu:24.04 container, from the repository root:
#
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 sh ci/cross-windows.sh
#
# libsodium is built for Windows from the same pinned, checksummed release
# ci/install-deps.sh uses, statically (SODIUM_STATIC).
set -eu

SODIUM_VERSION=1.0.20
SODIUM_SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
HOST=x86_64-w64-mingw32
PREFIX=/opt/sodium-mingw
out=build/ci-windows

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64 cmake make pkg-config \
    ca-certificates curl wine wine64 >/dev/null

work=$(mktemp -d)
tarball="libsodium-${SODIUM_VERSION}.tar.gz"
curl -sSLf --retry 3 -o "${work}/${tarball}" \
    "https://download.libsodium.org/libsodium/releases/${tarball}"
echo "${SODIUM_SHA256}  ${work}/${tarball}" | sha256sum -c -
tar -xzf "${work}/${tarball}" -C "${work}"
(cd "${work}/libsodium-stable" 2>/dev/null || cd "${work}/libsodium-${SODIUM_VERSION}"
 ./configure --host="${HOST}" --prefix="${PREFIX}" --disable-shared --enable-static \
     --disable-dependency-tracking >/dev/null
 make -s -j"$(nproc)" >/dev/null && make -s install >/dev/null)

export WINEDEBUG=-all WINEPREFIX="${work}/wine"
export PKG_CONFIG_LIBDIR="${PREFIX}/lib/pkgconfig"
# Create the Wine prefix once: tests started in parallel would race to create it.
wine wineboot --init >/dev/null 2>&1
# The POSIX thread model (winpthreads): the tests use <pthread.h>; the library
# itself uses only the Win32 port. Static, so Wine needs no MinGW DLLs.
for src in . test/sn; do
    dir="${out}/$(echo "${src}" | tr / -)"
    cmake -S "${src}" -B "${dir}" \
        -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_C_COMPILER="${HOST}-gcc-posix" \
        -DCMAKE_C_FLAGS="-DSODIUM_STATIC" -DCMAKE_EXE_LINKER_FLAGS="-static" \
        -DCMAKE_CROSSCOMPILING_EMULATOR=wine
    cmake --build "${dir}" -j"$(nproc)"
    ctest --test-dir "${dir}" --output-on-failure -j"$(nproc)"
done
