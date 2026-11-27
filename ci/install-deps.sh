#!/bin/sh
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Installs everything the CI jobs need into a stock ubuntu:24.04 container.
#
# Ubuntu 24.04 ships libsodium 1.0.18, and the library needs >= 1.0.19 for
# crypto_kdf_hkdf_sha256_* (CMake refuses anything older), so libsodium is built
# from a pinned, checksummed release into $HOME/.local -- the prefix every
# CMakeLists here already adds to PKG_CONFIG_PATH.
#
# Run as root in the container (CI), or reproduce a job locally with:
#   docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 \
#       sh -c 'ci/install-deps.sh && ci/build-and-test.sh asan'
set -eu

SODIUM_VERSION=1.0.20
SODIUM_SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
PREFIX="${HOME}/.local"

if [ "$(id -u)" -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # libclang-rt-18-dev: clang's ASan/UBSan and libFuzzer runtimes, which the
    # stock clang package does not include.
    apt-get install -y -qq --no-install-recommends \
        build-essential cmake pkg-config ca-certificates curl git python3 \
        clang libclang-rt-18-dev util-linux >/dev/null
fi

if PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig" \
        pkg-config --exact-version="${SODIUM_VERSION}" libsodium 2>/dev/null; then
    echo "libsodium ${SODIUM_VERSION} already in ${PREFIX} (cache hit)"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
tarball="libsodium-${SODIUM_VERSION}.tar.gz"
curl -sSLf --retry 3 -o "${work}/${tarball}" \
    "https://download.libsodium.org/libsodium/releases/${tarball}"
echo "${SODIUM_SHA256}  ${work}/${tarball}" | sha256sum -c -
tar -xzf "${work}/${tarball}" -C "${work}"
cd "${work}/libsodium-${SODIUM_VERSION}"
./configure --prefix="${PREFIX}" --disable-dependency-tracking >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
echo "libsodium ${SODIUM_VERSION} installed in ${PREFIX}"
