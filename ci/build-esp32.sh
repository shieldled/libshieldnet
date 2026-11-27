#!/bin/sh
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Builds the ESP-IDF benchmark apps in bench/ for every target their READMEs
# name: shieldnet-esp32 for esp32, esp32s3 and esp32p4, shieldnet-wifi for esp32
# and esp32s3 (the esp32p4 has no Wi-Fi radio of its own). Build only; nothing is
# flashed. Run from the repository root with ESP-IDF's environment loaded
# (`. $IDF_PATH/export.sh`), or in the espressif/idf image as CI does.
# Build trees go under build/ci-esp32/.
set -eu

out=build/ci-esp32
root=$(pwd)
for spec in shieldnet-esp32:esp32 shieldnet-esp32:esp32s3 shieldnet-esp32:esp32p4 \
            shieldnet-wifi:esp32 shieldnet-wifi:esp32s3; do
    app="${spec%%:*}"; target="${spec##*:}"
    dir="${root}/${out}/${app}-${target}"
    echo "== ${app} for ${target}"
    (cd "bench/${app}" &&
     idf.py -B "${dir}" -D SDKCONFIG="${dir}.sdkconfig" set-target "${target}" >/dev/null &&
     idf.py -B "${dir}" -D SDKCONFIG="${dir}.sdkconfig" build > "${dir}.log" 2>&1) || {
        echo "::error::${app} for ${target} failed"
        tail -40 "${dir}.log" 2>/dev/null || true
        exit 1
    }
done
echo "all ESP-IDF builds pass"
