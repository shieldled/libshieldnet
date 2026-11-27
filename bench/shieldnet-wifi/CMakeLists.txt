# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# ShieldNet over-the-air bandwidth benchmark (ESP-IDF).
#   . $IDF_PATH/export.sh
#   idf.py set-target esp32
#   idf.py menuconfig      # -> "ShieldNet Wi-Fi benchmark" -> SSID/password
#   idf.py build flash monitor
# Credentials come from Kconfig (stored in sdkconfig, which is gitignored here).
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(shieldnet_v3_wifi_bench)
