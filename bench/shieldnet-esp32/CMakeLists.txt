# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# ShieldNet on-device performance/bandwidth benchmark (ESP-IDF).
#   source $IDF_PATH/export.sh
#   idf.py set-target esp32        # or esp32s3 / esp32c3 / esp32p4
#   idf.py build flash monitor
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(shieldnet_v3_bench)
