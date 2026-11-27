# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Fail if device-role code takes or derives from a PSK again.
#
# Spec transport 3.2: a device MUST NOT store the PSK. It is given k_dev (and the
# device_id it was derived for) and starts with sn_device_init_kdev; a device
# handed the PSK once derives k_dev with sn_provision_kdev, which lives in
# sn_kdf.h, not in device code. The old sn_device_init took the PSK, so a firmware
# had to keep it in flash to call it at every start. This fails the build if
# either returns:
#   - a device-role source or header names the PSK (the lower-case identifier,
#     or an identifier containing it: SN_PSK_LEN, PSK_LEN, preshared_key),
#     sn_derive_kdev, sn_provision_kdev, or the PSK-to-k_dev HKDF label (a
#     hand-rolled derivation). Comments count too: write "PSK", "PSKs" or
#     "pre-shared key" in prose. The upper-case form is allowed on its own: the
#     character after PSK must not be upper case, a digit or "_", and the one
#     before must not be a letter, digit or "_";
#   - anything under include/, src/ or port/ names sn_device_init (without a
#     suffix): a PSK-taking init reintroduced in another header.
#
# Runs two ways, and must keep working both:
#   ctest --test-dir <build>            (add_test in test/sn/CMakeLists.txt)
#   cmake -P test/sn/no_device_psk.cmake   (CI, no build needed)
#
# cmake -E has no grep, so this is script mode with file(STRINGS ... REGEX).

cmake_minimum_required(VERSION 3.10)

get_filename_component(SN_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

# The device-role sources come from the build itself, so a device source added
# later is covered. A new device-role header must be added to DEVICE_HEADERS by
# hand.
include(${SN_ROOT}/shieldnet.cmake)
set(SN_DEVICE_C "${SN_ROOT}/src/sn_device.c")
if(NOT SHIELDNET_DEVICE_SOURCES)
    message(FATAL_ERROR "no_device_psk: SHIELDNET_DEVICE_SOURCES is empty; "
                        "was it renamed in shieldnet.cmake? This guard would check nothing.")
endif()
set(FOUND_DEVICE_C FALSE)
foreach(f ${SHIELDNET_DEVICE_SOURCES})
    get_filename_component(abs "${f}" ABSOLUTE)
    if(abs STREQUAL SN_DEVICE_C)
        set(FOUND_DEVICE_C TRUE)
    endif()
endforeach()
if(NOT FOUND_DEVICE_C)
    message(FATAL_ERROR "no_device_psk: SHIELDNET_DEVICE_SOURCES does not contain "
                        "src/sn_device.c; this guard would not check the device.")
endif()

set(DEVICE_HEADERS
    "${SN_ROOT}/include/shieldnet/sn_device.h"
    "${SN_ROOT}/include/shieldnet/sn_agent.h"
    "${SN_ROOT}/include/shieldnet/sn_agent_dispatch.h"
    "${SN_ROOT}/include/shieldnet/frame.h"
    "${SN_ROOT}/include/shieldnet/command.h"
    "${SN_ROOT}/port/shieldnet_device.h"
    "${SN_ROOT}/include/shieldnet/command_parse.h"
    "${SN_ROOT}/include/shieldnet/payload_encode_policy.h"
    "${SN_ROOT}/include/shieldnet/pixel_frame_policy.h"
    "${SN_ROOT}/include/shieldnet/command_response_policy.h"
)

set(OFFENDERS "")
foreach(f ${SHIELDNET_DEVICE_SOURCES} ${DEVICE_HEADERS})
    if(NOT EXISTS "${f}")
        message(FATAL_ERROR "no_device_psk: ${f} does not exist; update this guard.")
    endif()
    file(STRINGS "${f}" HITS REGEX "psk|[A-Za-z0-9_]PSK|PSK[A-Z0-9_]|[Pp]re_?[Ss]hared|PRE_?SHARED|sn_derive_kdev|sn_provision_kdev|shieldled/v1/device")
    if(HITS)
        file(RELATIVE_PATH rel "${SN_ROOT}" "${f}")
        list(APPEND OFFENDERS "${rel} (names the PSK or derives k_dev)")
    endif()
endforeach()

file(GLOB_RECURSE TREE
    "${SN_ROOT}/include/*.c" "${SN_ROOT}/include/*.h"
    "${SN_ROOT}/src/*.c" "${SN_ROOT}/src/*.h"
    "${SN_ROOT}/port/*.c" "${SN_ROOT}/port/*.h"
)
foreach(f ${TREE})
    file(STRINGS "${f}" HITS REGEX "sn_device_init([^_]|$)")
    if(HITS)
        file(RELATIVE_PATH rel "${SN_ROOT}" "${f}")
        list(APPEND OFFENDERS "${rel} (names sn_device_init)")
    endif()
endforeach()

if(OFFENDERS)
    string(REPLACE ";" "\n  " PRETTY "${OFFENDERS}")
    message(FATAL_ERROR
        "device-role code takes or derives from a PSK:\n  ${PRETTY}\n"
        "A device is given k_dev, never the PSK (spec transport 3.2): start it "
        "with sn_device_init_kdev, and provision a PSK once with "
        "sn_provision_kdev outside device code. Write \"PSK\" in comments.")
endif()

message(STATUS "no_device_psk: ok")
