# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# The library's source list, in one place.
#
# Every consumer used to enumerate these by hand -- test/sn, fuzz and host here,
# and each firmware and application build that embeds the library. Adding one
# source meant editing several files across several repos.
#
# Include this and use the variables; do not copy the list again.
#
#   include(${SHIELDNET_DIR}/shieldnet.cmake)
#   add_executable(app main.c ${SHIELDNET_SOURCES} ${SHIELDNET_VENDOR_SOURCES}
#                       ${SHIELDNET_PORT_POSIX_SOURCES})
#   target_include_directories(app PRIVATE ${SHIELDNET_INCLUDE_DIRS})
#
# Narrow unit tests deliberately keep their own short lists: linking only the
# translation unit under test is what makes a link error a real finding there.

get_filename_component(SHIELDNET_ROOT "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)

# Transport + app layer. Portable C: no ESP-IDF, no lwIP, no FreeRTOS.
#
# The client role links with no OS port and no sn_device.c; the device role needs
# the OS port. SHIELDNET_SOURCES is their union, unchanged for every existing
# consumer.
set(SHIELDNET_CLIENT_SOURCES
    ${SHIELDNET_ROOT}/src/sn_wire.c
    ${SHIELDNET_ROOT}/src/sn_kdf.c
    ${SHIELDNET_ROOT}/src/sn_source.c
    ${SHIELDNET_ROOT}/src/sn_replay.c
    ${SHIELDNET_ROOT}/src/sn_demux.c
    ${SHIELDNET_ROOT}/src/sn_client_wire.c
    ${SHIELDNET_ROOT}/src/sn_client_session.c
    ${SHIELDNET_ROOT}/src/sn_client.c
    ${SHIELDNET_ROOT}/src/sn_app_frame.c
    ${SHIELDNET_ROOT}/src/protocol.c
    ${SHIELDNET_ROOT}/src/crypto.c
    ${SHIELDNET_ROOT}/src/decompress.c
)

set(SHIELDNET_DEVICE_SOURCES
    ${SHIELDNET_ROOT}/src/sn_device.c
    ${SHIELDNET_ROOT}/src/sn_session.c
    ${SHIELDNET_ROOT}/src/sn_agent.c
    ${SHIELDNET_ROOT}/src/sn_agent_dispatch.c
    ${SHIELDNET_ROOT}/src/frame.c
    ${SHIELDNET_ROOT}/src/command.c
)

set(SHIELDNET_SOURCES ${SHIELDNET_CLIENT_SOURCES} ${SHIELDNET_DEVICE_SOURCES})

# Keep this list equal to src/*.c. src/arch/ is headers only (the Xtensa AEAD
# paths) and is reached through the include path, not compiled separately.


set(SHIELDNET_VENDOR_SOURCES
    ${SHIELDNET_ROOT}/vendor/ikcp.c
    ${SHIELDNET_ROOT}/vendor/lz4.c
)

# One per platform; a consumer picks exactly one.
set(SHIELDNET_PORT_POSIX_SOURCES ${SHIELDNET_ROOT}/port/shieldnet_os_posix.c)
set(SHIELDNET_PORT_WIN32_SOURCES ${SHIELDNET_ROOT}/port/shieldnet_os_win32.c)

# include/shieldnet is on the path as well as include/: the pre-sn sources use
# the bare `#include "protocol.h"` form, which the README documents.
set(SHIELDNET_INCLUDE_DIRS
    ${SHIELDNET_ROOT}/include
    ${SHIELDNET_ROOT}/include/shieldnet
    ${SHIELDNET_ROOT}/port
    ${SHIELDNET_ROOT}/vendor
)
