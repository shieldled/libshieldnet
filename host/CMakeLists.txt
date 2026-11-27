# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.10)
project(sn_host C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SHIELDNET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.19) # crypto_kdf_hkdf_sha256_* first shipped in 1.0.19
find_package(Threads REQUIRED)
link_directories(${SODIUM_LIBRARY_DIRS})

include(${SHIELDNET_DIR}/shieldnet.cmake)

# The C client over real UDP: mirror-direction interop and the desktop
# blocking wrapper are the same program, so it is built once.
add_executable(sn_client_host
    sn_client_host.c
    ${SHIELDNET_CLIENT_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
    ${SHIELDNET_PORT_POSIX_SOURCES}
)
target_include_directories(sn_client_host PRIVATE ${SHIELDNET_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_client_host PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_client_host PRIVATE -Wall -Wextra)

add_executable(sn_host
    sn_host.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SHIELDNET_DIR}/src/sn_agent.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/vendor/lz4.c
    ${SHIELDNET_DIR}/port/shieldnet_os_posix.c
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_host PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_host PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_host PRIVATE -Wall -Wextra)

# sn_host <-> sn_client_host over loopback: admission, echo, re-admission and
# the argv/PSK/port refusals. A POSIX sh driver, so it needs no
# build of its own; ctest --test-dir <build>/host runs it.
enable_testing()
add_test(NAME sn_host_loopback
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/sn_host_loopback.sh
                 $<TARGET_FILE:sn_host> $<TARGET_FILE:sn_client_host>)
set_tests_properties(sn_host_loopback PROPERTIES TIMEOUT 120)
