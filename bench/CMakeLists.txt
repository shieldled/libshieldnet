# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.10)
project(sn_client_bench C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SHIELDNET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
include(${SHIELDNET_DIR}/shieldnet.cmake)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.19) # crypto_kdf_hkdf_sha256_* first shipped in 1.0.19
find_package(Threads REQUIRED)

add_executable(sn_client_bench
    sn_client_bench.c
    ${SHIELDNET_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
    ${SHIELDNET_PORT_POSIX_SOURCES}
)
target_include_directories(sn_client_bench PRIVATE ${SHIELDNET_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_directories(sn_client_bench PRIVATE ${SODIUM_LIBRARY_DIRS})
target_link_libraries(sn_client_bench PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
# -O2: a benchmark built at -O0 measures the compiler, not the code.
target_compile_options(sn_client_bench PRIVATE -Wall -Wextra -O2)
