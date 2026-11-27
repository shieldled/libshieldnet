# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
#
# The example device and client (examples/README.md). Standalone:
#
#   cmake -S examples -B build/examples && cmake --build build/examples
#   ctest --test-dir build/examples
cmake_minimum_required(VERSION 3.10)
project(shieldnet_examples C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SHIELDNET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.19) # crypto_kdf_hkdf_sha256_* first shipped in 1.0.19
find_package(Threads REQUIRED)
link_directories(${SODIUM_LIBRARY_DIRS})

include(${SHIELDNET_DIR}/shieldnet.cmake)

# The device needs both roles' sources (SHIELDNET_SOURCES) and the OS port.
add_executable(led_device
    led_device.c
    ${SHIELDNET_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
    ${SHIELDNET_PORT_POSIX_SOURCES}
)
# The client needs only the client sources; the OS port gives it a clock.
add_executable(led_client
    led_client.c
    ${SHIELDNET_CLIENT_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
    ${SHIELDNET_PORT_POSIX_SOURCES}
)
foreach(t led_device led_client)
    target_include_directories(${t} PRIVATE ${SHIELDNET_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(${t} PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
    target_compile_options(${t} PRIVATE -Wall -Wextra)
endforeach()

# led_device <-> led_client over loopback (examples/led_loopback.sh).
enable_testing()
add_test(NAME led_loopback
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/led_loopback.sh
                 $<TARGET_FILE:led_device> $<TARGET_FILE:led_client>)
set_tests_properties(led_loopback PROPERTIES TIMEOUT 60)
