# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
# Root build for libshieldnet as a standalone library.
#
# This is a library a third party embeds, and a repo that cannot be
# built without copying a source list out of someone else's test directory is
# not embeddable. A client embedder links shieldnet_client; a device embedder
# links shieldnet (and sets SHIELDNET_MAX_RESPONSE_BODY if its extension's
# replies are larger than DEVICE_INFO). These targets are for host and POSIX consumers; ESP-IDF components keep using
# idf_component_register and take their file list from shieldnet.cmake.
cmake_minimum_required(VERSION 3.10)
project(shieldnet VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(${CMAKE_CURRENT_LIST_DIR}/shieldnet.cmake)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.19) # crypto_kdf_hkdf_sha256_* first shipped in 1.0.19
find_package(Threads REQUIRED)

# The client role: no device sources, no OS port. Always built.
add_library(shieldnet_client STATIC
    ${SHIELDNET_CLIENT_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
)
target_include_directories(shieldnet_client PUBLIC ${SHIELDNET_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_directories(shieldnet_client PUBLIC ${SODIUM_LIBRARY_DIRS})
target_link_libraries(shieldnet_client PUBLIC ${SODIUM_LIBRARIES})
# vendor/ikcp.c and vendor/lz4.c are third-party; keep our own set strict but do
# not fail the build on theirs.
# There is no -Werror, so their warnings stay visible without failing the build.
target_compile_options(shieldnet_client PRIVATE -Wall -Wextra)

# Both roles. SHIELDNET_MAX_RESPONSE_BODY (port/shieldnet_device.h) is the
# largest response body the device sends; empty keeps the default, DEVICE_INFO's
# maximum. It must have the same value in every translation unit, so setting it
# here defines it PUBLIC: a consumer that links shieldnet gets it too.
set(SHIELDNET_MAX_RESPONSE_BODY "" CACHE STRING
    "Largest response body the device sends, in bytes (empty = default)")
# The OS port: Win32 on Windows (MinGW-w64 or MSVC), POSIX everywhere else.
if(WIN32)
    set(SHIELDNET_PORT_SOURCES ${SHIELDNET_PORT_WIN32_SOURCES})
else()
    set(SHIELDNET_PORT_SOURCES ${SHIELDNET_PORT_POSIX_SOURCES})
endif()
add_library(shieldnet STATIC
    ${SHIELDNET_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
    ${SHIELDNET_PORT_SOURCES}
)
if(NOT "${SHIELDNET_MAX_RESPONSE_BODY}" STREQUAL "")
    target_compile_definitions(shieldnet PUBLIC SHIELDNET_MAX_RESPONSE_BODY=${SHIELDNET_MAX_RESPONSE_BODY})
endif()
target_include_directories(shieldnet PUBLIC ${SHIELDNET_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_directories(shieldnet PUBLIC ${SODIUM_LIBRARY_DIRS})
target_link_libraries(shieldnet PUBLIC ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(shieldnet PRIVATE -Wall -Wextra)

enable_testing()
# An archive never resolves symbols, so a target that only builds shieldnet.a
# cannot fail when the source list is incomplete -- which is exactly how
# src/frame.c went missing from it, with a clean build as the evidence it had
# not. This links, so an omission fails here instead of in a consumer's build.
add_executable(shieldnet_link_check ${CMAKE_CURRENT_LIST_DIR}/test/link_check.c)
target_link_libraries(shieldnet_link_check PRIVATE shieldnet)
add_test(NAME shieldnet_link_check COMMAND shieldnet_link_check)

# The client role's archive must link on its own: no sn_device.c, no OS port.
# shieldnet_link_check above links the union, so an accidental dependency of a
# client source on a device source would hide there. This links the
# shieldnet_client archive, so a client source that needs a device source fails
# here.
add_executable(shieldnet_client_link_check ${CMAKE_CURRENT_LIST_DIR}/test/client_link_check.c)
target_link_libraries(shieldnet_client_link_check PRIVATE shieldnet_client)
target_compile_options(shieldnet_client_link_check PRIVATE -Wall -Wextra)
add_test(NAME shieldnet_client_link_check COMMAND shieldnet_client_link_check)

# Client-side protocol helpers (PIXEL_FRAME header encoder, DEVICE_INFO geometry
# decoder). Lives here and not in POSIX-only test/sn so the Windows job can run it.
# Links the client set and vendor code only: no OS port, no device sources.
add_executable(sn_encoders
    ${CMAKE_CURRENT_LIST_DIR}/test/portable/test_sn_encoders.c
    ${SHIELDNET_CLIENT_SOURCES}
    ${SHIELDNET_VENDOR_SOURCES}
)
target_include_directories(sn_encoders PRIVATE ${SHIELDNET_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_directories(sn_encoders PRIVATE ${SODIUM_LIBRARY_DIRS})
target_link_libraries(sn_encoders PRIVATE ${SODIUM_LIBRARIES})
target_compile_options(sn_encoders PRIVATE -Wall -Wextra)
add_test(NAME sn_encoders COMMAND sn_encoders)
