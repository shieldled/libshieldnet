# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.10)
project(sn_oracle C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The library root is one level up from fuzz/.
set(SHIELDNET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.19) # crypto_kdf_hkdf_sha256_* first shipped in 1.0.19
link_directories(${SODIUM_LIBRARY_DIRS})

add_executable(sn_oracle
    sn_oracle.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_client_wire.c
)
target_include_directories(sn_oracle PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_oracle PRIVATE ${SODIUM_LIBRARIES})
# Sanitizers are the point of building this, not an extra. The differential
# harness only detects *disagreement*: a memory-safety bug in the C -- an
# overread in sn_classify on a malformed length, say -- yields the same verdict
# as correct code and passes silently. ASan/UBSan turn the same harness into a
# memory-safety fuzzer for the C side.
#
# -fno-sanitize-recover makes UBSan abort rather than log and continue, so the
# Go harness sees a dead pipe instead of quietly comparing verdicts produced
# after undefined behaviour.
option(ORACLE_SANITIZE "build the oracle with ASan+UBSan" ON)
if(ORACLE_SANITIZE)
    target_compile_options(sn_oracle PRIVATE
        -Wall -Wextra -O1 -g -fno-omit-frame-pointer
        -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_link_options(sn_oracle PRIVATE -fsanitize=address,undefined)
else()
    target_compile_options(sn_oracle PRIVATE -Wall -Wextra -O2)
endif()

# Sequence fuzzer for the admission/promotion state machine. Reads a program of
# operations on stdin; the harness supplies the cryptographically valid steps
# because a fuzzer cannot synthesise a FINISH, and the fuzzer supplies the order.
add_executable(sn_client_fuzz
    sn_client_fuzz.c
    ${SHIELDNET_DIR}/src/sn_client.c
    ${SHIELDNET_DIR}/src/sn_client_wire.c
    ${SHIELDNET_DIR}/src/sn_client_session.c
    ${SHIELDNET_DIR}/src/sn_app_frame.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SHIELDNET_DIR}/vendor/ikcp.c
    ${SHIELDNET_DIR}/vendor/lz4.c
    ${SHIELDNET_DIR}/port/shieldnet_os_posix.c
)
target_include_directories(sn_client_fuzz PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_client_fuzz PRIVATE ${SODIUM_LIBRARIES} pthread)
if(ORACLE_SANITIZE)
    target_compile_options(sn_client_fuzz PRIVATE
        -Wall -Wextra -O1 -g -fno-omit-frame-pointer
        -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_link_options(sn_client_fuzz PRIVATE -fsanitize=address,undefined)
endif()

add_executable(sn_state_fuzz
    sn_state_fuzz.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/vendor/ikcp.c
    ${SHIELDNET_DIR}/port/shieldnet_os_posix.c
)
target_include_directories(sn_state_fuzz PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/test/sn   # client_helper.h
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_state_fuzz PRIVATE ${SODIUM_LIBRARIES} pthread)
if(ORACLE_SANITIZE)
    target_compile_options(sn_state_fuzz PRIVATE
        -Wall -Wextra -O1 -g -fno-omit-frame-pointer
        -fsanitize=address,undefined -fno-sanitize-recover=all)
    target_link_options(sn_state_fuzz PRIVATE -fsanitize=address,undefined)
else()
    target_compile_options(sn_state_fuzz PRIVATE -Wall -Wextra -O2)
endif()

# ── libFuzzer targets (clang only) ────────────────────────────────────────────
# These instrument the C directly, so coverage feedback actually reflects this
# code. The Go-driven harnesses cannot: Go's engine instruments the Go binary
# and is blind to what the C reaches. Built only when the compiler is clang.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    # Sequence fuzzing, coverage-guided. Same runner as the stdin binary, but
    # in-process so libFuzzer sees which protocol orderings reach new branches.
    add_executable(sn_fuzz_state
        sn_state_fuzz.c
        ${SHIELDNET_DIR}/src/sn_demux.c
        ${SHIELDNET_DIR}/src/sn_source.c
        ${SHIELDNET_DIR}/src/sn_replay.c
        ${SHIELDNET_DIR}/src/sn_wire.c
        ${SHIELDNET_DIR}/src/sn_kdf.c
        ${SHIELDNET_DIR}/src/sn_device.c
        ${SHIELDNET_DIR}/src/sn_session.c
        ${SHIELDNET_DIR}/vendor/ikcp.c
        ${SHIELDNET_DIR}/port/shieldnet_os_posix.c)
    target_include_directories(sn_fuzz_state PRIVATE
        ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
        ${SHIELDNET_DIR}/test/sn   # client_helper.h, as for sn_state_fuzz
        ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
    target_compile_definitions(sn_fuzz_state PRIVATE SN_STATE_LIBFUZZER=1)
    target_compile_options(sn_fuzz_state PRIVATE
        -Wall -Wextra -O1 -g -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
    target_link_options(sn_fuzz_state PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(sn_fuzz_state PRIVATE ${SODIUM_LIBRARIES} pthread)

    # The client state machine, coverage-guided. sn_client_fuzz.c has carried a
    # SN_CLIENT_LIBFUZZER entry point all along; nothing built it.
    add_executable(sn_fuzz_client
        sn_client_fuzz.c
        ${SHIELDNET_DIR}/src/sn_client.c
        ${SHIELDNET_DIR}/src/sn_client_wire.c
        ${SHIELDNET_DIR}/src/sn_client_session.c
        ${SHIELDNET_DIR}/src/sn_app_frame.c
        ${SHIELDNET_DIR}/src/protocol.c
        ${SHIELDNET_DIR}/src/crypto.c
        ${SHIELDNET_DIR}/src/decompress.c
        ${SHIELDNET_DIR}/src/sn_device.c
        ${SHIELDNET_DIR}/src/sn_session.c
        ${SHIELDNET_DIR}/src/sn_demux.c
        ${SHIELDNET_DIR}/src/sn_kdf.c
        ${SHIELDNET_DIR}/src/sn_wire.c
        ${SHIELDNET_DIR}/src/sn_source.c
        ${SHIELDNET_DIR}/src/sn_replay.c
        ${SHIELDNET_DIR}/vendor/ikcp.c
        ${SHIELDNET_DIR}/vendor/lz4.c
        ${SHIELDNET_DIR}/port/shieldnet_os_posix.c)
    target_include_directories(sn_fuzz_client PRIVATE
        ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
        ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
    target_compile_definitions(sn_fuzz_client PRIVATE SN_CLIENT_LIBFUZZER=1)
    target_compile_options(sn_fuzz_client PRIVATE
        -Wall -Wextra -O1 -g -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
    target_link_options(sn_fuzz_client PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(sn_fuzz_client PRIVATE ${SODIUM_LIBRARIES} pthread)

    # What an admitted peer reaches past the AEAD: KCP input with the lowered
    # rcv_wnd, the app-layer open, and the command core against device ops that
    # abort on any contract violation. See sn_app_fuzz.c.
    add_executable(sn_fuzz_app
        sn_app_fuzz.c
        ${SHIELDNET_DIR}/src/sn_app_frame.c
        ${SHIELDNET_DIR}/src/command.c
        ${SHIELDNET_DIR}/src/frame.c
        ${SHIELDNET_DIR}/src/protocol.c
        ${SHIELDNET_DIR}/src/crypto.c
        ${SHIELDNET_DIR}/src/decompress.c
        ${SHIELDNET_DIR}/vendor/ikcp.c
        ${SHIELDNET_DIR}/vendor/lz4.c)
    target_include_directories(sn_fuzz_app PRIVATE
        ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
        ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
    target_compile_options(sn_fuzz_app PRIVATE
        -Wall -Wextra -O1 -g -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
    target_link_options(sn_fuzz_app PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(sn_fuzz_app PRIVATE ${SODIUM_LIBRARIES})

    foreach(spec "sn_fuzz_wire;1" "sn_fuzz_parsers;2" "sn_fuzz_sled;3")
        list(GET spec 0 tgt)
        list(GET spec 1 which)
        add_executable(${tgt} sn_libfuzzer.c
            ${SHIELDNET_DIR}/src/sn_demux.c
            ${SHIELDNET_DIR}/src/sn_source.c
            ${SHIELDNET_DIR}/src/sn_wire.c)
        target_include_directories(${tgt} PRIVATE
            ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
            ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
        target_compile_definitions(${tgt} PRIVATE FUZZ_TARGET=${which})
        target_compile_options(${tgt} PRIVATE
            -Wall -Wextra -O1 -g -fno-omit-frame-pointer
            -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all)
        target_link_options(${tgt} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_libraries(${tgt} PRIVATE ${SODIUM_LIBRARIES})
    endforeach()
endif()
