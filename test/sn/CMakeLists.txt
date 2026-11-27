# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.10)
project(sn_kdf_test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# The library root is two levels up from test/sn/.
set(SHIELDNET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "$ENV{HOME}/.local/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.19) # crypto_kdf_hkdf_sha256_* first shipped in 1.0.19
link_directories(${SODIUM_LIBRARY_DIRS})
find_package(Threads REQUIRED)

# The OS port under test: Win32 on Windows (ci/cross-windows.sh), POSIX elsewhere.
# ThreadSanitizer targets are built only where TSan exists (not on Windows).
if(WIN32)
    set(SN_TEST_OS_PORT ${SHIELDNET_DIR}/port/shieldnet_os_win32.c)
    set(SN_TSAN OFF)
else()
    set(SN_TEST_OS_PORT ${SHIELDNET_DIR}/port/shieldnet_os_posix.c)
    set(SN_TSAN ON)
endif()

add_executable(sn_kdf_test
    test_sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
)
add_executable(sn_source_test
    test_sn_source.c
    ${SHIELDNET_DIR}/src/sn_source.c
)
target_include_directories(sn_source_test PRIVATE ${SHIELDNET_DIR}/include)
target_compile_options(sn_source_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_pts_test test_sn_pts.c)
target_include_directories(sn_pts_test PRIVATE ${SHIELDNET_DIR}/include)
target_compile_options(sn_pts_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_tables_test
    test_sn_tables.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_demux.c
)
target_include_directories(sn_tables_test PRIVATE ${SHIELDNET_DIR}/include ${SODIUM_INCLUDE_DIRS})
target_compile_options(sn_tables_test PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(sn_tables_test PRIVATE ${SODIUM_LIBRARIES})
target_link_directories(sn_tables_test PRIVATE ${SODIUM_LIBRARY_DIRS})
add_test(NAME sn_tables COMMAND sn_tables_test)

add_executable(sn_demux_test
    test_sn_demux.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_source.c
)
target_include_directories(sn_demux_test PRIVATE ${SHIELDNET_DIR}/include)
target_compile_options(sn_demux_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_device_test
    test_sn_device.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SN_TEST_OS_PORT}
)
target_include_directories(sn_device_test PRIVATE ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_device_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_device_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_finish_test
    test_sn_finish.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SN_TEST_OS_PORT}
)
target_include_directories(sn_finish_test PRIVATE ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_finish_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_finish_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_agent_dispatch_test
    test_sn_agent_dispatch.c
    ${SHIELDNET_DIR}/src/sn_agent_dispatch.c
    ${SHIELDNET_DIR}/src/sn_app_frame.c
    ${SHIELDNET_DIR}/src/sn_agent.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
    ${SHIELDNET_DIR}/vendor/lz4.c
)
target_include_directories(sn_agent_dispatch_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_agent_dispatch_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_agent_dispatch_test PRIVATE -Wall -Wextra)

add_executable(sn_app_frame_test
    test_sn_app_frame.c
    ${SHIELDNET_DIR}/src/sn_app_frame.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/vendor/lz4.c
)
target_include_directories(sn_app_frame_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor
    ${SHIELDNET_DIR}/test          # sn_vectors.h (message-layer vectors)
    ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_app_frame_test PRIVATE ${SODIUM_LIBRARIES})
target_compile_options(sn_app_frame_test PRIVATE -Wall -Wextra)

add_executable(sn_command_test
    test_sn_command.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
)
target_include_directories(sn_command_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_compile_options(sn_command_test PRIVATE -Wall -Wextra)

# The extension hook and the core's own brightness and modes.
add_executable(sn_ext_test
    test_sn_ext.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
)
target_include_directories(sn_ext_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_compile_options(sn_ext_test PRIVATE -Wall -Wextra -Wpedantic)

# The same test with the pts capability compiled in (CONFIG_SLED_PTS).
add_executable(sn_command_pts_test
    test_sn_command.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
)
target_include_directories(sn_command_pts_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_compile_options(sn_command_pts_test PRIVATE -Wall -Wextra)
target_compile_definitions(sn_command_pts_test PRIVATE CONFIG_SLED_PTS)

# Log lines a peer can trigger are written once. esp_log_fake comes first on the
# include path so SHIELDNET_LOG_ESP_IDF finds its counting esp_log.h.
add_executable(sn_command_log_test
    test_sn_command_log.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c)
target_include_directories(sn_command_log_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/esp_log_fake
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
    ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_compile_options(sn_command_log_test PRIVATE -Wall -Wextra)
target_compile_definitions(sn_command_log_test PRIVATE
    SHIELDNET_LOG_ESP_IDF CONFIG_SLED_PTS)

# One source, two capability configurations.
foreach(t sn_caps_test sn_caps_pts_test)
    add_executable(${t} test_sn_caps.c
        ${SHIELDNET_DIR}/src/command.c
        ${SHIELDNET_DIR}/src/frame.c)
    target_include_directories(${t} PRIVATE
        ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
        ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
    target_compile_options(${t} PRIVATE -Wall -Wextra -Wpedantic)
endforeach()
target_compile_definitions(sn_caps_pts_test PRIVATE CONFIG_SLED_PTS)

add_executable(sn_client_e2e_test
    test_sn_client_e2e.c
    ${SHIELDNET_DIR}/src/sn_client.c
    ${SHIELDNET_DIR}/src/sn_agent_dispatch.c
    ${SHIELDNET_DIR}/src/sn_agent.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
    ${SHIELDNET_DIR}/src/sn_app_frame.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/vendor/lz4.c
    ${SHIELDNET_DIR}/src/sn_client_wire.c
    ${SHIELDNET_DIR}/src/sn_client_session.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_client_e2e_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet ${SHIELDNET_DIR}/port
    ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_client_e2e_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_client_e2e_test PRIVATE -Wall -Wextra)
# sn_agent_respond sends a 2600-byte body below (more than one KCP segment).
target_compile_definitions(sn_client_e2e_test PRIVATE SHIELDNET_MAX_RESPONSE_BODY=4096)

add_executable(sn_client_test
    test_sn_client.c
    ${SHIELDNET_DIR}/src/sn_client.c
    ${SHIELDNET_DIR}/src/sn_agent_dispatch.c
    ${SHIELDNET_DIR}/src/sn_agent.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
    ${SHIELDNET_DIR}/src/sn_app_frame.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/vendor/lz4.c
    ${SHIELDNET_DIR}/src/sn_client_wire.c
    ${SHIELDNET_DIR}/src/sn_client_session.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_demux.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_client_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_client_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_client_test PRIVATE -Wall -Wextra)

add_executable(sn_client_session_test
    test_sn_client_session.c
    ${SHIELDNET_DIR}/src/sn_client_session.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_client_session_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_client_session_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_client_session_test PRIVATE -Wall -Wextra)

add_executable(sn_client_wire_test
    test_sn_client_wire.c
    ${SHIELDNET_DIR}/src/sn_client_wire.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SN_TEST_OS_PORT}
)
target_include_directories(sn_client_wire_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_client_wire_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_client_wire_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_os_test
    test_sn_os.c
    ${SN_TEST_OS_PORT}
)
target_include_directories(sn_os_test PRIVATE ${SHIELDNET_DIR}/port)
target_compile_options(sn_os_test PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(sn_os_test PRIVATE Threads::Threads)

# ThreadSanitizer variant — the concurrency primitives are only meaningfully
# race-checked here (§10's platform lock hazards still need real hardware).
if(SN_TSAN)
add_executable(sn_os_test_tsan
    test_sn_os.c
    ${SN_TEST_OS_PORT}
)
target_include_directories(sn_os_test_tsan PRIVATE ${SHIELDNET_DIR}/port)
target_compile_options(sn_os_test_tsan PRIVATE -Wall -Wextra -Wpedantic -fsanitize=thread -g)
target_link_options(sn_os_test_tsan PRIVATE -fsanitize=thread)
target_link_libraries(sn_os_test_tsan PRIVATE Threads::Threads)
endif()
target_include_directories(sn_kdf_test PRIVATE
    ${SHIELDNET_DIR}/include
    ${SHIELDNET_DIR}/test          # sn_vectors.h: test/gen_sn_vectors.py over shieldnet-protocol/vectors
    ${SODIUM_INCLUDE_DIRS}
)
target_link_libraries(sn_kdf_test PRIVATE ${SODIUM_LIBRARIES})
# ShieldNet sources carry no logging macros, so the stricter set is fine here (unlike the
# protocol.c suites, which drop -Wpedantic for a zero-arg __VA_ARGS__ at old sites).
target_compile_options(sn_kdf_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_replay_test
    test_sn_replay.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SHIELDNET_DIR}/src/sn_wire.c
)
target_include_directories(sn_replay_test PRIVATE ${SHIELDNET_DIR}/include ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_replay_test PRIVATE ${SODIUM_LIBRARIES})
target_compile_options(sn_replay_test PRIVATE -Wall -Wextra -Wpedantic)

add_executable(sn_promote_test
    test_sn_promote.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_promote_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor
    ${SHIELDNET_DIR}/test          # sn_vectors.h (envelope_size)
    ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_promote_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
# ikcp.c is third-party; keep the strict set for our code but tolerate its warnings
target_compile_options(sn_promote_test PRIVATE -Wall -Wextra)

add_executable(sn_tick_test
    test_sn_tick.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_tick_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_tick_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_tick_test PRIVATE -Wall -Wextra)

add_executable(sn_short_send_test
    test_sn_short_send.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_short_send_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_short_send_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_short_send_test PRIVATE -Wall -Wextra)
# The one configuration in which ikcp_send's partial return is reachable: the
# default cap refuses a 128-segment message before ikcp_send sees it.
target_compile_definitions(sn_short_send_test PRIVATE SN_SEND_QUEUE_MAX=1048576)

add_executable(sn_agent_test
    test_sn_agent.c
    ${SHIELDNET_DIR}/src/sn_agent.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
)
target_include_directories(sn_agent_test PRIVATE
    ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
target_link_libraries(sn_agent_test PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
target_compile_options(sn_agent_test PRIVATE -Wall -Wextra)

# §8.5 promotion interrupted between (a) and (c) by a binding agent.
# SN_TEST_HOOKS compiles in the hook that parks the promoting thread there; no
# other target defines it. The _tsan twin races the same rendezvous under
# ThreadSanitizer (excluded from the ASan job like sn_os_test_tsan).
set(SN_PROMOTE_RACE_SOURCES
    test_sn_promote_race.c
    ${SHIELDNET_DIR}/src/sn_agent_dispatch.c
    ${SHIELDNET_DIR}/src/sn_app_frame.c
    ${SHIELDNET_DIR}/src/sn_agent.c
    ${SHIELDNET_DIR}/src/command.c
    ${SHIELDNET_DIR}/src/frame.c
    ${SHIELDNET_DIR}/src/protocol.c
    ${SHIELDNET_DIR}/src/crypto.c
    ${SHIELDNET_DIR}/src/decompress.c
    ${SHIELDNET_DIR}/src/sn_session.c
    ${SHIELDNET_DIR}/src/sn_device.c
    ${SHIELDNET_DIR}/src/sn_kdf.c
    ${SHIELDNET_DIR}/src/sn_wire.c
    ${SHIELDNET_DIR}/src/sn_source.c
    ${SHIELDNET_DIR}/src/sn_replay.c
    ${SN_TEST_OS_PORT}
    ${SHIELDNET_DIR}/vendor/ikcp.c
    ${SHIELDNET_DIR}/vendor/lz4.c
)
set(SN_PROMOTE_RACE_TARGETS sn_promote_race_test)
if(SN_TSAN)
    list(APPEND SN_PROMOTE_RACE_TARGETS sn_promote_race_test_tsan)
endif()
foreach(t ${SN_PROMOTE_RACE_TARGETS})
    add_executable(${t} ${SN_PROMOTE_RACE_SOURCES})
    target_include_directories(${t} PRIVATE
        ${SHIELDNET_DIR}/include ${SHIELDNET_DIR}/include/shieldnet
        ${SHIELDNET_DIR}/port ${SHIELDNET_DIR}/vendor ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(${t} PRIVATE ${SODIUM_LIBRARIES} Threads::Threads)
    target_compile_definitions(${t} PRIVATE SN_TEST_HOOKS)
    target_compile_options(${t} PRIVATE -Wall -Wextra)
endforeach()
if(SN_TSAN)
    target_compile_options(sn_promote_race_test_tsan PRIVATE -fsanitize=thread -g)
    target_link_options(sn_promote_race_test_tsan PRIVATE -fsanitize=thread)
endif()

# Deployment constants applied to every _test target (a list of NAME=VALUE, empty
# by default), so the suite can run at values other than the defaults: the CI
# `constants` mode sets SN_SEND_QUEUE_MAX, SN_WIRE_MTU, SN_PENDING_SLOTS and
# SHIELDNET_MAX_RESPONSE_BODY. Not applied to sn_short_send_test, which defines
# some of these itself (it never runs at the override). Tests must derive their
# numbers from the constants.
set(SN_TEST_DEPLOYMENT_DEFS "" CACHE STRING "NAME=VALUE deployment constants for every _test target")
if(SN_TEST_DEPLOYMENT_DEFS)
    get_directory_property(SN_ALL_TARGETS BUILDSYSTEM_TARGETS)
    foreach(t ${SN_ALL_TARGETS})
        if(t MATCHES "_test$" AND NOT t STREQUAL "sn_short_send_test")
            target_compile_definitions(${t} PRIVATE ${SN_TEST_DEPLOYMENT_DEFS})
        endif()
    endforeach()
endif()

enable_testing()
add_test(NAME sn_kdf COMMAND sn_kdf_test)
add_test(NAME sn_source COMMAND sn_source_test)
add_test(NAME sn_pts COMMAND sn_pts_test)
add_test(NAME sn_os COMMAND sn_os_test)
add_test(NAME sn_demux COMMAND sn_demux_test)
add_test(NAME sn_device COMMAND sn_device_test)
add_test(NAME sn_finish COMMAND sn_finish_test)
add_test(NAME sn_client_wire COMMAND sn_client_wire_test)
add_test(NAME sn_client_session COMMAND sn_client_session_test)
add_test(NAME sn_client COMMAND sn_client_test)
add_test(NAME sn_client_e2e COMMAND sn_client_e2e_test)
add_test(NAME sn_agent_dispatch COMMAND sn_agent_dispatch_test)
add_test(NAME sn_app_frame COMMAND sn_app_frame_test)
add_test(NAME sn_command COMMAND sn_command_test)
add_test(NAME sn_ext COMMAND sn_ext_test)
add_test(NAME sn_command_pts COMMAND sn_command_pts_test)
add_test(NAME sn_command_log COMMAND sn_command_log_test)
add_test(NAME sn_caps COMMAND sn_caps_test)
add_test(NAME sn_caps_pts COMMAND sn_caps_pts_test)
add_test(NAME sn_replay COMMAND sn_replay_test)
add_test(NAME sn_promote COMMAND sn_promote_test)
add_test(NAME sn_tick COMMAND sn_tick_test)
add_test(NAME sn_short_send COMMAND sn_short_send_test)
add_test(NAME sn_agent COMMAND sn_agent_test)
add_test(NAME sn_promote_race COMMAND sn_promote_race_test)
if(SN_TSAN)
    add_test(NAME sn_os_tsan COMMAND sn_os_test_tsan)
    add_test(NAME sn_promote_race_tsan COMMAND sn_promote_race_test_tsan)
endif()

# Guards the move of every hand-rolled admission into client_helper.h: a tenth
# hand-rolled FINISH fails here rather than in review.
add_test(NAME no_handrolled_admission
         COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/no_handrolled_admission.cmake)
add_test(NAME no_device_psk
         COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/no_device_psk.cmake)

# Compile checks: constants under which a response of SHIELDNET_MAX_RESPONSE_BODY
# cannot be sent must not build (src/sn_agent_dispatch.c asserts it). Each probe
# violates only its own assertion; _ok proves the include paths are right and
# that a small legal configuration still compiles. PASS_REGULAR_EXPRESSION
# ignores the exit status.
set(SN_SYNTAX_INCLUDES -I${SHIELDNET_DIR}/include -I${SHIELDNET_DIR}/include/shieldnet
    -I${SHIELDNET_DIR}/port -I${SHIELDNET_DIR}/vendor)
foreach(d ${SODIUM_INCLUDE_DIRS})
    list(APPEND SN_SYNTAX_INCLUDES -I${d})
endforeach()
add_test(NAME sn_build_response_queue
         COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only -DSHIELDNET_MAX_RESPONSE_BODY=10672 -DSN_SEND_QUEUE_MAX=4096
                 ${SN_SYNTAX_INCLUDES} ${SHIELDNET_DIR}/src/sn_agent_dispatch.c)
set_tests_properties(sn_build_response_queue PROPERTIES
                     PASS_REGULAR_EXPRESSION "SN_SEND_QUEUE_MAX too small for SHIELDNET_MAX_RESPONSE_BODY")
add_test(NAME sn_build_response_fragments
         COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only -DSN_WIRE_MTU=70 -DSHIELDNET_MAX_RESPONSE_BODY=4204
                 ${SN_SYNTAX_INCLUDES} ${SHIELDNET_DIR}/src/sn_agent_dispatch.c)
set_tests_properties(sn_build_response_fragments PROPERTIES
                     PASS_REGULAR_EXPRESSION "128 or more KCP fragments")
add_test(NAME sn_build_response_below_core
         COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only -DSHIELDNET_MAX_RESPONSE_BODY=512
                 ${SN_SYNTAX_INCLUDES} ${SHIELDNET_DIR}/src/sn_agent_dispatch.c)
# GCC prints the apostrophe in the message escaped (core\'s), so match around it.
set_tests_properties(sn_build_response_below_core PROPERTIES
                     PASS_REGULAR_EXPRESSION "below the core.*s largest response")
add_test(NAME sn_build_response_ok
         COMMAND ${CMAKE_C_COMPILER} -std=c11 -fsyntax-only -DSN_SEND_QUEUE_MAX=6144 -DSHIELDNET_MAX_RESPONSE_BODY=1024
                 -DSN_WIRE_MTU=576 ${SN_SYNTAX_INCLUDES} ${SHIELDNET_DIR}/src/sn_agent_dispatch.c)
