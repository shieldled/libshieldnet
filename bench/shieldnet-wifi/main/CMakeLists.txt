# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
set(SHIELDNET ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
idf_component_register(
    SRCS
        "main.c"
        "${SHIELDNET}/src/sn_kdf.c"
        "${SHIELDNET}/src/sn_wire.c"
        "${SHIELDNET}/src/sn_source.c"
        "${SHIELDNET}/src/sn_replay.c"
        "${SHIELDNET}/src/sn_demux.c"
        "${SHIELDNET}/src/sn_device.c"
        "${SHIELDNET}/src/sn_session.c"
        "${SHIELDNET}/src/sn_agent.c"
        "${SHIELDNET}/port/shieldnet_os_freertos.c"
        "${SHIELDNET}/vendor/ikcp.c"
    INCLUDE_DIRS
        "${SHIELDNET}/include"
        "${SHIELDNET}/include/shieldnet"
        "${SHIELDNET}/port"
        "${SHIELDNET}/vendor"
    REQUIRES libsodium esp_timer esp_wifi esp_netif nvs_flash esp_event lwip
)
