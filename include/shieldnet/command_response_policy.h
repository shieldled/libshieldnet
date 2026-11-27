/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Pure command-response policy shared by firmware and host regression tests. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SLED_RESPONSE_FREE_PIXEL_FRAME_KIND 0x00U
#define SLED_RESPONSE_FREE_NTP_SERVER_KIND  0x0BU

/* PIXEL_FRAME and NTP_SERVER are the response-free commands. Keep this guard at
 * the ACK boundary so a future handler cannot accidentally restore per-frame
 * ACKs. */
static inline bool sled_command_allows_ack(uint8_t command_kind)
{
    return command_kind != SLED_RESPONSE_FREE_PIXEL_FRAME_KIND
        && command_kind != SLED_RESPONSE_FREE_NTP_SERVER_KIND;
}
