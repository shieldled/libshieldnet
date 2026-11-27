/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* Pure mode-ownership policy shared by firmware and host regression tests. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Record an explicit mode request without losing an active automatic-source
 * lease. The automatic source keeps ownership until it releases; the explicit
 * request becomes the mode that remains after that release.
 *
 * Returning auto_active lets the caller assign the result directly, making it
 * impossible for the explicit path to accidentally clear the ownership bit.
 */
static inline bool sled_mode_record_explicit_target(
    bool auto_active, uint8_t requested_mode, uint8_t *auto_revert_mode)
{
    if (auto_active && auto_revert_mode) {
        *auto_revert_mode = requested_mode;
    }
    return auto_active;
}
