/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* The SET_MODE mode values the core owns. */
#pragma once

/* The one mode every device with pixel output has (sled 4.3). Any other value
 * is a mode the device defines through its extension; the core accepts it only
 * when shieldnet_device_ext_t.has_mode does. */
#define SLED_WIRE_MODE_PIXEL  1u
