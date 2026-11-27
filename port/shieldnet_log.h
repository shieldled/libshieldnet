/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_log — the logging seam.
 *
 * The library's log call sites are all error logs. Rather than
 * a function-pointer log port (runtime indirection and a null check on every
 * error path, for no benefit at this scale), logging is a macro that defaults
 * to a no-op.
 *
 * ESP-IDF consumers opt into ESP_LOGE/ESP_LOGI by defining SHIELDNET_LOG_ESP_IDF
 * before this header is included (e.g. via target_compile_definitions on the
 * component). Host tests get the no-op default and pay nothing.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SHIELDNET_LOG_ESP_IDF)

#include "esp_log.h"

/* The format is part of __VA_ARGS__ rather than a named parameter, so a call
 * with no arguments beyond it stays strictly conforming. Spelled the other way
 * round, the call sites in this library that pass only a format would need
 * the ##__VA_ARGS__ GNU extension, which -Wpedantic rejects. */
#define SHIELDNET_LOG_ERR(tag, ...)  ESP_LOGE(tag, __VA_ARGS__)
#define SHIELDNET_LOG_INFO(tag, ...) ESP_LOGI(tag, __VA_ARGS__)

#else

#define SHIELDNET_LOG_ERR(tag, ...)  ((void)(tag))
#define SHIELDNET_LOG_INFO(tag, ...) ((void)(tag))

#endif

#ifdef __cplusplus
}
#endif
