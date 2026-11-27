/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/* A stand-in for ESP-IDF's esp_log.h: counts ESP_LOGE calls. The tag and the
 * format arguments are used, so neither TAG in command.c/frame.c nor a value
 * computed only for a log is reported unused. */
#pragma once

#include <stdio.h>

extern int g_esp_loge_count;

#define ESP_LOGE(tag, ...) (g_esp_loge_count++, (void)(tag), (void)snprintf(NULL, 0, __VA_ARGS__))
#define ESP_LOGI(tag, ...) ((void)(tag), (void)snprintf(NULL, 0, __VA_ARGS__))
