/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_os over FreeRTOS / ESP-IDF.
 *
 * A standalone implementation of the shieldnet_os.h seam, with no dependency on
 * the firmware that links it. It mirrors shieldnet_os_posix.c over the
 * FreeRTOS/ESP-IDF API. The host build links shieldnet_os_posix.c instead.
 *
 * Two contract points that a naive pass-through gets wrong:
 *   - now_ms64 is the 64-bit ms clock §2 requires; now_ms is its low 32 bits.
 *   - the thread MUST trampoline: shieldnet_os.h's contract is "fn returns normally
 *     at shutdown; thread_release is the sole deletion point; there is no
 *     thread_exit." A raw FreeRTOS task fn that returns without vTaskDelete faults,
 *     so the trampoline suspends the task after fn returns and lets release delete it.
 */

#include "shieldnet_os.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_timer.h"

#include <stdlib.h>

_Static_assert(sizeof(portMUX_TYPE) <= sizeof(((shieldnet_crit_t *)0)->opaque),
               "shieldnet_crit_t is too small for portMUX_TYPE");
_Static_assert(_Alignof(portMUX_TYPE) <= 8,
               "portMUX_TYPE needs more alignment than shieldnet_crit_t provides");

static inline TickType_t ticks(int32_t timeout_ms) {
    if (timeout_ms < 0) return portMAX_DELAY;
    /* 64-bit arithmetic: pdMS_TO_TICKS overflows its 32-bit product for a
     * timeout above ~4.29e6 / configTICK_RATE_HZ seconds. A positive sub-tick
     * timeout rounds UP to one tick rather than to zero, or a bounded wait
     * becomes a busy poll and the caller's time accounting runs ahead of the
     * clock. */
    uint64_t t = ((uint64_t)(uint32_t)timeout_ms * configTICK_RATE_HZ) / 1000u;
    if (t == 0 && timeout_ms > 0) t = 1;
    if (t >= portMAX_DELAY) t = portMAX_DELAY - 1;
    return (TickType_t)t;
}

/* ── time ──────────────────────────────────────────────────────────────────── */

uint64_t shieldnet_os_now_ms64(void) { return (uint64_t)(esp_timer_get_time() / 1000); }
uint32_t shieldnet_os_now_ms(void)   { return (uint32_t)(esp_timer_get_time() / 1000); }

void shieldnet_os_sleep_ms(uint32_t ms) { vTaskDelay(pdMS_TO_TICKS(ms)); }

void shieldnet_os_sleep_until_ms(uint32_t *prev_ms, uint32_t interval_ms) {
    /* Drift-free cadence on the FreeRTOS tick.
     *
     * Two traps, both found on hardware:
     *  1. pdMS_TO_TICKS(interval) TRUNCATES TO ZERO whenever interval is shorter
     *     than one tick (the §9.2 tick asks for 5 ms; the default tick is 10 ms),
     *     and vTaskDelayUntil asserts on a zero increment — the device panicked in
     *     a boot loop. Clamp to at least one tick.
     *  2. The previous-wake time must be a real tick timestamp, not a value derived
     *     from the caller's millisecond accumulator, or the delay is computed
     *     against a fictional past and does not pace at all. Keep the tick anchor in
     *     a task-local static and re-anchor if it is stale (first call, or after the
     *     caller was blocked longer than the interval). */
    TickType_t incr = pdMS_TO_TICKS(interval_ms);
    if (incr == 0) {
        incr = 1; /* sub-tick interval: one tick is the finest cadence available */
    }
    static __thread TickType_t anchor;
    static __thread int have_anchor;
    TickType_t now = xTaskGetTickCount();
    if (!have_anchor || (TickType_t)(now - anchor) > (incr * 4)) {
        anchor = now;       /* (re)anchor: first use, or we fell far behind */
        have_anchor = 1;
    }
    vTaskDelayUntil(&anchor, incr);
    *prev_ms += interval_ms; /* the caller's ms accumulator, per the contract */
}

/* ── mutex — kcp_lock ──────────────────────────────────────────────────────── */

shieldnet_mutex_t *shieldnet_mutex_create(void) {
    return (shieldnet_mutex_t *)xSemaphoreCreateMutex();
}
void shieldnet_mutex_destroy(shieldnet_mutex_t *m) {
    if (m) vSemaphoreDelete((SemaphoreHandle_t)m);
}
bool shieldnet_mutex_lock(shieldnet_mutex_t *m, int32_t timeout_ms) {
    return xSemaphoreTake((SemaphoreHandle_t)m, ticks(timeout_ms)) == pdTRUE;
}
void shieldnet_mutex_unlock(shieldnet_mutex_t *m) {
    xSemaphoreGive((SemaphoreHandle_t)m);
}

/* ── critical section — rec_lock (portMUX spinlock) ────────────────────────── */

void shieldnet_crit_init(shieldnet_crit_t *c) {
    portMUX_TYPE init = portMUX_INITIALIZER_UNLOCKED;
    *(portMUX_TYPE *)(void *)c->opaque = init;
}
void shieldnet_crit_enter(shieldnet_crit_t *c) {
    portENTER_CRITICAL((portMUX_TYPE *)(void *)c->opaque);
}
void shieldnet_crit_exit(shieldnet_crit_t *c) {
    portEXIT_CRITICAL((portMUX_TYPE *)(void *)c->opaque);
}

/* ── one-shot signalling (binary semaphore) ────────────────────────────────── */

shieldnet_signal_t *shieldnet_signal_create(void) {
    return (shieldnet_signal_t *)xSemaphoreCreateBinary();
}
void shieldnet_signal_destroy(shieldnet_signal_t *s) {
    if (s) vSemaphoreDelete((SemaphoreHandle_t)s);
}
bool shieldnet_signal_wait(shieldnet_signal_t *s, int32_t timeout_ms) {
    return xSemaphoreTake((SemaphoreHandle_t)s, ticks(timeout_ms)) == pdTRUE;
}
void shieldnet_signal_post(shieldnet_signal_t *s) {
    xSemaphoreGive((SemaphoreHandle_t)s);
}

/* ── thread — the §9.2 tick, with the required trampoline ──────────────────── */

struct shieldnet_thread {
    TaskHandle_t handle;
    shieldnet_thread_fn fn;
    void *arg;
};

/* Run fn, then park — do NOT let the FreeRTOS task fn return (that faults) and do
 * NOT self-delete. thread_release deletes the parked task (shieldnet_os.h). */
static void trampoline(void *p) {
    struct shieldnet_thread *t = p;
    t->fn(t->arg);
    for (;;) {
        vTaskSuspend(NULL); /* reaped by shieldnet_thread_release */
    }
}

bool shieldnet_thread_create(shieldnet_thread_fn fn, const char *name,
                             size_t stack_bytes, void *arg, int priority,
                             int core, shieldnet_thread_t **out) {
    struct shieldnet_thread *t = malloc(sizeof(*t));
    if (t == NULL) {
        return false;
    }
    t->fn = fn;
    t->arg = arg;
    BaseType_t ok;
    if (core < 0) {
        ok = xTaskCreate(trampoline, name, (uint32_t)stack_bytes, t,
                         (UBaseType_t)priority, &t->handle);
    } else {
        ok = xTaskCreatePinnedToCore(trampoline, name, (uint32_t)stack_bytes, t,
                                     (UBaseType_t)priority, &t->handle, core);
    }
    if (ok != pdPASS) {
        free(t);
        return false;
    }
    *out = t;
    return true;
}

void shieldnet_thread_release(shieldnet_thread_t *t) {
    if (t == NULL) {
        return;
    }
    /* The caller has already observed the thread finish (fn posted its signal),
     * so it is parked in trampoline's suspend loop; delete it and reclaim. */
    vTaskDelete(t->handle);
    free(t);
}
