/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_os_win32 -- Win32 implementation of the shieldnet_os seam, the
 * counterpart of shieldnet_os_posix.c for a Windows desktop client or host.
 *
 * The contract and its rationale live in shieldnet_os.h. As on POSIX:
 *   - the clock is monotonic (QueryPerformanceCounter, never the system time);
 *   - the mutex is non-recursive (SRWLOCK), and its timed lock polls try-acquire
 *     against the monotonic clock;
 *   - the signal is binary and coalescing (an auto-reset event).
 *
 * Two things differ from POSIX and are worth knowing:
 *   - The seam has no wall-clock function, so GetSystemTimePreciseAsFileTime is
 *     not used here.
 *   - CRITICAL_SECTION is recursive on Windows, so a self-relock of a crit does
 *     NOT deadlock here the way the header promises for the mutex. The header
 *     promises non-recursion only for shieldnet_mutex_t; the library never
 *     nests crit sections (RFC 10.1).
 *
 * Not built or run on Linux; only a Windows build compiles it.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "shieldnet_os.h"

#include <process.h>
#include <stdlib.h>
#include <windows.h>

/* ── time ─────────────────────────────────────────────────────────────────── */

static uint64_t monotonic_ms(void) {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    uint64_t f = (uint64_t)freq.QuadPart;
    uint64_t c = (uint64_t)now.QuadPart;
    /* Split so that c * 1000 cannot overflow after months of uptime. */
    return (c / f) * 1000u + (c % f) * 1000u / f;
}

uint64_t shieldnet_os_now_ms64(void) { return monotonic_ms(); }

uint32_t shieldnet_os_now_ms(void) { return (uint32_t)monotonic_ms(); }

void shieldnet_os_sleep_ms(uint32_t ms) { Sleep(ms); }

void shieldnet_os_sleep_until_ms(uint32_t *prev_ms, uint32_t interval_ms) {
    uint32_t target = *prev_ms + interval_ms;
    uint32_t now = shieldnet_os_now_ms();
    int32_t remain = (int32_t)(target - now);
    if (remain > 0) {
        shieldnet_os_sleep_ms((uint32_t)remain);
    } else if ((uint32_t)(-remain) > interval_ms * 4u) {
        /* Fell far behind (descheduled): re-anchor rather than run the missed
         * intervals back to back with no sleep between them. */
        target = now;
    }
    *prev_ms = target;
}

/* ── mutex -- kcp_lock ────────────────────────────────────────────────────── */

struct shieldnet_mutex {
    SRWLOCK lock;
};

shieldnet_mutex_t *shieldnet_mutex_create(void) {
    shieldnet_mutex_t *mx = malloc(sizeof(*mx));
    if (mx == NULL) {
        return NULL;
    }
    InitializeSRWLock(&mx->lock);
    return mx;
}

void shieldnet_mutex_destroy(shieldnet_mutex_t *m) {
    /* An SRWLOCK has no destroy. */
    free(m);
}

bool shieldnet_mutex_lock(shieldnet_mutex_t *m, int32_t timeout_ms) {
    if (timeout_ms < 0) {
        AcquireSRWLockExclusive(&m->lock);
        return true;
    }
    if (timeout_ms == 0) {
        return TryAcquireSRWLockExclusive(&m->lock) != 0;
    }
    uint64_t deadline = monotonic_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (TryAcquireSRWLockExclusive(&m->lock)) {
            return true;
        }
        if (monotonic_ms() >= deadline) {
            return false;
        }
        Sleep(1);
    }
}

void shieldnet_mutex_unlock(shieldnet_mutex_t *m) { ReleaseSRWLockExclusive(&m->lock); }

/* ── critical section -- rec_lock (inline) ────────────────────────────────── */

_Static_assert(sizeof(CRITICAL_SECTION) <= sizeof(((shieldnet_crit_t *)0)->opaque),
               "CRITICAL_SECTION must fit in shieldnet_crit_t.opaque");
_Static_assert(_Alignof(CRITICAL_SECTION) <= 8,
               "CRITICAL_SECTION alignment must not exceed shieldnet_crit_t's");

void shieldnet_crit_init(shieldnet_crit_t *c) {
    InitializeCriticalSection((CRITICAL_SECTION *)(void *)c->opaque);
}

void shieldnet_crit_enter(shieldnet_crit_t *c) {
    EnterCriticalSection((CRITICAL_SECTION *)(void *)c->opaque);
}

void shieldnet_crit_exit(shieldnet_crit_t *c) {
    LeaveCriticalSection((CRITICAL_SECTION *)(void *)c->opaque);
}

/* ── one-shot signalling (binary, coalescing) ─────────────────────────────── */

struct shieldnet_signal {
    HANDLE ev; /* auto-reset: a wait that succeeds consumes the signal */
};

shieldnet_signal_t *shieldnet_signal_create(void) {
    shieldnet_signal_t *s = malloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (s->ev == NULL) {
        free(s);
        return NULL;
    }
    return s;
}

void shieldnet_signal_destroy(shieldnet_signal_t *s) {
    if (s == NULL) {
        return;
    }
    CloseHandle(s->ev);
    free(s);
}

bool shieldnet_signal_wait(shieldnet_signal_t *s, int32_t timeout_ms) {
    DWORD ms = timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms;
    return WaitForSingleObject(s->ev, ms) == WAIT_OBJECT_0;
}

void shieldnet_signal_post(shieldnet_signal_t *s) { SetEvent(s->ev); }

/* ── thread -- the §9.2 tick ──────────────────────────────────────────────── */

struct shieldnet_thread {
    HANDLE h;
    shieldnet_thread_fn fn;
    void *arg;
};

static unsigned __stdcall thread_trampoline(void *p) {
    shieldnet_thread_t *t = p;
    t->fn(t->arg);
    return 0;
}

bool shieldnet_thread_create(shieldnet_thread_fn fn, const char *name,
                             size_t stack_bytes, void *arg, int priority,
                             int core, shieldnet_thread_t **out) {
    (void)name;        /* hints ignored, as on POSIX */
    (void)stack_bytes;
    (void)priority;
    (void)core;
    shieldnet_thread_t *t = malloc(sizeof(*t));
    if (t == NULL) {
        return false;
    }
    t->fn = fn;
    t->arg = arg;
    uintptr_t h = _beginthreadex(NULL, 0, thread_trampoline, t, 0, NULL);
    if (h == 0) {
        free(t);
        return false;
    }
    t->h = (HANDLE)h;
    *out = t;
    return true;
}

void shieldnet_thread_release(shieldnet_thread_t *t) {
    if (t == NULL) {
        return;
    }
    /* The caller has already observed the thread finish (it posts its signal as
     * its final act), so this wait returns promptly; it makes release safe even
     * if the thread is still returning from its function. */
    WaitForSingleObject(t->h, INFINITE);
    CloseHandle(t->h);
    free(t);
}
