/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_os_posix — POSIX/pthreads implementation of the shieldnet_os seam,
 * for host builds (Linux and other POSIX boards) and the host test suite.
 *
 * The contract and its rationale live in shieldnet_os.h; this file only has to
 * satisfy it. Two contract points drive the choices here:
 *   - the clock MUST be CLOCK_MONOTONIC (a CLOCK_REALTIME step would break §9.4);
 *   - the mutex and critical section MUST be non-recursive PTHREAD_MUTEX_NORMAL,
 *     so a self-relock deadlocks (as promised) rather than returning EDEADLK.
 *
 * Timed waits follow the same clock. A CLOCK_REALTIME deadline stretches when
 * NTP steps the wall clock back and fires early when it steps forward -- and an
 * early readfull timeout inflates the agent's mid-frame budget until a healthy
 * session is torn down. The signal's condvar is bound to CLOCK_MONOTONIC; the
 * timed mutex lock, which POSIX only offers against CLOCK_REALTIME, polls
 * trylock against a monotonic deadline instead.
 *
 * The critical section stores its pthread_mutex_t INLINE in shieldnet_crit_t's
 * opaque blob (there is no crit_destroy to free a heap allocation), which is why
 * the blob is sized to the largest host pthread_mutex_t — see the static_assert.
 */

#ifdef __APPLE__
/* _POSIX_C_SOURCE below hides pthread_cond_timedwait_relative_np; Apple clang
 * treats the implicit declaration as an error. Must precede every include. */
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L /* clock_gettime, pthread_mutex_timedlock */

#include "shieldnet_os.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

/* ── time ─────────────────────────────────────────────────────────────────── */

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t shieldnet_os_now_ms64(void) { return monotonic_ms(); }

uint32_t shieldnet_os_now_ms(void) { return (uint32_t)monotonic_ms(); }

void shieldnet_os_sleep_ms(uint32_t ms) {
    struct timespec req;
    req.tv_sec = (time_t)(ms / 1000u);
    req.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
        /* resume with the remaining time nanosleep wrote back into req */
    }
}

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

/* ── mutex — kcp_lock ─────────────────────────────────────────────────────── */

struct shieldnet_mutex {
    pthread_mutex_t m;
};

shieldnet_mutex_t *shieldnet_mutex_create(void) {
    shieldnet_mutex_t *mx = malloc(sizeof(*mx));
    if (mx == NULL) {
        return NULL;
    }
    /* Default attributes give PTHREAD_MUTEX_NORMAL: non-recursive, self-relock
     * deadlocks rather than returning an error — the promised semantics. */
    if (pthread_mutex_init(&mx->m, NULL) != 0) {
        free(mx);
        return NULL;
    }
    return mx;
}

void shieldnet_mutex_destroy(shieldnet_mutex_t *m) {
    if (m == NULL) {
        return;
    }
    pthread_mutex_destroy(&m->m);
    free(m);
}

bool shieldnet_mutex_lock(shieldnet_mutex_t *m, int32_t timeout_ms) {
    if (timeout_ms < 0) {
        pthread_mutex_lock(&m->m);
        return true;
    }
    if (timeout_ms == 0) {
        return pthread_mutex_trylock(&m->m) == 0;
    }
    /* pthread_mutex_timedlock only takes a CLOCK_REALTIME deadline (see the
     * header comment), so poll against the monotonic clock. Only the host build
     * takes this path, and only for a bounded wait; a 1 ms granularity is fine. */
    uint64_t deadline = monotonic_ms() + (uint64_t)timeout_ms;
    for (;;) {
        if (pthread_mutex_trylock(&m->m) == 0) {
            return true;
        }
        if (monotonic_ms() >= deadline) {
            return false;
        }
        shieldnet_os_sleep_ms(1);
    }
}

void shieldnet_mutex_unlock(shieldnet_mutex_t *m) { pthread_mutex_unlock(&m->m); }

/* ── critical section — rec_lock (inline, non-recursive) ──────────────────── */

_Static_assert(sizeof(pthread_mutex_t) <= sizeof(((shieldnet_crit_t *)0)->opaque),
               "pthread_mutex_t must fit in shieldnet_crit_t.opaque");
_Static_assert(_Alignof(pthread_mutex_t) <= 8,
               "pthread_mutex_t alignment must not exceed shieldnet_crit_t's");

void shieldnet_crit_init(shieldnet_crit_t *c) {
    pthread_mutex_init((pthread_mutex_t *)(void *)c->opaque, NULL);
}

void shieldnet_crit_enter(shieldnet_crit_t *c) {
    pthread_mutex_lock((pthread_mutex_t *)(void *)c->opaque);
}

void shieldnet_crit_exit(shieldnet_crit_t *c) {
    pthread_mutex_unlock((pthread_mutex_t *)(void *)c->opaque);
}

/* ── one-shot signalling (binary, coalescing) ─────────────────────────────── */

struct shieldnet_signal {
    pthread_mutex_t m;
    pthread_cond_t cv;
    bool posted;
};

shieldnet_signal_t *shieldnet_signal_create(void) {
    shieldnet_signal_t *s = malloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->posted = false;
    if (pthread_mutex_init(&s->m, NULL) != 0) {
        free(s);
        return NULL;
    }
    /* Bind the condvar to CLOCK_MONOTONIC, so signal_wait's deadline is
     * immune to wall-clock steps (see the header comment). */
    pthread_condattr_t ca;
    if (pthread_condattr_init(&ca) != 0) {
        pthread_mutex_destroy(&s->m);
        free(s);
        return NULL;
    }
#ifdef __APPLE__
    /* No pthread_condattr_setclock on macOS: default attributes, and
     * signal_wait uses a relative wait instead of an absolute deadline. */
    int rc = 0;
#else
    int rc = pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
#endif
    if (rc == 0) {
        rc = pthread_cond_init(&s->cv, &ca);
    }
    pthread_condattr_destroy(&ca);
    if (rc != 0) {
        pthread_mutex_destroy(&s->m);
        free(s);
        return NULL;
    }
    return s;
}

void shieldnet_signal_destroy(shieldnet_signal_t *s) {
    if (s == NULL) {
        return;
    }
    pthread_cond_destroy(&s->cv);
    pthread_mutex_destroy(&s->m);
    free(s);
}

bool shieldnet_signal_wait(shieldnet_signal_t *s, int32_t timeout_ms) {
    bool got = false;
    pthread_mutex_lock(&s->m);
    if (timeout_ms < 0) {
        while (!s->posted) {
            pthread_cond_wait(&s->cv, &s->m);
        }
        got = true;
    } else {
#ifdef __APPLE__
        /* The wait is relative on macOS; recompute what is left against the
         * monotonic clock each time round, so a spurious wakeup does not
         * restart the full timeout. */
        uint64_t end_ms = monotonic_ms() + (uint64_t)timeout_ms;
        int rc = 0;
        while (!s->posted && rc == 0) {
            uint64_t now_ms = monotonic_ms();
            if (now_ms >= end_ms) {
                break;
            }
            uint64_t left_ms = end_ms - now_ms;
            struct timespec rel;
            rel.tv_sec = (time_t)(left_ms / 1000u);
            rel.tv_nsec = (long)(left_ms % 1000u) * 1000000L;
            rc = pthread_cond_timedwait_relative_np(&s->cv, &s->m, &rel);
        }
        got = s->posted;
#else
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline); /* the condvar's clock */
        deadline.tv_sec += timeout_ms / 1000;
        deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        int rc = 0;
        while (!s->posted && rc == 0) {
            rc = pthread_cond_timedwait(&s->cv, &s->m, &deadline);
        }
        got = s->posted;
#endif
    }
    if (got) {
        s->posted = false; /* consume */
    }
    pthread_mutex_unlock(&s->m);
    return got;
}

void shieldnet_signal_post(shieldnet_signal_t *s) {
    pthread_mutex_lock(&s->m);
    s->posted = true;
    pthread_cond_signal(&s->cv);
    pthread_mutex_unlock(&s->m);
}

/* ── thread — the §9.2 tick ───────────────────────────────────────────────── */

struct shieldnet_thread {
    pthread_t tid;
    shieldnet_thread_fn fn;
    void *arg;
};

static void *thread_trampoline(void *p) {
    shieldnet_thread_t *t = p;
    t->fn(t->arg);
    return NULL;
}

bool shieldnet_thread_create(shieldnet_thread_fn fn, const char *name,
                             size_t stack_bytes, void *arg, int priority,
                             int core, shieldnet_thread_t **out) {
    (void)name;        /* pthreads: no name in the portable API */
    (void)stack_bytes; /* hints ignored on POSIX (system default) */
    (void)priority;
    (void)core;
    shieldnet_thread_t *t = malloc(sizeof(*t));
    if (t == NULL) {
        return false;
    }
    t->fn = fn;
    t->arg = arg;
    if (pthread_create(&t->tid, NULL, thread_trampoline, t) != 0) {
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
    /* The caller has already observed the thread finish (it posts its signal as
     * its final act, per the teardown contract), so this join returns promptly
     * and reaps the pthread. */
    pthread_join(t->tid, NULL);
    free(t);
}
