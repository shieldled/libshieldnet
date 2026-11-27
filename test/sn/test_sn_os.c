/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_os POSIX backend — behavioural checks for the six primitives.
 * Not golden vectors: these assert the contract each
 * primitive promises (mutual exclusion, monotonic clock, one-shot signalling,
 * the tick teardown handshake), which is what the machine relies on.
 *
 * Concurrency correctness here is best judged under ThreadSanitizer; the CMake
 * target builds a second `_tsan` variant for that.
 */

#include "shieldnet_os.h"

#include <pthread.h>
#include <stdio.h>

static int failures = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            printf("FAIL %s\n", msg);                                           \
            failures++;                                                         \
        } else {                                                                \
            printf("ok   %s\n", msg);                                           \
        }                                                                       \
    } while (0)

/* ── mutex mutual exclusion under contention ──────────────────────────────── */

struct counter_ctx {
    shieldnet_mutex_t *m;
    long counter;
    int iters;
};

static void *bump_mutex(void *p) {
    struct counter_ctx *c = p;
    for (int i = 0; i < c->iters; i++) {
        shieldnet_mutex_lock(c->m, SHIELDNET_OS_WAIT_FOREVER);
        c->counter++;
        shieldnet_mutex_unlock(c->m);
    }
    return NULL;
}

static void test_mutex(void) {
    struct counter_ctx c = {shieldnet_mutex_create(), 0, 100000};
    CHECK(c.m != NULL, "mutex_create");
    pthread_t a, b, d;
    pthread_create(&a, NULL, bump_mutex, &c);
    pthread_create(&b, NULL, bump_mutex, &c);
    pthread_create(&d, NULL, bump_mutex, &c);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_join(d, NULL);
    CHECK(c.counter == 3L * c.iters, "mutex serialises 3x100k increments");
    /* trylock semantics: 0 timeout must fail while held, succeed when free */
    CHECK(shieldnet_mutex_lock(c.m, 0), "trylock acquires a free mutex");
    /* bounded wait: measured on the same monotonic clock the port waits on */
    uint32_t t0 = shieldnet_os_now_ms();
    CHECK(!shieldnet_mutex_lock(c.m, 30), "timed lock fails while the mutex is held");
    uint32_t waited = shieldnet_os_now_ms() - t0;
    CHECK(waited >= 30 && waited < 1000, "and only after (about) the timeout");
    shieldnet_mutex_unlock(c.m);
    CHECK(shieldnet_mutex_lock(c.m, 30), "timed lock acquires a free mutex");
    shieldnet_mutex_unlock(c.m);
    shieldnet_mutex_destroy(c.m);
}

/* ── critical section (inline, non-recursive) ─────────────────────────────── */

struct crit_ctx {
    shieldnet_crit_t c;
    long counter;
    int iters;
};

static void *bump_crit(void *p) {
    struct crit_ctx *x = p;
    for (int i = 0; i < x->iters; i++) {
        shieldnet_crit_enter(&x->c);
        x->counter++;
        shieldnet_crit_exit(&x->c);
    }
    return NULL;
}

static void test_crit(void) {
    struct crit_ctx x;
    x.counter = 0;
    x.iters = 100000;
    shieldnet_crit_init(&x.c);
    pthread_t a, b;
    pthread_create(&a, NULL, bump_crit, &x);
    pthread_create(&b, NULL, bump_crit, &x);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    CHECK(x.counter == 2L * x.iters, "crit serialises 2x100k increments");
}

/* ── monotonic clock: never goes backwards, ms32 == low 32 of ms64 ────────── */

static void test_clock(void) {
    uint64_t a64 = shieldnet_os_now_ms64();
    uint32_t a32 = shieldnet_os_now_ms();
    CHECK((uint32_t)a64 == a32 || (uint32_t)shieldnet_os_now_ms64() >= a32,
          "now_ms is the low 32 bits of now_ms64");
    uint64_t prev = shieldnet_os_now_ms64();
    int monotonic = 1;
    for (int i = 0; i < 1000; i++) {
        uint64_t now = shieldnet_os_now_ms64();
        if (now < prev) {
            monotonic = 0;
            break;
        }
        prev = now;
    }
    CHECK(monotonic, "now_ms64 is monotonic non-decreasing");

    /* sleep_ms advances the clock by at least the requested interval */
    uint64_t t0 = shieldnet_os_now_ms64();
    shieldnet_os_sleep_ms(50);
    uint64_t dt = shieldnet_os_now_ms64() - t0;
    CHECK(dt >= 45, "sleep_ms(50) advances the clock ~50ms");

    /* sleep_until_ms keeps cadence: two 30ms intervals land ~60ms out, and
     * *prev advances by exactly 2*interval regardless of drift */
    uint32_t prev32 = shieldnet_os_now_ms();
    uint32_t base = prev32;
    shieldnet_os_sleep_until_ms(&prev32, 30);
    shieldnet_os_sleep_until_ms(&prev32, 30);
    CHECK(prev32 - base == 60, "sleep_until_ms advances *prev by exactly 2x30");
}

/* ── signal one-shot handoff ──────────────────────────────────────────────── */

struct sig_ctx {
    shieldnet_signal_t *ready;
    shieldnet_signal_t *go;
    int stage;
};

static void *sig_worker(void *p) {
    struct sig_ctx *c = p;
    c->stage = 1;
    shieldnet_signal_post(c->ready);
    shieldnet_signal_wait(c->go, SHIELDNET_OS_WAIT_FOREVER);
    c->stage = 2;
    shieldnet_signal_post(c->ready);
    return NULL;
}

static void test_signal(void) {
    struct sig_ctx c = {shieldnet_signal_create(), shieldnet_signal_create(), 0};
    CHECK(c.ready != NULL && c.go != NULL, "signal_create");
    /* timeout path: nothing posted yet */
    uint32_t t0 = shieldnet_os_now_ms();
    CHECK(!shieldnet_signal_wait(c.ready, 20), "signal_wait times out when unposted");
    uint32_t waited = shieldnet_os_now_ms() - t0;
    CHECK(waited >= 20 && waited < 1000,
          "signal_wait's timeout runs on the monotonic clock (about 20 ms)");
    pthread_t w;
    pthread_create(&w, NULL, sig_worker, &c);
    CHECK(shieldnet_signal_wait(c.ready, 1000), "observe worker reach stage 1");
    CHECK(c.stage == 1, "worker is at stage 1");
    shieldnet_signal_post(c.go);
    CHECK(shieldnet_signal_wait(c.ready, 1000), "observe worker reach stage 2");
    CHECK(c.stage == 2, "worker is at stage 2");
    pthread_join(w, NULL);
    shieldnet_signal_destroy(c.ready);
    shieldnet_signal_destroy(c.go);
}

/* ── thread teardown handshake (fn returns → posts → release joins) ───────── */

struct tick_ctx {
    shieldnet_signal_t *stop;    /* shutdown asks the tick to stop */
    shieldnet_signal_t *stopped; /* tick's final act before returning */
    int ran;
};

static void tick_fn(void *p) {
    struct tick_ctx *c = p;
    /* run until asked to stop, on a fixed cadence like the real §9.2 tick */
    uint32_t prev = shieldnet_os_now_ms();
    while (!shieldnet_signal_wait(c->stop, 0)) {
        c->ran++;
        shieldnet_os_sleep_until_ms(&prev, 5);
    }
    shieldnet_signal_post(c->stopped); /* final act: announce we are done */
}

static void test_thread_teardown(void) {
    struct tick_ctx c = {shieldnet_signal_create(), shieldnet_signal_create(), 0};
    shieldnet_thread_t *t = NULL;
    bool started = shieldnet_thread_create(tick_fn, "tick", 8192, &c, 5, -1, &t);
    CHECK(started && t != NULL, "thread_create starts the tick");
    shieldnet_os_sleep_ms(40); /* let it iterate a few times */
    shieldnet_signal_post(c.stop);
    CHECK(shieldnet_signal_wait(c.stopped, 1000), "tick posts its done-signal");
    shieldnet_thread_release(t); /* joins the already-finished thread */
    CHECK(c.ran > 0, "tick iterated before shutdown");
    shieldnet_signal_destroy(c.stop);
    shieldnet_signal_destroy(c.stopped);
}

int main(void) {
    test_mutex();
    test_crit();
    test_clock();
    test_signal();
    test_thread_teardown();
    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("all shieldnet_os primitives behave\n");
    return 0;
}
