/* Copyright (c) 2025-2026 BlackShield LDA
 * SPDX-License-Identifier: Apache-2.0 */
/*
 * shieldnet_os — the operating-system seam for the stateful machine.
 *
 * Why this header exists at all. The admission/envelope/lifecycle machine
 * lives once in this library and is linked by every device, instead of being
 * copied into each one. To do that it needs a handful of OS services — a mutex,
 * a short critical section, a monotonic clock, sleep, one-shot signalling, and
 * a thread. The library declares them here, and a build links exactly one
 * implementation:
 *
 *   shieldnet_os_freertos.c  ESP32 (FreeRTOS / ESP-IDF) — portMUX + FreeRTOS
 *   shieldnet_os_posix.c     Linux and other POSIX hosts, and the host test
 *                            suite — over pthreads
 *   shieldnet_os_win32.c     Windows desktop clients and hosts
 *
 * This is the same seam pattern the library already uses for shieldnet_io_t
 * and shieldnet_device_ops_t, with one deliberate difference: selection is at
 * LINK time, not through a function table. An OS is never swapped at runtime,
 * there is never more than one in a binary, and rec_lock is taken on every
 * envelope datagram — a table indirection would be the wrong shape for a hot,
 * singular dependency. shieldnet_io_t is per-session and cold; this is not.
 *
 * ── The two locks this seam serves (RFC §10) ──────────────────────────────
 *
 * The machine has exactly two locks, and they map onto two DISTINCT
 * primitives here on purpose — collapsing them is forbidden by §10.
 *
 *   RFC rec_lock  → the critical section (shieldnet_crit_t).
 *                   A portMUX spinlock on ESP32, a plain mutex on POSIX.
 *                   Short: record state, the primary pointer, the c2s replay
 *                   window, admission_epoch. Held for microseconds. RFC §10.1
 *                   forbids blocking, allocating, transmitting, or doing crypto
 *                   under it — so NOTHING that can sleep may run between
 *                   crit_enter and crit_exit.
 *
 *   RFC kcp_lock  → the mutex (shieldnet_mutex_t).
 *                   Guards the ikcp object across ikcp_input / ikcp_flush /
 *                   ikcp_create / free / §9.4 resume re-base. Held as long as a
 *                   flush takes — milliseconds when a full window retransmits —
 *                   so it MUST be able to sleep/block, which is why it is a mutex
 *                   and not a second critical section.
 *
 * The library, not this header, is responsible for the §10.3 ordering rule
 * (kcp_lock before rec_lock, and rec_lock never held across a flush). This seam
 * only has to make the two primitives genuinely different in blocking behaviour
 * so the library CAN honour it. See the caveat below on what the host cannot
 * catch.
 *
 * ── Caveat: the host is necessary, not sufficient ─────────────────────────
 *
 * On POSIX the critical section is a plain mutex. That means the host build
 * exercises the library's logic and data races (under ThreadSanitizer) but
 * CANNOT reproduce the ESP32-only §10 hazards: blocking while holding a portMUX
 * spinlock, or the rec_lock-across-flush deadlock the RFC dwells on. Worse, a
 * plain mutex tolerates the ENTIRE §10.1 "no forbidden work under rec_lock"
 * class — an allocation, an HKDF, a socket send, or any blocking call placed
 * between crit_enter and crit_exit runs fine on the host and watchdog-resets
 * only on device — and ThreadSanitizer flags data races, not "you did forbidden
 * work under the lock." So the library SHOULD carry a debug assertion that no
 * allocation, syscall, or cryptography runs inside a critical section; a green
 * host suite is not proof §10 holds. The platform bugs surface only under
 * FreeRTOS on real hardware.
 *
 * ── Not in this seam ──────────────────────────────────────────────────────
 *
 * Networking. There is no socket here. The machine is handed datagrams and
 * hands back datagrams; the UDP loop belongs to the board (host/sn_host.c on a
 * host). Logging is its own seam (shieldnet_log.h). Allocation is not here
 * either — ikcp_create/free go through KCP's own malloc hooks, not this header.
 *
 * Randomness is NOT here — it belongs to the crypto library. RFC §4.2 requires a
 * CSPRNG for cookie_secret, admission_epoch, and the per-FINISH ephemeral
 * keypair, and §4.2 forbids serving admission before it is ready. libsodium
 * (already a hard dependency) provides randombytes_buf, which
 * resolves to esp_random on ESP-IDF and getrandom/arc4random on the host — the
 * exact platform sources §4.2's platform note names. The library draws its
 * randomness there, and gates admission on libsodium being initialised, not on
 * anything in this header.
 *
 * The outbound seq_full counter is NOT here either. §10.1 requires it be
 * advanced by a lock-free compare-and-swap that fails closed on wrap — that is
 * C11 <stdatomic.h> used directly by the library, no OS help. The library SHOULD
 * static_assert the 64-bit atomic is lock-free: on 32-bit Xtensa/RISC-V an
 * _Atomic uint64_t CAS can fall back to a libatomic global lock, which is still
 * correct for nonce uniqueness but breaks §10.1's "lock-free for cost" promise
 * and may not be ISR-safe.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHIELDNET_OS_WAIT_FOREVER (-1)

/* ── time ──────────────────────────────────────────────────────────────────
 *
 * There are two monotonic clocks here, and the distinction is normative.
 *
 * now_ms64 is the 64-bit monotonic-milliseconds-since-boot clock RFC §2 REQUIRES
 * for cookie_epoch = floor(now_ms64 / COOKIE_EPOCH_MS): a 32-bit ms tick wraps at
 * 49.7 days — inside a session's ~99-day envelope (§8.3) — and at that wrap
 * epochs run backwards and are reused under an unchanged cookie_secret, which no
 * test vector catches (§2). Any wall-age measure the library keeps (session age,
 * §9.5's no-idle-timeout accounting) MUST also read this clock, never now_ms.
 * ESP-IDF: esp_timer_get_time() / 1000. POSIX: CLOCK_MONOTONIC in ms.
 *
 * now_ms is the 32-bit KCP/tick timebase — the low 32 bits of now_ms64. ikcp
 * uses uint32 ms and _itimediff signed diffs, and §9.4's dead-link re-base
 * rewrites ts_flush and the segment timestamps against exactly this. It wraps
 * every ~49 days; every comparison MUST be a signed difference (a - b as
 * int32_t), never a magnitude test. A caller keeps it in uint32_t and subtracts;
 * it does not widen it (widening is what now_ms64 is for).
 *
 * Both MUST be backed by the same underlying monotonic source so they never
 * disagree. On POSIX that source MUST be CLOCK_MONOTONIC — a CLOCK_REALTIME
 * backward step would break the §9.4 re-base and every KCP timer.
 */
uint64_t shieldnet_os_now_ms64(void);
uint32_t shieldnet_os_now_ms(void);

/* Sleep for at least ms milliseconds. Used by the board's UDP loop and by test
 * teardown, not by the §5–§10 machine (the tick uses sleep_until_ms). */
void shieldnet_os_sleep_ms(uint32_t ms);

/* Sleep until *prev_ms + interval_ms, then advance *prev_ms by interval_ms.
 * Keeps the §9.2 maintenance tick on a fixed cadence instead of drifting by its
 * own run time. The tick is the only periodic caller and it wants this, not a
 * bare sleep, so a slow flush does not stretch the interval. */
void shieldnet_os_sleep_until_ms(uint32_t *prev_ms, uint32_t interval_ms);

/* ── mutex — the kcp_lock primitive ────────────────────────────────────────
 *
 * Blocking mutual exclusion, held across a flush. Not recursive: locking twice
 * from one thread deadlocks (matches FreeRTOS mutex semantics). A
 * POSIX impl MUST use a plain PTHREAD_MUTEX_NORMAL, not ERRORCHECK — the
 * contract promises a deadlock on self-relock, not an EDEADLK return.
 */
typedef struct shieldnet_mutex shieldnet_mutex_t;

shieldnet_mutex_t *shieldnet_mutex_create(void);
void               shieldnet_mutex_destroy(shieldnet_mutex_t *m);

/* Returns false only on timeout. A negative timeout waits forever and always
 * returns true. */
bool shieldnet_mutex_lock(shieldnet_mutex_t *m, int32_t timeout_ms);
void shieldnet_mutex_unlock(shieldnet_mutex_t *m);

/* ── critical section — the rec_lock primitive ─────────────────────────────
 *
 * A handful of very short regions guarding record state and the primary
 * pointer. On ESP32 this maps to portMUX, a spinlock that also stalls the
 * scheduler on that core; on POSIX it is a plain mutex. Kept distinct from
 * shieldnet_mutex_t on purpose (§10 forbids collapsing the two).
 *
 * Nothing that can sleep, block, allocate, transmit, or do cryptography may run
 * between enter and exit (RFC §10.1).
 *
 * Storage is an opaque blob rather than a per-platform typedef, so no platform
 * header sits on the include path. Each implementation static-asserts its real
 * type fits. There is deliberately NO crit_destroy, so the
 * POSIX impl must store its pthread_mutex_t INLINE in this blob — which is what
 * sets the floor on the size, not the tiny portMUX. The largest host
 * pthread_mutex_t decides it: 40 B on glibc x86-64, 48 B on glibc aarch64, and
 * 64 B on macOS. So the blob is 64 bytes to build on every host; the ESP32
 * portMUX (~8 B) pays nothing for the slack.
 */
typedef struct {
    _Alignas(8) uint8_t opaque[64];
} shieldnet_crit_t;

void shieldnet_crit_init(shieldnet_crit_t *c);
void shieldnet_crit_enter(shieldnet_crit_t *c);
void shieldnet_crit_exit(shieldnet_crit_t *c);

/* ── one-shot signalling ───────────────────────────────────────────────────
 *
 * Binary: a signal posted twice before being waited on is observed once. Use it
 * for "this has happened", not for counting. The library uses it to join the
 * tick thread deterministically at teardown — the thread posts on its way out,
 * the shutdown path waits — which the host test suite needs to start and stop a
 * device cleanly between cases.
 */
typedef struct shieldnet_signal shieldnet_signal_t;

shieldnet_signal_t *shieldnet_signal_create(void);
void                shieldnet_signal_destroy(shieldnet_signal_t *s);

/* Returns false only on timeout. Negative waits forever. Consumes the signal. */
bool shieldnet_signal_wait(shieldnet_signal_t *s, int32_t timeout_ms);
void shieldnet_signal_post(shieldnet_signal_t *s);

/* ── thread — the §9.2 maintenance tick ────────────────────────────────────
 *
 * The tick runs in every lifecycle state (§9.2): it drives KCP for an
 * established primary and sweeps pending-slot expiry (§6.3) even when
 * primary = none. stack_bytes and priority are hints a platform may ignore
 * (pthreads take the system default and no priority); core is -1 for "any" and
 * is ignored where there is no affinity.
 *
 * Returns false if the thread could not start, leaving *out untouched. Pass NULL
 * for out for a thread that is never joined — but the tick IS joined (see the
 * signal note above), so the library passes a real handle.
 *
 * TEARDOWN CONTRACT (single deletion owner, no thread_exit). The tick does not
 * self-terminate: fn returns normally when the shutdown flag is observed, and
 * its LAST act before returning is to post a shieldnet_signal_t. The shutdown
 * path waits on that signal, then calls thread_release exactly once. The
 * platform wrapper MUST NOT auto-delete the task when fn returns — release is
 * the sole deletion point — and release MUST be safe to call after fn has
 * already returned. There is deliberately no thread_exit: a second deletion
 * route is how the FreeRTOS task gets double-deleted.
 */
typedef struct shieldnet_thread shieldnet_thread_t;
typedef void (*shieldnet_thread_fn)(void *arg);

bool shieldnet_thread_create(shieldnet_thread_fn fn, const char *name,
                             size_t stack_bytes, void *arg, int priority,
                             int core, shieldnet_thread_t **out);

/* Releases the thread handle and deletes the underlying task. NOT a join: the
 * caller must already know the thread has finished — the tick arranges that by
 * posting its signal as its final act (see the teardown contract above). Must
 * not be called from the thread itself. */
void shieldnet_thread_release(shieldnet_thread_t *t);

#ifdef __cplusplus
}
#endif
