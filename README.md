# libshieldnet

[![Documentation](https://img.shields.io/badge/docs-shieldled.github.io%2Flibshieldnet-blue.svg)](https://shieldled.github.io/libshieldnet/)
[![CI](https://github.com/shieldled/libshieldnet/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shieldled/libshieldnet/actions/workflows/ci.yml)
[![Docs](https://github.com/shieldled/libshieldnet/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shieldled/libshieldnet/actions/workflows/docs.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/shieldled/libshieldnet/blob/main/LICENSE)
[![C11](https://img.shields.io/badge/C-11-blue.svg)](https://en.cppreference.com/w/c/11)
[![Platforms: ESP-IDF | POSIX | Windows](https://img.shields.io/badge/platforms-ESP--IDF%20%7C%20POSIX%20%7C%20Windows-lightgrey.svg)](#the-port-seams)

**Documentation: [shieldled.github.io/libshieldnet](https://shieldled.github.io/libshieldnet/)**, with the guides, the API
reference and the examples.

libshieldnet is the C implementation of **ShieldNet**, the encrypted protocol
ShieldLED controllers use to drive LED devices over a network. It implements
both ends of a connection:

- the **device** side, run by LED hardware such as the ShieldLED ESP32 boards;
- the **client** side, run by the application that controls the devices.

It is portable C11 with one dependency, libsodium, and contains no code for a
particular operating system or board: everything platform-specific goes through
a few small *port* headers that each platform implements.

> **Writing a desktop application?** Use
> [libshieldnet-client](https://github.com/shieldled/libshieldnet-client)
> instead. It wraps this library's client side in a blocking, thread-safe API
> with device discovery. Use libshieldnet directly to build device firmware, or
> to run the client on an embedded target.

## Documentation

- **[Examples](examples/README.md)**: two complete programs, an LED device and a
  client, that build with CMake and talk to each other and to other ShieldNet
  implementations. Start here to see the library in use.
- **[API reference](https://shieldled.github.io/libshieldnet/api/)**: every public
  header, with every function, type and constant and the comment that documents
  it, generated from `include/shieldnet/` and `port/` each time the
  documentation site is built (`mkdocs serve` shows it locally).
- **This README**: how the pieces fit, adding the library to a build, the port
  seams, and what an integrator must provide.
- **The protocol**: [shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol).

## How ShieldNet works, in brief

1. **Admission.** A client asks a device to admit it. They exchange four short
   UDP messages (INIT → RETRY, FINISH → ADMIT), authenticated with a key that
   both derive from a pre-shared key (PSK). A device serves one client at a
   time: a newly admitted client takes over from the previous one.
2. **Session.** Once admitted, the two exchange messages over KCP, a reliable
   transport on top of UDP. Every datagram is encrypted and authenticated
   (ChaCha20-Poly1305), and every message is sealed again end to end
   (XChaCha20-Poly1305) and may be compressed (LZ4).
3. **Application.** The messages are commands and their responses: device
   information, status, mode and brightness, and pixel frames, optionally with
   presentation times.

The protocol is specified in
[shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol), in three
documents: `spec/transport.md` (admission and the encrypted transport),
`spec/message-layer.md` (messages inside a session) and `spec/application.md`
(commands, responses and pixel frames). This README cites them as
"transport 4.3", "message layer 8" and "spec 5.2". The `§N` section numbers in
the source code refer to the design notes in the same repository,
`design/transport.md`.

## Quick start

You need CMake 3.10 or newer (3.20 for `ctest --test-dir`), a C11 compiler and
libsodium 1.0.19 or newer.
Ubuntu 24.04 and Debian 12 ship 1.0.18, which is too old: `ci/install-deps.sh`
builds 1.0.20 from a checksummed release into `~/.local`, where every build here
looks first.

```sh
# The libraries (shieldnet_client, and shieldnet for both roles) and link checks
cmake -S . -B build && cmake --build build

# The test suite
cmake -S test/sn -B build/test && cmake --build build/test && ctest --test-dir build/test

# A device and a client talking over real UDP on this machine
cmake -S host -B build/host && cmake --build build/host
sh host/sn_host_loopback.sh build/host/sn_host build/host/sn_client_host

# Client-side timings
cmake -S bench -B build/bench && cmake --build build/bench && build/bench/sn_client_bench

# The examples: an LED device and a client, and their loopback test
cmake -S examples -B build/examples && cmake --build build/examples && ctest --test-dir build/examples
```

CI runs `ci/build-and-test.sh` in the modes `asan`, `plain` and `constants`
(the last at non-default deployment constants), and `ci/fuzz.sh`; each runs
locally after `ci/install-deps.sh`. It also runs two cross-builds:

- **Windows**: `ci/cross-windows.sh` builds both libraries for 64-bit Windows
  with MinGW-w64 (the root build picks the Win32 OS port on Windows) and runs
  the link checks and the whole test suite under Wine. The script installs its
  own toolchain, so run it in a container:
  `docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 sh ci/cross-windows.sh`.
  A second CI job builds and tests the same on Windows itself, with MSYS2's
  UCRT64 toolchain.
- **ESP32**: `ci/build-esp32.sh` builds the two ESP-IDF benchmark apps for
  every target they support (esp32, esp32s3, esp32p4; the Wi-Fi one not for
  esp32p4), with ESP-IDF v6.0's environment loaded. See
  [On-device benchmark](bench/shieldnet-esp32/README.md) and
  [Wi-Fi benchmark](bench/shieldnet-wifi/README.md) to flash and run them.

This documentation is also built as a site with MkDocs and published to GitHub
Pages from `main`; preview it with
`pip install -r docs/requirements.txt && mkdocs serve`.

`shieldnet.cmake` holds the source lists; consumers include it rather than
copying them. The root build also links two small programs,
`shieldnet_client_link_check` and `shieldnet_link_check`: a static archive never
resolves its symbols, so only a link shows that a source list is complete.

## Using libshieldnet

### The device role

A device runs the admission state machine (`sn_device.c`), one session with the
admitted client (`sn_session.c`, including the takeover by a newly admitted
client), and the application layer (`sn_agent_dispatch.c`), which hands every
command to the device through a table of callbacks, `shieldnet_device_ops_t`.
The command core (`command.c`) parses and answers every ShieldNet command; the
device only implements the callbacks.

### The client role

A client runs the admission state machine from the other side (`sn_client.c`:
five states, INIT sent up to three times, FINISH resent byte for byte, and the
first message that completes the takeover), the receive checks
(`sn_client_wire.c`) and one session (`sn_client_session.c`).

**The client owns no thread, no socket and no lock, and reads no clock.**
Datagrams go in through `sn_client_input` and time through `sn_client_tick`,
and every `sn_client_*` call on one client must be serialised by the caller: on
FreeRTOS, give one task ownership of the client and feed it through a queue,
rather than wrapping a mutex around a shared client. `host/sn_client_host.c` is
a short program that turns it into a blocking desktop client.

Both roles share `sn_app_frame.c`, the message layer: header, nonce, AEAD,
message numbering, compression and padding. The device uses it with the keys
one way round, the client with them swapped.

### Adding it to a build

1. A client compiles the files of `SHIELDNET_CLIENT_SOURCES` (`shieldnet.cmake`)
   and `vendor/*.c`, or links the root's `shieldnet_client` (plus an OS port,
   `SHIELDNET_PORT_POSIX_SOURCES` or `SHIELDNET_PORT_WIN32_SOURCES`, and Threads if it calls
   `shieldnet_os_*`, which `shieldnet_client` does not include). A device
   compiles `src/*.c` and `vendor/*.c`, or links `shieldnet` (setting
   `SHIELDNET_MAX_RESPONSE_BODY` if its extension's replies are larger than
   DEVICE_INFO, see Integrator obligations). Put `include/`, `include/shieldnet/`,
   `port/` and `vendor/` on the include path (`SHIELDNET_INCLUDE_DIRS` in
   `shieldnet.cmake`): the headers include each other both as
   `#include "shieldnet/sn_device.h"` and in the bare `#include "protocol.h"` form,
   and `sn_device.h` and `sn_client_session.h` include `ikcp.h`. See
   `examples/CMakeLists.txt` for the `target_include_directories` shape and
   `bench/shieldnet-esp32/main/CMakeLists.txt` for the ESP-IDF `INCLUDE_DIRS` one.
2. Link libsodium 1.0.19 or newer, the first release with the HKDF-SHA256 API
   (`crypto_kdf_hkdf_sha256_*`). Its headers must be on the include path of every
   build that compiles `crypto.c`, test builds included: four `_Static_assert`s
   there check libsodium's AEAD and HKDF sizes.
3. Write a `shieldnet_io_t` adapter around your transport (about five lines; see
   [The port seams](#the-port-seams)). There is no handshake function to
   implement: a device drives admission through `sn_device.c`, and a client
   through `sn_client.h`.
4. A device holds `device_id` and `k_dev`, as a pair, and must never store the
   PSK (transport 3.2). It starts with `sn_device_init_kdev`, passing the
   `device_id` its `k_dev` was derived for, and checks the result: -1 means the
   key is missing or unusable, and the device must not serve. A device that is
   given the PSK once (a configuration portal) calls `sn_provision_kdev`
   (`shieldnet/sn_kdf.h`), stores only `k_dev` with that `device_id`, and erases
   every other copy of the PSK it received before handling anything else.
   `sn_derive_kdev` is for clients and off-device tools.
5. If your platform needs `ESP_LOG`-shaped logging, define
   `SHIELDNET_LOG_ESP_IDF` (or extend `shieldnet_log.h` with your own guard)
   before including `shieldnet_log.h`.
6. To handle ShieldNet commands (not just PIXEL_FRAME), also compile
   `src/command.c` and implement `shieldnet_device_ops_t` (below), then call
   `shieldnet_command_dispatch(&ops, hdr, payload, payload_len)` from wherever
   your platform hands off a decrypted, decompressed message.

Nothing in `src/` or `include/shieldnet/` includes a FreeRTOS, ESP-IDF or other
platform header, which is why step 1 needs no change to library code on a new
platform.

## The port seams

Everything ESP-IDF- or platform-specific stays on the far side of one of
four seams, all under `port/`:

- **`shieldnet_io.h`** — a `shieldnet_io_t` function table (`readfull`,
  `write`, `poison`, and the optional `frame_continues`) that
  `protocol_read_message`, `protocol_write_message` and `protocol_marshal_aad`
  take instead of a concrete transport handle.
  Each consumer writes a five-line adapter binding its own transport: see
  `sn_primary_io()` in `src/sn_agent.c`, which backs the seam with the
  device's established primary session. The adapter
  zero-initialises the struct (`shieldnet_io_t io = {0};`); the optional
  `frame_continues` member is what lets a frame whose body arrives after a read
  timeout complete, and that tolerance applies only to frames read with
  `protocol_read_message` through an io that sets it (`sn_primary_io` does).

  Admission does **not** go through this seam — it is inherently
  role-asymmetric. The v2 `protocol_handshake_client` /
  `protocol_handshake_server` pair this section used to name was removed in
  the v1 migration (see `protocol.h`); `protocol.c` is framing only. Admission
  lives in `sn_device.c` on the device side and in `sn_client.c` on the client
  side.

  `poison()` deserves care on a new platform. It marks the stream unusable
  after a partially-consumed frame — the wire format carries no resync
  marker, so a torn frame makes the stream position unrecoverable. If your
  platform's handle owns exactly one session for its lifetime, poisoning the
  handle directly is correct. If it is a long-lived handle that outlives
  sessions — like the device's `sn_device`, one per board across many
  admissions — `poison()` must be a no-op and the session torn down instead;
  a flag on a long-lived handle would permanently disable it after one
  desynchronised frame.

- **`shieldnet_log.h`** — `SHIELDNET_LOG_ERR`/`SHIELDNET_LOG_INFO` macros,
  defaulting to a no-op. Define `SHIELDNET_LOG_ESP_IDF` (an ESP-IDF build does,
  via `target_compile_definitions`) to route them
  through `ESP_LOGE`/`ESP_LOGI`. A new platform either defines that same
  macro name against its own logger, or leaves the default and gets
  zero-cost no-op logging.

- **`shieldnet_device.h`** — `shieldnet_device_ops_t`: one
  `const` function table plus an opaque `ctx`, same shape as `shieldnet_io_t`
  but wider — it is what every ShieldNet command actually does to a device:
  output (brightness/fps/mode), pixel frames, status, and the response path,
  plus one optional extension hook (below). `shieldnet_command_dispatch`
  (`src/command.c`) takes one of these and a decrypted message and does
  everything else — parsing (via `command_parse.h`), validation, deciding
  the ACK, and driving exactly one op per command.

  **Locking is the device's job, not the core's.** Each op implementation
  locks *inside itself*, around exactly the calls it wraps, and releases
  before returning; `shieldnet_command_dispatch` contains no locking of any
  kind and never assumes an op is cheap or non-blocking. An op whose
  documented sequence must be atomic says so in `shieldnet_device.h`; do not
  split it.

  **No allocation on this table.** The core never calls `malloc`/`free`.

- **`shieldnet_os.h`** — the OS services the admission and session machine
  needs: a mutex, a short critical section, a monotonic clock, sleep, one-shot
  signalling and a thread. Selected at link time, not through a table: link
  exactly one of `shieldnet_os_freertos.c`, `shieldnet_os_posix.c` or
  `shieldnet_os_win32.c`. The header states the contract, including which of
  the two locks may block.

## Integrator obligations

The library cannot see the platform around it. A device integration must also
provide the following; each item names the section of the specification that
requires it.

- **Start-up secrets.** `cookie_secret` and `admission_epoch` come from a ready
  CSPRNG at every start; the epoch is non-zero with its top 8 bits clear (byte 0
  of the big-endian array is zero), and neither is persisted
  (transport 3.4, transport 3.5). `sn_device_init_kdev` refuses an invalid
  epoch, fail-closed.
- **ICMP.** The interface emits no ICMP echo replies or unreachables, and
  inbound ICMP does not affect the socket (transport 9.4 items 3–4). On the
  client side, a connected UDP socket reports ICMP errors on the next
  `recv`/`send`; ignore them (see `sn_client.h`).
- **One interface, current prefixes.** The socket is bound to one interface,
  and the local-prefix table passed to `sn_device_init_kdev` is kept current:
  an empty table silently skips the own-address and broadcast checks
  (transport 7.2, transport 7.3).
- **No IP reassembly.** IP reassembly SHOULD be off on the socket's path
  (transport 5.7).
- **No priority for session traffic.** Session output gets no priority over
  RETRY/ADMIT (transport 9.4 item 6).
- **End the session.** When `sn_agent_step` returns -1, call `sn_agent_end`
  before binding again (message layer 8; see `sn_agent_dispatch.h`).
- **One value per build for each overridable constant.**
  `SHIELDNET_MAX_RESPONSE_BODY` (`port/shieldnet_device.h`), `SN_PENDING_TTL_MS`,
  `SN_PENDING_SLOTS` and `SN_WIRE_MTU` (`sn_device.h`) may be overridden, and the
  command and transport layers must agree on them. Define each one identically
  for every translation unit that includes its header, the integrator's ops
  included: set it on the compile target (for example
  `target_compile_definitions`), never with a `#define` in one source file.
  Through the root CMake build, set the cache variable
  `SHIELDNET_MAX_RESPONSE_BODY`: it is then defined PUBLIC on `shieldnet`, so a
  consumer that links it sees the same value as the archive.
- **The largest response.** `SHIELDNET_MAX_RESPONSE_BODY` is the largest response
  body the device sends. It defaults to DEVICE_INFO's maximum, 1024 bytes; a
  device whose extension replies with more raises it. It, `SN_WIRE_MTU` and
  `SN_SEND_QUEUE_MAX` must fit together (the reply, sealed, in fewer than 128
  KCP fragments and, with its header, within the send queue); `src/sn_agent_dispatch.c`
  asserts it at build time, and `sn_agent_respond` refuses a longer body.
  `get_tx_scratch` must offer at least that much if the extension writes its
  replies there. The agent task's stack also holds a `SN_PAD_MAX_CLASS` (512 B)
  pad buffer in `sn_app_seal_padded`: budget it.

## Porting the command core to a new device

The seam is bounded and documented at the point of use — every entry in
`shieldnet_device_ops_t` (`port/shieldnet_device.h`) says what it does, what
it returns, and where it matters, what must stay atomic. To wire up a new
device:

1. Implement `shieldnet_device_ops_t` against your hardware, locking inside
   each op. Leave an op NULL when the device cannot do it: the core answers the
   commands that need it `ERR_UNKNOWN_KIND`, and `shieldnet_device_caps` derives
   what the device advertises from what is set.
2. Provide the `shieldnet_io_t` port for the transport, same as any other
   consumer.
3. Write a thin dispatch shim that builds the ops table and forwards to
   `shieldnet_command_dispatch`.

Done. The parsing and the wire encoding ported with you; your own tests only
need to cover the ops implementation.

### Extensions

The core implements the commands, responses and modes the specification
(`spec/application.md`) defines for every device. A device that adds something
above them — a feature with its own commands, its own `DEVICE_INFO` entries and
its own state — plugs it in through one pointer, `shieldnet_device_ops_t.ext`,
which refers to a `shieldnet_device_ext_t`. The core does not know what the
extension is; it forwards to it:

- **`handle`** (required). Called for every command kind below `0x80` that the
  core does not implement, with the message number and payload. Return
  `SHIELDNET_EXT_UNHANDLED`, having sent nothing, for a kind that is not the
  extension's: the core then answers `ERR_UNKNOWN_KIND`. Otherwise send any
  typed responses with `dev->send_response`, then exactly one ACK with
  `shieldnet_send_ack` (none for a kind the extension defines as response-free),
  and return 0 or the first negative send result. Response kinds
  (`0x80`–`0xFF`) never reach it. Of the ops, only `send_response` is certain to
  be set: check any other op `handle` calls, and answer `ERR_UNKNOWN_KIND`
  through `shieldnet_send_ack` when one it needs is missing. A private
  extension's kinds are `0x60`–`0x7F` (spec 7.8).
- **`caps`** and **`fields`**. Capability names and valued fields added to
  `DEVICE_INFO` and the mDNS `caps` value, after the core's own. The core keeps
  the first `SHIELDNET_EXT_CAPS_MAX` and `SHIELDNET_EXT_FIELDS_MAX` valid
  entries and skips (logging once) a NULL or empty entry, a name outside
  `[a-z0-9-]`, a name or value over 255 bytes, and a core name (`envelope`,
  `strips`, `leds`, `bpp`, `pixel`, `pts`).
- **`fill_status`** (optional). Fills the 44-byte block at `STATUS` bytes 32–75,
  which the core otherwise sends as zero (spec 5.2). Only the program extension
  the specification reserves may use it.
- **`has_mode`** (optional). Whether the device has a mode (`SET_MODE`,
  `GET_MODE`, `STATUS`; spec 4.3) through the extension. The core accepts
  `SET_MODE` for mode 1 (`PIXEL`) when the device has pixel output and for any
  other mode only when `has_mode` says so, and reports a device mode only if it
  is one the device has.

`get_status` must fill `mode` and `brightness`, and the counters: a device
that sets `note_command` reports its count as `commands` (spec 5.2). An extension whose replies are
larger than `DEVICE_INFO` raises `SHIELDNET_MAX_RESPONSE_BODY` (see Integrator
obligations).

## Processing times (transport 4.3)

Transport 4.3 makes two timing budgets a deployment MUST check for its slowest
client/device pair, and requires an implementation to state the processing
times they need. Quoted from the specification:

```
round-trip time
  + the client's processing of ADMIT   (one X25519, the key derivation)
  + transmission of the first datagram                     <  PENDING_TTL_MS

round-trip time
  + the device's processing of FINISH  (three HMACs, two X25519,
                                        the key derivation)   <  FINISH_PHASE_MS
```

The defaults are `SN_PENDING_TTL_MS` 5000 ms (`sn_device.h`) and
`SN_FINISH_PHASE_MS` 1500 ms (`sn_client.h`); both are overridable.

- **The client's ADMIT processing**: 106.80 µs on the host, an Intel Core
  i7-14700KF, measured with
  `cmake -S bench -B build/bench && cmake --build build/bench && build/bench/sn_client_bench`
  (section `[3]`, line `admission, client side`). Measure your own client
  platform the same way.
- **The device's FINISH processing**: not yet measured on any target. The
  on-device benchmark (`bench/shieldnet-esp32`, section `[2]`) measures one
  X25519 and the key derivation, which is part of it; a deployment measures the
  whole of it on its own device before relying on the FINISH-phase budget.

## Compatibility with the Go implementation

The Go implementation ([goshieldnet](https://github.com/shieldled/goshieldnet),
`v1.Client`) is the reference the C code is matched against. The two are
compared continuously: a differential fuzzer runs both over the client's
receive checks, and `TestGoDeviceCClientInterop` in goshieldnet admits the real C
client to the real Go device. The test vectors in `test/sn_vectors.h` are
generated by `test/gen_sn_vectors.py` from the specification repository's
`vectors/`.

## For AI assistants and LLMs

- [`AGENTS.md`](https://github.com/shieldled/libshieldnet/blob/main/AGENTS.md) gives coding
  agents (Claude Code, Codex, Cursor, Copilot and others) the rules and entry points
  for writing code with the library or changing it. `CLAUDE.md` points Claude Code at
  it.
- The documentation site serves [`llms.txt`](https://shieldled.github.io/libshieldnet/llms.txt), an index of the
  documentation for LLMs, and [`llms-full.txt`](https://shieldled.github.io/libshieldnet/llms-full.txt), the whole
  documentation (README, agent guide, benchmarks and changelog) in one Markdown file to attach to a chat. Each page is also
  served as Markdown: add `index.md` to its URL.

## Repository layout

```
include/shieldnet/   public headers
                       transport: sn_wire.h (wire messages, envelope),
                       sn_kdf.h (key schedule, MACs), sn_demux.h, sn_replay.h,
                       sn_source.h, sn_device.h (device admission and session),
                       sn_client.h, sn_client_wire.h, sn_client_session.h
                       (client), sn_app_frame.h (app layer, both roles),
                       sn_agent.h, sn_agent_dispatch.h (device app layer),
                       sn_pts.h (frame timing)
                     command core: command.h (wire kinds and ACK codes),
                       command_parse.h, command_encode.h, response_decode.h,
                       and the pure policy headers (*_policy.h)
                     framing: protocol.h, frame.h, crypto.h, decompress.h
src/                 the implementations (the policy headers and sn_pts.h are
                       header-only); command.c is shieldnet_command_dispatch,
                       the portable command core;
                       src/arch/ holds the Xtensa ChaCha20-Poly1305 used on ESP32
port/                the seams: shieldnet_io.h, shieldnet_log.h,
                       shieldnet_device.h (shieldnet_device_ops_t),
                       shieldnet_os.h with its FreeRTOS, POSIX and Win32
                       implementations (shieldnet_os_*.c)
vendor/              ikcp.{c,h}, lz4.{c,h}: vendored dependencies, ikcp
                       carrying the ShieldNet fork documented in ikcp.h's
                       header (allocate-then-ACK, a guarded ikcp_ack_push, a
                       lowerable rcv_wnd, ikcp_ooo_budget)
examples/            led_device and led_client, the programs to learn from
host/                sn_host (a device) and sn_client_host (a blocking
                       client) over real UDP, and their loopback test
bench/               sn_client_bench (host) and two ESP-IDF benchmark apps
test/                the host test suite (test/sn) and link checks
fuzz/                libFuzzer targets
ci/                  the scripts CI runs
shieldnet.cmake      the source lists consumers include
AGENTS.md            guidance for coding agents (CLAUDE.md imports it)
```

## Third-party components

This repository distributes the following third-party code in `vendor/`, each
under its own licence. The full licence texts are in
[`LICENSE`](https://github.com/shieldled/libshieldnet/blob/main/LICENSE), and
the attributions in [`NOTICE`](https://github.com/shieldled/libshieldnet/blob/main/NOTICE).

| Component | Version | Licence | Files |
|---|---|---|---|
| [LZ4](https://github.com/lz4/lz4) | 1.10.0, unmodified | BSD-2-Clause | `vendor/lz4.c`, `vendor/lz4.h` |
| [KCP](https://github.com/skywind3000/kcp) | **modified**, see the header of `vendor/ikcp.h` | MIT | `vendor/ikcp.c`, `vendor/ikcp.h` |

[libsodium](https://libsodium.org) (ISC) is a required external dependency. It
is linked from the system or the ESP-IDF component, not distributed here.

## Security

Report a vulnerability privately, as
[`SECURITY.md`](https://github.com/shieldled/libshieldnet/blob/main/SECURITY.md)
describes; do not open a public issue for it.

## License

Copyright (c) 2025-2026 BlackShield LDA. Licensed under the Apache License,
Version 2.0. See [`LICENSE`](https://github.com/shieldled/libshieldnet/blob/main/LICENSE).
