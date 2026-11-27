# Changelog

All notable changes to **libshieldnet** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-27

First public release: the C implementation of ShieldNet v1
([shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol) version 1),
in portable C11 with libsodium as its one dependency.

- **Device role**: admission, the encrypted session over KCP with replay
  protection and source checks, the message layer, and the agent that reads
  commands from the session and writes responses (`sn_device.h`,
  `sn_agent_dispatch.h`); the ShieldLED command core, whose `shieldnet_device_ops_t`
  callbacks a device implements (`port/shieldnet_device.h`).
- **Client role**: admission and the session from the controller's side
  (`sn_client.h`), for embedded targets; desktop applications use
  [libshieldnet-client](https://github.com/shieldled/libshieldnet-client).
- **Ports**: ESP-IDF (FreeRTOS), POSIX and Win32 OS ports behind small port
  headers, and an Xtensa-optimised AEAD for the ESP32 (`src/arch/`).
- **Interoperability**: byte-exact with the Go implementation
  ([goshieldnet](https://github.com/shieldled/goshieldnet)), checked in CI, and
  with the specification's test vectors.
- **Tests**: the test suite under AddressSanitizer, UndefinedBehaviorSanitizer
  and ThreadSanitizer and with non-default build constants, libFuzzer targets,
  on Linux and on Windows (MinGW-w64 under Wine, and natively with MSYS2); the
  ESP32 benchmark apps build for esp32, esp32s3 and esp32p4.
- **Examples**: an LED device (`examples/led_device.c`) and a client
  (`examples/led_client.c`), with a loopback test.
- **Documentation site** with an API reference generated from the public
  headers, `llms.txt` / `llms-full.txt`, `AGENTS.md`, `SECURITY.md`, `NOTICE`,
  and a CycloneDX SBOM (`ci/sbom.py`) scanned with Grype in CI.

[1.0.0]: https://github.com/shieldled/libshieldnet/releases/tag/v1.0.0
