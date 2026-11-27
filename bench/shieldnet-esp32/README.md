# ShieldNet — on-device benchmark

A flashable ESP-IDF app that measures the stack's performance **on the ESP32
itself**, with no network peer: it drives the real library against an in-process
client and prints results over UART. This bounds what the device's CPU can do; the
wire will be slower.

## Build & flash

```sh
. $IDF_PATH/export.sh
cd bench/shieldnet-esp32
idf.py set-target esp32        # or esp32s3 / esp32p4
idf.py build flash monitor
```

libsodium is pulled automatically (managed component, `main/idf_component.yml`).

## What it measures

The sections print in this order:

- **[0] Envelope correctness** — `sn_seal` on Xtensa uses the library's
  Xtensa-tuned ChaCha20-Poly1305 (`src/arch/`); this checks its envelopes
  byte for byte against libsodium for both directions and several lengths,
  and that `sn_open` reverses them. Read it first: the numbers below mean
  nothing if it fails.
- **[1] Envelope AEAD** — `sn_seal` + `sn_open` at 64/256/1024/1380 B. This is
  the **per-byte bandwidth ceiling**: every enveloped datagram pays it. This is
  the number that caps throughput.
- **[1b] AEAD component costs** at 1024 B — ChaCha20 and Poly1305 alone, from
  libsodium and from the library's Xtensa-tuned versions in `src/arch/`
  (`sn_chacha_xtensa.h`, `sn_poly_xtensa.h`, `sn_aead_xtensa.h`, the code the
  envelope uses on Xtensa), each checked against libsodium (`matches
  libsodium: YES`).
- **[1c] Alternative AEADs** at 1024 B — AES-GCM and AES-CCM on the hardware AES
  engine, and software ChaCha20-Poly1305, through PSA Crypto (mbedTLS), for
  comparison only: the protocol's AEAD is ChaCha20-Poly1305.
- **[2] Admission crypto** — one X25519 DH + the §4.5 key schedule. This is part
  of the once-per-session FINISH cost (the full FINISH adds three HMACs and a
  second X25519); it bounds how fast the device can admit controllers, not
  steady-state bandwidth.
- **[3] Replay window** — test-and-mark ops/s (negligible next to the AEAD).
- **[4] Full inbound RX** — a bidirectional in-process loop (client streams c2s,
  the device processes and ACKs) exercising demux + AEAD open + replay +
  `ikcp_input`. Wall-clock throughput is skewed by the single-threaded
  virtual-clock KCP simulation, so it also prints `DEVICE RX THROUGHPUT`, the
  device's own RX work: read that as the full-path figure, and take [1] as the
  bandwidth ceiling.

## Host reference

This app runs on ESP-IDF only. For a host reference, `bench/sn_client_bench`
measures the client's receive checks, app-frame seal and open, and a full
admission against an in-process device on the host:

```sh
cmake -S bench -B build/bench && cmake --build build/bench && build/bench/sn_client_bench
```

## Tuning note

The inbound test raises the KCP windows to 64 segments (`snd_wnd` and `rcv_wnd`,
through `sn_device_set_tuning`) so throughput reflects the crypto, not the
default 8-segment window. In production `rcv_wnd` is a board setting sized to
the heap — see [transport tuning](https://github.com/shieldled/goshieldnet/blob/main/docs/tuning.md) in goshieldnet.
