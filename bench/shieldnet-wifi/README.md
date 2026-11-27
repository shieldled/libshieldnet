# ShieldNet — Wi-Fi bandwidth benchmark

Measures the **whole path**: host → Wi-Fi → lwIP → the admission/envelope/KCP
stack → application payload on the device. The sibling [`bench/shieldnet-esp32`](../shieldnet-esp32/README.md)
measures the device's CPU in isolation (no network); this one adds the radio.

## 1. Device side

```sh
. $IDF_PATH/export.sh
cd bench/shieldnet-wifi
idf.py set-target esp32          # or esp32s3 (not esp32p4: it has no Wi-Fi radio of its own)
idf.py menuconfig                # -> "ShieldNet Wi-Fi benchmark"
                                 #    set SSID, password, (optionally) port + PSK
idf.py build flash monitor
```

**Credentials live only in `sdkconfig`,** which is gitignored for this project —
they are never committed. The PSK defaults to `0x33` × 32 and must match the host.

At boot the device prints what the host driver needs:

```
DEVICE_IP 192.168.1.42
DEVICE_PORT 32100
RAW_PORT 32101
READY — waiting for the host driver
```

Then, once traffic flows, a line per second — **this is the authoritative number**,
because it counts payload that actually arrived and decrypted on the device:

```
RATE 1.842 MB/s  (14.74 Mbit/s)  total 5312 KB | dgrams=1862 active=1 quiesced=0 dead=0 rcv_que=0 rcv_buf=0 snd_que=0 snd_buf=0
```

After the totals, the line shows the primary session's state: `dgrams` is the
messages received so far, `active`, `quiesced` and `dead` the session's
flags, and `rcv_que`/`rcv_buf`/`snd_que`/`snd_buf` the KCP queue depths. When
the rate collapses, they tell a stuck receive queue from a quiesced or dead
session.

`RAW_PORT` (`DEVICE_PORT` + 1) is a plain UDP sink with no ShieldNet at all:
send it any UDP stream from the host and the device prints a
`RAWUDP <MB/s>` line per second. It is the radio and lwIP ceiling, to tell
apart from the protocol's.

You also need the device's STA MAC (the `device_id` is `MAC || 00 00`); it is in
the boot log, or read it from your AP's client list.

## 2. Host side

```sh
cd goshieldnet
SN_DEVICE=192.168.1.42:32100 \
SN_DEVICE_MAC=aa:bb:cc:dd:ee:ff \
SN_SECONDS=10 \
go test ./v1/ -run TestWifiBandwidth -v
```

Optional: `SN_PSK=<64 hex>` if you changed it in menuconfig.

The host reports what it managed to push plus `Send()` latency percentiles; the
device reports what it received. **Compare the two** — a gap is loss/retransmission
on the air, which is exactly what this benchmark exists to expose.

## Reading the results

- **Device `RATE` < host push rate** → the air or the device is the limit; check the
  gap and the KCP retransmit behaviour.
- **Both low but the device CPU is idle** → Wi-Fi is the constraint (distance, band,
  interference, or an AP that rate-limits).
- **Compare against the offline ceiling** (`bench/shieldnet-esp32`): the device's
  own RX path sustains ~2.77 MB/s on an ESP32 @240 MHz, so anything well below that
  over the air is the radio, not the protocol.

## Measured results (ESP32 @240 MHz, WPA2, RSSI −50 dBm)

20-second sustained run, 1 KB application messages:

| | Result |
|---|---|
| Admission over Wi-Fi | 135–330 ms |
| Sustained inbound | **0.39–0.71 MB/s (~0.49 MB/s avg, 3.9 Mbit/s)** |
| Total received | 9.8 MB in 20 s, no stall |
| Host `Send()` latency | p50 ~1 µs, p99 71 ms, max 600 ms |

Context from the offline benchmark: the device's RX path costs ~370 µs per 1 KB
datagram (2.77 MB/s of pure CPU), so at ~0.5 MB/s over the air the CPU is ~18%
busy — **the radio, not the protocol, is the limit here.**

### Two bugs this benchmark found

1. **Missing RX-path ACK flush** (`sn_session.c`, RFC §8.4/§12). Without it a
   sustained inbound stream collapsed from ~0.45 MB/s to ~0.005 MB/s and never
   recovered, while the device was provably idle (`rcv_que=0`, not quiesced, not
   dead) and the sender's writes blocked ~800 ms — ACK starvation, not overload.
   Fixed; the same run then held 0.5 MB/s for its full duration.
2. **`shieldnet_os_sleep_until_ms` panicked on FreeRTOS** — `pdMS_TO_TICKS(5)`
   truncates to 0 at the default 10 ms tick and `vTaskDelayUntil` asserts, so the
   device boot-looped. This would have hit the real firmware identically.

### A note on the device loop shape

The device app here is a single loop (recv → demux → drain). Restructuring it to
mirror the firmware's dedicated-RX-task split was tried and **reintroduced the
stall**, so it was reverted — the ACK flush and the task shape interact, and the
single loop is the configuration these numbers come from. The real firmware uses
separate RX and agent tasks, so **that path still needs its own over-the-air
measurement** before the numbers above are assumed to carry over to it.

## Notes

- Wi-Fi power save is disabled (`WIFI_PS_NONE`) — leaving it on roughly halves
  throughput and adds large latency jitter.
- The device uses `rcv_wnd = 64` (≈88 KB) here rather than the §11 default of 8, so
  the window is not the bottleneck; see [transport tuning](https://github.com/shieldled/goshieldnet/blob/main/docs/tuning.md) in goshieldnet.
- §4.3 source rejection is enforced on the device (the interface prefix comes from
  the live netif). The host driver sets `skipSrcCheck` for its own RX only.
