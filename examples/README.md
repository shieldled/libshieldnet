# Examples

Two small programs, one for each side of a ShieldNet link, written to be read
from top to bottom:

- [`led_device.c`](led_device.c) is an LED device. It admits a controller,
  runs the session and answers ShieldNet commands through the library's command
  core. Its "LEDs" are a 4 x 16 RGB framebuffer in memory, and it prints a line
  for every pixel frame it receives.
- [`led_client.c`](led_client.c) is a controller. It takes control of a device,
  prints the device's geometry, switches it to PIXEL mode, sends five frames of
  one colour and reads STATUS back to confirm the device counted them.

They talk to each other and to other ShieldNet implementations: the device
serves [libshieldnet-client](https://github.com/shieldled/libshieldnet-client)'s
`snc-info` and `snc-fill`, and the client drives the Go reference device.

Both are POSIX C11, tested on Linux, and link libsodium. Plumbing that
has nothing to do with ShieldNet (argument parsing, reading the key file,
listing the host's IPv4 addresses) is in [`example_util.h`](example_util.h).

## Build

From the repository root, with CMake 3.10 or newer (3.20 for `ctest --test-dir`)
and libsodium 1.0.19 or newer
(`ci/install-deps.sh` installs one into `~/.local`, where this build looks
first):

```sh
cmake -S examples -B build/examples
cmake --build build/examples
ctest --test-dir build/examples      # runs led_loopback.sh
```

[`CMakeLists.txt`](CMakeLists.txt) compiles the library's sources straight into
each program from the lists in `shieldnet.cmake`: the device takes
`SHIELDNET_SOURCES` (both roles), the client only `SHIELDNET_CLIENT_SOURCES`.

## The key

Both programs read the 32-byte pre-shared key (PSK) as 64 hex digits from the
file named by `SHIELDNET_PSK_FILE`. Neither accepts a key on the command line,
where every local user could read it with `ps`. To make one:

```sh
umask 077
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > psk.hex
```

Every device and controller that should talk to each other needs the same key.
The device turns it into its device key, `k_dev`, as soon as it has read it and
then forgets it: a real device is provisioned once and stores only `k_dev`.

## Running both on one machine: `-same-host`

ShieldNet refuses traffic from loopback and from the host's own addresses
(transport 7.2): a device never admits a client that appears to be itself.
That is right for a deployment and in the way when you run both ends on your
laptop. Both programs therefore take a first argument, `-same-host`, that turns
the check off:

- `led_device -same-host` calls `sn_device_set_source_check(&dev, 0)` and
  classifies datagrams with `sn_classify_datagram` instead of `sn_classify`;
- `led_client -same-host` skips its own check of the device's address.

**`-same-host` is for development only.** Without it both programs are strict:
the client refuses `127.0.0.1` or one of the host's addresses, and a strict
device never admits a client on the same host. The loopback test checks both.

## Quick run

```sh
# terminal 1: a device on loopback, port 32000, device id 0102030405060708
SHIELDNET_PSK_FILE=psk.hex build/examples/led_device -same-host 127.0.0.1 32000 0102030405060708

# terminal 2: fill it with orange
SHIELDNET_PSK_FILE=psk.hex build/examples/led_client -same-host 127.0.0.1 32000 0102030405060708 ff8000
```

The client prints:

```
device: 4 strips x 16 LEDs, 3 bytes per LED, envelope 4096
sent 5 frames of #ff8000 (64 pixels each); device reports 5 frames, 0 dropped, mode 1, brightness 255
```

and the device (stdout, then stderr):

```
listening on 127.0.0.1:32000
session started
frame 1: 64 pixels, first #ff8000
frame 2: 64 pixels, first #ff8000
frame 3: 64 pixels, first #ff8000
frame 4: 64 pixels, first #ff8000
frame 5: 64 pixels, first #ff8000
warning: -same-host: source checks are OFF (development only)
```

Stop the device with Ctrl-C: it prints `stopping`, ends the session and wipes
its keys. Use port `0` to let the system choose; the device prints the port it
got.

On a network, give the device the address of the interface it should serve
and leave out `-same-host` on both sides.

## led_device

```
SHIELDNET_PSK_FILE=<file> led_device [-same-host] <ipv4> <port> <device-id-hex-16>
```

What it demonstrates, in the order the code does it:

1. **Keys.** `sn_provision_kdev` (`sn_kdf.h`) turns the PSK and the device id
   into `k_dev`, and wipes the PSK. `sn_device_init_kdev` (`sn_device.h`)
   starts the device from `k_dev`, with a `cookie_secret` and an
   `admission_epoch` drawn from libsodium's CSPRNG at every start and never
   stored (the epoch with its top 8 bits clear). These are the first of the
   integrator obligations listed in the repository README.
2. **The local-prefix table.** `ex_local_prefixes` lists the host's IPv4
   addresses as `sn_prefix` entries (`sn_source.h`). The device uses it to drop
   datagrams from its own addresses and from subnet broadcasts. An empty table
   would silently skip those checks, so the program refuses to start without
   one.
3. **One socket, one address.** The device binds the address you give it, not
   `0.0.0.0`.
4. **The receive loop** (main thread). Each datagram goes through
   `sn_classify` (`sn_demux.h`) and then to its handler: `sn_handle_init`
   answers an INIT with a RETRY, `sn_handle_finish` answers a FINISH with an
   ADMIT, and `sn_handle_envelope` feeds session traffic to KCP. When it returns
   `SN_ENV_PROMOTED` a client has just taken control, and the loop tells the
   agent thread. The session's own output leaves through the sink set with
   `sn_device_set_send_to`, always to the address the session was admitted
   from.
5. **The timers.** `sn_device_start_tick` runs the transport's maintenance tick
   (retransmission, cookie epochs, expiry) on a thread of its own.
6. **The agent thread** (`sn_agent_dispatch.h`). After each promotion it binds
   an agent with `sn_agent_init`, then loops on `sn_agent_step`, which reads one
   whole message, decrypts it and hands it to the command core. When a step
   returns -1 the stream can no longer be trusted, and the thread calls
   `sn_agent_end`, as the README's obligations require.
7. **The ops table** (`shieldnet_device_ops_t`, `port/shieldnet_device.h`). The
   command core parses every command and encodes every response; the device
   only fills in the callbacks. `get_geometry` reports 4 strips of 16 RGB LEDs
   and the envelope (the largest message the device accepts);
   `publish_pixel_frame_at` receives each validated frame as R,G,B,W bytes with
   its frame number and timestamps; `note_command` counts the other messages;
   `get_status` fills STATUS;
   `send_response` seals a reply with `sn_agent_respond`. With these set, the
   device answers GET_DEVICE_INFO, GET_STATUS, PING, SET_BRIGHTNESS, SET_FPS,
   SET_MODE, GET_MODE, ON, OFF and PIXEL_FRAME. An op left NULL makes the core
   answer that command `ERR_UNKNOWN_KIND`.
8. **Teardown**, in order: `sn_device_stop_tick`, `sn_device_end_primary`
   (which wakes an agent waiting for data), join the agent thread,
   `sn_device_release_primary`, `sn_device_wipe`, `sn_device_locks_free`.

All ops run on the agent thread, so the framebuffer needs no lock. A device
whose ops share state with other threads locks inside each op.

The device uses `publish_pixel_frame_at`, so it prints the frame number the
controller sent, and `note_command`, so STATUS counts every command it
received (the GET_STATUS being answered included).

## led_client

```
SHIELDNET_PSK_FILE=<file> led_client [-same-host] <ipv4> <port> <device-id-hex-16> <rrggbb>
```

The client library (`sn_client.h`) owns no thread, no socket and no clock.
This program supplies all three, and the whole event loop is a `poll()` with a
10 ms timeout: every datagram that arrives goes to `sn_client_input`, and every
turn of the loop calls `sn_client_tick`, which drives retransmission and the
deadlines. What it demonstrates:

1. **The address check.** Before anything is sent, `sn_source_rejected`
   (`sn_source.h`) refuses a device address that is loopback, a local broadcast
   or this host's own address.
2. **A connected UDP socket.** `connect()` makes the kernel drop datagrams from
   anyone but the device, which is the source check `sn_client_input` relies
   on. `getsockname()` gives the client its own address, which admission binds
   (`own_source`, built with `sn_canonical_source`).
3. **Set-up.** `sn_client_init` derives the client's keys from the PSK (the
   program then wipes its copy); `sn_client_set_send` is the datagram sink;
   `sn_client_set_app_buffers` and `sn_client_set_compress_buffer` give the
   message layer its buffers, while the client is still idle;
   `sn_client_set_on_app` receives each decoded response.
4. **Taking control.** `sn_client_take_control_app_padded` starts admission,
   with GET_DEVICE_INFO as the first message. Control messages are sent padded,
   which hides their length (message layer 6.2).
5. **The conversation.** The callback only records what arrived and the main
   loop acts on it, because a callback must not call back into the client:
   - DEVICE_INFO is decoded with `sled_decode_geometry` (`response_decode.h`) and
     printed; then SET_MODE(PIXEL) is encoded with `shieldnet_encode_set_mode`
     (`command_encode.h`) and sent with `sn_client_send_app_padded`;
   - its ACK is decoded with `sled_decode_ack`; then five PIXEL_FRAMEs go out,
     40 ms apart, each a 28-byte header from `shieldnet_encode_pixel_frame_header`
     followed by 4 bytes per pixel (R,G,B,W), sent with
     `sn_client_send_app_compressed` (pixel frames may be compressed, never
     padded);
   - GET_STATUS last. The device answers commands in order, so its STATUS,
     decoded with `sled_decode_status_resp`, counts every frame sent before it.
6. **Back-pressure.** A send that returns `SN_CS_QUEUE_FULL` is retried on the
   next turn; any other error ends the program.
7. **Exit.** `sn_client_close` ends the session and `sn_client_free` wipes the
   client's keys.

The frame covers the whole device, unless the device is larger than one message
can carry (the device's envelope, or `sn_client_max_app_body`). A shorter frame
is still valid: it updates the first pixels only.

## The loopback test

[`led_loopback.sh`](led_loopback.sh) starts `led_device -same-host` on
127.0.0.1 with a fresh random key, runs `led_client -same-host` against it
twice (the second client takes control from the first), and checks the output
of both. It then checks that the default is strict: the client without
`-same-host` refuses 127.0.0.1, and a device without it never admits a client
on the same host. `ctest` runs it; to run it by hand:

```sh
sh examples/led_loopback.sh build/examples/led_device build/examples/led_client
```

```
ok   led_device -same-host listening on 127.0.0.1:60984
ok   client exits 0
ok   client printed the geometry
ok   client saw STATUS count all 5 frames
ok   device printed 5 frames of #00ff80
ok   second client exits 0
ok   device printed the second client's frames
ok   client without -same-host refuses 127.0.0.1 (exit 2)
ok   a strict device never admits a loopback client (client exits 1)
ok   the strict device started no session
all led_device / led_client loopback cases pass
```

## Against other implementations

The examples speak the same protocol as the Go reference implementation
([goshieldnet](https://github.com/shieldled/goshieldnet)) and the desktop client
library [libshieldnet-client](https://github.com/shieldled/libshieldnet-client). On one machine, use a LAN address rather than
127.0.0.1 (those implementations always refuse loopback) and `-same-host` on
the example.

`led_device`, queried by a libshieldnet-client tool that prints DEVICE_INFO and
STATUS:

```
envelope 4096  strips 4  leds 16  bpp 3
caps pixel
pixel 1  pts 0
mode 1  output_enabled 1  brightness 255  target_fps 25
frames 0  commands 2  pixel_frames_dropped 0
```

`led_client` against the Go reference device (4 strips of 64 LEDs):

```
device: 4 strips x 64 LEDs, 3 bytes per LED, envelope 1068
sent 5 frames of #00ff00 (256 pixels each); device reports 5 frames, 0 dropped, mode 1, brightness 255
```

That device counts the frames it has shown since it started, so a second run
reports a higher number, and a frame not yet shown when STATUS is read makes it
one lower.

## Where to go next

- The [repository README](https://github.com/shieldled/libshieldnet#readme): how the protocol works, the integrator obligations
  (ICMP handling, IP reassembly and the others a program cannot show), and how
  to port the command core to real hardware.
- `include/shieldnet/sn_client.h` and `include/shieldnet/sn_device.h`: the
  contracts of every call used here, documented at the declaration.
- `port/shieldnet_device.h`: each op of the table, what it must do and when it
  may be left NULL.
