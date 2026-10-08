# replaystorm

A multithreaded pcap replayer over Linux `AF_PACKET` (TX_RING) for testing network sensors with
large captures (hundreds of GB) at 25 Gbit/s and beyond, on machines with many but weak cores.

- Frames are sent **byte for byte, including L2**: MAC addresses, VLAN/QinQ, MPLS, PPPoE, ARP,
  STP, LLDP and any non-IP frames, as they were captured.
- Rate: maximum, fixed (Mbit/s, pps, or a share of the link "on the wire"), or by pcap timestamps
  with a speed multiplier (preserving the shape of the traffic, including its bursts).
- Built for files larger than RAM: an on-disk index cache, `O_DIRECT` streaming into a RAM window,
  NVMe temperature monitoring and a thermal governor.
- Built for runs that last days or weeks: endless looping with new sessions on every lap,
  surviving link outages, a watchdog, and long-run statistics you can query at any time.
- `AF_PACKET` by default; optionally DPDK (`--dpdk`, built with `make dpdk`). Rust, the only
  dependency is `libc` (plus DPDK for the DPDK build).

Contents: [Building](#building) · [Recipes](#recipes) · [How it works](#how-it-works) ·
[Rate modes](#rate-modes) · [Timestamp replay](#timestamp-replay) ·
[Looping with modification](#looping-with-modification) ·
[Files larger than RAM](#files-larger-than-ram) · [Long runs](#long-runs) ·
[Statistics](#statistics) · [Tuning the sender](#tuning-the-sender) ·
[Checking the receiver](#checking-the-receiver) · [Realism of the load](#realism-of-the-load) ·
[DPDK backend](#dpdk-backend) · [Analysis mode](#analysis-mode) · [Input files](#input-files) · [Tests](#tests) ·
[Results](#results) · [Known limitations](#known-limitations) · [Source layout](#source-layout) ·
[Command line reference](#command-line-reference)

## Building

replaystorm is written in Rust (edition 2021, the only dependency is the `libc` crate).

```sh
# Rust toolchain, once, without root (or the distribution's rust/cargo packages if recent enough)
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal

make                # cargo build --release, copies the binary to ./replaystorm
make static         # a fully static binary (musl) that runs on any x86_64 Linux
make unit-test      # cargo test --release
make test           # unit tests + test pcap generation + functional tests on veth
make clippy         # lints
make dpdk           # with the DPDK backend (see DPDK backend)
sudo install -m 755 replaystorm /usr/local/bin/
```

- Requires Rust 1.80+ and Linux 3.14+ (`PACKET_QDISC_BYPASS`). Tested on Fedora (kernel 6.19) and
  RHEL 8 (kernel 4.18). Some features are better on newer kernels (`MADV_POPULATE_READ` from
  5.14); older ones get an equivalent fallback.
- For older systems such as RHEL/CentOS 8, the simplest is to build a static binary on any
  machine (`rustup target add x86_64-unknown-linux-musl`, then `make static`) and copy only the
  binary: it does not depend on the system's glibc. A normal `make` binary must be built on a
  system with the same or an older glibc than the target.
- Without internet on the build machine: run `cargo vendor` on a machine with internet and copy
  the `vendor/` directory along (see the `cargo vendor` output for the config lines).
- Running requires root (or `CAP_NET_RAW`; `CAP_NET_ADMIN` to enlarge the socket buffer; root also
  for `mlock` of the index and for reading the NVMe temperature on older kernels).
- The tests need python3 without third-party modules, `ip` and `ethtool`. Functional tests use
  their own network namespace (`unshare -rn` without root).

## Recipes

```sh
# What is inside the file: traffic mix, VLAN share, timestamp anomalies, rate peaks, shards
replaystorm --analyze big.pcap
replaystorm --analyze --multiplier 10 --link-speed 25G big.pcap

# Build the index cache once (reads the whole file); later starts take seconds
replaystorm --analyze --index-cache /var/tmp/big.rsidx big.pcap

# Line rate on a 25G link, forever, new sessions on every lap
replaystorm -i ens1f0 big.pcap --mbps 99% --loop 0 --loop-mutate ip,port \
  --qdisc-bypass --index-cache /var/tmp/big.rsidx

# Customer traffic shape, 20x faster (peaks and pauses kept, scaled)
replaystorm -i ens1f0 big.pcap --multiplier 20 --loop 0 --loop-mutate ip,port --qdisc-bypass

# Maximum rate, 12 threads
replaystorm -i ens1f0 --topspeed --qdisc-bypass -t 12 big.pcap

# Play the file in exactly 10 minutes, statistics to JSON
replaystorm -i ens1f0 --duration 10m --stats-json run.json big.pcap

# RAW IP pcap (linktype 101/228/229): an Ethernet header is prepended
replaystorm -i ens1f0 --smac 02:00:00:00:00:01 --dmac 02:00:00:00:00:02 raw.pcap
```

### A run that lasts days or weeks

```sh
screen -S replaystorm
timeout -s INT 30d replaystorm -i ens1f0 /data/big.pcap \
  --mbps 99% --loop 0 --loop-mutate ip,port \
  --qdisc-bypass --cpus 1-11 -t 10 \
  --readahead 24G --disk-max-temp 74 \
  --index-cache /var/tmp/big.rsidx \
  --stats-json /root/replaystorm-$(date +%F).json -q
# Ctrl-A D to detach; screen -r replaystorm to come back
```

| Option | Why |
|---|---|
| `--mbps 99%` | 99% of the link counted on the wire, no ENOBUFS from asking more than the link carries |
| `--loop 0 --loop-mutate ip,port` | loop forever; every lap brings new sessions (see the address caveat below) |
| `--cpus 1-11 -t 10` | 10 IP threads + 1 non-IP thread on cores 1-11, core 0 left to the system |
| `--readahead 24G` | RAM window that rides out short disk slowdowns (index + window must fit in RAM) |
| `--disk-max-temp 74` | safety net: if cooling degrades, the read rate goes down smoothly instead of collapsing |
| `--index-cache` | start in seconds without heating the disk by reading the whole file |
| `-q` | no per-second line (millions of lines over days); statistics stay available on request |
| `timeout -s INT 30d` | stops after 30 days exactly like Ctrl-C: summary, status file and JSON are kept |

Check it at any time from another terminal: `replaystorm --status -i ens1f0`. In its own terminal:
Enter (statistics), `r` (reset minimum/maximum), `q` (stop).

Before a long run: build the index cache, make sure no other replayer uses the interface, enlarge
the NIC TX ring (`ethtool -G IF tx <max>`), check the NVMe temperature under load (see
[Files larger than RAM](#files-larger-than-ram)).

## How it works

1. **The file** is mapped read-only (`mmap`) for indexing and, if it fits in RAM, for sending. A file
   larger than RAM is streamed during the replay (see [Files larger than RAM](#files-larger-than-ram)).
2. **The index** is built in one sequential pass over the records (the pcap record chain cannot be
   walked otherwise); in parallel, N threads classify and hash already-read packets in blocks of 64K.
   It is built in two steps: the option-independent part (offset, length, timestamp, a 32-bit
   symmetric flow hash, classification flags; 21 bytes per packet) can be cached on disk; shard
   numbers and MTU-based skipping are resolved in parallel on every start.
3. **The timeline** is normalized from the timestamps (outliers, clamp, max-gap), in parallel and
   bit-identical to a single-threaded reference implementation (see
   [Parallel preparation](#parallel-preparation)).
4. **Sharding** uses a symmetric 5-tuple hash, so A→B and B→A go through the same thread and order
   within a session is preserved. The parser walks VLAN/QinQ (0x8100, 0x88a8, 0x9100, 0x9200), MPLS
   (including a pseudowire with control word and inner Ethernet), PPPoE and IPv6 extension headers.
   IP fragments (v4 and v6) are hashed without ports, so all fragments of a datagram stay together.
   The VLAN ID is deliberately not part of the hash: in SPAN captures from several segments the same
   session appears in several VLANs, and all copies must stay in order. Tunnels are hashed by the
   outer header. Non-IP frames go to a separate shard with its own thread.
5. **Sender threads.** One thread per non-empty shard, pinned to a core; it allocates its shard index
   (locked in RAM) and its TX_RING after pinning, so memory is NUMA-local. Default cores:
   `/sys/class/net/<if>/device/local_cpulist`; `--cpus` overrides. Default: one IP thread fewer than
   cores, the non-IP thread on the remaining core.
6. **Sending.** Each thread has its own `AF_PACKET`/`SOCK_RAW` socket with protocol 0 (receives
   nothing), `TPACKET_V2`, `PACKET_TX_RING`. A frame is copied into the ring and after a batch
   (`--batch`, 64) one `send(MSG_DONTWAIT)` hands the whole batch to the kernel.
   `PACKET_QDISC_BYPASS` and `PACKET_LOSS` are flags. Ring slots are sized by the largest frame in
   the file (capped by MTU+18), not by the MTU. When the device queue is full (ENOBUFS/EAGAIN) a
   thread backs off (short spins, then 5-100 µs sleeps) instead of hammering `send()`.
7. **The hot loop** has no locks and no malloc; per-thread counters are cache-line aligned and
   published with relaxed stores, the statistics thread only reads them. All modes start together:
   threads pass a barrier and wait for a common point T0.

Where the CPU time goes: copying a packet into the ring costs about 58 ns (~2% of a core at 25G);
batch size barely matters (1.79 vs 1.86 Mpps for batches of 16 and 1024). About 80% of the CPU is
the kernel's per-packet work (skb, driver, completion), so kernel and NIC settings matter more than
user-space code (see [Tuning the sender](#tuning-the-sender)).

Memory: the index needs ~16 bytes per packet while sending (~550 million packets of a 500 GB file:
~9 GB) and ~34 bytes per packet at peak while it is built (more with `--ts-order sort` on unordered
timestamps). Plus the `--readahead` window when streaming.

## Rate modes

| Mode | What it does |
|---|---|
| `--topspeed` | As fast as possible. Threads wait only for free ring frames. |
| `--mbps X` | Total X Mbit/s of L2 frame bytes (without FCS, preamble and IFG). Packets are paced **in file order**: packet i is due at `T0 + (bytes before i in the file) / rate`, whichever thread sends it. The total is exact and all threads move through the file together. |
| `--mbps line`, `--mbps N%` | A share of the link speed **on the wire** (preamble, IFG, FCS, 60-byte minimum): `line` = 100%, e.g. `99%`. The link speed comes from ethtool or `--link-speed`; it is converted to an L2 rate with the file's own L2/wire byte ratio. An explicit `--mbps X` above the link on the wire gives a warning before start. |
| `--pps X` | The same in packets per second: packet i is due at `T0 + i / rate`. |
| `--pace-slack T` | `--mbps`/`--pps`: a thread sleeps and sends everything due within the next T at once (default 200 µs) instead of busy-waiting for every packet. The schedule stays absolute, so the average is exact; bursts are at most T long per thread. At 4 Gbit/s this cut user CPU from 15.3 s to 2.5 s. |
| `--multiplier X` | Replay by timestamps (the default mode, X = 1); 2.0 is twice as fast. |
| `--duration T` | The multiplier is chosen so that one lap takes T (`ns`, `us`, `ms`, `s`, `m`, `h`). |

`--loop N` plays the file N times; `--loop 0` forever. Fixed-rate schedules are computed from a
common origin, so errors do not accumulate and a stalled thread catches up.

## Timestamp replay

**Schedule.** `t_send = T0 + (lap × lap_length + ts_pkt − ts_first) / multiplier`, from a common
origin T0 shared by all threads, so errors do not accumulate and threads do not drift. The lap
length is the timeline duration plus the mean inter-packet interval, so laps continue the timeline.

**Waiting** is hybrid: `clock_nanosleep(TIMER_ABSTIME)` for long pauses (in chunks of at most 50 ms),
busy-spin for the last `--spin-us` µs (50). Timer slack is 1 ns. If the next packet is not due yet,
the pending batch is sent first. A packet that is already due is sent without re-reading the clock.

**Clock** (`--clock auto|tsc|monotonic`). If the kernel uses the `hpet`/`acpi_pm` clocksource
(`clock_gettime` ~1 µs instead of ~20 ns), `auto` uses an invariant TSC, calibrated twice for 100 ms
on one core (falls back if the estimates differ by more than 0.1%), with a per-thread offset
(cores may have offset TSCs) and a resync against `CLOCK_MONOTONIC` before each sleep.

**Lag.** A late packet is sent immediately. Lateness (actual minus scheduled time) goes into a
per-thread histogram: p50/p99/max per second, p99.9 in the summary. `--lag-policy catchup` (default)
keeps absolute times and catches up; `rebase` shifts the common T0 when lateness exceeds
`--lag-threshold` (10 ms), stretching the timeline for all threads together.

### Problematic timestamps

| Problem | What replaystorm does |
|---|---|
| Non-monotonic timestamps | `--ts-order clamp` (default) replaces a backward timestamp with the running maximum; `sort` stably sorts the index within each shard; `asis` sends backward packets immediately and counts them separately. |
| Long pauses | `--max-gap X` compresses pauses longer than X to X. `--analyze` lists the top 10 pauses. |
| Outliers | ts = 0, before 1990, in the future, and short clock spikes (a packet or up to 16 that jumped further than `--outlier-jump`, 60 s, and came back) are reported; `--ts-outliers exclude` gives them a neighbour's timestamp. |
| Speedup beyond the link | Peak rates in 1 ms, 10 ms and 1 s windows are computed with the multiplier, on L2 and on the wire; a peak above the link speed gives a warning. |
| Intervals too small | The share of intervals within a shard shorter than `--timing-res` (2 µs) after the multiplier is reported as packets that will effectively go out in bursts. |

## Looping with modification

`--loop-mutate ip|port|ip,port`: on lap k > 0 frames are modified in the TX ring (the file is never
written). **L2 (MAC, VLAN, MPLS) is never changed.**

- **ip**: `k × --mutate-ip-offset` (0.1.0.0) is added to every IPv4 address (32-bit addition with
  carry; `10.0.0.1` → `10.1.0.1` → ...). For IPv6, the 32-bit word in bytes 8-11 is shifted; the /64
  prefix stays.
- **port**: ports ≥ 1024 are shifted by `k × --mutate-port-step` within 1024..65535; service ports
  (< 1024) are kept. Only TCP/UDP, only unfragmented packets.
- The mapping is the same for both directions, so a session stays one session. Checksums are updated
  incrementally (RFC 1624): IPv4 header, TCP/UDP/ICMPv6 with the pseudo-header; a UDP zero checksum
  stays zero.
- Uniqueness: with the defaults, addresses repeat only after 65 536 laps and ports after 64 512, so
  sessions stay new for months of looping.

**Caveat: address classes change over laps.** `192.168.x.x` becomes `192.169.x.x` (public) on lap 1,
`172.16/12` leaves the private range after a few laps, a carry can move `17.248.x.x` to `18.3.x.x`.
For capture and throughput tests this does not matter. If the sensor's analysis is part of the test,
internal hosts gradually look external, and every lap creates a new set of hosts in the sensor's
host tables (memory and storage grow with it).

## Files larger than RAM

A 500 GB file on a 62 GB machine is read from disk on every lap. `--io auto` (default) chooses
direct I/O when the file is larger than 80% of available RAM, the page cache otherwise.

### Direct I/O (`--io direct`)

Reader threads (`--io-threads`, 4) read the file with `O_DIRECT` in 32 MB chunks into a ring of
buffers in RAM (the window, `--readahead`), bypassing the page cache, like `dd iflag=direct`.
Chunks are numbered across laps; each slot also holds 128 KB of the next chunk, so a packet is
always contiguous. A slot is reused only when every sender thread has passed it (threads publish
the position they read *next*). The window is filled before T0, locked in RAM, and reduced with a
warning if it does not fit into free memory.

Sender threads never touch the disk, never take page faults and never wait in the kernel. The
per-second line shows `disk X GB/s, N ms/read` (mean time of one 32 MB read: if it grows, the drive
itself got slower). Threads are kept within half the window of the slowest thread; otherwise, at top
speed, they drift apart in the file and the fast ones outrun the window. A lap ends with the slowest
thread anyway, so this does not lower the total rate.

| 3 GB file streamed from NVMe, top speed, 8 threads | rate | disk waits in sender threads |
|---|---|---|
| page cache (`--io mmap`) | 17.2-18.1 Gbit/s | 1150-1350 |
| direct I/O (`--io direct`) | 22.7 Gbit/s | 0 |

### NVMe temperature and the thermal governor

Sustained reads at the drive's limit can heat an NVMe drive into thermal throttling (Thermal
Management T1), where it drops to a fraction of its speed for tens of seconds. Seen on a test server
(consumer NVMe drive in a rack server, chassis fans at 50%): throttling at ~77 °C, 3.5 → ~1 GB/s,
after ~190 s at 24 Gbit/s and ~345 s at 20 Gbit/s; building the index also heats the drive. With
the fans at 100% the same drive stayed at 61 °C under full load.

- The temperature of the NVMe drive(s) holding the file (found through partitions, LVM, dm-crypt, md,
  btrfs) is in the per-second line, `THROTTLED` marks throttling transitions, the summary has the
  maximum. Source: sysfs hwmon on newer kernels, the NVMe SMART log (admin ioctl, root) on older ones.
- `--disk-max-temp C`: once a second a governor limits the direct I/O read rate to keep the drive at
  or below C (2-3 °C below its throttling point). This does not raise the average (cooling sets it),
  but turns "full speed, then a collapse" into a steady rate. In a thermal model (unit test): 1.97
  GB/s steady and no throttling, versus 2.04 GB/s average with drops to 1 GB/s and 106 throttling
  events per hour without it.
- `--disk-start-temp C`: wait until the drive cools down to C before filling the window.
- The real fix is cooling (airflow, a heatsink, a server fan profile) or two drives in RAID0.

Check a drive: `nvme smart-log /dev/nvme0n1 | grep -i -E "^temperature|T1 Trans Count|media_errors"`.

### Page cache (`--io mmap`)

A background thread keeps `--readahead` bytes requested with `MADV_WILLNEED` (in 1 MB pieces: the
kernel caps each request at `read_ahead_kb`), pre-maps the nearest 512 MB with `MADV_POPULATE_READ`
(or by touching pages on kernels before 5.14), and with `--drop-behind` (auto for big files) drops
what all threads have passed from the page cache. `--preload` (whole file into RAM before start) is
ignored with a warning if the file does not fit.

### Index cache

`--index-cache FILE` (or `auto` for `FILE.pcap.rsidx`) stores the option-independent index (21
bytes per packet: ~11.5 GB for 500 GB of pcap). Later starts map it instead of reading the pcap
(minutes → seconds). It is used only for the same pcap (size, mtime, inode, a hash of the first and
last 64 KB, format version), otherwise rebuilt with a message; written atomically; valid for any
`-t`, `--cpus` and MTU. Delete the file to force a rebuild.

### Parallel preparation

Timeline normalization, the radix sort for unordered timestamps and the rate profile run on the
hashing threads. Stateful phases (running maximum, gap excess, last mapped value) summarize chunks,
merge the summaries in order and redo each chunk from the exact sequential state, so the result is
bit-identical to the single-threaded reference in `src/ref_sched.rs` (unit tests compare 360
combinations of data, options and thread counts 1-16; mutation testing confirmed they catch
boundary bugs). 4.7 million packets, 1 vs 11 threads: 34 → 14 ms (normalization), 131 → 24 ms (rate
profile).

## Long runs

**Link outages.** Interface down (`ENETDOWN`): threads wait, frames stay in the ring. Interface
removed and re-created (`ENXIO`/`ENODEV`, a driver reload): threads open a new socket and ring by
name; frames from the old ring are lost and counted. Carrier lost: threads wait in the ENOBUFS
backoff. The schedule is paused for the length of the outage (applied once, by whoever first sees
the link back), so the replay continues instead of bursting to catch up. `LINK DOWN` in the
per-second line, `Link outages: N, X s` in the summary.

**Watchdog.** Each thread publishes what it is doing: sending, waiting for its schedule, for a TX
ring frame (the NIC does not complete transmissions), for the device queue (ENOBUFS), for disk data,
for the slowest thread, or for the link. A thread that sends nothing for 3 s while not waiting for its
schedule gets a warning with the reason and the file position, and another when it resumes. The
summary and the JSON show per thread how long it waited for each.

**Long-run statistics on request.** The stats thread keeps statistics of the per-second rate:

- in the program's terminal (also in `screen`): Enter or `s` prints them, `r` resets
  minimum/maximum/averages, `q` stops gracefully;
- from any terminal: `replaystorm --status -i IF` prints `/tmp/replaystorm-IF.status` (`--status-file`),
  rewritten atomically every second and kept after the end;
- `kill -USR1 PID` prints them into the program's output (`nohup`, systemd).

```
replaystorm on ens1f0, pid 4242: running for 2d 03:14:07 (started 2026-10-07 10:40:12, now ...)
  now:          24.310 Gbit/s, 3.360 Mpps, disk 61 C
  average:      last minute 24.300, last hour 24.280, overall 24.250 Gbit/s
  minimum 1 s:  18.200 Gbit/s (2.510 Mpps min) at +1d 04:12:03 (2026-10-08 14:52:15)
  worst minute: 23.950 Gbit/s on average, ended at +1d 04:12:40 (2026-10-08 14:52:52)
  maximum 1 s:  24.500 Gbit/s at +00:12:31
  1 s rate:     p1 23.90, p5 24.10, median 24.30 Gbit/s over 184230 s; below 95% of the target ...
  not counted:  10 s (warm-up, link outages, partial seconds)
  sent:         ... packets, ... TB; lap 312; ENOBUFS ...; interface tx_dropped +0
  events:       link outages 0 (0.0 s), stalled-thread warnings 0, disk max 63 C, thermal throttling 0
```

The first 10 s (warm-up), seconds with the link down and partial intervals are not counted. The
worst minute (lowest 60-second average) is less sensitive to counter jitter than the 1-second
minimum. The block is also printed at the end and its values go into the JSON summary.

## Statistics

Once a second (unless `-q`):

```
[  161.0 s]   24.266 Gbit/s    3.819 Mpps | sent (sysfs) 3.760 Mpps, tx_dropped +0 | ENOBUFS +173175 EAGAIN +0 | disk 3.30 GB/s, 38 ms/read, 61 C | file 82.4% lap 1
```

- **Gbit/s, Mpps**: frames handed to the kernel. **sent (sysfs)**: increment of the interface
  `tx_packets` (whole interface; some drivers update it about once a second, so single seconds
  jitter); **tx_dropped**: increment of `tx_dropped`.
- **ENOBUFS / EAGAIN**: see below.
- **disk**: direct I/O read rate, mean time of one 32 MB read, drive temperature, `limit` of the
  thermal governor, `THROTTLED`.
- **file X% lap N**: position of the slowest thread (rate modes); in timestamp mode
  `lateness p50/p99/max` and `pcap +X s of Y` instead.
- `LINK DOWN` during an outage.

The summary adds totals, the difference from sysfs, `send()` calls and frames per call, skipped
frames, lateness quantiles, T0 shifts, link outages, disk temperature and throttling, the long-run
statistics block, and per thread: packets, bytes, ENOBUFS and time spent waiting by reason.
`--stats-json FILE` writes a header, one `intervals` entry per second (appended while running) and
the `summary`. Exit codes: 0 success or stopped by signal, 1 runtime error, 2 argument error.

### Interpreting ENOBUFS

`ENOBUFS` from `send()` means the qdisc or driver queue did not accept the next frame. On current
kernels the frame is **not lost**: it goes back to `SEND_REQUEST` in the ring and is sent on the next
`send()`. ENOBUFS is backpressure, not a loss count; high values at top speed or at a rate above the
link are normal (use `--mbps 99%`). Real losses: the difference between frames handed to the kernel
and `tx_packets`, `tx_dropped`, `tc -s qdisc`, `ethtool -S`. Under qdisc contention some drops happen
without an error from `send()` (seen on veth with a tbf qdisc). With `--qdisc-bypass`, `tx_dropped`
can overstate losses (it counts rejected attempts that are then resent). `EAGAIN`: the socket buffer
is full; run as root or raise `net.core.wmem_max`.

### Interpreting lateness

Lateness is sender-side delay (placed in the ring vs scheduled). p50 in single-digit microseconds is
normal. High p99 with low p50: preemption, late wakeup from deep C-states, interrupts; raise
`--spin-us`, isolate cores, disable deep C-states, or use `chrt -f 50`. Growing p50 and the pcap
position falling behind: the peak exceeds the link, not enough cores, the disk or the kernel cannot
keep up. A functional test showed that the lateness replaystorm reports matches the interval error
measured at the receiver to within a few microseconds.

## DPDK backend

With `--dpdk PORT` frames are sent by a DPDK poll-mode driver instead of the kernel: no skb,
no qdisc, no TX completion interrupts. The kernel path spends ~80% of the CPU per packet; DPDK
removes it, which matters for small packets and for 100G. Everything else is the same (index,
sharding, schedules, mutation, direct I/O, statistics); each sender thread gets its own TX
queue and mbuf pool, frames are copied into mbufs and sent with `rte_eth_tx_burst` in batches,
a full TX queue is backpressure and the thread retries.

Build (needs DPDK with pkg-config, e.g. `dnf install dpdk dpdk-devel dpdk-tools numactl-devel`):

```sh
make dpdk           # cargo build --release --features dpdk
make dpdk-test      # DPDK functional tests through the af_packet driver on veth
```

A normal `make` builds without DPDK; such a binary rejects `--dpdk` with a hint.

Preparing the server (example: RHEL 8, Broadcom bnxt):

```sh
# kernel command line: intel_iommu=on iommu=pt (AMD: amd_iommu=on iommu=pt), reboot
```

The NIC and the hugepages can be prepared by hand (`dpdk-hugepages.py -p 1G --setup 8G`,
`modprobe vfio-pci`, `dpdk-devbind.py -b vfio-pci 0000:3b:00.0`; the interface disappears from
the kernel until it is bound back), or by replaystorm for the time of the run:

```sh
replaystorm --dpdk ens1f0 --dpdk-bind --dpdk-hugepages 4G --mbps 99% --loop 0 \
  --loop-mutate ip,port --cpus 1-11 --index-cache /var/tmp/big.rsidx big.pcap
replaystorm --status --dpdk ens1f0           # long-run statistics from another terminal
```

- `--dpdk-bind` moves the NIC from its kernel driver to `vfio-pci` (loading the module if
  needed) and at the end binds it back to the same driver and restores the interface's MTU
  and up state. It refuses a NIC whose interface has IP addresses (it may carry the server's
  own connection) and one without an IOMMU group. A NIC that is already on vfio-pci is used
  and left as it is.
- VFIO gives a device to DPDK only when every device of its IOMMU group is on vfio-pci. The
  ports of one card often share a group (`ls /sys/bus/pci/devices/PCI/iommu_group/devices`):
  then `--dpdk-bind` refuses and lists them, and `--dpdk-bind-group` moves the whole group for
  the run and gives every port back at the end (their interfaces disappear meanwhile; a port
  with IP addresses is refused). Only network ports are ever moved: if the group also holds a
  disk or any other device, replaystorm refuses outright. Then the NIC needs a slot with its own
  group (another PCIe root port) or ACS in the BIOS, or the kernel path (`-i`) is used.
- After the NIC is given back, the interface first appears as ethN and udev renames it;
  replaystorm waits for udev before restoring the MTU and the up state.
- Mellanox/NVIDIA ConnectX (mlx5) works differently: the DPDK mlx5 driver runs next to the
  kernel driver `mlx5_core` (needs `rdma-core`), the interface stays in the system, and VFIO
  and IOMMU groups do not matter. `--dpdk-bind` leaves such a NIC alone. With the IOMMU in
  translation mode (`intel_iommu=on` without `iommu=pt`) the NIC can only reach the memory
  registered for it.
- `--dpdk-hugepages SIZE` adds SIZE of 2 MB hugepages on the NIC's NUMA node (compacting memory
  if it is fragmented) and removes them at the end.
- Both are restored at a normal end, on Ctrl-C/SIGTERM (also while the index is being built),
  on `q` and on errors. The change is recorded in `/run/replaystorm-dpdk-PCI.state` before it
  is made: if the process is killed (`kill -9`), the next run with `--dpdk-bind` or
  `--dpdk-hugepages` restores it first. Both need root.
- Without these options the NIC and hugepages are managed by hand (`dpdk-devbind.py`,
  `dpdk-hugepages.py`) and replaystorm leaves them as they are; it always stops and closes the
  port and releases the EAL memory at the end.

- `PORT` is the NIC's interface name (its PCI address is found in sysfs; while the NIC is on
  vfio-pci after a killed run, from the state file), a PCI address, a virtual device name or
  a port number. For a NIC given by interface or PCI address, `-a PCI` is added to the EAL
  arguments so that only this NIC is probed. A NIC still on its kernel driver needs
  `--dpdk-bind` (except mlx5, which works next to its kernel driver). `--eal` passes EAL
  arguments; replaystorm adds `-l <first CPU>` (the EAL's main lcore; the sender threads pin
  themselves), `--in-memory` (`--no-shconf` with `--no-huge`) and `--log-level=5` unless given.
- The link speed and MTU come from the port; without `-t` the thread count is limited to the
  port's TX queues. The CPUs default to the port's NUMA node.
- Statistics: "sent (port)" and `oerrors` come from the port counters (`rte_eth_stats`)
  instead of sysfs; the ENOBUFS column counts `rte_eth_tx_burst` calls that found the TX
  queue full. Link down pauses the schedule as with the kernel path.
- `--qdisc-bypass`, `--packet-loss` and `--ring-frames` above 4096 do not apply; `--ring-frames`
  sets the TX descriptors per queue (up to the driver's limit).
- Without a NIC, for tests: `--dpdk net_af_packet0 --eal "--no-huge --no-pci
  --vdev=net_af_packet0,iface=veth0,qpairs=8"` sends through an ordinary interface;
  `net_null0` discards frames and shows the program's own ceiling: 44.8 Gbit/s / 6.2 Mpps from
  one thread on the laptop (AF_PACKET: 4.7 Gbit/s per thread).
- Tested with DPDK 24.11 (shared libraries, drivers loaded from the plugin directory); the API
  used exists since DPDK 21.11.

## Tuning the sender

Most of the CPU time is spent in the kernel and the NIC driver, so these settings matter:

```sh
ethtool -l IF                 # TX queues: with --qdisc-bypass a thread on CPU c uses queue c % queues;
                              # have at least as many queues as sender cores
ethtool -G IF tx <max>        # larger NIC TX ring: fewer ENOBUFS (e.g. 511 -> 2047 on bnxt_en)
ethtool -C IF tx-usecs 64 tx-frames 128   # fewer TX completion interrupts (experimental)

# completion interrupt of queue i on the CPU of the thread using queue i
systemctl stop irqbalance
for irq in $(grep IF-TxRx /proc/interrupts | awk -F: '{print $1}'); do
  q=$(grep "^ *$irq:" /proc/interrupts | grep -o 'TxRx-[0-9]*' | cut -d- -f2)
  echo $(( q % $(nproc) )) > /proc/irq/$irq/smp_affinity_list
done
```

- `dmesg | grep -i "IOMMU enabled"`: if the IOMMU translates DMA, `iommu=pt` on the kernel command
  line may help a lot.
- `tuned-adm profile throughput-performance`, low `vm.swappiness`, no other traffic generator on the
  interface (it shares the link and the RAM).
- Experimental: a newer kernel, `isolcpus`/`nohz_full` for the sender cores, `mitigations=off` on a
  lab machine.
- Disk: `dd if=FILE of=/dev/null bs=16M count=2000 iflag=direct` must deliver the target rate
  (24 Gbit/s ≈ 3.1 GB/s of pcap); watch the NVMe temperature under sustained load.

Settings made with `ethtool` and `/proc/irq` are lost on reboot; persist them with tuned or udev
if they help.

## Checking the receiver

**L2 arrives as captured.** On the sensor: `tcpdump -i IF -nn -e -c 50`. Each line shows MACs and the
VLAN tag; with replaystorm they are the original ones (many vendors' MACs, the original VLAN IDs, the
original share of tagged frames, the same session in several VLANs for multi-segment SPAN
captures), not the sender's MAC as with replayers that rewrite L2. Compare with the source:

```sh
editcap -r big.pcap ref.pcap 1-2000000
tshark -r ref.pcap -T fields -e eth.src -e eth.dst -e vlan.id | sort | uniq -c | sort -rn | head
tshark -r rx.pcap  -T fields -e eth.src -e eth.dst -e vlan.id | sort | uniq -c | sort -rn | head
```

For a byte-exact check, replay a slice once without `--loop-mutate`, capture everything on the
sensor and compare frame by frame (like the functional tests do). Notes: the NIC pads frames shorter
than 60 bytes with zeros; FCS is not captured; a switch in between drops LLDP/STP and an access port
strips VLAN tags (use a direct cable, a TAP or a trunk); if the sensor captures with DPDK or its own
driver, `tcpdump` on the host sees nothing.

**Receiver drops.** NIC level: `ethtool -S IF | grep -i -E "rx_(packets|discard|drop|miss)"`.
Suricata with AF_PACKET: drop % = `capture.kernel_drops / capture.kernel_packets` (stats.log, eve
`stats`, `suricatasc -c "iface-stat IF"`); compute it per interval, not since start. Sent vs
received: `replaystorm --status` (`sent`) against the sensor's `rx_packets`.

**Capacity of the sensor.** Step the rate (e.g. 5, 10, 15, 20, 24 Gbit/s, 10 minutes each with
`timeout -s INT 600`) and find the highest rate with drops below the acceptable level.

**Filling the sensor's storage.** Storage growth depends on what the sensor stores (full packets
fill disks at the traffic rate; flow metadata grows with sessions per second). Calibrate for an hour
(`df` on the data partition every 10 minutes), then scale `--mbps`; make sure the sensor's retention
does not delete old data. `--loop-mutate` keeps sessions new, which is what makes metadata grow.

## Realism of the load

- **Content:** replaystorm sends the capture as it was (L2 included) and, with `--loop-mutate`, new
  sessions on every lap. A capture with L2 removed makes copies of a session from different VLANs
  collapse into one flow with duplicate segments, and looping without changes repeats the same TCP
  sessions and sequence numbers; both add work to an IDS that real traffic does not cause. Such
  setups typically show higher drop rates for that reason.
- **Shape:** `--mbps` gives a smooth rate. Real traffic at the same average has bursts, and bursts are
  what overflow receive buffers. To simulate a customer's peak load, replay by timestamps with a
  multiplier: pick it with `replaystorm --analyze --multiplier X --link-speed 25G FILE` so that the 1 s
  peak is the load you want and the 1 ms peak stays below the link.
- **Loop boundaries:** at the start of every lap many sessions appear at once (the capture started in
  the middle of them). With a large file this happens rarely (a 500 GB file at 24 Gbit/s: every
  ~3 min); periodic drop spikes at the lap period come from this.

## Analysis mode

`--analyze` sends nothing and prints: format, packets and bytes, index time; timestamp range and
replay timeline (with `--ts-order`, `--max-gap`, `--ts-outliers`); mean and peak rate in 1 ms, 10 ms,
1 s windows (with `--multiplier`/`--duration`); intervals within shards; timestamp anomalies;
traffic mix (IPv4, IPv6, non-IP: ARP, LLC/STP, LLDP, other; VLAN, QinQ, MPLS, PPPoE, fragments);
skipped and truncated frames; distribution across shards and the imbalance (shards = `-t`).

## Input files

- Classic pcap, microsecond or nanosecond, either endianness. pcapng: an error with the hint
  `editcap -F pcap in.pcapng out.pcap`.
- Linktype 1 (Ethernet); 101 and 12 (RAW IP), 228 (IPv4), 229 (IPv6): an Ethernet header
  `--dmac`/`--smac` is prepended.
- caplen < origlen: sent with caplen, counted. Frames longer than MTU+14 (MTU+18 with an outer
  802.1Q tag, the same rule as the kernel's) or shorter than 14 bytes: skipped, counted.
- A file truncated or corrupt in the middle of a record: a warning; everything before it is sent.

## Tests

- `make unit-test` (`cargo test`): pcap parser (us/ns, LE/BE, truncated, corrupt, pcapng,
  linktypes); index build, resolve and the index cache (round trip, another `-t`, a changed or
  damaged pcap/cache); symmetric hash (IPv4, VLAN with different IDs per direction, QinQ, MPLS, IPv6
  with extension headers, PPPoE, fragments, non-IP, RAW IP, distribution, MTU limits); timeline
  normalization, schedules, rate profile, radix sort, histograms, and the parallel implementation
  against the single-threaded reference in `src/ref_sched.rs` (360 combinations); the rate timeline; loop mutation and RFC 1624
  checksums; the thermal governor on a drive model; long-run statistics.
- `tests/gen_pcaps.py`: generates the test pcaps (L2 mix with ARP, STP, LLDP, VLAN, QinQ, MPLS,
  pseudowire, PPPoE, IPv6, fragments; RAW IP; timestamp anomalies; a timing file; a truncated file;
  pcapng) without third-party modules. `tests/gen_big.py out.pcap 4`: a 4 GB file for benchmarks.
- `make func-test` (`tests/func_veth.sh`): on a veth pair in a private network namespace (no root
  needed): every frame byte for byte with VLAN restored from `PACKET_AUXDATA` and order within
  sessions (several modes, RAW IP, direct I/O, drop-behind, the index cache with another `-t`);
  timing at x0.5/x1/x2 against nanosecond receive timestamps; `--duration`, `--max-gap`, `--loop`,
  outliers, `--ts-order`, `--mbps N%`; `--loop-mutate` (lap 0 unchanged, checksums valid, L2
  untouched); link down/up and interface re-creation; the watchdog; `--status`, SIGUSR1; CLI errors,
  SIGINT, a truncated file.
- `make clippy`: lints. Unsafe code is limited to the system interfaces (mmap, the TX ring
  shared with the kernel, the direct I/O window) and to disjoint parallel writes in the
  preparation phases; frame parsing and checksum updates are bounds-checked.

## Results

Laptop (Ryzen 5 7535HS, 12 threads, veth, which also receives on the same CPU):

| What | Result |
|---|---|
| index of 4.2 GB / 4.7 million packets (file cached) | 0.69 s; from the index cache 0.19 s total start |
| `--topspeed --qdisc-bypass`, 1 / 4 / 8 threads | 4.4 / 12.8 / 24.2 Gbit/s |
| `--mbps 5000`, `--pps 300000` | 5.000 Gbit/s, 0.300 Mpps |
| timestamps x1, 0.5 Mpps, 4 threads | lateness p50 14 ns, p99 13 µs |
| timing at the receiver (x0.5/x1/x2) | interval error p50 ~3 µs, p95 ~10 µs |
| direct I/O vs page cache, file from NVMe | 22.7 vs 17.2-18.1 Gbit/s |

The Rust version replaced an earlier C implementation of the same design. On the same laptop and
4 GB file they measure the same: index 0.82 s, `--topspeed` 8 threads 24.5 Gbit/s, `--mbps 10000`
13.9 s of CPU (user + system) for both, lateness p99 14 us at x2; `--analyze` output is identical
byte for byte on the test captures, and the index cache files are identical and interchangeable.

Test server (Dell, 12 cores, Broadcom bnxt_en 25G, RHEL 8, consumer NVMe drive), 500 GB capture,
`--mbps 99% --qdisc-bypass`, 10 IP threads, direct I/O: line rate, about 24.3 Gbit/s of L2 frames
(~25 Gbit/s on the wire), 3.3-3.8 Mpps, `tx_dropped` 0, the receiving sensor saw 25 Gbit/s; stable
for hours once the drive was cooled properly (61 °C under load).

## Known limitations

- Order is preserved within a session (one thread per session); order between sessions follows the
  timeline in timestamp mode, and is interleaved across threads in rate modes. Non-IP frames have
  their own thread.
- One very large session is limited by one core (the shard imbalance is shown by `--analyze`).
- Fragmented and unfragmented packets of the same session may go through different threads.
- Tunnels are hashed and modified by the outer header; addresses inside ICMP errors are not
  modified; SCTP/DCCP/UDP-Lite ports are not modified (CRC32c cannot be updated incrementally).
- Frames longer than MTU+14 (MTU+18 with 802.1Q) are skipped.
- `--mbps` counts L2 bytes; on the wire it is ~24 bytes per frame more (`--mbps N%` accounts for it).
- Rate modes are smoother than real traffic (see [Realism of the load](#realism-of-the-load)).
- Lateness quantiles per second have ±12.5% error; lateness of late packets is understated by at
  most one batch.
- Without `PACKET_LOSS`, a frame the kernel rejects stops the thread with an error (practically
  impossible after the length pre-filter).
- sysfs counters are per interface (other traffic included) and reset when the interface is
  re-created.
- Linux only; the TSC clock is x86 only.

## Source layout

```
src/main.rs        entry point
src/lib.rs         common definitions (packet index entry, offset/length packing, stop flag)
src/cli.rs         options and --help
src/prepare.rs     setup: CPUs, MTU, file, index, timeline, rate profile
src/pcap.rs        pcap parsing, mmap
src/dissect.rs     L2/L3/L4 parsing, symmetric flow hash
src/index.rs       index: sequential pass + parallel classification, resolve to shards
src/idxcache.rs    on-disk index cache (same format as the C version)
src/sched.rs       timeline normalization, schedules, rate profile, radix sort, histogram
src/ref_sched.rs   single-threaded reference of sched.rs for the tests
src/par.rs         parallel-for over chunks
src/clock.rs       fast clock (TSC or CLOCK_MONOTONIC)
src/worker.rs      sender thread: TX_RING, hot loop, pacing, link outages, wait states
src/dio.rs         direct I/O streaming into a RAM window
src/dpdk/          DPDK backend: mod.rs (EAL, port, TX queues), shim.c (C layer over DPDK inlines)
src/stream.rs      page-cache streaming: readahead, pre-mapping, drop-behind
src/therm.rs       NVMe temperature and the thermal governor
src/live.rs        long-run statistics
src/mutate.rs      --loop-mutate with incremental checksums
src/replay.rs      thread startup, T0, statistics, status file, watchdog, link monitor, JSON
src/report.rs      --analyze report and pre-start warnings
tests/             pcap generators, functional tests on veth
```

## Command line reference

Output of `replaystorm --help`:

```
replaystorm - multithreaded pcap replayer over AF_PACKET preserving L2

Usage:
  replaystorm -i INTERFACE [options] FILE.pcap
  replaystorm --analyze [options] FILE.pcap

Rate modes (mutually exclusive, default --multiplier 1):
  --topspeed              as fast as possible
  --mbps X                fixed total rate, Mbit/s (L2, without FCS)
  --mbps line | N%        rate as a share of the link speed counted on the wire
                          (preamble, IFG, FCS included): line = 100%, e.g. 99%
  --pace-slack T          --mbps/--pps: threads sleep and send packets due within T at
                          once instead of busy-waiting each packet (default 200us)
  --pps X                 fixed total rate, packets/s
  --multiplier X          replay by timestamps: 2.0 is twice as fast, 0.5 is twice
                          as slow, 1.0 is real time
  --duration T            pick the multiplier so the file plays in T
  --loop N                play N times (0 means infinite), default 1

Timestamps:
  --ts-order MODE         asis | clamp | sort (default clamp)
                            asis  - as is, "backward in time" is sent without waiting
                            clamp - "backward in time" is replaced by the previous stamp
                            sort  - stable sort of the index by timestamp
  --max-gap T             compress pauses longer than T down to T
  --ts-outliers MODE      report | exclude: outliers (ts=0, before 1990, future,
                          short clock jump) are only reported or excluded
                          from the timeline computation (default report)
  --outlier-jump T        clock jump threshold for outlier detection (default 60s,
                          0 disables detection)
  --lag-policy P          catchup | rebase: when lagging, catch up or shift T0
  --lag-threshold T       lag after which rebase kicks in (10ms)
  --spin-us N             busy-spin for the last N us of each wait (50)
  --timing-res T          achievable timing precision for burst estimation (2us)
  --clock C               auto | tsc | monotonic: hot-loop clock. auto picks TSC
                          if the kernel clocksource is not tsc (clock_gettime is slow then)

Sending:
  -i, --interface IF      interface
  -t, --threads N         threads for IP traffic (default: CPUs of the NUMA node - 1);
                          non-IP frames always go through a separate thread
  --cpus LIST             CPUs for threads, e.g. 2-9,12 (default:
                          /sys/class/net/IF/device/local_cpulist)
  --batch N               frames per send() call (64)
  --ring-frames N         frames in each thread's TX_RING (4096)
  --qdisc-bypass          PACKET_QDISC_BYPASS: bypass qdisc, straight to the driver
  --packet-loss           PACKET_LOSS: kernel silently skips malformed frames
  --link-speed X          link speed (25G, 10000M); default from ethtool
  --mtu N                 MTU (default from the interface, 1500 for --analyze)
  --dpdk PORT             send through DPDK instead of AF_PACKET (binary built with
                          make dpdk): PORT is the NIC's interface name (ens1f0) or PCI
                          address (0000:3b:00.0), a virtual device name or a port
                          number; replaces -i
  --eal "ARGS"            DPDK EAL arguments, e.g. "-a 0000:3b:00.0" or
                          "--no-huge --vdev=net_af_packet0,iface=eth1,qpairs=12"
  --dpdk-bind             move the NIC from its kernel driver
                          to vfio-pci for the run and give it back at the end, with its
                          MTU and up state; refused if the interface has IP addresses
  --dpdk-bind-group       like --dpdk-bind, and also move the other devices of the NIC's
                          IOMMU group (usually the other ports of the card), which VFIO
                          requires when they share one group
  --dpdk-hugepages SIZE   reserve SIZE of 2 MB hugepages (e.g. 4G) on the NIC's NUMA node
                          for the run and release them at the end

Input:
  --preload               load the whole file into memory before start
  --index-cache FILE      keep the packet index on disk: the first run builds and saves
                          it, later runs load it instead of scanning the pcap; auto =
                          FILE.pcap.rsidx next to the pcap. Rebuilt automatically if the
                          pcap changes; valid for any -t and MTU
  --readahead SIZE        how much of the file is kept in RAM ahead of the senders:
                          the direct I/O window or the page-cache readahead (2G)
  --drop-behind M         auto | on | off: drop already sent parts of the file from the
                          page cache; auto = on when the file is larger than free RAM
  --io MODE               auto | direct | mmap: how the file is read during replay.
                          direct: O_DIRECT reader threads fill a RAM window of
                          --readahead size, bypassing the page cache; mmap: through the
                          page cache; auto = direct when the file is larger than free RAM
  --io-threads N          direct I/O reader threads (default 4)
  --disk-max-temp C       thermal governor (direct I/O): limit the disk read rate to keep
                          the NVMe drive at or below C degrees instead of letting it hit
                          thermal throttling; e.g. 2-3 C below its throttling point
  --disk-start-temp C     before start, wait until the NVMe drive cools down to C
  --smac MAC, --dmac MAC  MAC addresses of the synthetic Ethernet header for RAW IP

Looping with mutation:
  --loop-mutate WHAT      ip | port | ip,port - on lap k>0 shift addresses/ports
                          so the sensor sees new sessions (L2 is untouched)
  --mutate-ip-offset A    IPv4 shift per lap, as an address (default 0.1.0.0)
  --mutate-port-step N    shift of ports >= 1024 per lap (default 1)

Output:
  --analyze               analyze the file only, do not send
  --stats-json FILE       write statistics as JSON
  --status-file F         live status file, rewritten every second (default
                          /tmp/replaystorm-IF.status)
  --status [-i IF]        print the live status of a running replaystorm and exit
                          (--status --dpdk PORT for a DPDK replay)
  -q, --quiet             do not print per-second statistics
  -h, --help              this help

Examples:
  replaystorm --analyze big.pcap
  replaystorm --status -i ens1f0          # statistics of a replay running elsewhere
  replaystorm -i ens1f0 --mbps 99% --index-cache /var/tmp/big.rsidx big.pcap
  replaystorm --analyze --multiplier 10 --link-speed 25G big.pcap
  replaystorm -i ens1f0 --topspeed --qdisc-bypass -t 12 big.pcap
  replaystorm -i ens1f0 --mbps 20000 --loop 0 big.pcap
  replaystorm -i ens1f0 --mbps 99% --loop 0 --loop-mutate ip,port big.pcap
  replaystorm -i ens1f0 --multiplier 2 --max-gap 1s --ts-order sort big.pcap
  replaystorm -i ens1f0 --duration 10m --stats-json run.json big.pcap
  replaystorm -i ens1f0 --loop 5 --loop-mutate ip,port big.pcap
  replaystorm -i ens1f0 --smac 02:00:00:00:00:01 --dmac 02:00:00:00:00:02 raw.pcap
  replaystorm --dpdk 0000:3b:00.0 --eal "-a 0000:3b:00.0" --mbps 99% --loop 0 big.pcap
  replaystorm --dpdk ens1f0 --dpdk-bind --dpdk-hugepages 4G --mbps 99% big.pcap

While running: press Enter (or s) for long-run statistics: minimum, worst minute,
percentiles, averages; r resets them, q stops; kill -USR1 PID prints them too.

Exit code: 0 - success (including stop by SIGINT/SIGTERM), 1 - runtime error,
2 - invalid arguments.
```
