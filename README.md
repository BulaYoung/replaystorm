# afreplay

A multithreaded pcap replayer over `AF_PACKET` (TX_RING), built for large files (50+ GB) and
multicore machines with weak single cores. Frames are sent **byte for byte, including L2**: MAC,
VLAN/QinQ, MPLS, ARP, STP, LLDP and any non-IP frames. The rate can be set in four ways:
maximum, fixed (Mbit/s or pps), by pcap timestamps with a multiplier, or to fit a given
duration. Looping is supported, including with modification of addresses and ports.

Only `AF_PACKET` is used, no DPDK, AF_XDP, netmap or libpcap. The language is C11, the only
dependencies are pthread and libm.

Program output (messages, statistics, `--help`) and code comments are in English.

## Building

```sh
make                # the ./afreplay binary
make unit-test      # unit tests
make test           # unit tests + test pcap generation + functional tests on veth
make sanitize       # unit tests built with UBSan (trap) and FORTIFY; SAN=-fsanitize=address if libasan is available
```

Requires gcc or clang with C11 and Linux 3.14+ (for `PACKET_QDISC_BYPASS`). The tests need
python3 without third-party modules, plus `ip` and `ethtool`. The build uses
`-Wall -Wextra -Werror`.

Running requires root or `CAP_NET_RAW`. With `CAP_NET_ADMIN` the socket buffer is enlarged
(`SO_SNDBUFFORCE`); without it, whatever `net.core.wmem_max` allows is used.

## Quick start

```sh
# What is inside the file: timestamp anomalies, rate peaks, traffic mix, shards
afreplay --analyze big.pcap
afreplay --analyze --multiplier 10 --link-speed 25G big.pcap

# Maximum rate, 12 threads, bypassing qdisc
afreplay -i ens1f0 --topspeed --qdisc-bypass -t 12 big.pcap

# Fixed 20 Gbit/s, forever (Ctrl-C prints the summary)
afreplay -i ens1f0 --mbps 20000 --loop 0 big.pcap

# Saturate a 25G link at 99% on the wire, forever, with new sessions every lap
afreplay -i ens1f0 --mbps 99% --loop 0 --loop-mutate ip,port --qdisc-bypass --preload big.pcap

# By timestamps at double speed, compress pauses longer than 1 s, sort timestamps
afreplay -i ens1f0 --multiplier 2 --max-gap 1s --ts-order sort big.pcap

# Replay the file in exactly 10 minutes, write statistics to JSON
afreplay -i ens1f0 --duration 10m --stats-json run.json big.pcap

# 5 laps, the sensor sees new sessions on each one
afreplay -i ens1f0 --loop 5 --loop-mutate ip,port big.pcap

# RAW IP (linktype 101/228/229): an Ethernet header is prepended
afreplay -i ens1f0 --smac 02:00:00:00:00:01 --dmac 02:00:00:00:00:02 raw.pcap
```

`afreplay --help` prints the full list of options.

## How it works

1. **The file** is mapped into memory (`mmap`, read-only) and is not copied to the heap. The
   `--preload` flag uses `MAP_POPULATE`, i.e. reads the whole file before starting. If the file
   is larger than available memory, the program warns. Without `--preload` the statistics
   thread calls `madvise(MADV_WILLNEED)` once a second on 512 MB ahead of the position of the
   slowest thread.
2. **The index** is built in a single sequential pass over the records (the pcap record chain
   cannot be walked any other way). In parallel with the pass, N threads classify and hash
   already-read packets in blocks of 64K. Per packet, 8 bytes are stored (48-bit offset +
   16-bit length), plus an 8-byte timestamp and a 2-byte shard number.
3. **The timeline** is normalized from each packet's timestamp: outliers, clamp and max-gap are
   handled (see below). These are pure functions covered by unit tests (`src/sched.c`).
4. **Sharding** uses a symmetric 5-tuple hash, so A→B and B→A land in the same thread and order
   within a session is preserved. The parser walks VLAN/QinQ (0x8100, 0x88a8, 0x9100, 0x9200),
   the MPLS stack (including a pseudowire with control word and inner Ethernet), PPPoE and IPv6
   extension headers. Ports are not used for IP fragments (IPv4 and IPv6), so all fragments of
   a datagram go to the same thread. The VLAN ID is deliberately excluded from the hash: with
   inter-VLAN routing the two sides of a session may be in different VLANs. Tunnels (GRE,
   VXLAN) are hashed by the outer header. Non-IP frames go to a separate shard served by its
   own thread.
5. **Sender threads.** A thread is created for each non-empty shard. It is pinned to a core and
   only then allocates its own copy of the shard index and its TX_RING, so the memory ends up
   on the right NUMA node. By default cores are taken from
   `/sys/class/net/<if>/device/local_cpulist`; `--cpus` overrides the list. By default there
   is one IP thread fewer than cores, and the non-IP thread takes the remaining core. Once the
   shards are built, the global index is freed.
6. **Sending.** Each thread has its own `AF_PACKET`/`SOCK_RAW` socket with protocol = 0 (the
   socket receives nothing), `TPACKET_V2`, `PACKET_TX_RING`. A frame is copied from the mmap
   straight into the ring, and after a batch (`--batch`, 64 by default) `send(MSG_DONTWAIT)` is
   called once. `PACKET_QDISC_BYPASS` and `PACKET_LOSS` are enabled by flags. Ring slots are
   sized by the largest frame actually present in the file (capped by MTU+18), not by the MTU:
   with MTU 9000 and ordinary traffic that is 2 KB per slot instead of 16 KB.
   When the device queue is full (ENOBUFS/EAGAIN), the thread backs off instead of retrying
   `send()` in a tight loop: a few short spins, then 5..100 us sleeps. When the ring itself is
   full of frames still in the driver, the thread also sleeps 10 us between checks.
7. **The hot loop** has no locks and no malloc. Its only system calls are the batched `send()`
   and `clock_nanosleep` in waiting modes. Counters are per thread, cache-line aligned and
   published with relaxed stores. The statistics thread only reads them.

Memory: building the index needs about 18 bytes per packet, distributing shards peaks at about
34 bytes per packet, and sending uses 16 bytes per packet. For 70 million packets that is
roughly 2.4 GB at peak and 1.1 GB while running. With `--ts-order sort` or `asis` on
non-monotonic timestamps, another 32 bytes per packet is added while the timeline is computed.

## Files larger than RAM

A file much larger than RAM (for example 500 GB on a 62 GB machine) cannot be preloaded and is
streamed from disk during replay:

- A background thread (`afr-stream`) wakes every 20 ms and keeps `--readahead` bytes (default
  2 GB) of the file requested with `madvise(MADV_WILLNEED)` ahead of the fastest sender thread,
  so sender threads do not stall on disk reads inside the hot loop. The nearest 512 MB are
  also pre-mapped into the process with `MADV_POPULATE_READ` (Linux 5.14+; older kernels fall
  back to readahead only), so sender threads take no page faults at all: in a test with the
  file streamed from disk, major faults per sender thread went from about 200 to 0.
- Drop-behind (`--drop-behind auto|on|off`, auto = on when the file is larger than 80% of
  available RAM): everything the slowest thread has passed (minus a 256 MB margin) is dropped
  from the page cache (`MADV_DONTNEED` + `POSIX_FADV_DONTNEED`). Without it the page cache would
  churn through hundreds of GB and push the packet index out to swap.
- The per-thread packet index is locked in RAM with `mlock` (works as root; otherwise raise
  `ulimit -l`).
- `--preload` is ignored with a warning when the file does not fit into available memory.
- The summary shows how much was requested ahead and dropped from the page cache.

Requirements for such a file:

- **Disk throughput.** Each lap re-reads the file from disk, so the disk must deliver the target
  rate: 24 Gbit/s is about 3 GB/s. Check before a run, e.g.
  `dd if=/mnt/big.pcap of=/dev/null bs=16M count=2000 iflag=direct`. If the disk is slower,
  the replay rate is capped by the disk (on the test laptop: 17.9 Gbit/s from a 2.2 GB/s NVMe
  versus 24.2 Gbit/s from the page cache).
- **Index memory.** About 16 bytes per packet during replay and about 34 bytes per packet at peak
  while the index is built (more with `--ts-order sort` on unordered timestamps). A 500 GB file
  with ~900-byte frames has ~550 million packets: ~9 GB during replay, ~19 GB at peak.
- **Startup time.** The index pass reads the whole file once (about 2.4 GB/s cold on mendel17:
  ~3.5 minutes for 500 GB). Use `--index-cache` so that only the first run pays for the scan.
  Timeline normalization, the radix sort and the rate profile run in parallel on the same
  threads as hashing (see below).

## Index cache

`--index-cache FILE` (or `--index-cache auto` for `FILE.pcap.afridx` next to the pcap) keeps the
packet index on disk. The first run builds the index as usual and saves it; later runs map the
cache instead of reading the whole pcap. For a 500 GB file this replaces a ~3.5 minute scan with
reading an ~11.5 GB cache.

- The cache stores the part of the index that does not depend on options: offset and length,
  timestamp, a 32-bit symmetric flow hash and classification flags (21 bytes per packet). Shard
  numbers and the MTU-based skipping are recomputed in parallel on every start, so one cache
  works for any `-t`, `--cpus` and MTU.
- The cache is used only for the same pcap: same size, mtime, inode and a hash of its first and
  last 64 KB, and the same cache format version. Otherwise it is rebuilt and overwritten, with a
  message saying why.
- It is written to a temporary file and then renamed, so an interrupted run never leaves a broken
  cache. The cache file is mapped read-only from the disk's point of view (copy-on-write), and
  is never modified by a run.
- Timeline normalization (`--ts-order`, `--max-gap`, outliers) is not cached and is redone on
  every start, since it depends on options.
- To force a rebuild, delete the cache file.

On the test laptop, a 4.2 GB file (4.7 million packets) produced a 98.5 MB cache, and a start
took 0.19 s with it versus 1.06 s without it.

## Parallel preparation

Timeline normalization (outliers, clamp, max-gap, mapping), the radix sort used for unordered
timestamps and the rate profile (peaks, interval statistics) run on as many threads as the index
hashing. Each phase is split into contiguous chunks; phases that carry state from packet to
packet (running maximum, accumulated gap excess, last mapped value, last good timestamp) first
summarize every chunk, then merge the summaries in chunk order, then redo each chunk from the
exact state the sequential algorithm would have had. The result is bit for bit identical to the
original single-threaded code, which is kept in `tests/ref_sched.c`; the unit tests compare both
on 360 combinations of data patterns, `--ts-order`, `--max-gap`, outlier exclusion and thread
counts (1 to 16). Clock spike detection stays sequential: each decision depends on the previous
good packet, and it is a single light pass.

On the test laptop, 4.7 million packets, 1 vs 11 threads:

| Phase | 1 thread | 11 threads |
|---|---|---|
| normalization, ordered timestamps | 34 ms | 14 ms |
| rate profile, ordered timestamps | 131 ms | 24 ms |
| normalization, unordered (sort + max-gap) | 219 ms | 116 ms |
| rate profile, unordered | 293 ms | 124 ms |

The unordered case is bound by memory bandwidth of the radix sort.

## Rate modes

| Mode | What it does |
|---|---|
| `--topspeed` | As fast as possible. Threads wait for nothing but free frames in the ring. |
| `--mbps X` | Total rate of X Mbit/s by L2 frame length (without FCS, preamble and IFG). It is split between threads **in proportion to the byte volume of their shards**, so all threads finish at the same time and the sum equals X. |
| `--mbps line`, `--mbps N%` | Rate as a share of the link speed **on the wire** (preamble, IFG, FCS and the 60-byte minimum included): `line` = 100%, e.g. `99%`. The link speed comes from ethtool or `--link-speed`. It is converted to an L2 rate with the file's own ratio of L2 bytes to on-the-wire bytes and then paced like `--mbps X`. If an explicit `--mbps X` exceeds the link on the wire, afreplay warns before start. |
| `--pace-slack T` | For `--mbps`/`--pps`: instead of busy-waiting for every packet, a thread sleeps and sends everything due within the next T at once (default 200 us). The schedule stays absolute, so the average rate is exact; bursts are at most T long per thread. In a 4 Gbit/s test this cut user CPU from 15.3 s to 2.5 s with the same rate. `--spin-us` only applies to timestamp replay. |
| `--pps X` | The same, but in packets per second; split in proportion to the packet count of the shards. |
| `--multiplier X` | Replay by timestamps (the default mode, X = 1). 2.0 is twice as fast, 0.5 twice as slow. |
| `--duration T` | The multiplier is chosen so that the whole file (one lap) plays in T. Suffixes: `ns`, `us`, `ms`, `s`, `m`, `h`. |

In the `--mbps` and `--pps` modes the send time is also computed from a common origin:
`T0 + bytes_so_far × ns_per_byte`. So the error does not accumulate, and after a stall (for
example, when the ring is full) the thread catches up with the schedule.

All modes start simultaneously: threads pass a barrier and wait for the common point T0.

`--loop N` plays the file N times; `--loop 0` loops forever, until SIGINT/SIGTERM.

## Timestamp replay

**Schedule.** A packet's send time is computed from a common origin, not from the previous
packet:

```
t_send = T0 + (lap_number × lap_length + ts_pkt − ts_first) / multiplier
```

So the error does not accumulate and threads do not drift apart. T0 is shared by all threads:
it is assigned after the barrier, once all sockets and rings are ready. The lap length equals
the timeline duration plus the mean inter-packet interval. This way the last packet of a lap
and the first packet of the next do not merge, and when looping the timeline continues rather
than starting over.

**Waiting** is hybrid. Long pauses are spent in `clock_nanosleep(TIMER_ABSTIME)` in chunks of
at most 50 ms, so a stop is noticed in time. The last `--spin-us` us (50 by default) are
busy-spun on the clock. The thread's timer slack is set to 1 ns.

**Batches do not break timing.** If the next packet is not yet due, the accumulated batch is
sent early, and only then does the thread sleep. If the packet is already due, the clock is not
read again: when lagging, this saves a clock call per packet. The clock is refreshed after
every `send()`.

**Clock** (`--clock auto|tsc|monotonic`). Normally `CLOCK_MONOTONIC` via vDSO costs about 20 ns.
But if the kernel has switched to the `hpet` or `acpi_pm` clocksource (TSC rejected; happens on
laptops and in VMs), each call costs about 1 us, and a single thread in timestamp mode loses
half its rate. In `auto` mode in this situation, if the CPU has an invariant TSC (`constant_tsc`
and `nonstop_tsc`), `rdtsc` is used. The frequency is calibrated against `CLOCK_MONOTONIC`
twice for 100 ms on one core; if the two estimates differ by more than 0.1%,
`CLOCK_MONOTONIC` is used. The offset is calibrated in each thread separately, after pinning
to a core. This matters: on the test laptop the TSC of CPU 0 is offset from the other cores by
2.09 s, which is why the kernel rejected the TSC. Before each `nanosleep` a thread checks the
TSC against `CLOCK_MONOTONIC` and resynchronizes if they diverge by more than 50 us. The
selected clock is shown in the "Clock: ..." line at startup.

**Lag.** If a packet is already late, the thread does not sleep and sends it immediately.
Lateness = actual time the frame is placed in the ring − scheduled time. It is recorded in a
per-thread histogram: p50, p99 and max for each second, plus p99.9 in the summary. What to do
on large lag is set by `--lag-policy`:

- `catchup` (default) — catch up: late packets are sent back to back until the thread is back
  on schedule. Absolute times are preserved, but there will be a burst after a stall.
- `rebase` — if lateness exceeds `--lag-threshold` (10 ms by default), the shared T0 is shifted
  forward by the lateness. The shift is common to all threads (a lock-free atomic variable),
  so the relative position of threads is preserved. Inter-packet intervals stay correct, and
  the whole timeline is "stretched". The number of shifts and the total shift are printed in
  the summary.

### Problematic timestamps

| Problem | What afreplay does |
|---|---|
| Non-monotonic timestamps (merged or multi-queue captures) | `--ts-order`: **`clamp`** (default) replaces a "backwards in time" timestamp with the previous one (more precisely, with the running maximum). **`sort`** stably sorts the index by timestamp; the data is untouched, only the index within a shard is sorted (order between threads is set by the timeline anyway). **`asis`** sends as is: a "backwards in time" packet is sent without waiting and without being counted in lateness; such packets are counted separately. `--analyze` shows the count and the largest backward jump. |
| Long pauses | `--max-gap X` compresses every pause longer than X down to X. Pauses are found on the ordered timeline, so this also works with `asis`/`sort`. `--analyze` shows the top 10 pauses with timestamps and packet numbers. |
| Outliers | Always detected: ts = 0, timestamps before 1990, timestamps in the future (later than the current time + one day), and a short clock spike. A spike is a packet (or a run of up to 16 packets) that jumped further than `--outlier-jump` (60 s by default) from the previous normal one, after which time returned. By default outliers are only reported (`--ts-outliers report`) with a warning before start. With `--ts-outliers exclude` they are excluded from the timeline: the packet gets the timestamp of a neighbouring normal packet and is sent next to it. If the timeline with outliers would be longer than a day, there is also a warning. |
| Speedup beyond link capacity | Before start, peak rates in 1 ms, 10 ms and 1 s windows are computed **taking the multiplier into account**, in two variants: L2 and "on the wire" (with an 8 B preamble, 12 B IFG, 4 B FCS and a 60 B minimum frame). If the on-the-wire peak exceeds the link speed (from ethtool, i.e. from `/sys/class/net/<if>/speed`, or from `--link-speed`), a warning is printed. Example: "on x10 the 1 ms peak is 38.42 Gbit/s (with preamble and IFG), above the 25.00 Gbit/s link; timing will be violated". |
| Intervals too small | After applying the multiplier, the distribution of intervals between adjacent packets **within a shard** is computed (< 1 us, < 10 us, < 100 us). The share of intervals shorter than `--timing-res` (2 us by default) is shown as the share of packets that will effectively be sent in batches. If it is at least 1%, a warning is printed. |

## Looping with modification

`--loop-mutate ip|port|ip,port`: on lap k > 0 frames are modified directly in the TX ring. The
file mmap stays read-only. L2 (MAC, VLAN, MPLS) is not changed.

- **ip.** `k × --mutate-ip-offset` is added to every IPv4 address (both source and destination)
  (0.1.0.0 by default: 10.0.0.1 → 10.1.0.1 → 10.2.0.1). For IPv6 the 32-bit word in bytes 8–11
  of the address (the high part of the interface identifier) is shifted; the /64 prefix stays
  the same.
- **port.** Ports of 1024 and above are shifted by `k × --mutate-port-step`, wrapping within
  1024..65535. Service ports (< 1024) are not changed, so protocol detection is not broken.
  Ports are changed only for TCP and UDP and only in unfragmented packets: otherwise the first
  fragment would diverge from the rest.

The transformation is deterministic and identical for both sides, so A→B and B→A remain one
session after the shift (and land in the same shard). Checksums are updated incrementally
(RFC 1624, eq. 3): for IPv4 the header checksum, for TCP, UDP and ICMPv6 the checksum with the
pseudo-header. UDP with a zero checksum (IPv4) stays without a checksum; a computed zero is
written as 0xFFFF. For the first fragment the L4 checksum is updated as well: it covers the
whole datagram, and the pseudo-header changes by the same amount.

## Analysis mode

`--analyze` sends nothing. It prints:

- file format, number of packets and bytes, index build time;
- timestamp range, replay timeline duration (taking `--ts-order`, `--max-gap`, `--ts-outliers`
  into account);
- mean and peak rate in 1 ms, 10 ms and 1 s windows (taking `--multiplier` or `--duration` into
  account);
- the distribution of intervals within shards and the share that will be sent in batches;
- timestamp anomalies: number of "backwards in time" packets and the largest backward jump,
  outliers by kind, top 10 pauses;
- traffic mix: IPv4, IPv6, non-IP (ARP, 802.3/LLC with STP, LLDP, other), VLAN, QinQ, MPLS,
  PPPoE, IP fragments;
- skipped frames by reason, and frames truncated at capture;
- the distribution of packets and bytes across shards and the imbalance of the most loaded
  shard.

There are as many shards as set by `-t` (CPU − 1 by default), so the distribution matches what
sending with the same options will produce.

## Input files

- Classic pcap: microsecond and nanosecond, both endiannesses. For pcapng the program reports
  an error with the hint `editcap -F pcap in.pcapng out.pcap` (for nanoseconds, `-F nsecpcap`).
- Linktype 1 (Ethernet); 101 and 12 (RAW IP, the version is taken from the packet), 228 (IPv4),
  229 (IPv6). For RAW IP an Ethernet header `--dmac`/`--smac` with ethertype 0x0800 or 0x86dd
  is prepended.
- A packet with caplen < origlen is sent with length caplen and counted in the statistics.
- A frame longer than MTU+14 is skipped and counted. For a frame with an outer 802.1Q tag
  (0x8100) the limit is MTU+18. The kernel checks the same way: the exception is made only for
  0x8100, so an 802.1ad frame of the same length would be rejected by the kernel. Frames shorter
  than 14 bytes are skipped too.
- If the file is truncated or corrupted in the middle of a record, there will be a warning, and
  everything up to that point is sent.

## Statistics

Once a second a line is printed:

```
[    3.0 s]    3.590 Gbit/s    0.499 Mpps | sent (sysfs) 0.499 Mpps, tx_dropped +0 | ENOBUFS +0 EAGAIN +0 | lateness p50 1.28 us p99 20.48 us max 425.98 us | pcap +3.000 s of 9.387 s
```

- **Gbit/s, Mpps** — how many frames were placed in the ring and handed to the kernel
  (`send()`).
- **sent (sysfs)** — the increment of `/sys/class/net/<if>/statistics/tx_packets`;
  **tx_dropped** — the increment of `tx_dropped`. These are whole-interface counters, so other
  traffic is included too.
- **ENOBUFS / EAGAIN** — how many times `send()` returned these errors (see below).
- **lateness p50/p99/max** — lateness over the second (timestamp mode only). Quantiles come
  from a log-linear histogram with ±12.5% accuracy. The maximum over the whole run in the
  summary is exact.
- **pcap +X s of Y** — the position on the pcap timeline of the slowest thread; with `--loop`
  also the lap number.

At the end a summary is printed: total packets and bytes, mean rate, difference from sysfs,
number of `send()` calls and mean frames per call, ENOBUFS and EAGAIN, skipped frames, lateness
p50, p99, p99.9 and max, T0 shifts (rebase) and a per-thread breakdown. On SIGINT/SIGTERM the
summary is printed too, with exit code 0.

`--stats-json FILE` writes the same in JSON: a header (file, mode, multiplier, threads,
timeline and lap duration), an `intervals` array (one entry per second; the file is appended to
while running) and a `summary` with a per-thread breakdown.

Exit codes: 0 — success or stopped by signal, 1 — runtime error, 2 — argument error.

### Interpreting ENOBUFS

`send()` returns `ENOBUFS` when the qdisc or the driver queue did not accept the next frame. On
modern kernels (checked on 6.19) **the frame itself is not lost**: the kernel returns it to the
ring with status `SEND_REQUEST`, and `send()` stops at it. afreplay repeats `send()`, and the
frame goes out on the next attempt. So ENOBUFS signals backpressure ("the link or the queue
cannot keep up"), not a loss count. A large ENOBUFS value with `--topspeed` is normal.

If ENOBUFS is high with `--mbps`, the requested rate is above what the link can carry on the
wire. Each ENOBUFS triggers a short backoff (see "How it works"), so CPU usage stays reasonable,
but the cleaner fix is `--mbps line` or `--mbps 99%`.

Test on veth with a tbf qdisc (20 Mbit/s, 2 threads): 219 515 ENOBUFS, but 211 of 6000 frames
were lost.

**Real losses** should be read from the difference between "handed to the kernel" and
`tx_packets` in sysfs, as well as from `tx_dropped` and `tc -s qdisc show dev <if>`. Not every
loss comes with ENOBUFS: in the experiment above 211 frames were dropped by the qdisc without
an error from `send()`. This appears to be the path where, under qdisc contention, the skb is
put on a deferred queue while `send()` has already returned success. This conclusion is drawn
from the kernel sources and has not been confirmed separately.

With `--qdisc-bypass` the frame goes straight to the driver. If the driver queue is stopped,
the kernel increments `tx_dropped` and returns ENOBUFS, but the frame in the ring is likewise
returned to `SEND_REQUEST` and resent. So with bypass `tx_dropped` may **overstate** losses: it
counts attempts, not frames. This could not be reproduced on veth (veth does not stop its
queue); the conclusion is drawn from the 6.x kernel sources. On a real NIC, rely on the
difference between sent and `tx_packets`, and on the NIC counters (`ethtool -S`).

`EAGAIN` means the socket send buffer (`SO_SNDBUF`) is exhausted. afreplay tries to size it to
the ring via `SO_SNDBUFFORCE`, and without `CAP_NET_ADMIN` is capped by `net.core.wmem_max`.
Frequent EAGAIN is a reason to raise `wmem_max` or run as root.

### Interpreting lateness

Lateness is how much later than scheduled a frame was placed in the ring. This is sender-side
delay: time in the qdisc, the driver and on the wire is not included.

- **p50 in single-digit microseconds** — normal.
- **High p99 with low p50** — rare delays: thread preemption by the scheduler, late wakeup from
  a deep C-state, interrupts on the same core. What helps: a larger `--spin-us` (busy-spin
  covers `nanosleep` misses), dedicated cores (`isolcpus`, `nohz_full`), disabling deep
  C-states (`cpupower idle-set -D 10`, `tuned-adm profile network-latency`), running with
  real-time priority (`chrt -f 50 afreplay ...`; threads inherit the policy).
- **Growing p50 and a pcap position falling behind real time** — the thread cannot sustain the
  rate: the peak exceeds the link (see the warnings before start), not enough cores (increase
  `-t`), the disk cannot keep up (`--preload`), the kernel cannot keep up (ENOBUFS grows). With
  `catchup` the thread will later "fire" the backlog; with `rebase` the timeline will shift.

On the test laptop (Ryzen 5 7535HS, clocksource hpet) `nanosleep` occasionally wakes up 1–4 ms
late. The functional test showed that the lateness reported by afreplay matches the interval
error measured at the receiver to within a few microseconds. So the metric is honest.

## Tests

- `make unit-test` — unit tests (`tests/test_*.c`):
  - **parser**: us and ns, LE and BE, truncated file (in the data and in the record header),
    "insane" caplen, pcapng, unknown magic numbers and linktypes, FCS bits in the linktype,
    index building and skip reasons;
  - **hash**: A→B/B→A symmetry for IPv4, VLAN (with different VLAN IDs in the two
    directions), QinQ, MPLS, IPv6, IPv6 with an extension header, PPPoE; IPv4 and IPv6
    fragments in the same shard; non-IP in a separate shard; RAW IP; distribution uniformity;
    MTU limits;
  - **schedule** as a pure function: clamp, asis, sort, max-gap (including on a non-monotonic
    timeline), outliers (ts=0, before 1990, future, clock spike, a genuine long jump), gaps,
    the `t_send` formula with different multipliers and laps, lap length, sort stability, rate
    peaks, histogram;
  - **modification**: the RFC 1624 example, IPv4 TCP/UDP with and without VLAN, comparison with
    full checksum recomputation, UDP without a checksum, carry across 65535 and across an
    octet, symmetry, fragments, IPv6, ports only, non-IP.
- `tests/gen_pcaps.py` — a test pcap generator without third-party modules: an L2 mix (ARP,
  STP, LLDP, VLAN, QinQ, MPLS and pseudowire, PPPoE, IPv6 with extension headers, fragments,
  sessions in both directions, a truncated frame, a frame larger than MTU, frames of exactly
  MTU+14 and MTU+18), the same mix in ns/BE, RAW IP, files with anomalies (backward jumps, long
  pauses, ts = 0 and future, clock spike), a timing file, a truncated file and a pcapng.
- `make func-test` (or `tests/func_veth.sh`) — functional tests on a veth pair in a separate
  network namespace. Without root `unshare -rn` (user namespace) is used, so root is not
  required. If user namespaces are disabled and there is no root, the tests are skipped. What
  is checked:
  - all frames arrived **byte for byte**; the VLAN tag stripped by the kernel on receive is
    restored from `PACKET_AUXDATA`; there are no extra frames; order within sessions is
    preserved (modes `--pps`, `--topspeed --qdisc-bypass`, `--mbps --ts-order sort`, RAW IP);
  - intervals at **x1, x2 and x0.5**, captured with nanosecond timestamps (`SO_TIMESTAMPNS`):
    p95 error < 100 us, total duration ±0.2%; a rare large outlier is allowed only if afreplay
    itself reported the same lateness;
  - `--duration`, `--max-gap`, `--loop` (common timeline across laps), `--ts-outliers exclude`,
    `--ts-order sort/clamp/asis`;
  - `--loop-mutate`: lap 0 is unchanged, on the other laps all IP frames are changed, checksums
    are correct, non-IP and MAC are untouched;
  - CLI: pcapng (code 1 and hint), unknown option (code 2), `--help`, nonexistent interface,
    SIGINT with `--loop 0` (summary and code 0), truncated file.

  Timing tolerances are configurable: `tests/func_veth.sh build/pcaps --tol-p95-us 200 --spin-us 3000`.
- `tests/gen_big.py out.pcap 4` — a large synthetic file (4 GB) for performance measurements.

## Results on the test machine

Laptop, Ryzen 5 7535HS (12 threads), veth in a netns. On veth the same CPU also receives the
frames, so the numbers on a real NIC will differ.

| What | Result |
|---|---|
| Index of 4.2 GB, 4.7 million packets (file in page cache) | 0.69 s |
| `--topspeed --qdisc-bypass`, 1 / 4 / 8 threads | 4.4 / 12.8 / 24.2 Gbit/s (0.61 / 1.78 / 3.36 Mpps) |
| `--mbps 5000` | 5.000 Gbit/s |
| `--pps 300000` | 0.300 Mpps |
| x1, 0.5 Mpps, 4 threads | lateness p50 14 ns, p99 13 us |

Real NIC (mendel17, 25G, 11 threads, `--mbps 32000 --qdisc-bypass --preload`, 53.7 GB file):
24.3-24.4 Gbit/s L2, about 25.0 Gbit/s on the wire (line rate), 3.3 Mpps, `tx_dropped` 0, the
receiving sensor saw 25 Gbps with 0 RX drops. That run requested more than the link and showed
about 1.2 M ENOBUFS/s with all threads at 100% CPU; it predates the ENOBUFS backoff and
`--mbps line`.

## Known limitations

- Order is preserved **within a session**: all its packets go through one thread. Order
  between different sessions is set only by the timeline. With `--topspeed`, `--mbps` and
  `--pps` packets of different threads are interleaved, and non-IP frames have their own
  thread.
- Sharding by session yields unequal shards: a single "elephant" session is capped by the speed
  of one core. The imbalance is visible in `--analyze`.
- Packets of one session in which some packets are fragmented and others are not may end up in
  different threads (ports are not used for fragments).
- Tunnels (GRE, VXLAN, IP-in-IP) are hashed and modified by the outer header. Headers inside
  ICMP errors are not changed by `--loop-mutate`. SCTP, DCCP and UDP-Lite are not touched by
  `--loop-mutate=port` (SCTP uses CRC32c, which cannot be updated incrementally).
- When modifying an MPLS pseudowire with inner Ethernet, the inner IP is changed; MAC and
  labels stay the same.
- Frames longer than MTU+14 (MTU+18
  with 802.1Q) are skipped: they cannot be put on the wire without changing the MTU.
- `--mbps` counts L2 bytes without FCS, preamble and IFG. The on-the-wire rate is higher by
  about 24 bytes per frame.
- The peak rate in the 1 s window for a file shorter than a second (after the multiplier) is
  the whole volume divided by one second. The report marks this.
- Per-second lateness quantiles have ±12.5% error (log-linear histogram).
- When a thread is lagging, the time is not re-read until the next packet is in the future.
  The lateness of such packets is understated by at most the duration of one batch.
- With `PACKET_LOSS` enabled, the kernel silently skips a malformed frame. Without it, such a
  frame stops the thread with an error (the frame would otherwise stay in the ring forever).
  Thanks to the length pre-filter this practically never happens.
- sysfs statistics are whole-interface counters, not just afreplay traffic. Inside a network
  namespace without its own mounted sysfs they are unavailable, and the program reports this.
- Linux is required. The TSC clock works only on x86; other architectures use
  `CLOCK_MONOTONIC`.

## Source layout

```
src/pcap.[ch]      pcap parsing, mmap, preload
src/dissect.[ch]   L2/L3/L4 parsing, symmetric hash
src/index.[ch]     index: sequential pass + parallel hashing, then resolve to shards
src/idxcache.[ch]  on-disk index cache
src/stream.[ch]    readahead and drop-behind for files larger than RAM
src/par.[ch]       parallel-for over chunks
src/sched.[ch]     timeline normalization, t_send, rate profile, histogram (pure functions)
src/clock.[ch]     fast clock (TSC or CLOCK_MONOTONIC)
src/worker.[ch]    sender thread: TX_RING, hot loop, waiting, batches
src/mutate.[ch]    --loop-mutate and incremental checksums
src/replay.c       thread startup, barrier and T0, statistics, JSON, signals
src/report.c       --analyze report and pre-start warnings
src/cli.[ch]       options and --help
src/main.c         setup: CPU, MTU, file, index, timeline, profile
tests/             unit tests, pcap generator, functional tests on veth
```
