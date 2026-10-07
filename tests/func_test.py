#!/usr/bin/env python3
"""afreplay functional tests on a veth pair.

Runs inside a separate network namespace (see func_veth.sh): afreplay
sends to va, the receiver listens on vb via AF_PACKET with PACKET_AUXDATA (to
restore the VLAN tag stripped by the kernel) and SO_TIMESTAMPNS (nanosecond receive timestamps).
"""
import argparse
import collections
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_AUXDATA = 8
SO_TIMESTAMPNS = 35
SO_RCVBUFFORCE = 33
TP_STATUS_VLAN_VALID = 0x10
TP_STATUS_VLAN_TPID_VALID = 0x40
PACKET_OUTGOING = 4

FAILED = []


def check(cond, msg):
    if cond:
        print("    ok   ", msg)
    else:
        print("    FAIL ", msg)
        FAILED.append(msg)


def read_pcap(path):
    """Returns (linktype, [(ts_ns, data)])."""
    with open(path, "rb") as f:
        data = f.read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    else:
        e = ">"
        magic = struct.unpack(">I", data[:4])[0]
    nsec = magic == 0xA1B23C4D
    linktype = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFFF
    off, out = 24, []
    while off + 16 <= len(data):
        sec, frac, cap, orig = struct.unpack(e + "IIII", data[off:off + 16])
        if off + 16 + cap > len(data):
            break
        ts = sec * 1_000_000_000 + (frac if nsec else frac * 1000)
        out.append((ts, data[off + 16:off + 16 + cap]))
        off += 16 + cap
    return linktype, out


class Receiver:
    def __init__(self, iface):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        self.s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        try:
            self.s.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 64 << 20)
        except OSError:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 << 20)
        self.s.bind((iface, ETH_P_ALL))
        self.frames = []
        self.stop = False
        self.drain()
        self.th = threading.Thread(target=self.loop, daemon=True)
        self.th.start()

    def drain(self):
        self.s.setblocking(False)
        try:
            while True:
                self.s.recv(65535)
        except BlockingIOError:
            pass
        self.s.setblocking(True)

    def loop(self):
        while not self.stop:
            r, _, _ = select.select([self.s], [], [], 0.05)
            if not r:
                continue
            data, anc, _, addr = self.s.recvmsg(65535, 512)
            if addr[2] == PACKET_OUTGOING:
                continue
            ts = None
            for lvl, typ, val in anc:
                if lvl == SOL_PACKET and typ == PACKET_AUXDATA:
                    st, _l, _sn, _m, _n, tci, tpid = struct.unpack("IIIHHHH", val[:20])
                    if st & TP_STATUS_VLAN_VALID:
                        if not (st & TP_STATUS_VLAN_TPID_VALID) or tpid == 0:
                            tpid = 0x8100
                        data = data[:12] + struct.pack("!HH", tpid, tci) + data[12:]
                elif lvl == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS:
                    sec, nsec = struct.unpack("qq", val[:16])
                    ts = sec * 1_000_000_000 + nsec
            self.frames.append((ts, data))

    def finish(self, idle=0.4):
        last = -1
        while True:
            time.sleep(idle)
            if len(self.frames) == last:
                break
            last = len(self.frames)
        self.stop = True
        self.th.join()
        self.s.close()
        return self.frames


def run_afr(args, timeout=60):
    p = subprocess.run([BIN] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    return p.returncode, p.stdout.decode()


def replay(pcap, extra, json_path=None):
    rx = Receiver(RX)
    args = ["-i", TX, "-q"] + extra
    if json_path:
        args += ["--stats-json", json_path]
    rc, out = run_afr(args + [pcap])
    frames = rx.finish()
    js = None
    if json_path and os.path.exists(json_path):
        with open(json_path) as f:
            js = json.load(f)
    return rc, out, frames, js


def flow_key(fr):
    """Symmetric IPv4 TCP/UDP key (VLAN-aware), otherwise None."""
    off, et = 12, struct.unpack("!H", fr[12:14])[0]
    while et in (0x8100, 0x88A8):
        off += 4
        et = struct.unpack("!H", fr[off:off + 2])[0]
    off += 2
    if et != 0x0800 or len(fr) < off + 24:
        return None
    ihl = (fr[off] & 0xF) * 4
    proto = fr[off + 9]
    if struct.unpack("!H", fr[off + 6:off + 8])[0] & 0x3FFF:
        return None
    if proto not in (6, 17):
        return None
    a = (fr[off + 12:off + 16], fr[off + ihl:off + ihl + 2])
    b = (fr[off + 16:off + 20], fr[off + ihl + 2:off + ihl + 4])
    return (proto,) + tuple(sorted([a, b]))


def compare_frames(expected, got, label):
    ce, cg = collections.Counter(expected), collections.Counter(got)
    missing = ce - cg
    extra = cg - ce
    check(not missing, "%s: all %d frames arrived byte for byte (missing: %d)" % (label, len(expected), sum(missing.values())))
    check(not extra, "%s: no extra frames (extra: %d)" % (label, sum(extra.values())))
    # Order within sessions
    pos = collections.defaultdict(list)
    for i, f in enumerate(expected):
        pos[f].append(i)
    used = collections.Counter()
    seq = []
    for f in got:
        if f in pos and used[f] < len(pos[f]):
            seq.append(pos[f][used[f]])
            used[f] += 1
    per_flow = collections.defaultdict(list)
    for idx in seq:
        k = flow_key(expected[idx])
        if k:
            per_flow[k].append(idx)
    bad = [k for k, v in per_flow.items() if v != sorted(v)]
    check(not bad and per_flow, "%s: order within %d sessions preserved" % (label, len(per_flow)))


def expected_frames(pcap, mtu=1500, smac=None, dmac=None):
    lt, recs = read_pcap(pcap)
    out = []
    for _ts, d in recs:
        if lt in (101, 228, 229):
            v6 = (d[0] >> 4) == 6
            d = bytes.fromhex(dmac.replace(":", "")) + bytes.fromhex(smac.replace(":", "")) + \
                (b"\x86\xdd" if v6 else b"\x08\x00") + d
        et = struct.unpack("!H", d[12:14])[0]
        limit = mtu + 14 + (4 if et == 0x8100 else 0)
        if 14 <= len(d) <= limit:
            out.append(d)
    return out


def t_bytes(pcaps):
    print("== Frames byte for byte (L2: ARP, STP, LLDP, VLAN, QinQ, MPLS, PPPoE, IPv6, fragments)")
    for name, extra in (("l2mix.pcap", ["--pps", "3000", "-t", "3"]),
                        ("l2mix_ns_be.pcap", ["--topspeed", "-t", "2", "--qdisc-bypass"]),
                        ("l2mix.pcap", ["--mbps", "20", "-t", "4", "--ts-order", "sort"])):
        p = os.path.join(pcaps, name)
        rc, out, frames, js = replay(p, extra, "/tmp/afr_func.json")
        check(rc == 0, "%s %s: exit code 0 (%d)" % (name, " ".join(extra), rc))
        if rc:
            print(out)
        compare_frames(expected_frames(p), [f for _, f in frames], name)
        check(js and js["summary"]["skipped"] == 1, "%s: 1 frame larger than MTU skipped (JSON)" % name)
        check(js and js["summary"]["truncated_caplen"] == 1, "%s: 1 truncated frame counted (JSON)" % name)

    print("== Streaming: drop-behind and a minimal readahead window do not affect content")
    p = os.path.join(pcaps, "l2mix.pcap")
    rc, out, frames, _ = replay(p, ["--topspeed", "-t", "2", "--loop", "3", "--drop-behind", "on",
                                    "--readahead", "16M"])
    check(rc == 0 and "dropped from page cache" in out, "drop-behind: exit code 0, streaming summary printed")
    check(collections.Counter(f for _, f in frames) == collections.Counter(expected_frames(p) * 3),
          "drop-behind: all frames of 3 laps arrived byte for byte")

    print("== Index cache: second run loads the index, also with another thread count")
    p = os.path.join(pcaps, "l2mix.pcap")
    cache = "/tmp/afr_func_l2mix.afridx"
    if os.path.exists(cache):
        os.unlink(cache)
    rc1, out1, frames1, _ = replay(p, ["--pps", "5000", "-t", "3", "--index-cache", cache])
    rc2, out2, frames2, _ = replay(p, ["--pps", "5000", "-t", "5", "--index-cache", cache])
    check(rc1 == 0 and os.path.exists(cache), "first run saved the cache")
    rc4, out4 = run_afr(["--analyze", "-t", "7", "--index-cache", cache, p])
    check(rc2 == 0 and rc4 == 0 and "Index loaded from cache" in out4,
          "later runs load the index from the cache (any -t)")
    exp = collections.Counter(expected_frames(p))
    check(collections.Counter(f for _, f in frames2) == exp, "cached index: all frames arrived byte for byte")
    rc3, out3 = run_afr(["--analyze", "--index-cache", cache, os.path.join(pcaps, "l2mix_ns_be.pcap")])
    check(rc3 == 0 and "not used" in out3, "cache of another pcap is not used")
    os.unlink(cache)

    print("== Direct I/O (O_DIRECT window instead of the page cache)")
    p = os.path.join(pcaps, "l2mix.pcap")
    for extra in (["--topspeed", "-t", "3", "--loop", "3"], ["--pps", "4000", "-t", "2", "--loop", "2"]):
        rc, out, frames, js = replay(p, ["--io", "direct", "--io-threads", "2"] + extra, "/tmp/afr_dio.json")
        laps = int(extra[-1])
        check(rc == 0 and "Direct I/O: read" in out, "direct I/O %s: exit code 0, direct I/O summary" % " ".join(extra))
        check(collections.Counter(f for _, f in frames) == collections.Counter(expected_frames(p) * laps),
              "direct I/O %s: all frames of %d laps arrived byte for byte" % (" ".join(extra), laps))
    rc, out, frames, _ = replay(p, ["--io", "direct", "--loop", "2", "--topspeed", "-t", "1",
                                    "--loop-mutate", "ip,port"])
    got = [f for _, f in frames]
    check(rc == 0 and len(got) == 2 * len(expected_frames(p)), "direct I/O with --loop-mutate: 2 laps")

    print("== RAW IP with synthetic Ethernet")
    p = os.path.join(pcaps, "raw_ip.pcap")
    sm, dm = "02:aa:00:00:00:01", "02:bb:00:00:00:02"
    rc, out, frames, _ = replay(p, ["--topspeed", "--smac", sm, "--dmac", dm])
    check(rc == 0, "raw_ip: exit code 0")
    compare_frames(expected_frames(p, smac=sm, dmac=dm), [f for _, f in frames], "raw_ip")


def seq_of(fr):
    return struct.unpack("!I", fr[42:46])[0]


def timing_errors(pcap, frames, mult, laps=1, lap_len=None):
    _, recs = read_pcap(pcap)
    t0 = recs[0][0]
    exp = {}
    for i, (ts, _d) in enumerate(recs):
        exp[i] = (ts - t0)
    got = {}
    lapc = collections.Counter()
    for ts, fr in frames:
        s = seq_of(fr)
        lap = lapc[s]
        lapc[s] += 1
        got[(s, lap)] = ts
    pairs = []
    for (s, lap), ts in got.items():
        e = (exp[s] + lap * (lap_len or 0)) / mult
        pairs.append((e, ts))
    pairs.sort()
    base = pairs[0][1] - pairs[0][0]
    errs = sorted(ts - base - e for e, ts in pairs)
    med = errs[len(errs) // 2]
    abs_errs = sorted(abs(x - med) for x in errs)
    return len(pairs), abs_errs, (pairs[-1][1] - pairs[0][1]), (pairs[-1][0] - pairs[0][0])


def t_timing(pcaps, spin):
    print("== Timestamp-based timing (x0.5, x1, x2), capture with nanosecond timestamps")
    p = os.path.join(pcaps, "timing.pcap")
    for mult in (1.0, 2.0, 0.5):
        rc, out, frames, js = replay(p, ["--multiplier", str(mult), "-t", "3", "--spin-us", str(spin)],
                                     "/tmp/afr_func.json")
        check(rc == 0, "x%g: exit code 0" % mult)
        n, errs, real, want = timing_errors(p, frames, mult)
        p50 = errs[len(errs) // 2]
        p95 = errs[int(len(errs) * 0.95)]
        mx = errs[-1]
        print("      x%g: packets %d, |error| p50 %.1f us, p95 %.1f us, max %.1f us; duration %.4f s (expected %.4f s)"
              % (mult, n, p50 / 1e3, p95 / 1e3, mx / 1e3, real / 1e9, want / 1e9))
        check(n == 300, "x%g: all 300 packets received" % mult)
        check(p95 < TOL_P95, "x%g: p95 interval error < %d us" % (mult, TOL_P95 // 1000))
        late_max = js["summary"].get("late_max_ns", 0) if js else 0
        # A rare large outlier (thread preemption, late wakeup) is acceptable
        # only if the replayer itself reported such lateness.
        check(mx < TOL_MAX or mx <= late_max + 200_000,
              "x%g: max error < %d us or explained by lateness seen by the replayer (%.1f us)"
              % (mult, TOL_MAX // 1000, late_max / 1e3))
        check(abs(real - want) < 0.002 * want + 300_000, "x%g: total duration matches (±0.2%%)" % mult)
        check(js and "late_p99_ns" in js["summary"], "x%g: lateness p50/p99/max in JSON" % mult)

    print("== --duration picks the multiplier")
    p = os.path.join(pcaps, "timing.pcap")
    rc, out, frames, _ = replay(p, ["--duration", "500ms", "--spin-us", str(spin)])
    ts = sorted(t for t, _ in frames)
    dur = (ts[-1] - ts[0]) / 1e9
    check(rc == 0 and len(frames) == 300 and abs(dur - 0.5) < 0.005, "--duration 500ms: replayed in %.4f s" % dur)

    print("== --ts-order: sort/clamp/asis on timestamps jumping backwards")
    p = os.path.join(pcaps, "ts_backward.pcap")
    _, recs = read_pcap(p)
    for order in ("sort", "clamp", "asis"):
        rc, out, frames, js = replay(p, ["--ts-order", order, "-t", "3", "--spin-us", str(spin)], "/tmp/afr_func.json")
        check(rc == 0 and len(frames) == 100, "%s: all 100 packets" % order)
        per_flow = collections.defaultdict(list)
        for t, f in sorted(frames):
            per_flow[flow_key(f)].append(recs[seq_of(f)][0])
        if order == "sort":
            ok = all(v == sorted(v) for v in per_flow.values())
            check(ok, "sort: within sessions packets are sent in ascending pcap timestamp order")
        else:
            seqs = collections.defaultdict(list)
            for t, f in sorted(frames):
                seqs[flow_key(f)].append(seq_of(f))
            check(all(v == sorted(v) for v in seqs.values()), "%s: file order preserved within sessions" % order)
        if order == "asis":
            check(js and js["summary"].get("asis_backward", 0) > 0,
                  "asis: \"backwards in time\" packets counted separately (%s)" % (js and js["summary"].get("asis_backward")))

    print("== --mbps N%: rate as a share of the link on the wire")
    p = os.path.join(pcaps, "timing.pcap")
    _, recs = read_pcap(p)
    l2 = [len(d) for _, d in recs]
    l1 = sum(max(x, 60) + 24 for x in l2)
    rate_l2 = 2e6 * 0.5 * sum(l2) / l1  # 50% of a 2 Mbit/s link, converted to L2
    want = (sum(l2) - l2[-1]) * 8 / rate_l2
    rc, out, frames, _ = replay(p, ["--mbps", "50%", "--link-speed", "2M", "-t", "1"])
    ts = sorted(t for t, _ in frames)
    dur = (ts[-1] - ts[0]) / 1e9
    check(rc == 0 and len(frames) == 300 and abs(dur - want) < 0.02 * want,
          "--mbps 50%% of 2M: played in %.3f s, expected %.3f s" % (dur, want))

    print("== --max-gap compresses pauses")
    p = os.path.join(pcaps, "ts_gaps.pcap")
    rc, out, frames, _ = replay(p, ["--max-gap", "100ms", "--spin-us", str(spin)])
    ts = sorted(t for t, _ in frames)
    dur = (ts[-1] - ts[0]) / 1e9
    check(rc == 0 and len(frames) == 90, "ts_gaps: all 90 packets")
    check(abs(dur - 0.287) < 0.005, "ts_gaps: duration %.3f s ≈ 0.287 s (2 s and 5 s pauses compressed to 100 ms)" % dur)

    print("== --loop continues the timeline")
    p = os.path.join(pcaps, "timing.pcap")
    rc, out, frames, js = replay(p, ["--loop", "3", "--multiplier", "2", "--spin-us", str(spin)], "/tmp/afr_func.json")
    check(rc == 0, "loop: exit code 0")
    lap_len = js["lap_ns"] if js else 0
    n, errs, real, want = timing_errors(p, frames, 2.0, laps=3, lap_len=lap_len)
    check(n == 900, "loop: 3 laps of 300 packets (%d)" % n)
    check(errs[int(len(errs) * 0.95)] < TOL_P95, "loop: laps follow a common timeline (p95 < %d us)" % (TOL_P95 // 1000))

    print("== Timestamp outliers")
    p = os.path.join(pcaps, "ts_spike.pcap")
    rc, out, frames, _ = replay(p, ["--ts-outliers", "exclude", "--spin-us", str(spin)])
    ts = sorted(t for t, _ in frames)
    check(rc == 0 and len(frames) == 50, "ts_spike: all 50 packets")
    check((ts[-1] - ts[0]) / 1e9 < 0.1, "ts_spike: one-hour clock spike excluded from the timeline")


def ip_l4_sums_ok(fr):
    """Checks the IPv4 checksum and the TCP/UDP checksum (IPv4, with VLAN). None means the frame is not checked."""
    off, et = 12, struct.unpack("!H", fr[12:14])[0]
    while et in (0x8100, 0x88A8):
        off += 4
        et = struct.unpack("!H", fr[off:off + 2])[0]
    off += 2
    if et != 0x0800:
        return None

    def s16(b):
        if len(b) % 2:
            b += b"\0"
        x = sum(struct.unpack("!%dH" % (len(b) // 2), b))
        while x >> 16:
            x = (x & 0xFFFF) + (x >> 16)
        return x

    ihl = (fr[off] & 0xF) * 4
    if s16(fr[off:off + ihl]) != 0xFFFF:
        return False
    total = struct.unpack("!H", fr[off + 2:off + 4])[0]
    proto = fr[off + 9]
    if struct.unpack("!H", fr[off + 6:off + 8])[0] & 0x3FFF or proto not in (6, 17):
        return True
    seg = fr[off + ihl:off + total]
    if len(seg) < total - ihl:
        return True  # truncated at capture
    if proto == 17 and seg[6:8] == b"\0\0":
        return True
    ph = fr[off + 12:off + 20] + struct.pack("!BBH", 0, proto, len(seg))
    return s16(ph + seg) == 0xFFFF


def t_mutate(pcaps):
    print("== --loop-mutate: new sessions on every lap, checksums recomputed, L2 untouched")
    p = os.path.join(pcaps, "l2mix.pcap")
    exp = expected_frames(p)
    # One IP flow: its frames arrive strictly lap by lap. Non-IP frames go in
    # a separate flow and are interleaved with them, so they are checked separately.
    rc, out, frames, _ = replay(p, ["--loop", "3", "--pps", "20000", "-t", "1", "--loop-mutate", "ip,port"])
    got = [f for _, f in frames]
    check(rc == 0 and len(got) == 3 * len(exp), "3 laps: %d frames of %d" % (len(got), 3 * len(exp)))
    is_ip = lambda f: ip_l4_sums_ok(f) is not None or flow_key(f) is not None or \
        struct.unpack("!H", f[12:14])[0] in (0x86DD, 0x8847, 0x8864, 0x0800) or \
        (struct.unpack("!H", f[12:14])[0] in (0x8100, 0x88A8) and f[16:18] != b"\x88\xcc")
    exp_ip = [f for f in exp if is_ip(f)]
    exp_l2 = [f for f in exp if not is_ip(f)]
    got_ip = [f for f in got if is_ip(f)]
    got_l2 = [f for f in got if not is_ip(f)]
    n = len(exp_ip)
    check(collections.Counter(got_ip[:n]) == collections.Counter(exp_ip), "lap 0 unchanged")
    check(collections.Counter(got_l2) == collections.Counter(exp_l2 * 3),
          "non-IP frames (ARP, STP, LLDP, ...) unchanged on all laps (%d)" % len(got_l2))
    expset = set(exp_ip)
    bad = [f for f in got_ip if ip_l4_sums_ok(f) is False]
    checked = [f for f in got_ip if ip_l4_sums_ok(f) is True]
    check(not bad and checked, "IPv4/TCP/UDP checksums are correct (%d frames, %d errors)" % (len(checked), len(bad)))
    changed1 = sum(1 for f in got_ip[n:2 * n] if f not in expset)
    changed2 = sum(1 for f in got_ip[2 * n:] if f not in expset)
    check(changed1 == n and changed2 == n, "all IP frames of laps 1 and 2 changed (%d, %d of %d)" % (changed1, changed2, n))
    check(not (set(got_ip[n:2 * n]) & set(got_ip[2 * n:])), "laps 1 and 2 produce different frames")
    l2_ok = all(a[:12] == b[:12] for a, b in zip(got_ip[n:2 * n], got_ip[:n]))
    check(l2_ok, "MAC addresses on changed laps are the same")


def t_cli(pcaps):
    print("== CLI and errors")
    rc, out = run_afr(["--analyze", os.path.join(pcaps, "fake.pcapng")])
    check(rc == 1 and "editcap -F pcap" in out, "pcapng: code 1 and editcap hint")
    rc, out = run_afr(["--bogus"])
    check(rc == 2, "unknown option: code 2")
    rc, out = run_afr(["--help"])
    check(rc == 0 and "Examples" in out, "--help with examples")
    rc, out = run_afr(["-i", "nonexistent0", "--topspeed", os.path.join(pcaps, "l2mix.pcap")])
    check(rc == 1, "nonexistent interface: code 1")
    # SIGINT during an infinite loop
    p = subprocess.Popen([BIN, "-i", TX, "--pps", "2000", "--loop", "0", os.path.join(pcaps, "timing.pcap")],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    p.send_signal(signal.SIGINT)
    out = p.communicate(timeout=10)[0].decode()
    check(p.returncode == 0 and "Summary" in out and "stopped" in out, "SIGINT: final statistics and code 0")
    rc, out = run_afr(["-i", TX, "-q", "--topspeed", os.path.join(pcaps, "truncated_file.pcap")])
    check(rc == 0 and "truncated" in out, "truncated file: warning, sends what is available")


def sh(cmd):
    subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def recreate_veth():
    sh("ip link del %s" % TX)
    sh("ip link add name %s type veth peer name %s" % (TX, RX))
    for i in (TX, RX):
        sh("echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6" % i)
        sh("ip link set %s mtu 1500 up" % i)
    sh("ethtool -K %s gro off" % RX)


def t_robust(pcaps):
    print("== Link outages: interface down/up and re-created, the replay continues")
    p = subprocess.Popen([BIN, "-i", TX, "--pps", "2000", "--loop", "0", "-t", "2",
                          os.path.join(pcaps, "timing.pcap")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    sh("ip link set %s down" % TX)
    time.sleep(2.5)
    sh("ip link set %s up" % TX)
    time.sleep(1.5)
    sh("ip link del %s" % TX)
    time.sleep(1.5)
    recreate_veth()
    rx = Receiver(RX)
    time.sleep(2.0)
    p.send_signal(signal.SIGINT)
    out = p.communicate(timeout=20)[0].decode()
    got = rx.finish()
    check(p.returncode == 0, "exit code 0 after two outages (%s)" % p.returncode)
    check("Link outages: 2" in out, "both outages detected and the schedule paused")
    check(len(got) > 100, "sending resumed on the re-created interface (%d frames)" % len(got))

    print("== Watchdog: a stalled thread is reported with the reason")
    sh("tc qdisc add dev %s root tbf rate 8kbit burst 2kb limit 3kb" % TX)
    p = subprocess.Popen([BIN, "-i", TX, "-q", "--topspeed", "--loop", "0", "-t", "1",
                          os.path.join(pcaps, "timing.pcap")], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(8)
    p.send_signal(signal.SIGINT)
    out = p.communicate(timeout=20)[0].decode()
    sh("tc qdisc del dev %s root" % TX)
    check("has sent nothing" in out and "device queue" in out,
          "stall reported: waiting for the device queue")
    check("waited for: device queue" in out, "per-thread wait times in the summary")


def main():
    global BIN, TX, RX, TOL_P95, TOL_MAX
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--pcaps", required=True)
    ap.add_argument("--tx", default="va")
    ap.add_argument("--rx", default="vb")
    ap.add_argument("--spin-us", type=int, default=3000)
    ap.add_argument("--tol-p95-us", type=int, default=100)
    ap.add_argument("--tol-max-us", type=int, default=1000)
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    BIN, TX, RX = os.path.abspath(a.bin), a.tx, a.rx
    TOL_P95, TOL_MAX = a.tol_p95_us * 1000, a.tol_max_us * 1000
    tests = {"bytes": lambda: t_bytes(a.pcaps), "timing": lambda: t_timing(a.pcaps, a.spin_us),
             "mutate": lambda: t_mutate(a.pcaps), "cli": lambda: t_cli(a.pcaps),
             "robust": lambda: t_robust(a.pcaps)}
    for name, fn in tests.items():
        if not a.only or name in a.only.split(","):
            fn()
    if FAILED:
        print("\nFAILED: %d" % len(FAILED))
        sys.exit(1)
    print("\nFunctional tests passed")


if __name__ == "__main__":
    main()
