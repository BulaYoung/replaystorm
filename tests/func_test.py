#!/usr/bin/env python3
"""Функциональные тесты afreplay на паре veth.

Запускается внутри отдельного network namespace (см. func_veth.sh): afreplay
шлёт в va, приёмник слушает vb через AF_PACKET с PACKET_AUXDATA (чтобы
вернуть снятый ядром VLAN-тег) и SO_TIMESTAMPNS (наносекундные метки приёма).
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
    """Возвращает (linktype, [(ts_ns, данные)])."""
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
    """Симметричный ключ IPv4 TCP/UDP (с учётом VLAN), иначе None."""
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
    check(not missing, "%s: все %d кадров дошли байт в байт (не дошло: %d)" % (label, len(expected), sum(missing.values())))
    check(not extra, "%s: лишних кадров нет (лишних: %d)" % (label, sum(extra.values())))
    # Порядок внутри сессий
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
    check(not bad and per_flow, "%s: порядок внутри %d сессий сохранён" % (label, len(per_flow)))


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
    print("== Кадры байт в байт (L2: ARP, STP, LLDP, VLAN, QinQ, MPLS, PPPoE, IPv6, фрагменты)")
    for name, extra in (("l2mix.pcap", ["--pps", "3000", "-t", "3"]),
                        ("l2mix_ns_be.pcap", ["--topspeed", "-t", "2", "--qdisc-bypass"]),
                        ("l2mix.pcap", ["--mbps", "20", "-t", "4", "--ts-order", "sort"])):
        p = os.path.join(pcaps, name)
        rc, out, frames, js = replay(p, extra, "/tmp/afr_func.json")
        check(rc == 0, "%s %s: код выхода 0 (%d)" % (name, " ".join(extra), rc))
        if rc:
            print(out)
        compare_frames(expected_frames(p), [f for _, f in frames], name)
        check(js and js["summary"]["skipped"] == 1, "%s: пропущен 1 кадр больше MTU (JSON)" % name)
        check(js and js["summary"]["truncated_caplen"] == 1, "%s: 1 обрезанный кадр учтён (JSON)" % name)

    print("== RAW IP с синтетическим Ethernet")
    p = os.path.join(pcaps, "raw_ip.pcap")
    sm, dm = "02:aa:00:00:00:01", "02:bb:00:00:00:02"
    rc, out, frames, _ = replay(p, ["--topspeed", "--smac", sm, "--dmac", dm])
    check(rc == 0, "raw_ip: код выхода 0")
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
    print("== Тайминг по тайм-стампам (x0.5, x1, x2), захват с наносекундными метками")
    p = os.path.join(pcaps, "timing.pcap")
    for mult in (1.0, 2.0, 0.5):
        rc, out, frames, js = replay(p, ["--multiplier", str(mult), "-t", "3", "--spin-us", str(spin)],
                                     "/tmp/afr_func.json")
        check(rc == 0, "x%g: код выхода 0" % mult)
        n, errs, real, want = timing_errors(p, frames, mult)
        p50 = errs[len(errs) // 2]
        p95 = errs[int(len(errs) * 0.95)]
        mx = errs[-1]
        print("      x%g: пакетов %d, |ошибка| p50 %.1f мкс, p95 %.1f мкс, max %.1f мкс; длительность %.4f с (ожидалась %.4f с)"
              % (mult, n, p50 / 1e3, p95 / 1e3, mx / 1e3, real / 1e9, want / 1e9))
        check(n == 300, "x%g: получены все 300 пакетов" % mult)
        check(p95 < TOL_P95, "x%g: p95 ошибки интервалов < %d мкс" % (mult, TOL_P95 // 1000))
        late_max = js["summary"].get("late_max_ns", 0) if js else 0
        # Редкий большой выброс (вытеснение потока, позднее пробуждение) допустим,
        # только если реплеер сам сообщил о таком опоздании.
        check(mx < TOL_MAX or mx <= late_max + 200_000,
              "x%g: max ошибки < %d мкс или объяснён опозданием, которое видит реплеер (%.1f мкс)"
              % (mult, TOL_MAX // 1000, late_max / 1e3))
        check(abs(real - want) < 0.002 * want + 300_000, "x%g: общая длительность совпадает (±0.2%%)" % mult)
        check(js and "late_p99_ns" in js["summary"], "x%g: lateness p50/p99/max в JSON" % mult)

    print("== --max-gap сжимает паузы")
    p = os.path.join(pcaps, "ts_gaps.pcap")
    rc, out, frames, _ = replay(p, ["--max-gap", "100ms", "--spin-us", str(spin)])
    ts = sorted(t for t, _ in frames)
    dur = (ts[-1] - ts[0]) / 1e9
    check(rc == 0 and len(frames) == 90, "ts_gaps: все 90 пакетов")
    check(abs(dur - 0.287) < 0.005, "ts_gaps: длительность %.3f с ≈ 0.287 с (паузы 2 с и 5 с сжаты до 100 мс)" % dur)

    print("== --loop продолжает шкалу")
    p = os.path.join(pcaps, "timing.pcap")
    rc, out, frames, js = replay(p, ["--loop", "3", "--multiplier", "2", "--spin-us", str(spin)], "/tmp/afr_func.json")
    check(rc == 0, "loop: код выхода 0")
    lap_len = js["lap_ns"] if js else 0
    n, errs, real, want = timing_errors(p, frames, 2.0, laps=3, lap_len=lap_len)
    check(n == 900, "loop: 3 круга по 300 пакетов (%d)" % n)
    check(errs[int(len(errs) * 0.95)] < TOL_P95, "loop: круги идут по общей шкале (p95 < %d мкс)" % (TOL_P95 // 1000))

    print("== Выбросы тайм-стампов")
    p = os.path.join(pcaps, "ts_spike.pcap")
    rc, out, frames, _ = replay(p, ["--ts-outliers", "exclude", "--spin-us", str(spin)])
    ts = sorted(t for t, _ in frames)
    check(rc == 0 and len(frames) == 50, "ts_spike: все 50 пакетов")
    check((ts[-1] - ts[0]) / 1e9 < 0.1, "ts_spike: скачок часов на час исключён из шкалы")


def t_cli(pcaps):
    print("== CLI и ошибки")
    rc, out = run_afr(["--analyze", os.path.join(pcaps, "fake.pcapng")])
    check(rc == 1 and "editcap -F pcap" in out, "pcapng: код 1 и подсказка editcap")
    rc, out = run_afr(["--bogus"])
    check(rc == 2, "неизвестная опция: код 2")
    rc, out = run_afr(["--help"])
    check(rc == 0 and "Примеры" in out, "--help с примерами")
    rc, out = run_afr(["-i", "nonexistent0", "--topspeed", os.path.join(pcaps, "l2mix.pcap")])
    check(rc == 1, "несуществующий интерфейс: код 1")
    # SIGINT при бесконечном цикле
    p = subprocess.Popen([BIN, "-i", TX, "--pps", "2000", "--loop", "0", os.path.join(pcaps, "timing.pcap")],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    p.send_signal(signal.SIGINT)
    out = p.communicate(timeout=10)[0].decode()
    check(p.returncode == 0 and "Итог" in out and "остановлено" in out, "SIGINT: итоговая статистика и код 0")
    rc, out = run_afr(["-i", TX, "-q", "--topspeed", os.path.join(pcaps, "truncated_file.pcap")])
    check(rc == 0 and "обрезан" in out, "обрезанный файл: предупреждение, отправка того, что есть")


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
             "cli": lambda: t_cli(a.pcaps)}
    for name, fn in tests.items():
        if not a.only or name in a.only.split(","):
            fn()
    if FAILED:
        print("\nНЕ ПРОЙДЕНО: %d" % len(FAILED))
        sys.exit(1)
    print("\nФункциональные тесты пройдены")


if __name__ == "__main__":
    main()
