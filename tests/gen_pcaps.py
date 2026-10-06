#!/usr/bin/env python3
"""Генератор тестовых pcap для afreplay (без внешних зависимостей).

Создаёт в каталоге OUT:
  l2mix.pcap          — ARP, STP, LLDP, VLAN, QinQ, MPLS (+PW), PPPoE, IPv6 (+ext hdr),
                        IPv4/IPv6 фрагменты, TCP/UDP-сессии в обе стороны,
                        обрезанный при захвате кадр, кадр больше MTU (us, little-endian)
  l2mix_ns_be.pcap    — то же, наносекунды, big-endian
  raw_ip.pcap         — linktype 101 (RAW IP), IPv4 и IPv6
  ts_backward.pcap    — тайм-стампы со скачками назад
  ts_gaps.pcap        — большие паузы
  ts_zero.pcap        — ts = 0 и далёкое будущее
  ts_spike.pcap       — кратковременный скачок часов
  timing.pcap         — для проверки тайминга: несколько потоков, интервалы 0.5..6 мс
  truncated_file.pcap — файл обрезан посреди записи
  fake.pcapng         — заголовок pcapng
"""
import os
import random
import struct
import sys


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def ip6(n):
    return bytes.fromhex("20010db8000000000000000000000000")[:15] + bytes([n])


def eth(dst, src, et, payload):
    return mac(dst) + mac(src) + struct.pack("!H", et) + payload


def vlan(tpid, vid, et):
    """Возвращает тег: TCI + следующий ethertype (TPID кладётся предыдущим уровнем)."""
    return struct.pack("!HH", vid, et)


def ipv4(src, dst, proto, payload, ident=1, flags_off=0, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags_off, ttl, proto,
                      0, ip4(src), ip4(dst))
    c = csum(hdr)
    return hdr[:10] + struct.pack("!H", c) + hdr[12:] + payload


def l4_csum4(src, dst, proto, seg):
    ph = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, proto, len(seg))
    return csum(ph + seg)


def l4_csum6(src, dst, proto, seg):
    ph = src + dst + struct.pack("!IxxxB", len(seg), proto)
    return csum(ph + seg)


def tcp(sport, dport, seq, flags=0x18, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def with_csum4(src, dst, proto, seg):
    off = 16 if proto == 6 else 6
    c = l4_csum4(src, dst, proto, seg)
    if proto == 17 and c == 0:
        c = 0xFFFF
    return seg[:off] + struct.pack("!H", c) + seg[off + 2:]


def with_csum6(src, dst, proto, seg):
    off = 16 if proto == 6 else 6
    c = l4_csum6(src, dst, proto, seg)
    if proto == 17 and c == 0:
        c = 0xFFFF
    return seg[:off] + struct.pack("!H", c) + seg[off + 2:]


def ipv4_tcp(src, dst, sport, dport, seq, payload=b"", flags=0x18):
    return ipv4(src, dst, 6, with_csum4(src, dst, 6, tcp(sport, dport, seq, flags, payload)))


def ipv4_udp(src, dst, sport, dport, payload=b""):
    return ipv4(src, dst, 17, with_csum4(src, dst, 17, udp(sport, dport, payload)))


def ipv6(src, dst, nh, payload, hlim=64):
    return struct.pack("!IHBB", 0x60000000, len(payload), nh, hlim) + src + dst + payload


def ipv6_tcp(src, dst, sport, dport, seq, payload=b""):
    return ipv6(src, dst, 6, with_csum6(src, dst, 6, tcp(sport, dport, seq, 0x18, payload)))


def ipv6_udp(src, dst, sport, dport, payload=b""):
    return ipv6(src, dst, 17, with_csum6(src, dst, 17, udp(sport, dport, payload)))


A = "00:11:22:33:44:55"
B = "66:77:88:99:aa:bb"


def frames_l2mix():
    """Список (кадр, origlen или None)."""
    fr = []
    # ARP запрос/ответ
    arp_req = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(A) + ip4("10.0.0.1") + bytes(6) + ip4("10.0.0.2")
    arp_rep = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + mac(B) + ip4("10.0.0.2") + mac(A) + ip4("10.0.0.1")
    fr.append(eth("ff:ff:ff:ff:ff:ff", A, 0x0806, arp_req))
    fr.append(eth(A, B, 0x0806, arp_rep))
    # STP BPDU (802.3 + LLC)
    bpdu = bytes([0x42, 0x42, 0x03]) + bytes(35)
    fr.append(mac("01:80:c2:00:00:00") + mac(A) + struct.pack("!H", len(bpdu)) + bpdu)
    # LLDP
    lldp = bytes([0x02, 0x07, 0x04]) + mac(A) + bytes([0x04, 0x02, 0x07, 0x31, 0x06, 0x02, 0x00, 0x78, 0x00, 0x00])
    fr.append(eth("01:80:c2:00:00:0e", A, 0x88CC, lldp))
    # Неизвестный ethertype
    fr.append(eth(B, A, 0x88B5, b"local experimental" + bytes(30)))
    # Несколько TCP-сессий в обе стороны, в т.ч. в VLAN
    rnd = random.Random(1)
    for s in range(12):
        cli = "10.1.%d.%d" % (s, 10 + s)
        srv = "192.168.%d.1" % (s % 3)
        sp = 40000 + s
        for k in range(6):
            pl = bytes([rnd.randrange(256) for _ in range(rnd.randrange(0, 200))])
            if k % 2 == 0:
                l3 = ipv4_tcp(cli, srv, sp, 443, 1000 + k, pl)
                d, sm = B, A
            else:
                l3 = ipv4_tcp(srv, cli, 443, sp, 5000 + k, pl)
                d, sm = A, B
            if s % 3 == 1:
                fr.append(eth(d, sm, 0x8100, vlan(0x8100, 100 + s, 0x0800) + l3))
            elif s % 3 == 2:
                # QinQ: 802.1ad снаружи, 802.1Q внутри
                fr.append(eth(d, sm, 0x88A8, vlan(0x88A8, 10, 0x8100) + vlan(0x8100, 200 + s, 0x0800) + l3))
            else:
                fr.append(eth(d, sm, 0x0800, l3))
    # MPLS: два лейбла, внутри IPv4 UDP
    for k in range(4):
        l3 = ipv4_udp("172.16.0.1", "172.16.0.2", 5000, 53, b"q" * (20 + k)) if k % 2 == 0 else \
            ipv4_udp("172.16.0.2", "172.16.0.1", 53, 5000, b"r" * (40 + k))
        labels = struct.pack("!I", (16 << 12) | (0 << 9) | (0 << 8) | 64) + struct.pack("!I", (17 << 12) | (1 << 8) | 64)
        fr.append(eth(B, A, 0x8847, labels + l3))
    # MPLS псевдопровод с control word и внутренним Ethernet
    inner = eth("02:00:00:00:00:aa", "02:00:00:00:00:bb", 0x0800, ipv4_udp("10.9.9.1", "10.9.9.2", 1111, 2222, b"pw"))
    fr.append(eth(B, A, 0x8847, struct.pack("!I", (30 << 12) | (1 << 8) | 64) + bytes(4) + inner))
    # PPPoE session с IPv4
    l3 = ipv4_udp("100.64.0.1", "8.8.8.8", 33333, 53, b"pppoe")
    fr.append(eth(B, A, 0x8864, struct.pack("!BBHH", 0x11, 0, 0x1234, len(l3) + 2) + struct.pack("!H", 0x0021) + l3))
    # IPv6 TCP в обе стороны и с заголовком расширения
    a6, b6 = ip6(1), ip6(2)
    for k in range(4):
        if k % 2 == 0:
            fr.append(eth(B, A, 0x86DD, ipv6_tcp(a6, b6, 50000, 80, k, b"GET /" + bytes(k))))
        else:
            fr.append(eth(A, B, 0x86DD, ipv6_tcp(b6, a6, 80, 50000, k, b"HTTP/1.1 200" + bytes(k))))
    seg = with_csum6(a6, b6, 17, udp(7000, 7001, b"hbh"))
    hbh = bytes([17, 0, 1, 4, 0, 0, 0, 0])
    fr.append(eth(B, A, 0x86DD, ipv6(a6, b6, 0, hbh + seg)))
    # IPv4 фрагменты одной UDP-датаграммы
    big = with_csum4("10.2.0.1", "10.2.0.2", 17, udp(9999, 8888, bytes(range(256)) * 10))
    chunks = [big[i:i + 1000] for i in range(0, len(big), 1000)]
    for i, ch in enumerate(chunks):
        mf = 0x2000 if i < len(chunks) - 1 else 0
        fr.append(eth(B, A, 0x0800, ipv4("10.2.0.1", "10.2.0.2", 17, ch, ident=77, flags_off=mf | (i * 1000 // 8))))
    # IPv6 фрагменты
    big6 = with_csum6(a6, b6, 17, udp(9999, 8888, bytes(range(256)) * 6))
    chunks = [big6[i:i + 800] for i in range(0, len(big6), 800)]
    for i, ch in enumerate(chunks):
        m = 1 if i < len(chunks) - 1 else 0
        fh = struct.pack("!BBHI", 17, 0, ((i * 800 // 8) << 3) | m, 0xabcdef)
        fr.append(eth(B, A, 0x86DD, ipv6(a6, b6, 44, fh + ch)))
    # ICMP
    icmp = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping" * 8
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    fr.append(eth(B, A, 0x0800, ipv4("10.3.0.1", "10.3.0.2", 1, icmp)))
    out = [(f, None) for f in fr]
    # Обрезанный при захвате кадр: origlen больше caplen
    full = eth(B, A, 0x0800, ipv4_udp("10.4.0.1", "10.4.0.2", 1234, 4321, bytes(600)))
    out.append((full[:128], len(full)))
    # Кадр больше MTU 1500 (будет пропущен)
    out.append((eth(B, A, 0x0800, ipv4_udp("10.5.0.1", "10.5.0.2", 1, 2, bytes(1600))), None))
    # Кадр ровно MTU+14 и 802.1Q ровно MTU+18 (должны пройти)
    out.append((eth(B, A, 0x0800, ipv4_udp("10.6.0.1", "10.6.0.2", 1, 2, bytes(1500 - 28))), None))
    out.append((eth(B, A, 0x8100, vlan(0x8100, 5, 0x0800) + ipv4_udp("10.6.0.1", "10.6.0.2", 1, 2, bytes(1500 - 28))), None))
    return out


def write_pcap(path, recs, nsec=False, big_endian=False, linktype=1):
    """recs: список (ts_ns, кадр, origlen или None)."""
    e = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nsec else 0xA1B2C3D4
    with open(path, "wb") as f:
        f.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
        for ts, data, orig in recs:
            sec = ts // 1_000_000_000
            frac = ts % 1_000_000_000
            if not nsec:
                frac //= 1000
            f.write(struct.pack(e + "IIII", sec, frac, len(data), orig if orig else len(data)))
            f.write(data)


BASE = 1_700_000_000 * 1_000_000_000  # 2023-11-14


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "pcaps"
    os.makedirs(out, exist_ok=True)

    mix = frames_l2mix()
    recs = [(BASE + i * 1_000_000, f, o) for i, (f, o) in enumerate(mix)]
    write_pcap(os.path.join(out, "l2mix.pcap"), recs)
    write_pcap(os.path.join(out, "l2mix_ns_be.pcap"),
               [(BASE + i * 1_000_123, f, o) for i, (f, o) in enumerate(mix)], nsec=True, big_endian=True)

    raw = []
    for i in range(20):
        if i % 2:
            raw.append(ipv4_udp("10.7.0.%d" % i, "10.7.1.1", 1000 + i, 53, b"raw4"))
        else:
            raw.append(ipv6_udp(ip6(i), ip6(200), 1000 + i, 53, b"raw6"))
    write_pcap(os.path.join(out, "raw_ip.pcap"), [(BASE + i * 1_000_000, f, None) for i, f in enumerate(raw)],
               linktype=101)

    def flow_frames(n, seed):
        r = random.Random(seed)
        fr = []
        for i in range(n):
            s = i % 8
            if r.random() < 0.5:
                fr.append(eth(B, A, 0x0800, ipv4_udp("10.8.0.%d" % s, "10.8.1.1", 2000 + s, 9000, bytes(r.randrange(10, 400)))))
            else:
                fr.append(eth(A, B, 0x0800, ipv4_udp("10.8.1.1", "10.8.0.%d" % s, 9000, 2000 + s, bytes(r.randrange(10, 400)))))
        return fr

    # Скачки назад: каждый 10-й пакет на 3 мс раньше
    fr = flow_frames(100, 2)
    recs = []
    for i, f in enumerate(fr):
        ts = BASE + i * 1_000_000
        if i % 10 == 5:
            ts -= 3_000_000
        recs.append((ts, f, None))
    write_pcap(os.path.join(out, "ts_backward.pcap"), recs)

    # Большие паузы: 2 с после 30-го пакета и 5 с после 60-го
    fr = flow_frames(90, 3)
    recs, t = [], BASE
    for i, f in enumerate(fr):
        if i == 30:
            t += 2_000_000_000
        if i == 60:
            t += 5_000_000_000
        recs.append((t, f, None))
        t += 1_000_000
    write_pcap(os.path.join(out, "ts_gaps.pcap"), recs)

    # ts=0 и будущее
    fr = flow_frames(50, 4)
    recs = []
    for i, f in enumerate(fr):
        ts = BASE + i * 1_000_000
        if i in (0, 20):
            ts = 0
        if i == 35:
            ts = 4_000_000_000 * 1_000_000_000 // 1  # ~2096 год
        recs.append((ts, f, None))
    write_pcap(os.path.join(out, "ts_zero.pcap"), recs)

    # Кратковременный скачок часов: пакеты 20..22 на час вперёд
    fr = flow_frames(50, 5)
    recs = []
    for i, f in enumerate(fr):
        ts = BASE + i * 1_000_000
        if 20 <= i <= 22:
            ts += 3600 * 1_000_000_000
        recs.append((ts, f, None))
    write_pcap(os.path.join(out, "ts_spike.pcap"), recs)

    # Тайминг: 8 потоков, интервалы 0.5..6 мс, ~1 с
    r = random.Random(6)
    fr = flow_frames(300, 6)
    recs, t = [], BASE
    for f in fr:
        recs.append((t, f, None))
        t += r.randrange(500_000, 6_000_000)
    write_pcap(os.path.join(out, "timing.pcap"), recs, nsec=True)

    # Обрезанный файл
    p = os.path.join(out, "truncated_file.pcap")
    write_pcap(p, [(BASE + i * 1_000_000, f, o) for i, (f, o) in enumerate(mix[:20])])
    sz = os.path.getsize(p)
    with open(p, "r+b") as f:
        f.truncate(sz - 7)

    with open(os.path.join(out, "fake.pcapng"), "wb") as f:
        f.write(struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28))

    print("тестовые pcap записаны в", out)


if __name__ == "__main__":
    main()
