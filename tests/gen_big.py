#!/usr/bin/env python3
"""Большой синтетический pcap для замеров производительности.

Использование: gen_big.py ВЫХОД.pcap РАЗМЕР_ГБ
4096 TCP/UDP-сессий, кадры 64..1400 байт, ~2 мкс между пакетами.
"""
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_pcaps import A, B, eth, ipv4_tcp, ipv4_udp  # noqa: E402


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    r = random.Random(1)
    tmpl = []
    for i in range(4096):
        sz = r.choice([64, 128, 512, 1000, 1400, 1400, 1400])
        src = "10.%d.%d.%d" % (i >> 8 & 255, i & 255, 1 + i % 200)
        dst = "192.168.%d.%d" % (i % 7, 1 + i % 250)
        if i % 2:
            tmpl.append(eth(B, A, 0x0800, ipv4_tcp(src, dst, 1024 + i, 443, i, bytes(sz))))
        else:
            tmpl.append(eth(A, B, 0x0800, ipv4_udp(dst, src, 53, 1024 + i, bytes(sz))))
    target = int(float(sys.argv[2]) * (1 << 30))
    with open(sys.argv[1], "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        t = 1_700_000_000 * 1_000_000
        size, n, buf = 24, 0, []
        while size < target:
            f = tmpl[r.randrange(4096)]
            t += r.randrange(1, 4)
            buf.append(struct.pack("<IIII", t // 1_000_000, t % 1_000_000, len(f), len(f)) + f)
            size += 16 + len(f)
            n += 1
            if len(buf) >= 65536:
                out.write(b"".join(buf))
                buf = []
        out.write(b"".join(buf))
    print("пакетов:", n)


if __name__ == "__main__":
    main()
