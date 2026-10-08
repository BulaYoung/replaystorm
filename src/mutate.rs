//! Frame modification on loop laps: shifting IP addresses and/or ports with incremental
//! checksum update (RFC 1624). L2 is left unchanged.

use crate::dissect::{dissect, Dis};

#[derive(Clone, Copy, Debug, Default)]
pub struct MutateCfg {
    pub ip: bool,
    pub port: bool,
    pub ip_offset: u32, // host byte order, multiplied by the lap number
    pub port_step: u32,
    pub raw_ip: i32,    // how to parse the frame (see dissect); 0 for a frame in the ring
}

/// Incremental update of a 16-bit checksum (RFC 1624, eqn. 3).
#[inline(always)]
pub fn csum_update16(hc: u16, old: u16, new: u16) -> u16 {
    let mut s = (!hc) as u32 + (!old) as u32 + new as u32;
    s = (s & 0xFFFF) + (s >> 16);
    s = (s & 0xFFFF) + (s >> 16);
    !(s as u16)
}

#[inline(always)]
fn rd16(f: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([f[o], f[o + 1]])
}

#[inline(always)]
fn wr16(f: &mut [u8], o: usize, v: u16) {
    f[o..o + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline(always)]
fn rd32(f: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(f[o..o + 4].try_into().unwrap())
}

#[inline(always)]
fn wr32(f: &mut [u8], o: usize, v: u32) {
    f[o..o + 4].copy_from_slice(&v.to_be_bytes());
}

/// Account for replacing 32-bit word old -> new in the checksum at offset c.
#[inline(always)]
fn csum_fix32(f: &mut [u8], c: usize, old: u32, new: u32) {
    let mut s = rd16(f, c);
    s = csum_update16(s, (old >> 16) as u16, (new >> 16) as u16);
    s = csum_update16(s, old as u16, new as u16);
    wr16(f, c, s);
}

#[inline(always)]
fn shift_port(p: u16, lap: u64, step: u32) -> u16 {
    // Ports < 1024 (services) are left alone; others are shifted within 1024..65535.
    if p < 1024 {
        return p;
    }
    let r = ((p - 1024) as u64).wrapping_add(lap.wrapping_mul(step as u64)) % 64512;
    (1024 + r) as u16
}

/// Location of the L4 checksum covering the pseudo-header, and whether it is UDP.
fn l4_csum(f: &[u8], d: &Dis) -> (Option<usize>, bool) {
    if d.l4_off == 0 || !d.frag_first {
        return (None, false);
    }
    let (off, is_udp) = match d.proto {
        6 => (16, false),
        17 => (6, true),
        58 if d.l3 == 6 => (2, false),
        _ => return (None, false),
    };
    let c = d.l4_off as usize + off;
    if c + 2 > f.len() {
        return (None, is_udp);
    }
    // UDP with a zero checksum: the checksum is not used.
    if is_udp && rd16(f, c) == 0 {
        return (None, is_udp);
    }
    (Some(c), is_udp)
}

/// Modify the frame in place for lap (> 0). Returns true if the frame was changed.
pub fn mutate(f: &mut [u8], lap: u64, cfg: &MutateCfg) -> bool {
    if lap == 0 {
        return false;
    }
    let d = dissect(f, cfg.raw_ip);
    if d.l3 == 0 {
        return false;
    }
    let (l4c, is_udp) = l4_csum(f, &d);
    let mut changed = false;

    if cfg.ip {
        let delta = lap.wrapping_mul(cfg.ip_offset as u64) as u32;
        let ip = d.l3_off as usize;
        if d.l3 == 4 {
            for k in 0..2 {
                let a = ip + 12 + 4 * k;
                let old = rd32(f, a);
                let nw = old.wrapping_add(delta);
                wr32(f, a, nw);
                csum_fix32(f, ip + 10, old, nw);
                if let Some(c) = l4c {
                    csum_fix32(f, c, old, nw);
                }
            }
        } else {
            // IPv6: shift address bytes 8..11 (upper part of the interface identifier).
            for k in 0..2 {
                let a = ip + 8 + 16 * k + 8;
                let old = rd32(f, a);
                let nw = old.wrapping_add(delta);
                wr32(f, a, nw);
                if let Some(c) = l4c {
                    csum_fix32(f, c, old, nw);
                }
            }
        }
        changed = true;
    }

    if cfg.port && !d.frag && (d.proto == 6 || d.proto == 17) && d.l4_off != 0 && d.l4_off as usize + 4 <= f.len() {
        let pp = d.l4_off as usize;
        let old = rd32(f, pp);
        let s = shift_port(rd16(f, pp), lap, cfg.port_step);
        let t = shift_port(rd16(f, pp + 2), lap, cfg.port_step);
        let nw = ((s as u32) << 16) | t as u32;
        if nw != old {
            wr32(f, pp, nw);
            if let Some(c) = l4c {
                csum_fix32(f, c, old, nw);
            }
            changed = true;
        }
    }
    // In UDP zero means "no checksum"; a computed zero is sent as 0xFFFF.
    if let Some(c) = l4c {
        if is_udp && rd16(f, c) == 0 {
            wr16(f, c, 0xFFFF);
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::flow_hash;

    /// Full checksum recomputation to verify the incremental one.
    fn sum16(p: &[u8], mut s: u32) -> u32 {
        let mut i = 0;
        while i + 1 < p.len() {
            s += ((p[i] as u32) << 8) | p[i + 1] as u32;
            i += 2;
        }
        if p.len() & 1 == 1 {
            s += (p[p.len() - 1] as u32) << 8;
        }
        s
    }

    fn fold(mut s: u32) -> u16 {
        while s >> 16 != 0 {
            s = (s & 0xFFFF) + (s >> 16);
        }
        !(s as u16)
    }

    /// The frame's IP and L4 checksums are correct (as with full recomputation).
    fn sums_ok(f: &[u8]) -> bool {
        let d = dissect(f, 0);
        let l3 = d.l3_off as usize;
        if d.l3 == 4 && fold(sum16(&f[l3..l3 + (f[l3] & 0xF) as usize * 4], 0)) != 0 {
            return false;
        }
        if d.l4_off == 0 || !d.frag_first {
            return true;
        }
        let l4 = d.l4_off as usize;
        let seglen = (f.len() - l4) as u32;
        let ps = if d.l3 == 4 { sum16(&f[l3 + 12..l3 + 20], 0) } else { sum16(&f[l3 + 8..l3 + 40], 0) } + d.proto as u32 + seglen;
        if d.proto == 17 && rd16(f, l4 + 6) == 0 {
            return true;
        }
        fold(sum16(&f[l4..], ps)) == 0
    }

    /// Fill in correct checksums.
    fn fill_sums(f: &mut [u8]) {
        let d = dissect(f, 0);
        let l3 = d.l3_off as usize;
        if d.l3 == 4 {
            wr16(f, l3 + 10, 0);
            let c = fold(sum16(&f[l3..l3 + (f[l3] & 0xF) as usize * 4], 0));
            wr16(f, l3 + 10, c);
        }
        if d.l4_off == 0 || !d.frag_first {
            return;
        }
        let l4 = d.l4_off as usize;
        let off = match d.proto {
            6 => 16,
            17 => 6,
            _ => 2,
        };
        let seglen = (f.len() - l4) as u32;
        wr16(f, l4 + off, 0);
        let ps = if d.l3 == 4 { sum16(&f[l3 + 12..l3 + 20], 0) } else { sum16(&f[l3 + 8..l3 + 40], 0) } + d.proto as u32 + seglen;
        let mut c = fold(sum16(&f[l4..], ps));
        if d.proto == 17 && c == 0 {
            c = 0xFFFF;
        }
        wr16(f, l4 + off, c);
    }

    #[allow(clippy::too_many_arguments)]
    fn build_v4(vlan: bool, proto: u8, s: u32, dd: u32, sp: u16, dp: u16, frag: u16) -> Vec<u8> {
        let mut f: Vec<u8> = (0..12).map(|i| 0xa0 + i).collect();
        if vlan {
            f.extend_from_slice(&[0x81, 0x00, 0, 42]);
        }
        f.extend_from_slice(&[0x08, 0x00]);
        let l3 = f.len();
        let payload = 37;
        let l4len = if proto == 6 { 20 } else { 8 } + payload;
        f.resize(l3 + 20 + l4len, 0);
        f[l3] = 0x45;
        wr16(&mut f, l3 + 2, (20 + l4len) as u16);
        wr16(&mut f, l3 + 6, frag);
        f[l3 + 8] = 64;
        f[l3 + 9] = proto;
        wr32(&mut f, l3 + 12, s);
        wr32(&mut f, l3 + 16, dd);
        let o = l3 + 20;
        wr16(&mut f, o, sp);
        wr16(&mut f, o + 2, dp);
        if proto == 6 {
            f[o + 12] = 0x50;
        } else {
            wr16(&mut f, o + 4, l4len as u16);
        }
        for i in 0..payload {
            f[o + l4len - payload + i] = (i * 7 + 3) as u8;
        }
        fill_sums(&mut f);
        f
    }

    fn build_v6(proto: u8) -> Vec<u8> {
        let mut f: Vec<u8> = (0..12).map(|i| 0xb0 + i).collect();
        f.extend_from_slice(&[0x86, 0xdd]);
        let o = f.len();
        let l4len = if proto == 6 { 20 } else { 8 } + 25;
        f.resize(o + 40 + l4len, 0);
        f[o] = 0x60;
        wr16(&mut f, o + 4, l4len as u16);
        f[o + 6] = proto;
        f[o + 7] = 64;
        for i in 0..16 {
            f[o + 8 + i] = 0x20 + i as u8;
            f[o + 24 + i] = 0x90 + i as u8;
        }
        let o = o + 40;
        wr16(&mut f, o, 50000);
        wr16(&mut f, o + 2, 443);
        if proto == 6 {
            f[o + 12] = 0x50;
        } else {
            wr16(&mut f, o + 4, l4len as u16);
        }
        for i in 0..25 {
            f[o + l4len - 25 + i] = (i * 13) as u8;
        }
        fill_sums(&mut f);
        f
    }

    #[test]
    fn rfc1624() {
        // Example from RFC 1624, section 4: HC=0xDD2F, m=0x5555 -> m'=0x3285, HC'=0x0000
        assert_eq!(csum_update16(0xDD2F, 0x5555, 0x3285), 0x0000);
    }

    #[test]
    fn v4_cases() {
        let cfg = MutateCfg { ip: true, port: true, ip_offset: 0x00010000, port_step: 1, raw_ip: 0 };
        for vlan in [false, true] {
            for proto in [6u8, 17] {
                let mut f = build_v4(vlan, proto, 0x0a000001, 0xc0a80105, 51000, 443, 0);
                let orig = f.clone();
                assert!(sums_ok(&f));
                assert!(!mutate(&mut f, 0, &cfg)); // lap 0 is unchanged
                assert_eq!(f, orig);
                assert!(mutate(&mut f, 3, &cfg));
                assert!(sums_ok(&f));
                let l2 = if vlan { 18 } else { 14 };
                assert_eq!(f[..l2], orig[..l2]); // L2 untouched
                let ip = &f[l2..];
                assert_eq!(ip[13], 0x03); // 10.0.0.1 + 3*0.1.0.0 = 10.3.0.1
                assert_eq!(ip[17], 0xab); // 192.168.1.5 -> 192.171.1.5
                assert_eq!(rd16(ip, 20), 51003);
                assert_eq!(rd16(ip, 22), 443); // port < 1024 is unchanged
            }
        }
        // UDP without checksum: stays without one
        let mut f = build_v4(false, 17, 1, 2, 2000, 3000, 0);
        wr16(&mut f, 14 + 20 + 6, 0);
        mutate(&mut f, 1, &cfg);
        assert_eq!(rd16(&f, 14 + 20 + 6), 0);
        assert!(sums_ok(&f));
        // Wraparound past 65535 for the port and past 255 for the octet
        let mut f = build_v4(false, 6, 0x0affffff, 0x0b000000, 65535, 65000, 0);
        mutate(&mut f, 1, &cfg);
        assert!(sums_ok(&f));
        assert_eq!(rd16(&f, 34), 1024);
        // Symmetry: forward and reverse packets are still mirrored after the shift
        let mut a = build_v4(false, 6, 0x0a000001, 0x0a000002, 40000, 50000, 0);
        let mut b = build_v4(false, 6, 0x0a000002, 0x0a000001, 50000, 40000, 0);
        mutate(&mut a, 5, &cfg);
        mutate(&mut b, 5, &cfg);
        assert!(a[26..30] == b[30..34] && a[30..34] == b[26..30]);
        assert!(rd16(&a, 34) == rd16(&b, 36) && rd16(&a, 36) == rd16(&b, 34));
        let (da, db) = (dissect(&a, 0), dissect(&b, 0));
        assert_eq!(flow_hash(&da, &a), flow_hash(&db, &b));
    }

    #[test]
    fn fragments() {
        let cfg = MutateCfg { ip: true, port: true, ip_offset: 0x00010000, port_step: 1, raw_ip: 0 };
        // First fragment: the L4 checksum covers the whole datagram, shift only the addresses
        // (fragment ports are left alone, otherwise they would diverge from the other fragments).
        let mut f = build_v4(false, 17, 0x0a000001, 0x0a000002, 5000, 6000, 0x2000);
        let c0 = rd16(&f, 34 + 6);
        mutate(&mut f, 2, &cfg);
        assert_eq!(rd16(&f, 34), 5000);
        assert_ne!(rd16(&f, 34 + 6), c0);
        assert_eq!(fold(sum16(&f[14..34], 0)), 0);
        // Non-first fragment: no L4, only the addresses and the IP checksum change
        let mut f = build_v4(false, 17, 0x0a000001, 0x0a000002, 0x1111, 0x2222, 100);
        let before = f.clone();
        mutate(&mut f, 2, &cfg);
        assert_eq!(fold(sum16(&f[14..34], 0)), 0);
        assert_eq!(f[34..], before[34..]);
    }

    #[test]
    fn v6_cases() {
        let cfg = MutateCfg { ip: true, port: true, ip_offset: 0x00010000, port_step: 7, raw_ip: 0 };
        for proto in [6u8, 17] {
            let mut f = build_v6(proto);
            let orig = f.clone();
            assert!(sums_ok(&f));
            assert!(mutate(&mut f, 4, &cfg));
            assert!(sums_ok(&f));
            assert_eq!(f[..14], orig[..14]);
            assert_eq!(f[22..30], orig[22..30]); // /64 prefix is unchanged
            assert_ne!(f[30..38], orig[30..38]);
            assert_eq!(rd16(&f, 54), 50000 + 28);
        }
    }

    #[test]
    fn only_ports() {
        let cfg = MutateCfg { ip: false, port: true, ip_offset: 0, port_step: 100, raw_ip: 0 };
        let mut f = build_v4(true, 6, 0x0a000001, 0x0a000002, 2000, 80, 0);
        let orig = f.clone();
        mutate(&mut f, 1, &cfg);
        assert!(sums_ok(&f));
        assert_eq!(f[18..38], orig[18..38]); // IP header unchanged
        assert_eq!(rd16(&f, 38), 2100);
        // non-IP frame is left untouched
        let mut arp = [0u8; 60];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert!(!mutate(&mut arp, 1, &cfg));
    }
}
