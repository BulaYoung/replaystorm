//! Frame dissection: L2 (VLAN/QinQ/MPLS/PPPoE) -> L3 -> L4, plus a symmetric flow hash.

pub const ETH_HLEN: u32 = 14;
pub const ETHT_IPV4: u16 = 0x0800;
pub const ETHT_ARP: u16 = 0x0806;
pub const ETHT_VLAN: u16 = 0x8100;
pub const ETHT_QINQ: u16 = 0x88a8;
pub const ETHT_QINQ_OLD1: u16 = 0x9100;
pub const ETHT_QINQ_OLD2: u16 = 0x9200;
pub const ETHT_IPV6: u16 = 0x86dd;
pub const ETHT_MPLS_UC: u16 = 0x8847;
pub const ETHT_MPLS_MC: u16 = 0x8848;
pub const ETHT_PPPOE_S: u16 = 0x8864;
pub const ETHT_LLDP: u16 = 0x88cc;

/// Kind of non-IP frame (for statistics).
pub const L2K_IP: u8 = 0;
pub const L2K_ARP: u8 = 1;
pub const L2K_LLC: u8 = 2; // 802.3 + LLC: STP, CDP, etc.
pub const L2K_LLDP: u8 = 3;
pub const L2K_OTHER: u8 = 4;
pub const L2K_COUNT: usize = 5;

#[derive(Default, Clone, Copy, Debug)]
pub struct Dis {
    pub l3: u8,              // 0 = not IP, 4 or 6
    pub proto: u8,           // L4 protocol (after IPv6 extension headers)
    pub frag: bool,          // fragment (any)
    pub frag_first: bool,    // first fragment (offset == 0) or not a fragment
    pub vlan_depth: u8,      // number of VLAN tags
    pub mpls: bool,          // MPLS stack present
    pub pppoe: bool,
    pub l2kind: u8,
    pub outer_ethertype: u16, // ethertype right after the MAC addresses
    pub l3_off: u16,         // L3 offset in the frame
    pub l4_off: u16,         // L4 offset, 0 if none
    pub sport: u16,          // host byte order; 0 if no ports
    pub dport: u16,
    pub src: u16,            // offsets of the L3 addresses (4 or 16 bytes)
    pub dst: u16,
}

#[inline(always)]
fn be16(p: &[u8], o: u32) -> u16 {
    u16::from_be_bytes([p[o as usize], p[o as usize + 1]])
}

#[inline(always)]
fn is_vlan_tpid(t: u16) -> bool {
    t == ETHT_VLAN || t == ETHT_QINQ || t == ETHT_QINQ_OLD1 || t == ETHT_QINQ_OLD2
}

#[inline(always)]
fn has_ports(proto: u8) -> bool {
    // TCP, UDP, DCCP, SCTP, UDP-Lite
    matches!(proto, 6 | 17 | 33 | 132 | 136)
}

fn parse_l4(p: &[u8], d: &mut Dis, l4: u32) {
    let len = p.len() as u32;
    if l4 > 0xFFFF {
        return;
    }
    d.l4_off = l4 as u16;
    if !d.frag && has_ports(d.proto) && l4 + 4 <= len {
        d.sport = be16(p, l4);
        d.dport = be16(p, l4 + 2);
    }
}

fn parse_ipv4(p: &[u8], off: u32, d: &mut Dis) {
    let len = p.len() as u32;
    if off + 20 > len || (p[off as usize] >> 4) != 4 {
        return;
    }
    let ihl = (p[off as usize] & 0x0F) as u32 * 4;
    if ihl < 20 || off + ihl > len {
        return;
    }
    d.l3 = 4;
    d.l3_off = off as u16;
    d.proto = p[off as usize + 9];
    d.src = (off + 12) as u16;
    d.dst = (off + 16) as u16;
    let fo = be16(p, off + 6);
    let frag_off = fo & 0x1FFF;
    d.frag = (fo & 0x2000) != 0 || frag_off != 0;
    d.frag_first = frag_off == 0;
    if d.frag_first {
        parse_l4(p, d, off + ihl);
    }
}

fn parse_ipv6(p: &[u8], off: u32, d: &mut Dis) {
    let len = p.len() as u32;
    if off + 40 > len || (p[off as usize] >> 4) != 6 {
        return;
    }
    d.l3 = 6;
    d.l3_off = off as u16;
    d.src = (off + 8) as u16;
    d.dst = (off + 24) as u16;
    d.frag_first = true;
    let mut nh = p[off as usize + 6];
    let mut cur = off + 40;
    for _ in 0..8 {
        if nh == 0 || nh == 43 || nh == 60 || nh == 135 {
            if cur + 8 > len {
                d.proto = nh;
                return;
            }
            let next = p[cur as usize];
            cur += (p[cur as usize + 1] as u32 + 1) * 8;
            nh = next;
        } else if nh == 51 {
            // AH
            if cur + 8 > len {
                d.proto = nh;
                return;
            }
            let next = p[cur as usize];
            cur += (p[cur as usize + 1] as u32 + 2) * 4;
            nh = next;
        } else if nh == 44 {
            // fragment
            if cur + 8 > len {
                d.proto = nh;
                d.frag = true;
                d.frag_first = false;
                return;
            }
            let fo = be16(p, cur + 2);
            d.frag = true;
            d.frag_first = (fo & 0xFFF8) == 0;
            nh = p[cur as usize];
            cur += 8;
        } else {
            break;
        }
    }
    d.proto = nh;
    if d.frag_first && cur <= len {
        parse_l4(p, d, cur);
    }
}

fn parse_ip_by_version(p: &[u8], off: u32, d: &mut Dis) {
    if off >= p.len() as u32 {
        return;
    }
    match p[off as usize] >> 4 {
        4 => parse_ipv4(p, off, d),
        6 => parse_ipv6(p, off, d),
        _ => {}
    }
}

fn parse_ethertype(p: &[u8], mut off: u32, mut et: u16, d: &mut Dis, depth: u32) {
    let len = p.len() as u32;
    // VLAN / QinQ
    let mut i = 0;
    while i < 8 && is_vlan_tpid(et) {
        if off + 4 > len {
            return;
        }
        d.vlan_depth += 1;
        et = be16(p, off + 2);
        off += 4;
        i += 1;
    }
    match et {
        ETHT_IPV4 => parse_ipv4(p, off, d),
        ETHT_IPV6 => parse_ipv6(p, off, d),
        ETHT_ARP => d.l2kind = L2K_ARP,
        ETHT_LLDP => d.l2kind = L2K_LLDP,
        ETHT_MPLS_UC | ETHT_MPLS_MC => {
            d.mpls = true;
            for _ in 0..16 {
                if off + 4 > len {
                    return;
                }
                let bos = p[off as usize + 2] & 1;
                off += 4;
                if bos != 0 {
                    break;
                }
            }
            if off >= len {
                return;
            }
            match p[off as usize] >> 4 {
                4 => parse_ipv4(p, off, d),
                6 => parse_ipv6(p, off, d),
                0 => {
                    // Pseudowire with control word: an Ethernet frame inside.
                    if depth == 0 {
                        parse_eth(p, off + 4, d, depth + 1);
                    }
                }
                _ => {}
            }
        }
        ETHT_PPPOE_S => {
            if off + 8 > len {
                return;
            }
            let ppp = be16(p, off + 6);
            d.pppoe = true;
            if ppp == 0x0021 {
                parse_ipv4(p, off + 8, d);
            } else if ppp == 0x0057 {
                parse_ipv6(p, off + 8, d);
            }
        }
        _ => {
            if et < 0x0600 {
                d.l2kind = L2K_LLC;
            }
        }
    }
}

fn parse_eth(p: &[u8], off: u32, d: &mut Dis, depth: u32) {
    if off + ETH_HLEN > p.len() as u32 {
        return;
    }
    let et = be16(p, off + 12);
    if depth == 0 {
        d.outer_ethertype = et;
    }
    parse_ethertype(p, off + ETH_HLEN, et, d, depth);
}

/// Dissect a frame. raw_ip: 0 = frame starts with Ethernet, 4/6 = with IP of the given
/// version, 1 = with IP, version taken from the first nibble.
pub fn dissect(p: &[u8], raw_ip: i32) -> Dis {
    let mut d = Dis { l2kind: L2K_OTHER, ..Default::default() };
    match raw_ip {
        0 => parse_eth(p, 0, &mut d, 0),
        4 => parse_ipv4(p, 0, &mut d),
        6 => parse_ipv6(p, 0, &mut d),
        _ => parse_ip_by_version(p, 0, &mut d),
    }
    if d.l3 != 0 {
        d.l2kind = L2K_IP;
    }
    d
}

#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    x
}

#[inline(always)]
fn ld64(p: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(p[o..o + 8].try_into().unwrap())
}

#[inline(always)]
fn ld32(p: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes(p[o..o + 4].try_into().unwrap())
}

/// Symmetric flow hash: A->B and B->A yield the same value. Only for d.l3 != 0.
/// p is the frame the dissection was made of.
pub fn flow_hash(d: &Dis, p: &[u8]) -> u64 {
    let (mut pa, mut pb) = (d.sport, d.dport);
    let h;
    if d.l3 == 4 {
        let mut a = ld32(p, d.src as usize);
        let mut b = ld32(p, d.dst as usize);
        // Order the connection endpoints so the hash is symmetric.
        if a > b || (a == b && pa > pb) {
            std::mem::swap(&mut a, &mut b);
            std::mem::swap(&mut pa, &mut pb);
        }
        h = mix64(((a as u64) << 32) | b as u64);
    } else {
        let mut a = d.src as usize;
        let mut b = d.dst as usize;
        let c = p[a..a + 16].cmp(&p[b..b + 16]);
        if c == std::cmp::Ordering::Greater || (c == std::cmp::Ordering::Equal && pa > pb) {
            std::mem::swap(&mut a, &mut b);
            std::mem::swap(&mut pa, &mut pb);
        }
        let mut x = mix64(ld64(p, a) ^ 0x9e3779b97f4a7c15);
        x = mix64(x ^ ld64(p, a + 8));
        x = mix64(x ^ ld64(p, b));
        h = mix64(x ^ ld64(p, b + 8));
    }
    mix64(h ^ (((pa as u64) << 32) | ((pb as u64) << 16) | d.proto as u64))
}
