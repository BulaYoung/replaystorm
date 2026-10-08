//! Packet index construction: one sequential pass over the pcap records and parallel
//! classification/hashing in several threads.
//!
//! The index is built in two steps:
//!   1. build (or load from the index cache): per packet the offset+length, the
//!      timestamp, a 32-bit symmetric flow hash and classification flags. None of it
//!      depends on options, so it can be cached on disk.
//!   2. resolve: shard numbers for the current thread count and the MTU-dependent
//!      skip decision, plus the per-shard and per-skip-reason counters.

use crate::dissect::{dissect, flow_hash, Dis, ETHT_VLAN, ETH_HLEN, L2K_COUNT};
use crate::pcap::{PcapFile, PcapRec, RecResult, PCAP_FILE_HDR_LEN, PCAP_REC_HDR_LEN};
use crate::sched::l1_bytes;
use crate::{offlen_len, offlen_make, offlen_off, SyncPtr, SHARD_SKIP, SKIP_BAD_RAW, SKIP_REASONS, SKIP_TOO_BIG, SKIP_TOO_SMALL};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Per-packet classification flags (independent of MTU and thread count).
pub const PF_NONIP: u8 = 0x01; // not IP: goes to the non-IP shard
pub const PF_VLAN8100: u8 = 0x02; // outer ethertype is 802.1Q: the kernel allows 4 more bytes
pub const PF_SMALL: u8 = 0x04; // always skipped: shorter than an Ethernet header
pub const PF_BADRAW: u8 = 0x08; // always skipped: RAW IP without version 4/6
pub const PF_HUGE: u8 = 0x10; // always skipped: caplen above 64 KB

const HASH_CHUNK: usize = 65536;
const PUBLISH_EVERY: usize = 4096;

/// Index counters. The layout is part of the index cache format.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct IdxStats {
    // filled by build (cached)
    pub pkts: u64, // all records in the file
    pub bytes: u64, // by caplen
    pub truncated_caplen: u64, // caplen < origlen
    pub ipv4: u64,
    pub ipv6: u64,
    pub nonip: u64,
    pub vlan: u64,
    pub qinq: u64,
    pub mpls: u64,
    pub pppoe: u64,
    pub frag: u64,
    pub l2kind: [u64; L2K_COUNT],
    // filled by resolve (depend on MTU)
    pub skipped: [u64; SKIP_REASONS],
    pub skipped_bytes: u64,
    pub max_frame: u32, // largest frame that will be sent (with synthetic L2)
    pub l1_bytes: u64,  // sent frames counted on the wire: preamble, IFG, FCS, min 60
}

/// A per-packet array: anonymous mapping, heap (fallback), or a view into the cache map.
pub(crate) enum Arr<T> {
    Empty,
    Anon { ptr: *mut T, cap: usize },
    Heap(Vec<T>),
    View(*mut T),
}

unsafe impl<T> Send for Arr<T> {}
unsafe impl<T> Sync for Arr<T> {}

impl<T> Arr<T> {
    fn anon(cap: usize) -> Option<Arr<T>> {
        let bytes = (cap * std::mem::size_of::<T>()).max(1);
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), bytes, libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE, -1, 0)
        };
        if p == libc::MAP_FAILED {
            None
        } else {
            Some(Arr::Anon { ptr: p as *mut T, cap })
        }
    }

    pub fn ptr(&self) -> *mut T {
        match self {
            Arr::Empty => std::ptr::NonNull::dangling().as_ptr(),
            Arr::Anon { ptr, .. } => *ptr,
            Arr::Heap(v) => v.as_ptr() as *mut T,
            Arr::View(p) => *p,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Arr::Empty)
    }
}

impl<T> Drop for Arr<T> {
    fn drop(&mut self) {
        if let Arr::Anon { ptr, cap } = self {
            unsafe { libc::munmap(*ptr as *mut libc::c_void, (*cap * std::mem::size_of::<T>()).max(1)) };
        }
    }
}

/// A read-only or private mapping owned by the index (the index cache file).
pub(crate) struct Mapping {
    pub ptr: *mut u8,
    pub len: usize,
}

unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

pub struct PktIndex {
    pub n: usize,                     // number of records
    pub(crate) offlen: Arr<u64>,      // offset + length
    pub(crate) ts: Arr<i64>,          // absolute timestamps, then the schedule timeline
    pub(crate) h32: Arr<u32>,         // upper 32 bits of the symmetric flow hash (0 for non-IP)
    pub(crate) flags: Arr<u8>,        // PF_*
    pub(crate) shard: Vec<u16>,       // shard number or SHARD_SKIP (filled by resolve)
    pub(crate) cache_map: Option<Mapping>,
    pub nshards: usize,               // IP shards + 1 shard for non-IP
    pub shard_pkts: Vec<u64>,
    pub shard_bytes: Vec<u64>,
    pub st: IdxStats,
    pub tail_problem: Option<RecResult>, // Truncated / Corrupt
    pub tail_off: u64,                // where parsing stopped
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IdxCfg {
    pub ip_shards: usize,    // number of IP shards (= sender threads)
    pub max_frame: u32,      // MTU + 14
    pub hash_threads: usize, // threads for hashing and resolving
}

impl Default for PktIndex {
    fn default() -> Self {
        PktIndex {
            n: 0,
            offlen: Arr::Empty,
            ts: Arr::Empty,
            h32: Arr::Empty,
            flags: Arr::Empty,
            shard: Vec::new(),
            cache_map: None,
            nshards: 0,
            shard_pkts: Vec::new(),
            shard_bytes: Vec::new(),
            st: IdxStats::default(),
            tail_problem: None,
            tail_off: 0,
        }
    }
}

macro_rules! slice_of {
    ($s:expr, $f:ident) => {
        if $s.$f.is_empty() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts($s.$f.ptr(), $s.n) }
        }
    };
}

impl PktIndex {
    pub fn offlen(&self) -> &[u64] {
        slice_of!(self, offlen)
    }
    pub fn ts(&self) -> &[i64] {
        slice_of!(self, ts)
    }
    pub fn h32(&self) -> &[u32] {
        slice_of!(self, h32)
    }
    pub fn flags(&self) -> &[u8] {
        slice_of!(self, flags)
    }
    pub fn shard(&self) -> &[u16] {
        &self.shard
    }
    pub fn ts_mut(&mut self) -> &mut [i64] {
        if self.ts.is_empty() {
            return &mut [];
        }
        unsafe { std::slice::from_raw_parts_mut(self.ts.ptr(), self.n) }
    }
    /// Timestamps (mutable), offsets and shard numbers at the same time.
    pub fn parts_mut(&mut self) -> (&mut [i64], &[u64], &[u16]) {
        let ts = if self.ts.is_empty() { &mut [][..] } else { unsafe { std::slice::from_raw_parts_mut(self.ts.ptr(), self.n) } };
        let ol = if self.offlen.is_empty() { &[][..] } else { unsafe { std::slice::from_raw_parts(self.offlen.ptr(), self.n) } };
        (ts, ol, &self.shard)
    }
    pub fn have_arrays(&self) -> bool {
        !self.offlen.is_empty()
    }

    /// Free the per-packet arrays. Counters are kept.
    pub fn free_arrays(&mut self) {
        self.offlen = Arr::Empty;
        self.ts = Arr::Empty;
        self.h32 = Arr::Empty;
        self.flags = Arr::Empty;
        self.shard = Vec::new();
        self.cache_map = None;
    }
}

/// Classify a frame independently of options: PF_* flags, the flow hash and the dissection.
pub fn classify_frame(p: &[u8], raw_ip: i32) -> (u8, u32, Dis) {
    let caplen = p.len() as u32;
    let flen = caplen + if raw_ip != 0 { ETH_HLEN } else { 0 };
    let mut f = 0;
    let d = dissect(p, raw_ip);
    let mut h32 = 0;
    if (raw_ip != 0 && caplen == 0) || flen < ETH_HLEN {
        f |= PF_SMALL;
    } else if raw_ip != 0 && d.l3 == 0 {
        f |= PF_BADRAW;
    }
    if caplen >= 0xFFFF {
        f |= PF_HUGE; // the index stores at most 0xFFFF; anything that long is too big
    }
    if raw_ip == 0 && d.outer_ethertype == ETHT_VLAN {
        f |= PF_VLAN8100;
    }
    if d.l3 == 0 {
        f |= PF_NONIP;
    } else {
        h32 = (flow_hash(&d, p) >> 32) as u32;
    }
    (f, h32, d)
}

/// Shard number for a classified frame, or Err(skip reason).
#[inline(always)]
pub fn resolve_shard(flen: u32, h32: u32, flags: u8, cfg: &IdxCfg) -> Result<u16, usize> {
    if flags & PF_SMALL != 0 {
        return Err(SKIP_TOO_SMALL);
    }
    if flags & PF_BADRAW != 0 {
        return Err(SKIP_BAD_RAW);
    }
    // Same check as the kernel: beyond MTU+14 only an 802.1Q tag is allowed.
    let limit = cfg.max_frame + if flags & PF_VLAN8100 != 0 { 4 } else { 0 };
    if flags & PF_HUGE != 0 || flen > limit || flen > 0xFFFF {
        return Err(SKIP_TOO_BIG);
    }
    if flags & PF_NONIP != 0 {
        return Ok(cfg.ip_shards as u16); // separate shard for non-IP
    }
    Ok(((h32 as u64 * cfg.ip_shards as u64) >> 32) as u16)
}

/// Both steps for one frame (used by tests): shard number (SHARD_SKIP with the reason).
pub fn classify(p: &[u8], raw_ip: i32, cfg: &IdxCfg) -> (u16, usize, Dis) {
    let (f, h32, d) = classify_frame(p, raw_ip);
    match resolve_shard(p.len() as u32 + if raw_ip != 0 { ETH_HLEN } else { 0 }, h32, f, cfg) {
        Ok(s) => (s, 0, d),
        Err(r) => (SHARD_SKIP, r, d),
    }
}

/* ---------- Step 1: build ---------- */

fn hash_range(pf: &PcapFile, ol: *const u64, h32: SyncPtr<u32>, flags: SyncPtr<u8>, a: usize, b: usize, st: &mut IdxStats) {
    let raw = pf.raw_ip;
    let data = pf.data();
    for i in a..b {
        let v = unsafe { *ol.add(i) };
        let len = offlen_len(v) as usize;
        let off = offlen_off(v) as usize;
        let (f, h, d) = classify_frame(&data[off..off + len], raw);
        // Each index is written by one hasher only.
        unsafe {
            *flags.get(i) = f;
            *h32.get(i) = h;
        }
        st.bytes += len as u64 + if raw != 0 { ETH_HLEN as u64 } else { 0 };
        st.l2kind[d.l2kind as usize] += 1;
        match d.l3 {
            4 => st.ipv4 += 1,
            6 => st.ipv6 += 1,
            _ => st.nonip += 1,
        }
        if d.vlan_depth > 0 {
            st.vlan += 1;
        }
        if d.vlan_depth >= 2 {
            st.qinq += 1;
        }
        if d.mpls {
            st.mpls += 1;
        }
        if d.pppoe {
            st.pppoe += 1;
        }
        if d.frag {
            st.frag += 1;
        }
    }
}

struct BuildShared {
    scanned: AtomicUsize,
    done: AtomicBool,
    next_chunk: AtomicUsize,
}

fn hasher_main(pf: &PcapFile, sh: &BuildShared, ol: SyncPtr<u64>, h32: SyncPtr<u32>, flags: SyncPtr<u8>) -> IdxStats {
    let mut st = IdxStats::default();
    loop {
        let chunk = sh.next_chunk.fetch_add(1, Ordering::SeqCst);
        let a = chunk * HASH_CHUNK;
        let mut b = a + HASH_CHUNK;
        let avail;
        loop {
            let done = sh.done.load(Ordering::Acquire);
            let s = sh.scanned.load(Ordering::Acquire);
            if s >= b || done {
                avail = s;
                break;
            }
            crate::util::sleep_ns(100_000);
        }
        if a >= avail {
            return st;
        }
        b = b.min(avail);
        hash_range(pf, ol.0, h32, flags, a, b, &mut st);
    }
}

/// Step 1: build the option-independent part of the index from the pcap.
pub fn build(pf: &PcapFile, cfg: &IdxCfg) -> Result<PktIndex, String> {
    let mut ix = PktIndex::default();
    // Upper bound on the record count: each takes at least 16 bytes.
    let cap = (pf.size.saturating_sub(PCAP_FILE_HDR_LEN as usize)) / PCAP_REC_HDR_LEN as usize + 1;
    let anon = match (Arr::anon(cap), Arr::anon(cap), Arr::anon(cap), Arr::anon(cap)) {
        (Some(a), Some(b), Some(c), Some(d)) => Some((a, b, c, d)),
        _ => None,
    };
    // Fallback: growing arrays, hashing after the pass.
    let mut heap_ol: Vec<u64> = Vec::new();
    let mut heap_ts: Vec<i64> = Vec::new();
    let heap = anon.is_none();
    if let Some((a, b, c, d)) = anon {
        ix.offlen = a;
        ix.ts = b;
        ix.h32 = c;
        ix.flags = d;
    }

    let shared = BuildShared { scanned: AtomicUsize::new(0), done: AtomicBool::new(false), next_chunk: AtomicUsize::new(0) };
    let nh = cfg.hash_threads.max(1);
    let mut stats: Vec<IdxStats> = Vec::new();
    let mut n = 0usize;
    let mut oom = false;
    let mut stopped = false;
    let mut rc = RecResult::Ok;
    let mut off = PCAP_FILE_HDR_LEN;

    std::thread::scope(|s| {
        let mut handles = Vec::new();
        let start = |ix: &PktIndex, handles: &mut Vec<_>| {
            let (ol, h, f) = (SyncPtr(ix.offlen.ptr()), SyncPtr(ix.h32.ptr()), SyncPtr(ix.flags.ptr()));
            for _ in 0..nh {
                let sh = &shared;
                match std::thread::Builder::new().spawn_scoped(s, move || hasher_main(pf, sh, ol, h, f)) {
                    Ok(hd) => handles.push(hd),
                    Err(_) => break,
                }
            }
        };
        if !heap {
            start(&ix, &mut handles);
        }

        // Sequential pass: the pcap record chain cannot be walked any other way.
        let olp = ix.offlen.ptr();
        let tsp = ix.ts.ptr();
        let mut r = PcapRec::default();
        loop {
            rc = pf.next(&mut off, &mut r);
            if rc != RecResult::Ok {
                break;
            }
            // A frame longer than 64 KB will be skipped as oversized anyway.
            let len = r.caplen.min(0xFFFF);
            let v = offlen_make(r.data_off, len);
            if heap {
                if heap_ol.try_reserve(1).is_err() || heap_ts.try_reserve(1).is_err() {
                    oom = true;
                    break;
                }
                heap_ol.push(v);
                heap_ts.push(r.ts_ns);
            } else {
                if n == cap {
                    oom = true;
                    break;
                }
                // The hashers only read entries below the published count.
                unsafe {
                    *olp.add(n) = v;
                    *tsp.add(n) = r.ts_ns;
                }
            }
            if r.caplen < r.origlen {
                ix.st.truncated_caplen += 1;
            }
            n += 1;
            if n & (PUBLISH_EVERY - 1) == 0 {
                shared.scanned.store(n, Ordering::Release);
                if crate::stop_requested() {
                    stopped = true;
                    break;
                }
            }
        }
        shared.scanned.store(n, Ordering::Release);
        shared.done.store(true, Ordering::Release);

        if heap && !oom && !stopped {
            ix.offlen = Arr::Heap(std::mem::take(&mut heap_ol));
            ix.ts = Arr::Heap(std::mem::take(&mut heap_ts));
            ix.h32 = Arr::Heap(vec![0u32; n]);
            ix.flags = Arr::Heap(vec![0u8; n]);
            start(&ix, &mut handles);
        }
        if handles.is_empty() && !oom && !stopped && n > 0 {
            // Threads failed to start; hash in this thread.
            shared.next_chunk.store(0, Ordering::SeqCst);
            stats.push(hasher_main(pf, &shared, SyncPtr(ix.offlen.ptr()), SyncPtr(ix.h32.ptr()), SyncPtr(ix.flags.ptr())));
        }
        for h in handles {
            stats.push(h.join().unwrap_or_default());
        }
    });
    if !stopped && rc != RecResult::Ok && rc != RecResult::End {
        ix.tail_problem = Some(rc);
        ix.tail_off = off;
    }
    ix.n = n;
    for s in &stats {
        ix.st.bytes += s.bytes;
        for k in 0..L2K_COUNT {
            ix.st.l2kind[k] += s.l2kind[k];
        }
        ix.st.ipv4 += s.ipv4;
        ix.st.ipv6 += s.ipv6;
        ix.st.nonip += s.nonip;
        ix.st.vlan += s.vlan;
        ix.st.qinq += s.qinq;
        ix.st.mpls += s.mpls;
        ix.st.pppoe += s.pppoe;
        ix.st.frag += s.frag;
    }
    ix.st.pkts = n as u64;
    if oom {
        return Err(format!("out of memory for the index ({} packets)", n));
    }
    if stopped {
        return Err("stopped while building the index".into());
    }
    Ok(ix)
}

/* ---------- Step 2: resolve ---------- */

#[derive(Default)]
struct ResolveOut {
    skipped: [u64; SKIP_REASONS],
    skipped_bytes: u64,
    l1_bytes: u64,
    max_frame: u32,
    shard_pkts: Vec<u64>,
    shard_bytes: Vec<u64>,
}

fn resolve_range(ix: &PktIndex, shard: SyncPtr<u16>, raw_ip: i32, cfg: &IdxCfg, a: usize, b: usize, nshards: usize) -> ResolveOut {
    let mut r = ResolveOut { shard_pkts: vec![0; nshards], shard_bytes: vec![0; nshards], ..Default::default() };
    let extra = if raw_ip != 0 { ETH_HLEN } else { 0 };
    let (ol, h32, flags) = (ix.offlen(), ix.h32(), ix.flags());
    for i in a..b {
        let flen = offlen_len(ol[i]) + extra;
        let sh = match resolve_shard(flen, h32[i], flags[i], cfg) {
            Ok(s) => {
                r.shard_pkts[s as usize] += 1;
                r.shard_bytes[s as usize] += flen as u64;
                r.l1_bytes += l1_bytes(flen);
                r.max_frame = r.max_frame.max(flen);
                s
            }
            Err(reason) => {
                r.skipped[reason] += 1;
                r.skipped_bytes += flen as u64;
                SHARD_SKIP
            }
        };
        // Each range is written by one thread only.
        unsafe { *shard.get(i) = sh };
    }
    r
}

/// Step 2: shard numbers and MTU-dependent counters for the given configuration.
pub fn resolve(ix: &mut PktIndex, raw_ip: i32, cfg: &IdxCfg) {
    ix.nshards = cfg.ip_shards + 1;
    ix.shard_pkts = vec![0; ix.nshards];
    ix.shard_bytes = vec![0; ix.nshards];
    if ix.shard.len() != ix.n {
        ix.shard = vec![0u16; ix.n];
    }
    let nt = cfg.hash_threads.max(1);
    ix.st.skipped = [0; SKIP_REASONS];
    ix.st.skipped_bytes = 0;
    ix.st.l1_bytes = 0;
    ix.st.max_frame = 0;
    let n = ix.n;
    let per = n.div_ceil(nt);
    let shp = SyncPtr(ix.shard.as_mut_ptr());
    let nshards = ix.nshards;
    let outs: Vec<ResolveOut> = {
        let ixr: &PktIndex = ix;
        std::thread::scope(|s| {
            let mut hs = Vec::new();
            let mut outs = Vec::new();
            for t in 0..nt {
                let a = (t * per).min(n);
                let b = (a + per).min(n);
                match std::thread::Builder::new().spawn_scoped(s, move || resolve_range(ixr, shp, raw_ip, cfg, a, b, nshards)) {
                    Ok(h) => hs.push(h),
                    Err(_) => outs.push(resolve_range(ixr, shp, raw_ip, cfg, a, b, nshards)),
                }
            }
            for h in hs {
                outs.push(h.join().unwrap());
            }
            outs
        })
    };
    for r in outs {
        for k in 0..SKIP_REASONS {
            ix.st.skipped[k] += r.skipped[k];
        }
        ix.st.skipped_bytes += r.skipped_bytes;
        ix.st.l1_bytes += r.l1_bytes;
        ix.st.max_frame = ix.st.max_frame.max(r.max_frame);
        for k in 0..nshards {
            ix.shard_pkts[k] += r.shard_pkts[k];
            ix.shard_bytes[k] += r.shard_bytes[k];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::tests::WBuf;
    use crate::NS_PER_SEC;

    #[test]
    fn index_build() {
        let mut w = WBuf::file_hdr(false, false, 1);
        w.rec(1700000000, 0, 60, 60);
        w.rec(1700000000, 10, 2000, 2000); // larger than MTU
        w.rec(1700000000, 20, 10, 10); // shorter than Ethernet
        w.rec(1700000000, 30, 64, 9000); // truncated at capture
        let pf = PcapFile::from_mem(&w.buf).unwrap();
        let cfg = IdxCfg { ip_shards: 4, max_frame: 1514, hash_threads: 2 };
        let mut ix = build(&pf, &cfg).unwrap();
        resolve(&mut ix, pf.raw_ip, &cfg);
        assert_eq!(ix.n, 4);
        assert_eq!(ix.st.skipped[SKIP_TOO_BIG], 1);
        assert_eq!(ix.st.skipped[SKIP_TOO_SMALL], 1);
        assert_eq!(ix.st.truncated_caplen, 1);
        assert_eq!(ix.shard()[0], 4); // non-IP shard
        assert_eq!(ix.shard()[1], SHARD_SKIP);
        assert_eq!(ix.shard()[2], SHARD_SKIP);
        assert_eq!(offlen_len(ix.offlen()[3]), 64);
        assert_eq!(ix.ts()[1], 1700000000 * NS_PER_SEC + 10000);
        // The same index resolves for another MTU without rebuilding.
        let jumbo = IdxCfg { ip_shards: 4, max_frame: 9014, hash_threads: 2 };
        resolve(&mut ix, pf.raw_ip, &jumbo);
        assert_eq!(ix.st.skipped[SKIP_TOO_BIG], 0);
        assert_ne!(ix.shard()[1], SHARD_SKIP);
        assert_eq!(ix.st.max_frame, 2000);
    }

    /* Frame builder for the hashing tests. */
    struct Fr(Vec<u8>);
    impl Fr {
        fn eth(et: u16) -> Fr {
            let mut f = Fr((0..12).collect());
            f.p16(et);
            f
        }
        fn p8(&mut self, v: u8) {
            self.0.push(v);
        }
        fn p16(&mut self, v: u16) {
            self.0.extend_from_slice(&v.to_be_bytes());
        }
        fn p32(&mut self, v: u32) {
            self.0.extend_from_slice(&v.to_be_bytes());
        }
        fn ip4(&mut self, s: u32, d: u32, proto: u8, fragoff: u16) {
            self.p8(0x45);
            self.p8(0);
            self.p16(40);
            self.p16(1);
            self.p16(fragoff);
            self.p8(64);
            self.p8(proto);
            self.p16(0);
            self.p32(s);
            self.p32(d);
        }
        fn ports(&mut self, s: u16, d: u16) {
            self.p16(s);
            self.p16(d);
            for _ in 0..4 {
                self.p32(0);
            }
        }
        fn ip6(&mut self, s: u8, d: u8, nh: u8) {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            self.p32(0x60000000);
            self.p16(20);
            self.p8(nh);
            self.p8(64);
            a[15] = s;
            self.0.extend_from_slice(&a);
            a[15] = d;
            self.0.extend_from_slice(&a);
        }
    }

    fn b_v4(rev: bool) -> Fr {
        let mut f = Fr::eth(0x0800);
        f.ip4(if rev { 0x0a000002 } else { 0x0a000001 }, if rev { 0x0a000001 } else { 0x0a000002 }, 6, 0);
        f.ports(if rev { 443 } else { 51000 }, if rev { 51000 } else { 443 });
        f
    }
    fn b_vlan(rev: bool) -> Fr {
        // VLAN ID differs between directions; it is not part of the hash
        let mut f = Fr::eth(0x8100);
        f.p16(if rev { 20 } else { 10 });
        f.p16(0x0800);
        f.ip4(if rev { 0xc0a80002 } else { 0xc0a80001 }, if rev { 0xc0a80001 } else { 0xc0a80002 }, 17, 0);
        f.ports(if rev { 53 } else { 3333 }, if rev { 3333 } else { 53 });
        f
    }
    fn b_qinq(rev: bool) -> Fr {
        let mut f = Fr::eth(0x88a8);
        f.p16(100);
        f.p16(0x8100);
        f.p16(200);
        f.p16(0x0800);
        f.ip4(if rev { 0x01020304 } else { 0x05060708 }, if rev { 0x05060708 } else { 0x01020304 }, 6, 0);
        f.ports(if rev { 80 } else { 1234 }, if rev { 1234 } else { 80 });
        f
    }
    fn b_mpls(rev: bool) -> Fr {
        let mut f = Fr::eth(0x8847);
        f.p32((16 << 12) | 64);
        f.p32((17 << 12) | (1 << 8) | 64);
        f.ip4(if rev { 0x0b000002 } else { 0x0b000001 }, if rev { 0x0b000001 } else { 0x0b000002 }, 17, 0);
        f.ports(if rev { 9 } else { 10 }, if rev { 10 } else { 9 });
        f
    }
    fn b_v6(rev: bool) -> Fr {
        let mut f = Fr::eth(0x86dd);
        f.ip6(if rev { 2 } else { 1 }, if rev { 1 } else { 2 }, 6);
        f.ports(if rev { 80 } else { 50000 }, if rev { 50000 } else { 80 });
        f
    }
    fn b_v6ext(rev: bool) -> Fr {
        let mut f = Fr::eth(0x86dd);
        f.ip6(if rev { 2 } else { 1 }, if rev { 1 } else { 2 }, 0);
        f.p8(17); // hop-by-hop, 8 bytes
        f.p8(0);
        f.p16(0);
        f.p32(0);
        f.ports(if rev { 53 } else { 4000 }, if rev { 4000 } else { 53 });
        f
    }
    fn b_pppoe(rev: bool) -> Fr {
        let mut f = Fr::eth(0x8864);
        f.p8(0x11);
        f.p8(0);
        f.p16(1);
        f.p16(42);
        f.p16(0x0021);
        f.ip4(if rev { 0x08080808 } else { 0x64400001 }, if rev { 0x64400001 } else { 0x08080808 }, 17, 0);
        f.ports(if rev { 53 } else { 33333 }, if rev { 33333 } else { 53 });
        f
    }

    #[test]
    fn symmetric_hash() {
        let cases: [(fn(bool) -> Fr, &str, u8); 7] = [
            (b_v4, "IPv4", 4),
            (b_vlan, "VLAN", 4),
            (b_qinq, "QinQ", 4),
            (b_mpls, "MPLS", 4),
            (b_v6, "IPv6", 6),
            (b_v6ext, "IPv6 ext", 6),
            (b_pppoe, "PPPoE", 4),
        ];
        for (fn_, name, l3) in cases {
            let (a, b) = (fn_(false), fn_(true));
            let da = dissect(&a.0, 0);
            let db = dissect(&b.0, 0);
            assert_eq!(da.l3, l3, "{}", name);
            assert_eq!(db.l3, l3, "{}", name);
            assert!(da.sport != 0 && da.dport != 0, "{}", name);
            assert_eq!(flow_hash(&da, &a.0), flow_hash(&db, &b.0), "asymmetric hash: {}", name);
            let cfg = IdxCfg { ip_shards: 7, max_frame: 1514, hash_threads: 0 };
            assert_eq!(classify(&a.0, 0, &cfg).0, classify(&b.0, 0, &cfg).0, "{}", name);
        }
    }

    #[test]
    fn fragments() {
        // Fragments of one datagram: ports are ignored, same shard.
        let mut f1 = Fr::eth(0x0800);
        f1.ip4(0x0a000001, 0x0a000002, 17, 0x2000); // MF, offset 0
        f1.ports(1111, 2222);
        let mut f2 = Fr::eth(0x0800);
        f2.ip4(0x0a000001, 0x0a000002, 17, 0x2000 | 125);
        f2.p32(0xdeadbeef);
        f2.p32(0x12345678);
        let mut f3 = Fr::eth(0x0800);
        f3.ip4(0x0a000002, 0x0a000001, 17, 250); // last fragment, reverse direction
        f3.p32(0xcafebabe);
        f3.p32(0);
        let (d1, d2, d3) = (dissect(&f1.0, 0), dissect(&f2.0, 0), dissect(&f3.0, 0));
        assert!(d1.frag && d2.frag && d3.frag);
        assert!(d1.frag_first && !d2.frag_first && !d3.frag_first);
        assert_eq!(d1.sport, 0);
        assert_eq!(d1.l4_off, 34); // the first fragment has L4 (for checksums)
        assert_eq!(d2.l4_off, 0);
        assert_eq!(flow_hash(&d1, &f1.0), flow_hash(&d2, &f2.0));
        assert_eq!(flow_hash(&d1, &f1.0), flow_hash(&d3, &f3.0));

        // IPv6 fragments
        let mut g1 = Fr::eth(0x86dd);
        g1.ip6(1, 2, 44);
        g1.p8(17);
        g1.p8(0);
        g1.p16(1);
        g1.p32(7); // offset 0, M
        g1.ports(5, 6);
        let mut g2 = Fr::eth(0x86dd);
        g2.ip6(2, 1, 44);
        g2.p8(17);
        g2.p8(0);
        g2.p16(100 << 3);
        g2.p32(7);
        g2.p32(0);
        let (e1, e2) = (dissect(&g1.0, 0), dissect(&g2.0, 0));
        assert!(e1.frag && e2.frag);
        assert_eq!(e1.proto, 17);
        assert_eq!(e2.proto, 17);
        assert_eq!(flow_hash(&e1, &g1.0), flow_hash(&e2, &g2.0));
    }

    #[test]
    fn non_ip() {
        use crate::dissect::{L2K_ARP, L2K_LLC, L2K_LLDP};
        let cfg = IdxCfg { ip_shards: 5, max_frame: 1514, hash_threads: 0 };
        let mut f = Fr::eth(0x0806);
        f.0.extend_from_slice(&[0; 28]);
        let (s, _, d) = classify(&f.0, 0, &cfg);
        assert_eq!(s, 5);
        assert_eq!(d.l2kind, L2K_ARP);
        // STP: 802.3 + LLC
        let mut f = Fr::eth(38);
        f.0.extend_from_slice(&[0x42, 0x42, 3]);
        f.0.extend_from_slice(&[0; 35]);
        let (s, _, d) = classify(&f.0, 0, &cfg);
        assert_eq!(s, 5);
        assert_eq!(d.l2kind, L2K_LLC);
        // LLDP in VLAN
        let mut f = Fr::eth(0x8100);
        f.p16(5);
        f.p16(0x88cc);
        f.0.extend_from_slice(&[0; 30]);
        let (s, _, d) = classify(&f.0, 0, &cfg);
        assert_eq!(s, 5);
        assert_eq!(d.l2kind, L2K_LLDP);
        assert_eq!(d.vlan_depth, 1);
    }

    #[test]
    fn raw_ip() {
        let mut f = Fr(Vec::new());
        f.ip4(1, 2, 6, 0);
        f.ports(10, 20);
        let d = dissect(&f.0, 1);
        assert_eq!(d.l3, 4);
        assert_eq!(d.sport, 10);
        let mut f = Fr(Vec::new());
        f.ip6(1, 2, 17);
        f.ports(10, 20);
        let d = dissect(&f.0, 1);
        assert_eq!(d.l3, 6);
        assert_eq!(d.dport, 20);
        let cfg = IdxCfg { ip_shards: 3, max_frame: 1514, hash_threads: 0 };
        f.0[0] = 0x50; // not IP
        let (s, r, _) = classify(&f.0, 1, &cfg);
        assert_eq!(s, SHARD_SKIP);
        assert_eq!(r, SKIP_BAD_RAW);
    }

    #[test]
    fn distribution() {
        // Different flows spread across shards roughly evenly.
        let cfg = IdxCfg { ip_shards: 8, max_frame: 1514, hash_threads: 0 };
        let mut cnt = [0u32; 9];
        for i in 0..8000u32 {
            let mut f = Fr::eth(0x0800);
            f.ip4(0x0a000000 + i, 0xc0a80001, 6, 0);
            f.ports((1024 + i) as u16, 443);
            cnt[classify(&f.0, 0, &cfg).0 as usize] += 1;
        }
        for c in &cnt[..8] {
            assert!(*c > 800 && *c < 1200);
        }
        assert_eq!(cnt[8], 0);
    }

    #[test]
    fn mtu_limits() {
        let cfg = IdxCfg { ip_shards: 2, max_frame: 1514, hash_threads: 0 };
        let mut big = [0u8; 1600];
        big[12] = 0x08;
        big[14] = 0x45;
        assert_ne!(classify(&big[..1514], 0, &cfg).0, SHARD_SKIP);
        assert_eq!(classify(&big[..1515], 0, &cfg).0, SHARD_SKIP);
        big[12] = 0x81; // 802.1Q allows 4 more bytes
        big[13] = 0x00;
        big[16] = 0x08;
        big[17] = 0x00;
        big[18] = 0x45;
        assert_ne!(classify(&big[..1518], 0, &cfg).0, SHARD_SKIP);
        assert_eq!(classify(&big[..1519], 0, &cfg).0, SHARD_SKIP);
        big[12] = 0x88; // 802.1ad: the kernel makes no exception for it
        big[13] = 0xa8;
        assert_eq!(classify(&big[..1518], 0, &cfg).0, SHARD_SKIP);
    }
}
