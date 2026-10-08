//! On-disk cache of the option-independent part of the packet index (see index.rs).
//! Building the index of a 500 GB pcap means reading the whole file; with the cache a
//! restart only maps ~21 bytes per packet.
//!
//! The cache is valid only for the same pcap: same size, mtime, inode and a hash of its
//! first and last 64 KB, and the same cache format version. The format is the same as
//! the one of the C version of replaystorm.

use crate::index::{Arr, IdxStats, Mapping, PktIndex};
use crate::pcap::{PcapFile, RecResult};
use crate::util::{errno, strerror};
use crate::NS_PER_SEC;
use std::ffi::CString;

const IDXC_MAGIC: &[u8; 8] = b"AFRIDX\r\n";
/// Bump whenever the classification, hashing or the layout below changes.
const IDXC_VERSION: u32 = 1;
const IDXC_HDR_SIZE: u32 = 4096;
const IDXC_ALIGN: u64 = 4096;
const IDXC_SAMPLE: usize = 64 * 1024;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Hdr {
    magic: [u8; 8],
    version: u32,
    hdr_size: u32,
    stats_size: u32, // size of IdxStats, guards against layout changes
    linktype: u32,
    raw_ip: i32,
    tail_problem: i32,
    // identity of the pcap
    pcap_size: u64,
    pcap_ino: u64,
    pcap_dev: u64,
    pcap_mtime_ns: i64,
    pcap_sample: u64,
    // index
    n: u64,
    tail_off: u64,
    off_offlen: u64,
    off_ts: u64,
    off_h32: u64,
    off_flags: u64,
    file_size: u64,
    st: IdxStats,
}

const _: () = assert!(std::mem::size_of::<Hdr>() <= IDXC_HDR_SIZE as usize);

fn mix(mut h: u64, v: u64) -> u64 {
    h ^= v.wrapping_add(0x9e3779b97f4a7c15).wrapping_add(h << 6).wrapping_add(h >> 2);
    h ^= h >> 29;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^ (h >> 32)
}

/// Hash of the first and last 64 KB of the pcap: catches a file replaced in place.
fn pcap_sample(pf: &PcapFile) -> u64 {
    let d = pf.data();
    let mut h = pf.size as u64;
    let n = pf.size.min(IDXC_SAMPLE);
    let mut i = 0;
    while i + 8 <= n {
        h = mix(h, u64::from_ne_bytes(d[i..i + 8].try_into().unwrap()));
        i += 8;
    }
    let mut i = pf.size - n;
    while i + 8 <= pf.size {
        h = mix(h, u64::from_ne_bytes(d[i..i + 8].try_into().unwrap()));
        i += 8;
    }
    h
}

fn pcap_identity(pf: &PcapFile, h: &mut Hdr) -> Result<(), i32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(pf.fd, &mut st) } < 0 {
        return Err(errno());
    }
    h.pcap_size = st.st_size as u64;
    h.pcap_ino = st.st_ino;
    h.pcap_dev = st.st_dev;
    h.pcap_mtime_ns = st.st_mtime * NS_PER_SEC + st.st_mtime_nsec;
    h.pcap_sample = pcap_sample(pf);
    h.linktype = pf.linktype;
    h.raw_ip = pf.raw_ip;
    Ok(())
}

fn align_up(v: u64) -> u64 {
    v.div_ceil(IDXC_ALIGN) * IDXC_ALIGN
}

fn layout(h: &mut Hdr, n: u64) {
    h.off_offlen = IDXC_HDR_SIZE as u64;
    h.off_ts = align_up(h.off_offlen + n * 8);
    h.off_h32 = align_up(h.off_ts + n * 8);
    h.off_flags = align_up(h.off_h32 + n * 4);
    h.file_size = align_up(h.off_flags + n);
}

fn as_bytes<T>(p: *const T, n: usize) -> &'static [u8] {
    if n == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(p as *const u8, n * std::mem::size_of::<T>()) }
}

fn tail_code(t: Option<RecResult>) -> i32 {
    t.map_or(0, |r| r as i32)
}

/// Save the index built by index::build (before timestamps are normalized).
pub fn save(path: &str, pf: &PcapFile, ix: &PktIndex) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let mut h = Hdr {
        magic: *IDXC_MAGIC,
        version: IDXC_VERSION,
        hdr_size: IDXC_HDR_SIZE,
        stats_size: std::mem::size_of::<IdxStats>() as u32,
        tail_problem: tail_code(ix.tail_problem),
        tail_off: ix.tail_off,
        n: ix.n as u64,
        st: ix.st,
        ..Default::default()
    };
    pcap_identity(pf, &mut h).map_err(|e| format!("fstat of the pcap: {}", strerror(e)))?;
    layout(&mut h, ix.n as u64);

    let tmp = format!("{}.tmp{}", path, std::process::id());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|e| format!("cannot create {}: {}", tmp, e.kind_str()))?;
    let mut hdr = vec![0u8; IDXC_HDR_SIZE as usize];
    hdr[..std::mem::size_of::<Hdr>()].copy_from_slice(as_bytes(&h, 1));
    let n = ix.n;
    let res = (|| -> std::io::Result<()> {
        f.set_len(h.file_size)?;
        let mut write_at = |off: u64, b: &[u8]| -> std::io::Result<()> {
            f.seek(SeekFrom::Start(off))?;
            f.write_all(b)
        };
        write_at(0, &hdr)?;
        write_at(h.off_offlen, as_bytes(ix.offlen().as_ptr(), n))?;
        write_at(h.off_ts, as_bytes(ix.ts().as_ptr(), n))?;
        write_at(h.off_h32, as_bytes(ix.h32().as_ptr(), n))?;
        write_at(h.off_flags, as_bytes(ix.flags().as_ptr(), n))?;
        Ok(())
    })();
    drop(f);
    let res = res.and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("writing {}: {}", path, e.kind_str()));
    }
    Ok(())
}

trait KindStr {
    fn kind_str(&self) -> String;
}

impl KindStr for std::io::Error {
    fn kind_str(&self) -> String {
        match self.raw_os_error() {
            Some(e) => strerror(e),
            None => self.to_string(),
        }
    }
}

/// Load the index from the cache. Ok(Some) if loaded, Ok(None) with the reason if the
/// cache is missing or not valid for this pcap, Err on a hard error.
pub fn load(path: &str, pf: &PcapFile) -> Result<Result<PktIndex, String>, String> {
    let cpath = CString::new(path).map_err(|_| "bad path".to_string())?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = errno();
        return Ok(Err(if e == libc::ENOENT { "no cache file yet".into() } else { strerror(e) }));
    }
    struct Fd(i32);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
    let fd = Fd(fd);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut h = Hdr::default();
    let hs = std::mem::size_of::<Hdr>();
    if unsafe { libc::fstat(fd.0, &mut st) } < 0
        || unsafe { libc::pread(fd.0, &mut h as *mut Hdr as *mut libc::c_void, hs, 0) } != hs as isize
    {
        return Ok(Err("cannot read the cache header".into()));
    }
    if &h.magic != IDXC_MAGIC || h.hdr_size != IDXC_HDR_SIZE {
        return Ok(Err("not an replaystorm index cache".into()));
    }
    if h.version != IDXC_VERSION || h.stats_size != std::mem::size_of::<IdxStats>() as u32 {
        return Ok(Err("cache was written by another replaystorm version".into()));
    }
    let mut cur = Hdr::default();
    if pcap_identity(pf, &mut cur).is_err() {
        return Ok(Err("fstat of the pcap failed".into()));
    }
    if cur.pcap_size != h.pcap_size
        || cur.pcap_mtime_ns != h.pcap_mtime_ns
        || cur.pcap_ino != h.pcap_ino
        || cur.pcap_dev != h.pcap_dev
        || cur.pcap_sample != h.pcap_sample
        || cur.linktype != h.linktype
        || cur.raw_ip != h.raw_ip
    {
        return Ok(Err("cache belongs to another file or the pcap has changed".into()));
    }
    let mut chk = h;
    layout(&mut chk, h.n);
    if chk.off_ts != h.off_ts
        || chk.off_h32 != h.off_h32
        || chk.off_flags != h.off_flags
        || chk.file_size != h.file_size
        || st.st_size as u64 != h.file_size
    {
        return Ok(Err("cache file is truncated or damaged".into()));
    }
    // Private writable mapping: timestamps are normalized in place, which copies only
    // those pages; the cache file itself never changes.
    let len = h.file_size as usize;
    let map = unsafe {
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE, fd.0, 0)
    };
    if map == libc::MAP_FAILED {
        return Err(format!("mmap of the cache: {}", strerror(errno())));
    }
    unsafe { libc::madvise(map, len, libc::MADV_WILLNEED) };
    let base = map as *mut u8;
    let mut ix = PktIndex {
        n: h.n as usize,
        cache_map: Some(Mapping { ptr: base, len }),
        st: h.st,
        tail_problem: match h.tail_problem {
            2 => Some(RecResult::Truncated),
            3 => Some(RecResult::Corrupt),
            _ => None,
        },
        tail_off: h.tail_off,
        ..Default::default()
    };
    unsafe {
        ix.offlen = Arr::View(base.add(h.off_offlen as usize) as *mut u64);
        ix.ts = Arr::View(base.add(h.off_ts as usize) as *mut i64);
        ix.h32 = Arr::View(base.add(h.off_h32 as usize) as *mut u32);
        ix.flags = Arr::View(base.add(h.off_flags as usize));
    }
    Ok(Ok(ix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{build, resolve, IdxCfg};

    /// Write a pcap with many flows to a real file (the cache checks inode and mtime).
    fn write_flows_pcap(path: &str, npkts: u32, salt: u32) {
        let mut out = Vec::new();
        for v in [0xa1b2c3d4u32, 0x00040002, 0, 0, 65535, 1] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for i in 0..npkts {
            let mut fr = [0u8; 80];
            for k in 0..12 {
                fr[k] = k as u8 + 1;
            }
            fr[12] = 0x08; // IPv4
            fr[14] = 0x45;
            fr[23] = 17;
            let src = 0x0a000000u32 + i % 97 + salt;
            let dst = 0xc0a80001u32;
            fr[26..30].copy_from_slice(&src.to_be_bytes());
            fr[30..34].copy_from_slice(&dst.to_be_bytes());
            fr[34] = (i >> 8) as u8;
            fr[35] = i as u8;
            let len = if i % 5 == 0 { 60 } else { 80 };
            for v in [1700000000 + i / 1000, (i % 1000) * 1000, len, len] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.extend_from_slice(&fr[..len as usize]);
        }
        std::fs::write(path, out).unwrap();
    }

    #[test]
    fn index_cache() {
        let dir = std::env::temp_dir();
        let pcap = dir.join(format!("rs_test_{}.pcap", std::process::id())).to_string_lossy().into_owned();
        let cache = format!("{}.rsidx", pcap);
        let _ = std::fs::remove_file(&cache);
        write_flows_pcap(&pcap, 5000, 0);

        let pf = PcapFile::open(&pcap, false).unwrap();
        let cfg = IdxCfg { ip_shards: 3, max_frame: 1514, hash_threads: 2 };
        assert!(load(&cache, &pf).unwrap().is_err()); // no file yet
        let mut a = build(&pf, &cfg).unwrap();
        save(&cache, &pf, &a).unwrap();
        let mut b = load(&cache, &pf).unwrap().unwrap();
        assert_eq!(b.n, a.n);
        assert_eq!(a.offlen(), b.offlen());
        assert_eq!(a.ts(), b.ts());
        assert_eq!(a.h32(), b.h32());
        assert_eq!(a.flags(), b.flags());
        assert_eq!(b.st.ipv4, a.st.ipv4);
        // Resolving the cached index gives the same shards, also for another -t
        resolve(&mut a, 0, &cfg);
        resolve(&mut b, 0, &cfg);
        assert_eq!(a.shard(), b.shard());
        assert_eq!(a.shard_pkts, b.shard_pkts);
        let cfg7 = IdxCfg { ip_shards: 7, max_frame: 1514, hash_threads: 3 };
        resolve(&mut b, 0, &cfg7);
        assert_eq!(b.shard_pkts.iter().sum::<u64>(), 5000);
        // Writing to the cached timestamps does not change the cache file
        b.ts_mut()[0] = 12345;
        drop(b);
        let b = load(&cache, &pf).unwrap().unwrap();
        assert_eq!(b.ts()[0], a.ts()[0]);
        drop(b);
        drop(pf);

        // The pcap is rewritten with other content: the cache must be rejected
        write_flows_pcap(&pcap, 5000, 1000);
        let pf = PcapFile::open(&pcap, false).unwrap();
        let why = load(&cache, &pf).unwrap().err().unwrap();
        assert!(why.contains("changed"));
        drop(pf);
        // A damaged cache file is rejected
        std::fs::OpenOptions::new().write(true).open(&cache).unwrap().set_len(4096 + 100).unwrap();
        let pf = PcapFile::open(&pcap, false).unwrap();
        assert!(load(&cache, &pf).unwrap().is_err());
        let _ = std::fs::remove_file(&cache);
        let _ = std::fs::remove_file(&pcap);
    }
}
