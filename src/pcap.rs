//! Parsing of a memory-mapped classic pcap file.

use crate::util::{errno, strerror};
use crate::NS_PER_SEC;
use std::ffi::CString;

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_RAW_OLD: u32 = 12; // DLT_RAW on some platforms

/// Maximum sane caplen of a single record: anything larger means the file is corrupt.
pub const PCAP_MAX_CAPLEN: u32 = 256 * 1024;
pub const PCAP_FILE_HDR_LEN: u64 = 24;
pub const PCAP_REC_HDR_LEN: u64 = 16;
/// Alignment of a preloaded file in memory (and of its external-memory registration).
pub const PRELOAD_ALIGN: usize = 2 << 20;

const MAGIC_US: u32 = 0xa1b2c3d4;
const MAGIC_NS: u32 = 0xa1b23c4d;
const MAGIC_PCAPNG: u32 = 0x0a0d0d0a;

pub struct PcapFile {
    pub fd: i32,
    pub base: *const u8,
    pub size: usize,
    pub swapped: bool,  // file byte order differs from ours
    pub nsec: bool,     // nanosecond timestamps
    pub linktype: u32,  // without FCS bits
    pub snaplen: u32,
    pub raw_ip: i32,    // 0 = Ethernet, 4/6 = fixed version, 1 = version from packet
    pub preloaded: bool,
    pub locked: bool,   // --preload: the file is locked in RAM (mlock)
    mapped: bool,
    map_base: *mut libc::c_void, // what to unmap: the mapping and its reserved alignment
    map_len: usize,
}

unsafe impl Send for PcapFile {}
unsafe impl Sync for PcapFile {}

/// A single pcap record.
#[derive(Default, Clone, Copy, Debug)]
pub struct PcapRec {
    pub data_off: u64, // offset of packet data from start of file
    pub caplen: u32,
    pub origlen: u32,
    pub ts_ns: i64,    // absolute time, ns
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecResult {
    Ok = 0,
    End = 1,       // clean end of file
    Truncated = 2, // file truncated mid-record
    Corrupt = 3,   // nonsensical record header
}

pub fn linktype_name(lt: u32) -> &'static str {
    match lt {
        LINKTYPE_ETHERNET => "Ethernet",
        LINKTYPE_RAW | LINKTYPE_RAW_OLD => "RAW IP",
        LINKTYPE_IPV4 => "RAW IPv4",
        LINKTYPE_IPV6 => "RAW IPv6",
        _ => "unknown",
    }
}

impl PcapFile {
    /// A pcap in a memory buffer (tests). The buffer must outlive the PcapFile.
    pub fn from_mem(buf: &[u8]) -> Result<PcapFile, String> {
        let mut pf = PcapFile::empty();
        pf.base = buf.as_ptr();
        pf.size = buf.len();
        pf.parse_header()?;
        Ok(pf)
    }

    fn empty() -> PcapFile {
        PcapFile {
            fd: -1,
            base: std::ptr::null(),
            size: 0,
            swapped: false,
            nsec: false,
            linktype: 0,
            snaplen: 0,
            raw_ip: 0,
            preloaded: false,
            locked: false,
            mapped: false,
            map_base: std::ptr::null_mut(),
            map_len: 0,
        }
    }

    /// Open and mmap the file.
    pub fn open(path: &str, preload: bool) -> Result<PcapFile, String> {
        let mut pf = PcapFile::empty();
        let cpath = CString::new(path).map_err(|_| format!("cannot open {}: bad path", path))?;
        pf.fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if pf.fd < 0 {
            return Err(format!("cannot open {}: {}", path, strerror(errno())));
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(pf.fd, &mut st) } < 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(format!("{}: not a regular file", path));
        }
        pf.size = st.st_size as usize;
        if pf.size == 0 {
            return Err(format!("{}: empty file", path));
        }
        let flags = libc::MAP_PRIVATE | if preload { libc::MAP_POPULATE } else { 0 };
        let p = if preload {
            // A preloaded file may be handed to the NIC as external memory (zero-copy), which
            // is registered in units of PRELOAD_ALIGN: map it at such an address, inside a
            // reserved range that covers the rounded-up length.
            let span = pf.size.div_ceil(PRELOAD_ALIGN) * PRELOAD_ALIGN;
            let res = unsafe {
                libc::mmap(std::ptr::null_mut(), span + PRELOAD_ALIGN, libc::PROT_NONE,
                           libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE, -1, 0)
            };
            if res == libc::MAP_FAILED {
                return Err(format!("mmap {}: {}", path, strerror(errno())));
            }
            let aligned = (res as usize).div_ceil(PRELOAD_ALIGN) * PRELOAD_ALIGN;
            let p = unsafe {
                libc::mmap(aligned as *mut libc::c_void, pf.size, libc::PROT_READ, flags | libc::MAP_FIXED, pf.fd, 0)
            };
            if p == libc::MAP_FAILED {
                let e = errno();
                unsafe { libc::munmap(res, span + PRELOAD_ALIGN) };
                return Err(format!("mmap {}: {}", path, strerror(e)));
            }
            // Give back the reserved head before the aligned start and the tail after the span.
            unsafe {
                if aligned > res as usize {
                    libc::munmap(res, aligned - res as usize);
                }
                let end = res as usize + span + PRELOAD_ALIGN;
                if end > aligned + span {
                    libc::munmap((aligned + span) as *mut libc::c_void, end - aligned - span);
                }
            }
            pf.map_base = aligned as *mut libc::c_void;
            pf.map_len = span;
            p
        } else {
            let p = unsafe { libc::mmap(std::ptr::null_mut(), pf.size, libc::PROT_READ, flags, pf.fd, 0) };
            if p == libc::MAP_FAILED {
                return Err(format!("mmap {}: {}", path, strerror(errno())));
            }
            pf.map_base = p;
            pf.map_len = pf.size;
            p
        };
        pf.base = p as *const u8;
        pf.mapped = true;
        pf.preloaded = preload;
        // --preload: keep the whole file in RAM for the run, so that the page cache never
        // evicts parts of it under memory pressure (other programs reading big files).
        if preload {
            pf.locked = unsafe { libc::mlock(p, pf.size) } == 0;
        }
        // Indexing reads the file sequentially.
        unsafe {
            libc::madvise(p, pf.size, if preload { libc::MADV_WILLNEED } else { libc::MADV_SEQUENTIAL })
        };
        pf.parse_header()?;
        Ok(pf)
    }

    /// The preloaded mapping: aligned start and length rounded up to PRELOAD_ALIGN.
    pub fn preload_span(&self) -> Option<(*mut u8, usize)> {
        (self.preloaded && self.mapped).then_some((self.map_base as *mut u8, self.map_len))
    }

    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base, self.size) }
    }

    #[inline(always)]
    fn u32_at(&self, off: usize) -> u32 {
        let v = u32::from_ne_bytes(unsafe { *(self.base.add(off) as *const [u8; 4]) });
        if self.swapped {
            v.swap_bytes()
        } else {
            v
        }
    }

    /// Parse the header of an already mapped buffer.
    pub fn parse_header(&mut self) -> Result<(), String> {
        if self.size < 4 {
            return Err(format!("file too short for pcap ({} bytes)", self.size));
        }
        let mut magic = u32::from_ne_bytes(unsafe { *(self.base as *const [u8; 4]) });
        if magic == MAGIC_PCAPNG {
            return Err("this is pcapng, only classic pcap is supported. \
                        Convert it: editcap -F pcap in.pcapng out.pcap \
                        (for nanosecond timestamps: editcap -F nsecpcap ...)"
                .into());
        }
        if magic == MAGIC_US || magic == MAGIC_NS {
            self.swapped = false;
        } else if magic == MAGIC_US.swap_bytes() || magic == MAGIC_NS.swap_bytes() {
            self.swapped = true;
            magic = magic.swap_bytes();
        } else {
            return Err(format!("unknown file magic 0x{:08x}: not a pcap", magic));
        }
        self.nsec = magic == MAGIC_NS;
        if (self.size as u64) < PCAP_FILE_HDR_LEN {
            return Err("file truncated: incomplete pcap header".into());
        }
        self.snaplen = self.u32_at(16);
        // The upper bits of the linktype field may carry the FCS length.
        self.linktype = self.u32_at(20) & 0x0FFF_FFFF;
        self.raw_ip = match self.linktype {
            LINKTYPE_ETHERNET => 0,
            LINKTYPE_RAW | LINKTYPE_RAW_OLD => 1,
            LINKTYPE_IPV4 => 4,
            LINKTYPE_IPV6 => 6,
            lt => {
                return Err(format!(
                    "linktype {} is not supported (need Ethernet=1 or RAW IP=101/228/229)",
                    lt
                ))
            }
        };
        Ok(())
    }

    /// Read the record at offset *off; on success advances *off to the next one.
    #[inline(always)]
    pub fn next(&self, off: &mut u64, r: &mut PcapRec) -> RecResult {
        let o = *off;
        let size = self.size as u64;
        if o == size {
            return RecResult::End;
        }
        if o + PCAP_REC_HDR_LEN > size {
            return RecResult::Truncated;
        }
        let h = o as usize;
        let sec = self.u32_at(h);
        let frac = self.u32_at(h + 4);
        r.caplen = self.u32_at(h + 8);
        r.origlen = self.u32_at(h + 12);
        if r.caplen > PCAP_MAX_CAPLEN {
            return RecResult::Corrupt;
        }
        if o + PCAP_REC_HDR_LEN + r.caplen as u64 > size {
            return RecResult::Truncated;
        }
        r.data_off = o + PCAP_REC_HDR_LEN;
        r.ts_ns = sec as i64 * NS_PER_SEC + if self.nsec { frac as i64 } else { frac as i64 * 1000 };
        *off = r.data_off + r.caplen as u64;
        RecResult::Ok
    }
}

impl Drop for PcapFile {
    fn drop(&mut self) {
        if self.mapped && !self.map_base.is_null() {
            unsafe { libc::munmap(self.map_base, self.map_len) };
        }
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// pcap writer for tests.
    pub struct WBuf {
        pub buf: Vec<u8>,
        pub be: bool,
    }

    impl WBuf {
        pub fn put32(&mut self, v: u32) {
            let b = if self.be { v.to_be_bytes() } else { v.to_le_bytes() };
            self.buf.extend_from_slice(&b);
        }
        pub fn put16(&mut self, v: u16) {
            let b = if self.be { v.to_be_bytes() } else { v.to_le_bytes() };
            self.buf.extend_from_slice(&b);
        }
        pub fn file_hdr(nsec: bool, be: bool, linktype: u32) -> WBuf {
            let mut w = WBuf { buf: Vec::new(), be };
            w.put32(if nsec { 0xa1b23c4d } else { 0xa1b2c3d4 });
            w.put16(2);
            w.put16(4);
            w.put32(0);
            w.put32(0);
            w.put32(65535);
            w.put32(linktype);
            w
        }
        pub fn rec(&mut self, sec: u32, frac: u32, caplen: u32, origlen: u32) {
            self.put32(sec);
            self.put32(frac);
            self.put32(caplen);
            self.put32(origlen);
            for i in 0..caplen {
                self.buf.push(if i < 12 {
                    0x02
                } else if i == 12 {
                    0x88
                } else if i == 13 {
                    0xb5
                } else {
                    i as u8
                });
            }
        }
    }

    #[test]
    fn formats() {
        for nsec in [false, true] {
            for be in [false, true] {
                let mut w = WBuf::file_hdr(nsec, be, 1);
                w.rec(1700000000, if nsec { 123456789 } else { 123456 }, 60, 60);
                w.rec(1700000001, 5, 100, 1500);
                let pf = PcapFile::from_mem(&w.buf).unwrap();
                assert_eq!(pf.nsec, nsec);
                assert_eq!(pf.swapped, be != cfg!(target_endian = "big"));
                assert_eq!(pf.linktype, 1);
                let mut off = PCAP_FILE_HDR_LEN;
                let mut r = PcapRec::default();
                assert_eq!(pf.next(&mut off, &mut r), RecResult::Ok);
                assert_eq!(r.caplen, 60);
                assert_eq!(r.ts_ns, 1700000000 * NS_PER_SEC + if nsec { 123456789 } else { 123456000 });
                assert_eq!(r.data_off, PCAP_FILE_HDR_LEN + PCAP_REC_HDR_LEN);
                assert_eq!(pf.next(&mut off, &mut r), RecResult::Ok);
                assert_eq!(r.caplen, 100);
                assert_eq!(r.origlen, 1500);
                assert_eq!(r.ts_ns, 1700000001 * NS_PER_SEC + if nsec { 5 } else { 5000 });
                assert_eq!(pf.next(&mut off, &mut r), RecResult::End);
            }
        }
    }

    #[test]
    fn truncated() {
        let mut w = WBuf::file_hdr(false, false, 1);
        w.rec(1, 0, 60, 60);
        w.rec(2, 0, 60, 60);
        let full = w.buf.len();
        let mut r = PcapRec::default();

        // Data of the last record truncated
        let pf = PcapFile::from_mem(&w.buf[..full - 10]).unwrap();
        let mut off = PCAP_FILE_HDR_LEN;
        assert_eq!(pf.next(&mut off, &mut r), RecResult::Ok);
        assert_eq!(pf.next(&mut off, &mut r), RecResult::Truncated);

        // Record header truncated
        let pf = PcapFile::from_mem(&w.buf[..24 + 16 + 60 + 7]).unwrap();
        let mut off = PCAP_FILE_HDR_LEN;
        assert_eq!(pf.next(&mut off, &mut r), RecResult::Ok);
        assert_eq!(pf.next(&mut off, &mut r), RecResult::Truncated);

        // File header truncated
        assert!(PcapFile::from_mem(&w.buf[..10]).is_err());

        // Insane caplen
        let mut w = WBuf::file_hdr(false, false, 1);
        w.put32(1);
        w.put32(0);
        w.put32(0x7fffffff);
        w.put32(0x7fffffff);
        let pf = PcapFile::from_mem(&w.buf).unwrap();
        let mut off = PCAP_FILE_HDR_LEN;
        assert_eq!(pf.next(&mut off, &mut r), RecResult::Corrupt);
    }

    #[test]
    fn bad_headers() {
        // pcapng
        let mut w = WBuf { buf: Vec::new(), be: false };
        w.put32(0x0a0d0d0a);
        w.put32(28);
        w.put32(0x1a2b3c4d);
        for _ in 0..4 {
            w.put32(0);
        }
        let e = PcapFile::from_mem(&w.buf).err().unwrap();
        assert!(e.contains("editcap -F pcap"));
        // unknown magic
        let mut w = WBuf { buf: Vec::new(), be: false };
        w.put32(0xdeadbeef);
        for _ in 0..5 {
            w.put32(0);
        }
        assert!(PcapFile::from_mem(&w.buf).is_err());
        // unsupported linktype
        let w = WBuf::file_hdr(false, false, 105);
        assert!(PcapFile::from_mem(&w.buf).is_err());
        // RAW and FCS bits in linktype
        let w = WBuf::file_hdr(false, false, 101);
        assert_eq!(PcapFile::from_mem(&w.buf).unwrap().raw_ip, 1);
        let w = WBuf::file_hdr(false, false, 228);
        assert_eq!(PcapFile::from_mem(&w.buf).unwrap().raw_ip, 4);
        let w = WBuf::file_hdr(false, false, 0x10000001);
        assert_eq!(PcapFile::from_mem(&w.buf).unwrap().linktype, 1);
    }
}
