//! Streaming read of the pcap during replay: a background thread keeps a sliding window of
//! the file in the page cache ahead of the sender threads (readahead) and, for files larger
//! than RAM, drops what all threads have already sent (drop-behind). Without it a file much
//! larger than RAM would thrash the page cache, evict the index and stall sender threads on
//! disk reads inside the hot loop.

use crate::pcap::PcapFile;
use crate::worker::WorkerShared;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Margin kept behind the slowest thread before dropping (covers small reordering).
const STREAM_DROP_MARGIN: u64 = 256 << 20;
const STREAM_CHUNK: u64 = 64 << 20;
/// One readahead request (the kernel caps each at the device readahead size anyway).
const STREAM_RA_PIECE: u64 = 1 << 20;
/// How far ahead of the fastest thread pages are pre-mapped into the process.
const STREAM_POPULATE_AHEAD: u64 = 512 << 20;

const RLX: Ordering = Ordering::Relaxed;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Populate {
    Off,
    Madvise,
    Touch,
}

pub struct Streamer<'a> {
    pf: &'a PcapFile,
    ws: &'a [WorkerShared],
    window: u64,       // bytes to keep requested ahead of the fastest thread
    pub drop_behind: bool, // drop pages behind the slowest thread
    pub stop: AtomicBool,
    // positions are "global": lap * file_size + offset
    pub populate_madvise: AtomicBool, // MADV_POPULATE_READ works (else pages are touched)
    pub ra_bytes: AtomicU64,
    pub dropped_bytes: AtomicU64,
}

#[derive(Clone, Copy)]
enum RangeFn {
    WillNeed,
    Populate,
    Drop,
}

struct State {
    ra_upto: u64,   // readahead requested up to here
    drop_upto: u64, // dropped from the cache below here
    pop_upto: u64,  // pages mapped (MADV_POPULATE_READ) up to here
    populate: Populate,
}

impl<'a> Streamer<'a> {
    pub fn new(pf: &'a PcapFile, ws: &'a [WorkerShared], window: u64, drop_behind: bool) -> Streamer<'a> {
        Streamer {
            pf,
            ws,
            window,
            drop_behind,
            stop: AtomicBool::new(false),
            populate_madvise: AtomicBool::new(std::env::var_os("AFR_NO_POPULATE_MADVISE").is_none()),
            ra_bytes: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
        }
    }

    fn base(&self, off: u64) -> *mut libc::c_void {
        unsafe { self.pf.base.add(off as usize) as *mut libc::c_void }
    }

    fn do_range(&self, st: &mut State, f: RangeFn, off: u64, len: u64) {
        match f {
            RangeFn::WillNeed => {
                // The kernel caps one WILLNEED request at the device readahead size (128 KB
                // by default), so a large range has to be requested piece by piece. Each
                // piece only queues I/O and returns.
                let mut o = 0;
                while o < len {
                    let l = (len - o).min(STREAM_RA_PIECE);
                    unsafe { libc::madvise(self.base(off + o), l as usize, libc::MADV_WILLNEED) };
                    o += STREAM_RA_PIECE;
                }
                self.ra_bytes.fetch_add(len, RLX);
            }
            RangeFn::Populate => {
                // Map the pages into our page tables ahead of the senders, so they take no
                // page faults (and never wait for the disk) in the hot loop. Blocks this
                // thread, not them.
                if st.populate == Populate::Madvise {
                    if unsafe { libc::madvise(self.base(off), len as usize, libc::MADV_POPULATE_READ) } == 0 {
                        return;
                    }
                    let e = crate::util::errno();
                    if e != libc::EINVAL && e != libc::ENOSYS {
                        return;
                    }
                    st.populate = Populate::Touch; // kernel older than 5.14
                    self.populate_madvise.store(false, RLX);
                }
                // Fallback: read one byte per page. The faults (and any disk wait) happen in
                // this thread; the kernel's fault-around maps neighbouring pages as well.
                let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
                let p = self.base(off) as *const u8;
                let mut sink = 0u8;
                let mut o = 0;
                while o < len && !self.stop.load(RLX) {
                    sink ^= unsafe { std::ptr::read_volatile(p.add(o as usize)) };
                    o += page;
                }
                std::hint::black_box(sink);
            }
            RangeFn::Drop => {
                // Unmap our PTEs first (read-only private mapping, nothing to write back),
                // then drop the now unmapped clean pages from the page cache.
                unsafe {
                    libc::madvise(self.base(off), len as usize, libc::MADV_DONTNEED);
                    libc::posix_fadvise(self.pf.fd, off as libc::off_t, len as libc::off_t, libc::POSIX_FADV_DONTNEED);
                }
                self.dropped_bytes.fetch_add(len, RLX);
            }
        }
    }

    /// Apply f to the global range [g0, g1), split at lap boundaries and page aligned.
    fn apply(&self, st: &mut State, mut g0: u64, g1: u64, f: RangeFn) {
        let size = self.pf.size as u64;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        while g0 < g1 && !self.stop.load(RLX) {
            let off = g0 % size;
            let len = (g1 - g0).min(size - off).min(STREAM_CHUNK);
            let a = off & !(page - 1);
            let e = (off + len).min(size);
            self.do_range(st, f, a, e - a);
            g0 += len;
        }
    }

    /// The streaming loop (runs in its own thread until stop).
    pub fn run(&self) {
        let mut st = State {
            ra_upto: 0,
            drop_upto: 0,
            pop_upto: 0,
            populate: if self.populate_madvise.load(RLX) { Populate::Madvise } else { Populate::Touch },
        };
        while !self.stop.load(Ordering::SeqCst) {
            let mut mn = u64::MAX;
            let mut active = 0;
            for w in self.ws {
                if w.st.finished.load(RLX) {
                    continue;
                }
                active += 1;
                mn = mn.min(w.st.gpos.load(RLX));
            }
            if active > 0 {
                // Every thread reports the position it reads next, and all threads move
                // through the file together (both timestamp and rate modes follow file
                // order), so the slowest position is the front: read ahead from it.
                let target = mn + self.window;
                let from = st.ra_upto.max(mn);
                if from < target {
                    self.apply(&mut st, from, target, RangeFn::WillNeed);
                    st.ra_upto = target;
                }
                // Pre-map the nearest part of the window.
                if st.populate != Populate::Off {
                    let ahead = self.window.min(STREAM_POPULATE_AHEAD);
                    let pfrom = st.pop_upto.max(mn);
                    if pfrom < mn + ahead {
                        self.apply(&mut st, pfrom, mn + ahead, RangeFn::Populate);
                        st.pop_upto = mn + ahead;
                    }
                }
                // Drop-behind: everything the slowest thread has passed, minus a margin.
                if self.drop_behind && mn > STREAM_DROP_MARGIN {
                    let end = mn - STREAM_DROP_MARGIN;
                    let du = st.drop_upto;
                    if end > du + STREAM_CHUNK {
                        self.apply(&mut st, du, end, RangeFn::Drop);
                        st.drop_upto = end;
                    }
                }
            }
            crate::util::sleep_ns(10_000_000);
        }
    }
}
