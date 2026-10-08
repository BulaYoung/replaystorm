//! Direct I/O streaming of the pcap: reader threads read the file with O_DIRECT in large
//! chunks into a ring of buffers in RAM (the window), bypassing the page cache. Sender
//! threads take packet data from the window and never touch the disk or take page faults.
//! A slot is reused only when every sender thread has moved past it.
//!
//! Chunks are numbered globally across laps: q = lap * nchunks + offset / chunk_size.
//! Each slot holds its chunk plus a tail of the next one, so a packet whose data starts
//! inside a chunk is always contiguous in its slot.

use crate::util::{errno, now_ns, sleep_ns, strerror};
use crate::worker::WorkerShared;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

pub const DIO_CHUNK_SHIFT: u32 = 25; // 32 MB chunks
pub const DIO_CHUNK: u64 = 1 << DIO_CHUNK_SHIFT;
const DIO_TAIL: usize = 128 * 1024; // > largest packet (64 KB)
const DIO_ALIGN: usize = 4096; // O_DIRECT offset/size/buffer alignment
const DIO_MAX_READERS: usize = 32;

const RLX: Ordering = Ordering::Relaxed;

#[repr(align(64))]
struct Slot {
    loaded: AtomicU64, // q + 1 of the chunk in the slot, 0 if none
    buf: *mut u8,
}

pub struct Dio {
    fd: i32,
    file_size: u64,
    pub nchunks: u64, // chunks per lap
    end_q: u64,       // stop after this chunk number (u64::MAX: loop forever)
    pub nslots: usize,
    slots: Vec<Slot>,
    mem: *mut u8,
    mem_len: usize,
    slot_len: usize,
    pub nreaders: usize,
    next_q: AtomicU64,
    pub stop: AtomicBool,
    pub failed: AtomicBool,
    pub err: Mutex<String>,
    // statistics
    pub bytes_read: AtomicU64,
    chunks_loaded: AtomicU64,
    pub reader_waits: AtomicU64,
    pub reads: AtomicU64,   // chunk reads
    pub read_ns: AtomicU64, // and their total duration
    // read rate limit from the thermal governor (bytes/s, 0 = none)
    pub rate_limit: AtomicU64,
    next_ns: AtomicI64, // earliest start of the next read under the limit
    pub locked: bool,   // the window is locked in RAM
}

unsafe impl Send for Dio {}
unsafe impl Sync for Dio {}

impl Dio {
    /// Open the file with O_DIRECT and allocate the window. Err with a reason if direct I/O
    /// cannot be used (the caller falls back to mmap).
    pub fn open(path: &str, file_size: u64, window: u64, readers: usize, loops: u64) -> Result<Dio, String> {
        let c = CString::new(path).map_err(|_| "bad path".to_string())?;
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECT | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(format!("O_DIRECT open: {}", strerror(errno())));
        }
        let nchunks = file_size.div_ceil(DIO_CHUNK);
        let end_q = if loops > 0 { loops * nchunks } else { u64::MAX };
        let mut ns = (window / DIO_CHUNK).max(4);
        // No point in a window larger than the whole replay.
        if loops > 0 && ns > end_q {
            ns = end_q;
        }
        let nslots = ns as usize;
        let slot_len = DIO_CHUNK as usize + DIO_TAIL;
        let mem_len = nslots * slot_len;
        let mem = unsafe {
            libc::mmap(std::ptr::null_mut(), mem_len, libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        if mem == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(format!("cannot allocate a {:.1} GB direct I/O window", mem_len as f64 / 1e9));
        }
        let mem = mem as *mut u8;
        // Keep the window in RAM: it must not be swapped out under memory pressure.
        let locked = unsafe { libc::mlock(mem as *const libc::c_void, mem_len) } == 0;
        let slots = (0..nslots)
            .map(|i| Slot { loaded: AtomicU64::new(0), buf: unsafe { mem.add(i * slot_len) } })
            .collect();
        let d = Dio {
            fd,
            file_size,
            nchunks,
            end_q,
            nslots,
            slots,
            mem,
            mem_len,
            slot_len,
            nreaders: readers.clamp(1, DIO_MAX_READERS),
            next_q: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            err: Mutex::new(String::new()),
            bytes_read: AtomicU64::new(0),
            chunks_loaded: AtomicU64::new(0),
            reader_waits: AtomicU64::new(0),
            reads: AtomicU64::new(0),
            read_ns: AtomicU64::new(0),
            rate_limit: AtomicU64::new(0),
            next_ns: AtomicI64::new(0),
            locked,
        };
        // Probe: one aligned direct read, so that an unsupported filesystem is caught here
        // (and the caller can fall back) rather than inside the reader threads.
        let r = unsafe { libc::pread(d.fd, d.slots[0].buf as *mut libc::c_void, DIO_ALIGN, 0) };
        if r < 0 {
            return Err(format!("O_DIRECT read: {}", strerror(errno())));
        }
        Ok(d)
    }

    /// Slot of chunk q, or None if it is not loaded (yet).
    #[inline(always)]
    pub fn chunk(&self, q: u64) -> Option<*const u8> {
        let s = &self.slots[(q % self.nslots as u64) as usize];
        if s.loaded.load(Ordering::Acquire) == q + 1 {
            Some(s.buf)
        } else {
            None
        }
    }

    /// Slowest next-read chunk of the sender threads (u64::MAX if all finished).
    fn slowest_chunk(&self, ws: &[WorkerShared]) -> u64 {
        let mut mn = u64::MAX;
        for w in ws {
            if w.st.finished.load(RLX) {
                continue;
            }
            let g = w.st.gpos.load(RLX);
            let q = (g / self.file_size) * self.nchunks + (g % self.file_size) / DIO_CHUNK;
            mn = mn.min(q);
        }
        mn
    }

    fn read_chunk(&self, q: u64, buf: *mut u8) -> Result<(), String> {
        let off = (q % self.nchunks) * DIO_CHUNK;
        let mut want = self.slot_len;
        if off + want as u64 > self.file_size {
            want = ((self.file_size - off) as usize).div_ceil(DIO_ALIGN) * DIO_ALIGN;
        }
        let mut got = 0usize;
        let t0 = now_ns();
        while got < want {
            let r = unsafe {
                libc::pread(self.fd, buf.add(got) as *mut libc::c_void, want - got, (off + got as u64) as libc::off_t)
            };
            if r < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(format!("direct read at offset {}: {}", off + got as u64, strerror(e)));
            }
            if r == 0 {
                break; // end of file
            }
            got += r as usize;
            if got % DIO_ALIGN != 0 {
                break; // short read at the end of the file
            }
        }
        self.bytes_read.fetch_add(got as u64, RLX);
        self.read_ns.fetch_add((now_ns() - t0) as u64, RLX);
        self.reads.fetch_add(1, RLX);
        Ok(())
    }

    /// A reader thread. ws: the sender threads (their next-read positions).
    pub fn reader_main(&self, ws: &[WorkerShared]) {
        while !self.stop.load(Ordering::SeqCst) {
            let q = self.next_q.fetch_add(1, Ordering::SeqCst);
            if q >= self.end_q {
                return;
            }
            // The slot may hold chunk q - nslots, which some sender may still need.
            let mut waited = false;
            loop {
                if self.stop.load(Ordering::SeqCst) {
                    return;
                }
                let mn = self.slowest_chunk(ws);
                if mn == u64::MAX && !ws.is_empty() {
                    return; // every sender has finished
                }
                if q < mn.saturating_add(self.nslots as u64) {
                    break;
                }
                if !waited {
                    waited = true;
                    self.reader_waits.fetch_add(1, RLX);
                }
                sleep_ns(200_000);
            }
            // Thermal governor: spread reads so the average rate stays under the limit.
            let lim = self.rate_limit.load(RLX);
            if lim > 0 {
                let cost = (self.slot_len as f64 * 1e9 / lim as f64) as i64;
                let now = now_ns();
                let mut cur = self.next_ns.load(Ordering::SeqCst);
                let start = loop {
                    let start = cur.max(now);
                    match self.next_ns.compare_exchange_weak(cur, start + cost, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break start,
                        Err(v) => cur = v,
                    }
                };
                while now_ns() < start && !self.stop.load(Ordering::SeqCst) {
                    let left = start - now_ns();
                    sleep_ns(left.clamp(0, 20_000_000));
                }
            }
            let s = &self.slots[(q % self.nslots as u64) as usize];
            s.loaded.store(0, Ordering::Release);
            if let Err(e) = self.read_chunk(q, s.buf) {
                *self.err.lock().unwrap() = e;
                self.failed.store(true, Ordering::SeqCst);
                crate::request_stop();
                return;
            }
            s.loaded.store(q + 1, Ordering::Release);
            self.chunks_loaded.fetch_add(1, RLX);
        }
    }

    /// Wait until the window is filled (or the whole file is read); returns seconds taken.
    pub fn prefill(&self, timeout_s: f64) -> f64 {
        let want = (self.nslots as u64).min(self.end_q);
        let t0 = now_ns();
        while self.chunks_loaded.load(Ordering::SeqCst) < want
            && !self.failed.load(Ordering::SeqCst)
            && !crate::stop_requested()
        {
            if (now_ns() - t0) as f64 / 1e9 > timeout_s {
                break;
            }
            sleep_ns(5_000_000);
        }
        (now_ns() - t0) as f64 / 1e9
    }
}

impl Drop for Dio {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mem as *mut libc::c_void, self.mem_len);
            libc::close(self.fd);
        }
    }
}
