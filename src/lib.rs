//! replaystorm - multithreaded pcap replayer over AF_PACKET.

// The algorithms keep the shape of the original C code (index loops, explicit checks),
// which the parallel/sequential equivalence tests compare against.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_is_multiple_of,
    clippy::manual_checked_ops,
    clippy::int_plus_one,
    clippy::collapsible_match,
    clippy::needless_late_init,
    clippy::unnecessary_cast,
    clippy::type_complexity,
    clippy::result_unit_err
)]

#[macro_use]
pub mod util;

pub mod cli;
pub mod clock;
pub mod dio;
pub mod dissect;
pub mod dpdk;
pub mod idxcache;
pub mod index;
pub mod live;
pub mod mutate;
pub mod par;
pub mod pcap;
pub mod prepare;
pub mod replay;
pub mod report;
pub mod sched;
pub mod stream;
pub mod therm;
pub mod worker;

#[cfg(test)]
mod ref_sched;

pub const CACHELINE: usize = 64;

pub const NS_PER_SEC: i64 = 1_000_000_000;
pub const NS_PER_MS: i64 = 1_000_000;
pub const NS_PER_US: i64 = 1_000;

/// File offset (48 bits) and frame length (16 bits) packed into one word.
#[inline(always)]
pub const fn offlen_make(off: u64, len: u32) -> u64 {
    ((len as u64) << 48) | (off & 0xFFFF_FFFF_FFFF)
}
#[inline(always)]
pub const fn offlen_off(v: u64) -> u64 {
    v & 0xFFFF_FFFF_FFFF
}
#[inline(always)]
pub const fn offlen_len(v: u64) -> u32 {
    (v >> 48) as u32
}

/// Shard index entry: 16 bytes. ts is the time on the schedule timeline (ns from start).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Pkt {
    pub ts: i64,
    pub offlen: u64,
}

/// Special shard number value in the global index.
pub const SHARD_SKIP: u16 = 0xFFFF;

/// Frame skip reasons.
pub const SKIP_TOO_BIG: usize = 0; // larger than MTU + header
pub const SKIP_TOO_SMALL: usize = 1; // smaller than an Ethernet header
pub const SKIP_BAD_RAW: usize = 2; // RAW IP without version 4/6
pub const SKIP_REASONS: usize = 3;

/// Global stop request (signals, fatal errors, the "q" command).
pub static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[inline(always)]
pub fn stop_requested() -> bool {
    STOP.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn request_stop() {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// A raw pointer that may be shared between threads which write disjoint ranges.
#[derive(Clone, Copy)]
pub struct SyncPtr<T>(pub *mut T);
unsafe impl<T> Send for SyncPtr<T> {}
unsafe impl<T> Sync for SyncPtr<T> {}

impl<T> SyncPtr<T> {
    /// The pointer (a method, so closures capture the whole Send+Sync wrapper).
    #[inline(always)]
    pub fn ptr(&self) -> *mut T {
        self.0
    }

    /// # Safety
    /// i must be in bounds and no other thread may access element i concurrently.
    #[inline(always)]
    pub unsafe fn get(&self, i: usize) -> *mut T {
        self.0.add(i)
    }
}
