//! Sender thread: its own AF_PACKET socket with TX_RING and its own packet shard.

use crate::cli::{LagPolicy, Mode};
use crate::clock;
use crate::dio::{Dio, DIO_CHUNK, DIO_CHUNK_SHIFT};
use crate::dpdk::TxQueue;
use crate::index::PktIndex;
use crate::mutate::{mutate, MutateCfg};
use crate::prepare::Ctx;
use crate::sched::{lh_bucket, radix_sort16, target, Rec16, TsOrder, LH_BUCKETS};
use crate::util::{cpu_relax, errno, now_ns, sleep_ns, strerror};
use crate::{offlen_len, offlen_off, request_stop, stop_requested, Pkt, NS_PER_MS, NS_PER_SEC};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Barrier, Mutex, OnceLock, RwLock};

const RLX: Ordering = Ordering::Relaxed;

/// What a sender thread is doing right now (for the watchdog and the wait statistics).
pub const W_RUN: usize = 0; // sending
pub const W_PACE: usize = 1; // waiting for the schedule: normal
pub const W_RING: usize = 2; // TX ring full: waiting for the NIC to complete transmissions
pub const W_QUEUE: usize = 3; // device queue full (ENOBUFS/EAGAIN)
pub const W_DISK: usize = 4; // data not yet read from the disk (direct I/O)
pub const W_FENCE: usize = 5; // too far ahead of the slowest thread
pub const W_LINK: usize = 6; // interface down or being re-created
pub const W_COUNT: usize = 7;

pub const WSTATE_NAMES: [&str; W_COUNT] =
    ["sending", "schedule", "TX ring", "device queue", "disk", "slowest thread", "link"];

/// Shared run state.
pub struct Shared {
    pub bar: Barrier,
    pub t0: AtomicI64,         // common CLOCK_MONOTONIC reference point
    pub shift: AtomicI64,      // T0 shift for --lag-policy=rebase
    pub pause: AtomicI64,      // T0 shift for link outages (all modes)
    pub down_since: AtomicI64, // start of the current link outage, 0 if the link is up
    pub failed: AtomicBool,
}

impl Shared {
    pub fn new(parties: usize) -> Shared {
        Shared {
            bar: Barrier::new(parties),
            t0: AtomicI64::new(0),
            shift: AtomicI64::new(0),
            pause: AtomicI64::new(0),
            down_since: AtomicI64::new(0),
            failed: AtomicBool::new(false),
        }
    }

    /// Link outage bookkeeping shared by the sender threads and the stats thread: whoever
    /// first sees the link come back shifts the schedule by the outage, exactly once.
    pub fn link_down(&self, now: i64) {
        let _ = self.down_since.compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn link_up(&self, now: i64) {
        let v = self.down_since.load(Ordering::SeqCst);
        if v != 0 && self.down_since.compare_exchange(v, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            self.pause.fetch_add(now - v, Ordering::SeqCst);
        }
    }
}

/// Thread counters: written only by the thread itself, read by the stats thread.
#[repr(align(64))]
#[derive(Default)]
pub struct WStats {
    pub pkts: AtomicU64,
    pub bytes: AtomicU64,
    pub sends: AtomicU64,
    pub enobufs: AtomicU64,
    pub eagain: AtomicU64,
    pub asis_back: AtomicU64,   // packets "backward in time" under asis
    pub rebases: AtomicU64,
    pub fence_waits: AtomicU64, // times the thread waited for the slowest one
    pub dio_waits: AtomicU64,   // times the thread waited for data from the disk
    pub late_max: AtomicI64,
    pub pos: AtomicI64,         // position on the timeline (lap*length + ts)
    pub lap: AtomicU64,
    pub gpos: AtomicU64,        // lap * file_size + file offset of the next packet
    pub t_end: AtomicI64,       // when the thread finished sending
    pub state: AtomicI32,       // W_*
    pub wait_ns: [AtomicU64; W_COUNT],
    pub link_lost: AtomicU64,   // frames lost when the interface was re-created
    pub finished: AtomicBool,
}

#[repr(align(64))]
pub struct Hist(pub [AtomicU64; LH_BUCKETS]);

/// The part of a sender thread visible to the other threads.
pub struct WorkerShared {
    pub id: usize,
    pub cpu: i32,
    pub is_l2: bool,
    pub st: WStats,
    pub hist: Hist, // lateness, ns
    pub err: Mutex<String>,
    pub mlock_failed: AtomicBool,
}

impl WorkerShared {
    pub fn new(id: usize, cpu: i32, is_l2: bool) -> WorkerShared {
        WorkerShared {
            id,
            cpu,
            is_l2,
            st: WStats::default(),
            hist: Hist(std::array::from_fn(|_| AtomicU64::new(0))),
            err: Mutex::new(String::new()),
            mlock_failed: AtomicBool::new(false),
        }
    }
}

/// Set by the main thread between the two start barriers.
pub struct Setup<'a> {
    pub dio: Option<&'a Dio>,      // direct I/O window (None: data from the mmap)
    pub fence_lead: Option<u64>,   // how far ahead of the slowest thread a thread may read
}

/* ---------- TX_RING ---------- */

struct TxRing {
    fd: i32,
    ring: *mut u8,
    ring_size: usize,
    frame_size: usize,
    frame_nr: usize,
    data_off: usize,
}

const TPACKET_ALIGNMENT: usize = 16;

/// The kernel may set timestamp flags in the status (commit 171c3b151118).
#[inline(always)]
fn status_mask(s: u32) -> u32 {
    s & !(libc::TP_STATUS_TS_SOFTWARE | libc::TP_STATUS_TS_RAW_HARDWARE)
}

fn setsockopt_int(fd: i32, level: i32, name: i32, v: i32) -> bool {
    unsafe {
        libc::setsockopt(fd, level, name, &v as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as u32) == 0
    }
}

impl TxRing {
    fn closed() -> TxRing {
        TxRing { fd: -1, ring: std::ptr::null_mut(), ring_size: 0, frame_size: 0, frame_nr: 0, data_off: 0 }
    }

    fn open(iface: &str, frames: usize, max_len: usize, bypass: bool, loss: bool) -> Result<TxRing, String> {
        let mut t = TxRing::closed();
        // protocol 0: the socket receives nothing
        t.fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        if t.fd < 0 {
            let e = errno();
            return Err(format!(
                "socket(AF_PACKET): {}{}",
                strerror(e),
                if e == libc::EPERM { " (requires root or CAP_NET_RAW)" } else { "" }
            ));
        }
        if !setsockopt_int(t.fd, libc::SOL_PACKET, libc::PACKET_VERSION, libc::tpacket_versions::TPACKET_V2 as i32) {
            return Err(format!("PACKET_VERSION: {}", strerror(errno())));
        }
        if bypass && !setsockopt_int(t.fd, libc::SOL_PACKET, libc::PACKET_QDISC_BYPASS, 1) {
            return Err(format!("PACKET_QDISC_BYPASS: {}", strerror(errno())));
        }
        if loss && !setsockopt_int(t.fd, libc::SOL_PACKET, libc::PACKET_LOSS, 1) {
            return Err(format!("PACKET_LOSS: {}", strerror(errno())));
        }
        t.data_off = std::mem::size_of::<libc::tpacket2_hdr>().div_ceil(TPACKET_ALIGNMENT) * TPACKET_ALIGNMENT;
        let mut fs = 2048usize;
        while fs < t.data_off + max_len {
            fs <<= 1;
        }
        let block = fs.max(65536);
        let per_block = block / fs;
        let nblocks = frames.div_ceil(per_block);
        t.frame_size = fs;
        t.frame_nr = nblocks * per_block;
        // The send buffer must hold the whole ring, otherwise send() hits EAGAIN.
        let sndbuf = (t.frame_nr * fs * 2).min(1 << 30) as i32;
        if !setsockopt_int(t.fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, sndbuf) {
            setsockopt_int(t.fd, libc::SOL_SOCKET, libc::SO_SNDBUF, sndbuf);
        }
        let req = libc::tpacket_req {
            tp_block_size: block as u32,
            tp_block_nr: nblocks as u32,
            tp_frame_size: fs as u32,
            tp_frame_nr: t.frame_nr as u32,
        };
        if unsafe {
            libc::setsockopt(t.fd, libc::SOL_PACKET, libc::PACKET_TX_RING, &req as *const _ as *const libc::c_void,
                             std::mem::size_of::<libc::tpacket_req>() as u32)
        } < 0
        {
            return Err(format!("PACKET_TX_RING ({} frames of {} bytes): {}", t.frame_nr, fs, strerror(errno())));
        }
        t.ring_size = block * nblocks;
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), t.ring_size, libc::PROT_READ | libc::PROT_WRITE,
                       libc::MAP_SHARED | libc::MAP_POPULATE, t.fd, 0)
        };
        if p == libc::MAP_FAILED {
            return Err(format!("mmap TX_RING: {}", strerror(errno())));
        }
        t.ring = p as *mut u8;
        let name = CString::new(iface).unwrap_or_default();
        let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) } as i32;
        if ifindex == 0 {
            return Err(format!("interface {} not found", iface));
        }
        let mut ll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        ll.sll_family = libc::AF_PACKET as u16;
        ll.sll_protocol = 0;
        ll.sll_ifindex = ifindex;
        if unsafe {
            libc::bind(t.fd, &ll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32)
        } < 0
        {
            return Err(format!("bind {}: {}", iface, strerror(errno())));
        }
        Ok(t)
    }

    fn close(&mut self) {
        if !self.ring.is_null() {
            unsafe { libc::munmap(self.ring as *mut libc::c_void, self.ring_size) };
        }
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
        self.ring = std::ptr::null_mut();
        self.fd = -1;
    }

    #[inline(always)]
    fn frame(&self, i: usize) -> *mut libc::tpacket2_hdr {
        unsafe { self.ring.add(i * self.frame_size) as *mut libc::tpacket2_hdr }
    }

    #[inline(always)]
    fn status(&self, i: usize) -> u32 {
        // tp_status is shared with the kernel.
        unsafe { (*(self.frame(i) as *const AtomicU32)).load(Ordering::Acquire) }
    }
}

impl Drop for TxRing {
    fn drop(&mut self) {
        self.close();
    }
}

/* ---------- Sending ---------- */

struct Worker<'a> {
    c: &'a Ctx,
    me: &'a WorkerShared,
    sh: &'a Shared,
    mutate: bool,
    mut_cfg: MutateCfg,
    peers: Option<&'a [WorkerShared]>, // all sender threads (None: no position fence)
    fence_lead: u64,
    fence_min: u64, // last computed slowest position
    dio: Option<&'a Dio>,
    dio_q: u64,     // chunk of the last packet and its buffer
    dio_buf: *const u8,
    pk: Vec<Pkt>,
    tx: TxRing,
    dq: Option<TxQueue>, // DPDK TX queue instead of the TX ring
    // hot state (thread only)
    head: usize,
    pending: u32,
    now: i64,       // last clock reading
    wstate: usize,  // W_* (thread-local copy)
    ring_len: usize, // max frame length the ring was sized for
    l_pkts: u64,
    l_bytes: u64,
    l_sends: u64,
    l_enobufs: u64,
    l_eagain: u64,
}

/// Back off after the device queue rejected frames (ENOBUFS/EAGAIN). Hammering send() in a
/// tight loop only burns the CPU: the queue frees up at line rate anyway. The first few
/// attempts spin briefly, then the thread sleeps for 5..100 us.
fn backoff(fails: u32) {
    if fails <= 4 {
        for _ in 0..(64u32 << fails) {
            cpu_relax();
        }
        return;
    }
    let sh = (fails - 5).min(5);
    sleep_ns((5000i64 << sh).min(100_000));
}

/// Hybrid wait: nanosleep for long pauses, busy-spin at the end.
fn wait_until(target: i64, spin_ns: i64) -> i64 {
    let mut now = clock::clock_ns();
    while now < target {
        let d = target - now;
        if d > spin_ns {
            // Before sleeping, check TSC against CLOCK_MONOTONIC (reading the clock is free here).
            if clock::resync() {
                now = clock::clock_ns();
                continue;
            }
            let sl = (d - spin_ns).min(50 * NS_PER_MS); // to notice a stop request in time
            // Our clock is calibrated against CLOCK_MONOTONIC, so it is valid for it.
            let wake = now + sl;
            let ts = libc::timespec { tv_sec: (wake / NS_PER_SEC) as libc::time_t, tv_nsec: (wake % NS_PER_SEC) as _ };
            unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) };
            if stop_requested() {
                return clock::clock_ns();
            }
        } else {
            cpu_relax();
        }
        now = clock::clock_ns();
    }
    now
}

/// Slowest next-read position of the given threads (u64::MAX if all finished).
pub fn slowest_gpos(ws: &[WorkerShared]) -> u64 {
    ws.iter()
        .filter(|w| !w.st.finished.load(RLX))
        .map(|w| w.st.gpos.load(RLX))
        .min()
        .unwrap_or(u64::MAX)
}

impl<'a> Worker<'a> {
    /// Enter a wait state; returns the time it started and the previous state. Nested
    /// waits keep the outer state.
    #[inline(always)]
    fn wenter(&mut self, s: usize) -> (i64, usize) {
        let prev = self.wstate;
        if self.wstate != W_RUN && self.wstate != W_PACE {
            // Already inside another wait, which accounts for the time. A link outage is
            // still made visible: it explains every other wait.
            if s == W_LINK {
                self.me.st.state.store(s as i32, RLX);
            }
            return (0, prev);
        }
        self.wstate = s;
        self.me.st.state.store(s as i32, RLX);
        (now_ns(), prev)
    }

    #[inline(always)]
    fn wleave(&mut self, s: usize, prev: usize, t0: i64) {
        if t0 == 0 {
            if s == W_LINK {
                self.me.st.state.store(self.wstate as i32, RLX);
            }
            return;
        }
        let c = &self.me.st.wait_ns[s];
        c.store(c.load(RLX) + (now_ns() - t0) as u64, RLX);
        self.wstate = prev;
        self.me.st.state.store(prev as i32, RLX);
    }

    fn publish(&self) {
        let st = &self.me.st;
        st.pkts.store(self.l_pkts, RLX);
        st.bytes.store(self.l_bytes, RLX);
        st.sends.store(self.l_sends, RLX);
        st.enobufs.store(self.l_enobufs, RLX);
        st.eagain.store(self.l_eagain, RLX);
    }

    fn fatal(&self, what: &str, e: i32) {
        let mut err = self.me.err.lock().unwrap();
        if err.is_empty() {
            *err = format!(
                "thread {}: {}: {}{}",
                self.me.id,
                what,
                strerror(e),
                if (e == libc::EMSGSIZE || e == libc::EINVAL) && !self.c.o.packet_loss {
                    " (kernel rejected the frame; --packet-loss lets it be skipped)"
                } else {
                    ""
                }
            );
        }
        self.sh.failed.store(true, Ordering::SeqCst);
        request_stop();
    }

    /// The interface was removed and may come back (driver reload, re-created device): the
    /// socket is bound to a stale ifindex, so open a new socket and ring by name. Frames
    /// still in the old ring are lost and counted.
    fn tx_reopen(&mut self) {
        let lost = (0..self.tx.frame_nr).filter(|&i| status_mask(self.tx.status(i)) != libc::TP_STATUS_AVAILABLE).count();
        let ll = &self.me.st.link_lost;
        ll.store(ll.load(RLX) + lost as u64, RLX);
        let frames = self.tx.frame_nr;
        self.tx.close();
        let o = &self.c.o;
        while !stop_requested() {
            match TxRing::open(o.iface.as_deref().unwrap_or(""), frames, self.ring_len, o.qdisc_bypass, o.packet_loss) {
                Ok(t) => {
                    self.tx = t;
                    break;
                }
                Err(_) => sleep_ns(200 * NS_PER_MS),
            }
        }
        self.head = 0;
        self.pending = 0;
    }

    /// DPDK: rte_eth_tx_burst until the NIC has taken every pending frame. A full TX queue
    /// is backpressure, like ENOBUFS: back off and retry.
    fn flush_dpdk(&mut self) {
        self.pending = 0;
        let mut fails = 0;
        let (mut prev, mut t0, mut state) = (W_RUN, 0, W_RUN);
        loop {
            self.l_sends += 1;
            let dq = self.dq.as_mut().unwrap();
            dq.tx();
            if dq.pending() == 0 {
                break;
            }
            self.l_enobufs += 1;
            let want = if self.sh.down_since.load(RLX) != 0 { W_LINK } else { W_QUEUE };
            if state != want {
                self.wleave(state, prev, t0);
                let (t, p) = self.wenter(want);
                t0 = t;
                prev = p;
                state = if t0 != 0 { want } else { W_RUN };
            }
            if stop_requested() {
                break; // the frames left are freed with the queue
            }
            fails += 1;
            backoff(fails);
        }
        self.wleave(state, prev, t0);
        self.publish();
        self.now = clock::clock_ns();
    }

    /// DPDK: a free mbuf. When the pool is empty, all mbufs are queued in the NIC: send
    /// what is pending and let the driver return the completed ones.
    fn acquire_mbuf(&mut self) -> Option<*mut libc::c_void> {
        if let Some(m) = self.dq.as_mut().unwrap().alloc() {
            return Some(m);
        }
        let (t0, prev) = self.wenter(W_RING);
        let mut spins = 0u32;
        loop {
            if stop_requested() {
                self.wleave(W_RING, prev, t0);
                return None;
            }
            if self.pending > 0 {
                self.flush();
            } else {
                let dq = self.dq.as_mut().unwrap();
                dq.cleanup();
            }
            if let Some(m) = self.dq.as_mut().unwrap().alloc() {
                self.wleave(W_RING, prev, t0);
                return Some(m);
            }
            spins += 1;
            if spins > 64 {
                sleep_ns(10_000);
            } else {
                cpu_relax();
            }
        }
    }

    /// Batched send(): the kernel transmits all frames with status SEND_REQUEST.
    fn flush(&mut self) {
        if self.dq.is_some() {
            return self.flush_dpdk();
        }
        let mut fails = 0;
        self.pending = 0;
        let mut prev = W_RUN;
        let mut t0 = 0;
        let mut state = W_RUN;
        let mut link_seen = false;
        loop {
            self.l_sends += 1;
            let r = if self.tx.fd >= 0 {
                unsafe { libc::send(self.tx.fd, std::ptr::null(), 0, libc::MSG_DONTWAIT) }
            } else {
                -1
            };
            if r >= 0 {
                break;
            }
            let e = if self.tx.fd >= 0 { errno() } else { libc::ENXIO };
            let mut want = W_QUEUE;
            if e == libc::ENOBUFS {
                // Device/qdisc queue is full. The frame stays SEND_REQUEST; the kernel
                // retries it on the next send().
                self.l_enobufs += 1;
            } else if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                self.l_eagain += 1; // socket buffer exhausted
            } else if e == libc::ENETDOWN || e == libc::ENXIO || e == libc::ENODEV {
                // The interface is down or gone: wait for it instead of giving up. Frames
                // stay in the ring and go out when it is back.
                want = W_LINK;
            } else if e != libc::EINTR {
                self.fatal("send", e);
                break;
            }
            if state != want {
                self.wleave(state, prev, t0);
                let (t, p) = self.wenter(want);
                t0 = t;
                prev = p;
                state = if t0 != 0 { want } else { W_RUN };
            }
            if want == W_LINK {
                link_seen = true;
                self.sh.link_down(now_ns());
            }
            if stop_requested() {
                break;
            }
            if want == W_LINK {
                if e == libc::ENXIO || e == libc::ENODEV {
                    self.tx_reopen();
                }
                sleep_ns(100 * NS_PER_MS);
                if self.tx.fd >= 0 && self.pending == 0 && e != libc::ENETDOWN {
                    break; // re-created: the old frames are gone, nothing left to send
                }
            } else {
                fails += 1;
                backoff(fails);
            }
        }
        self.wleave(state, prev, t0);
        if link_seen && !stop_requested() {
            self.sh.link_up(now_ns()); // back: shift the schedule right away
        }
        self.publish();
        self.now = clock::clock_ns();
    }

    fn acquire_slow(&mut self) -> Option<*mut libc::tpacket2_hdr> {
        let mut spins = 0u32;
        let (t0, prev) = self.wenter(W_RING);
        loop {
            if stop_requested() || self.tx.ring.is_null() {
                self.wleave(W_RING, prev, t0);
                return None; // stopping, or the ring could not be re-created
            }
            // The ring may have been re-created by flush() (interface came back).
            let s = status_mask(self.tx.status(self.head));
            if s == libc::TP_STATUS_AVAILABLE {
                self.wleave(W_RING, prev, t0);
                return Some(self.tx.frame(self.head));
            }
            if s & libc::TP_STATUS_WRONG_FORMAT != 0 {
                self.fatal("frame rejected by kernel (TP_STATUS_WRONG_FORMAT)", libc::EINVAL);
                self.wleave(W_RING, prev, t0);
                return None;
            }
            let mut kick = false;
            let mut idle = false;
            if self.pending == 0 {
                if s == libc::TP_STATUS_SEND_REQUEST {
                    spins += 1;
                    kick = spins & 255 == 0;
                }
                if !kick {
                    spins += 1;
                    idle = spins > 4096;
                }
            }
            if self.pending > 0 || kick {
                // Pending frames, or a frame not picked up after ENOBUFS/EAGAIN: kick it.
                self.flush();
            } else if idle {
                // The ring is full of frames still in the driver: wait for completions
                // without burning the CPU.
                sleep_ns(10_000);
            } else {
                cpu_relax();
            }
            if stop_requested() {
                self.wleave(W_RING, prev, t0);
                return None;
            }
        }
    }

    #[inline(always)]
    fn acquire(&mut self) -> Option<*mut libc::tpacket2_hdr> {
        if status_mask(self.tx.status(self.head)) == libc::TP_STATUS_AVAILABLE {
            return Some(self.tx.frame(self.head));
        }
        self.acquire_slow()
    }

    /// Wait until all ring frames have been sent (no longer than timeout).
    fn drain(&mut self, timeout: i64) {
        if self.dq.is_some() {
            if self.dq.as_ref().unwrap().pending() > 0 {
                self.flush();
            }
            self.publish();
            return;
        }
        if self.tx.ring.is_null() {
            return;
        }
        if self.pending > 0 {
            self.flush();
        }
        let deadline = now_ns() + timeout;
        let mut i = 0;
        while i < self.tx.frame_nr {
            let s = status_mask(self.tx.status(i));
            if s == libc::TP_STATUS_AVAILABLE || s & libc::TP_STATUS_WRONG_FORMAT != 0 {
                i += 1;
                continue;
            }
            if now_ns() > deadline {
                break;
            }
            if s == libc::TP_STATUS_SEND_REQUEST {
                self.flush();
            }
            sleep_ns(20_000);
            if self.tx.ring.is_null() {
                break;
            }
        }
        self.publish();
    }

    /// The chunk is not in the direct I/O window yet: wait in memory, never in the kernel.
    fn dio_wait(&mut self, dio: &Dio, q: u64) -> Option<*const u8> {
        if self.pending > 0 {
            self.flush();
        }
        self.me.st.dio_waits.fetch_add(1, RLX);
        let mut spins = 0;
        let (t0, prev) = self.wenter(W_DISK);
        let b = loop {
            if let Some(b) = dio.chunk(q) {
                break b;
            }
            if stop_requested() {
                self.wleave(W_DISK, prev, t0);
                return None;
            }
            spins += 1;
            if spins < 64 {
                cpu_relax();
            } else {
                sleep_ns(20_000);
            }
        };
        self.wleave(W_DISK, prev, t0);
        self.now = clock::clock_ns();
        Some(b)
    }

    /// Packet data: from the direct I/O window or from the mmap of the file.
    #[inline(always)]
    fn pkt_data(&mut self, p: Pkt, lap: u64) -> Option<*const u8> {
        let off = offlen_off(p.offlen);
        let Some(dio) = self.dio else {
            return Some(unsafe { self.c.pf.base.add(off as usize) });
        };
        let q = lap * dio.nchunks + (off >> DIO_CHUNK_SHIFT);
        if q != self.dio_q {
            // The previous chunk may be recycled once our published position moved past it,
            // but the current one cannot: our position is still inside it.
            let b = match dio.chunk(q) {
                Some(b) => b,
                None => self.dio_wait(dio, q)?,
            };
            self.dio_q = q;
            self.dio_buf = b;
        }
        Some(unsafe { self.dio_buf.add((off & (DIO_CHUNK - 1)) as usize) })
    }

    /// Copy a packet into the ring and mark it for sending.
    #[inline(always)]
    fn emit(&mut self, p: Pkt, lap: u64) -> bool {
        let Some(src) = self.pkt_data(p, lap) else { return false };
        let o = &self.c.o;
        let raw_ip = self.c.pf.raw_ip;
        let len = offlen_len(p.offlen) as usize;
        let flen = len + if raw_ip != 0 { 14 } else { 0 };
        // Destination: a TX ring frame, or a DPDK mbuf.
        let (h, m, dst) = if self.dq.is_some() {
            let Some(m) = self.acquire_mbuf() else { return false };
            (std::ptr::null_mut(), m, unsafe { self.dq.as_ref().unwrap().data(m, flen as u32) })
        } else {
            let Some(h) = self.acquire() else { return false };
            (h, std::ptr::null_mut(), unsafe { (h as *mut u8).add(self.tx.data_off) })
        };
        unsafe {
            if raw_ip != 0 {
                // Synthetic Ethernet header for RAW IP.
                std::ptr::copy_nonoverlapping(o.dmac.as_ptr(), dst, 6);
                std::ptr::copy_nonoverlapping(o.smac.as_ptr(), dst.add(6), 6);
                let v6 = raw_ip == 6 || (raw_ip == 1 && len > 0 && (*src >> 4) == 6);
                *dst.add(12) = if v6 { 0x86 } else { 0x08 };
                *dst.add(13) = if v6 { 0xdd } else { 0x00 };
                std::ptr::copy_nonoverlapping(src, dst.add(14), len);
            } else {
                std::ptr::copy_nonoverlapping(src, dst, len);
            }
            if self.mutate && lap > 0 {
                mutate(std::slice::from_raw_parts_mut(dst, flen), lap, &self.mut_cfg);
            }
        }
        if let Some(dq) = self.dq.as_mut() {
            dq.push(m);
        } else {
            unsafe {
                (*h).tp_len = flen as u32;
                (*(h as *const AtomicU32)).store(libc::TP_STATUS_SEND_REQUEST, Ordering::Release);
            }
            self.head = if self.head + 1 == self.tx.frame_nr { 0 } else { self.head + 1 };
        }
        self.pending += 1;
        self.l_pkts += 1;
        self.l_bytes += flen as u64;
        if self.pending >= o.batch {
            self.flush();
        }
        true
    }

    /// Wait until target and return the current time. If the packet is already known to
    /// be due (target <= last clock reading), the clock is not read: when lagging, this
    /// saves a call per packet, and lateness is underestimated by at most the duration of
    /// one batch (the clock is updated after every send).
    #[inline(always)]
    fn pace(&mut self, target: i64, spin: i64) -> i64 {
        let mut now = self.now;
        if now >= target {
            return now;
        }
        now = clock::clock_ns();
        if now < target {
            // Packet not yet due: flush what has accumulated early.
            if self.pending > 0 {
                self.flush();
                now = self.now;
            }
            if now < target {
                let (t0, prev) = self.wenter(W_PACE);
                now = wait_until(target, spin);
                self.wleave(W_PACE, prev, t0);
            }
        }
        self.now = now;
        now
    }

    #[inline(always)]
    fn hist_add(&self, late: i64) {
        let v = late.max(0) as u64;
        let b = &self.me.hist.0[lh_bucket(v)];
        b.store(b.load(RLX) + 1, RLX);
        if late > self.me.st.late_max.load(RLX) {
            self.me.st.late_max.store(late, RLX);
        }
    }

    #[inline(always)]
    fn publish_pos(&self, i: usize, lap: u64, lap_len: i64) {
        let st = &self.me.st;
        st.pos.store(lap as i64 * lap_len + self.pk[i].ts, RLX);
        st.lap.store(lap, RLX);
        // The streamer needs where this thread reads next, not where it has been: a thread
        // whose next packet is far ahead must not hold back dropping the pages behind.
        let size = self.c.pf.size as u64;
        let next = if i + 1 < self.pk.len() {
            lap * size + offlen_off(self.pk[i + 1].offlen)
        } else {
            (lap + 1) * size + offlen_off(self.pk[0].offlen)
        };
        st.gpos.store(next, RLX);
    }

    /// Keep this thread within fence_lead of the slowest one. Without it, at top speed (or
    /// a rate the link cannot reach) threads drift apart in the file: the fast ones outrun
    /// the readahead window and wait for the disk, the slow one keeps the pages behind it
    /// alive. The lap still ends with the slowest thread, so the total rate does not suffer.
    fn wait_fence(&mut self, peers: &[WorkerShared], g: u64) {
        // Recompute from the peers' positions (cheap) before deciding to wait.
        self.fence_min = slowest_gpos(peers);
        if self.fence_min == u64::MAX || g <= self.fence_min + self.fence_lead {
            return;
        }
        if self.pending > 0 {
            self.flush();
        }
        self.me.st.fence_waits.fetch_add(1, RLX);
        let (t0, prev) = self.wenter(W_FENCE);
        while !stop_requested() {
            sleep_ns(50_000);
            self.fence_min = slowest_gpos(peers);
            if g <= self.fence_min.saturating_add(self.fence_lead) {
                break;
            }
        }
        self.wleave(W_FENCE, prev, t0);
        self.now = clock::clock_ns();
    }

    fn run(&mut self) {
        let c = self.c;
        let o = &c.o;
        let t0 = self.sh.t0.load(Ordering::SeqCst);
        let spin = o.spin_ns;
        let pace_slack = o.pace_slack;
        let rate_mode = o.mode == Mode::Mbps || o.mode == Mode::Pps;
        // Rate modes have their own timeline: cumulative bytes (or packets) in file order.
        let lap_len = if rate_mode { c.rate_lap_ns } else { c.tsr.lap_len };
        let loops = o.loops;
        let mode = o.mode;
        let asis = o.ts_order == TsOrder::Asis;
        let rebase = o.lag_policy == LagPolicy::Rebase;
        let lag_thr = o.lag_threshold;
        let inv_mult = 1.0 / c.mult;
        let size = c.pf.size as u64;

        // All modes start simultaneously at the common point T0.
        self.now = wait_until(t0, spin);
        let mut lap = 0u64;
        while loops == 0 || lap < loops {
            let mut max_sched = i64::MIN;
            for i in 0..self.pk.len() {
                if stop_requested() {
                    return;
                }
                let p = self.pk[i];
                if let Some(peers) = self.peers {
                    let g = lap * size + offlen_off(p.offlen);
                    if g > self.fence_min.saturating_add(self.fence_lead) {
                        self.wait_fence(peers, g);
                    }
                }
                if mode == Mode::Timed {
                    if asis && p.ts < max_sched {
                        // "Backward in time" under asis: no wait, lateness not counted.
                        self.me.st.asis_back.fetch_add(1, RLX);
                    } else {
                        max_sched = p.ts;
                        let shift = self.sh.pause.load(RLX) + if rebase { self.sh.shift.load(RLX) } else { 0 };
                        let tgt = target(t0 + shift, lap, lap_len, p.ts, inv_mult);
                        let late = self.pace(tgt, spin) - tgt;
                        self.hist_add(late);
                        if rebase && late > lag_thr {
                            // Shift the common T0 forward so this packet is on time.
                            let base = self.sh.shift.load(RLX);
                            let want = base + late;
                            let mut cur = base;
                            while cur < want {
                                match self.sh.shift.compare_exchange_weak(cur, want, Ordering::SeqCst, Ordering::SeqCst) {
                                    Ok(_) => break,
                                    Err(v) => cur = v,
                                }
                            }
                            self.me.st.rebases.fetch_add(1, RLX);
                        }
                    }
                } else if mode != Mode::Topspeed {
                    // p.ts is the packet's place in the common rate timeline (bytes or packets
                    // before it in the file, converted to ns), so all threads move through the
                    // file together and the total rate is exact. Fixed rate needs no
                    // microsecond precision: sleep instead of spinning and send everything due
                    // within the next pace_slack at once.
                    let t0p = t0 + self.sh.pause.load(RLX);
                    self.pace(target(t0p, lap, lap_len, p.ts, 1.0) - pace_slack, 0);
                }
                if !self.emit(p, lap) {
                    return;
                }
                self.publish_pos(i, lap, lap_len);
            }
            lap += 1;
        }
    }
}

/// Copy this thread's shard out of the global index.
fn build_shard(c: &Ctx, ix: &PktIndex, sid: usize) -> Vec<Pkt> {
    let cnt = ix.shard_pkts[sid] as usize;
    let mut pk = Vec::with_capacity(cnt.max(1));
    let (sh, ts, ol) = (ix.shard(), ix.ts(), ix.offlen());
    for i in 0..ix.n {
        if pk.len() >= cnt {
            break;
        }
        if sh[i] as usize == sid {
            pk.push(Pkt { ts: ts[i], offlen: ol[i] });
        }
    }
    if c.o.ts_order == TsOrder::Sort && !c.tsr.monotone {
        // Stable sort of the shard index by timestamp; data is not touched.
        let mut tmp = vec![Rec16::default(); pk.len()];
        // Pkt and Rec16 have the same layout: {i64, u64}.
        let recs = unsafe { std::slice::from_raw_parts_mut(pk.as_mut_ptr() as *mut Rec16, pk.len()) };
        radix_sort16(recs, &mut tmp);
    }
    pk
}

/// Ring slot size: the largest frame actually present in the file, not the MTU. With MTU
/// 9000 and ordinary traffic this gives 2 KB slots instead of 16 KB, which keeps the ring
/// compact in cache and TLB.
fn ring_frame_len(c: &Ctx, max_frame: u32) -> usize {
    let mtu_max = c.mtu as usize + 14 + 4;
    let m = max_frame as usize;
    if m > 0 && m < mtu_max {
        m
    } else {
        mtu_max
    }
}

/// A sender thread.
pub fn worker_main<'a, 'd: 'a>(c: &'a Ctx, ix: &RwLock<PktIndex>, me: &'a WorkerShared, all: &'a [WorkerShared],
                               sh: &'a Shared, setup: &OnceLock<Setup<'d>>, mut_cfg: MutateCfg) {
    if me.cpu >= 0 {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_SET(me.cpu as usize, &mut set) };
        if unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) } != 0 {
            eprintln!("WARNING: thread {}: failed to pin to CPU {}", me.id, me.cpu);
        }
    }
    unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong, 0, 0, 0) };
    clock::thread_init();

    // Shard memory and the ring are allocated after pinning, on the thread's own NUMA node.
    let o = &c.o;
    let (pk, max_frame) = {
        let ix = ix.read().unwrap();
        (build_shard(c, &ix, me.id), ix.st.max_frame)
    };
    let ring_len = ring_frame_len(c, max_frame);
    let mut ok = true;
    // DPDK: queue number = this thread's position among the sender threads.
    let dq = crate::dpdk::port().map(|p| {
        let q = all.iter().position(|w| std::ptr::eq(w, me)).unwrap_or(0);
        TxQueue::new(p.port, q as u16, o.batch as usize)
    });
    let tx = if dq.is_some() {
        Ok(TxRing::closed())
    } else {
        TxRing::open(o.iface.as_deref().unwrap_or(""), o.ring_frames as usize, ring_len, o.qdisc_bypass, o.packet_loss)
    };
    let tx = match tx {
        Ok(t) => t,
        Err(e) => {
            *me.err.lock().unwrap() = format!("thread {}: {}", me.id, e);
            sh.failed.store(true, Ordering::SeqCst);
            ok = false;
            TxRing::closed()
        }
    };
    if ok && unsafe { libc::mlock(pk.as_ptr() as *const libc::c_void, pk.len().max(1) * std::mem::size_of::<Pkt>()) } != 0 {
        // Not fatal: the index stays swappable. With a file much larger than RAM the page
        // cache churns hard, so pinning the index avoids stalls on swap-in.
        me.mlock_failed.store(true, RLX);
    }
    if let Some(p) = pk.first() {
        me.st.gpos.store(offlen_off(p.offlen), Ordering::SeqCst);
    }
    sh.bar.wait(); // 1: everything is prepared
    sh.bar.wait(); // 2: T0 is set
    let mut w = Worker {
        c,
        me,
        sh,
        mutate: o.mutate_ip || o.mutate_port,
        mut_cfg,
        peers: None,
        fence_lead: 0,
        fence_min: 0,
        dio: None,
        dio_q: u64::MAX,
        dio_buf: std::ptr::null(),
        pk,
        tx,
        dq,
        head: 0,
        pending: 0,
        now: 0,
        wstate: W_RUN,
        ring_len,
        l_pkts: 0,
        l_bytes: 0,
        l_sends: 0,
        l_enobufs: 0,
        l_eagain: 0,
    };
    if let Some(s) = setup.get() {
        w.dio = s.dio;
        if let Some(lead) = s.fence_lead {
            w.peers = Some(all);
            w.fence_lead = lead;
        }
    }
    if ok && !sh.failed.load(Ordering::SeqCst) {
        w.run();
        w.drain(3 * NS_PER_SEC);
    }
    me.st.t_end.store(now_ns(), RLX);
    w.publish();
    drop(w);
    me.st.finished.store(true, Ordering::SeqCst);
}
