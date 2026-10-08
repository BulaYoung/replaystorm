//! DPDK sending backend (--dpdk, cargo feature "dpdk").
//!
//! The NIC is driven by a DPDK poll-mode driver instead of the kernel: no skb, no qdisc, no
//! driver interrupts. Everything else stays the same: one sender thread per shard, each with
//! its own TX queue and mbuf pool; frames are copied into mbufs and sent in batches with
//! rte_eth_tx_burst; a full queue is backpressure (the thread retries, like ENOBUFS).
//!
//! The port is set up once before the replay (EAL init, TX queues, start), which also gives
//! the MTU and the link speed. Without the feature every entry point returns an error.

use crate::cli::Opts;
#[cfg(feature = "dpdk")]
use crate::cli::MAX_CPUS;
#[cfg(feature = "dpdk")]
use crate::util::*;

#[derive(Clone, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub name: String,
    pub driver: String,
    pub ntxq: u16,    // TX queues configured (one per sender thread)
    pub nb_desc: u16, // descriptors per TX queue
    pub mtu: u16,
    pub socket: i32,
}

/// The port in use (set once by init).
pub static PORT: std::sync::OnceLock<PortInfo> = std::sync::OnceLock::new();

pub fn port() -> Option<&'static PortInfo> {
    PORT.get()
}

#[cfg(feature = "dpdk")]
pub mod sys;

/// The EAL has been initialized (it must be released at the end).
#[cfg(feature = "dpdk")]
static EAL_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "dpdk")]
mod ffi {
    use std::os::raw::{c_char, c_int, c_uint, c_void};
    extern "C" {
        pub fn rs_dpdk_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
        pub fn rs_dpdk_strerror(e: c_int) -> *const c_char;
        pub fn rs_dpdk_port_count() -> c_uint;
        pub fn rs_dpdk_find_port(name: *const c_char, port: *mut u16) -> c_int;
        pub fn rs_dpdk_port_name(port: u16, buf: *mut c_char, n: usize) -> c_int;
        pub fn rs_dpdk_info(port: u16, max_txq: *mut u16, mtu: *mut u16, socket: *mut c_int, driver: *mut c_char, n: usize) -> c_int;
        pub fn rs_dpdk_link(port: u16, speed: *mut u32, up: *mut c_int) -> c_int;
        pub fn rs_dpdk_setup(port: u16, ntxq: u16, nb_desc: u16, nmbufs: c_uint, data_room: c_uint, mtu: u16, err: *mut c_char, errlen: usize) -> c_int;
        pub fn rs_dpdk_alloc(q: u16, m: *mut *mut c_void, n: c_uint) -> c_int;
        pub fn rs_dpdk_data(m: *mut c_void, len: u32) -> *mut u8;
        pub fn rs_dpdk_tx(port: u16, q: u16, m: *mut *mut c_void, n: u16) -> u16;
        pub fn rs_dpdk_tx_cleanup(port: u16, q: u16);
        pub fn rs_dpdk_free(m: *mut *mut c_void, n: c_uint);
        pub fn rs_dpdk_stats(port: u16, opackets: *mut u64, obytes: *mut u64, oerrors: *mut u64) -> c_int;
        pub fn rs_dpdk_close(port: u16);
        pub fn rs_dpdk_cleanup();
    }
}

#[cfg(feature = "dpdk")]
fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(feature = "dpdk")]
fn dpdk_err(e: i32) -> String {
    unsafe { std::ffi::CStr::from_ptr(ffi::rs_dpdk_strerror(e)) }.to_string_lossy().into_owned()
}

pub const BUILT_WITH_DPDK: bool = cfg!(feature = "dpdk");

#[cfg(feature = "dpdk")]
/// The CPUs near a DPDK port: its PCI device's local_cpulist, or its NUMA node.
fn port_cpus(name: &str, socket: i32, allowed: &libc::cpu_set_t) -> Vec<i32> {
    let isset = |c: i32| c >= 0 && (c as usize) < libc::CPU_SETSIZE as usize && unsafe { libc::CPU_ISSET(c as usize, allowed) };
    let mut lists = vec![format!("/sys/bus/pci/devices/{}/local_cpulist", name)];
    if socket >= 0 {
        lists.push(format!("/sys/devices/system/node/node{}/cpulist", socket));
    }
    for p in lists {
        if let Some(cpus) = std::fs::read_to_string(&p).ok().and_then(|s| parse_cpulist(&s, 1024)) {
            let cpus: Vec<i32> = cpus.into_iter().filter(|&c| isset(c)).take(MAX_CPUS).collect();
            if !cpus.is_empty() {
                return cpus;
            }
        }
    }
    (0..libc::CPU_SETSIZE).filter(|&c| isset(c)).take(MAX_CPUS).collect()
}

/// Initialize the EAL, find and start the port given with --dpdk. Fills in the MTU, the
/// link speed and the CPUs (if not given) so that the rest of the setup works as usual.
#[cfg(feature = "dpdk")]
pub fn init(o: &mut Opts) -> Result<(), String> {
    use std::ffi::CString;
    let want = o.dpdk.clone().unwrap();
    // The EAL pins the calling thread to its main lcore; the replay's own threads choose
    // their CPUs themselves, so the original mask is restored afterwards.
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let sz = std::mem::size_of::<libc::cpu_set_t>();
    unsafe { libc::sched_getaffinity(0, sz, &mut allowed) };
    let first_cpu = (0..libc::CPU_SETSIZE).find(|&c| unsafe { libc::CPU_ISSET(c as usize, &allowed) }).unwrap_or(0);

    // --dpdk-bind / --dpdk-hugepages: prepare the system; restored by shutdown().
    if o.dpdk_bind || o.dpdk_hugepages > 0 {
        let pci = sys::pci_addr(&want).ok_or_else(|| {
            format!("--dpdk-bind/--dpdk-hugepages need the port as a PCI address (0000:3b:00.0), not '{}'", want)
        })?;
        sys::prepare(&pci, o.dpdk_bind, o.dpdk_hugepages)?;
    }

    let user: Vec<String> = o.eal.as_deref().unwrap_or("").split_whitespace().map(String::from).collect();
    let has = |opts: &[&str]| user.iter().any(|a| opts.iter().any(|o| a == o || a.starts_with(&format!("{}=", o))));
    let mut args = vec!["replaystorm".to_string()];
    if !has(&["-l", "--lcores", "-c"]) {
        args.push("-l".into());
        args.push(first_cpu.to_string());
    }
    if !has(&["--in-memory", "--file-prefix", "--no-shconf"]) {
        // No hugepage files and runtime directories left behind. Without hugepages the EAL
        // uses legacy memory, which --in-memory does not allow.
        args.push(if has(&["--no-huge"]) { "--no-shconf" } else { "--in-memory" }.into());
    }
    if !has(&["--log-level"]) {
        args.push("--log-level=5".into()); // warnings and errors only
    }
    args.extend(user);
    log_info!("DPDK: EAL {}", args[1..].join(" "));
    let cargs: Vec<CString> = args.iter().map(|a| CString::new(a.as_str()).unwrap()).collect();
    let mut argv: Vec<*mut std::os::raw::c_char> = cargs.iter().map(|a| a.as_ptr() as *mut _).collect();
    argv.push(std::ptr::null_mut());
    let r = unsafe { ffi::rs_dpdk_init(cargs.len() as i32, argv.as_mut_ptr()) };
    unsafe { libc::sched_setaffinity(0, sz, &allowed) };
    if r < 0 {
        return Err(format!("rte_eal_init: {} (EAL arguments: {})", dpdk_err(r), args[1..].join(" ")));
    }
    EAL_UP.store(true, std::sync::atomic::Ordering::SeqCst);
    if unsafe { ffi::rs_dpdk_port_count() } == 0 {
        return Err("no DPDK ports: bind the NIC to vfio-pci (dpdk-devbind.py -b vfio-pci PCI) or pass a virtual \
                    device with --eal \"--vdev=...\""
            .into());
    }
    let mut port = 0u16;
    let cname = CString::new(want.as_str()).map_err(|_| "bad port name".to_string())?;
    if unsafe { ffi::rs_dpdk_find_port(cname.as_ptr(), &mut port) } != 0 {
        let names: Vec<String> = (0..64u16)
            .filter_map(|p| {
                let mut b = [0u8; 128];
                (unsafe { ffi::rs_dpdk_port_name(p, b.as_mut_ptr() as *mut _, b.len()) } == 0).then(|| format!("{}={}", p, cstr(&b)))
            })
            .collect();
        return Err(format!("DPDK port {} not found (available: {})", want, names.join(", ")));
    }
    let mut name = [0u8; 128];
    unsafe { ffi::rs_dpdk_port_name(port, name.as_mut_ptr() as *mut _, name.len()) };
    let name = cstr(&name);
    let (mut max_txq, mut mtu, mut socket) = (0u16, 0u16, 0i32);
    let mut driver = [0u8; 64];
    let r = unsafe { ffi::rs_dpdk_info(port, &mut max_txq, &mut mtu, &mut socket, driver.as_mut_ptr() as *mut _, driver.len()) };
    if r != 0 {
        return Err(format!("rte_eth_dev_info_get: {}", dpdk_err(r)));
    }
    let driver = cstr(&driver);

    // CPUs and thread count as in the kernel path, but near the port.
    let cpus = match &o.cpus {
        Some(list) => parse_cpulist(list, MAX_CPUS).unwrap_or_default(),
        None => {
            let c = port_cpus(&name, socket, &allowed);
            o.cpus = Some(c.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","));
            c
        }
    };
    let mut ip_threads = if o.threads > 0 { o.threads } else { cpus.len().saturating_sub(1).max(1) };
    if o.threads == 0 && ip_threads + 1 > max_txq as usize && max_txq >= 2 {
        // Without -t: as many sender threads as the port has TX queues.
        ip_threads = max_txq as usize - 1;
        o.threads = ip_threads;
        log_info!("DPDK: port has {} TX queues: {} IP threads + 1 non-IP thread", max_txq, ip_threads);
    }
    let ntxq = ip_threads + 1; // + the non-IP thread
    if ntxq > max_txq as usize {
        return Err(format!(
            "port {} ({}) has {} TX queues, but {} sender threads need one each: use -t {}",
            name,
            driver,
            max_txq,
            ntxq,
            (max_txq as usize).saturating_sub(1).max(1)
        ));
    }
    if o.mtu == 0 {
        o.mtu = mtu as u32;
    }
    let data_room = (o.mtu as usize + 18).max(2048) as u32;
    let nb_desc = o.ring_frames.min(4096) as u16;
    let nmbufs = nb_desc as u32 + 2 * o.batch + 1024;
    let mut err = [0u8; 256];
    let r = unsafe {
        ffi::rs_dpdk_setup(port, ntxq as u16, nb_desc, nmbufs, data_room, o.mtu as u16, err.as_mut_ptr() as *mut _, err.len())
    };
    if r < 0 {
        return Err(format!("port {}: {}", name, cstr(&err)));
    }
    // The link comes up after the start; wait a little for its speed.
    if o.link_speed_bps <= 0.0 {
        for _ in 0..50 {
            if let Some((speed, true)) = link(port) {
                if speed > 0 {
                    o.link_speed_bps = speed as f64 * 1e6;
                    o.link_from_port = true;
                    break;
                }
            }
            sleep_ns(100 * crate::NS_PER_MS);
        }
    }
    let info = PortInfo { port, name, driver, ntxq: ntxq as u16, nb_desc: r as u16, mtu: o.mtu as u16, socket };
    log_info!(
        "DPDK: port {} {} ({}), {} TX queues of {} descriptors, NUMA node {}, link {}",
        info.port,
        info.name,
        info.driver,
        info.ntxq,
        info.nb_desc,
        info.socket,
        match link(port) {
            Some((s, true)) if s > 0 => format!("up, {}", fmt_bps(s as f64 * 1e6)),
            Some((_, true)) => "up".into(),
            _ => "down".into(),
        }
    );
    let _ = PORT.set(info);
    Ok(())
}

#[cfg(not(feature = "dpdk"))]
pub fn init(_o: &mut Opts) -> Result<(), String> {
    Err("this binary is built without DPDK support: build it with make dpdk".into())
}

/// Link speed (Mbit/s, 0 if unknown) and state.
pub fn link(port: u16) -> Option<(u32, bool)> {
    #[cfg(feature = "dpdk")]
    {
        let (mut speed, mut up) = (0u32, 0i32);
        if unsafe { ffi::rs_dpdk_link(port, &mut speed, &mut up) } == 0 {
            return Some((speed, up != 0));
        }
    }
    let _ = port;
    None
}

/// Port counters: packets and errors sent (like tx_packets / tx_dropped of a netdev).
pub fn stats(port: u16) -> Option<(u64, u64)> {
    #[cfg(feature = "dpdk")]
    {
        let (mut p, mut b, mut e) = (0u64, 0u64, 0u64);
        if unsafe { ffi::rs_dpdk_stats(port, &mut p, &mut b, &mut e) } == 0 {
            return Some((p, e));
        }
    }
    let _ = port;
    None
}

/// Stop and close the port, release the EAL, then give the system back what
/// --dpdk-bind / --dpdk-hugepages took (the NIC to its driver, the hugepages).
pub fn shutdown() {
    #[cfg(feature = "dpdk")]
    {
        if let Some(p) = PORT.get() {
            unsafe { ffi::rs_dpdk_close(p.port) };
        }
        if EAL_UP.swap(false, std::sync::atomic::Ordering::SeqCst) {
            unsafe { ffi::rs_dpdk_cleanup() };
        }
        sys::restore();
    }
}

/// A sender thread's TX queue: allocated mbufs ready for frames, and frames not yet sent.
pub struct TxQueue {
    port: u16,
    q: u16,
    stash: Vec<*mut libc::c_void>,
    pending: Vec<*mut libc::c_void>,
    #[cfg_attr(not(feature = "dpdk"), allow(dead_code))]
    batch: usize,
}

unsafe impl Send for TxQueue {}

impl TxQueue {
    pub fn new(port: u16, q: u16, batch: usize) -> TxQueue {
        TxQueue { port, q, stash: Vec::with_capacity(batch), pending: Vec::with_capacity(batch), batch }
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// A free mbuf, None if the pool is empty (all mbufs are queued in the NIC).
    #[inline(always)]
    pub fn alloc(&mut self) -> Option<*mut libc::c_void> {
        if let Some(m) = self.stash.pop() {
            return Some(m);
        }
        #[cfg(feature = "dpdk")]
        {
            // Bulk allocation is all-or-nothing: fall back to smaller requests.
            let mut n = self.batch;
            while n > 0 {
                self.stash.resize(n, std::ptr::null_mut());
                if unsafe { ffi::rs_dpdk_alloc(self.q, self.stash.as_mut_ptr(), n as u32) } == 0 {
                    return self.stash.pop();
                }
                n /= 4;
            }
            self.stash.clear();
        }
        None
    }

    /// Frame buffer of length len in mbuf m.
    ///
    /// # Safety
    /// m must be an mbuf returned by alloc() of this queue, and len must fit its data room.
    #[inline(always)]
    pub unsafe fn data(&self, m: *mut libc::c_void, len: u32) -> *mut u8 {
        #[cfg(feature = "dpdk")]
        return ffi::rs_dpdk_data(m, len);
        #[cfg(not(feature = "dpdk"))]
        {
            let _ = (m, len);
            unreachable!()
        }
    }

    #[inline(always)]
    pub fn push(&mut self, m: *mut libc::c_void) {
        self.pending.push(m);
    }

    /// One rte_eth_tx_burst of the pending frames; returns how many the NIC took.
    pub fn tx(&mut self) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        #[cfg(feature = "dpdk")]
        {
            let n = self.pending.len().min(u16::MAX as usize);
            let sent = unsafe { ffi::rs_dpdk_tx(self.port, self.q, self.pending.as_mut_ptr(), n as u16) } as usize;
            self.pending.drain(..sent);
            sent
        }
        #[cfg(not(feature = "dpdk"))]
        0
    }

    /// Ask the driver to return completed mbufs to the pool.
    pub fn cleanup(&mut self) {
        #[cfg(feature = "dpdk")]
        unsafe {
            ffi::rs_dpdk_tx_cleanup(self.port, self.q)
        };
    }
}

impl Drop for TxQueue {
    fn drop(&mut self) {
        #[cfg(feature = "dpdk")]
        {
            self.stash.append(&mut self.pending);
            if !self.stash.is_empty() {
                unsafe { ffi::rs_dpdk_free(self.stash.as_mut_ptr(), self.stash.len() as u32) };
            }
        }
        let _ = (self.port, self.q);
    }
}
