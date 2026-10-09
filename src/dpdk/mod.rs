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
    pub zc_capable: bool, // zero-copy pools are set up
    pub zc_multi: bool,   // the driver sends multi-segment frames (header + file data)
}

/// Zero-copy is active: frames are sent straight from the preloaded file.
static ZERO_COPY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The registered file: (address, registered length, DMA-mapped length, mapped for DMA).
#[cfg(feature = "dpdk")]
static EXTMEM: std::sync::Mutex<Option<(usize, usize, usize, bool)>> = std::sync::Mutex::new(None);
/// The port has been stopped and closed.
#[cfg(feature = "dpdk")]
static CLOSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn zero_copy() -> bool {
    ZERO_COPY.load(std::sync::atomic::Ordering::Relaxed)
}

/// Zero-copy frames may have a copied header segment in front of the file data.
pub fn zero_copy_multi() -> bool {
    zero_copy() && PORT.get().is_some_and(|p| p.zc_multi)
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
        pub fn rs_dpdk_info(port: u16, max_txq: *mut u16, max_desc: *mut u16, mtu: *mut u16, socket: *mut c_int, driver: *mut c_char, n: usize) -> c_int;
        pub fn rs_dpdk_link(port: u16, speed: *mut u32, up: *mut c_int) -> c_int;
        pub fn rs_dpdk_setup(port: u16, ntxq: u16, nb_desc: u16, nmbufs: c_uint, data_room: c_uint, mtu: u16, zc: c_int, zc_ok: *mut c_int, err: *mut c_char, errlen: usize) -> c_int;
        pub fn rs_dpdk_alloc_zc(q: u16, m: *mut *mut c_void, n: c_uint) -> c_int;
        pub fn rs_dpdk_attach(m: *mut c_void, addr: *const u8, len: u32);
        pub fn rs_dpdk_chain(head: *mut c_void, tail: *mut c_void);
        pub fn rs_dpdk_extmem(port: u16, addr: *mut u8, len: usize, dma_len: usize, page_sz: usize, err: *mut c_char, errlen: usize) -> c_int;
        pub fn rs_dpdk_extmem_release(port: u16, addr: *mut u8, len: usize, dma_len: usize, mapped: c_int);
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
    let given = o.dpdk.clone().unwrap();
    // An interface name is turned into the NIC's PCI address (DPDK knows no interface names).
    let resolved = sys::resolve(&given)?;
    // A NIC given by interface name or PCI address: say which it is, and check that DPDK
    // can use it with its current driver.
    let want = match &resolved {
        Some((pci, iface)) => {
            if !std::path::Path::new(&format!("/sys/bus/pci/devices/{}", pci)).exists() {
                return Err(format!("PCI device {} not found (lspci -D, dpdk-devbind.py -s)", pci));
            }
            let drv = sys::driver_of(pci).unwrap_or_default();
            let iface = iface.clone().or_else(|| sys::netdev_of(pci));
            log_info!(
                "DPDK: NIC {}{}{}",
                pci,
                iface.as_ref().map(|i| format!(", interface {}", i)).unwrap_or_default(),
                if drv.is_empty() { ", no driver".to_string() } else { format!(", driver {}", drv) }
            );
            // Only vfio/uio drivers (and mlx5, which works next to its kernel driver) are
            // usable by DPDK.
            let usable = matches!(drv.as_str(), "vfio-pci" | "uio_pci_generic" | "igb_uio" | "mlx5_core");
            if !usable && !o.dpdk_bind {
                return Err(format!(
                    "{} is {}: add --dpdk-bind to move it to vfio-pci for the run, or bind it yourself \
                     (dpdk-devbind.py -b vfio-pci {})",
                    pci,
                    if drv.is_empty() { "not bound to any driver".to_string() } else { format!("driven by the kernel ({})", drv) },
                    pci
                ));
            }
            pci.clone()
        }
        None => given.clone(),
    };
    // The EAL pins the calling thread to its main lcore; the replay's own threads choose
    // their CPUs themselves, so the original mask is restored afterwards.
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let sz = std::mem::size_of::<libc::cpu_set_t>();
    unsafe { libc::sched_getaffinity(0, sz, &mut allowed) };
    // The EAL main lcore (only the setup and control run there) on a CPU near the NIC.
    let isset = |c: i32| c >= 0 && (c as usize) < libc::CPU_SETSIZE as usize && unsafe { libc::CPU_ISSET(c as usize, &allowed) };
    let local: Vec<i32> = match &resolved {
        Some((pci, _)) => pci_local_cpus(pci).into_iter().filter(|&c| isset(c)).collect(),
        None => Vec::new(),
    };
    let first_cpu = local
        .first()
        .copied()
        .or_else(|| (0..libc::CPU_SETSIZE as i32).find(|&c| isset(c)))
        .unwrap_or(0);

    // --dpdk-bind / --dpdk-hugepages: prepare the system; restored by shutdown().
    if o.dpdk_bind || o.dpdk_hugepages > 0 {
        let pci = sys::pci_addr(&want).ok_or_else(|| {
            format!("--dpdk-bind/--dpdk-hugepages need a PCI NIC (interface name or PCI address), not '{}'", want)
        })?;
        sys::prepare(&pci, o.dpdk_bind, o.dpdk_bind_group, o.dpdk_hugepages)?;
    }

    let user: Vec<String> = o.eal.as_deref().unwrap_or("").split_whitespace().map(String::from).collect();
    let has = |opts: &[&str]| user.iter().any(|a| opts.iter().any(|o| a == o || a.starts_with(&format!("{}=", o))));
    let mut args = vec!["replaystorm".to_string()];
    // Probe only this NIC (otherwise the EAL takes every device bound to vfio-pci).
    if resolved.is_some() && !has(&["-a", "--allow", "-b", "--block", "--no-pci"]) {
        args.push("-a".into());
        args.push(want.clone());
    }
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
    let mut max_desc = 0u16;
    let r = unsafe {
        ffi::rs_dpdk_info(port, &mut max_txq, &mut max_desc, &mut mtu, &mut socket, driver.as_mut_ptr() as *mut _, driver.len())
    };
    if r != 0 {
        return Err(format!("rte_eth_dev_info_get: {}", dpdk_err(r)));
    }
    let driver = cstr(&driver);

    // CPUs and thread count as in the kernel path, but near the port.
    let cpus = match &o.cpus {
        Some(list) => {
            let c = parse_cpulist(list, MAX_CPUS).unwrap_or_default();
            warn_remote_cpus(&c, &local, &name);
            c
        }
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
    let nb_desc = tx_descriptors(o, max_desc, ntxq, data_room, &driver);
    let nmbufs = nb_desc as u32 + 2 * o.batch + 1024;
    let mut err = [0u8; 256];
    // Zero-copy needs the whole file in memory for the run (--preload).
    let want_zc = o.preload && o.zero_copy;
    let mut zc_ok = 0i32;
    let r = unsafe {
        ffi::rs_dpdk_setup(port, ntxq as u16, nb_desc, nmbufs, data_room, o.mtu as u16, want_zc as i32, &mut zc_ok,
                           err.as_mut_ptr() as *mut _, err.len())
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
    if want_zc && zc_ok == 0 {
        log_warn!(
            "{}: the driver cannot send multi-segment frames: zero-copy only for frames that are sent \
             unchanged (no --loop-mutate laps, no RAW IP)",
            driver
        );
    }
    let info = PortInfo {
        port,
        name,
        driver,
        ntxq: ntxq as u16,
        nb_desc: r as u16,
        mtu: o.mtu as u16,
        socket,
        zc_capable: want_zc,
        zc_multi: zc_ok != 0,
    };
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

/// Memory of one mbuf in the pool: data room, headroom, the mbuf and the pool's own header.
#[cfg(feature = "dpdk")]
const MBUF_OVERHEAD: u64 = 128 + 128 + 64;

/// Free hugepage memory (default hugepage size), bytes.
#[cfg(feature = "dpdk")]
fn hugepages_free() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else { return 0 };
    let field = |name: &str| -> u64 {
        s.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.split_whitespace().next()?.parse().ok())
            .unwrap_or(0)
    };
    field("HugePages_Free:") * field("Hugepagesize:") * 1024
}

/// TX descriptors per queue: --ring-frames if given, else the NIC's maximum, as far as the
/// mbuf pools of all queues fit into the free hugepages.
#[cfg(feature = "dpdk")]
fn tx_descriptors(o: &Opts, max_desc: u16, ntxq: usize, data_room: u32, driver: &str) -> u16 {
    let max = if max_desc == 0 { 4096 } else { max_desc as u32 };
    if o.ring_frames_set {
        return o.ring_frames.min(max).min(u16::MAX as u32) as u16;
    }
    // mlx5 stops inlining frame headers into the descriptors of a large queue (txq_inline
    // 290 -> 12 bytes), and the NIC then fetches every header with a separate DMA read.
    if driver.starts_with("mlx5") {
        return max.min(4096) as u16;
    }
    let per = data_room as u64 + MBUF_OVERHEAD;
    let pool = |d: u32| (d as u64 + 2 * o.batch as u64 + 1024) * per * ntxq as u64;
    let free = hugepages_free();
    if free == 0 {
        return max.min(4096) as u16; // no hugepages (--no-huge): memory size unknown, stay modest
    }
    let mut d = max.min(32768);
    // Leave a quarter of the hugepages to the EAL and the driver.
    while d > 1024 && pool(d) > free / 4 * 3 {
        d /= 2;
    }
    if d < max.min(32768) {
        log_info!(
            "DPDK: {} TX descriptors per queue (the NIC allows {}; more need more hugepages: {:.1} GB for {} queues)",
            d,
            max,
            pool(max.min(32768)) as f64 / 0.75 / (1u64 << 30) as f64,
            ntxq
        );
    }
    d as u16
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
            if !CLOSED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                // Closing frees the frames still queued, before their memory goes away.
                unsafe { ffi::rs_dpdk_close(p.port) };
                if let Some((addr, len, dma_len, mapped)) = EXTMEM.lock().unwrap().take() {
                    unsafe { ffi::rs_dpdk_extmem_release(p.port, addr as *mut u8, len, dma_len, mapped as i32) };
                }
            }
        }
        if EAL_UP.swap(false, std::sync::atomic::Ordering::SeqCst) {
            unsafe { ffi::rs_dpdk_cleanup() };
        }
        sys::restore();
    }
}

/// Zero-copy: register the preloaded file (aligned start, aligned length; the first
/// mapped_len bytes are mapped) with the port, so that frames can point into it. Returns
/// whether zero-copy is on.
pub fn register_file(span: (*mut u8, usize), mapped_len: usize) -> bool {
    #[cfg(feature = "dpdk")]
    {
        let Some(p) = PORT.get().filter(|p| p.zc_capable) else { return false };
        let (addr, len) = span;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let dma_len = mapped_len.div_ceil(page) * page;
        let mut err = [0u8; 256];
        let t0 = now_ns();
        let r = unsafe {
            ffi::rs_dpdk_extmem(p.port, addr, len, dma_len, crate::pcap::PRELOAD_ALIGN, err.as_mut_ptr() as *mut _, err.len())
        };
        if r < 0 {
            log_warn!("zero-copy is off: {}", cstr(&err));
            return false;
        }
        *EXTMEM.lock().unwrap() = Some((addr as usize, len, dma_len, r == 0));
        ZERO_COPY.store(true, std::sync::atomic::Ordering::SeqCst);
        log_info!(
            "DPDK: zero-copy: frames are sent straight from the preloaded file ({:.1} GB {} in {:.1} s)",
            mapped_len as f64 / 1e9,
            if r == 0 { "registered for DMA" } else { "used by the driver as is" },
            (now_ns() - t0) as f64 / 1e9
        );
        true
    }
    #[cfg(not(feature = "dpdk"))]
    {
        let _ = (span, mapped_len);
        false
    }
}

/// A sender thread's TX queue: allocated mbufs ready for frames, and frames not yet sent.
pub struct TxQueue {
    port: u16,
    q: u16,
    stash: Vec<*mut libc::c_void>,
    zc_stash: Vec<*mut libc::c_void>, // mbufs of the zero-copy pool
    pending: Vec<*mut libc::c_void>,
    #[cfg_attr(not(feature = "dpdk"), allow(dead_code))]
    batch: usize,
}

unsafe impl Send for TxQueue {}

impl TxQueue {
    pub fn new(port: u16, q: u16, batch: usize) -> TxQueue {
        TxQueue {
            port,
            q,
            stash: Vec::with_capacity(batch),
            zc_stash: Vec::with_capacity(batch),
            pending: Vec::with_capacity(batch),
            batch,
        }
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
        return refill(&mut self.stash, self.batch, |m, n| unsafe { ffi::rs_dpdk_alloc(self.q, m, n) });
        #[cfg(not(feature = "dpdk"))]
        None
    }

    /// A free mbuf of the zero-copy pool (no data room: it points into the file).
    #[inline(always)]
    pub fn alloc_zc(&mut self) -> Option<*mut libc::c_void> {
        if let Some(m) = self.zc_stash.pop() {
            return Some(m);
        }
        #[cfg(feature = "dpdk")]
        return refill(&mut self.zc_stash, self.batch, |m, n| unsafe { ffi::rs_dpdk_alloc_zc(self.q, m, n) });
        #[cfg(not(feature = "dpdk"))]
        None
    }

    /// Point zero-copy mbuf m at len bytes of the preloaded file.
    ///
    /// # Safety
    /// m comes from alloc_zc(); addr..addr+len lies in the registered file.
    #[inline(always)]
    pub unsafe fn attach(&self, m: *mut libc::c_void, addr: *const u8, len: u32) {
        #[cfg(feature = "dpdk")]
        ffi::rs_dpdk_attach(m, addr, len);
        #[cfg(not(feature = "dpdk"))]
        let _ = (m, addr, len);
    }

    /// Chain a copied header (head) and the rest of the frame (tail) into one frame.
    ///
    /// # Safety
    /// head and tail are mbufs of this queue's pools, with their lengths set.
    #[inline(always)]
    pub unsafe fn chain(&self, head: *mut libc::c_void, tail: *mut libc::c_void) {
        #[cfg(feature = "dpdk")]
        ffi::rs_dpdk_chain(head, tail);
        #[cfg(not(feature = "dpdk"))]
        let _ = (head, tail);
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

    /// Give back an allocated zero-copy mbuf that was not used.
    pub fn push_free(&mut self, m: *mut libc::c_void) {
        self.zc_stash.push(m);
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

/// Refill a stash with a bulk allocation (all-or-nothing: fall back to smaller requests).
#[cfg(feature = "dpdk")]
#[inline(never)]
fn refill(stash: &mut Vec<*mut libc::c_void>, batch: usize, alloc: impl Fn(*mut *mut libc::c_void, u32) -> i32) -> Option<*mut libc::c_void> {
    let mut n = batch;
    while n > 0 {
        stash.resize(n, std::ptr::null_mut());
        if alloc(stash.as_mut_ptr(), n as u32) == 0 {
            return stash.pop();
        }
        n /= 4;
    }
    stash.clear();
    None
}

impl Drop for TxQueue {
    fn drop(&mut self) {
        #[cfg(feature = "dpdk")]
        {
            self.stash.append(&mut self.pending);
            self.stash.append(&mut self.zc_stash);
            if !self.stash.is_empty() {
                unsafe { ffi::rs_dpdk_free(self.stash.as_mut_ptr(), self.stash.len() as u32) };
            }
        }
        let _ = (self.port, self.q);
    }
}
