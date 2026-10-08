//! Replay: thread startup, T0, per-second statistics, the status file, the watchdog,
//! link monitoring and the JSON output.

use crate::cli::{IoMode, LagPolicy, Mode, Opts};
use crate::dio::{Dio, DIO_CHUNK};
use crate::live::Live;
use crate::mutate::MutateCfg;
use crate::prepare::Ctx;
use crate::sched::{lh_quantile, LH_BUCKETS};
use crate::stream::Streamer;
use crate::therm::{Gov, ThermDev, ThermMon};
use crate::util::*;
use crate::worker::*;
use crate::{clock, report, stop_requested, NS_PER_MS, NS_PER_SEC, SKIP_REASONS};
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};

const RLX: Ordering = Ordering::Relaxed;

static WANT_STATUS: AtomicBool = AtomicBool::new(false);
static WANT_RESET: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    crate::STOP.store(true, Ordering::SeqCst);
}

extern "C" fn on_usr1(_: libc::c_int) {
    WANT_STATUS.store(true, Ordering::SeqCst);
}

fn install_signal(sig: libc::c_int, h: extern "C" fn(libc::c_int), flags: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = h as usize;
        sa.sa_flags = flags;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

/* ---------- Link outages and the watchdog ---------- */

#[derive(Default)]
struct LinkState {
    down: bool, // shown in the per-second line
    since: i64,
    outages: u32,
    down_ns: i64,
}

/// Link state from operstate (and from threads waiting in W_LINK). While the link is down
/// the schedule must not run on: when it comes back, T0 is shifted by the outage so the
/// replay continues where it was instead of bursting to catch up.
fn link_check(ls: &mut LinkState, ws: &[WorkerShared], iface: &str, sh: &Shared, now: i64) {
    let mut down = match crate::dpdk::port() {
        Some(p) => crate::dpdk::link(p.port).is_some_and(|(_, up)| !up),
        None => match sysfs_read_str(iface, "operstate") {
            Some(st) => st != "up" && st != "unknown",
            // sysfs works but the interface is gone (driver reload, re-creation)
            None => std::path::Path::new("/sys/class/net/lo").exists(),
        },
    };
    if !down {
        down = ws.iter().any(|w| !w.st.finished.load(RLX) && w.st.state.load(RLX) as usize == W_LINK);
    }
    // A sender thread may already have seen the outage start or end before us.
    if sh.down_since.load(Ordering::SeqCst) != 0 && ls.since == 0 {
        down = true;
    }
    if down && ls.since == 0 {
        ls.since = now;
        ls.outages += 1;
        sh.link_down(now);
        log_warn!("{} is down: waiting for it, the schedule is paused", iface);
    } else if !down && ls.since != 0 {
        let d = now - ls.since;
        sh.link_up(now); // no-op if a sender thread already did it
        ls.down_ns += d;
        ls.since = 0;
        log_warn!("{} is back after {:.1} s, continuing", iface, d as f64 / 1e9);
    }
    ls.down = down;
}

#[derive(Default, Clone)]
struct Stall {
    last_pkts: u64,
    since: i64,
    warned: bool,
}

const STALL_WARN_NS: i64 = 3 * NS_PER_SEC;

/// A thread that sends nothing for a few seconds while not simply waiting for its schedule:
/// say what it waits for, and again when it moves on.
fn watchdog(ws: &[WorkerShared], st: &mut [Stall], stalls: &mut u32, link_down: bool, file_size: u64, now: i64) {
    for (w, s) in ws.iter().zip(st.iter_mut()) {
        if w.st.finished.load(RLX) {
            continue;
        }
        let p = w.st.pkts.load(RLX);
        let state = w.st.state.load(RLX) as usize;
        if s.since == 0 {
            s.since = now;
            s.last_pkts = p;
            continue;
        }
        if p != s.last_pkts || state == W_PACE || link_down {
            if s.warned && p != s.last_pkts {
                log_warn!("thread {} resumed after {:.1} s", w.id, (now - s.since) as f64 / 1e9);
            }
            s.last_pkts = p;
            s.since = now;
            s.warned = false;
            continue;
        }
        if s.warned || now - s.since < STALL_WARN_NS {
            continue;
        }
        s.warned = true;
        *stalls += 1;
        let why = match state {
            W_RING => " (the NIC is not completing transmissions)",
            W_QUEUE => " (ENOBUFS: the device queue stays full)",
            W_DISK => " (the direct I/O window is empty: the disk is too slow)",
            W_FENCE => " (another thread is behind)",
            W_RUN => " (busy without progress)",
            _ => "",
        };
        let g = w.st.gpos.load(RLX);
        log_warn!(
            "thread {} (CPU {}) has sent nothing for {:.0} s: waiting for {}{}, at {:.1}% of the file, lap {}",
            w.id,
            w.cpu,
            (now - s.since) as f64 / 1e9,
            WSTATE_NAMES[if state < W_COUNT { state } else { 0 }],
            why,
            if file_size > 0 { 100.0 * (g % file_size) as f64 / file_size as f64 } else { 0.0 },
            if file_size > 0 { g / file_size + 1 } else { 0 }
        );
    }
}

/* ---------- Snapshots ---------- */

/// Snapshot of all threads' counters.
#[derive(Clone)]
struct Snap {
    pkts: u64,
    bytes: u64,
    sends: u64,
    enobufs: u64,
    eagain: u64,
    asis_back: u64,
    rebases: u64,
    late_max: i64,
    hist: Vec<u64>,
    sys_tx: u64,
    sys_drop: u64,
    disk_bytes: u64,
    disk_reads: u64,
    disk_read_ns: u64,
    gpos_min: u64, // slowest next-read position: lap * size + offset
    disk_temp: i32,
    throttle: u64,
    rate_limit: u64,
    sys_ok: bool,
    pos_min: i64,
    pos_last: i64,
    lap_min: u64,
    lap_last: u64,
    active: u32,
}

struct Io<'a> {
    dio: Option<&'a Dio>,
    therm: Option<&'a ThermMon>,
}

fn take_snap(ws: &[WorkerShared], iface: &str, io: &Io) -> Snap {
    let mut s = Snap {
        pkts: 0,
        bytes: 0,
        sends: 0,
        enobufs: 0,
        eagain: 0,
        asis_back: 0,
        rebases: 0,
        late_max: 0,
        hist: vec![0; LH_BUCKETS],
        sys_tx: 0,
        sys_drop: 0,
        disk_bytes: 0,
        disk_reads: 0,
        disk_read_ns: 0,
        gpos_min: u64::MAX,
        disk_temp: -1,
        throttle: 0,
        rate_limit: 0,
        sys_ok: false,
        pos_min: i64::MAX,
        pos_last: i64::MIN,
        lap_min: u64::MAX,
        lap_last: 0,
        active: 0,
    };
    for w in ws {
        let st = &w.st;
        let lp = st.pos.load(RLX);
        if lp > s.pos_last {
            s.pos_last = lp;
            s.lap_last = st.lap.load(RLX);
        }
        s.pkts += st.pkts.load(RLX);
        s.bytes += st.bytes.load(RLX);
        s.sends += st.sends.load(RLX);
        s.enobufs += st.enobufs.load(RLX);
        s.eagain += st.eagain.load(RLX);
        s.asis_back += st.asis_back.load(RLX);
        s.rebases += st.rebases.load(RLX);
        s.late_max = s.late_max.max(st.late_max.load(RLX));
        for (h, b) in s.hist.iter_mut().zip(w.hist.0.iter()) {
            *h += b.load(RLX);
        }
        if !st.finished.load(Ordering::SeqCst) {
            s.active += 1;
            s.pos_min = s.pos_min.min(st.pos.load(RLX));
            s.lap_min = s.lap_min.min(st.lap.load(RLX));
            s.gpos_min = s.gpos_min.min(st.gpos.load(RLX));
        }
    }
    if let Some(d) = io.dio {
        s.disk_bytes = d.bytes_read.load(RLX);
        s.disk_reads = d.reads.load(RLX);
        s.disk_read_ns = d.read_ns.load(RLX);
        s.rate_limit = d.rate_limit.load(RLX);
    }
    if let Some(t) = io.therm {
        s.disk_temp = t.temp.load(RLX);
        s.throttle = t.throttle.load(RLX);
    }
    let counters = match crate::dpdk::port() {
        Some(p) => crate::dpdk::stats(p.port).map(|(a, b)| (Some(a), Some(b))).unwrap_or((None, None)),
        None => (sysfs_read_u64(iface, "statistics/tx_packets"), sysfs_read_u64(iface, "statistics/tx_dropped")),
    };
    match counters {
        (Some(a), Some(b)) => {
            s.sys_tx = a;
            s.sys_drop = b;
            s.sys_ok = true;
        }
        _ => s.sys_ok = false,
    }
    s
}

/// Where the "sent" and "dropped" counters come from (sysfs of the interface, or the DPDK port).
fn sent_src() -> &'static str {
    if crate::dpdk::port().is_some() {
        "port"
    } else {
        "sysfs"
    }
}

fn drop_short() -> &'static str {
    if crate::dpdk::port().is_some() {
        "oerrors"
    } else {
        "tx_dropped"
    }
}

fn drop_name() -> &'static str {
    if crate::dpdk::port().is_some() {
        "port oerrors"
    } else {
        "interface tx_dropped"
    }
}

/* ---------- Long-run statistics on request ---------- */

/// Commands typed in the terminal while the replay runs.
fn stdin_main() {
    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        match line.trim_end_matches(['\r', '\n']) {
            "" | "s" | "stats" => WANT_STATUS.store(true, Ordering::SeqCst),
            "r" | "reset" => WANT_RESET.store(true, Ordering::SeqCst),
            "q" | "quit" | "stop" => crate::request_stop(),
            _ => println!("commands: Enter or s - long-run statistics, r - reset minimum/maximum, q - stop"),
        }
    }
}

fn fmt_dur(sec: f64) -> String {
    let s = if sec > 0.0 { sec as u64 } else { 0 };
    if s >= 86400 {
        format!("{}d {:02}:{:02}:{:02}", s / 86400, s % 86400 / 3600, s % 3600 / 60, s % 60)
    } else {
        format!("{:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
    }
}

struct Status<'a> {
    c: &'a Ctx,
    live: &'a Live,
    link: &'a LinkState,
    stalls: u32,
    therm: Option<&'a ThermMon>,
}

/// The long-run statistics block (also the content of the status file).
fn status_text(x: &Status, cur: &Snap, start: &Snap, since_t0: i64, finished: bool) -> String {
    use std::fmt::Write as _;
    let l = x.live;
    let mut b = String::new();
    let _ = writeln!(
        b,
        "replaystorm on {}, pid {}: {} for {} (started {}, now {})",
        x.c.o.label(),
        std::process::id(),
        if finished { "finished after running" } else { "running" },
        fmt_dur(since_t0 as f64 / 1e9),
        fmt_local(l.start_real_ns),
        fmt_local(l.start_real_ns + since_t0)
    );
    let _ = write!(b, "  now:          {:.3} Gbit/s, {:.3} Mpps", l.now_gbps, l.now_mpps);
    if cur.disk_temp >= 0 {
        let _ = write!(b, ", disk {} C", cur.disk_temp);
    }
    if x.link.down {
        b += ", LINK DOWN";
    }
    b += "\n";
    if l.seconds > 0 {
        let m = l.ring_n.min(60);
        let _ = writeln!(
            b,
            "  average:      last minute {:.3}, last hour {:.3}, overall {:.3} Gbit/s",
            if m > 0 { l.sum_60 / m as f64 } else { 0.0 },
            if l.ring_n > 0 { l.sum_3600 / l.ring_n as f64 } else { 0.0 },
            l.sum_gbps / l.seconds as f64
        );
        let _ = writeln!(
            b,
            "  minimum 1 s:  {:.3} Gbit/s ({:.3} Mpps min) at +{} ({})",
            l.min_gbps,
            l.min_mpps,
            fmt_dur(l.min_at as f64 / 1e9),
            fmt_local(l.start_real_ns + l.min_at)
        );
        if l.worst_min_at != 0 {
            let _ = writeln!(
                b,
                "  worst minute: {:.3} Gbit/s on average, ended at +{} ({})",
                l.worst_min_gbps,
                fmt_dur(l.worst_min_at as f64 / 1e9),
                fmt_local(l.start_real_ns + l.worst_min_at)
            );
        }
        let _ = writeln!(b, "  maximum 1 s:  {:.3} Gbit/s at +{}", l.max_gbps, fmt_dur(l.max_at as f64 / 1e9));
        let _ = write!(
            b,
            "  1 s rate:     p1 {:.2}, p5 {:.2}, median {:.2} Gbit/s over {} s",
            l.quantile(0.01),
            l.quantile(0.05),
            l.quantile(0.5),
            l.seconds
        );
        if l.target_gbps > 0.0 {
            let _ = write!(
                b,
                "; below 95% of the target ({:.2} Gbit/s): {} s ({:.3}%)",
                0.95 * l.target_gbps,
                l.below_target,
                100.0 * l.below_target as f64 / l.seconds as f64
            );
        }
        b += "\n";
    } else {
        b += "  (no full seconds counted yet: the first 10 s are a warm-up)\n";
    }
    if l.excluded > 0 {
        let _ = writeln!(b, "  not counted:  {} s (warm-up, link outages, partial seconds)", l.excluded);
    }
    if l.reset_ns > l.start_ns {
        let _ = writeln!(b, "  (minimum, maximum and averages since the reset at +{})", fmt_dur(l.reset_ns as f64 / 1e9));
    }
    let lap = if cur.lap_min == u64::MAX { cur.lap_last } else { cur.lap_min };
    let _ = write!(
        b,
        "  sent:         {} packets, {:.3} TB; lap {}; ENOBUFS {}",
        fmt_count(cur.pkts as f64),
        cur.bytes as f64 / 1e12,
        lap + 1,
        cur.enobufs
    );
    if cur.sys_ok && start.sys_ok {
        let _ = write!(b, "; {} +{}", drop_name(), cur.sys_drop.wrapping_sub(start.sys_drop));
    }
    b += "\n";
    let down_ns = x.link.down_ns + if x.link.since != 0 { now_ns() - x.link.since } else { 0 };
    let _ = write!(b, "  events:       link outages {} ({:.1} s)", x.link.outages, down_ns as f64 / 1e9);
    let _ = write!(b, ", stalled-thread warnings {}", x.stalls);
    if let Some(t) = x.therm {
        let _ = write!(b, ", disk max {} C, thermal throttling {}", t.max_temp.load(RLX), t.throttle.load(RLX));
    }
    b += "\n";
    b
}

/// Rewrite the status file atomically so a reader never sees half of it.
fn status_write(path: &str, text: &str) {
    if path.is_empty() {
        return;
    }
    let tmp = format!("{}.tmp", path);
    let ok = File::create(&tmp).and_then(|mut f| f.write_all(text.as_bytes())).is_ok();
    if ok {
        let _ = std::fs::rename(&tmp, path);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Status files matching a path with an optional '*' in the file name (like glob).
fn status_files(pattern: &str) -> Vec<String> {
    let Some(star) = pattern.find('*') else {
        return if std::path::Path::new(pattern).exists() { vec![pattern.to_string()] } else { vec![] };
    };
    let dir = match pattern[..star].rfind('/') {
        Some(i) => &pattern[..i + 1],
        None => "./",
    };
    let prefix = &pattern[dir.len().min(star)..star];
    let suffix = &pattern[star + 1..];
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(prefix) && n.ends_with(suffix) && n.len() >= prefix.len() + suffix.len())
                .map(|n| format!("{}{}", dir, n))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// --status: print the live status of a running replaystorm. Returns the exit code.
pub fn status_query(o: &Opts) -> i32 {
    let label = o.label();
    let path = match &o.status_file {
        Some(f) => f.clone(),
        None if !label.is_empty() => format!("/tmp/replaystorm-{}.status", label),
        None => "/tmp/replaystorm-*.status".to_string(),
    };
    let files = status_files(&path);
    if files.is_empty() {
        log_err!("no status file {}: is replaystorm running (on this interface)?", path);
        return 1;
    }
    for f in files {
        let Ok(buf) = std::fs::read(&f) else { continue };
        let buf = String::from_utf8_lossy(&buf[..buf.len().min(8191)]).into_owned();
        print!("{}", buf);
        if !buf.contains("finished after") {
            if let Ok(age) = std::fs::metadata(&f).and_then(|m| m.modified()).map(|t| t.elapsed().unwrap_or_default()) {
                let age = age.as_secs() as f64;
                if age > 5.0 {
                    println!("  (not updated for {:.0} s: the replay is probably not running any more)", age);
                }
            }
        }
    }
    0
}

/* ---------- JSON ---------- */

fn json_open(c: &Ctx, nw: usize) -> Option<File> {
    let o = &c.o;
    let path = o.stats_json.as_deref().unwrap();
    let mut f = match File::create(path) {
        Ok(f) => f,
        Err(e) => {
            log_err!("failed to open {}: {}", path, e.raw_os_error().map(strerror).unwrap_or_else(|| e.to_string()));
            return None;
        }
    };
    let mut file = String::new();
    for ch in o.file.chars() {
        if ch == '"' || ch == '\\' {
            file.push('\\');
        }
        file.push(ch);
    }
    let _ = write!(
        f,
        "{{\n  \"file\": \"{}\",\n  \"interface\": \"{}\",\n  \"mode\": \"{}\",\n  \"multiplier\": {},\n  \"mbps\": {},\n  \"pps\": {},\n  \"loops\": {},\n  \"threads\": {},\n  \"ip_shards\": {},\n  \"timeline_ns\": {},\n  \"lap_ns\": {},\n  \"intervals\": [",
        file,
        o.label(),
        o.mode.name(),
        fmt_g(c.mult, 9),
        fmt_g(o.mbps, 9),
        fmt_g(o.pps, 9),
        o.loops,
        nw,
        c.ip_threads,
        c.tsr.duration,
        c.tsr.lap_len
    );
    let _ = f.flush();
    Some(f)
}

#[derive(Default)]
struct Row {
    t: f64,
    dt: f64,
    pkts: u64,
    bytes: u64,
    sys_tx: u64,
    sys_drop: u64,
    enobufs: u64,
    eagain: u64,
    sends: u64,
    disk: u64,
    disk_lat_ms: f64, // mean duration of one 32 MB direct read
    file_pct: f64,    // slowest thread's position in the file, % (-1: unknown)
    disk_temp: i32,   // C, -1 unknown
    throttled: u64,   // new thermal throttling transitions during the interval
    rate_limit: u64,  // governor read limit, bytes/s (0 = none)
    file_lap: u64,
    sys_ok: bool,
    p50: u64,
    p99: u64,
    pmax: u64,
    late_n: u64,
    timed: bool,
    pos_s: f64,
    lap: u64,
}

fn json_row(f: &mut File, first: bool, r: &Row, dio_on: bool) {
    let mut s = format!(
        "{}\n    {{\"t\": {:.3}, \"pkts\": {}, \"bytes\": {}, \"gbps\": {:.6}, \"mpps\": {:.6}, \"sends\": {}, \"enobufs\": {}, \"eagain\": {}",
        if first { "" } else { "," },
        r.t,
        r.pkts,
        r.bytes,
        r.bytes as f64 * 8.0 / r.dt / 1e9,
        r.pkts as f64 / r.dt / 1e6,
        r.sends,
        r.enobufs,
        r.eagain
    );
    if r.sys_ok {
        s += &format!(", \"sys_tx_packets\": {}, \"sys_tx_dropped\": {}", r.sys_tx, r.sys_drop);
    }
    if dio_on {
        s += &format!(", \"disk_gbytes_per_s\": {:.3}, \"disk_read_ms\": {:.2}", r.disk as f64 / r.dt / 1e9, r.disk_lat_ms);
    }
    if r.file_pct >= 0.0 {
        s += &format!(", \"file_pct\": {:.2}, \"file_lap\": {}", r.file_pct, r.file_lap);
    }
    if r.disk_temp >= 0 {
        s += &format!(
            ", \"disk_temp_c\": {}, \"disk_throttle_events\": {}, \"disk_read_limit_gbytes_per_s\": {:.3}",
            r.disk_temp,
            r.throttled,
            r.rate_limit as f64 / 1e9
        );
    }
    if r.timed {
        s += &format!(
            ", \"late_p50_ns\": {}, \"late_p99_ns\": {}, \"late_max_ns\": {}, \"pcap_pos_s\": {:.6}, \"lap\": {}",
            r.p50, r.p99, r.pmax, r.pos_s, r.lap
        );
    }
    s += "}";
    let _ = f.write_all(s.as_bytes());
    let _ = f.flush();
}

/* ---------- Output ---------- */

fn print_row(r: &Row, c: &Ctx, dio_on: bool, link_down: bool) {
    let mut s = format!(
        "[{:>7.1} s] {:>8} Gbit/s {:>8} Mpps",
        r.t,
        format!("{:.3}", r.bytes as f64 * 8.0 / r.dt / 1e9),
        format!("{:.3}", r.pkts as f64 / r.dt / 1e6)
    );
    if r.sys_ok {
        s += &format!(" | sent ({}) {:.3} Mpps, {} +{}", sent_src(), r.sys_tx as f64 / r.dt / 1e6, drop_short(), r.sys_drop);
    } else {
        s += if crate::dpdk::port().is_some() { " | port counters unavailable" } else { " | sysfs unavailable" };
    }
    s += &format!(" | ENOBUFS +{} EAGAIN +{}", r.enobufs, r.eagain);
    if dio_on {
        s += &format!(" | disk {:.2} GB/s, {:.0} ms/read", r.disk as f64 / r.dt / 1e9, r.disk_lat_ms);
    }
    if r.disk_temp >= 0 {
        s += &format!(", {} C", r.disk_temp);
    }
    if r.rate_limit > 0 {
        s += &format!(", limit {:.2} GB/s", r.rate_limit as f64 / 1e9);
    }
    if r.throttled > 0 {
        s += " THROTTLED";
    }
    if !r.timed && r.file_pct >= 0.0 {
        s += &format!(" | file {:.1}% lap {}", r.file_pct, r.file_lap + 1);
    }
    if link_down {
        s += " | LINK DOWN";
    }
    if r.timed {
        if r.late_n > 0 {
            s += &format!(
                " | lateness p50 {} p99 {} max {}",
                fmt_ns(r.p50 as f64),
                fmt_ns(r.p99 as f64),
                fmt_ns(r.pmax as f64)
            );
        }
        s += &format!(" | pcap +{:.3} s of {}", r.pos_s, fmt_ns(c.tsr.duration as f64));
        if c.o.loops != 1 {
            s += &format!(", lap {}", r.lap + 1);
        }
    }
    println!("{}", s);
}

fn make_row(cur: &Snap, prev: &Snap, t: f64, dt: f64, c: &Ctx) -> Row {
    let mut r = Row {
        t,
        dt: if dt > 0.0 { dt } else { 1.0 },
        pkts: cur.pkts - prev.pkts,
        bytes: cur.bytes - prev.bytes,
        sends: cur.sends - prev.sends,
        enobufs: cur.enobufs - prev.enobufs,
        eagain: cur.eagain - prev.eagain,
        disk: cur.disk_bytes - prev.disk_bytes,
        file_pct: -1.0,
        disk_temp: cur.disk_temp,
        throttled: cur.throttle.wrapping_sub(prev.throttle),
        rate_limit: cur.rate_limit,
        ..Default::default()
    };
    let nr = cur.disk_reads - prev.disk_reads;
    r.disk_lat_ms = if nr > 0 { (cur.disk_read_ns - prev.disk_read_ns) as f64 / nr as f64 / 1e6 } else { 0.0 };
    let size = c.pf.size as u64;
    if cur.gpos_min != u64::MAX && size > 0 {
        r.file_lap = cur.gpos_min / size;
        r.file_pct = 100.0 * (cur.gpos_min % size) as f64 / size as f64;
    }
    r.sys_ok = cur.sys_ok && prev.sys_ok;
    if r.sys_ok {
        r.sys_tx = cur.sys_tx.wrapping_sub(prev.sys_tx);
        r.sys_drop = cur.sys_drop.wrapping_sub(prev.sys_drop);
    }
    r.timed = c.o.mode == Mode::Timed;
    if r.timed {
        let h: Vec<u64> = cur.hist.iter().zip(&prev.hist).map(|(a, b)| a - b).collect();
        r.late_n = h.iter().sum();
        r.p50 = lh_quantile(&h, 0.5);
        r.p99 = lh_quantile(&h, 0.99);
        r.pmax = lh_quantile(&h, 1.0);
        if cur.pos_min != i64::MAX {
            let lap = cur.lap_min;
            r.pos_s = (cur.pos_min - lap as i64 * c.tsr.lap_len) as f64 / 1e9;
            r.lap = lap;
        } else if cur.pos_last != i64::MIN {
            // All threads finished or stopped: final position.
            r.lap = cur.lap_last;
            r.pos_s = (cur.pos_last - r.lap as i64 * c.tsr.lap_len) as f64 / 1e9;
        }
    }
    r
}

struct Summary<'a> {
    c: &'a Ctx,
    ws: &'a [WorkerShared],
    skipped: u64,
    truncated: u64,
    live: Option<&'a Live>,
}

#[allow(clippy::too_many_arguments)]
fn print_summary(x: &Summary, end: &Snap, start: &Snap, elapsed: f64, json: Option<&mut File>, stopped: bool, shift: i64) {
    let c = x.c;
    let (pkts, bytes) = (end.pkts, end.bytes);
    let gbps = if elapsed > 0.0 { bytes as f64 * 8.0 / elapsed / 1e9 } else { 0.0 };
    let mpps = if elapsed > 0.0 { pkts as f64 / elapsed / 1e6 } else { 0.0 };
    println!("\n=== Summary{} ===", if stopped { " (stopped by signal)" } else { "" });
    println!(
        "Sent to {}: {} packets ({}), {} bytes in {:.3} s: {:.3} Gbit/s, {:.3} Mpps",
        if crate::dpdk::port().is_some() { "the port" } else { "kernel" },
        pkts,
        fmt_count(pkts as f64),
        bytes,
        elapsed,
        gbps,
        mpps
    );
    if end.sys_ok && start.sys_ok {
        let d = end.sys_tx.wrapping_sub(start.sys_tx);
        println!(
            "Sent per {}: {} ({:+.0} vs sent; other traffic on the {} is counted too), {}: +{}",
            if crate::dpdk::port().is_some() { "port counters (opackets)" } else { "sysfs tx_packets" },
            d,
            d as f64 - pkts as f64,
            if crate::dpdk::port().is_some() { "port" } else { "interface" },
            drop_short(),
            end.sys_drop.wrapping_sub(start.sys_drop)
        );
    } else {
        println!("{}", if crate::dpdk::port().is_some() { "Port statistics unavailable" } else { "Interface statistics unavailable in sysfs" });
    }
    println!(
        "{}: {} calls ({:.1} frames per call), {}: {}, EAGAIN: {}",
        if crate::dpdk::port().is_some() { "rte_eth_tx_burst()" } else { "send()" },
        end.sends,
        if end.sends > 0 { pkts as f64 / end.sends as f64 } else { 0.0 },
        if crate::dpdk::port().is_some() { "TX queue full" } else { "ENOBUFS" },
        end.enobufs,
        end.eagain
    );
    println!("Skipped frames (per lap): {}, truncated at capture: {}", x.skipped, x.truncated);
    let late_n: u64 = end.hist.iter().sum();
    let timed = c.o.mode == Mode::Timed;
    if timed && late_n > 0 {
        println!(
            "Lateness vs schedule: p50 {}, p99 {}, p99.9 {}, max {}",
            fmt_ns(lh_quantile(&end.hist, 0.5) as f64),
            fmt_ns(lh_quantile(&end.hist, 0.99) as f64),
            fmt_ns(lh_quantile(&end.hist, 0.999) as f64),
            fmt_ns(end.late_max as f64)
        );
        if end.rebases > 0 {
            println!("T0 shifts (rebase): {}, total shift {:.3} ms", end.rebases, shift as f64 / 1e6);
        }
        if end.asis_back > 0 {
            println!("Sent without waiting (backward in time, asis): {}", end.asis_back);
        }
    }
    println!("Per thread:");
    for w in x.ws {
        let st = &w.st;
        let mut line = format!(
            "  {} {:>2} (CPU {:>3}): {:>12} packets, {:>14} bytes, ENOBUFS {}",
            if w.is_l2 { "non-IP" } else { "thread" },
            w.id,
            w.cpu,
            st.pkts.load(RLX),
            st.bytes.load(RLX),
            st.enobufs.load(RLX)
        );
        // Where the thread spent its time waiting.
        let mut any = false;
        for k in W_PACE..W_COUNT {
            let sec = st.wait_ns[k].load(RLX) as f64 / 1e9;
            if sec < 0.05 {
                continue;
            }
            line += &format!("{}{} {:.1} s", if any { ", " } else { "; waited for: " }, WSTATE_NAMES[k], sec);
            any = true;
        }
        let lost = st.link_lost.load(RLX);
        if lost > 0 {
            line += &format!("; lost on interface re-creation: {}", lost);
        }
        println!("{}", line);
    }
    if let Some(json) = json {
        let mut s = format!(
            "\n  ],\n  \"summary\": {{\"stopped\": {}, \"elapsed_s\": {:.6}, \"pkts\": {}, \"bytes\": {}, \"gbps\": {:.6}, \"mpps\": {:.6}, \"sends\": {}, \"enobufs\": {}, \"eagain\": {}, \"skipped\": {}, \"truncated_caplen\": {}",
            stopped, elapsed, pkts, bytes, gbps, mpps, end.sends, end.enobufs, end.eagain, x.skipped, x.truncated
        );
        if end.sys_ok && start.sys_ok {
            s += &format!(
                ", \"sys_tx_packets\": {}, \"sys_tx_dropped\": {}",
                end.sys_tx.wrapping_sub(start.sys_tx),
                end.sys_drop.wrapping_sub(start.sys_drop)
            );
        }
        if timed && late_n > 0 {
            s += &format!(
                ", \"late_p50_ns\": {}, \"late_p99_ns\": {}, \"late_p999_ns\": {}, \"late_max_ns\": {}, \"rebases\": {}, \"asis_backward\": {}",
                lh_quantile(&end.hist, 0.5),
                lh_quantile(&end.hist, 0.99),
                lh_quantile(&end.hist, 0.999),
                end.late_max,
                end.rebases,
                end.asis_back
            );
        }
        if let Some(l) = x.live.filter(|l| l.seconds > 0) {
            s += &format!(
                ", \"rate_avg_gbps\": {:.4}, \"rate_min_gbps\": {:.4}, \"rate_min_at_s\": {:.1}, \"rate_worst_minute_gbps\": {:.4}, \"rate_p1_gbps\": {:.2}, \"rate_p5_gbps\": {:.2}, \"rate_median_gbps\": {:.2}, \"seconds_counted\": {}, \"seconds_below_target\": {}",
                l.sum_gbps / l.seconds as f64,
                l.min_gbps,
                l.min_at as f64 / 1e9,
                l.worst_min_gbps,
                l.quantile(0.01),
                l.quantile(0.05),
                l.quantile(0.5),
                l.seconds,
                l.below_target
            );
        }
        s += ", \"per_thread\": [";
        const KEYS: [&str; W_COUNT] = ["send", "schedule", "tx_ring", "device_queue", "disk", "fence", "link"];
        for (i, w) in x.ws.iter().enumerate() {
            let st = &w.st;
            s += &format!(
                "{}{{\"id\": {}, \"non_ip\": {}, \"cpu\": {}, \"pkts\": {}, \"bytes\": {}, \"enobufs\": {}, \"link_lost\": {}, \"wait_s\": {{",
                if i > 0 { ", " } else { "" },
                w.id,
                w.is_l2,
                w.cpu,
                st.pkts.load(RLX),
                st.bytes.load(RLX),
                st.enobufs.load(RLX),
                st.link_lost.load(RLX)
            );
            for k in W_PACE..W_COUNT {
                s += &format!(
                    "{}\"{}\": {:.3}",
                    if k > W_PACE { ", " } else { "" },
                    KEYS[k],
                    st.wait_ns[k].load(RLX) as f64 / 1e9
                );
            }
            s += "}}";
        }
        s += "]}\n}\n";
        let _ = json.write_all(s.as_bytes());
        let _ = json.flush();
    }
}

fn print_plan(c: &Ctx, ws: &[WorkerShared]) {
    let o = &c.o;
    log_info!(
        "File {}: {} packets to send, index {} in {}",
        o.file,
        c.tsr.n,
        if c.index_cached { "loaded from cache" } else { "built" },
        fmt_ns(c.index_ns as f64)
    );
    match o.mode {
        Mode::Topspeed => log_info!("Mode: top speed"),
        Mode::Mbps => log_info!("Mode: fixed rate {} (packets paced in file order)", fmt_bps(o.mbps * 1e6)),
        Mode::Pps => log_info!("Mode: fixed rate {}pps", fmt_count(o.pps)),
        Mode::Timed => log_info!(
            "Mode: timestamps x{}, timeline {} -> {} per lap, lag-policy={}",
            g(c.mult),
            fmt_ns(c.tsr.duration as f64),
            fmt_ns(c.tsr.duration as f64 / c.mult),
            if o.lag_policy == LagPolicy::Rebase { "rebase" } else { "catchup" }
        ),
    }
    let mut cpus = String::new();
    for (i, w) in ws.iter().enumerate() {
        if cpus.len() >= 248 {
            break;
        }
        if i > 0 {
            cpus.push(',');
        }
        cpus += &w.cpu.to_string();
    }
    let link = if c.link_bps > 0.0 { fmt_bps(c.link_bps) } else { "?".into() };
    let numa = if c.cpus_from_numa { ", NIC NUMA node" } else { "" };
    if let Some(p) = crate::dpdk::port() {
        log_info!(
            "DPDK port {} {} ({}), MTU {}, link {} ({}); {} threads (CPU {}{}), one TX queue each, batch {}, \
             {} TX descriptors per queue",
            p.port,
            p.name,
            p.driver,
            c.mtu,
            link,
            c.link_src,
            ws.len(),
            cpus,
            numa,
            o.batch,
            p.nb_desc
        );
    } else {
        log_info!(
            "Interface {}, MTU {}, link {} ({}); {} threads (CPU {}{}), qdisc-bypass {}, packet-loss {}, batch {}, ring {} frames",
            o.iface.as_deref().unwrap_or(""),
            c.mtu,
            link,
            c.link_src,
            ws.len(),
            cpus,
            numa,
            if o.qdisc_bypass { "on" } else { "off" },
            if o.packet_loss { "on" } else { "off" },
            o.batch,
            o.ring_frames
        );
    }
    if o.loops == 0 {
        log_info!("Loops: infinite (until SIGINT/SIGTERM)");
    } else if o.loops > 1 {
        log_info!("Loops: {}", o.loops);
    }
}

fn spawn_or_die<'scope, 'env, F>(s: &'scope std::thread::Scope<'scope, 'env>, name: String, f: F) -> std::thread::ScopedJoinHandle<'scope, ()>
where
    F: FnOnce() + Send + 'scope,
{
    match std::thread::Builder::new().name(name).spawn_scoped(s, f) {
        Ok(h) => h,
        Err(_) => {
            log_err!("failed to create a thread");
            // Already created threads may wait on a barrier sized for all of them: they
            // cannot be joined cleanly, so exit abruptly.
            unsafe { libc::_exit(1) };
        }
    }
}

/// Replay; returns the exit code.
pub fn run(c: &mut Ctx) -> i32 {
    report::warnings(c);
    let ixlock = RwLock::new(std::mem::take(&mut c.ix));
    let c: &Ctx = c;
    let o = &c.o;
    let iface = o.label();
    let (shard_pkts, ixst) = {
        let ix = ixlock.read().unwrap();
        (ix.shard_pkts.clone(), ix.st)
    };
    let ncpus = c.cpus.len();

    // Threads: one per non-empty IP shard plus a separate one for non-IP.
    if c.ip_threads > ncpus {
        log_warn!("more threads ({}) than CPUs ({}): several threads share a core", c.ip_threads, ncpus);
    } else if shard_pkts[c.ip_threads] > 0 && c.ip_threads == ncpus {
        log_warn!(
            "the non-IP thread shares CPU {} with thread 0 ({} IP threads on {} CPUs); use -t {} to give it its own core",
            c.cpus[0],
            c.ip_threads,
            ncpus,
            if c.ip_threads > 1 { c.ip_threads - 1 } else { 1 }
        );
    }
    let ws: Vec<WorkerShared> = (0..shard_pkts.len())
        .filter(|&s| shard_pkts[s] > 0)
        .map(|s| WorkerShared::new(s, c.cpus[s % ncpus], s == c.ip_threads))
        .collect();
    let nw = ws.len();
    let mut_cfg = MutateCfg {
        ip: o.mutate_ip,
        port: o.mutate_port,
        ip_offset: o.mutate_ip_offset,
        port_step: o.mutate_port_step,
        raw_ip: 0,
    };
    print_plan(c, &ws);
    log_info!("Clock: {}", clock::init(o.clock_mode));

    install_signal(libc::SIGINT, on_signal, 0);
    install_signal(libc::SIGTERM, on_signal, 0);
    install_signal(libc::SIGUSR1, on_usr1, libc::SA_RESTART);

    let sh = Shared::new(nw + 1);
    // Filled in between the start barriers; the threads borrow them.
    let dio_cell: OnceLock<Dio> = OnceLock::new();
    let therm_cell: OnceLock<ThermMon> = OnceLock::new();
    let stream_cell: OnceLock<Streamer> = OnceLock::new();
    let setup: OnceLock<Setup> = OnceLock::new();
    let mut rc = 0;

    std::thread::scope(|s| {
        let mut workers = Vec::new();
        for w in &ws {
            let name = if w.is_l2 { "rs-l2".to_string() } else { format!("rs-tx{}", w.id) };
            let (ixl, wsr, shr, setr) = (&ixlock, &ws[..], &sh, &setup);
            workers.push(spawn_or_die(s, name, move || worker_main(c, ixl, w, wsr, shr, setr, mut_cfg)));
        }

        sh.bar.wait(); // 1
        // Threads have copied their shards; the global index is no longer needed.
        ixlock.write().unwrap().free_arrays();
        if o.drop_behind > 0 && ws.iter().any(|w| w.mlock_failed.load(RLX)) {
            log_warn!(
                "could not lock the packet index in RAM (mlock); with a file larger than RAM it may be \
                 swapped out. Run as root or raise ulimit -l"
            );
        }
        // Threads stay within half the window of the slowest one.
        let mut readahead = o.readahead;
        let lead = (readahead / 2).max(256 << 20);
        // Direct I/O: reader threads fill a RAM window with O_DIRECT, bypassing the page cache.
        let mut dio_t0 = 0;
        let want_dio = !c.pf.preloaded && (o.io_mode == IoMode::Direct || (o.io_mode == IoMode::Auto && c.big_file));
        // The window must fit into free memory (the index is already loaded and locked).
        if want_dio {
            let avail = mem_available();
            let cap = if avail > 3 << 30 { avail - (2 << 30) } else { 1 << 30 };
            if avail > 0 && readahead > cap {
                log_warn!(
                    "--readahead {:.1} GB does not fit into free memory ({:.1} GB available); using {:.1} GB",
                    readahead as f64 / (1u64 << 30) as f64,
                    avail as f64 / (1u64 << 30) as f64,
                    cap as f64 / (1u64 << 30) as f64
                );
                readahead = cap;
            }
        }
        // Disk temperature: shown in the statistics, used by --disk-max-temp/--disk-start-temp.
        if !c.pf.preloaded {
            match ThermDev::open(&o.file) {
                Ok((dev, desc)) => {
                    let _ = therm_cell.set(ThermMon::new(dev));
                    log_info!("Disk: {}", desc);
                }
                Err(why) => {
                    if o.disk_max_temp > 0 || o.disk_start_temp > 0 {
                        log_warn!("disk temperature unavailable ({}); --disk-max-temp/--disk-start-temp are ignored", why);
                    }
                }
            }
        }
        let therm = therm_cell.get();
        if let (Some(t), true) = (therm, o.disk_start_temp > 0) {
            let mut last_msg = 0;
            loop {
                match t.read() {
                    Some((temp, _)) if temp > o.disk_start_temp => {
                        if stop_requested() {
                            break;
                        }
                        if now_ns() - last_msg > 5 * NS_PER_SEC {
                            log_info!("Waiting for the disk to cool down: {} C, start at {} C", temp, o.disk_start_temp);
                            last_msg = now_ns();
                        }
                        sleep_ns(NS_PER_SEC);
                    }
                    _ => break,
                }
            }
        }
        let mut aux = Vec::new(); // reader, monitor and streamer threads
        let mut therm_started = false;
        if want_dio {
            match Dio::open(&o.file, c.pf.size as u64, readahead, o.io_threads, o.loops) {
                Err(e) => log_warn!("direct I/O unavailable ({}); reading through the page cache", e),
                Ok(d) => {
                    let d = dio_cell.get_or_init(|| d);
                    for _ in 0..d.nreaders {
                        let wsr = &ws[..];
                        aux.push(spawn_or_die(s, "rs-dio".into(), move || d.reader_main(wsr)));
                    }
                    dio_t0 = now_ns();
                    if !d.locked {
                        log_warn!(
                            "could not lock the direct I/O window in RAM (mlock); it may be swapped out under memory pressure"
                        );
                    }
                    if let Some(t) = therm {
                        t.governor.store(o.disk_max_temp > 0, RLX);
                        *t.gov.lock().unwrap() = Gov::new(o.disk_max_temp);
                        t.prime();
                        therm_started = true;
                        aux.push(spawn_or_die(s, "rs-therm".into(), move || {
                            t.run(Some(&d.rate_limit), Some(&d.bytes_read))
                        }));
                        if o.disk_max_temp > 0 {
                            log_info!(
                                "Thermal governor: keep the disk at or below {} C by limiting the read rate",
                                o.disk_max_temp
                            );
                        }
                    }
                    let wnd = d.nslots as f64 * DIO_CHUNK as f64;
                    let sec = d.prefill(300.0);
                    log_info!(
                        "Direct I/O: window {:.1} GB ({} x 32 MB), {} reader threads; filled in {:.1} s ({:.2} GB/s)",
                        wnd / (1u64 << 30) as f64,
                        d.nslots,
                        d.nreaders,
                        sec,
                        if sec > 0.0 { d.bytes_read.load(RLX) as f64 / sec / 1e9 } else { 0.0 }
                    );
                }
            }
        }
        let dio = dio_cell.get();
        if let (Some(t), false) = (therm, therm_started) {
            if o.disk_max_temp > 0 {
                log_warn!("--disk-max-temp works with direct I/O only (--io direct)");
            }
            t.prime();
            aux.push(spawn_or_die(s, "rs-therm".into(), move || t.run(None, None)));
        }
        // Streaming of the file: readahead ahead of the senders, drop-behind for big files.
        let mut fence = None;
        if dio.is_some() {
            fence = Some(lead);
        } else if !c.pf.preloaded {
            let st = stream_cell.get_or_init(|| Streamer::new(&c.pf, &ws, readahead, o.drop_behind > 0));
            aux.push(spawn_or_die(s, "rs-stream".into(), move || st.run()));
            log_info!(
                "File streaming: readahead {:.1} GB, drop-behind {}",
                readahead as f64 / (1u64 << 30) as f64,
                if st.drop_behind { "on (file larger than free RAM)" } else { "off" }
            );
            fence = Some(lead);
        }
        let _ = setup.set(Setup { dio, fence_lead: fence });
        let io = Io { dio, therm };
        // Is something else already sending on this interface (another replayer, for
        // example)? It would share the link with us and distort every rate we report.
        if let Some(a) = sysfs_read_u64(&iface, "statistics/tx_packets") {
            sleep_ns(300 * NS_PER_MS);
            if let Some(b) = sysfs_read_u64(&iface, "statistics/tx_packets") {
                let pps = b.saturating_sub(a) as f64 / 0.3;
                if pps > 10000.0 {
                    log_warn!(
                        "{} is already sending {}pps before the start: another program (another replayer?) \
                         shares the link, and the rates below will be lower; \"sent (sysfs)\" includes its traffic",
                        iface,
                        fmt_count(pps)
                    );
                }
            }
        }
        let start = take_snap(&ws, &iface, &io);
        let t0 = now_ns() + 20 * NS_PER_MS;
        sh.t0.store(t0, Ordering::SeqCst);
        sh.bar.wait(); // 2

        let stop_aux = || {
            if let Some(st) = stream_cell.get() {
                st.stop.store(true, Ordering::SeqCst);
            }
            if let Some(d) = dio {
                d.stop.store(true, Ordering::SeqCst);
            }
            if let Some(t) = therm {
                t.stop.store(true, Ordering::SeqCst);
            }
        };
        if sh.failed.load(Ordering::SeqCst) {
            for h in workers {
                let _ = h.join();
            }
            stop_aux();
            for h in aux {
                let _ = h.join();
            }
            for w in &ws {
                let e = w.err.lock().unwrap();
                if !e.is_empty() {
                    log_err!("{}", e);
                }
            }
            rc = 1;
            return;
        }

        let mut json = if o.stats_json.is_some() { json_open(c, nw) } else { None };
        if o.stats_json.is_some() && json.is_none() {
            crate::request_stop();
        }

        let mut prev = start.clone();
        let mut cur;
        let mut tick = t0;
        let mut last = t0;
        let mut stalls = vec![Stall::default(); nw];
        let mut nstalls = 0u32;
        let mut link = LinkState::default();
        // Long-run statistics: on request in the terminal, by SIGUSR1, and in a status file.
        let mut live = Live::new(if o.mode == Mode::Mbps { o.mbps / 1000.0 } else { 0.0 }, t0, realtime_ns() + (t0 - now_ns()));
        let status_path = o.status_file.clone().unwrap_or_else(|| format!("/tmp/replaystorm-{}.status", iface));
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
            let _ = std::thread::Builder::new().name("rs-stdin".into()).spawn(stdin_main);
        }
        log_info!(
            "Long-run statistics: press Enter here, or from another terminal: replaystorm --status {} (file {}), or kill -USR1 {}",
            match &o.dpdk {
                Some(p) => format!("--dpdk {}", p),
                None => format!("-i {}", iface),
            },
            status_path,
            std::process::id()
        );
        let mut first_row = true;
        loop {
            tick += NS_PER_SEC;
            // Sleep until the next second, but wake earlier if all threads have finished.
            loop {
                let now = now_ns();
                if now >= tick || ws.iter().all(|w| w.st.finished.load(Ordering::SeqCst)) {
                    break;
                }
                sleep_ns((tick - now).min(20 * NS_PER_MS));
            }
            let now = now_ns();
            cur = take_snap(&ws, &iface, &io);
            link_check(&mut link, &ws, &iface, &sh, now);
            watchdog(&ws, &mut stalls, &mut nstalls, link.down, c.pf.size as u64, now);
            if now - last >= NS_PER_SEC / 2 || cur.active == 0 {
                let r = make_row(&cur, &prev, (now - t0) as f64 / 1e9, (now - last) as f64 / 1e9, c);
                if !o.quiet {
                    print_row(&r, c, dio.is_some(), link.down);
                }
                if let Some(j) = json.as_mut() {
                    json_row(j, first_row, &r, dio.is_some());
                    first_row = false;
                }
                live.add(now - t0, r.dt, r.bytes as f64 * 8.0 / r.dt / 1e9, r.pkts as f64 / r.dt / 1e6, link.down);
                prev = cur.clone();
                last = now;
            }
            if WANT_RESET.swap(false, Ordering::SeqCst) {
                live.reset(now - t0);
                println!("Long-run statistics reset");
            }
            let text = status_text(&Status { c, live: &live, link: &link, stalls: nstalls, therm }, &cur, &start, now - t0, false);
            status_write(&status_path, &text);
            if WANT_STATUS.swap(false, Ordering::SeqCst) {
                print!("----\n{}----\n", text);
                let _ = std::io::stdout().flush();
            }
            if cur.active == 0 {
                break;
            }
        }
        let mut t_end = t0;
        for h in workers {
            let _ = h.join();
        }
        for w in &ws {
            t_end = t_end.max(w.st.t_end.load(RLX));
        }
        stop_aux();
        for h in aux {
            let _ = h.join();
        }
        // Wait for interface counters to catch up (frames may still be queued).
        sleep_ns(100 * NS_PER_MS);
        cur = take_snap(&ws, &iface, &io);
        let stopped = stop_requested() && !sh.failed.load(Ordering::SeqCst);
        let summary = Summary {
            c,
            ws: &ws,
            skipped: ixst.skipped.iter().take(SKIP_REASONS).sum(),
            truncated: ixst.truncated_caplen,
            live: Some(&live),
        };
        print_summary(&summary, &cur, &start, (t_end - t0) as f64 / 1e9, json.as_mut(), stopped, sh.shift.load(RLX));
        if link.since != 0 {
            link.down_ns += now_ns() - link.since;
            link.since = 0;
        }
        if link.outages > 0 {
            println!(
                "Link outages: {}, {:.1} s in total (the schedule was paused for that time)",
                link.outages,
                link.down_ns as f64 / 1e9
            );
        }
        let text = status_text(&Status { c, live: &live, link: &link, stalls: nstalls, therm }, &cur, &start, t_end - t0, true);
        status_write(&status_path, &text);
        print!("Long-run statistics:\n{}", text);
        let fwaits: u64 = ws.iter().map(|w| w.st.fence_waits.load(RLX)).sum();
        if fwaits > 0 {
            println!(
                "Threads waited {} times for the slowest one (kept within half the readahead window)",
                fwaits
            );
        }
        if let Some(d) = dio {
            let dw: u64 = ws.iter().map(|w| w.st.dio_waits.load(RLX)).sum();
            let secs = (t_end - dio_t0) as f64 / 1e9;
            let br = d.bytes_read.load(RLX) as f64;
            println!(
                "Direct I/O: read {:.1} GB, {:.2} GB/s on average; senders waited for data {} times, readers waited for the slowest sender {} times",
                br / 1e9,
                if secs > 0.0 { br / secs / 1e9 } else { 0.0 },
                dw,
                d.reader_waits.load(RLX)
            );
            if d.failed.load(Ordering::SeqCst) {
                log_err!("{}", d.err.lock().unwrap());
                rc = 1;
            }
        }
        if let Some(t) = therm {
            let mut line = format!(
                "Disk temperature: max {} C, thermal throttling events during the run: {}",
                t.max_temp.load(RLX),
                t.throttle.load(RLX)
            );
            if t.governor.load(RLX) {
                let lim = dio.map_or(0, |d| d.rate_limit.load(RLX));
                if lim > 0 {
                    line += &format!(", governor read limit at the end: {:.2} GB/s", lim as f64 / 1e9);
                } else {
                    line += ", governor read limit at the end: none";
                }
            }
            println!("{}", line);
        }
        if let Some(st) = stream_cell.get() {
            println!(
                "File streaming: requested ahead {:.1} GB, dropped from page cache {:.1} GB, pages pre-mapped by {}",
                st.ra_bytes.load(RLX) as f64 / 1e9,
                st.dropped_bytes.load(RLX) as f64 / 1e9,
                if st.populate_madvise.load(RLX) {
                    "MADV_POPULATE_READ"
                } else {
                    "touching (kernel without MADV_POPULATE_READ)"
                }
            );
        }
        for w in &ws {
            let e = w.err.lock().unwrap();
            if !e.is_empty() {
                log_err!("{}", e);
                rc = 1;
            }
        }
        if sh.failed.load(Ordering::SeqCst) {
            rc = 1;
        }
    });
    rc
}

/// Analysis (--analyze) of a prepared context.
pub fn analyze(c: &Ctx) {
    report::analysis(c);
    report::warnings(c);
}

