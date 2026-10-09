//! Logging, option value parsers, sysfs readers and formatting.

use crate::NS_PER_SEC;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

pub static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::Relaxed);
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

pub fn log_err_str(msg: &str) {
    eprintln!("replaystorm: error: {}", msg);
}

pub fn log_warn_str(msg: &str) {
    eprintln!("WARNING: {}", msg);
}

pub fn log_info_str(msg: &str) {
    if quiet() {
        return;
    }
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", msg);
    let _ = out.flush();
}

#[macro_export]
macro_rules! log_err {
    ($($a:tt)*) => { $crate::util::log_err_str(&format!($($a)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($($a:tt)*) => { $crate::util::log_warn_str(&format!($($a)*)) };
}
#[macro_export]
macro_rules! log_info {
    ($($a:tt)*) => { $crate::util::log_info_str(&format!($($a)*)) };
}

/* ---------- Clocks ---------- */

#[inline(always)]
pub fn now_ns() -> i64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

pub fn realtime_ns() -> i64 {
    clock_ns(libc::CLOCK_REALTIME)
}

#[inline(always)]
fn clock_ns(id: libc::clockid_t) -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as i64 * NS_PER_SEC + ts.tv_nsec as i64
}

#[inline(always)]
pub fn cpu_relax() {
    std::hint::spin_loop();
}

/// nanosleep for a relative time (interrupted sleeps are not resumed).
pub fn sleep_ns(ns: i64) {
    if ns <= 0 {
        return;
    }
    let ts = libc::timespec { tv_sec: (ns / NS_PER_SEC) as libc::time_t, tv_nsec: (ns % NS_PER_SEC) as _ };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn strerror(e: i32) -> String {
    std::io::Error::from_raw_os_error(e).to_string().split(" (os error").next().unwrap_or("").to_string()
}

/* ---------- Parsers ---------- */

/// strtod-like: the longest prefix that is a decimal floating point number, and the rest.
/// Leading whitespace is skipped. inf/nan are not accepted.
pub fn strtod_prefix(s: &str) -> Option<(f64, &str)> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || (b'\t'..=b'\r').contains(&b[i])) {
        i += 1;
    }
    let start = i;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let mut digits = i - int_start;
    if i < b.len() && b[i] == b'.' {
        let f = i + 1;
        let mut j = f;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        digits += j - f;
        if digits > 0 {
            i = j;
        }
    }
    if digits == 0 {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let e = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j > e {
            i = j;
        }
    }
    let v: f64 = s[start..i].parse().ok()?;
    Some((v, &s[i..]))
}

pub fn parse_double(s: &str) -> Option<f64> {
    match strtod_prefix(s) {
        Some((d, "")) if d.is_finite() => Some(d),
        _ => None,
    }
}

pub fn parse_u64(s: &str) -> Option<u64> {
    if s.starts_with('-') {
        return None;
    }
    let t = s.trim_start();
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// "1.5s", "10ms", "200us", "500ns", "2m", "1h"; a number without a suffix means seconds.
pub fn parse_duration(s: &str) -> Option<i64> {
    let (d, end) = strtod_prefix(s)?;
    if d < 0.0 || !d.is_finite() {
        return None;
    }
    let m = match end {
        "" | "s" => 1e9,
        "ms" => 1e6,
        "us" => 1e3,
        "ns" => 1.0,
        "m" => 60e9,
        "h" => 3600e9,
        _ => return None,
    };
    let r = d * m;
    if r > 9e18 {
        return None;
    }
    Some(r.round() as i64)
}

/// "25G", "10000M", "1.5g"; a number without a suffix means bit/s.
pub fn parse_bitrate(s: &str) -> Option<f64> {
    let (d, end) = strtod_prefix(s)?;
    if d <= 0.0 || !d.is_finite() {
        return None;
    }
    let m = match end.to_ascii_lowercase().as_str() {
        "" => 1.0,
        "k" => 1e3,
        "m" => 1e6,
        "g" => 1e9,
        _ => return None,
    };
    Some(d * m)
}

/// "2G", "512M", "64K"; a number without a suffix means bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let (d, end) = strtod_prefix(s)?;
    if d < 0.0 || !d.is_finite() {
        return None;
    }
    let m = match end.to_ascii_lowercase().as_str() {
        "" => 1.0,
        "k" => 1024.0,
        "m" => 1024.0 * 1024.0,
        "g" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((d * m) as u64)
}

pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 8 || !p.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let v = u32::from_str_radix(p, 16).ok()?;
        if v > 0xFF {
            return None;
        }
        mac[i] = v as u8;
    }
    Some(mac)
}

/// Dotted IPv4 address in host byte order.
pub fn parse_ipv4(s: &str) -> Option<u32> {
    s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

/// CPU list of the form "0-3,8,10-11".
pub fn parse_cpulist(s: &str, max: usize) -> Option<Vec<i32>> {
    let mut cpus = Vec::new();
    let b = s.as_bytes();
    let mut p = 0;
    let skip_ws = |p: &mut usize| {
        while *p < b.len() && (b[*p] == b' ' || b[*p] == b'\n') {
            *p += 1;
        }
    };
    let num = |p: &mut usize| -> Option<i64> {
        let st = *p;
        while *p < b.len() && b[*p].is_ascii_digit() {
            *p += 1;
        }
        if *p == st {
            return None;
        }
        s[st..*p].parse().ok()
    };
    while p < b.len() {
        skip_ws(&mut p);
        if p >= b.len() {
            break;
        }
        let a = num(&mut p)?;
        let mut e = a;
        if p < b.len() && b[p] == b'-' {
            p += 1;
            e = num(&mut p)?;
            if e < a {
                return None;
            }
        }
        for c in a..=e {
            if cpus.len() >= max {
                return None;
            }
            cpus.push(c as i32);
        }
        skip_ws(&mut p);
        if p < b.len() && b[p] == b',' {
            p += 1;
        } else if p < b.len() {
            return None;
        }
    }
    Some(cpus)
}

fn read_sysfs(path: &str) -> Option<String> {
    let s = std::fs::read(path).ok()?;
    if s.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&s).into_owned())
}

/// CPUs of the NIC's NUMA node (or all CPUs available to the process), and whether they
/// came from the NUMA node.
pub fn iface_cpus(iface: Option<&str>, max: usize) -> (Vec<i32>, bool) {
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut allowed) };
    let setsize = libc::CPU_SETSIZE as i32;
    let isset = |c: i32| c >= 0 && c < setsize && unsafe { libc::CPU_ISSET(c as usize, &allowed) };
    if let Some(iface) = iface {
        if let Some(buf) = read_sysfs(&format!("/sys/class/net/{}/device/local_cpulist", iface)) {
            if let Some(list) = parse_cpulist(&buf, 1024) {
                let cpus: Vec<i32> = list.into_iter().filter(|&c| isset(c)).take(max).collect();
                if !cpus.is_empty() {
                    return (cpus, true);
                }
            }
        }
    }
    ((0..setsize).filter(|&c| isset(c)).take(max).collect(), false)
}

/// CPUs of the PCI device's NUMA node (its local_cpulist), empty if unknown.
pub fn pci_local_cpus(pci: &str) -> Vec<i32> {
    read_sysfs(&format!("/sys/bus/pci/devices/{}/local_cpulist", pci))
        .and_then(|s| parse_cpulist(&s, 1024))
        .unwrap_or_default()
}

/// Warn when --cpus puts sender threads on CPUs far from the NIC (another NUMA node):
/// every frame then crosses the interconnect between the sockets.
pub fn warn_remote_cpus(cpus: &[i32], local: &[i32], nic: &str) {
    if local.is_empty() {
        return;
    }
    let remote: Vec<String> = cpus.iter().filter(|c| !local.contains(c)).map(|c| c.to_string()).collect();
    if remote.is_empty() {
        return;
    }
    let mut near: Vec<String> = local.iter().map(|c| c.to_string()).collect();
    near.truncate(64);
    log_warn!(
        "--cpus: CPUs {} are not on the NUMA node of {}; the CPUs near it are {}. Leave out --cpus to use them",
        remote.join(","),
        nic,
        near.join(",")
    );
}

pub fn sysfs_read_str(iface: &str, attr: &str) -> Option<String> {
    let s = read_sysfs(&format!("/sys/class/net/{}/{}", iface, attr))?;
    Some(s.split('\n').next().unwrap_or("").to_string())
}

pub fn sysfs_read_u64(iface: &str, attr: &str) -> Option<u64> {
    let s = read_sysfs(&format!("/sys/class/net/{}/{}", iface, attr))?;
    let t = s.trim_start();
    let end = t.find(|c: char| !(c.is_ascii_digit() || c == '-' || c == '+')).unwrap_or(t.len());
    let v: i64 = t[..end].parse().ok()?;
    if v < 0 {
        return None;
    }
    Some(v as u64)
}

pub fn iface_mtu(iface: &str) -> Option<u32> {
    match sysfs_read_u64(iface, "mtu") {
        Some(v) if v > 0 && v <= 65535 => Some(v as u32),
        _ => None,
    }
}

/// Link speed in bit/s. /sys/.../speed reports the same value as ethtool (Mbit/s).
pub fn iface_speed(iface: &str) -> Option<f64> {
    match sysfs_read_u64(iface, "speed") {
        Some(v) if v > 0 && v < 0xFFFF_FFFF => Some(v as f64 * 1e6),
        _ => None,
    }
}

/// MemAvailable from /proc/meminfo in bytes, 0 if unknown.
pub fn mem_available() -> u64 {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else { return 0 };
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

/* ---------- Formatting ---------- */

/// "23.41 Gbit/s"
pub fn fmt_bps(bps: f64) -> String {
    if bps >= 1e9 {
        format!("{:.2} Gbit/s", bps / 1e9)
    } else if bps >= 1e6 {
        format!("{:.2} Mbit/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.2} Kbit/s", bps / 1e3)
    } else {
        format!("{:.0} bit/s", bps)
    }
}

/// "1.20 us" / "3.4 ms"
pub fn fmt_ns(ns: f64) -> String {
    let a = ns.abs();
    if a >= 86400e9 {
        format!("{:.2} days", ns / 86400e9)
    } else if a >= 3600e9 {
        format!("{:.2} h", ns / 3600e9)
    } else if a >= 1e9 {
        format!("{:.3} s", ns / 1e9)
    } else if a >= 1e6 {
        format!("{:.2} ms", ns / 1e6)
    } else if a >= 1e3 {
        format!("{:.2} us", ns / 1e3)
    } else {
        format!("{:.0} ns", ns)
    }
}

/// "1.23 M"
pub fn fmt_count(v: f64) -> String {
    if v >= 1e9 {
        format!("{:.2} G", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.2} M", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.2} K", v / 1e3)
    } else {
        format!("{:.0}", v)
    }
}

fn tm_of(sec: i64, local: bool) -> Option<libc::tm> {
    let t = sec as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = unsafe {
        if local {
            libc::localtime_r(&t, &mut tm)
        } else {
            libc::gmtime_r(&t, &mut tm)
        }
    };
    if r.is_null() {
        None
    } else {
        Some(tm)
    }
}

fn fmt_tm(tm: &libc::tm) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year as i64 + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// "2024-05-01 12:00:03.123456789 UTC"
pub fn fmt_abs_ts(ns: i64) -> String {
    let mut sec = ns / NS_PER_SEC;
    let mut frac = ns % NS_PER_SEC;
    if frac < 0 {
        frac += NS_PER_SEC;
        sec -= 1;
    }
    match tm_of(sec, false) {
        Some(tm) => format!("{}.{:09} UTC", fmt_tm(&tm), frac),
        None => format!("{} ns", ns),
    }
}

/// Local time "2024-05-01 12:00:03" of a CLOCK_REALTIME value.
pub fn fmt_local(real_ns: i64) -> String {
    match tm_of(real_ns / NS_PER_SEC, true) {
        Some(tm) => fmt_tm(&tm),
        None => "?".to_string(),
    }
}

/// C printf "%.<prec>g".
pub fn fmt_g(v: f64, prec: usize) -> String {
    if v.is_nan() {
        return "nan".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let p = if prec == 0 { 1 } else { prec };
    if v == 0.0 {
        return if v.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let e = format!("{:.*e}", p - 1, v);
    let (mant, exp) = e.split_once('e').unwrap();
    let x: i32 = exp.parse().unwrap();
    let strip = |s: String| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s
        }
    };
    if x < -4 || x >= p as i32 {
        let m = strip(mant.to_string());
        format!("{}e{}{:02}", m, if x < 0 { '-' } else { '+' }, x.abs())
    } else {
        strip(format!("{:.*}", (p as i32 - 1 - x) as usize, v))
    }
}

/// C printf "%g".
pub fn g(v: f64) -> String {
    fmt_g(v, 6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printf_g() {
        assert_eq!(g(1.0), "1");
        assert_eq!(g(0.5), "0.5");
        assert_eq!(g(20.0), "20");
        assert_eq!(g(1234567.0), "1.23457e+06");
        assert_eq!(g(0.0001), "0.0001");
        assert_eq!(g(0.00001), "1e-05");
        assert_eq!(fmt_g(99.0, 4), "99");
        assert_eq!(fmt_g(1.0 / 3.0, 9), "0.333333333");
        assert_eq!(fmt_g(100.0, 2), "1e+02");
    }

    #[test]
    fn parsers() {
        assert_eq!(parse_duration("1.5s"), Some(1_500_000_000));
        assert_eq!(parse_duration("10ms"), Some(10_000_000));
        assert_eq!(parse_duration("2m"), Some(120_000_000_000));
        assert_eq!(parse_duration("5"), Some(5_000_000_000));
        assert_eq!(parse_duration("5x"), None);
        assert_eq!(parse_duration("-1s"), None);
        assert_eq!(parse_bitrate("25G"), Some(25e9));
        assert_eq!(parse_size("2G"), Some(2 << 30));
        assert_eq!(parse_u64("12"), Some(12));
        assert_eq!(parse_u64("-1"), None);
        assert_eq!(parse_u64("1x"), None);
        assert_eq!(parse_double("99.5"), Some(99.5));
        assert_eq!(parse_double(".5"), Some(0.5));
        assert_eq!(parse_double("inf"), None);
        assert_eq!(parse_mac("02:00:00:00:00:0a"), Some([2, 0, 0, 0, 0, 10]));
        assert_eq!(parse_mac("02:00:00:00:00"), None);
        assert_eq!(parse_ipv4("0.1.0.0"), Some(0x10000));
        assert_eq!(parse_cpulist("0-3,8", 64), Some(vec![0, 1, 2, 3, 8]));
        assert_eq!(parse_cpulist("3-1", 64), None);
    }
}
