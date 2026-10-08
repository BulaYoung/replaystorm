//! NVMe temperature and a thermal governor for disk reads.
//!
//! A pcap much larger than RAM is read from disk for every lap. Sustained reads at the
//! drive's limit heat it up until it enters thermal throttling (Thermal Management T1)
//! and drops to a fraction of its speed for tens of seconds. The governor keeps the
//! drive just below a target temperature by limiting the direct I/O read rate, which
//! turns "full speed, then a collapse" into a steady rate the cooling can sustain.

use crate::util::{errno, now_ns, strerror};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Mutex;

const THERM_MAX_DEVS: usize = 8;
const GOV_MIN_RATE: f64 = 200.0 * 1024.0 * 1024.0; // bytes/s: never throttle reads below this

/* ---------- Governor (pure, unit-tested) ---------- */

#[derive(Clone, Debug, Default)]
pub struct Gov {
    pub target: i32,   // keep the drive at or below this temperature, C
    pub limit: f64,    // current read rate limit, bytes/s; 0 = unlimited
    prev_temp: i32,
    max_seen: f64,     // highest measured read rate
}

impl Gov {
    pub fn new(target: i32) -> Gov {
        Gov { target, limit: 0.0, prev_temp: -1, max_seen: 0.0 }
    }

    /// One step per second: temperature now and bytes/s read during the last second.
    /// Returns the new limit in bytes/s (0 = unlimited).
    pub fn step(&mut self, temp: i32, measured_bps: f64) -> f64 {
        let tgt = self.target;
        let rising = self.prev_temp >= 0 && temp > self.prev_temp;
        let falling = self.prev_temp >= 0 && temp < self.prev_temp;
        self.prev_temp = temp;
        if measured_bps > self.max_seen {
            self.max_seen = measured_bps;
        }
        if self.limit == 0.0 {
            // Unlimited until the drive gets close to the target; then start from the rate
            // it is reading at right now.
            if temp < tgt - 2 {
                return 0.0;
            }
            self.limit = measured_bps.max(GOV_MIN_RATE);
        }
        // The drive heats and cools over tens of seconds, so steps are small and react to
        // the trend as well as to the level.
        if temp >= tgt + 1 {
            self.limit *= 0.80;
        } else if temp >= tgt {
            self.limit *= 0.92;
        } else if temp == tgt - 1 {
            self.limit *= if rising { 0.97 } else { 1.0 };
        } else if temp == tgt - 2 {
            self.limit *= if rising { 1.0 } else { 1.02 };
        } else {
            self.limit *= if falling { 1.06 } else { 1.04 };
        }
        if self.limit < GOV_MIN_RATE {
            self.limit = GOV_MIN_RATE;
        }
        // Well below the target and above anything the disk has done: lift the limit.
        if temp <= tgt - 4 && self.max_seen > 0.0 && self.limit > self.max_seen * 1.1 {
            self.limit = 0.0;
        }
        self.limit
    }
}

/* ---------- Temperature ---------- */

pub struct ThermDev {
    fd: Vec<i32>,         // /dev/nvmeX for the SMART log (ioctl), or -1
    hwmon: Vec<String>,   // sysfs temp1_input, or ""
    name: Vec<String>,
    pub have_t1: bool,    // T1 counters readable (ioctl)
}

/// nvme0n1 -> nvme0 (controller of a namespace block device).
fn nvme_controller(disk: &str) -> Option<String> {
    let rest = disk.strip_prefix("nvme")?;
    let k = rest.bytes().take_while(|c| c.is_ascii_digit()).count();
    if k == 0 {
        return None;
    }
    Some(format!("nvme{}", &rest[..k]))
}

fn find_hwmon(dir: &str) -> Option<String> {
    let rd = std::fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("hwmon") {
            return Some(format!("{}/{}/temp1_input", dir, name));
        }
    }
    None
}

fn realpath(p: &str) -> Option<String> {
    std::fs::canonicalize(p).ok().map(|p| p.to_string_lossy().into_owned())
}

fn exists(p: &str) -> bool {
    std::path::Path::new(p).exists()
}

/// Strip the last path component.
fn dirname(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[..i],
        None => p,
    }
}

fn basename(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// Block device of the mount holding path, from /proc/self/mountinfo (longest mount point
/// that is a prefix of the file's real path).
fn mount_source_dev(path: &str) -> Option<libc::dev_t> {
    let rp = realpath(path)?;
    let mi = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut best_src = String::new();
    let mut best_len = 0;
    for line in mi.lines() {
        // id parent major:minor root mountpoint options ... - fstype source superopts
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        let mnt = f[4];
        let Some(dash) = line.find(" - ") else { continue };
        let tail: Vec<&str> = line[dash + 3..].split(' ').collect();
        if tail.len() < 2 {
            continue;
        }
        let src = tail[1];
        let ml = mnt.len();
        let prefix = rp.starts_with(mnt) && (rp.len() == ml || rp.as_bytes()[ml] == b'/' || ml == 1);
        if prefix && ml >= best_len && src.starts_with('/') {
            best_len = ml;
            best_src = src.to_string();
        }
    }
    if best_src.is_empty() {
        return None;
    }
    let c = CString::new(best_src).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFBLK {
        return None;
    }
    Some(st.st_rdev)
}

impl ThermDev {
    fn add_nvme(&mut self, disk: &str) {
        let Some(ctrl) = nvme_controller(disk) else { return };
        if self.name.len() >= THERM_MAX_DEVS || self.name.contains(&ctrl) {
            return;
        }
        // sysfs hwmon (newer kernels, readable without root)
        let hw = find_hwmon(&format!("/sys/class/nvme/{}", ctrl))
            .or_else(|| find_hwmon(&format!("/sys/class/nvme/{}/device/hwmon", ctrl)))
            .unwrap_or_default();
        // NVMe admin ioctl: works on old kernels too, needs root; also gives T1/T2 counters.
        let dev = CString::new(format!("/dev/{}", ctrl)).unwrap();
        let fd = unsafe { libc::open(dev.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        self.name.push(ctrl);
        self.hwmon.push(hw);
        self.fd.push(fd);
    }

    /// Walk dm/md/LVM layers down to the physical disks.
    fn collect(&mut self, disk: &str, depth: u32) {
        if depth > 8 {
            return;
        }
        if disk.starts_with("nvme") {
            self.add_nvme(disk);
            return;
        }
        let Ok(rd) = std::fs::read_dir(format!("/sys/block/{}/slaves", disk)) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            // a slave may be a partition: nvme0n1p2 -> its disk
            let mut disk2 = name.clone();
            if let Some(real) = realpath(&format!("/sys/class/block/{}", name)) {
                if exists(&format!("{}/partition", real)) {
                    disk2 = basename(dirname(&real)).to_string();
                }
            }
            self.collect(&disk2, depth + 1);
        }
    }

    /// Find the NVMe drive(s) holding the file. Ok(description) if at least one
    /// temperature source works, Err(why not) otherwise.
    pub fn open(path: &str) -> Result<(ThermDev, String), String> {
        let mut t = ThermDev { fd: Vec::new(), hwmon: Vec::new(), name: Vec::new(), have_t1: false };
        let c = CString::new(path).map_err(|_| "bad path".to_string())?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 {
            return Err(format!("stat: {}", strerror(errno())));
        }
        let link = |dev: libc::dev_t| format!("/sys/dev/block/{}:{}", libc::major(dev), libc::minor(dev));
        let real = match realpath(&link(st.st_dev)) {
            Some(r) => r,
            None => {
                // btrfs and some others report an anonymous device number: take the block
                // device the filesystem is mounted from instead.
                let bdev = mount_source_dev(path).ok_or("the file is not on a local block device")?;
                realpath(&link(bdev)).ok_or("the file is not on a local block device")?
            }
        };
        let real = if exists(&format!("{}/partition", real)) { dirname(&real).to_string() } else { real };
        let disk = basename(&real).to_string();
        t.collect(&disk, 0);
        if t.name.is_empty() {
            return Err(format!("{} is not on an NVMe drive", disk));
        }
        let Some((temp, _)) = t.read() else {
            return Err(format!(
                "cannot read the temperature of {} (no hwmon in sysfs; the NVMe ioctl needs root)",
                t.name[0]
            ));
        };
        let desc = format!(
            "{}, {} C{}",
            t.name.join("+"),
            temp,
            if t.have_t1 { ", throttling counters available" } else { "" }
        );
        Ok((t, desc))
    }

    /// Highest temperature over the drives, C, and the sum of T1/T2 throttling
    /// transitions (0 if not available). None if no temperature could be read.
    pub fn read(&mut self) -> Option<(i32, u64)> {
        let mut best = i32::MIN;
        let mut thr_sum = 0u64;
        let mut have_t1 = false;
        for i in 0..self.name.len() {
            let mut temp = i32::MIN;
            if self.fd[i] >= 0 {
                if let Some((t, thr)) = smart_log(self.fd[i]) {
                    temp = t;
                    thr_sum += thr;
                    have_t1 = true;
                }
            }
            if temp == i32::MIN && !self.hwmon[i].is_empty() {
                if let Ok(s) = std::fs::read_to_string(&self.hwmon[i]) {
                    let s = s.trim();
                    let end = s.find(|c: char| !(c.is_ascii_digit() || c == '-')).unwrap_or(s.len());
                    temp = s[..end].parse::<i32>().unwrap_or(0) / 1000;
                }
            }
            best = best.max(temp);
        }
        self.have_t1 = have_t1;
        if best == i32::MIN {
            return None;
        }
        Some((best, thr_sum))
    }
}

impl Drop for ThermDev {
    fn drop(&mut self) {
        for &fd in &self.fd {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// struct nvme_admin_cmd from <linux/nvme_ioctl.h>.
#[repr(C)]
#[derive(Default)]
struct NvmeAdminCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

/// _IOWR('N', 0x41, struct nvme_admin_cmd)
const NVME_IOCTL_ADMIN_CMD: libc::c_ulong =
    (3 << 30) | ((std::mem::size_of::<NvmeAdminCmd>() as libc::c_ulong) << 16) | ((b'N' as libc::c_ulong) << 8) | 0x41;

/// SMART / Health log (log page 0x02): composite temperature (K) at bytes 1-2, Thermal
/// Management T1/T2 transition counts at 216 and 220.
fn smart_log(fd: i32) -> Option<(i32, u64)> {
    let mut log = [0u8; 512];
    let cmd = NvmeAdminCmd {
        opcode: 0x02,
        nsid: 0xffffffff,
        addr: log.as_mut_ptr() as u64,
        data_len: log.len() as u32,
        cdw10: 0x02 | (((log.len() / 4 - 1) as u32) << 16),
        ..Default::default()
    };
    if unsafe { libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD as _, &cmd) } != 0 {
        return None;
    }
    let kelvin = log[1] as i32 | (log[2] as i32) << 8;
    if kelvin == 0 {
        return None;
    }
    let t1 = u32::from_ne_bytes(log[216..220].try_into().unwrap());
    let t2 = u32::from_ne_bytes(log[220..224].try_into().unwrap());
    Some((kelvin - 273, t1 as u64 + t2 as u64))
}

/* ---------- Monitor thread ---------- */

pub struct ThermMon {
    pub dev: Mutex<ThermDev>,
    pub gov: Mutex<Gov>,
    pub governor: AtomicBool, // control the read rate
    pub temp: AtomicI32,      // last temperature, C (-1 unknown)
    pub max_temp: AtomicI32,
    pub throttle: AtomicU64,  // throttling transitions since start
    throttle0: AtomicU64,
    pub stop: AtomicBool,
    pub running: AtomicBool,
}

impl ThermMon {
    pub fn new(dev: ThermDev) -> ThermMon {
        ThermMon {
            dev: Mutex::new(dev),
            gov: Mutex::new(Gov::new(0)),
            governor: AtomicBool::new(false),
            temp: AtomicI32::new(-1),
            max_temp: AtomicI32::new(-1),
            throttle: AtomicU64::new(0),
            throttle0: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            running: AtomicBool::new(false),
        }
    }

    pub fn read(&self) -> Option<(i32, u64)> {
        self.dev.lock().unwrap().read()
    }

    /// Initial reading before the monitor thread starts.
    pub fn prime(&self) {
        let mut thr = 0;
        if let Some((t, th)) = self.read() {
            self.temp.store(t, Ordering::Relaxed);
            self.max_temp.store(t, Ordering::Relaxed);
            thr = th;
        }
        self.throttle0.store(thr, Ordering::Relaxed);
        self.stop.store(false, Ordering::Relaxed);
    }

    /// The monitor loop (runs in its own thread). rate_limit: where the governor
    /// publishes its limit (bytes/s); bytes_read: total bytes read, to measure the rate.
    pub fn run(&self, rate_limit: Option<&AtomicU64>, bytes_read: Option<&AtomicU64>) {
        let mut last_bytes = bytes_read.map_or(0, |b| b.load(Ordering::Relaxed));
        let mut last_t = now_ns();
        while !self.stop.load(Ordering::Relaxed) {
            crate::util::sleep_ns(crate::NS_PER_SEC);
            let Some((temp, thr)) = self.read() else { continue };
            self.temp.store(temp, Ordering::Relaxed);
            if temp > self.max_temp.load(Ordering::Relaxed) {
                self.max_temp.store(temp, Ordering::Relaxed);
            }
            let t0 = self.throttle0.load(Ordering::Relaxed);
            self.throttle.store(thr.saturating_sub(t0), Ordering::Relaxed);
            let now = now_ns();
            let b = bytes_read.map_or(0, |b| b.load(Ordering::Relaxed));
            let rate = (b - last_bytes) as f64 * 1e9 / (now - last_t) as f64;
            last_bytes = b;
            last_t = now;
            if self.governor.load(Ordering::Relaxed) {
                if let Some(rl) = rate_limit {
                    rl.store(self.gov.lock().unwrap().step(temp, rate) as u64, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simple thermal model of an NVMe drive: the steady temperature is proportional to
    /// the read rate (2.0 GB/s -> 74 C), the time constant is two minutes, and at 77 C the
    /// drive throttles itself to 1 GB/s (like Thermal Management T1 on the test server).
    struct Drive {
        temp: f64,
        throttled: bool,
        throttle_events: u64,
    }

    impl Drive {
        fn step(&mut self, want_bps: f64) -> f64 {
            let (max_rate, throttled_rate) = (3.5e9, 1.0e9);
            if !self.throttled && self.temp >= 77.0 {
                self.throttled = true;
                self.throttle_events += 1;
            } else if self.throttled && self.temp <= 73.0 {
                self.throttled = false;
            }
            let mut rate = if want_bps > 0.0 && want_bps < max_rate { want_bps } else { max_rate };
            if self.throttled && rate > throttled_rate {
                rate = throttled_rate;
            }
            let (tau, ambient, deg_per_gbps) = (120.0, 25.0, 24.5);
            self.temp += ((ambient + deg_per_gbps * rate / 1e9) - self.temp) / tau;
            rate
        }
    }

    /// (average and minimum rate over the last 1000 s, max temperature, throttle events)
    fn run(governor: bool) -> (f64, f64, f64, u64) {
        let mut d = Drive { temp: 60.0, throttled: false, throttle_events: 0 };
        let mut g = Gov::new(74);
        let (mut limit, mut sum, mut min_last, mut max_temp) = (0.0, 0.0, 1e18f64, 0.0f64);
        let mut n = 0;
        for s in 0..3600 {
            let rate = d.step(limit);
            max_temp = max_temp.max(d.temp);
            if governor {
                limit = g.step(d.temp as i32, rate);
            }
            if s >= 2600 {
                min_last = min_last.min(rate);
                sum += rate;
                n += 1;
            }
        }
        (sum / n as f64, min_last, max_temp, d.throttle_events)
    }

    #[test]
    fn governor() {
        let (avg, mn, maxt, ev) = run(false);
        assert!(ev > 0); // without the governor the drive throttles
        assert!(mn <= 1.0e9); // down to 1 GB/s
        eprintln!("[model] no governor: avg {:.2} GB/s, min {:.2} GB/s, max {:.1} C, throttles {}", avg / 1e9, mn / 1e9, maxt, ev);
        let (avg, mn, maxt, ev) = run(true);
        eprintln!("[model] governor 74C: avg {:.2} GB/s, min {:.2} GB/s, max {:.1} C, throttles {}", avg / 1e9, mn / 1e9, maxt, ev);
        assert_eq!(ev, 0); // with it, never
        assert!(maxt < 76.0);
        assert!(avg > 1.8e9); // close to the sustainable 2.0 GB/s
        assert!(mn > 1.5e9); // and without collapses

        // Far below the target the limit is lifted again.
        let mut g = Gov::new(74);
        assert_eq!(g.step(60, 3e9), 0.0);
        assert!(g.step(73, 3e9) > 0.0);
        for _ in 0..200 {
            g.step(50, 3e9);
        }
        assert_eq!(g.step(50, 3e9), 0.0);
    }

    #[test]
    fn ioctl_number() {
        assert_eq!(std::mem::size_of::<NvmeAdminCmd>(), 72);
        assert_eq!(NVME_IOCTL_ADMIN_CMD, 0xC0484E41);
    }
}
