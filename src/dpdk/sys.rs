//! Preparing the system for DPDK and giving it back: binding the NIC to vfio-pci
//! (--dpdk-bind) and reserving hugepages (--dpdk-hugepages) for the time of the run.
//!
//! What was changed is written to a state file before the change, so that the original
//! state is restored at the end (normal end, signal, error) and, if the process was killed
//! (kill -9, power loss of the process), by the next run.
//!
//! Paths are relative to RS_SYSFS_ROOT (empty: the real system), so the logic can be
//! tested on a fake tree.

use crate::util::*;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

/// Hugepage size used for the reservation.
pub const HUGEPAGE_KB: u64 = 2048;

fn root() -> String {
    std::env::var("RS_SYSFS_ROOT").unwrap_or_default()
}

fn p(path: &str) -> String {
    format!("{}{}", root(), path)
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(p(path)).ok().map(|s| s.trim().to_string())
}

fn write(path: &str, v: &str) -> Result<(), String> {
    std::fs::write(p(path), v).map_err(|e| format!("writing {} to {}: {}", v.trim(), path, e))
}

/// A PCI address in the full form 0000:3b:00.0 (also accepts 3b:00.0).
pub fn pci_addr(s: &str) -> Option<String> {
    let full = if s.matches(':').count() == 1 { format!("0000:{}", s) } else { s.to_string() };
    let b = full.as_bytes();
    let ok = full.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && full.chars().enumerate().all(|(i, c)| [4, 7, 10].contains(&i) || c.is_ascii_hexdigit());
    ok.then(|| full.to_ascii_lowercase())
}

fn dev(pci: &str) -> String {
    format!("/sys/bus/pci/devices/{}", pci)
}

/// Driver the device is bound to now (None: no driver).
pub fn driver_of(pci: &str) -> Option<String> {
    let link = std::fs::read_link(p(&format!("{}/driver", dev(pci)))).ok()?;
    link.file_name().map(|n| n.to_string_lossy().into_owned())
}

/// Network interface of the device, if the kernel driver has created one.
fn netdev_of(pci: &str) -> Option<String> {
    let rd = std::fs::read_dir(p(&format!("{}/net", dev(pci)))).ok()?;
    rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).next()
}

/// Global (not link-local) addresses on an interface.
fn addresses(iface: &str) -> Vec<String> {
    let mut out = Vec::new();
    if !root().is_empty() {
        // fake tree for tests: addresses listed in a file
        if let Some(s) = read(&format!("/sys/class/net/{}/test_addresses", iface)) {
            out.extend(s.split_whitespace().map(String::from));
        }
        return out;
    }
    unsafe {
        let mut ifa: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifa) != 0 {
            return out;
        }
        let mut cur = ifa;
        while !cur.is_null() {
            let a = &*cur;
            cur = a.ifa_next;
            if a.ifa_addr.is_null() || std::ffi::CStr::from_ptr(a.ifa_name).to_string_lossy() != iface {
                continue;
            }
            match (*a.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let sin = &*(a.ifa_addr as *const libc::sockaddr_in);
                    out.push(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).to_string());
                }
                libc::AF_INET6 => {
                    let sin6 = &*(a.ifa_addr as *const libc::sockaddr_in6);
                    let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if ip.segments()[0] & 0xffc0 != 0xfe80 {
                        out.push(ip.to_string());
                    }
                }
                _ => {}
            }
        }
        libc::freeifaddrs(ifa);
    }
    out
}

/// What was changed, to be restored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub pci: String,
    pub driver: String,           // original kernel driver ("" if we did not rebind)
    pub iface: String,
    pub mtu: u32,
    pub up: bool,
    pub huge_path: String,        // nr_hugepages file ("" if we did not reserve)
    pub huge_orig: u64,
}

impl State {
    fn to_text(&self) -> String {
        format!(
            "pci={}\ndriver={}\niface={}\nmtu={}\nup={}\nhuge_path={}\nhuge_orig={}\n",
            self.pci, self.driver, self.iface, self.mtu, self.up as u8, self.huge_path, self.huge_orig
        )
    }

    fn from_text(s: &str) -> State {
        let mut st = State::default();
        for line in s.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k {
                "pci" => st.pci = v.into(),
                "driver" => st.driver = v.into(),
                "iface" => st.iface = v.into(),
                "mtu" => st.mtu = v.parse().unwrap_or(0),
                "up" => st.up = v == "1",
                "huge_path" => st.huge_path = v.into(),
                "huge_orig" => st.huge_orig = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        st
    }
}

/// State file of a device (cleared on reboot, when /run is a tmpfs).
pub fn state_path(pci: &str) -> String {
    let dir = if Path::new(&p("/run")).is_dir() { "/run" } else { "/tmp" };
    format!("{}/replaystorm-dpdk-{}.state", dir, pci)
}

fn save_state(st: &State) -> Result<(), String> {
    let path = state_path(&st.pci);
    std::fs::write(p(&path), st.to_text()).map_err(|e| {
        format!(
            "cannot write the state file {}: {}{}",
            path,
            e.raw_os_error().map(strerror).unwrap_or_else(|| e.to_string()),
            if e.kind() == std::io::ErrorKind::PermissionDenied { " (--dpdk-bind/--dpdk-hugepages need root)" } else { "" }
        )
    })
}

fn load_state(pci: &str) -> Option<State> {
    read(&state_path(pci)).map(|s| State::from_text(&s))
}

/// What has to be restored at the end of this run.
static RESTORE: Mutex<Option<State>> = Mutex::new(None);

fn modprobe_vfio() {
    if Path::new(&p("/sys/bus/pci/drivers/vfio-pci")).exists() || !root().is_empty() {
        return;
    }
    let _ = Command::new("modprobe").arg("vfio-pci").status();
}

fn bind_to(pci: &str, driver: &str) -> Result<(), String> {
    let d = dev(pci);
    write(&format!("{}/driver_override", d), driver)?;
    if driver_of(pci).is_some() {
        write(&format!("{}/driver/unbind", d), pci)?;
    }
    // drivers_probe binds the device to the driver named in driver_override.
    write("/sys/bus/pci/drivers_probe", pci)?;
    Ok(())
}

/// Prepare the system before the EAL starts. pci: the --dpdk port as a PCI address.
pub fn prepare(pci: &str, bind: bool, huge_bytes: u64) -> Result<(), String> {
    let d = dev(pci);
    if !Path::new(&p(&d)).exists() {
        return Err(format!("PCI device {} not found ({} does not exist)", pci, d));
    }
    let mut st = State { pci: pci.to_string(), ..Default::default() };

    // A previous run that was killed may have left the device on vfio-pci or hugepages
    // reserved: restore what it recorded first.
    if let Some(old) = load_state(pci) {
        log_warn!(
            "a previous run did not finish cleanly ({}): restoring its changes first",
            state_path(pci)
        );
        let _ = restore_state(&old);
    }

    if bind {
        let cur = driver_of(pci).unwrap_or_default();
        if cur == "vfio-pci" || cur == "uio_pci_generic" || cur == "igb_uio" {
            log_info!("DPDK: {} is already bound to {}; it is left so at the end", pci, cur);
        } else {
            if !Path::new(&p(&format!("{}/iommu_group", d))).exists()
                && read("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode").as_deref() != Some("Y")
            {
                return Err(format!(
                    "{} has no IOMMU group: enable the IOMMU (kernel command line intel_iommu=on \
                     iommu=pt, or amd_iommu=on iommu=pt) and reboot",
                    pci
                ));
            }
            if let Some(iface) = netdev_of(pci) {
                let addrs = addresses(&iface);
                if !addrs.is_empty() {
                    return Err(format!(
                        "{} ({}) has addresses {}: it may carry this server's connection. Remove them \
                         (ip addr flush dev {}) or bind the NIC yourself",
                        iface,
                        pci,
                        addrs.join(", "),
                        iface
                    ));
                }
                st.iface = iface.clone();
                st.mtu = read(&format!("/sys/class/net/{}/mtu", iface)).and_then(|s| s.parse().ok()).unwrap_or(0);
                let flags = read(&format!("/sys/class/net/{}/flags", iface)).unwrap_or_default();
                st.up = u32::from_str_radix(flags.trim_start_matches("0x"), 16).is_ok_and(|f| f & 1 != 0);
            }
            st.driver = cur;
        }
    }

    if huge_bytes > 0 {
        let node = read(&format!("{}/numa_node", d)).and_then(|s| s.parse::<i64>().ok()).unwrap_or(-1);
        let node_path = format!("/sys/devices/system/node/node{}/hugepages/hugepages-{}kB/nr_hugepages", node, HUGEPAGE_KB);
        let path = if node >= 0 && Path::new(&p(&node_path)).exists() {
            node_path
        } else {
            format!("/sys/kernel/mm/hugepages/hugepages-{}kB/nr_hugepages", HUGEPAGE_KB)
        };
        st.huge_path = path;
        st.huge_orig = read(&st.huge_path).and_then(|s| s.parse().ok()).ok_or("cannot read nr_hugepages")?;
    }

    // Record first, then change: a crash in between is restored by the next run.
    if !st.driver.is_empty() || !st.huge_path.is_empty() {
        save_state(&st)?;
        *RESTORE.lock().unwrap() = Some(st.clone());
    }

    if !st.huge_path.is_empty() {
        let want = huge_bytes.div_ceil(HUGEPAGE_KB * 1024);
        let target = st.huge_orig + want;
        let mut got = 0;
        for attempt in 0..2 {
            write(&st.huge_path, &target.to_string())?;
            got = read(&st.huge_path).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0).saturating_sub(st.huge_orig);
            if got >= want || attempt == 1 || !root().is_empty() {
                break;
            }
            // Memory too fragmented for 2 MB pages: compact it and try again.
            let _ = write("/proc/sys/vm/compact_memory", "1");
        }
        if got == 0 {
            return Err(format!("could not reserve hugepages ({})", st.huge_path));
        }
        if got < want {
            log_warn!(
                "only {} of {} hugepages could be reserved ({:.1} of {:.1} GB): memory is fragmented",
                got,
                want,
                (got * HUGEPAGE_KB * 1024) as f64 / (1u64 << 30) as f64,
                huge_bytes as f64 / (1u64 << 30) as f64
            );
        }
        log_info!(
            "DPDK: reserved {} hugepages of 2 MB ({:.1} GB) in {}, released at the end",
            got,
            (got * HUGEPAGE_KB * 1024) as f64 / (1u64 << 30) as f64,
            st.huge_path
        );
    }

    if !st.driver.is_empty() {
        modprobe_vfio();
        bind_to(pci, "vfio-pci")?;
        let now = driver_of(pci).unwrap_or_default();
        if now != "vfio-pci" && root().is_empty() {
            return Err(format!("{} could not be bound to vfio-pci (driver now: {})", pci, if now.is_empty() { "none" } else { &now }));
        }
        log_info!(
            "DPDK: {} moved from {}{} to vfio-pci; it goes back at the end",
            pci,
            st.driver,
            if st.iface.is_empty() { String::new() } else { format!(" (interface {})", st.iface) }
        );
    }
    Ok(())
}

fn restore_state(st: &State) -> Result<(), String> {
    let mut errs = Vec::new();
    if !st.driver.is_empty() {
        let res = (|| -> Result<(), String> {
            bind_to(&st.pci, &st.driver)?;
            write(&format!("{}/driver_override", dev(&st.pci)), "\n")?;
            Ok(())
        })();
        if let Err(e) = res {
            errs.push(e);
        } else if root().is_empty() {
            // The interface comes back under its predictable name; restore MTU and state.
            let mut iface = None;
            for _ in 0..50 {
                iface = netdev_of(&st.pci);
                if iface.is_some() {
                    break;
                }
                sleep_ns(100 * crate::NS_PER_MS);
            }
            match iface {
                Some(i) => {
                    let mut args = vec!["link".to_string(), "set".into(), "dev".into(), i.clone()];
                    if st.mtu > 0 {
                        args.extend(["mtu".into(), st.mtu.to_string()]);
                    }
                    if st.up {
                        args.push("up".into());
                    }
                    if !matches!(Command::new("ip").args(&args).status(), Ok(s) if s.success()) {
                        errs.push(format!("ip {} failed", args.join(" ")));
                    } else {
                        log_info!("DPDK: {} is back on {} as {}{}", st.pci, st.driver, i, if st.up { ", up" } else { "" });
                    }
                }
                None => errs.push(format!("{} is bound to {} but no interface appeared", st.pci, st.driver)),
            }
        }
    }
    if !st.huge_path.is_empty() {
        if let Err(e) = write(&st.huge_path, &st.huge_orig.to_string()) {
            errs.push(e);
        }
    }
    if errs.is_empty() {
        let _ = std::fs::remove_file(p(&state_path(&st.pci)));
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// Restore what prepare() changed (after the EAL has released the device and memory).
pub fn restore() {
    let st = RESTORE.lock().unwrap().take();
    if let Some(st) = st {
        if let Err(e) = restore_state(&st) {
            log_err!(
                "could not restore the system after DPDK: {}. State: {} (the next run with --dpdk-bind restores it)",
                e,
                state_path(&st.pci)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_names() {
        assert_eq!(pci_addr("0000:3b:00.0").as_deref(), Some("0000:3b:00.0"));
        assert_eq!(pci_addr("3B:00.1").as_deref(), Some("0000:3b:00.1"));
        assert_eq!(pci_addr("net_af_packet0"), None);
        assert_eq!(pci_addr("0"), None);
    }

    #[test]
    fn state_text() {
        let s = State { pci: "0000:3b:00.0".into(), driver: "bnxt_en".into(), iface: "ens1f0".into(), mtu: 9000, up: true,
                        huge_path: "/sys/x/nr_hugepages".into(), huge_orig: 3 };
        assert_eq!(State::from_text(&s.to_text()), s);
    }

    /// Bind, reserve and restore on a fake sysfs tree.
    #[test]
    fn fake_tree() {
        use std::os::unix::fs::symlink;
        let r = std::env::temp_dir().join(format!("rs_sysfs_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        let pci = "0000:3b:00.0";
        let mk = |d: &str| std::fs::create_dir_all(r.join(d.trim_start_matches('/'))).unwrap();
        let put = |f: &str, v: &str| std::fs::write(r.join(f.trim_start_matches('/')), v).unwrap();
        mk("/run");
        mk("/sys/bus/pci/drivers/bnxt_en");
        mk("/sys/bus/pci/drivers/vfio-pci");
        mk(&format!("/sys/bus/pci/devices/{}/net/ens1f0", pci));
        mk(&format!("/sys/bus/pci/devices/{}/iommu_group", pci));
        mk(&format!("/sys/bus/pci/devices/{}/driver", pci));
        put(&format!("/sys/bus/pci/devices/{}/numa_node", pci), "1\n");
        mk("/sys/class/net/ens1f0");
        put("/sys/class/net/ens1f0/mtu", "9000\n");
        put("/sys/class/net/ens1f0/flags", "0x1003\n");
        mk("/sys/devices/system/node/node1/hugepages/hugepages-2048kB");
        let huge = "/sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages";
        put(huge, "4\n");
        // the driver link: replace the directory by a symlink to bnxt_en
        std::fs::remove_dir(r.join(format!("sys/bus/pci/devices/{}/driver", pci))).unwrap();
        symlink(r.join("sys/bus/pci/drivers/bnxt_en"), r.join(format!("sys/bus/pci/devices/{}/driver", pci))).unwrap();
        std::env::set_var("RS_SYSFS_ROOT", r.to_string_lossy().as_ref());

        // an interface with addresses is refused
        put("/sys/class/net/ens1f0/test_addresses", "10.0.0.5\n");
        assert!(prepare(pci, true, 0).unwrap_err().contains("10.0.0.5"));
        std::fs::remove_file(r.join("sys/class/net/ens1f0/test_addresses")).unwrap();

        prepare(pci, true, 1 << 30).unwrap();
        let st = State::from_text(&read(&state_path(pci)).unwrap());
        assert_eq!(st.driver, "bnxt_en");
        assert_eq!((st.iface.as_str(), st.mtu, st.up), ("ens1f0", 9000, true));
        assert_eq!(st.huge_orig, 4);
        assert_eq!(read(huge).unwrap(), "516"); // 4 + 512 pages of 2 MB
        assert_eq!(read(&format!("/sys/bus/pci/devices/{}/driver_override", pci)).unwrap(), "vfio-pci");
        assert_eq!(read("/sys/bus/pci/drivers_probe").unwrap(), pci);
        restore();
        assert_eq!(read(huge).unwrap(), "4");
        assert_eq!(read(&format!("/sys/bus/pci/devices/{}/driver_override", pci)).unwrap(), "");
        assert!(read(&state_path(pci)).is_none());

        // a state file left by a killed run is restored by the next one
        save_state(&State { pci: pci.into(), huge_path: huge.into(), huge_orig: 2, ..Default::default() }).unwrap();
        put(huge, "100\n");
        prepare(pci, false, 0).unwrap();
        assert_eq!(read(huge).unwrap(), "2");
        assert!(read(&state_path(pci)).is_none());
        std::env::remove_var("RS_SYSFS_ROOT");
        let _ = std::fs::remove_dir_all(&r);
    }
}
