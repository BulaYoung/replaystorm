//! Fast clock for the hot loop.
//!
//! CLOCK_MONOTONIC via vDSO normally costs ~20 ns. But if the kernel has fallen back to
//! the hpet/acpi_pm clocksource (TSC marked unstable, which happens on laptops and VMs),
//! each call costs ~1 us. In that case we use rdtsc: the frequency is calibrated once
//! against CLOCK_MONOTONIC, and the offset is set per thread (in case TSCs of different
//! cores are not synchronized). The result is nanoseconds on the same timeline as
//! CLOCK_MONOTONIC.

use crate::util::now_ns;
use crate::NS_PER_US;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClockMode {
    #[default]
    Auto,
    Tsc,
    Monotonic,
}

static USE_TSC: AtomicBool = AtomicBool::new(false);
static NS_PER_TICK: AtomicU64 = AtomicU64::new(0x3FF0_0000_0000_0000); // 1.0

thread_local! {
    static BASE_TICK: Cell<u64> = const { Cell::new(0) };
    static BASE_NS: Cell<i64> = const { Cell::new(0) };
}

/// Check TSC against CLOCK_MONOTONIC and resync on a larger drift.
pub const CLOCK_RESYNC_NS: i64 = 50 * NS_PER_US;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
fn rdtsc() -> u64 {
    0
}

const HAVE_TSC: bool = cfg!(target_arch = "x86_64");

#[inline(always)]
fn ns_per_tick() -> f64 {
    f64::from_bits(NS_PER_TICK.load(Ordering::Relaxed))
}

#[inline(always)]
pub fn clock_ns() -> i64 {
    if HAVE_TSC && USE_TSC.load(Ordering::Relaxed) {
        let bt = BASE_TICK.with(|c| c.get());
        let bn = BASE_NS.with(|c| c.get());
        return bn + (rdtsc().wrapping_sub(bt) as f64 * ns_per_tick()) as i64;
    }
    now_ns()
}

/// A (tsc, monotonic) pair with minimal uncertainty.
fn sample() -> (u64, i64) {
    let mut best = u64::MAX;
    let (mut tick, mut ns) = (0, 0);
    for _ in 0..7 {
        let a = rdtsc();
        let m = now_ns();
        let b = rdtsc();
        if b.wrapping_sub(a) < best {
            best = b.wrapping_sub(a);
            tick = a + (b - a) / 2;
            ns = m;
        }
    }
    (tick, ns)
}

fn cpu_has_invariant_tsc() -> bool {
    let Ok(s) = std::fs::read_to_string("/proc/cpuinfo") else { return false };
    for line in s.lines() {
        if line.starts_with("flags") {
            return line.contains(" constant_tsc") && line.contains(" nonstop_tsc");
        }
    }
    false
}

fn read_clocksource() -> String {
    std::fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
        .map(|s| s.lines().next().unwrap_or("").to_string())
        .unwrap_or_else(|_| "?".into())
}

/// Choose the clock and calibrate the TSC frequency. Returns a description for the log.
pub fn init(mode: ClockMode) -> String {
    let cs = read_clocksource();
    USE_TSC.store(false, Ordering::Relaxed);
    if HAVE_TSC {
        let want = match mode {
            ClockMode::Tsc => true,
            ClockMode::Auto => cs != "tsc" && cpu_has_invariant_tsc(),
            ClockMode::Monotonic => false,
        };
        if want {
            // Calibrate on a single core: TSCs of different cores may be unsynchronized.
            let mut saved: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            let sz = std::mem::size_of::<libc::cpu_set_t>();
            let mut pinned = unsafe { libc::sched_getaffinity(0, sz, &mut saved) } == 0;
            if pinned {
                let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::CPU_SET(libc::sched_getcpu().max(0) as usize, &mut one);
                }
                pinned = unsafe { libc::sched_setaffinity(0, sz, &one) } == 0;
            }
            let mut k = [0f64; 2];
            for kr in k.iter_mut() {
                let (t1, n1) = sample();
                crate::util::sleep_ns(100_000_000);
                let (t2, n2) = sample();
                if t2 > t1 && n2 > n1 {
                    *kr = (n2 - n1) as f64 / (t2 - t1) as f64;
                }
            }
            if pinned {
                unsafe { libc::sched_setaffinity(0, sz, &saved) };
            }
            if k[0] > 0.0 && k[1] > 0.0 && (k[0] - k[1]).abs() / k[0] < 1e-3 {
                let npt = (k[0] + k[1]) / 2.0;
                NS_PER_TICK.store(npt.to_bits(), Ordering::Relaxed);
                USE_TSC.store(true, Ordering::Relaxed);
                thread_init();
                return format!("TSC {:.3} GHz (kernel clocksource: {})", 1.0 / npt, cs);
            }
            return format!("CLOCK_MONOTONIC (kernel clocksource: {}; TSC calibration unstable)", cs);
        }
    }
    format!("CLOCK_MONOTONIC (kernel clocksource: {})", cs)
}

/// Align the current thread's TSC offset to CLOCK_MONOTONIC.
pub fn thread_init() {
    if HAVE_TSC && USE_TSC.load(Ordering::Relaxed) {
        let (t, n) = sample();
        BASE_TICK.with(|c| c.set(t));
        BASE_NS.with(|c| c.set(n));
    }
}

/// Check TSC against CLOCK_MONOTONIC and resync on drift (call where the thread is about
/// to sleep anyway). Returns true if a resync happened.
pub fn resync() -> bool {
    if HAVE_TSC && USE_TSC.load(Ordering::Relaxed) {
        let d = clock_ns() - now_ns();
        if !(-CLOCK_RESYNC_NS..=CLOCK_RESYNC_NS).contains(&d) {
            thread_init();
            return true;
        }
    }
    false
}
