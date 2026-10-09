//! Shared run context and its preparation: CPUs, MTU, file, index, timeline, rate profile.

use crate::cli::{Mode, Opts, MAX_CPUS};
use crate::index::{self, IdxCfg, PktIndex};
use crate::pcap::PcapFile;
use crate::sched::{self, RateCfg, RateResult, TsCfg, TsResult};
use crate::util::*;
use crate::{idxcache, SHARD_SKIP};

pub struct Ctx {
    pub o: Opts,
    pub pf: PcapFile,
    pub ix: PktIndex,
    pub tsr: TsResult,
    pub rr: Option<RateResult>,
    pub mult: f64,          // effective multiplier for Mode::Timed
    pub ip_threads: usize,  // number of IP shards/threads
    pub cpus: Vec<i32>,
    pub cpus_from_numa: bool,
    pub mtu: u32,
    pub link_bps: f64,      // 0 means unknown
    pub link_src: &'static str,
    pub index_ns: i64,      // preparation time
    pub norm_ns: i64,
    pub index_cached: bool, // index was loaded from the cache
    pub rate_lap_ns: i64,   // --mbps/--pps: duration of one lap of the rate timeline
    pub big_file: bool,     // the file is larger than 80% of available RAM
}

/// Returns the context, or the exit code.
pub fn prepare(mut o: Opts) -> Result<Ctx, i32> {
    // CPUs and thread count.
    let (cpus, cpus_from_numa) = match &o.cpus {
        Some(list) => match parse_cpulist(list, MAX_CPUS) {
            Some(c) if !c.is_empty() => {
                if let Some(iface) = o.iface.as_deref() {
                    let local = std::fs::read_to_string(format!("/sys/class/net/{}/device/local_cpulist", iface))
                        .ok()
                        .and_then(|s| parse_cpulist(&s, 1024))
                        .unwrap_or_default();
                    warn_remote_cpus(&c, &local, iface);
                }
                (c, false)
            }
            _ => {
                log_err!("invalid --cpus list '{}'", list);
                return Err(2);
            }
        },
        None => {
            let (c, numa) = iface_cpus(o.iface.as_deref(), MAX_CPUS);
            if c.is_empty() {
                log_err!("failed to determine available CPUs");
                return Err(1);
            }
            (c, numa)
        }
    };
    let ncpus = cpus.len();
    let ip_threads = if o.threads > 0 { o.threads } else if ncpus > 1 { ncpus - 1 } else { 1 };
    if ip_threads >= SHARD_SKIP as usize {
        log_err!("too many threads");
        return Err(2);
    }

    // MTU and link speed.
    let mut mtu = o.mtu;
    if mtu == 0 {
        if let Some(iface) = &o.iface {
            match iface_mtu(iface) {
                Some(m) => mtu = m,
                None => {
                    if !o.analyze {
                        log_warn!("failed to read MTU of {} from sysfs, assuming 1500 (set --mtu)", iface);
                    }
                    mtu = 1500;
                }
            }
        }
    }
    if mtu == 0 {
        mtu = 1500;
    }
    let mut link_bps = o.link_speed_bps;
    let mut link_src = if o.link_from_port { "DPDK port" } else { "--link-speed" };
    if link_bps <= 0.0 {
        if let Some(b) = o.iface.as_deref().and_then(iface_speed) {
            link_bps = b;
            link_src = "ethtool";
        }
    }
    if link_bps <= 0.0 {
        link_bps = 0.0;
        link_src = "unknown";
    }

    // File. A file larger than RAM is streamed: --preload is pointless (it would only
    // thrash the page cache), and already sent data is dropped from the cache.
    let avail = mem_available();
    let fsize = std::fs::metadata(&o.file).map(|m| m.len()).unwrap_or(0);
    let too_big = avail > 0 && fsize > avail / 10 * 8;
    if o.preload && too_big {
        log_warn!(
            "--preload ignored: the file is {:.1} GB but only {:.1} GB of memory is available; \
             the file will be streamed from disk instead",
            fsize as f64 / 1e9,
            avail as f64 / 1e9
        );
        o.preload = false;
    }
    if o.drop_behind < 0 {
        o.drop_behind = (!o.preload && too_big) as i32;
    }
    if o.preload {
        log_info!("Loading the whole file into memory (--preload)...");
    }
    let tl = now_ns();
    let pf = PcapFile::open(&o.file, o.preload).map_err(|e| {
        log_err!("{}", e);
        1
    })?;
    if pf.preloaded {
        let sec = (now_ns() - tl) as f64 / 1e9;
        log_info!(
            "Loaded {:.1} GB into memory in {:.1} s ({:.2} GB/s){}",
            pf.size as f64 / 1e9,
            sec,
            if sec > 0.0 { pf.size as f64 / sec / 1e9 } else { 0.0 },
            if pf.locked { ", locked in RAM: the disk is not read again" } else { "" }
        );
        if !pf.locked {
            log_warn!(
                "could not lock the file in RAM (mlock): under memory pressure parts of it may be \
                 evicted and read from disk again. Run as root or raise ulimit -l"
            );
        }
    }

    // Index.
    let t0 = now_ns();
    let icfg = IdxCfg { ip_shards: ip_threads, max_frame: mtu + 14, hash_threads: ip_threads.min(ncpus) };
    // Index cache: next to the pcap with "auto", or an explicit path.
    let cache_path = o.index_cache.as_ref().map(|c| if c == "auto" { format!("{}.rsidx", o.file) } else { c.clone() });
    let mut ix = None;
    if let Some(cp) = &cache_path {
        match idxcache::load(cp, &pf) {
            Ok(Ok(i)) => {
                log_info!("Index loaded from cache {}", cp);
                ix = Some(i);
            }
            Ok(Err(why)) | Err(why) => log_info!("Index cache {} not used: {}; building the index", cp, why),
        }
    }
    let index_cached = ix.is_some();
    let mut ix = match ix {
        Some(i) => i,
        None => {
            let i = index::build(&pf, &icfg).map_err(|e| {
                if crate::stop_requested() {
                    log_info!("Stopped before the start");
                    return 0;
                }
                log_err!("{}", e);
                1
            })?;
            if let Some(cp) = &cache_path {
                let ts0 = now_ns();
                match idxcache::save(cp, &pf, &i) {
                    Err(e) => log_warn!("index cache not saved: {}", e),
                    Ok(()) => log_info!(
                        "Index saved to cache {} ({:.1} GB) in {:.1} s",
                        cp,
                        i.n as f64 * 21.0 / 1e9,
                        (now_ns() - ts0) as f64 / 1e9
                    ),
                }
            }
            i
        }
    };
    // Shards for the current thread count and MTU-dependent skipping.
    index::resolve(&mut ix, pf.raw_ip, &icfg);
    let t1 = now_ns();
    let index_ns = t1 - t0;
    if ix.n == 0 {
        log_err!(
            "the file contains no packets{}",
            if ix.tail_problem.is_some() { " (file is truncated or corrupt right after the header)" } else { "" }
        );
        return Err(1);
    }

    // Timeline.
    let tcfg = TsCfg {
        order: o.ts_order,
        max_gap: o.max_gap,
        exclude_outliers: o.exclude_outliers,
        outlier_jump: o.outlier_jump,
        now_ns: realtime_ns(),
        threads: icfg.hash_threads,
    };
    let tsr = {
        let (ts, _, shard) = ix.parts_mut();
        sched::ts_normalize(ts, Some(shard), &tcfg)
    };
    if tsr.n == 0 {
        log_err!("all {} frames would be skipped (see --analyze)", ix.st.pkts);
        if !o.analyze {
            return Err(1);
        }
    }

    if o.mode == Mode::Mbps && o.line_frac > 0.0 {
        // Pacing works on L2 bytes; convert the wire-rate target using the file's own ratio
        // of L2 bytes to on-the-wire bytes (preamble, IFG, FCS, 60-byte minimum).
        if link_bps <= 0.0 {
            log_err!("--mbps line/N%: link speed is unknown, set it with --link-speed");
            return Err(2);
        }
        let l2: u64 = ix.shard_bytes.iter().sum();
        if l2 == 0 || ix.st.l1_bytes == 0 {
            log_err!("--mbps line/N%: no frames to send");
            return Err(1);
        }
        let ratio = l2 as f64 / ix.st.l1_bytes as f64;
        o.mbps = link_bps * o.line_frac * ratio / 1e6;
        log_info!(
            "--mbps {}% of {} link on the wire -> {:.0} Mbit/s L2 (L2/wire byte ratio {:.4})",
            fmt_g(o.line_frac * 100.0, 4),
            fmt_bps(link_bps),
            o.mbps,
            ratio
        );
    }

    let mut mult = if o.mode == Mode::Timed { o.multiplier } else { 1.0 };
    if o.mode == Mode::Timed && o.duration_ns > 0 {
        if tsr.duration <= 0 {
            log_err!("--duration: the file has zero duration by timestamps");
            return Err(1);
        }
        mult = tsr.duration as f64 / o.duration_ns as f64;
        log_info!(
            "--duration: timeline {} -> {}, multiplier x{}",
            fmt_ns(tsr.duration as f64),
            fmt_ns(o.duration_ns as f64),
            fmt_g(mult, 6)
        );
    }

    let mut rr = None;
    if o.analyze || o.mode == Mode::Timed {
        let rcfg = RateCfg {
            mult,
            timing_res: o.timing_res,
            l2_extra: if pf.raw_ip != 0 { 14 } else { 0 },
            nshards: ix.nshards,
            threads: icfg.hash_threads,
        };
        rr = Some(sched::rate_profile(ix.ts(), ix.offlen(), Some(ix.shard()), tsr.monotone, &rcfg));
    }
    let mut rate_lap_ns = 0;
    if !o.analyze && (o.mode == Mode::Mbps || o.mode == Mode::Pps) {
        // Pace in file order: every packet gets its place on a common rate timeline.
        let ns_per_unit = if o.mode == Mode::Mbps { 8e9 / (o.mbps * 1e6) } else { 1e9 / o.pps };
        let (ts, ol, shard) = ix.parts_mut();
        rate_lap_ns = sched::rate_timeline(ts, ol, Some(shard), if pf.raw_ip != 0 { 14 } else { 0 },
                                           o.mode == Mode::Pps, ns_per_unit, icfg.hash_threads);
    }
    let norm_ns = now_ns() - t1;
    Ok(Ctx {
        o,
        pf,
        ix,
        tsr,
        rr,
        mult,
        ip_threads,
        cpus,
        cpus_from_numa,
        mtu,
        link_bps,
        link_src,
        index_ns,
        norm_ns,
        index_cached,
        rate_lap_ns,
        big_file: too_big,
    })
}
