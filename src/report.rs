//! --analyze report and pre-start warnings.

use crate::cli::Mode;
use crate::dissect::{L2K_ARP, L2K_LLC, L2K_LLDP, L2K_OTHER};
use crate::pcap::{linktype_name, RecResult};
use crate::prepare::Ctx;
use crate::sched::{RATE_WINDOWS, RATE_WINDOWS_NS, RATE_WINDOW_NAMES};
use crate::util::*;
use crate::{SKIP_BAD_RAW, SKIP_TOO_BIG, SKIP_TOO_SMALL};

fn pct(a: u64, b: u64) -> f64 {
    if b > 0 {
        100.0 * a as f64 / b as f64
    } else {
        0.0
    }
}

fn fmt_bytes(b: f64) -> String {
    if b >= 1e9 {
        format!("{:.2} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.2} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.2} KB", b / 1e3)
    } else {
        format!("{:.0} B", b)
    }
}

fn tail_name(t: RecResult) -> &'static str {
    if t == RecResult::Truncated {
        "truncated"
    } else {
        "corrupt"
    }
}

/// Analysis report (--analyze).
pub fn analysis(c: &Ctx) {
    let pf = &c.pf;
    let ix = &c.ix;
    let t = &c.tsr;
    let s = &ix.st;
    let o = &c.o;

    println!("File: {} ({})", o.file, fmt_bytes(pf.size as f64));
    println!(
        "  format: pcap, {}, {}, linktype {} ({}), snaplen {}",
        if pf.nsec { "nanoseconds" } else { "microseconds" },
        if pf.swapped { "swapped byte order" } else { "native byte order" },
        pf.linktype,
        linktype_name(pf.linktype),
        pf.snaplen
    );
    if let Some(tp) = ix.tail_problem {
        println!("  WARNING: file {} at offset {}, cannot parse further", tail_name(tp), ix.tail_off);
    }
    println!("Packets: {} ({}), to send: {}", s.pkts, fmt_bytes(s.bytes as f64), t.n);
    println!(
        "Index {} in {}, timeline in {} ({} threads)",
        if c.index_cached { "loaded from cache" } else { "built" },
        fmt_ns(c.index_ns as f64),
        fmt_ns(c.norm_ns as f64),
        c.ip_threads
    );

    // Time
    if t.n > 0 {
        println!(
            "Timestamps: from {} to {} ({})",
            fmt_abs_ts(t.min_abs),
            fmt_abs_ts(t.max_abs),
            fmt_ns((t.max_abs - t.min_abs) as f64)
        );
        let mut line = format!("Replay timeline duration: {} (ts-order={}", fmt_ns(t.duration as f64), o.ts_order.name());
        if o.max_gap > 0 {
            line += &format!(", max-gap={}", fmt_ns(o.max_gap as f64));
        }
        println!("{})", line);
    }
    if let Some(r) = c.rr.as_ref().filter(|r| r.wall_duration_s > 0.0) {
        println!(
            "Average rate (x{}): {}, {}pps",
            g(c.mult),
            fmt_bps(r.avg_bps),
            fmt_count(r.pkts as f64 / r.wall_duration_s)
        );
        println!("Peak rate (x{}), L2 / on the wire with preamble and IFG:", g(c.mult));
        for w in 0..RATE_WINDOWS {
            println!(
                "  window {}: {} / {}{}",
                RATE_WINDOW_NAMES[w],
                fmt_bps(r.peak_bps[w]),
                fmt_bps(r.peak_l1_bps[w]),
                if r.wall_duration_s * 1e9 < RATE_WINDOWS_NS[w] as f64 {
                    " (file shorter than window: total volume divided by window)"
                } else {
                    ""
                }
            );
        }
        if r.gaps_total > 0 {
            println!(
                "Intervals within shards (x{}): < 1 us {:.2}%, < 10 us {:.2}%, < 100 us {:.2}%; \
                 shorter than precision {}: {:.2}% (will go out in bursts)",
                g(c.mult),
                pct(r.gaps_lt[0], r.gaps_total),
                pct(r.gaps_lt[1], r.gaps_total),
                pct(r.gaps_lt[2], r.gaps_total),
                fmt_ns(o.timing_res as f64),
                pct(r.gaps_below_res, r.gaps_total)
            );
        }
    }

    // Anomalies
    println!("Timestamp anomalies:");
    if t.backward > 0 {
        println!(
            "  backward in time: {} packets ({:.3}%), max backward jump {} (packet #{})",
            t.backward,
            pct(t.backward, t.n),
            fmt_ns(t.max_backward as f64),
            t.max_backward_idx + 1
        );
    } else {
        println!("  backward in time: none");
    }
    if t.outliers > 0 {
        println!(
            "  outliers: {} (ts=0: {}, before 1990: {}, in the future: {}, short clock jump: {}) - {}",
            t.outliers,
            t.outl_zero,
            t.outl_past,
            t.outl_future,
            t.outl_spike,
            if t.excluded {
                "excluded from timeline"
            } else {
                "kept in timeline (to exclude: --ts-outliers exclude)"
            }
        );
    } else {
        println!("  outliers: none");
    }
    if o.max_gap > 0 {
        println!("  pauses longer than max-gap: {}, removed {}", t.gaps_over, fmt_ns(t.gap_removed as f64));
    }
    if t.ntop > 0 {
        println!("  top-{} pauses:", t.ntop);
        for (i, gp) in t.top[..t.ntop].iter().enumerate() {
            let mut line = format!(
                "   {:>2}. {:<12} after mark +{} ({})",
                i + 1,
                fmt_ns(gp.len as f64),
                fmt_ns((gp.at - t.min_abs) as f64),
                fmt_abs_ts(gp.at)
            );
            if gp.idx_known {
                line += &format!(", before packet #{}", gp.idx + 1);
            }
            println!("{}", line);
        }
    }

    // Composition
    println!("Traffic composition:");
    println!(
        "  IPv4 {:.2}%, IPv6 {:.2}%, non-IP {:.2}% (ARP {}, 802.3/LLC (STP etc.) {}, LLDP {}, other {})",
        pct(s.ipv4, s.pkts),
        pct(s.ipv6, s.pkts),
        pct(s.nonip, s.pkts),
        s.l2kind[L2K_ARP as usize],
        s.l2kind[L2K_LLC as usize],
        s.l2kind[L2K_LLDP as usize],
        s.l2kind[L2K_OTHER as usize]
    );
    println!(
        "  VLAN {:.2}% (of which QinQ and deeper {}), MPLS {}, PPPoE {}, IP fragments {}",
        pct(s.vlan, s.pkts),
        s.qinq,
        s.mpls,
        s.pppoe,
        s.frag
    );

    // Skipped
    let skipped: u64 = s.skipped.iter().sum();
    let mut line = format!("Skipped frames: {}", skipped);
    if skipped > 0 {
        line += &format!(
            " (larger than MTU+14={}, +4 for 802.1Q: {}; shorter than 14 bytes: {}; RAW without IPv4/IPv6: {})",
            c.mtu + 14,
            s.skipped[SKIP_TOO_BIG],
            s.skipped[SKIP_TOO_SMALL],
            s.skipped[SKIP_BAD_RAW]
        );
    }
    println!("{}", line);
    println!("Truncated at capture (caplen < origlen): {} - will be sent with length caplen", s.truncated_caplen);

    // Shards
    let (mut maxp, mut sum) = (0u64, 0u64);
    println!("Distribution across shards ({} IP + 1 non-IP):", c.ip_threads);
    for i in 0..ix.nshards {
        println!(
            "  {} {:>3}: {:>12} packets ({:>5.2}%), {}",
            if i == c.ip_threads { "non-IP" } else { "shard " },
            i,
            ix.shard_pkts[i],
            pct(ix.shard_pkts[i], t.n),
            fmt_bytes(ix.shard_bytes[i] as f64)
        );
        if i < c.ip_threads {
            sum += ix.shard_bytes[i];
            maxp = maxp.max(ix.shard_bytes[i]);
        }
    }
    if sum > 0 && c.ip_threads > 1 {
        println!(
            "  byte imbalance: busiest shard = {:.2} x average",
            maxp as f64 / (sum as f64 / c.ip_threads as f64)
        );
    }
}

/// Pre-start warnings; returns the number of warnings.
pub fn warnings(c: &Ctx) -> u32 {
    let mut n = 0;
    let t = &c.tsr;
    let o = &c.o;
    let timed = o.mode == Mode::Timed;

    if t.outliers > 0 && !t.excluded {
        log_warn!(
            "found {} timestamp outliers (ts=0/before 1990/future/clock jump); they distort the \
             timeline. To exclude: --ts-outliers exclude",
            t.outliers
        );
        n += 1;
    }
    if t.backward > 0 && o.ts_order == crate::sched::TsOrder::Asis {
        log_warn!(
            "{} packets go backward in time; with ts-order=asis they will be sent without waiting \
             (alternatives: clamp, sort)",
            t.backward
        );
        n += 1;
    }
    if timed && c.mult > 0.0 {
        let wall = t.duration as f64 / c.mult;
        if wall > 86400e9 {
            log_warn!(
                "replay will take {}; check outliers and pauses (--max-gap, --ts-outliers exclude, --analyze)",
                fmt_ns(wall)
            );
            n += 1;
        }
    }
    if let (true, Some(r), true) = (timed, &c.rr, c.link_bps > 0.0) {
        for w in 0..RATE_WINDOWS {
            if r.peak_l1_bps[w] > c.link_bps {
                log_warn!(
                    "at x{} the {} peak is {} (with preamble and IFG), exceeding the link {} ({}); \
                     timing will be violated",
                    g(c.mult),
                    RATE_WINDOW_NAMES[w],
                    fmt_bps(r.peak_l1_bps[w]),
                    fmt_bps(c.link_bps),
                    c.link_src
                );
                n += 1;
            }
        }
    }
    if let (true, Some(r)) = (timed, &c.rr) {
        if r.gaps_total > 0 && r.gaps_below_res > 0 {
            let p = pct(r.gaps_below_res, r.gaps_total);
            if p >= 1.0 {
                log_warn!(
                    "at x{} {:.1}% of intervals within shards are shorter than achievable precision {}: \
                     these packets will effectively go out in bursts",
                    g(c.mult),
                    p,
                    fmt_ns(o.timing_res as f64)
                );
                n += 1;
            }
        }
    }
    if o.mode == Mode::Mbps && c.link_bps > 0.0 {
        // Compare on the wire: L2 bytes plus preamble, IFG, FCS (file's own ratio).
        let l2: u64 = c.ix.shard_bytes.iter().sum();
        let wire = o.mbps * 1e6 * if l2 > 0 { c.ix.st.l1_bytes as f64 / l2 as f64 } else { 1.0 };
        if wire > c.link_bps * 1.0001 {
            log_warn!(
                "requested {} L2 = {} on the wire, above the {} link: the NIC will cap the rate and \
                 threads will spend time on ENOBUFS; use --mbps line or --mbps 99%",
                fmt_bps(o.mbps * 1e6),
                fmt_bps(wire),
                fmt_bps(c.link_bps)
            );
            n += 1;
        }
    }
    let skipped: u64 = c.ix.st.skipped.iter().sum();
    if skipped > 0 {
        log_warn!(
            "{} frames will not be sent (larger than MTU {}+14 or shorter than 14 bytes), details: --analyze",
            skipped,
            c.mtu
        );
        n += 1;
    }
    if let Some(tp) = c.ix.tail_problem {
        log_warn!("file {} at offset {}; only the part before it will be sent", tail_name(tp), c.ix.tail_off);
        n += 1;
    }
    n
}
