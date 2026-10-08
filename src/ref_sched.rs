//! Reference (original single-threaded) implementation of timeline normalization and the
//! rate profile. The unit tests check that the parallel implementation in sched.rs gives
//! exactly the same results for any thread count.

use crate::sched::*;
use crate::{offlen_len, SHARD_SKIP};

pub fn ref_ts_normalize(ts: &mut [i64], shard: Option<&[u16]>, cfg: &TsCfg) -> TsResult {
    let n = ts.len();
    let mut res = TsResult::default();
    let skip = |i: usize| shard.is_some_and(|s| s[i] == SHARD_SKIP);

    /* 1. Outliers. */
    let mut outl: Option<Vec<bool>> = None;
    let future = cfg.now_ns + TS_FUTURE_SLACK_NS;
    for i in 0..n {
        if skip(i) {
            continue;
        }
        let t = ts[i];
        let cls = if t == 0 {
            res.outl_zero += 1;
            true
        } else if t < TS_PAST_LIMIT_NS {
            res.outl_past += 1;
            true
        } else if cfg.now_ns > 0 && t > future {
            res.outl_future += 1;
            true
        } else {
            false
        };
        if cls {
            outl.get_or_insert_with(|| vec![false; n])[i] = true;
        }
    }
    if cfg.outlier_jump > 0 {
        let is_out = |o: &Option<Vec<bool>>, i: usize| o.as_ref().is_some_and(|v| v[i]);
        let mut prev = usize::MAX;
        let mut i = 0;
        while i < n {
            if skip(i) || is_out(&outl, i) {
                i += 1;
                continue;
            }
            if prev != usize::MAX && (ts[i] - ts[prev]).abs() > cfg.outlier_jump {
                // A jump. If time comes back within a few packets, these are outliers.
                let mut j = i + 1;
                let mut seen = 0;
                let mut back = false;
                while j < n && seen < TS_SPIKE_LOOKAHEAD {
                    if skip(j) || is_out(&outl, j) {
                        j += 1;
                        continue;
                    }
                    seen += 1;
                    if (ts[j] - ts[prev]).abs() <= cfg.outlier_jump {
                        back = true;
                        break;
                    }
                    j += 1;
                }
                if back {
                    let bm = outl.get_or_insert_with(|| vec![false; n]);
                    for k in i..j {
                        if skip(k) || bm[k] {
                            continue;
                        }
                        bm[k] = true;
                        res.outl_spike += 1;
                    }
                    i = j;
                    continue;
                }
            }
            prev = i;
            i += 1;
        }
    }
    res.outliers = res.outl_zero + res.outl_past + res.outl_future + res.outl_spike;
    if let (Some(bm), true) = (&outl, cfg.exclude_outliers) {
        let mut fg = 0;
        while fg < n && (skip(fg) || bm[fg]) {
            fg += 1;
        }
        if fg < n {
            let mut last = ts[fg];
            for i in 0..n {
                if skip(i) {
                    continue;
                }
                if bm[i] {
                    ts[i] = last;
                } else {
                    last = ts[i];
                }
            }
            res.excluded = true;
        }
    }

    /* 2. Bounds, non-monotonicity, clamp. */
    let mut have = false;
    let mut rm = 0;
    for i in 0..n {
        if skip(i) {
            continue;
        }
        let t = ts[i];
        res.n += 1;
        if !have {
            have = true;
            rm = t;
            res.first_abs = t;
            res.min_abs = t;
            res.max_abs = t;
            continue;
        }
        res.min_abs = res.min_abs.min(t);
        res.max_abs = res.max_abs.max(t);
        if t < rm {
            res.backward += 1;
            if rm - t > res.max_backward {
                res.max_backward = rm - t;
                res.max_backward_idx = i as u64;
            }
            if cfg.order == TsOrder::Clamp {
                ts[i] = rm;
            }
        } else {
            rm = t;
        }
    }
    if !have {
        res.monotone = true;
        res.lap_len = 1000;
        return res;
    }
    res.monotone = cfg.order == TsOrder::Clamp || res.backward == 0;
    res.base_abs = if cfg.order == TsOrder::Sort { res.min_abs } else { res.first_abs };
    let base = res.base_abs;

    /* 3. Gaps and mapping onto the timeline. */
    let mut maxmapped = i64::MIN;
    if res.monotone {
        let (mut prev, mut excess, mut last_mapped) = (0i64, 0i64, 0i64);
        let mut first = true;
        for i in 0..n {
            if skip(i) {
                ts[i] = last_mapped;
                continue;
            }
            let t = ts[i];
            if !first {
                let gap = t - prev;
                top_insert(&mut res.top, &mut res.ntop, TsGap { at: prev, len: gap, idx: i as u64, idx_known: true });
                if cfg.max_gap > 0 && gap > cfg.max_gap {
                    excess += gap - cfg.max_gap;
                    res.gaps_over += 1;
                }
            }
            first = false;
            prev = t;
            last_mapped = t - base - excess;
            ts[i] = last_mapped;
            maxmapped = maxmapped.max(last_mapped);
        }
        res.gap_removed = excess;
    } else {
        let mut s: Vec<Rec16> = (0..n).filter(|&i| !skip(i)).map(|i| Rec16 { key: ts[i], val: 0 }).collect();
        let mut tmp = vec![Rec16::default(); s.len()];
        radix_sort16(&mut s, &mut tmp);
        let mut gl = GapList::default();
        let mut excess = 0;
        for j in 1..s.len() {
            let gap = s[j].key - s[j - 1].key;
            top_insert(&mut res.top, &mut res.ntop, TsGap { at: s[j - 1].key, len: gap, idx: 0, idx_known: false });
            if cfg.max_gap > 0 && gap > cfg.max_gap {
                excess += gap - cfg.max_gap;
                res.gaps_over += 1;
                gl.b.push(s[j].key);
                gl.cum.push(excess);
            }
        }
        res.gap_removed = excess;
        let eb = gl.excess(base);
        let mut last_mapped = 0;
        for i in 0..n {
            if skip(i) {
                ts[i] = last_mapped;
                continue;
            }
            let t = ts[i];
            last_mapped = t - base - (gl.excess(t) - eb);
            ts[i] = last_mapped;
            maxmapped = maxmapped.max(last_mapped);
        }
    }
    res.duration = maxmapped.max(0);
    res.lap_len = res.duration + if res.n > 1 { res.duration / (res.n - 1) as i64 } else { 0 };
    if res.lap_len <= 0 {
        res.lap_len = 1000;
    }
    res
}

pub fn ref_rate_profile(sched: &[i64], offlen: &[u64], shard: Option<&[u16]>, monotone: bool, cfg: &RateCfg) -> RateResult {
    let mut res = RateResult::default();
    let sorted;
    let get: Box<dyn Fn(usize) -> Option<(i64, u32, usize)>>;
    let vn;
    if monotone {
        vn = sched.len();
        get = Box::new(move |i| {
            if shard.is_some_and(|s| s[i] == SHARD_SKIP) {
                return None;
            }
            Some((sched[i], offlen_len(offlen[i]), shard.map_or(0, |s| s[i] as usize)))
        });
    } else {
        let mut s: Vec<Rec16> = (0..sched.len())
            .filter(|&i| !shard.is_some_and(|s| s[i] == SHARD_SKIP))
            .map(|i| Rec16 {
                key: sched[i],
                val: offlen_len(offlen[i]) as u64 | (shard.map_or(0, |s| s[i] as u64) << 32),
            })
            .collect();
        let mut tmp = vec![Rec16::default(); s.len()];
        radix_sort16(&mut s, &mut tmp);
        sorted = s;
        vn = sorted.len();
        let sr = &sorted;
        get = Box::new(move |i| Some((sr[i].key, (sr[i].val & 0xFFFF_FFFF) as u32, (sr[i].val >> 32) as usize)));
    }

    let nsh = cfg.nshards.max(1);
    let mut last = vec![i64::MIN; nsh];
    let mult = if cfg.mult > 0.0 { cfg.mult } else { 1.0 };
    let mut win = [0i64; RATE_WINDOWS];
    let mut left = [0usize; RATE_WINDOWS];
    let mut sum = [0u64; RATE_WINDOWS];
    let mut sum1 = [0u64; RATE_WINDOWS];
    let mut best = [0u64; RATE_WINDOWS];
    let mut best1 = [0u64; RATE_WINDOWS];
    for w in 0..RATE_WINDOWS {
        let s = RATE_WINDOWS_NS[w] as f64 * mult;
        win[w] = if s < 1.0 { 1 } else if s > 9e18 { i64::MAX } else { s as i64 };
    }
    let lt = [1000i64, 10000, 100000];
    let (mut tmin, mut tmax) = (i64::MAX, i64::MIN);
    for r in 0..vn {
        let Some((t, len, sh)) = get(r) else { continue };
        let len = len + cfg.l2_extra;
        res.pkts += 1;
        res.bytes += len as u64;
        tmin = tmin.min(t);
        tmax = tmax.max(t);
        if sh < nsh {
            if last[sh] != i64::MIN {
                let gw = (t - last[sh]) as f64 / mult;
                res.gaps_total += 1;
                if gw < cfg.timing_res as f64 {
                    res.gaps_below_res += 1;
                }
                for q in 0..3 {
                    if gw < lt[q] as f64 {
                        res.gaps_lt[q] += 1;
                    }
                }
            }
            last[sh] = t;
        }
        for w in 0..RATE_WINDOWS {
            sum[w] += len as u64;
            sum1[w] += l1_bytes(len);
            loop {
                let Some((tl, ll, _)) = get(left[w]) else {
                    left[w] += 1;
                    continue;
                };
                if t - tl >= win[w] {
                    let ll = ll + cfg.l2_extra;
                    sum[w] -= ll as u64;
                    sum1[w] -= l1_bytes(ll);
                    left[w] += 1;
                } else {
                    break;
                }
            }
            best[w] = best[w].max(sum[w]);
            best1[w] = best1[w].max(sum1[w]);
        }
    }
    for w in 0..RATE_WINDOWS {
        let ws = RATE_WINDOWS_NS[w] as f64 / 1e9;
        res.peak_bps[w] = best[w] as f64 * 8.0 / ws;
        res.peak_l1_bps[w] = best1[w] as f64 * 8.0 / ws;
    }
    if res.pkts > 0 && tmax > tmin {
        res.wall_duration_s = (tmax - tmin) as f64 / mult / 1e9;
        res.avg_bps = res.bytes as f64 * 8.0 / res.wall_duration_s;
    }
    res
}
