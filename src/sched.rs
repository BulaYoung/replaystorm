//! Send schedule: timestamp normalization, send time computation, rate profile. All
//! functions are pure (no global state) and covered by unit tests.

use crate::par::{par_for_each, par_range, par_threads};
use crate::{offlen_len, SyncPtr, NS_PER_MS, NS_PER_SEC, SHARD_SKIP};

/* ---------- Stable radix sort of 16-byte records ---------- */

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Rec16 {
    pub key: i64,
    pub val: u64,
}

const SIGN: u64 = 1 << 63;

#[inline(always)]
fn digit(r: &Rec16, d: usize) -> usize {
    (((r.key as u64 ^ SIGN) >> (d * 8)) & 0xFF) as usize
}

/// Stably sorts a by signed key; tmp is a buffer of the same size.
pub fn radix_sort16(a: &mut [Rec16], tmp: &mut [Rec16]) {
    let n = a.len();
    if n < 2 {
        return;
    }
    let tmp = &mut tmp[..n];
    let mut cnt = vec![[0usize; 256]; 8];
    for r in a.iter() {
        for (d, c) in cnt.iter_mut().enumerate() {
            c[digit(r, d)] += 1;
        }
    }
    let mut in_a = true;
    for (d, c) in cnt.iter_mut().enumerate() {
        let (src, dst): (&[Rec16], &mut [Rec16]) =
            if in_a { (&*a, &mut *tmp) } else { (&*tmp, &mut *a) };
        // All keys share the same digit; this pass is not needed.
        if c[digit(&src[0], d)] == n {
            continue;
        }
        let mut pos = 0;
        for b in c.iter_mut() {
            let k = *b;
            *b = pos;
            pos += k;
        }
        for r in src.iter() {
            let b = &mut c[digit(r, d)];
            dst[*b] = *r;
            *b += 1;
        }
        in_a = !in_a;
    }
    if !in_a {
        a.copy_from_slice(tmp);
    }
}

/// Parallel stable LSD radix sort: per pass each thread counts the digits of its chunk,
/// offsets are laid out bucket by bucket and, within a bucket, chunk by chunk, and each
/// thread scatters its chunk. This keeps the order of equal keys, so the result is
/// identical to radix_sort16.
pub fn radix_sort16_mt(a: &mut [Rec16], tmp: &mut [Rec16], nt: usize) {
    let n = a.len();
    let nt = par_threads(nt, n);
    if nt <= 1 {
        radix_sort16(a, tmp);
        return;
    }
    let tmp = &mut tmp[..n];
    let mut cnt = vec![[0usize; 256]; nt];
    let mut in_a = true;
    for d in 0..8 {
        let (src, dst): (&[Rec16], &mut [Rec16]) =
            if in_a { (&*a, &mut *tmp) } else { (&*tmp, &mut *a) };
        par_for_each(nt, n, 1, &mut cnt, |c, _t, lo, hi| {
            *c = [0; 256];
            for r in &src[lo..hi] {
                c[digit(r, d)] += 1;
            }
        });
        // All keys share the same digit: this pass is not needed.
        let mut single = false;
        for bkt in 0..256 {
            let tot: usize = cnt.iter().map(|c| c[bkt]).sum();
            if tot == n {
                single = true;
                break;
            } else if tot != 0 {
                break;
            }
        }
        if single {
            continue;
        }
        let mut pos = 0;
        for bkt in 0..256 {
            for c in cnt.iter_mut() {
                let k = c[bkt];
                c[bkt] = pos;
                pos += k;
            }
        }
        let dp = SyncPtr(dst.as_mut_ptr());
        par_for_each(nt, n, 1, &mut cnt, |off, _t, lo, hi| {
            for r in &src[lo..hi] {
                let b = &mut off[digit(r, d)];
                // Offsets of different threads never overlap.
                unsafe { *dp.get(*b) = *r };
                *b += 1;
            }
        });
        in_a = !in_a;
    }
    if !in_a {
        a.copy_from_slice(tmp);
    }
}

/* ---------- Timestamp normalization ---------- */

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TsOrder {
    Asis,
    #[default]
    Clamp,
    Sort,
}

impl TsOrder {
    pub fn name(self) -> &'static str {
        match self {
            TsOrder::Asis => "asis",
            TsOrder::Clamp => "clamp",
            TsOrder::Sort => "sort",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TsCfg {
    pub order: TsOrder,
    pub max_gap: i64,           // compress gaps longer than this, ns (0 = off)
    pub exclude_outliers: bool, // exclude outliers from the timeline
    pub outlier_jump: i64,      // clock jump threshold, ns (0 = do not look for jumps)
    pub now_ns: i64,            // current UTC time, ns, for detecting "future" timestamps
    pub threads: usize,         // threads for the computation (0/1 = one); result is identical
}

pub const TS_TOP_GAPS: usize = 10;
pub const TS_SPIKE_LOOKAHEAD: usize = 16;
pub const TS_PAST_LIMIT_NS: i64 = 631152000 * NS_PER_SEC; // 1990-01-01
pub const TS_FUTURE_SLACK_NS: i64 = 86400 * NS_PER_SEC;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TsGap {
    pub at: i64,         // absolute timestamp of gap start
    pub len: i64,        // gap length, ns
    pub idx: u64,        // index of the packet after the gap (in file order), if known
    pub idx_known: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TsResult {
    pub n: u64,         // packets on the timeline (excluding skipped)
    pub first_abs: i64, // timestamp of the first packet (in file order)
    pub min_abs: i64,
    pub max_abs: i64,
    pub base_abs: i64,  // timeline origin
    // non-monotonicity (in file order, relative to the running maximum)
    pub backward: u64,
    pub max_backward: i64,
    pub max_backward_idx: u64,
    // outliers
    pub outl_zero: u64,
    pub outl_past: u64,
    pub outl_future: u64,
    pub outl_spike: u64,
    pub outliers: u64,
    pub excluded: bool,
    // gaps
    pub gaps_over: u64,  // number of gaps longer than max_gap
    pub gap_removed: i64, // total time cut out
    pub top: [TsGap; TS_TOP_GAPS],
    pub ntop: usize,
    // result
    pub monotone: bool,  // timeline is non-decreasing in file order
    pub duration: i64,   // timeline duration (ns)
    pub lap_len: i64,    // length of one lap when looping (ns)
}

/// Send time: T0 + (lap_index * lap_len + ts) / multiplier.
#[inline(always)]
pub fn target(t0: i64, lap: u64, lap_len: i64, sched: i64, inv_mult: f64) -> i64 {
    t0 + ((lap as f64 * lap_len as f64 + sched as f64) * inv_mult) as i64
}

/*
 * Every phase below runs over contiguous chunks in parallel and reproduces the original
 * sequential algorithm exactly: phases that carry state from one packet to the next
 * (running maximum, accumulated gap excess, last mapped value, last good timestamp) are
 * split into a pass that summarizes each chunk, a short sequential merge of those
 * summaries in chunk order, and a pass that redoes the chunk starting from the state
 * the sequential algorithm would have had at its first packet. src/ref_sched.rs keeps
 * the original single-threaded code, and the unit tests compare both bit for bit.
 */

/// Chunk boundaries are multiples of 64 packets, so chunks never share a bitmap byte.
const NORM_ALIGN: usize = 64;

pub(crate) fn top_insert(top: &mut [TsGap; TS_TOP_GAPS], ntop: &mut usize, g: TsGap) {
    if g.len <= 0 {
        return;
    }
    if *ntop == TS_TOP_GAPS && top[TS_TOP_GAPS - 1].len >= g.len {
        return;
    }
    let mut pos = if *ntop < TS_TOP_GAPS {
        *ntop += 1;
        *ntop - 1
    } else {
        TS_TOP_GAPS - 1
    };
    while pos > 0 && top[pos - 1].len < g.len {
        top[pos] = top[pos - 1];
        pos -= 1;
    }
    top[pos] = g;
}

/// Gaps to compress: E(x) = total time cut out before moment x.
#[derive(Default)]
pub(crate) struct GapList {
    pub b: Vec<i64>,   // upper end of the gap
    pub cum: Vec<i64>, // accumulated cut time
}

impl GapList {
    pub fn excess(&self, x: i64) -> i64 {
        // last k with b[k] <= x
        let lo = self.b.partition_point(|&v| v <= x);
        if lo == 0 {
            0
        } else {
            self.cum[lo - 1]
        }
    }
}

#[repr(align(64))]
#[derive(Clone)]
struct NChunk {
    // outliers
    zero: u64,
    past: u64,
    future: u64,
    // exclusion: first good index and last good value
    first_good: usize,
    has_good: bool,
    last_good: i64,
    good_in: i64,
    // bounds
    n: u64,
    has: bool,
    first: i64,
    mn: i64,
    mx: i64,
    cmax: i64,
    backward: u64,
    max_back: i64,
    max_back_idx: u64,
    rm_valid: bool,
    rm_in: i64,
    // gaps
    f: i64,
    l: i64,
    internal: i64,
    big: u64, // gaps above max_gap inside the chunk (unordered path)
    prev_valid: bool,
    prev_in: i64,
    excess_in: i64,
    list_off: usize, // where this chunk writes its gap list entries
    gaps_over: u64,
    maxmapped: i64,
    first_ns: usize, // first non-skipped index (unordered mapping)
    last_mapped: i64,
    top: [TsGap; TS_TOP_GAPS],
    ntop: usize,
    // building the sorted copy
    cnt: usize,
    out_off: usize,
}

impl Default for NChunk {
    fn default() -> Self {
        NChunk {
            zero: 0,
            past: 0,
            future: 0,
            first_good: 0,
            has_good: false,
            last_good: 0,
            good_in: 0,
            n: 0,
            has: false,
            first: 0,
            mn: 0,
            mx: 0,
            cmax: 0,
            backward: 0,
            max_back: 0,
            max_back_idx: 0,
            rm_valid: false,
            rm_in: 0,
            f: 0,
            l: 0,
            internal: 0,
            big: 0,
            prev_valid: false,
            prev_in: 0,
            excess_in: 0,
            list_off: 0,
            gaps_over: 0,
            maxmapped: 0,
            first_ns: 0,
            last_mapped: 0,
            top: [TsGap::default(); TS_TOP_GAPS],
            ntop: 0,
            cnt: 0,
            out_off: 0,
        }
    }
}

#[inline(always)]
fn bit_get(bm: *const u8, i: usize) -> bool {
    unsafe { *bm.add(i >> 3) & (1 << (i & 7)) != 0 }
}

#[inline(always)]
fn bit_set(bm: *mut u8, i: usize) {
    unsafe { *bm.add(i >> 3) |= 1 << (i & 7) };
}

/// Short clock spikes: inherently sequential (each decision depends on the previous
/// "good" packet), but it is a single light pass.
fn find_spikes(ts: &[i64], skip: &dyn Fn(usize) -> bool, bm: *mut u8, jump: i64, res: &mut TsResult) {
    let n = ts.len();
    let mut prev = usize::MAX;
    let mut i = 0;
    while i < n {
        if skip(i) || bit_get(bm, i) {
            i += 1;
            continue;
        }
        if prev != usize::MAX && (ts[i] - ts[prev]).abs() > jump {
            // A jump. If time comes back within a few packets, it is an outlier.
            let mut j = i + 1;
            let mut seen = 0;
            let mut back = false;
            while j < n && seen < TS_SPIKE_LOOKAHEAD {
                if skip(j) || bit_get(bm, j) {
                    j += 1;
                    continue;
                }
                seen += 1;
                if (ts[j] - ts[prev]).abs() <= jump {
                    back = true;
                    break;
                }
                j += 1;
            }
            if back {
                for k in i..j {
                    if skip(k) || bit_get(bm, k) {
                        continue;
                    }
                    bit_set(bm, k);
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

/// Converts absolute timestamps ts (ns) into the schedule timeline (ns from start,
/// accounting for clamp, outliers and max-gap). shard[i] == SHARD_SKIP means the packet
/// is skipped. Packet order is unchanged: with order=sort, sorting is done later, within
/// each shard.
pub fn ts_normalize(ts: &mut [i64], shard: Option<&[u16]>, cfg: &TsCfg) -> TsResult {
    let n = ts.len();
    let mut res = TsResult::default();
    let nt = par_threads(cfg.threads, n);
    let skip = move |i: usize| -> bool { shard.is_some_and(|s| s[i] == SHARD_SKIP) };
    let mut ch = vec![NChunk::default(); nt];
    let tsp = SyncPtr(ts.as_mut_ptr());

    /* 1. Outliers. */
    let mut bmv = vec![0u8; n / 8 + 1];
    let bm = SyncPtr(bmv.as_mut_ptr());
    {
        let future = cfg.now_ns + TS_FUTURE_SLACK_NS;
        let check_future = cfg.now_ns > 0;
        let ts: &[i64] = ts;
        par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
            for i in a..b {
                if skip(i) {
                    continue;
                }
                let v = ts[i];
                if v == 0 {
                    c.zero += 1;
                } else if v < TS_PAST_LIMIT_NS {
                    c.past += 1;
                } else if check_future && v > future {
                    c.future += 1;
                } else {
                    continue;
                }
                bit_set(bm.ptr(), i);
            }
        });
    }
    for c in &ch {
        res.outl_zero += c.zero;
        res.outl_past += c.past;
        res.outl_future += c.future;
    }
    if cfg.outlier_jump > 0 {
        find_spikes(ts, &skip, bm.ptr(), cfg.outlier_jump, &mut res);
    }
    res.outliers = res.outl_zero + res.outl_past + res.outl_future + res.outl_spike;
    if res.outliers > 0 && cfg.exclude_outliers {
        {
            let ts: &[i64] = ts;
            par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
                for i in a..b {
                    if skip(i) || bit_get(bm.ptr(), i) {
                        continue;
                    }
                    if !c.has_good {
                        c.has_good = true;
                        c.first_good = i;
                    }
                    c.last_good = ts[i];
                }
            });
        }
        let mut fg = usize::MAX;
        let mut last = 0;
        for c in &ch {
            if c.has_good && fg == usize::MAX {
                fg = c.first_good;
                last = ts[fg];
            }
        }
        if fg != usize::MAX {
            // Outliers before the first good packet take its timestamp.
            for c in ch.iter_mut() {
                c.good_in = last;
                if c.has_good {
                    last = c.last_good;
                }
            }
            par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
                let mut last = c.good_in;
                for i in a..b {
                    if skip(i) {
                        continue;
                    }
                    // Chunks write disjoint ranges of ts.
                    let p = unsafe { tsp.get(i) };
                    if bit_get(bm.ptr(), i) {
                        unsafe { *p = last };
                    } else {
                        last = unsafe { *p };
                    }
                }
            });
            res.excluded = true;
        }
    }
    drop(bmv);

    /* 2. Bounds, non-monotonicity, clamp. */
    {
        let ts: &[i64] = ts;
        par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
            for i in a..b {
                if skip(i) {
                    continue;
                }
                if !c.has || ts[i] > c.cmax {
                    c.cmax = ts[i];
                }
                c.has = true;
            }
        });
    }
    {
        let mut have = false;
        let mut rm = 0;
        for c in ch.iter_mut() {
            c.rm_valid = have;
            c.rm_in = rm;
            if c.has && (!have || c.cmax > rm) {
                rm = c.cmax;
                have = true;
            }
        }
    }
    let clamp = cfg.order == TsOrder::Clamp;
    par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
        let mut have = c.rm_valid;
        let mut rm = c.rm_in;
        let mut seen = false;
        for i in a..b {
            if skip(i) {
                continue;
            }
            let p = unsafe { tsp.get(i) };
            let v = unsafe { *p };
            c.n += 1;
            if !seen {
                seen = true;
                c.first = v;
                c.mn = v;
                c.mx = v;
            } else {
                if v < c.mn {
                    c.mn = v;
                }
                if v > c.mx {
                    c.mx = v;
                }
            }
            if !have {
                have = true;
                rm = v;
                continue;
            }
            if v < rm {
                c.backward += 1;
                if rm - v > c.max_back {
                    c.max_back = rm - v;
                    c.max_back_idx = i as u64;
                }
                if clamp {
                    unsafe { *p = rm };
                }
            } else {
                rm = v;
            }
        }
    });
    let mut have = false;
    for c in &ch {
        res.n += c.n;
        if c.n == 0 {
            continue;
        }
        if !have {
            have = true;
            res.first_abs = c.first;
            res.min_abs = c.mn;
            res.max_abs = c.mx;
        } else {
            res.min_abs = res.min_abs.min(c.mn);
            res.max_abs = res.max_abs.max(c.mx);
        }
        res.backward += c.backward;
        if c.max_back > res.max_backward {
            res.max_backward = c.max_back;
            res.max_backward_idx = c.max_back_idx;
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
    for c in ch.iter_mut() {
        c.ntop = 0;
        c.internal = 0;
    }
    let mg = cfg.max_gap;
    if res.monotone {
        // Pass A: first/last packet of the chunk and the excess inside it.
        {
            let ts: &[i64] = ts;
            par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
                let mut seen = false;
                let mut prev = 0;
                c.has = false;
                let mut i = a;
                while i < b {
                    if skip(i) {
                        i += 1;
                        continue;
                    }
                    let v = ts[i];
                    if !seen {
                        seen = true;
                        c.f = v;
                    } else if mg > 0 && v - prev > mg {
                        c.internal += v - prev - mg;
                    }
                    prev = v;
                    if mg <= 0 {
                        // Without max-gap only the first and last values are needed.
                        let mut j = b;
                        while j > i + 1 && skip(j - 1) {
                            j -= 1;
                        }
                        prev = ts[j - 1];
                        break;
                    }
                    i += 1;
                }
                c.has = seen;
                c.l = prev;
            });
        }
        let mut hp = false;
        let mut prev = 0;
        let mut excess = 0;
        for c in ch.iter_mut() {
            c.prev_valid = hp;
            c.prev_in = prev;
            c.excess_in = excess;
            if !c.has {
                continue;
            }
            if hp && mg > 0 && c.f - prev > mg {
                excess += c.f - prev - mg;
            }
            excess += c.internal;
            prev = c.l;
            hp = true;
        }
        // Pass B: the original sequential loop, started from the merged state.
        par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
            let mut first = !c.prev_valid;
            let mut prev = c.prev_in;
            let mut excess = c.excess_in;
            let mut last_mapped = if c.prev_valid { c.prev_in - base - c.excess_in } else { 0 };
            c.maxmapped = i64::MIN;
            for i in a..b {
                let p = unsafe { tsp.get(i) };
                if skip(i) {
                    unsafe { *p = last_mapped };
                    continue;
                }
                let v = unsafe { *p };
                if !first {
                    let gap = v - prev;
                    top_insert(&mut c.top, &mut c.ntop, TsGap { at: prev, len: gap, idx: i as u64, idx_known: true });
                    if mg > 0 && gap > mg {
                        excess += gap - mg;
                        c.gaps_over += 1;
                    }
                }
                first = false;
                prev = v;
                last_mapped = v - base - excess;
                unsafe { *p = last_mapped };
                c.maxmapped = c.maxmapped.max(last_mapped);
            }
        });
        for c in &ch {
            for g in &c.top[..c.ntop] {
                top_insert(&mut res.top, &mut res.ntop, *g);
            }
            res.gaps_over += c.gaps_over;
            maxmapped = maxmapped.max(c.maxmapped);
        }
        res.gap_removed = excess;
    } else {
        // Sorted copy of the timestamps (only for finding gaps).
        par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
            c.cnt = (a..b).filter(|&i| !skip(i)).count();
        });
        let mut k = 0;
        for c in ch.iter_mut() {
            c.out_off = k;
            k += c.cnt;
        }
        let mut s = vec![Rec16::default(); k];
        {
            let sp = SyncPtr(s.as_mut_ptr());
            let ts: &[i64] = ts;
            par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
                let mut o = c.out_off;
                for i in a..b {
                    if !skip(i) {
                        unsafe { *sp.get(o) = Rec16 { key: ts[i], val: 0 } };
                        o += 1;
                    }
                }
            });
        }
        {
            let mut tmp = vec![Rec16::default(); k];
            radix_sort16_mt(&mut s, &mut tmp, nt);
        }

        let ns = par_threads(nt, k);
        for c in ch.iter_mut() {
            c.big = 0;
            c.gaps_over = 0;
        }
        // Chunk t handles gaps ending at j in [a, b).
        par_for_each(ns, k, 1, &mut ch, |c, _t, a, b| {
            for j in a.max(1)..b {
                let gap = s[j].key - s[j - 1].key;
                if mg > 0 && gap > mg {
                    c.internal += gap - mg;
                    c.big += 1;
                }
            }
        });
        let mut excess = 0;
        let mut total = 0usize;
        for c in ch.iter_mut().take(ns) {
            c.excess_in = excess;
            c.list_off = total;
            excess += c.internal;
            total += c.big as usize;
        }
        let mut gl = GapList { b: vec![0; total], cum: vec![0; total] };
        {
            let gb = SyncPtr(gl.b.as_mut_ptr());
            let gc = SyncPtr(gl.cum.as_mut_ptr());
            let s = &s;
            par_for_each(ns, k, 1, &mut ch, |c, _t, a, b| {
                let mut excess = c.excess_in;
                let mut o = c.list_off;
                for j in a.max(1)..b {
                    let gap = s[j].key - s[j - 1].key;
                    top_insert(&mut c.top, &mut c.ntop, TsGap { at: s[j - 1].key, len: gap, idx: 0, idx_known: false });
                    if mg > 0 && gap > mg {
                        excess += gap - mg;
                        c.gaps_over += 1;
                        unsafe {
                            *gb.get(o) = s[j].key;
                            *gc.get(o) = excess;
                        }
                        o += 1;
                    }
                }
            });
        }
        for c in ch.iter().take(ns) {
            for g in &c.top[..c.ntop] {
                top_insert(&mut res.top, &mut res.ntop, *g);
            }
            res.gaps_over += c.gaps_over;
        }
        drop(s);
        res.gap_removed = excess;
        let eb = gl.excess(base);

        {
            let gl = &gl;
            par_for_each(nt, n, NORM_ALIGN, &mut ch, |c, _t, a, b| {
                let mut seen = false;
                let mut last_mapped = 0;
                c.maxmapped = i64::MIN;
                c.first_ns = b;
                for i in a..b {
                    let p = unsafe { tsp.get(i) };
                    if skip(i) {
                        if seen {
                            unsafe { *p = last_mapped };
                        }
                        continue; // leading skipped packets are filled in after the merge
                    }
                    if !seen {
                        seen = true;
                        c.first_ns = i;
                    }
                    let v = unsafe { *p };
                    last_mapped = v - base - (gl.excess(v) - eb);
                    unsafe { *p = last_mapped };
                    c.maxmapped = c.maxmapped.max(last_mapped);
                }
                c.has = seen;
                c.last_mapped = last_mapped;
            });
        }
        // Leading skipped packets of a chunk take the last mapped value before them.
        let mut last_mapped = 0;
        for (t, c) in ch.iter().enumerate() {
            let (a, b) = par_range(nt, n, NORM_ALIGN, t);
            for v in &mut ts[a..c.first_ns.min(b)] {
                *v = last_mapped;
            }
            if c.has {
                last_mapped = c.last_mapped;
                maxmapped = maxmapped.max(c.maxmapped);
            }
        }
    }
    res.duration = maxmapped.max(0);
    // A lap is longer than the file by the mean interval, so that the last packet of a lap and
    // the first packet of the next one do not coincide in time.
    res.lap_len = res.duration + if res.n > 1 { res.duration / (res.n - 1) as i64 } else { 0 };
    if res.lap_len <= 0 {
        res.lap_len = 1000;
    }
    res
}

/* ---------- Rate profile ---------- */

pub const RATE_WINDOWS: usize = 3;
pub const RATE_WINDOWS_NS: [i64; RATE_WINDOWS] = [NS_PER_MS, 10 * NS_PER_MS, NS_PER_SEC];
pub const RATE_WINDOW_NAMES: [&str; RATE_WINDOWS] = ["1 ms", "10 ms", "1 s"];

#[derive(Clone, Copy, Debug, Default)]
pub struct RateCfg {
    pub mult: f64,       // speed multiplier
    pub timing_res: i64, // achievable timing resolution, ns
    pub l2_extra: u32,   // bytes added to each frame (synthetic Ethernet)
    pub nshards: usize,  // number of shards (including non-IP)
    pub threads: usize,  // threads for the computation (0/1 = one); result is identical
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RateResult {
    pub pkts: u64,
    pub bytes: u64,
    pub wall_duration_s: f64,                 // duration after the multiplier
    pub avg_bps: f64,
    pub peak_bps: [f64; RATE_WINDOWS],        // L2 (frame bytes)
    pub peak_l1_bps: [f64; RATE_WINDOWS],     // with preamble, IFG and FCS
    pub gaps_total: u64,                      // intervals within shards
    pub gaps_below_res: u64,                  // of which shorter than timing_res
    pub gaps_lt: [u64; 3],                    // < 1 us, < 10 us, < 100 us
}

/// On-wire bytes beyond the frame: preamble 8 + IFG 12 + FCS 4; minimum frame 60.
#[inline(always)]
pub fn l1_bytes(frame_len: u32) -> u64 {
    frame_len.max(60) as u64 + 24
}

/// The packets in file order, or a sorted copy.
#[derive(Clone, Copy)]
pub(crate) enum View<'a> {
    Plain { t: &'a [i64], ol: &'a [u64], sh: Option<&'a [u16]> },
    Sorted(&'a [Rec16]),
}

impl View<'_> {
    pub fn len(&self) -> usize {
        match self {
            View::Plain { t, .. } => t.len(),
            View::Sorted(s) => s.len(),
        }
    }

    /// (time, length, shard) of entry i, None if it is skipped.
    #[inline(always)]
    pub fn get(&self, i: usize) -> Option<(i64, u32, usize)> {
        match self {
            View::Sorted(s) => Some((s[i].key, (s[i].val & 0xFFFF_FFFF) as u32, (s[i].val >> 32) as usize)),
            View::Plain { t, ol, sh } => {
                let shard = match sh {
                    Some(sh) if sh[i] == SHARD_SKIP => return None,
                    Some(sh) => sh[i] as usize,
                    None => 0,
                };
                Some((t[i], offlen_len(ol[i]), shard))
            }
        }
    }

    /// Time of entry i regardless of whether it is skipped (the view is non-decreasing).
    #[inline(always)]
    fn time(&self, i: usize) -> i64 {
        match self {
            View::Sorted(s) => s[i].key,
            View::Plain { t, .. } => t[i],
        }
    }
}

/// Sorted copy of the non-skipped packets: key = time, val = length | shard << 32.
pub(crate) fn sorted_view(sched: &[i64], offlen: &[u64], shard: Option<&[u16]>, nt: usize) -> Vec<Rec16> {
    let n = sched.len();
    let skip = |i: usize| shard.is_some_and(|s| s[i] == SHARD_SKIP);
    let mut cnt = vec![(0usize, 0usize); nt.max(1)];
    par_for_each(nt, n, 1, &mut cnt, |c, _t, a, b| c.0 = (a..b).filter(|&i| !skip(i)).count());
    let mut k = 0;
    for c in cnt.iter_mut() {
        c.1 = k;
        k += c.0;
    }
    let mut sorted = vec![Rec16::default(); k];
    {
        let sp = SyncPtr(sorted.as_mut_ptr());
        par_for_each(nt, n, 1, &mut cnt, |c, _t, a, b| {
            let mut o = c.1;
            for i in a..b {
                if skip(i) {
                    continue;
                }
                let sh = shard.map_or(0, |s| s[i] as u64);
                unsafe { *sp.get(o) = Rec16 { key: sched[i], val: offlen_len(offlen[i]) as u64 | (sh << 32) } };
                o += 1;
            }
        });
    }
    let mut tmp = vec![Rec16::default(); k];
    radix_sort16_mt(&mut sorted, &mut tmp, nt);
    sorted
}

#[repr(align(64))]
#[derive(Clone, Default)]
struct RChunk {
    pkts: u64,
    bytes: u64,
    sum: u64,  // pass A: bytes and wire bytes of the chunk
    sum1: u64,
    pre: u64,  // prefix of all previous chunks
    pre1: u64,
    tmin: i64,
    tmax: i64,
    has: bool,
    best: [u64; RATE_WINDOWS],
    best1: [u64; RATE_WINDOWS],
    gaps_total: u64,
    gaps_below_res: u64,
    gaps_lt: [u64; 3],
    first: Vec<i64>, // per shard, i64::MIN if not seen
    last: Vec<i64>,
}

const GAP_LT_NS: [i64; 3] = [1000, 10000, 100000];

#[inline(always)]
fn count_gap(gaps_total: &mut u64, gaps_below: &mut u64, gaps_lt: &mut [u64; 3], gw: f64, res_ns: i64) {
    *gaps_total += 1;
    if gw < res_ns as f64 {
        *gaps_below += 1;
    }
    for q in 0..3 {
        if gw < GAP_LT_NS[q] as f64 {
            gaps_lt[q] += 1;
        }
    }
}

pub fn rate_profile(sched: &[i64], offlen: &[u64], shard: Option<&[u16]>, monotone: bool, cfg: &RateCfg) -> RateResult {
    let n = sched.len();
    let mut res = RateResult::default();
    let mut nt = par_threads(cfg.threads, n);
    let nsh = cfg.nshards.max(1);
    let mult = if cfg.mult > 0.0 { cfg.mult } else { 1.0 };
    let mut win = [0i64; RATE_WINDOWS];
    for w in 0..RATE_WINDOWS {
        let s = RATE_WINDOWS_NS[w] as f64 * mult;
        win[w] = if s < 1.0 {
            1
        } else if s > 9e18 {
            i64::MAX
        } else {
            s as i64
        };
    }
    let sorted;
    let v = if monotone {
        View::Plain { t: sched, ol: offlen, sh: shard }
    } else {
        sorted = sorted_view(sched, offlen, shard, nt);
        nt = par_threads(cfg.threads, sorted.len());
        View::Sorted(&sorted)
    };
    let vn = v.len();
    let extra = cfg.l2_extra;
    let mut ch: Vec<RChunk> = (0..nt)
        .map(|_| RChunk { first: vec![i64::MIN; nsh], last: vec![i64::MIN; nsh], ..Default::default() })
        .collect();

    par_for_each(nt, vn, 1, &mut ch, |c, _t, a, b| {
        for i in a..b {
            if let Some((_, len, _)) = v.get(i) {
                let len = len + extra;
                c.sum += len as u64;
                c.sum1 += l1_bytes(len);
            }
        }
    });
    let mut pre = 0;
    let mut pre1 = 0;
    for c in ch.iter_mut() {
        c.pre = pre;
        c.pre1 = pre1;
        pre += c.sum;
        pre1 += c.sum1;
    }
    let pres: Vec<(u64, u64)> = ch.iter().map(|c| (c.pre, c.pre1)).collect();
    // Sum of bytes (and wire bytes) of valid entries in [0, pos).
    let prefix_at = |pos: usize| -> (u64, u64) {
        let mut t = 0;
        let mut a = 0;
        while t < nt {
            let (ca, cb) = par_range(nt, vn, 1, t);
            a = ca;
            if pos < cb || t == nt - 1 {
                break;
            }
            t += 1;
        }
        let (mut s, mut s1) = pres[t];
        for i in a..pos {
            if let Some((_, len, _)) = v.get(i) {
                let len = len + extra;
                s += len as u64;
                s1 += l1_bytes(len);
            }
        }
        (s, s1)
    };
    par_for_each(nt, vn, 1, &mut ch, |c, _t, a, b| {
        let mut r0 = a;
        while r0 < b && v.get(r0).is_none() {
            r0 += 1;
        }
        if r0 >= b {
            return;
        }
        let t0 = v.get(r0).unwrap().0;
        // Window state at r0, as the sequential pass would have it before adding r0.
        let mut left = [0usize; RATE_WINDOWS];
        let mut sum = [0u64; RATE_WINDOWS];
        let mut sum1 = [0u64; RATE_WINDOWS];
        let (pr, pr1) = prefix_at(r0);
        for w in 0..RATE_WINDOWS {
            // First entry with t > t(r0) - win: entries before it have left the window.
            let (mut lo, mut hi) = (0, r0);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if t0 - v.time(mid) >= win[w] {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            left[w] = lo;
            let (pl, pl1) = prefix_at(lo);
            sum[w] = pr - pl;
            sum1[w] = pr1 - pl1;
        }
        for r in r0..b {
            let Some((tt, len, sh)) = v.get(r) else { continue };
            let len = len + extra;
            if !c.has {
                c.has = true;
                c.tmin = tt;
            }
            c.tmax = tt;
            c.pkts += 1;
            c.bytes += len as u64;
            if sh < nsh {
                if c.last[sh] != i64::MIN {
                    count_gap(&mut c.gaps_total, &mut c.gaps_below_res, &mut c.gaps_lt,
                              (tt - c.last[sh]) as f64 / mult, cfg.timing_res);
                } else {
                    c.first[sh] = tt;
                }
                c.last[sh] = tt;
            }
            for w in 0..RATE_WINDOWS {
                sum[w] += len as u64;
                sum1[w] += l1_bytes(len);
                loop {
                    let Some((tl, ll, _)) = v.get(left[w]) else {
                        left[w] += 1;
                        continue;
                    };
                    if tt - tl >= win[w] {
                        let ll = ll + extra;
                        sum[w] -= ll as u64;
                        sum1[w] -= l1_bytes(ll);
                        left[w] += 1;
                    } else {
                        break;
                    }
                }
                c.best[w] = c.best[w].max(sum[w]);
                c.best1[w] = c.best1[w].max(sum1[w]);
            }
        }
    });

    // Merge in chunk order; gaps between chunks are counted per shard here.
    let mut glast = vec![i64::MIN; nsh];
    let mut best = [0u64; RATE_WINDOWS];
    let mut best1 = [0u64; RATE_WINDOWS];
    let mut tmin = i64::MAX;
    let mut tmax = i64::MIN;
    for c in &ch {
        if !c.has {
            continue;
        }
        res.pkts += c.pkts;
        res.bytes += c.bytes;
        tmin = tmin.min(c.tmin);
        tmax = tmax.max(c.tmax);
        for w in 0..RATE_WINDOWS {
            best[w] = best[w].max(c.best[w]);
            best1[w] = best1[w].max(c.best1[w]);
        }
        res.gaps_total += c.gaps_total;
        res.gaps_below_res += c.gaps_below_res;
        for q in 0..3 {
            res.gaps_lt[q] += c.gaps_lt[q];
        }
        for s in 0..nsh {
            if c.first[s] == i64::MIN {
                continue;
            }
            if glast[s] != i64::MIN {
                count_gap(&mut res.gaps_total, &mut res.gaps_below_res, &mut res.gaps_lt,
                          (c.first[s] - glast[s]) as f64 / mult, cfg.timing_res);
            }
            glast[s] = c.last[s];
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

/* ---------- Lateness histogram (log-linear, no allocation) ---------- */

pub const LH_SUB_BITS: u32 = 3;
pub const LH_SUB: u32 = 1 << LH_SUB_BITS;
pub const LH_BUCKETS: usize = 64 * LH_SUB as usize;

#[inline(always)]
pub fn lh_bucket(v: u64) -> usize {
    if v < LH_SUB as u64 {
        return v as usize;
    }
    let msb = 63 - v.leading_zeros();
    let shift = msb - LH_SUB_BITS;
    ((msb - LH_SUB_BITS + 1) * LH_SUB + ((v >> shift) as u32 & (LH_SUB - 1))) as usize
}

/// Upper bound of a bucket's values.
pub fn lh_upper(b: usize) -> u64 {
    let b = b as u32;
    if b < LH_SUB {
        return b as u64;
    }
    let g = b / LH_SUB;
    let m = b % LH_SUB;
    let shift = g - 1;
    let lower = ((LH_SUB + m) as u64) << shift;
    lower + ((1u64 << shift) - 1)
}

/// Value of the q-quantile (0..1) from the histogram; 0 if empty.
pub fn lh_quantile(hist: &[u64], q: f64) -> u64 {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return 0;
    }
    // Rank definition: the smallest value such that at least q*N elements are <= it.
    let mut want = (q * total as f64).ceil() as u64;
    want = want.saturating_sub(1);
    if want >= total {
        want = total - 1;
    }
    let mut acc = 0;
    for (b, &h) in hist.iter().enumerate() {
        acc += h;
        if acc > want {
            return lh_upper(b);
        }
    }
    lh_upper(LH_BUCKETS - 1)
}

/* ---------- Rate timeline (--mbps / --pps) ---------- */

/// Timeline for --mbps/--pps: ts[i] = (bytes, or packets, of all non-skipped packets before
/// i in file order) * ns_per_unit. Skipped packets get the value of the next one. Returns
/// the length of one lap in ns.
pub fn rate_timeline(ts: &mut [i64], offlen: &[u64], shard: Option<&[u16]>, l2_extra: u32,
                     per_packet: bool, ns_per_unit: f64, threads: usize) -> i64 {
    let n = ts.len();
    let nt = par_threads(threads, n);
    let units = |i: usize| -> u64 {
        if shard.is_some_and(|s| s[i] == SHARD_SKIP) {
            return 0;
        }
        if per_packet {
            1
        } else {
            (offlen_len(offlen[i]) + l2_extra) as u64
        }
    };
    let mut sums = vec![0u64; nt.max(1)];
    par_for_each(nt, n, 1, &mut sums, |s, _t, a, b| *s = (a..b).map(units).sum());
    let mut total = 0u64;
    for s in sums.iter_mut() {
        let v = *s;
        *s = total;
        total += v;
    }
    let tsp = SyncPtr(ts.as_mut_ptr());
    par_for_each(nt, n, 1, &mut sums, |cum, _t, a, b| {
        let mut c = *cum;
        for i in a..b {
            unsafe { *tsp.get(i) = (c as f64 * ns_per_unit) as i64 };
            c += units(i);
        }
    });
    let lap = (total as f64 * ns_per_unit) as i64;
    if lap > 0 {
        lap
    } else {
        1000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offlen_make;
    use crate::ref_sched::{ref_rate_profile, ref_ts_normalize};

    const T0: i64 = 1700000000 * NS_PER_SEC;

    fn cfg_of(order: TsOrder, max_gap: i64) -> TsCfg {
        TsCfg { order, max_gap, outlier_jump: 60 * NS_PER_SEC, now_ns: 1800000000 * NS_PER_SEC, ..Default::default() }
    }

    #[test]
    fn orders() {
        let mut ts = [T0, T0 + 10, T0 + 5, T0 + 20];
        let r = ts_normalize(&mut ts, None, &cfg_of(TsOrder::Clamp, 0));
        assert_eq!(ts, [0, 10, 10, 20]);
        assert_eq!(r.backward, 1);
        assert_eq!(r.max_backward, 5);
        assert_eq!(r.max_backward_idx, 2);
        assert!(r.monotone);
        assert_eq!(r.duration, 20);

        let mut ts = [T0, T0 + 10, T0 + 5, T0 + 20];
        let r = ts_normalize(&mut ts, None, &cfg_of(TsOrder::Asis, 0));
        assert_eq!(ts, [0, 10, 5, 20]);
        assert!(!r.monotone);

        // sort: the origin is the minimum, even if it is not first
        let mut ts = [T0 + 10, T0, T0 + 30];
        let r = ts_normalize(&mut ts, None, &cfg_of(TsOrder::Sort, 0));
        assert_eq!(ts, [10, 0, 30]);
        assert_eq!(r.duration, 30);

        // asis: the first in file order is the origin, earlier ones go negative
        let mut ts = [T0 + 10, T0, T0 + 30];
        ts_normalize(&mut ts, None, &cfg_of(TsOrder::Asis, 0));
        assert_eq!(ts, [0, -10, 20]);
    }

    #[test]
    fn max_gap() {
        let mut c = cfg_of(TsOrder::Clamp, 10);
        let mut ts = [T0, T0 + 1, T0 + 100, T0 + 101, T0 + 105];
        let r = ts_normalize(&mut ts, None, &c);
        assert_eq!(ts, [0, 1, 11, 12, 16]);
        assert_eq!(r.gaps_over, 1);
        assert_eq!(r.gap_removed, 89);
        assert_eq!(r.top[0].len, 99);
        assert_eq!(r.top[0].idx, 2);
        assert_eq!(r.duration, 16);

        // Non-monotonic case: gaps are computed on the sorted timeline
        let mut ts = [T0, T0 + 100, T0 + 50, T0 + 101];
        c.order = TsOrder::Asis;
        let r = ts_normalize(&mut ts, None, &c);
        assert_eq!(ts, [0, 20, 10, 21]);
        assert_eq!(r.gap_removed, 80);

        // A gap of exactly max_gap is not compressed
        let mut ts = [T0, T0 + 10, T0 + 20];
        c.order = TsOrder::Clamp;
        ts_normalize(&mut ts, None, &c);
        assert_eq!(ts, [0, 10, 20]);
    }

    #[test]
    fn outliers() {
        let mut c = cfg_of(TsOrder::Clamp, 0);
        let base = [0, T0, T0 + 1000, 5, T0 + 3000, 4000000000 * NS_PER_SEC, T0 + 5000];
        let mut ts = base;
        let r = ts_normalize(&mut ts, None, &c);
        assert_eq!(r.outl_zero, 1);
        assert_eq!(r.outl_past, 1);
        assert_eq!(r.outl_future, 1);
        assert_eq!(r.outliers, 3);
        assert!(!r.excluded);

        let mut ts = base;
        c.exclude_outliers = true;
        let r = ts_normalize(&mut ts, None, &c);
        assert!(r.excluded);
        // outliers get their neighbour's timestamp, leading ones get the first normal one
        assert_eq!(ts, [0, 0, 1000, 1000, 3000, 3000, 5000]);
        assert_eq!(r.duration, 5000);
        assert_eq!(r.backward, 0);

        // Short-lived clock jump one hour forward
        let mut s = [T0, T0 + 1000, T0 + 3600 * NS_PER_SEC, T0 + 3600 * NS_PER_SEC + 1, T0 + 2000, T0 + 3000];
        let r = ts_normalize(&mut s, None, &c);
        assert_eq!(r.outl_spike, 2);
        assert_eq!(s, [0, 1000, 1000, 1000, 2000, 3000]);

        // A real long jump (no return) is not an outlier
        let mut j = [T0, T0 + 1000, T0 + 3600 * NS_PER_SEC, T0 + 3600 * NS_PER_SEC + 1000];
        let r = ts_normalize(&mut j, None, &c);
        assert_eq!(r.outl_spike, 0);
        assert_eq!(r.duration, 3600 * NS_PER_SEC + 1000);
    }

    #[test]
    fn skips() {
        let mut ts = [T0 + 7, T0, T0 + 10, T0 + 3];
        let sh = [SHARD_SKIP, 0, SHARD_SKIP, 1];
        let r = ts_normalize(&mut ts, Some(&sh), &cfg_of(TsOrder::Clamp, 0));
        assert_eq!(r.n, 2);
        assert_eq!(r.backward, 0);
        assert_eq!(ts[1], 0);
        assert_eq!(ts[3], 3);
        assert_eq!(r.duration, 3);
    }

    #[test]
    fn targets() {
        // t_send = T0 + (lap * lap_len + ts) / multiplier
        assert_eq!(target(1000, 0, 100, 10, 1.0), 1010);
        assert_eq!(target(1000, 0, 100, 10, 0.5), 1005); // x2
        assert_eq!(target(1000, 0, 100, 10, 2.0), 1020); // x0.5
        assert_eq!(target(1000, 2, 100, 10, 0.5), 1105); // third lap, x2
        // Large values: a day-long timeline, nanosecond precision
        let day = 86400 * NS_PER_SEC;
        assert_eq!(target(0, 3, day, 123456789, 1.0), 3 * day + 123456789);
        // Lap length = duration + mean interval
        let mut ts = [T0, T0 + 10, T0 + 20, T0 + 30];
        let r = ts_normalize(&mut ts, None, &cfg_of(TsOrder::Clamp, 0));
        assert_eq!(r.duration, 30);
        assert_eq!(r.lap_len, 40);
        // The second lap continues the first: the last packet of lap 0 is earlier than the
        // first packet of lap 1
        assert!(target(0, 0, r.lap_len, ts[3], 1.0) < target(0, 1, r.lap_len, ts[0], 1.0));
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn radix() {
        let mut rng = Rng(7);
        let mut a: Vec<Rec16> =
            (0..5000).map(|i| Rec16 { key: (rng.next() % 200) as i64 - 100, val: i }).collect();
        let mut tmp = vec![Rec16::default(); a.len()];
        radix_sort16(&mut a, &mut tmp);
        for w in a.windows(2) {
            assert!(w[0].key <= w[1].key);
            if w[0].key == w[1].key {
                assert!(w[0].val < w[1].val); // stability
            }
        }
    }

    #[test]
    fn rate() {
        // 10 frames of 1000 bytes within 1 ms, then a 1 s gap
        let mut t = [0i64; 11];
        let mut ol = [0u64; 11];
        let mut sh = [0u16; 11];
        for i in 0..10 {
            t[i] = i as i64 * 100000;
            ol[i] = offlen_make(0, 1000);
        }
        t[10] = NS_PER_SEC + 900000;
        ol[10] = offlen_make(0, 1000);
        sh[10] = 1;
        let mut c = RateCfg { mult: 1.0, timing_res: 2000, nshards: 2, ..Default::default() };
        let r = rate_profile(&t, &ol, Some(&sh), true, &c);
        assert_eq!(r.pkts, 11);
        assert_eq!(r.peak_bps[0] as i64, 80000000); // 10*1000*8 bits / 1 ms
        assert_eq!(r.peak_l1_bps[0] as i64, 81920000); // (1000+24)*8*10 / 1 ms
        assert_eq!(r.peak_bps[2] as i64, 80000); // 1 s window
        assert_eq!(r.gaps_total, 9); // shard 1 has a single packet
        assert_eq!(r.gaps_below_res, 0);
        assert_eq!(r.gaps_lt[2], 0);
        // x100: intervals 1 us < 2 us, the 1 ms peak grows
        c.mult = 100.0;
        let r = rate_profile(&t, &ol, Some(&sh), true, &c);
        assert_eq!(r.gaps_below_res, 9);
        assert_eq!(r.gaps_lt[1], 9);
        assert_eq!(r.peak_bps[0] as i64, 80000000);
        assert_eq!(r.peak_bps[2] as i64, 88000); // 1 s window = 100 s of timeline, all 11 frames
        // Non-monotonic order gives the same result
        let t2: Vec<i64> = t.iter().rev().copied().collect();
        let ol2: Vec<u64> = ol.iter().rev().copied().collect();
        let sh2: Vec<u16> = sh.iter().rev().copied().collect();
        c.mult = 1.0;
        let r = rate_profile(&t2, &ol2, Some(&sh2), false, &c);
        assert_eq!(r.peak_bps[0] as i64, 80000000);
        assert_eq!(r.gaps_total, 9);
    }

    #[test]
    fn histogram() {
        for v in 0..100000u64 {
            let b = lh_bucket(v);
            assert!(b < LH_BUCKETS);
            assert!(lh_upper(b) >= v);
            if b > 0 {
                assert!(lh_upper(b - 1) < v);
            }
        }
        assert!(lh_bucket(u64::MAX) < LH_BUCKETS);
        let mut h = vec![0u64; LH_BUCKETS];
        h[lh_bucket(1000)] += 99;
        h[lh_bucket(1000000)] += 1;
        let p50 = lh_quantile(&h, 0.5);
        let p99 = lh_quantile(&h, 0.99);
        assert!((1000..1130).contains(&p50));
        assert!((1000..1130).contains(&p99));
        assert!(lh_quantile(&h, 1.0) >= 1000000);
    }

    /// Timestamps with gaps, backward jumps, outliers and spikes; some packets skipped.
    fn gen_data(rng: &mut Rng, n: usize, pattern: i32) -> (Vec<i64>, Vec<u16>, Vec<u64>) {
        let (mut ts, mut sh, mut ol) = (vec![0; n], vec![0; n], vec![0; n]);
        let mut t = T0;
        let mut skip_run = 0u64;
        for i in 0..n {
            // pattern 3: every other gap is above max-gap, so chunk boundaries hit them
            t += (rng.next() % if pattern == 3 { 100000 } else { 3000 }) as i64;
            if rng.next() % 5000 == 0 {
                t += (rng.next() % (5 * NS_PER_SEC as u64)) as i64; // big pause
            }
            let mut v = t;
            if pattern >= 1 && rng.next() % 50 == 0 {
                v -= (rng.next() % 20000) as i64; // backward in time
            }
            if pattern >= 2 {
                match rng.next() % 20000 {
                    0 => v = 0,
                    1 => v = 4000000000 * NS_PER_SEC, // far future
                    2 => v = t + 3600 * NS_PER_SEC,   // short clock spike
                    _ => {}
                }
            }
            if pattern == 5 && rng.next() % 5 == 0 {
                v = if rng.next() & 1 != 0 { 0 } else { 4000000000 * NS_PER_SEC }; // frequent outliers
            }
            ts[i] = v;
            // pattern 4: long runs of skipped packets that cover chunk boundaries
            if pattern == 4 && skip_run == 0 && rng.next() % 3000 == 0 {
                skip_run = 500 + rng.next() % 5000;
            }
            if skip_run > 0 {
                skip_run -= 1;
                sh[i] = SHARD_SKIP;
            } else {
                sh[i] = if rng.next() % 37 == 0 { SHARD_SKIP } else { (rng.next() % 6) as u16 };
            }
            if pattern == 4 && rng.next() % 40 == 0 {
                ts[i] -= (rng.next() % 20000) as i64; // unordered too
            }
            ol[i] = offlen_make(i as u64 * 100, 40 + (rng.next() % 1500) as u32);
        }
        (ts, sh, ol)
    }

    /// The parallel implementation against the original single-threaded one.
    #[test]
    fn parallel_equivalence() {
        const N: usize = 300000;
        let mut rng = Rng(88172645463325252);
        let mut cases = 0;
        let mut bad = 0;
        for pattern in 0..6 {
            let (orig, sh, ol) = gen_data(&mut rng, N, pattern);
            for order in [TsOrder::Asis, TsOrder::Clamp, TsOrder::Sort] {
                for mg in [0, 50000] {
                    for ex in [false, true] {
                        let mut c = TsCfg { order, max_gap: mg, exclude_outliers: ex, outlier_jump: 60 * NS_PER_SEC,
                                            now_ns: 1800000000 * NS_PER_SEC, threads: 1 };
                        let mut a = orig.clone();
                        let rr = ref_ts_normalize(&mut a, Some(&sh), &c);
                        let mut rc = RateCfg { mult: 3.0, timing_res: 2000, nshards: 6, ..Default::default() };
                        let qr = ref_rate_profile(&a, &ol, Some(&sh), rr.monotone, &rc);
                        for th in [1, 2, 3, 7, 16] {
                            c.threads = th;
                            rc.threads = th;
                            let mut b = orig.clone();
                            let rp = ts_normalize(&mut b, Some(&sh), &c);
                            let qp = rate_profile(&b, &ol, Some(&sh), rp.monotone, &rc);
                            cases += 1;
                            if a != b || rr != rp || qr != qp {
                                bad += 1;
                                eprintln!("parallel mismatch: pattern {} order {:?} max_gap {} exclude {} threads {}",
                                          pattern, order, mg, ex, th);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 6 * 3 * 2 * 2 * 5);
        assert_eq!(bad, 0);

        // Parallel radix sort: same order of equal keys as the sequential one
        let mut r1: Vec<Rec16> =
            (0..N).map(|i| Rec16 { key: (rng.next() % 100000) as i64 - 50000, val: i as u64 }).collect();
        let mut r2 = r1.clone();
        let mut tmp = vec![Rec16::default(); N];
        radix_sort16(&mut r1, &mut tmp);
        radix_sort16_mt(&mut r2, &mut tmp, 7);
        assert_eq!(r1, r2);
    }

    #[test]
    fn rate_timeline_cases() {
        // ts = units before the packet in file order * ns_per_unit; skipped packets add nothing
        let mut ts = [0i64; 5];
        let ol = [offlen_make(0, 100), offlen_make(0, 200), offlen_make(0, 50), offlen_make(0, 300), offlen_make(0, 10)];
        let sh = [0, 3, SHARD_SKIP, 1, 0];
        let lap = rate_timeline(&mut ts, &ol, Some(&sh), 0, false, 2.0, 1);
        assert_eq!(ts, [0, 200, 600, 600, 1200]);
        assert_eq!(lap, 1220);
        // per packet, with the synthetic Ethernet header ignored
        let lap = rate_timeline(&mut ts, &ol, Some(&sh), 14, true, 10.0, 1);
        assert_eq!(ts, [0, 10, 20, 20, 30]);
        assert_eq!(lap, 40);
        // parallel version is identical
        const N: usize = 400000;
        let mut rng = Rng(12345);
        let o2: Vec<u64> = (0..N).map(|i| offlen_make(i as u64, 60 + (rng.next() % 1400) as u32)).collect();
        let s2: Vec<u16> = (0..N).map(|_| if rng.next() % 50 == 0 { SHARD_SKIP } else { 0 }).collect();
        let mut a = vec![0i64; N];
        let mut b = vec![0i64; N];
        let l1 = rate_timeline(&mut a, &o2, Some(&s2), 0, false, 0.8, 1);
        let l7 = rate_timeline(&mut b, &o2, Some(&s2), 0, false, 0.8, 7);
        assert_eq!(l1, l7);
        assert_eq!(a, b);
    }
}
