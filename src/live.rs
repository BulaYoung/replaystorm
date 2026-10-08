//! Long-run statistics: what a replay that runs for days has done so far. Updated once a
//! second by the stats thread; shown on request (Enter in the terminal, SIGUSR1) and
//! written to a status file that can be read from any terminal (replaystorm --status).

use crate::NS_PER_SEC;

pub const LIVE_HIST_STEP: f64 = 0.01; // Gbit/s per histogram bin
pub const LIVE_HIST_BINS: usize = 50000; // up to 500 Gbit/s
pub const LIVE_RING: usize = 3600; // last hour of per-second rates
pub const LIVE_WARMUP_NS: i64 = 10 * NS_PER_SEC;

#[derive(Clone)]
pub struct Live {
    pub target_gbps: f64,   // fixed-rate target (0: none)
    pub start_ns: i64,      // CLOCK_MONOTONIC at T0
    pub start_real_ns: i64, // CLOCK_REALTIME at T0
    pub reset_ns: i64,      // last reset of the min/max statistics
    // last second
    pub now_gbps: f64,
    pub now_mpps: f64,
    // counted seconds (warm-up, link outages and partial intervals excluded)
    pub seconds: u64,
    pub excluded: u64,
    pub sum_gbps: f64,
    pub min_gbps: f64,
    pub max_gbps: f64,
    pub min_mpps: f64,
    pub min_at: i64,       // ns since T0
    pub max_at: i64,
    pub below_target: u64, // seconds below 95% of the target
    hist: Vec<u32>,        // per-second Gbit/s histogram
    // rolling windows over counted seconds
    ring: Vec<f64>,
    ring_pos: usize,
    pub ring_n: usize,
    pub sum_60: f64,
    pub sum_3600: f64,
    run: u64,               // consecutive counted seconds (for the worst minute)
    pub worst_min_gbps: f64, // lowest 60-second average
    pub worst_min_at: i64,  // end of that minute, ns since T0
}

impl Live {
    pub fn new(target_gbps: f64, start_ns: i64, start_real_ns: i64) -> Live {
        Live {
            target_gbps,
            start_ns,
            start_real_ns,
            reset_ns: start_ns,
            now_gbps: 0.0,
            now_mpps: 0.0,
            seconds: 0,
            excluded: 0,
            sum_gbps: 0.0,
            min_gbps: 0.0,
            max_gbps: 0.0,
            min_mpps: 0.0,
            min_at: 0,
            max_at: 0,
            below_target: 0,
            hist: vec![0; LIVE_HIST_BINS],
            ring: vec![0.0; LIVE_RING],
            ring_pos: 0,
            ring_n: 0,
            sum_60: 0.0,
            sum_3600: 0.0,
            run: 0,
            worst_min_gbps: 0.0,
            worst_min_at: 0,
        }
    }

    /// Forget minima, maxima, percentiles and windows (totals elsewhere are kept).
    pub fn reset(&mut self, now_ns: i64) {
        let mut l = Live::new(self.target_gbps, self.start_ns, self.start_real_ns);
        l.now_gbps = self.now_gbps;
        l.now_mpps = self.now_mpps;
        l.reset_ns = now_ns;
        *self = l;
    }

    /// One interval: t = end of the interval (ns since T0), dt in seconds. excluded: the
    /// link was down during it.
    pub fn add(&mut self, t: i64, dt: f64, gbps: f64, mpps: f64, excluded: bool) {
        self.now_gbps = gbps;
        self.now_mpps = mpps;
        // Not counted: the warm-up, link outages, and short (partial) intervals.
        if excluded || t < LIVE_WARMUP_NS || dt < 0.9 {
            self.excluded += 1;
            self.run = 0;
            return;
        }
        if self.seconds == 0 || gbps < self.min_gbps {
            self.min_gbps = gbps;
            self.min_at = t;
        }
        if self.seconds == 0 || mpps < self.min_mpps {
            self.min_mpps = mpps;
        }
        if self.seconds == 0 || gbps > self.max_gbps {
            self.max_gbps = gbps;
            self.max_at = t;
        }
        self.seconds += 1;
        self.sum_gbps += gbps;
        if self.target_gbps > 0.0 && gbps < 0.95 * self.target_gbps {
            self.below_target += 1;
        }
        let bin = ((gbps / LIVE_HIST_STEP + 0.5) as usize).min(LIVE_HIST_BINS - 1);
        self.hist[bin] += 1;

        // Rolling windows: the value leaving the last minute, and the last hour.
        if self.ring_n >= 60 {
            self.sum_60 -= self.ring[(self.ring_pos + LIVE_RING - 60) % LIVE_RING];
        }
        if self.ring_n == LIVE_RING {
            self.sum_3600 -= self.ring[self.ring_pos];
        }
        self.ring[self.ring_pos] = gbps;
        self.ring_pos = (self.ring_pos + 1) % LIVE_RING;
        if self.ring_n < LIVE_RING {
            self.ring_n += 1;
        }
        self.sum_60 += gbps;
        self.sum_3600 += gbps;

        // Worst minute: only over 60 consecutive counted seconds.
        self.run += 1;
        if self.run >= 60 && self.ring_n >= 60 {
            let avg = self.sum_60 / 60.0;
            if self.worst_min_at == 0 || avg < self.worst_min_gbps {
                self.worst_min_gbps = avg;
                self.worst_min_at = t;
            }
        }
    }

    /// Value of the q-quantile of the per-second rate, Gbit/s (0 if nothing counted).
    pub fn quantile(&self, q: f64) -> f64 {
        if self.seconds == 0 {
            return 0.0;
        }
        let want = ((q * self.seconds as f64) as u64).min(self.seconds - 1);
        let mut acc = 0u64;
        for (b, &h) in self.hist.iter().enumerate() {
            acc += h as u64;
            if acc > want {
                return b as f64 * LIVE_HIST_STEP;
            }
        }
        (LIVE_HIST_BINS - 1) as f64 * LIVE_HIST_STEP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: i64) -> i64 {
        x * NS_PER_SEC
    }

    #[test]
    fn live() {
        let mut l = Live::new(25.0, 0, 0);
        // warm-up: the first 10 s are not counted
        for t in 1..10 {
            l.add(s(t), 1.0, 1.0, 0.1, false);
        }
        assert_eq!(l.seconds, 0);
        assert_eq!(l.excluded, 9);
        // 100 s at 24, one second at 18 at t=50, a link outage second at 1.0 (excluded)
        for t in 10..110 {
            l.add(s(t), 1.0, if t == 50 { 18.0 } else { 24.0 }, 3.0, false);
        }
        l.add(s(110), 1.0, 1.0, 0.1, true);
        assert_eq!(l.seconds, 100);
        assert_eq!(l.excluded, 10);
        assert_eq!(l.min_gbps, 18.0);
        assert_eq!(l.min_at, s(50));
        assert_eq!(l.max_gbps, 24.0);
        assert_eq!(l.below_target, 1); // < 95% of 25 = 23.75
        // worst minute contains the 18 Gbit/s second: (59*24 + 18) / 60
        assert!(l.worst_min_gbps > 23.89 && l.worst_min_gbps < 23.91);
        assert!(l.quantile(0.005) > 17.99 && l.quantile(0.005) < 18.01);
        assert!(l.quantile(0.5) > 23.99 && l.quantile(0.5) < 24.01);
        // a partial interval is not counted either
        l.add(s(111), 0.4, 5.0, 0.5, false);
        assert_eq!(l.seconds, 100);
        // reset forgets the minimum
        l.reset(s(111));
        l.add(s(112), 1.0, 22.0, 3.0, false);
        assert_eq!(l.min_gbps, 22.0);
        assert_eq!(l.seconds, 1);
        // the worst minute needs 60 consecutive counted seconds
        assert_eq!(l.worst_min_at, 0);
    }
}
