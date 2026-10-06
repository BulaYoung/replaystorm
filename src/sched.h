/*
 * Send schedule: timestamp normalization, send time computation,
 * rate profile. All functions are pure (no global state) and
 * covered by unit tests.
 */
#ifndef AFR_SCHED_H
#define AFR_SCHED_H

#include "afr.h"

/* ---------- Stable radix sort of 16-byte records ---------- */

typedef struct {
	int64_t key;
	uint64_t val;
} rec16_t;

/* Stably sorts a[0..n) by signed key; tmp is a buffer of the same size. */
void afr_radix_sort16(rec16_t *a, rec16_t *tmp, size_t n);
/* The same, using up to nt threads (identical result). */
void afr_radix_sort16_mt(rec16_t *a, rec16_t *tmp, size_t n, unsigned nt);

/* ---------- Timestamp normalization ---------- */

enum { TS_ORDER_ASIS = 0, TS_ORDER_CLAMP, TS_ORDER_SORT };

typedef struct {
	int order;            /* TS_ORDER_* */
	int64_t max_gap;      /* compress gaps longer than this, ns (0 = off) */
	int exclude_outliers; /* exclude outliers from the timeline */
	int64_t outlier_jump; /* clock jump threshold, ns (0 = do not look for jumps) */
	int64_t now_ns;       /* current UTC time, ns, for detecting "future" timestamps */
	unsigned threads;     /* threads for the computation (0/1 = one); result is identical */
} ts_cfg_t;

#define TS_TOP_GAPS 10
#define TS_SPIKE_LOOKAHEAD 16
#define TS_PAST_LIMIT_NS (631152000LL * NS_PER_SEC) /* 1990-01-01 */
#define TS_FUTURE_SLACK_NS (86400LL * NS_PER_SEC)

typedef struct {
	int64_t at;    /* absolute timestamp of gap start */
	int64_t len;   /* gap length, ns */
	uint64_t idx;  /* index of the packet after the gap (in file order), if known */
	int idx_known;
} ts_gap_t;

typedef struct {
	uint64_t n;         /* packets on the timeline (excluding skipped) */
	int64_t first_abs;  /* timestamp of the first packet (in file order) */
	int64_t min_abs, max_abs;
	int64_t base_abs;   /* timeline origin */
	/* non-monotonicity (in file order, relative to the running maximum) */
	uint64_t backward;
	int64_t max_backward;
	uint64_t max_backward_idx;
	/* outliers */
	uint64_t outl_zero, outl_past, outl_future, outl_spike;
	uint64_t outliers;
	int excluded;
	/* gaps */
	uint64_t gaps_over;   /* number of gaps longer than max_gap */
	int64_t gap_removed;  /* total time cut out */
	ts_gap_t top[TS_TOP_GAPS];
	int ntop;
	/* result */
	int monotone;         /* timeline is non-decreasing in file order */
	int64_t duration;     /* timeline duration (ns) */
	int64_t lap_len;      /* length of one lap when looping (ns) */
} ts_result_t;

/*
 * Converts absolute timestamps ts[] (ns) into the schedule timeline (ns from start,
 * accounting for clamp, outliers and max-gap). shard[i] == SHARD_SKIP means the packet
 * is skipped (shard may be NULL). Packet order is unchanged: with
 * order=sort, sorting is done later, within each shard. Returns 0
 * or -1 when out of memory.
 */
int afr_ts_normalize(int64_t *ts, const uint16_t *shard, size_t n, const ts_cfg_t *cfg,
                     ts_result_t *res);

/* Send time: T0 + (lap_index * lap_len + ts) / multiplier. */
static inline int64_t afr_target(int64_t t0, uint64_t lap, int64_t lap_len, int64_t sched,
                                 double inv_mult)
{
	return t0 + (int64_t)(((double)lap * (double)lap_len + (double)sched) * inv_mult);
}

/*
 * Timeline for --mbps/--pps: ts[i] = (bytes, or packets, of all non-skipped packets before
 * i in file order) * ns_per_unit. Skipped packets get the value of the next one. Returns
 * the length of one lap in ns.
 */
int64_t afr_rate_timeline(int64_t *ts, const uint64_t *offlen, const uint16_t *shard, size_t n,
                          uint32_t l2_extra, int per_packet, double ns_per_unit, unsigned threads);

/* ---------- Rate profile ---------- */

#define RATE_WINDOWS 3
extern const int64_t afr_rate_windows_ns[RATE_WINDOWS]; /* 1 ms, 10 ms, 1 s */
extern const char *const afr_rate_window_names[RATE_WINDOWS];

typedef struct {
	double mult;         /* speed multiplier */
	int64_t timing_res;  /* achievable timing resolution, ns */
	uint32_t l2_extra;   /* bytes added to each frame (synthetic Ethernet) */
	unsigned nshards;    /* number of shards (including non-IP) */
	unsigned threads;     /* threads for the computation (0/1 = one); result is identical */
} rate_cfg_t;

typedef struct {
	uint64_t pkts, bytes;
	double wall_duration_s;               /* duration after the multiplier */
	double avg_bps;
	double peak_bps[RATE_WINDOWS];        /* L2 (frame bytes) */
	double peak_l1_bps[RATE_WINDOWS];     /* with preamble, IFG and FCS */
	uint64_t gaps_total;                  /* intervals within shards */
	uint64_t gaps_below_res;              /* of which shorter than timing_res */
	uint64_t gaps_lt[3];                  /* < 1 us, < 10 us, < 100 us */
} rate_result_t;

/* On-wire bytes beyond the frame: preamble 8 + IFG 12 + FCS 4; minimum frame 60. */
static inline uint64_t afr_l1_bytes(uint32_t frame_len)
{
	return (uint64_t)(frame_len < 60 ? 60 : frame_len) + 24;
}

int afr_rate_profile(const int64_t *sched, const uint64_t *offlen, const uint16_t *shard, size_t n,
                     int monotone, const rate_cfg_t *cfg, rate_result_t *res);

/* ---------- Lateness histogram (log-linear, no malloc) ---------- */

#define LH_SUB_BITS 3
#define LH_SUB (1u << LH_SUB_BITS)
#define LH_BUCKETS (64u * LH_SUB)

static inline unsigned afr_lh_bucket(uint64_t v)
{
	if (v < LH_SUB)
		return (unsigned)v;
	unsigned msb = 63u - (unsigned)__builtin_clzll(v);
	unsigned shift = msb - LH_SUB_BITS;
	return (msb - LH_SUB_BITS + 1) * LH_SUB + (unsigned)((v >> shift) & (LH_SUB - 1));
}

/* Upper bound of a bucket's values. */
uint64_t afr_lh_upper(unsigned b);
/* Value of the q-quantile (0..1) from the histogram; 0 if empty. */
uint64_t afr_lh_quantile(const uint64_t *hist, double q);

#endif
