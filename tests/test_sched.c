#include "sched.h"
#include "t.h"

#include <stdlib.h>
#include <string.h>

#define T0 (1700000000LL * NS_PER_SEC)

static ts_cfg_t cfg_of(int order, int64_t max_gap)
{
	ts_cfg_t c = {.order = order, .max_gap = max_gap, .outlier_jump = 60 * NS_PER_SEC,
	              .now_ns = 1800000000LL * NS_PER_SEC};
	return c;
}

static void check_arr(const int64_t *got, const int64_t *exp, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (got[i] != exp[i])
			fprintf(stderr, "  [%zu]: %lld != %lld\n", i, (long long)got[i], (long long)exp[i]);
		CHECK_EQ(got[i], exp[i]);
	}
}

static void orders(void)
{
	ts_result_t r;
	ts_cfg_t c;
	{
		int64_t ts[] = {T0, T0 + 10, T0 + 5, T0 + 20};
		c = cfg_of(TS_ORDER_CLAMP, 0);
		CHECK_EQ(afr_ts_normalize(ts, NULL, 4, &c, &r), 0);
		int64_t e[] = {0, 10, 10, 20};
		check_arr(ts, e, 4);
		CHECK_EQ(r.backward, 1);
		CHECK_EQ(r.max_backward, 5);
		CHECK_EQ(r.max_backward_idx, 2);
		CHECK(r.monotone);
		CHECK_EQ(r.duration, 20);
	}
	{
		int64_t ts[] = {T0, T0 + 10, T0 + 5, T0 + 20};
		c = cfg_of(TS_ORDER_ASIS, 0);
		afr_ts_normalize(ts, NULL, 4, &c, &r);
		int64_t e[] = {0, 10, 5, 20};
		check_arr(ts, e, 4);
		CHECK(!r.monotone);
	}
	{
		/* sort: the origin is the minimum, even if it is not first */
		int64_t ts[] = {T0 + 10, T0, T0 + 30};
		c = cfg_of(TS_ORDER_SORT, 0);
		afr_ts_normalize(ts, NULL, 3, &c, &r);
		int64_t e[] = {10, 0, 30};
		check_arr(ts, e, 3);
		CHECK_EQ(r.duration, 30);
	}
	{
		/* asis: the first in file order is the origin, earlier ones go negative */
		int64_t ts[] = {T0 + 10, T0, T0 + 30};
		c = cfg_of(TS_ORDER_ASIS, 0);
		afr_ts_normalize(ts, NULL, 3, &c, &r);
		int64_t e[] = {0, -10, 20};
		check_arr(ts, e, 3);
	}
}

static void max_gap(void)
{
	ts_result_t r;
	ts_cfg_t c = cfg_of(TS_ORDER_CLAMP, 10);
	{
		int64_t ts[] = {T0, T0 + 1, T0 + 100, T0 + 101, T0 + 105};
		afr_ts_normalize(ts, NULL, 5, &c, &r);
		int64_t e[] = {0, 1, 11, 12, 16};
		check_arr(ts, e, 5);
		CHECK_EQ(r.gaps_over, 1);
		CHECK_EQ(r.gap_removed, 89);
		CHECK_EQ(r.top[0].len, 99);
		CHECK_EQ(r.top[0].idx, 2);
		CHECK_EQ(r.duration, 16);
	}
	{
		/* Non-monotonic case: gaps are computed on the sorted timeline */
		int64_t ts[] = {T0, T0 + 100, T0 + 50, T0 + 101};
		c.order = TS_ORDER_ASIS;
		afr_ts_normalize(ts, NULL, 4, &c, &r);
		int64_t e[] = {0, 20, 10, 21};
		check_arr(ts, e, 4);
		CHECK_EQ(r.gap_removed, 80);
	}
	{
		/* A gap of exactly max_gap is not compressed */
		int64_t ts[] = {T0, T0 + 10, T0 + 20};
		c.order = TS_ORDER_CLAMP;
		afr_ts_normalize(ts, NULL, 3, &c, &r);
		int64_t e[] = {0, 10, 20};
		check_arr(ts, e, 3);
	}
}

static void outliers(void)
{
	ts_result_t r;
	ts_cfg_t c = cfg_of(TS_ORDER_CLAMP, 0);
	int64_t base[] = {0, T0, T0 + 1000, 5, T0 + 3000, 4000000000LL * NS_PER_SEC, T0 + 5000};
	int64_t ts[7];

	memcpy(ts, base, sizeof(ts));
	afr_ts_normalize(ts, NULL, 7, &c, &r);
	CHECK_EQ(r.outl_zero, 1);
	CHECK_EQ(r.outl_past, 1);
	CHECK_EQ(r.outl_future, 1);
	CHECK_EQ(r.outliers, 3);
	CHECK(!r.excluded);

	memcpy(ts, base, sizeof(ts));
	c.exclude_outliers = 1;
	afr_ts_normalize(ts, NULL, 7, &c, &r);
	CHECK(r.excluded);
	/* outliers get their neighbour's timestamp, leading ones get the first normal one */
	int64_t e[] = {0, 0, 1000, 1000, 3000, 3000, 5000};
	check_arr(ts, e, 7);
	CHECK_EQ(r.duration, 5000);
	CHECK_EQ(r.backward, 0);

	/* Short-lived clock jump one hour forward */
	int64_t s[] = {T0, T0 + 1000, T0 + 3600 * NS_PER_SEC, T0 + 3600 * NS_PER_SEC + 1, T0 + 2000,
	               T0 + 3000};
	afr_ts_normalize(s, NULL, 6, &c, &r);
	CHECK_EQ(r.outl_spike, 2);
	int64_t es[] = {0, 1000, 1000, 1000, 2000, 3000};
	check_arr(s, es, 6);

	/* A real long jump (no return) is not an outlier */
	int64_t j[] = {T0, T0 + 1000, T0 + 3600 * NS_PER_SEC, T0 + 3600 * NS_PER_SEC + 1000};
	afr_ts_normalize(j, NULL, 4, &c, &r);
	CHECK_EQ(r.outl_spike, 0);
	CHECK_EQ(r.duration, 3600 * NS_PER_SEC + 1000);
}

static void skips(void)
{
	ts_result_t r;
	ts_cfg_t c = cfg_of(TS_ORDER_CLAMP, 0);
	int64_t ts[] = {T0 + 7, T0, T0 + 10, T0 + 3};
	uint16_t sh[] = {SHARD_SKIP, 0, SHARD_SKIP, 1};
	afr_ts_normalize(ts, sh, 4, &c, &r);
	CHECK_EQ(r.n, 2);
	CHECK_EQ(r.backward, 0);
	CHECK_EQ(ts[1], 0);
	CHECK_EQ(ts[3], 3);
	CHECK_EQ(r.duration, 3);
}

static void targets(void)
{
	/* t_send = T0 + (lap * lap_len + ts) / multiplier */
	CHECK_EQ(afr_target(1000, 0, 100, 10, 1.0), 1010);
	CHECK_EQ(afr_target(1000, 0, 100, 10, 0.5), 1005);  /* x2 */
	CHECK_EQ(afr_target(1000, 0, 100, 10, 2.0), 1020);  /* x0.5 */
	CHECK_EQ(afr_target(1000, 2, 100, 10, 0.5), 1105);  /* third lap, x2 */
	/* Large values: a day-long timeline, nanosecond precision */
	int64_t day = 86400LL * NS_PER_SEC;
	CHECK_EQ(afr_target(0, 3, day, 123456789, 1.0), 3 * day + 123456789);
	/* Lap length = duration + mean interval */
	ts_result_t r;
	ts_cfg_t c = cfg_of(TS_ORDER_CLAMP, 0);
	int64_t ts[] = {T0, T0 + 10, T0 + 20, T0 + 30};
	afr_ts_normalize(ts, NULL, 4, &c, &r);
	CHECK_EQ(r.duration, 30);
	CHECK_EQ(r.lap_len, 40);
	/* The second lap timeline continues the first: the last packet of lap 0
	 * is earlier than the first packet of lap 1 */
	CHECK(afr_target(0, 0, r.lap_len, ts[3], 1.0) < afr_target(0, 1, r.lap_len, ts[0], 1.0));
}

static void radix(void)
{
	enum { N = 5000 };
	rec16_t *a = malloc(N * sizeof(*a)), *tmp = malloc(N * sizeof(*tmp));
	srand(7);
	for (int i = 0; i < N; i++)
		a[i] = (rec16_t){.key = (int64_t)(rand() % 200) - 100, .val = (uint64_t)i};
	afr_radix_sort16(a, tmp, N);
	int ok = 1;
	for (int i = 1; i < N; i++) {
		if (a[i - 1].key > a[i].key)
			ok = 0;
		if (a[i - 1].key == a[i].key && a[i - 1].val > a[i].val)
			ok = 0; /* stability */
	}
	CHECK(ok);
	free(a);
	free(tmp);
}

static void rate(void)
{
	/* 10 frames of 1000 bytes within 1 ms, then a 1 s gap */
	int64_t t[11];
	uint64_t ol[11];
	uint16_t sh[11];
	for (int i = 0; i < 10; i++) {
		t[i] = i * 100000;
		ol[i] = OFFLEN_MAKE(0, 1000);
		sh[i] = 0;
	}
	t[10] = NS_PER_SEC + 900000;
	ol[10] = OFFLEN_MAKE(0, 1000);
	sh[10] = 1;
	rate_cfg_t c = {.mult = 1.0, .timing_res = 2000, .nshards = 2};
	rate_result_t r;
	CHECK_EQ(afr_rate_profile(t, ol, sh, 11, 1, &c, &r), 0);
	CHECK_EQ(r.pkts, 11);
	CHECK_EQ((int64_t)r.peak_bps[0], 80000000);         /* 10*1000*8 bits / 1 ms */
	CHECK_EQ((int64_t)r.peak_l1_bps[0], 81920000);      /* (1000+24)*8*10 / 1 ms */
	CHECK_EQ((int64_t)r.peak_bps[2], 80000);            /* 1 s window */
	CHECK_EQ(r.gaps_total, 9);                          /* shard 1 has a single packet */
	CHECK_EQ(r.gaps_below_res, 0);
	CHECK_EQ(r.gaps_lt[2], 0);
	/* x100: intervals 1 us < 2 us, the 1 ms peak grows */
	c.mult = 100;
	CHECK_EQ(afr_rate_profile(t, ol, sh, 11, 1, &c, &r), 0);
	CHECK_EQ(r.gaps_below_res, 9);
	CHECK_EQ(r.gaps_lt[1], 9);
	CHECK_EQ((int64_t)r.peak_bps[0], 80000000);
	CHECK_EQ((int64_t)r.peak_bps[2], 88000); /* 1 s window = 100 s of timeline, all 11 frames */
	/* Non-monotonic order gives the same result */
	int64_t t2[11];
	uint64_t ol2[11];
	uint16_t sh2[11];
	for (int i = 0; i < 11; i++) {
		t2[i] = t[10 - i];
		ol2[i] = ol[10 - i];
		sh2[i] = sh[10 - i];
	}
	c.mult = 1.0;
	CHECK_EQ(afr_rate_profile(t2, ol2, sh2, 11, 0, &c, &r), 0);
	CHECK_EQ((int64_t)r.peak_bps[0], 80000000);
	CHECK_EQ(r.gaps_total, 9);
}

static void histogram(void)
{
	uint64_t h[LH_BUCKETS];
	memset(h, 0, sizeof(h));
	for (uint64_t v = 0; v < 100000; v++) {
		unsigned b = afr_lh_bucket(v);
		CHECK(b < LH_BUCKETS);
		if (afr_lh_upper(b) < v) {
			CHECK(0);
			break;
		}
		if (b > 0 && afr_lh_upper(b - 1) >= v) {
			CHECK(0);
			break;
		}
	}
	CHECK(afr_lh_bucket(UINT64_MAX) < LH_BUCKETS);
	for (int i = 0; i < 99; i++)
		h[afr_lh_bucket(1000)]++;
	h[afr_lh_bucket(1000000)]++;
	uint64_t p50 = afr_lh_quantile(h, 0.5), p99 = afr_lh_quantile(h, 0.99);
	CHECK(p50 >= 1000 && p50 < 1130);
	CHECK(p99 >= 1000 && p99 < 1130);
	CHECK(afr_lh_quantile(h, 1.0) >= 1000000);
}

void test_sched(void)
{
	orders();
	max_gap();
	outliers();
	skips();
	targets();
	radix();
	rate();
	histogram();
}
