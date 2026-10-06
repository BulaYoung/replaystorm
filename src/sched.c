#include "sched.h"

#include "par.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ---------- Radix sort ---------- */

void afr_radix_sort16(rec16_t *a, rec16_t *tmp, size_t n)
{
	if (n < 2)
		return;
	static const uint64_t SIGN = 1ULL << 63;
	size_t cnt[8][256];
	memset(cnt, 0, sizeof(cnt));
	for (size_t i = 0; i < n; i++) {
		uint64_t k = (uint64_t)a[i].key ^ SIGN;
		for (int d = 0; d < 8; d++)
			cnt[d][(k >> (d * 8)) & 0xFF]++;
	}
	rec16_t *src = a, *dst = tmp;
	for (int d = 0; d < 8; d++) {
		/* All keys share the same digit; this pass is not needed. */
		uint64_t k0 = (uint64_t)src[0].key ^ SIGN;
		if (cnt[d][(k0 >> (d * 8)) & 0xFF] == n)
			continue;
		size_t pos = 0;
		for (int b = 0; b < 256; b++) {
			size_t c = cnt[d][b];
			cnt[d][b] = pos;
			pos += c;
		}
		for (size_t i = 0; i < n; i++) {
			uint64_t k = (uint64_t)src[i].key ^ SIGN;
			dst[cnt[d][(k >> (d * 8)) & 0xFF]++] = src[i];
		}
		rec16_t *t = src;
		src = dst;
		dst = t;
	}
	if (src != a)
		memcpy(a, src, n * sizeof(*a));
}

/*
 * Parallel stable LSD radix sort: per pass each thread counts the digits of its chunk,
 * offsets are laid out bucket by bucket and, within a bucket, chunk by chunk, and each
 * thread scatters its chunk. This keeps the order of equal keys, so the result is
 * identical to afr_radix_sort16.
 */
typedef struct {
	rec16_t *src, *dst;
	size_t (*cnt)[256];
	unsigned d;
	unsigned nt;
} radix_ctx_t;

#define RADIX_SIGN (1ULL << 63)

static void radix_count(void *arg, unsigned t, size_t a, size_t b)
{
	radix_ctx_t *x = arg;
	size_t *c = x->cnt[t];
	memset(c, 0, 256 * sizeof(size_t));
	const unsigned sh = x->d * 8;
	for (size_t i = a; i < b; i++)
		c[(((uint64_t)x->src[i].key ^ RADIX_SIGN) >> sh) & 0xFF]++;
}

static void radix_scatter(void *arg, unsigned t, size_t a, size_t b)
{
	radix_ctx_t *x = arg;
	size_t *off = x->cnt[t];
	const unsigned sh = x->d * 8;
	for (size_t i = a; i < b; i++)
		x->dst[off[(((uint64_t)x->src[i].key ^ RADIX_SIGN) >> sh) & 0xFF]++] = x->src[i];
}

void afr_radix_sort16_mt(rec16_t *a, rec16_t *tmp, size_t n, unsigned nt)
{
	nt = afr_par_threads(nt, n);
	if (nt <= 1) {
		afr_radix_sort16(a, tmp, n);
		return;
	}
	size_t (*cnt)[256] = malloc(nt * sizeof(*cnt));
	if (!cnt) {
		afr_radix_sort16(a, tmp, n);
		return;
	}
	radix_ctx_t x = {.src = a, .dst = tmp, .cnt = cnt, .nt = nt};
	for (unsigned d = 0; d < 8; d++) {
		x.d = d;
		afr_par_for(nt, n, 1, radix_count, &x);
		/* All keys share the same digit: this pass is not needed. */
		int single = 0;
		for (unsigned bkt = 0; bkt < 256 && !single; bkt++) {
			size_t tot = 0;
			for (unsigned t = 0; t < nt; t++)
				tot += cnt[t][bkt];
			if (tot == n)
				single = 1;
			else if (tot)
				break;
		}
		if (single)
			continue;
		size_t pos = 0;
		for (unsigned bkt = 0; bkt < 256; bkt++) {
			for (unsigned t = 0; t < nt; t++) {
				size_t c = cnt[t][bkt];
				cnt[t][bkt] = pos;
				pos += c;
			}
		}
		afr_par_for(nt, n, 1, radix_scatter, &x);
		rec16_t *sw = x.src;
		x.src = x.dst;
		x.dst = sw;
	}
	if (x.src != a)
		memcpy(a, x.src, n * sizeof(*a));
	free(cnt);
}

/* ---------- Normalization ---------- */

/*
 * Every phase below runs over contiguous chunks in parallel and reproduces the original
 * sequential algorithm exactly: phases that carry state from one packet to the next
 * (running maximum, accumulated gap excess, last mapped value, last good timestamp) are
 * split into a pass that summarizes each chunk, a short sequential merge of those
 * summaries in chunk order, and a pass that redoes the chunk starting from the state
 * the sequential algorithm would have had at its first packet. tests/ref_sched.c keeps
 * the original single-threaded code, and the unit tests compare both bit for bit.
 */

#define IS_SKIP(i) (shard && shard[i] == SHARD_SKIP)
#define BIT_GET(bm, i) ((bm)[(i) >> 3] & (1u << ((i) & 7)))
#define BIT_SET(bm, i) ((bm)[(i) >> 3] |= (uint8_t)(1u << ((i) & 7)))
/* Chunk boundaries are multiples of 64 packets, so chunks never share a bitmap byte. */
#define NORM_ALIGN 64

static void top_insert(ts_gap_t *top, int *ntop, int64_t at, int64_t len, uint64_t idx,
                       int idx_known)
{
	if (len <= 0)
		return;
	if (*ntop == TS_TOP_GAPS && top[TS_TOP_GAPS - 1].len >= len)
		return;
	int pos = *ntop < TS_TOP_GAPS ? (*ntop)++ : TS_TOP_GAPS - 1;
	while (pos > 0 && top[pos - 1].len < len) {
		top[pos] = top[pos - 1];
		pos--;
	}
	top[pos] = (ts_gap_t){.at = at, .len = len, .idx = idx, .idx_known = idx_known};
}

/* Merging per-chunk top lists in chunk order gives the same list as one sequential pass:
 * an equal-length gap from a later chunk never displaces an earlier one. */
static void top_merge(ts_result_t *res, const ts_gap_t *top, int ntop)
{
	for (int i = 0; i < ntop; i++)
		top_insert(res->top, &res->ntop, top[i].at, top[i].len, top[i].idx, top[i].idx_known);
}

static int64_t abs64(int64_t v)
{
	return v < 0 ? -v : v;
}

/* Gaps to compress: E(x) = total time cut out before moment x. */
typedef struct {
	int64_t *b;   /* upper end of the gap */
	int64_t *cum; /* accumulated cut time */
	size_t n;
} gap_list_t;

static int64_t gap_list_excess(const gap_list_t *g, int64_t x)
{
	/* last k with b[k] <= x */
	size_t lo = 0, hi = g->n;
	while (lo < hi) {
		size_t mid = (lo + hi) / 2;
		if (g->b[mid] <= x)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo == 0 ? 0 : g->cum[lo - 1];
}

typedef struct AFR_ALIGNED {
	/* outliers */
	uint64_t zero, past, future;
	/* exclusion: first good index and last good value */
	size_t first_good;
	int has_good;
	int64_t last_good, good_in;
	/* bounds */
	uint64_t n;
	int has;
	int64_t first, mn, mx, cmax;
	uint64_t backward;
	int64_t max_back;
	uint64_t max_back_idx;
	int rm_valid;
	int64_t rm_in;
	/* gaps */
	int64_t f, l;
	int64_t internal;
	uint64_t big;          /* gaps above max_gap inside the chunk (unordered path) */
	int prev_valid;
	int64_t prev_in, excess_in;
	uint64_t list_off;     /* where this chunk writes its gap list entries */
	uint64_t gaps_over;
	int64_t maxmapped;
	size_t first_ns;       /* first non-skipped index (unordered mapping) */
	int64_t last_mapped;
	ts_gap_t top[TS_TOP_GAPS];
	int ntop;
	/* building the sorted copy */
	size_t cnt, out_off;
} nchunk_t;

typedef struct {
	int64_t *ts;
	const uint16_t *shard;
	size_t n;
	const ts_cfg_t *cfg;
	uint8_t *bm;
	nchunk_t *ch;
	int64_t base;
	rec16_t *s;     /* sorted copy (unordered path) */
	size_t k;
	gap_list_t gl;
	int64_t eb;
} nctx_t;

static void p_abs_outliers(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	const int64_t *ts = x->ts;
	const uint16_t *shard = x->shard;
	const int64_t future = x->cfg->now_ns + TS_FUTURE_SLACK_NS;
	const int check_future = x->cfg->now_ns > 0;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i))
			continue;
		int64_t v = ts[i];
		if (v == 0)
			c->zero++;
		else if (v < TS_PAST_LIMIT_NS)
			c->past++;
		else if (check_future && v > future)
			c->future++;
		else
			continue;
		BIT_SET(x->bm, i);
	}
}

/* Short clock spikes: inherently sequential (each decision depends on the previous
 * "good" packet), but it is a single light pass. */
static void find_spikes(nctx_t *x, ts_result_t *res)
{
	const int64_t *ts = x->ts;
	const uint16_t *shard = x->shard;
	const size_t n = x->n;
	uint8_t *bm = x->bm;
	const int64_t jump = x->cfg->outlier_jump;
	size_t prev = SIZE_MAX;
	for (size_t i = 0; i < n; i++) {
		if (IS_SKIP(i) || BIT_GET(bm, i))
			continue;
		if (prev != SIZE_MAX && abs64(ts[i] - ts[prev]) > jump) {
			/* A jump. If time comes back within a few packets, it is an outlier. */
			size_t j = i + 1;
			int seen = 0, back = 0;
			for (; j < n && seen < TS_SPIKE_LOOKAHEAD; j++) {
				if (IS_SKIP(j) || BIT_GET(bm, j))
					continue;
				seen++;
				if (abs64(ts[j] - ts[prev]) <= jump) {
					back = 1;
					break;
				}
			}
			if (back) {
				for (size_t k = i; k < j; k++) {
					if (IS_SKIP(k) || BIT_GET(bm, k))
						continue;
					BIT_SET(bm, k);
					res->outl_spike++;
				}
				i = j - 1;
				continue;
			}
		}
		prev = i;
	}
}

static void p_good_scan(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	const uint16_t *shard = x->shard;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i) || BIT_GET(x->bm, i))
			continue;
		if (!c->has_good) {
			c->has_good = 1;
			c->first_good = i;
		}
		c->last_good = x->ts[i];
	}
}

static void p_exclude(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	int64_t last = x->ch[t].good_in;
	const uint16_t *shard = x->shard;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i))
			continue;
		if (BIT_GET(x->bm, i))
			x->ts[i] = last;
		else
			last = x->ts[i];
	}
}

static void p_chunk_max(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	const uint16_t *shard = x->shard;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i))
			continue;
		if (!c->has || x->ts[i] > c->cmax)
			c->cmax = x->ts[i];
		c->has = 1;
	}
}

static void p_bounds(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	int64_t *ts = x->ts;
	const uint16_t *shard = x->shard;
	const int clamp = x->cfg->order == TS_ORDER_CLAMP;
	int have = c->rm_valid;
	int64_t rm = c->rm_in;
	int seen = 0;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i))
			continue;
		int64_t v = ts[i];
		c->n++;
		if (!seen) {
			seen = 1;
			c->first = c->mn = c->mx = v;
		} else {
			if (v < c->mn)
				c->mn = v;
			if (v > c->mx)
				c->mx = v;
		}
		if (!have) {
			have = 1;
			rm = v;
			continue;
		}
		if (v < rm) {
			c->backward++;
			if (rm - v > c->max_back) {
				c->max_back = rm - v;
				c->max_back_idx = i;
			}
			if (clamp)
				ts[i] = rm;
		} else {
			rm = v;
		}
	}
}

/* Monotone path, pass A: first/last packet of the chunk and the excess inside it. */
static void p_mono_scan(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	const int64_t *ts = x->ts;
	const uint16_t *shard = x->shard;
	const int64_t mg = x->cfg->max_gap;
	int seen = 0;
	int64_t prev = 0;
	c->has = 0;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i))
			continue;
		int64_t v = ts[i];
		if (!seen) {
			seen = 1;
			c->f = v;
		} else if (mg > 0 && v - prev > mg) {
			c->internal += v - prev - mg;
		}
		prev = v;
		if (mg <= 0) {
			/* Without max-gap only the first and last values are needed. */
			size_t j = b;
			while (j > i + 1 && IS_SKIP(j - 1))
				j--;
			prev = ts[j - 1];
			break;
		}
	}
	c->has = seen;
	c->l = prev;
}

/* Monotone path, pass B: the original sequential loop, started from the merged state. */
static void p_mono_map(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	int64_t *ts = x->ts;
	const uint16_t *shard = x->shard;
	const int64_t mg = x->cfg->max_gap;
	const int64_t base = x->base;
	int first = !c->prev_valid;
	int64_t prev = c->prev_in, excess = c->excess_in;
	int64_t last_mapped = c->prev_valid ? c->prev_in - base - c->excess_in : 0;
	c->maxmapped = INT64_MIN;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i)) {
			ts[i] = last_mapped;
			continue;
		}
		int64_t v = ts[i];
		if (!first) {
			int64_t gap = v - prev;
			top_insert(c->top, &c->ntop, prev, gap, i, 1);
			if (mg > 0 && gap > mg) {
				excess += gap - mg;
				c->gaps_over++;
			}
		}
		first = 0;
		prev = v;
		last_mapped = ts[i] = v - base - excess;
		if (last_mapped > c->maxmapped)
			c->maxmapped = last_mapped;
	}
}

static void p_count_ns(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	const uint16_t *shard = x->shard;
	size_t k = 0;
	for (size_t i = a; i < b; i++)
		if (!IS_SKIP(i))
			k++;
	x->ch[t].cnt = k;
}

static void p_fill_sorted(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	const uint16_t *shard = x->shard;
	size_t k = x->ch[t].out_off;
	for (size_t i = a; i < b; i++)
		if (!IS_SKIP(i))
			x->s[k++] = (rec16_t){.key = x->ts[i], .val = 0};
}

/* Unordered path: gaps over the sorted copy. Chunk t handles gaps ending at j in [a, b). */
static void p_sorted_scan(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	const int64_t mg = x->cfg->max_gap;
	for (size_t j = a > 0 ? a : 1; j < b; j++) {
		int64_t gap = x->s[j].key - x->s[j - 1].key;
		if (mg > 0 && gap > mg) {
			c->internal += gap - mg;
			c->big++;
		}
	}
}

static void p_sorted_fill(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	const int64_t mg = x->cfg->max_gap;
	int64_t excess = c->excess_in;
	uint64_t o = c->list_off;
	for (size_t j = a > 0 ? a : 1; j < b; j++) {
		int64_t gap = x->s[j].key - x->s[j - 1].key;
		top_insert(c->top, &c->ntop, x->s[j - 1].key, gap, 0, 0);
		if (mg > 0 && gap > mg) {
			excess += gap - mg;
			c->gaps_over++;
			x->gl.b[o] = x->s[j].key;
			x->gl.cum[o] = excess;
			o++;
		}
	}
}

static void p_sorted_map(void *arg, unsigned t, size_t a, size_t b)
{
	nctx_t *x = arg;
	nchunk_t *c = &x->ch[t];
	int64_t *ts = x->ts;
	const uint16_t *shard = x->shard;
	const int64_t base = x->base;
	int seen = 0;
	int64_t last_mapped = 0;
	c->maxmapped = INT64_MIN;
	c->first_ns = b;
	for (size_t i = a; i < b; i++) {
		if (IS_SKIP(i)) {
			if (seen)
				ts[i] = last_mapped;
			continue; /* leading skipped packets are filled in after the merge */
		}
		if (!seen) {
			seen = 1;
			c->first_ns = i;
		}
		int64_t v = ts[i];
		last_mapped = ts[i] = v - base - (gap_list_excess(&x->gl, v) - x->eb);
		if (last_mapped > c->maxmapped)
			c->maxmapped = last_mapped;
	}
	c->has = seen;
	c->last_mapped = last_mapped;
}

int afr_ts_normalize(int64_t *ts, const uint16_t *shard, size_t n, const ts_cfg_t *cfg,
                     ts_result_t *res)
{
	memset(res, 0, sizeof(*res));
	const unsigned nt = afr_par_threads(cfg->threads, n);
	nctx_t x = {.ts = ts, .shard = shard, .n = n, .cfg = cfg};
	x.ch = aligned_alloc(AFR_CACHELINE, nt * sizeof(nchunk_t));
	x.bm = calloc(n / 8 + 1, 1);
	if (!x.ch || !x.bm) {
		free(x.ch);
		free(x.bm);
		return -1;
	}
	memset(x.ch, 0, nt * sizeof(nchunk_t));

	/* 1. Outliers. */
	afr_par_for(nt, n, NORM_ALIGN, p_abs_outliers, &x);
	for (unsigned t = 0; t < nt; t++) {
		res->outl_zero += x.ch[t].zero;
		res->outl_past += x.ch[t].past;
		res->outl_future += x.ch[t].future;
	}
	if (cfg->outlier_jump > 0)
		find_spikes(&x, res);
	res->outliers = res->outl_zero + res->outl_past + res->outl_future + res->outl_spike;
	if (res->outliers && cfg->exclude_outliers) {
		afr_par_for(nt, n, NORM_ALIGN, p_good_scan, &x);
		size_t fg = SIZE_MAX;
		int64_t last = 0;
		for (unsigned t = 0; t < nt; t++) {
			if (x.ch[t].has_good && fg == SIZE_MAX) {
				fg = x.ch[t].first_good;
				last = ts[fg];
			}
		}
		if (fg != SIZE_MAX) {
			/* Outliers before the first good packet take its timestamp. */
			for (unsigned t = 0; t < nt; t++) {
				x.ch[t].good_in = last;
				if (x.ch[t].has_good)
					last = x.ch[t].last_good;
			}
			afr_par_for(nt, n, NORM_ALIGN, p_exclude, &x);
			res->excluded = 1;
		}
	}
	free(x.bm);
	x.bm = NULL;

	/* 2. Bounds, non-monotonicity, clamp. */
	afr_par_for(nt, n, NORM_ALIGN, p_chunk_max, &x);
	{
		int have = 0;
		int64_t rm = 0;
		for (unsigned t = 0; t < nt; t++) {
			x.ch[t].rm_valid = have;
			x.ch[t].rm_in = rm;
			if (x.ch[t].has && (!have || x.ch[t].cmax > rm)) {
				rm = x.ch[t].cmax;
				have = 1;
			}
		}
	}
	afr_par_for(nt, n, NORM_ALIGN, p_bounds, &x);
	int have = 0;
	for (unsigned t = 0; t < nt; t++) {
		nchunk_t *c = &x.ch[t];
		res->n += c->n;
		if (!c->n)
			continue;
		if (!have) {
			have = 1;
			res->first_abs = c->first;
			res->min_abs = c->mn;
			res->max_abs = c->mx;
		} else {
			if (c->mn < res->min_abs)
				res->min_abs = c->mn;
			if (c->mx > res->max_abs)
				res->max_abs = c->mx;
		}
		res->backward += c->backward;
		if (c->max_back > res->max_backward) {
			res->max_backward = c->max_back;
			res->max_backward_idx = c->max_back_idx;
		}
	}
	if (!have) {
		free(x.ch);
		res->monotone = 1;
		res->lap_len = 1000;
		return 0;
	}
	res->monotone = (cfg->order == TS_ORDER_CLAMP) || res->backward == 0;
	res->base_abs = (cfg->order == TS_ORDER_SORT) ? res->min_abs : res->first_abs;
	x.base = res->base_abs;

	/* 3. Gaps and mapping onto the timeline. */
	int64_t maxmapped = INT64_MIN;
	for (unsigned t = 0; t < nt; t++) {
		x.ch[t].ntop = 0;
		x.ch[t].internal = 0;
	}
	if (res->monotone) {
		afr_par_for(nt, n, NORM_ALIGN, p_mono_scan, &x);
		int hp = 0;
		int64_t prev = 0, excess = 0;
		for (unsigned t = 0; t < nt; t++) {
			nchunk_t *c = &x.ch[t];
			c->prev_valid = hp;
			c->prev_in = prev;
			c->excess_in = excess;
			if (!c->has)
				continue;
			if (hp && cfg->max_gap > 0 && c->f - prev > cfg->max_gap)
				excess += c->f - prev - cfg->max_gap;
			excess += c->internal;
			prev = c->l;
			hp = 1;
		}
		afr_par_for(nt, n, NORM_ALIGN, p_mono_map, &x);
		for (unsigned t = 0; t < nt; t++) {
			nchunk_t *c = &x.ch[t];
			top_merge(res, c->top, c->ntop);
			res->gaps_over += c->gaps_over;
			if (c->maxmapped > maxmapped)
				maxmapped = c->maxmapped;
		}
		res->gap_removed = excess;
	} else {
		/* Sorted copy of the timestamps (only for finding gaps). */
		afr_par_for(nt, n, NORM_ALIGN, p_count_ns, &x);
		size_t k = 0;
		for (unsigned t = 0; t < nt; t++) {
			x.ch[t].out_off = k;
			k += x.ch[t].cnt;
		}
		x.k = k;
		x.s = malloc(k * sizeof(rec16_t));
		rec16_t *tmp = malloc(k * sizeof(rec16_t));
		if (!x.s || !tmp) {
			free(x.s);
			free(tmp);
			free(x.ch);
			return -1;
		}
		afr_par_for(nt, n, NORM_ALIGN, p_fill_sorted, &x);
		afr_radix_sort16_mt(x.s, tmp, k, nt);
		free(tmp);

		const unsigned ns = afr_par_threads(nt, k);
		for (unsigned t = 0; t < nt; t++) {
			x.ch[t].big = 0;
			x.ch[t].gaps_over = 0;
		}
		afr_par_for(ns, k, 1, p_sorted_scan, &x);
		int64_t excess = 0;
		uint64_t total = 0;
		for (unsigned t = 0; t < ns; t++) {
			x.ch[t].excess_in = excess;
			x.ch[t].list_off = total;
			excess += x.ch[t].internal;
			total += x.ch[t].big;
		}
		x.gl.n = total;
		x.gl.b = malloc((total ? total : 1) * sizeof(int64_t));
		x.gl.cum = malloc((total ? total : 1) * sizeof(int64_t));
		if (!x.gl.b || !x.gl.cum) {
			free(x.gl.b);
			free(x.gl.cum);
			free(x.s);
			free(x.ch);
			return -1;
		}
		afr_par_for(ns, k, 1, p_sorted_fill, &x);
		for (unsigned t = 0; t < ns; t++) {
			top_merge(res, x.ch[t].top, x.ch[t].ntop);
			res->gaps_over += x.ch[t].gaps_over;
		}
		free(x.s);
		x.s = NULL;
		res->gap_removed = excess;
		x.eb = gap_list_excess(&x.gl, x.base);

		afr_par_for(nt, n, NORM_ALIGN, p_sorted_map, &x);
		/* Leading skipped packets of a chunk take the last mapped value before them. */
		int64_t last_mapped = 0;
		for (unsigned t = 0; t < nt; t++) {
			nchunk_t *c = &x.ch[t];
			size_t a, b;
			afr_par_range(nt, n, NORM_ALIGN, t, &a, &b);
			for (size_t i = a; i < c->first_ns && i < b; i++)
				ts[i] = last_mapped;
			if (c->has) {
				last_mapped = c->last_mapped;
				if (c->maxmapped > maxmapped)
					maxmapped = c->maxmapped;
			}
		}
		free(x.gl.b);
		free(x.gl.cum);
	}
	free(x.ch);
	res->duration = maxmapped > 0 ? maxmapped : 0;
	/* A lap is longer than the file by the mean interval, so that the last packet of a lap and
	 * the first packet of the next one do not coincide in time. */
	res->lap_len = res->duration + (res->n > 1 ? res->duration / (int64_t)(res->n - 1) : 0);
	if (res->lap_len <= 0)
		res->lap_len = 1000;
	return 0;
}

/* ---------- Rate profile ---------- */

const int64_t afr_rate_windows_ns[RATE_WINDOWS] = {NS_PER_MS, 10 * NS_PER_MS, NS_PER_SEC};
const char *const afr_rate_window_names[RATE_WINDOWS] = {"1 ms", "10 ms", "1 s"};

typedef struct {
	const int64_t *t;
	const uint64_t *ol;
	const uint16_t *sh;
	const rec16_t *s; /* sorted view, or NULL */
	size_t n;
} view_t;

static inline int v_get(const view_t *v, size_t i, int64_t *t, uint32_t *len, unsigned *sh)
{
	if (v->s) {
		*t = v->s[i].key;
		*len = (uint32_t)(v->s[i].val & 0xFFFFFFFFu);
		*sh = (unsigned)(v->s[i].val >> 32);
		return 1;
	}
	if (v->sh && v->sh[i] == SHARD_SKIP)
		return 0;
	*t = v->t[i];
	*len = OFFLEN_LEN(v->ol[i]);
	*sh = v->sh ? v->sh[i] : 0;
	return 1;
}

/* Time of view entry i regardless of whether it is skipped (the view is non-decreasing). */
static inline int64_t v_time(const view_t *v, size_t i)
{
	return v->s ? v->s[i].key : v->t[i];
}

typedef struct AFR_ALIGNED {
	uint64_t pkts, bytes;
	uint64_t sum, sum1;        /* pass A: bytes and wire bytes of the chunk */
	uint64_t pre, pre1;        /* prefix of all previous chunks */
	int64_t tmin, tmax;
	int has;
	uint64_t best[RATE_WINDOWS], best1[RATE_WINDOWS];
	uint64_t gaps_total, gaps_below_res, gaps_lt[3];
	int64_t *first, *last;     /* per shard, INT64_MIN if not seen */
	size_t cnt, out_off;
} rchunk_t;

typedef struct {
	view_t v;
	const rate_cfg_t *cfg;
	rchunk_t *ch;
	unsigned nt;
	unsigned nsh;
	int64_t win[RATE_WINDOWS];
	double mult;
	/* building the sorted view */
	const int64_t *sched;
	const uint64_t *offlen;
	const uint16_t *shard;
	rec16_t *sorted;
} rctx_t;

static const int64_t gap_lt_ns[3] = {1000, 10000, 100000};

static inline void count_gap(rchunk_t *c, double gw, int64_t res_ns)
{
	c->gaps_total++;
	if (gw < (double)res_ns)
		c->gaps_below_res++;
	for (int q = 0; q < 3; q++)
		if (gw < (double)gap_lt_ns[q])
			c->gaps_lt[q]++;
}

static void r_sum(void *arg, unsigned t, size_t a, size_t b)
{
	rctx_t *x = arg;
	rchunk_t *c = &x->ch[t];
	for (size_t i = a; i < b; i++) {
		int64_t tt;
		uint32_t len;
		unsigned sh;
		if (!v_get(&x->v, i, &tt, &len, &sh))
			continue;
		len += x->cfg->l2_extra;
		c->sum += len;
		c->sum1 += afr_l1_bytes(len);
	}
}

/* Sum of bytes (and wire bytes) of valid entries in [0, pos). */
static void prefix_at(const rctx_t *x, size_t pos, uint64_t *s, uint64_t *s1)
{
	unsigned t = 0;
	size_t a = 0, b = 0;
	for (; t < x->nt; t++) {
		afr_par_range(x->nt, x->v.n, 1, t, &a, &b);
		if (pos < b || t == x->nt - 1)
			break;
	}
	*s = x->ch[t].pre;
	*s1 = x->ch[t].pre1;
	for (size_t i = a; i < pos; i++) {
		int64_t tt;
		uint32_t len;
		unsigned sh;
		if (!v_get(&x->v, i, &tt, &len, &sh))
			continue;
		len += x->cfg->l2_extra;
		*s += len;
		*s1 += afr_l1_bytes(len);
	}
}

static void r_main(void *arg, unsigned t, size_t a, size_t b)
{
	rctx_t *x = arg;
	rchunk_t *c = &x->ch[t];
	const view_t *v = &x->v;
	const uint32_t extra = x->cfg->l2_extra;
	size_t r0 = a;
	int64_t t0;
	uint32_t l0;
	unsigned s0;
	while (r0 < b && !v_get(v, r0, &t0, &l0, &s0))
		r0++;
	if (r0 >= b)
		return;
	/* Window state at r0, as the sequential pass would have it before adding r0. */
	size_t left[RATE_WINDOWS];
	uint64_t sum[RATE_WINDOWS], sum1[RATE_WINDOWS];
	uint64_t pr, pr1;
	prefix_at(x, r0, &pr, &pr1);
	for (int w = 0; w < RATE_WINDOWS; w++) {
		/* First entry with t > t(r0) - win: entries before it have left the window. */
		size_t lo = 0, hi = r0;
		while (lo < hi) {
			size_t mid = lo + (hi - lo) / 2;
			if (t0 - v_time(v, mid) >= x->win[w])
				lo = mid + 1;
			else
				hi = mid;
		}
		left[w] = lo;
		uint64_t pl, pl1;
		prefix_at(x, lo, &pl, &pl1);
		sum[w] = pr - pl;
		sum1[w] = pr1 - pl1;
	}
	for (unsigned s = 0; s < x->nsh; s++)
		c->first[s] = c->last[s] = INT64_MIN;
	for (size_t r = r0; r < b; r++) {
		int64_t tt;
		uint32_t len;
		unsigned sh;
		if (!v_get(v, r, &tt, &len, &sh))
			continue;
		len += extra;
		if (!c->has) {
			c->has = 1;
			c->tmin = tt;
		}
		c->tmax = tt;
		c->pkts++;
		c->bytes += len;
		if (sh < x->nsh) {
			if (c->last[sh] != INT64_MIN)
				count_gap(c, (double)(tt - c->last[sh]) / x->mult, x->cfg->timing_res);
			else
				c->first[sh] = tt;
			c->last[sh] = tt;
		}
		for (int w = 0; w < RATE_WINDOWS; w++) {
			sum[w] += len;
			sum1[w] += afr_l1_bytes(len);
			for (;;) {
				int64_t tl;
				uint32_t ll;
				unsigned sl;
				if (!v_get(v, left[w], &tl, &ll, &sl)) {
					left[w]++;
					continue;
				}
				if (tt - tl >= x->win[w]) {
					ll += extra;
					sum[w] -= ll;
					sum1[w] -= afr_l1_bytes(ll);
					left[w]++;
				} else {
					break;
				}
			}
			if (sum[w] > c->best[w])
				c->best[w] = sum[w];
			if (sum1[w] > c->best1[w])
				c->best1[w] = sum1[w];
		}
	}
}

static void r_count(void *arg, unsigned t, size_t a, size_t b)
{
	rctx_t *x = arg;
	size_t k = 0;
	for (size_t i = a; i < b; i++)
		if (!x->shard || x->shard[i] != SHARD_SKIP)
			k++;
	x->ch[t].cnt = k;
}

static void r_fill(void *arg, unsigned t, size_t a, size_t b)
{
	rctx_t *x = arg;
	size_t k = x->ch[t].out_off;
	for (size_t i = a; i < b; i++) {
		if (x->shard && x->shard[i] == SHARD_SKIP)
			continue;
		uint64_t sh = x->shard ? x->shard[i] : 0;
		x->sorted[k++] =
		    (rec16_t){.key = x->sched[i], .val = OFFLEN_LEN(x->offlen[i]) | (sh << 32)};
	}
}

int afr_rate_profile(const int64_t *sched, const uint64_t *offlen, const uint16_t *shard, size_t n,
                     int monotone, const rate_cfg_t *cfg, rate_result_t *res)
{
	memset(res, 0, sizeof(*res));
	unsigned nt = afr_par_threads(cfg->threads, n);
	rctx_t x = {.cfg = cfg, .sched = sched, .offlen = offlen, .shard = shard};
	x.v = (view_t){.t = sched, .ol = offlen, .sh = shard, .s = NULL, .n = n};
	x.nsh = cfg->nshards ? cfg->nshards : 1;
	x.mult = cfg->mult > 0 ? cfg->mult : 1.0;
	for (int w = 0; w < RATE_WINDOWS; w++) {
		double s = (double)afr_rate_windows_ns[w] * x.mult;
		x.win[w] = s < 1 ? 1 : (s > 9e18 ? INT64_MAX : (int64_t)s);
	}
	x.ch = aligned_alloc(AFR_CACHELINE, nt * sizeof(rchunk_t));
	if (!x.ch)
		return -1;
	memset(x.ch, 0, nt * sizeof(rchunk_t));
	x.nt = nt;

	if (!monotone) {
		afr_par_for(nt, n, 1, r_count, &x);
		size_t k = 0;
		for (unsigned t = 0; t < nt; t++) {
			x.ch[t].out_off = k;
			k += x.ch[t].cnt;
		}
		x.sorted = malloc((k ? k : 1) * sizeof(rec16_t));
		rec16_t *tmp = malloc((k ? k : 1) * sizeof(rec16_t));
		if (!x.sorted || !tmp) {
			free(x.sorted);
			free(tmp);
			free(x.ch);
			return -1;
		}
		afr_par_for(nt, n, 1, r_fill, &x);
		afr_radix_sort16_mt(x.sorted, tmp, k, nt);
		free(tmp);
		x.v.s = x.sorted;
		x.v.n = k;
		nt = afr_par_threads(cfg->threads, k);
		x.nt = nt;
		memset(x.ch, 0, sizeof(rchunk_t) * nt);
	}

	int64_t *shard_mem = malloc((size_t)nt * x.nsh * 2 * sizeof(int64_t));
	if (!shard_mem) {
		free(x.sorted);
		free(x.ch);
		return -1;
	}
	for (unsigned t = 0; t < nt; t++) {
		x.ch[t].first = shard_mem + (size_t)t * x.nsh * 2;
		x.ch[t].last = x.ch[t].first + x.nsh;
	}
	afr_par_for(nt, x.v.n, 1, r_sum, &x);
	uint64_t pre = 0, pre1 = 0;
	for (unsigned t = 0; t < nt; t++) {
		x.ch[t].pre = pre;
		x.ch[t].pre1 = pre1;
		pre += x.ch[t].sum;
		pre1 += x.ch[t].sum1;
	}
	afr_par_for(nt, x.v.n, 1, r_main, &x);

	/* Merge in chunk order; gaps between chunks are counted per shard here. */
	int64_t *glast = malloc(x.nsh * sizeof(int64_t));
	if (!glast) {
		free(shard_mem);
		free(x.sorted);
		free(x.ch);
		return -1;
	}
	for (unsigned s = 0; s < x.nsh; s++)
		glast[s] = INT64_MIN;
	uint64_t best[RATE_WINDOWS] = {0}, best1[RATE_WINDOWS] = {0};
	int64_t tmin = INT64_MAX, tmax = INT64_MIN;
	rchunk_t acc;
	memset(&acc, 0, sizeof(acc));
	for (unsigned t = 0; t < nt; t++) {
		rchunk_t *c = &x.ch[t];
		if (!c->has)
			continue;
		res->pkts += c->pkts;
		res->bytes += c->bytes;
		if (c->tmin < tmin)
			tmin = c->tmin;
		if (c->tmax > tmax)
			tmax = c->tmax;
		for (int w = 0; w < RATE_WINDOWS; w++) {
			if (c->best[w] > best[w])
				best[w] = c->best[w];
			if (c->best1[w] > best1[w])
				best1[w] = c->best1[w];
		}
		acc.gaps_total += c->gaps_total;
		acc.gaps_below_res += c->gaps_below_res;
		for (int q = 0; q < 3; q++)
			acc.gaps_lt[q] += c->gaps_lt[q];
		for (unsigned s = 0; s < x.nsh; s++) {
			if (c->first[s] == INT64_MIN)
				continue;
			if (glast[s] != INT64_MIN)
				count_gap(&acc, (double)(c->first[s] - glast[s]) / x.mult, cfg->timing_res);
			glast[s] = c->last[s];
		}
	}
	res->gaps_total = acc.gaps_total;
	res->gaps_below_res = acc.gaps_below_res;
	for (int q = 0; q < 3; q++)
		res->gaps_lt[q] = acc.gaps_lt[q];
	for (int w = 0; w < RATE_WINDOWS; w++) {
		double ws = (double)afr_rate_windows_ns[w] / 1e9;
		res->peak_bps[w] = (double)best[w] * 8.0 / ws;
		res->peak_l1_bps[w] = (double)best1[w] * 8.0 / ws;
	}
	if (res->pkts > 0 && tmax > tmin) {
		res->wall_duration_s = (double)(tmax - tmin) / x.mult / 1e9;
		res->avg_bps = (double)res->bytes * 8.0 / res->wall_duration_s;
	}
	free(glast);
	free(shard_mem);
	free(x.sorted);
	free(x.ch);
	return 0;
}

/* ---------- Histogram ---------- */

uint64_t afr_lh_upper(unsigned b)
{
	if (b < LH_SUB)
		return b;
	unsigned g = b / LH_SUB, m = b % LH_SUB;
	unsigned shift = g - 1;
	uint64_t lower = (uint64_t)(LH_SUB + m) << shift;
	return lower + ((1ULL << shift) - 1);
}

uint64_t afr_lh_quantile(const uint64_t *hist, double q)
{
	uint64_t total = 0;
	for (unsigned b = 0; b < LH_BUCKETS; b++)
		total += hist[b];
	if (total == 0)
		return 0;
	/* Rank definition: the smallest value such that at least q*N elements are <= it. */
	uint64_t want = (uint64_t)ceil(q * (double)total);
	if (want > 0)
		want--;
	if (want >= total)
		want = total - 1;
	uint64_t acc = 0;
	for (unsigned b = 0; b < LH_BUCKETS; b++) {
		acc += hist[b];
		if (acc > want)
			return afr_lh_upper(b);
	}
	return afr_lh_upper(LH_BUCKETS - 1);
}
