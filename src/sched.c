#include "sched.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ---------- Поразрядная сортировка ---------- */

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
		/* Все ключи с одинаковой цифрой — проход не нужен. */
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

/* ---------- Нормализация ---------- */

#define IS_SKIP(i) (shard && shard[i] == SHARD_SKIP)
#define BIT_GET(bm, i) ((bm)[(i) >> 3] & (1u << ((i) & 7)))
#define BIT_SET(bm, i) ((bm)[(i) >> 3] |= (uint8_t)(1u << ((i) & 7)))

static void top_gap_insert(ts_result_t *res, int64_t at, int64_t len, uint64_t idx, int idx_known)
{
	if (len <= 0)
		return;
	if (res->ntop == TS_TOP_GAPS && res->top[TS_TOP_GAPS - 1].len >= len)
		return;
	int pos = res->ntop < TS_TOP_GAPS ? res->ntop++ : TS_TOP_GAPS - 1;
	while (pos > 0 && res->top[pos - 1].len < len) {
		res->top[pos] = res->top[pos - 1];
		pos--;
	}
	res->top[pos] = (ts_gap_t){.at = at, .len = len, .idx = idx, .idx_known = idx_known};
}

static int64_t abs64(int64_t v)
{
	return v < 0 ? -v : v;
}

/* Поиск выбросов. Возвращает битовую карту (или NULL, если выбросов нет / нет памяти). */
static uint8_t *find_outliers(const int64_t *ts, const uint16_t *shard, size_t n,
                              const ts_cfg_t *cfg, ts_result_t *res, int *oom)
{
	uint8_t *bm = NULL;
	*oom = 0;
	const int64_t future = cfg->now_ns + TS_FUTURE_SLACK_NS;
	for (size_t i = 0; i < n; i++) {
		if (IS_SKIP(i))
			continue;
		int64_t t = ts[i];
		int cls = 0;
		if (t == 0) {
			res->outl_zero++;
			cls = 1;
		} else if (t < TS_PAST_LIMIT_NS) {
			res->outl_past++;
			cls = 1;
		} else if (cfg->now_ns > 0 && t > future) {
			res->outl_future++;
			cls = 1;
		}
		if (cls) {
			if (!bm && !(bm = calloc(n / 8 + 1, 1))) {
				*oom = 1;
				return NULL;
			}
			BIT_SET(bm, i);
		}
	}
	if (cfg->outlier_jump > 0) {
		size_t prev = SIZE_MAX;
		for (size_t i = 0; i < n; i++) {
			if (IS_SKIP(i) || (bm && BIT_GET(bm, i)))
				continue;
			if (prev != SIZE_MAX && abs64(ts[i] - ts[prev]) > cfg->outlier_jump) {
				/* Скачок. Если через несколько пакетов время вернулось — это выброс. */
				size_t j = i + 1;
				int seen = 0, back = 0;
				for (; j < n && seen < TS_SPIKE_LOOKAHEAD; j++) {
					if (IS_SKIP(j) || (bm && BIT_GET(bm, j)))
						continue;
					seen++;
					if (abs64(ts[j] - ts[prev]) <= cfg->outlier_jump) {
						back = 1;
						break;
					}
				}
				if (back) {
					if (!bm && !(bm = calloc(n / 8 + 1, 1))) {
						*oom = 1;
						return NULL;
					}
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
	res->outliers = res->outl_zero + res->outl_past + res->outl_future + res->outl_spike;
	return bm;
}

/* Список сжимаемых пауз: E(x) = суммарно вырезанное время до момента x. */
typedef struct {
	int64_t *b;   /* верхняя граница паузы */
	int64_t *cum; /* накопленное вырезанное время */
	size_t n, cap;
} gap_list_t;

static int gap_list_push(gap_list_t *g, int64_t b, int64_t cum)
{
	if (g->n == g->cap) {
		size_t nc = g->cap ? g->cap * 2 : 64;
		int64_t *nb = realloc(g->b, nc * sizeof(int64_t));
		if (!nb)
			return -1;
		g->b = nb;
		int64_t *ncum = realloc(g->cum, nc * sizeof(int64_t));
		if (!ncum)
			return -1;
		g->cum = ncum;
		g->cap = nc;
	}
	g->b[g->n] = b;
	g->cum[g->n] = cum;
	g->n++;
	return 0;
}

static int64_t gap_list_excess(const gap_list_t *g, int64_t x)
{
	/* последний k с b[k] <= x */
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

int afr_ts_normalize(int64_t *ts, const uint16_t *shard, size_t n, const ts_cfg_t *cfg,
                     ts_result_t *res)
{
	memset(res, 0, sizeof(*res));

	/* 1. Выбросы. */
	int oom;
	uint8_t *outl = find_outliers(ts, shard, n, cfg, res, &oom);
	if (oom)
		return -1;
	if (outl && cfg->exclude_outliers) {
		size_t fg = 0;
		while (fg < n && (IS_SKIP(fg) || BIT_GET(outl, fg)))
			fg++;
		if (fg < n) {
			int64_t last = ts[fg];
			for (size_t i = 0; i < n; i++) {
				if (IS_SKIP(i))
					continue;
				if (BIT_GET(outl, i))
					ts[i] = last;
				else
					last = ts[i];
			}
			res->excluded = 1;
		}
	}
	free(outl);

	/* 2. Границы, немонотонность, clamp. */
	int have = 0;
	int64_t rm = 0;
	for (size_t i = 0; i < n; i++) {
		if (IS_SKIP(i))
			continue;
		int64_t t = ts[i];
		res->n++;
		if (!have) {
			have = 1;
			rm = res->first_abs = res->min_abs = res->max_abs = t;
			continue;
		}
		if (t < res->min_abs)
			res->min_abs = t;
		if (t > res->max_abs)
			res->max_abs = t;
		if (t < rm) {
			res->backward++;
			if (rm - t > res->max_backward) {
				res->max_backward = rm - t;
				res->max_backward_idx = i;
			}
			if (cfg->order == TS_ORDER_CLAMP)
				ts[i] = rm;
		} else {
			rm = t;
		}
	}
	if (!have) {
		res->monotone = 1;
		res->lap_len = 1000;
		return 0;
	}
	res->monotone = (cfg->order == TS_ORDER_CLAMP) || res->backward == 0;
	res->base_abs = (cfg->order == TS_ORDER_SORT) ? res->min_abs : res->first_abs;
	const int64_t base = res->base_abs;

	/* 3. Паузы и отображение на шкалу. */
	int64_t maxmapped = INT64_MIN;
	if (res->monotone) {
		int64_t prev = 0, excess = 0, last_mapped = 0;
		int first = 1;
		for (size_t i = 0; i < n; i++) {
			if (IS_SKIP(i)) {
				ts[i] = last_mapped;
				continue;
			}
			int64_t t = ts[i];
			if (!first) {
				int64_t gap = t - prev;
				top_gap_insert(res, prev, gap, i, 1);
				if (cfg->max_gap > 0 && gap > cfg->max_gap) {
					excess += gap - cfg->max_gap;
					res->gaps_over++;
				}
			}
			first = 0;
			prev = t;
			last_mapped = ts[i] = t - base - excess;
			if (last_mapped > maxmapped)
				maxmapped = last_mapped;
		}
		res->gap_removed = excess;
	} else {
		rec16_t *s = malloc(res->n * sizeof(*s));
		rec16_t *tmp = malloc(res->n * sizeof(*tmp));
		if (!s || !tmp) {
			free(s);
			free(tmp);
			return -1;
		}
		size_t k = 0;
		for (size_t i = 0; i < n; i++)
			if (!IS_SKIP(i))
				s[k++] = (rec16_t){.key = ts[i], .val = 0};
		afr_radix_sort16(s, tmp, k);
		free(tmp);
		gap_list_t gl = {0};
		int64_t excess = 0;
		for (size_t j = 1; j < k; j++) {
			int64_t gap = s[j].key - s[j - 1].key;
			top_gap_insert(res, s[j - 1].key, gap, 0, 0);
			if (cfg->max_gap > 0 && gap > cfg->max_gap) {
				excess += gap - cfg->max_gap;
				res->gaps_over++;
				if (gap_list_push(&gl, s[j].key, excess) < 0) {
					free(gl.b);
					free(gl.cum);
					free(s);
					return -1;
				}
			}
		}
		free(s);
		res->gap_removed = excess;
		const int64_t eb = gap_list_excess(&gl, base);
		int64_t last_mapped = 0;
		for (size_t i = 0; i < n; i++) {
			if (IS_SKIP(i)) {
				ts[i] = last_mapped;
				continue;
			}
			int64_t t = ts[i];
			last_mapped = ts[i] = t - base - (gap_list_excess(&gl, t) - eb);
			if (last_mapped > maxmapped)
				maxmapped = last_mapped;
		}
		free(gl.b);
		free(gl.cum);
	}
	res->duration = maxmapped > 0 ? maxmapped : 0;
	/* Круг длиннее файла на средний интервал, чтобы последний пакет круга и
	 * первый пакет следующего не совпали по времени. */
	res->lap_len = res->duration + (res->n > 1 ? res->duration / (int64_t)(res->n - 1) : 0);
	if (res->lap_len <= 0)
		res->lap_len = 1000;
	return 0;
}

/* ---------- Профиль скорости ---------- */

const int64_t afr_rate_windows_ns[RATE_WINDOWS] = {NS_PER_MS, 10 * NS_PER_MS, NS_PER_SEC};
const char *const afr_rate_window_names[RATE_WINDOWS] = {"1 мс", "10 мс", "1 с"};

typedef struct {
	const int64_t *t;
	const uint64_t *ol;
	const uint16_t *sh;
	const rec16_t *s; /* отсортированное представление или NULL */
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

int afr_rate_profile(const int64_t *sched, const uint64_t *offlen, const uint16_t *shard, size_t n,
                     int monotone, const rate_cfg_t *cfg, rate_result_t *res)
{
	memset(res, 0, sizeof(*res));
	view_t v = {.t = sched, .ol = offlen, .sh = shard, .s = NULL, .n = n};
	rec16_t *sorted = NULL;
	if (!monotone) {
		size_t cnt = 0;
		for (size_t i = 0; i < n; i++)
			if (!shard || shard[i] != SHARD_SKIP)
				cnt++;
		sorted = malloc((cnt ? cnt : 1) * sizeof(*sorted));
		rec16_t *tmp = malloc((cnt ? cnt : 1) * sizeof(*tmp));
		if (!sorted || !tmp) {
			free(sorted);
			free(tmp);
			return -1;
		}
		size_t k = 0;
		for (size_t i = 0; i < n; i++) {
			if (shard && shard[i] == SHARD_SKIP)
				continue;
			uint64_t sh = shard ? shard[i] : 0;
			sorted[k++] = (rec16_t){.key = sched[i], .val = OFFLEN_LEN(offlen[i]) | (sh << 32)};
		}
		afr_radix_sort16(sorted, tmp, k);
		free(tmp);
		v.s = sorted;
		v.n = k;
	}

	unsigned nsh = cfg->nshards ? cfg->nshards : 1;
	int64_t *last = malloc(nsh * sizeof(int64_t));
	if (!last) {
		free(sorted);
		return -1;
	}
	for (unsigned i = 0; i < nsh; i++)
		last[i] = INT64_MIN;

	const double mult = cfg->mult > 0 ? cfg->mult : 1.0;
	int64_t win[RATE_WINDOWS];
	size_t left[RATE_WINDOWS] = {0};
	uint64_t sum[RATE_WINDOWS] = {0}, sum1[RATE_WINDOWS] = {0};
	uint64_t best[RATE_WINDOWS] = {0}, best1[RATE_WINDOWS] = {0};
	for (int w = 0; w < RATE_WINDOWS; w++) {
		double s = (double)afr_rate_windows_ns[w] * mult;
		win[w] = s < 1 ? 1 : (s > 9e18 ? INT64_MAX : (int64_t)s);
	}
	const int64_t lt[3] = {1000, 10000, 100000};
	int64_t tmin = INT64_MAX, tmax = INT64_MIN;

	for (size_t r = 0; r < v.n; r++) {
		int64_t t;
		uint32_t len;
		unsigned sh;
		if (!v_get(&v, r, &t, &len, &sh))
			continue;
		len += cfg->l2_extra;
		res->pkts++;
		res->bytes += len;
		if (t < tmin)
			tmin = t;
		if (t > tmax)
			tmax = t;
		if (sh < nsh) {
			if (last[sh] != INT64_MIN) {
				double gw = (double)(t - last[sh]) / mult;
				res->gaps_total++;
				if (gw < (double)cfg->timing_res)
					res->gaps_below_res++;
				for (int q = 0; q < 3; q++)
					if (gw < (double)lt[q])
						res->gaps_lt[q]++;
			}
			last[sh] = t;
		}
		for (int w = 0; w < RATE_WINDOWS; w++) {
			sum[w] += len;
			sum1[w] += afr_l1_bytes(len);
			for (;;) {
				int64_t tl;
				uint32_t ll;
				unsigned sl;
				if (!v_get(&v, left[w], &tl, &ll, &sl)) {
					left[w]++;
					continue;
				}
				if (t - tl >= win[w]) {
					ll += cfg->l2_extra;
					sum[w] -= ll;
					sum1[w] -= afr_l1_bytes(ll);
					left[w]++;
				} else {
					break;
				}
			}
			if (sum[w] > best[w])
				best[w] = sum[w];
			if (sum1[w] > best1[w])
				best1[w] = sum1[w];
		}
	}
	for (int w = 0; w < RATE_WINDOWS; w++) {
		double ws = (double)afr_rate_windows_ns[w] / 1e9;
		res->peak_bps[w] = (double)best[w] * 8.0 / ws;
		res->peak_l1_bps[w] = (double)best1[w] * 8.0 / ws;
	}
	if (res->pkts > 0 && tmax > tmin) {
		res->wall_duration_s = (double)(tmax - tmin) / mult / 1e9;
		res->avg_bps = (double)res->bytes * 8.0 / res->wall_duration_s;
	}
	free(last);
	free(sorted);
	return 0;
}

/* ---------- Гистограмма ---------- */

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
	/* Ранговое определение: наименьшее значение, не меньше которого q*N элементов. */
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
