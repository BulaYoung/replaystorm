#include "live.h"

#include <stdlib.h>
#include <string.h>

int afr_live_init(live_t *l, double target_gbps, int64_t start_ns, int64_t start_real_ns)
{
	memset(l, 0, sizeof(*l));
	l->hist = calloc(LIVE_HIST_BINS, sizeof(uint32_t));
	if (!l->hist)
		return -1;
	l->target_gbps = target_gbps;
	l->start_ns = start_ns;
	l->start_real_ns = start_real_ns;
	l->reset_ns = start_ns;
	return 0;
}

void afr_live_free(live_t *l)
{
	free(l->hist);
	l->hist = NULL;
}

void afr_live_reset(live_t *l, int64_t now_ns)
{
	uint32_t *h = l->hist;
	double target = l->target_gbps;
	int64_t s = l->start_ns, r = l->start_real_ns;
	double ng = l->now_gbps, nm = l->now_mpps;
	memset(l, 0, sizeof(*l));
	memset(h, 0, LIVE_HIST_BINS * sizeof(uint32_t));
	l->hist = h;
	l->target_gbps = target;
	l->start_ns = s;
	l->start_real_ns = r;
	l->now_gbps = ng;
	l->now_mpps = nm;
	l->reset_ns = now_ns;
}

void afr_live_add(live_t *l, int64_t t, double dt, double gbps, double mpps, int excluded)
{
	l->now_gbps = gbps;
	l->now_mpps = mpps;
	/* Not counted: the warm-up, link outages, and short (partial) intervals. */
	if (excluded || t < LIVE_WARMUP_NS || dt < 0.9) {
		l->excluded++;
		l->run = 0;
		return;
	}
	if (l->seconds == 0 || gbps < l->min_gbps) {
		l->min_gbps = gbps;
		l->min_at = t;
	}
	if (l->seconds == 0 || mpps < l->min_mpps)
		l->min_mpps = mpps;
	if (l->seconds == 0 || gbps > l->max_gbps) {
		l->max_gbps = gbps;
		l->max_at = t;
	}
	l->seconds++;
	l->sum_gbps += gbps;
	if (l->target_gbps > 0 && gbps < 0.95 * l->target_gbps)
		l->below_target++;
	size_t bin = (size_t)(gbps / LIVE_HIST_STEP + 0.5);
	if (bin >= LIVE_HIST_BINS)
		bin = LIVE_HIST_BINS - 1;
	l->hist[bin]++;

	/* Rolling windows: the value leaving the last minute, and the last hour. */
	if (l->ring_n >= 60)
		l->sum_60 -= l->ring[(l->ring_pos + LIVE_RING - 60) % LIVE_RING];
	if (l->ring_n == LIVE_RING)
		l->sum_3600 -= l->ring[l->ring_pos];
	l->ring[l->ring_pos] = gbps;
	l->ring_pos = (l->ring_pos + 1) % LIVE_RING;
	if (l->ring_n < LIVE_RING)
		l->ring_n++;
	l->sum_60 += gbps;
	l->sum_3600 += gbps;

	/* Worst minute: only over 60 consecutive counted seconds. */
	l->run++;
	if (l->run >= 60 && l->ring_n >= 60) {
		double avg = l->sum_60 / 60.0;
		if (l->worst_min_at == 0 || avg < l->worst_min_gbps) {
			l->worst_min_gbps = avg;
			l->worst_min_at = t;
		}
	}
}

double afr_live_quantile(const live_t *l, double q)
{
	if (!l->seconds)
		return 0;
	uint64_t want = (uint64_t)(q * (double)l->seconds);
	if (want >= l->seconds)
		want = l->seconds - 1;
	uint64_t acc = 0;
	for (size_t b = 0; b < LIVE_HIST_BINS; b++) {
		acc += l->hist[b];
		if (acc > want)
			return (double)b * LIVE_HIST_STEP;
	}
	return (double)(LIVE_HIST_BINS - 1) * LIVE_HIST_STEP;
}
