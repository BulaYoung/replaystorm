/*
 * Long-run statistics: what a replay that runs for days has done so far. Updated once a
 * second by the stats thread; shown on request (Enter in the terminal, SIGUSR1) and
 * written to a status file that can be read from any terminal (afreplay --status).
 */
#ifndef AFR_LIVE_H
#define AFR_LIVE_H

#include "afr.h"

#define LIVE_HIST_STEP 0.01     /* Gbit/s per histogram bin */
#define LIVE_HIST_BINS 50000    /* up to 500 Gbit/s */
#define LIVE_RING 3600          /* last hour of per-second rates */
#define LIVE_WARMUP_NS (10 * NS_PER_SEC)

typedef struct {
	double target_gbps;      /* fixed-rate target (0: none) */
	int64_t start_ns;        /* CLOCK_MONOTONIC at T0 */
	int64_t start_real_ns;   /* CLOCK_REALTIME at T0 */
	int64_t reset_ns;        /* last reset of the min/max statistics */
	/* last second */
	double now_gbps, now_mpps;
	/* counted seconds (warm-up, link outages and partial intervals excluded) */
	uint64_t seconds, excluded;
	double sum_gbps;
	double min_gbps, max_gbps, min_mpps;
	int64_t min_at, max_at;   /* ns since T0 */
	uint64_t below_target;    /* seconds below 95% of the target */
	uint32_t *hist;           /* per-second Gbit/s histogram */
	/* rolling windows over counted seconds */
	double ring[LIVE_RING];
	unsigned ring_pos, ring_n;
	double sum_60, sum_3600;
	unsigned run;             /* consecutive counted seconds (for the worst minute) */
	double worst_min_gbps;    /* lowest 60-second average */
	int64_t worst_min_at;     /* end of that minute, ns since T0 */
} live_t;

int afr_live_init(live_t *l, double target_gbps, int64_t start_ns, int64_t start_real_ns);
void afr_live_free(live_t *l);
/* One interval: t = end of the interval (ns since T0), dt in seconds. excluded: the link
 * was down during it. */
void afr_live_add(live_t *l, int64_t t, double dt, double gbps, double mpps, int excluded);
/* Forget minima, maxima, percentiles and windows (totals elsewhere are kept). */
void afr_live_reset(live_t *l, int64_t now_ns);
/* Value of the q-quantile of the per-second rate, Gbit/s (0 if nothing counted). */
double afr_live_quantile(const live_t *l, double q);

#endif
