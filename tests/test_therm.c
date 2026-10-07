#include "t.h"
#include "therm.h"

/*
 * A simple thermal model of an NVMe drive: the steady temperature is proportional to
 * the read rate (2.0 GB/s -> 74 C), the time constant is two minutes, and at 77 C the
 * drive throttles itself to 1 GB/s (like Thermal Management T1 on the test server).
 */
typedef struct {
	double temp;
	int throttled;
	uint64_t throttle_events;
} drive_t;

static double drive_step(drive_t *d, double want_bps)
{
	const double max_rate = 3.5e9, throttled_rate = 1.0e9;
	if (!d->throttled && d->temp >= 77.0) {
		d->throttled = 1;
		d->throttle_events++;
	} else if (d->throttled && d->temp <= 73.0) {
		d->throttled = 0;
	}
	double rate = want_bps > 0 && want_bps < max_rate ? want_bps : max_rate;
	if (d->throttled && rate > throttled_rate)
		rate = throttled_rate;
	const double tau = 120.0, ambient = 25.0, deg_per_gbps = 24.5;
	d->temp += ((ambient + deg_per_gbps * rate / 1e9) - d->temp) / tau;
	return rate;
}

static void run(int governor, double *avg_last, double *max_temp, uint64_t *events, double *min_last)
{
	drive_t d = {.temp = 60.0};
	gov_t g;
	afr_gov_init(&g, 74);
	double limit = 0, sum = 0;
	*min_last = 1e18;
	int n = 0;
	*max_temp = 0;
	for (int s = 0; s < 3600; s++) {
		double rate = drive_step(&d, limit);
		if (d.temp > *max_temp)
			*max_temp = d.temp;
		if (governor)
			limit = afr_gov_step(&g, (int)d.temp, rate);
		if (s >= 2600) {
			if (rate < *min_last)
				*min_last = rate;
			sum += rate;
			n++;
		}
	}
	*avg_last = sum / n;
	*events = d.throttle_events;
}

void test_therm(void)
{
	double avg, maxt, mn;
	uint64_t ev;
	run(0, &avg, &maxt, &ev, &mn);
	CHECK(ev > 0);        /* without the governor the drive throttles */
	CHECK(mn <= 1.0e9);   /* down to 1 GB/s */
	fprintf(stderr, "  [model] no governor: avg %.2f GB/s, min %.2f GB/s, max %.1f C, throttles %llu\n",
	        avg / 1e9, mn / 1e9, maxt, (unsigned long long)ev);
	run(1, &avg, &maxt, &ev, &mn);
	fprintf(stderr, "  [model] governor 74C: avg %.2f GB/s, min %.2f GB/s, max %.1f C, throttles %llu\n",
	        avg / 1e9, mn / 1e9, maxt, (unsigned long long)ev);
	CHECK_EQ(ev, 0);      /* with it, never */
	CHECK(maxt < 76.0);
	CHECK(avg > 1.8e9);   /* close to the sustainable 2.0 GB/s */
	CHECK(mn > 1.5e9);    /* and without collapses */

	/* Far below the target the limit is lifted again. */
	gov_t g;
	afr_gov_init(&g, 74);
	CHECK(afr_gov_step(&g, 60, 3e9) == 0);
	CHECK(afr_gov_step(&g, 73, 3e9) > 0);
	for (int i = 0; i < 200; i++)
		afr_gov_step(&g, 50, 3e9);
	CHECK(afr_gov_step(&g, 50, 3e9) == 0);
}
