#include "clock.h"

#include <math.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>

int afr_clk_use_tsc;
double afr_clk_ns_per_tick = 1.0;
__thread uint64_t afr_clk_base_tick;
__thread int64_t afr_clk_base_ns;

#if AFR_HAVE_TSC
/* A (tsc, monotonic) pair with minimal uncertainty. */
static void sample(uint64_t *tick, int64_t *ns)
{
	uint64_t best = UINT64_MAX;
	for (int i = 0; i < 7; i++) {
		uint64_t a = __rdtsc();
		int64_t m = afr_now_ns();
		uint64_t b = __rdtsc();
		if (b - a < best) {
			best = b - a;
			*tick = a + (b - a) / 2;
			*ns = m;
		}
	}
}

static int cpu_has_invariant_tsc(void)
{
	FILE *f = fopen("/proc/cpuinfo", "r");
	if (!f)
		return 0;
	char line[8192];
	int ok = 0;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "flags", 5)) {
			ok = strstr(line, " constant_tsc") && strstr(line, " nonstop_tsc");
			break;
		}
	}
	fclose(f);
	return ok;
}
#endif

static void read_clocksource(char *buf, size_t n)
{
	snprintf(buf, n, "?");
	FILE *f = fopen("/sys/devices/system/clocksource/clocksource0/current_clocksource", "r");
	if (!f)
		return;
	if (fgets(buf, (int)n, f))
		buf[strcspn(buf, "\n")] = 0;
	fclose(f);
}

const char *afr_clock_init(int mode)
{
	static char desc[160];
	char cs[32];
	read_clocksource(cs, sizeof(cs));
	afr_clk_use_tsc = 0;
#if AFR_HAVE_TSC
	int want = 0;
	if (mode == CLOCK_MODE_TSC)
		want = 1;
	else if (mode == CLOCK_MODE_AUTO)
		want = strcmp(cs, "tsc") != 0 && cpu_has_invariant_tsc();
	if (want) {
		/* Calibrate on a single core: TSCs of different cores may be unsynchronized. */
		cpu_set_t saved, one;
		int pinned = sched_getaffinity(0, sizeof(saved), &saved) == 0;
		if (pinned) {
			CPU_ZERO(&one);
			CPU_SET(sched_getcpu(), &one);
			pinned = sched_setaffinity(0, sizeof(one), &one) == 0;
		}
		double k[2] = {0, 0};
		for (int r = 0; r < 2; r++) {
			uint64_t t1 = 0, t2 = 0;
			int64_t n1 = 0, n2 = 0;
			sample(&t1, &n1);
			struct timespec ts = {0, 100 * 1000 * 1000};
			nanosleep(&ts, NULL);
			sample(&t2, &n2);
			if (t2 > t1 && n2 > n1)
				k[r] = (double)(n2 - n1) / (double)(t2 - t1);
		}
		if (pinned)
			sched_setaffinity(0, sizeof(saved), &saved);
		if (k[0] > 0 && k[1] > 0 && fabs(k[0] - k[1]) / k[0] < 1e-3) {
			afr_clk_ns_per_tick = (k[0] + k[1]) / 2;
			afr_clk_use_tsc = 1;
			snprintf(desc, sizeof(desc), "TSC %.3f GHz (kernel clocksource: %s)",
			         1.0 / afr_clk_ns_per_tick, cs);
			afr_clock_thread_init();
			return desc;
		}
		snprintf(desc, sizeof(desc),
		         "CLOCK_MONOTONIC (kernel clocksource: %s; TSC calibration unstable)", cs);
		return desc;
	}
#else
	(void)mode;
#endif
	snprintf(desc, sizeof(desc), "CLOCK_MONOTONIC (kernel clocksource: %s)", cs);
	return desc;
}

int afr_clock_resync(void)
{
#if AFR_HAVE_TSC
	if (afr_clk_use_tsc) {
		int64_t d = afr_clock_ns() - afr_now_ns();
		if (d > AFR_CLOCK_RESYNC_NS || d < -AFR_CLOCK_RESYNC_NS) {
			afr_clock_thread_init();
			return 1;
		}
	}
#endif
	return 0;
}

void afr_clock_thread_init(void)
{
#if AFR_HAVE_TSC
	if (afr_clk_use_tsc)
		sample(&afr_clk_base_tick, &afr_clk_base_ns);
#endif
}
