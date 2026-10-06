/*
 * Fast clock for the hot loop.
 *
 * CLOCK_MONOTONIC via vDSO normally costs ~20 ns. But if the kernel has fallen
 * back to the hpet/acpi_pm clocksource (TSC marked unstable, which happens on
 * laptops and VMs), each call costs ~1 us. In that case we use rdtsc: the
 * frequency is calibrated once against CLOCK_MONOTONIC, and the offset is set per
 * thread (in case TSCs of different cores are not synchronized). The result is
 * nanoseconds on the same timeline as CLOCK_MONOTONIC.
 */
#ifndef AFR_CLOCK_H
#define AFR_CLOCK_H

#include "afr.h"

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define AFR_HAVE_TSC 1
#else
#define AFR_HAVE_TSC 0
#endif

enum { CLOCK_MODE_AUTO = 0, CLOCK_MODE_TSC, CLOCK_MODE_MONO };

extern int afr_clk_use_tsc;
extern double afr_clk_ns_per_tick;
extern __thread uint64_t afr_clk_base_tick;
extern __thread int64_t afr_clk_base_ns;

/* Choose the clock and calibrate the TSC frequency. Returns a description for the log. */
const char *afr_clock_init(int mode);
/* Align the current thread's TSC offset to CLOCK_MONOTONIC. */
void afr_clock_thread_init(void);

/* Check TSC against CLOCK_MONOTONIC and resync on drift (call where the thread
 * is about to sleep anyway). Returns 1 if a resync happened. */
#define AFR_CLOCK_RESYNC_NS (50 * NS_PER_US)
int afr_clock_resync(void);

static inline int64_t afr_clock_ns(void)
{
#if AFR_HAVE_TSC
	if (AFR_LIKELY(afr_clk_use_tsc))
		return afr_clk_base_ns +
		       (int64_t)((double)(__rdtsc() - afr_clk_base_tick) * afr_clk_ns_per_tick);
#endif
	return afr_now_ns();
}

#endif
