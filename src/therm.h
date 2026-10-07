/*
 * NVMe temperature and a thermal governor for disk reads.
 *
 * A pcap much larger than RAM is read from disk for every lap. Sustained reads at the
 * drive's limit heat it up until it enters thermal throttling (Thermal Management T1)
 * and drops to a fraction of its speed for tens of seconds. The governor keeps the
 * drive just below a target temperature by limiting the direct I/O read rate, which
 * turns "full speed, then a collapse" into a steady rate the cooling can sustain.
 */
#ifndef AFR_THERM_H
#define AFR_THERM_H

#include "afr.h"

#include <pthread.h>
#include <stdatomic.h>

#define THERM_MAX_DEVS 8
#define GOV_MIN_RATE (200.0 * 1024 * 1024) /* bytes/s: never throttle reads below this */

/* ---------- Governor (pure, unit-tested) ---------- */

typedef struct {
	int target;      /* keep the drive at or below this temperature, C */
	double limit;    /* current read rate limit, bytes/s; 0 = unlimited */
	int prev_temp;
	double max_seen; /* highest measured read rate */
} gov_t;

void afr_gov_init(gov_t *g, int target);
/* One step per second: temperature now and bytes/s read during the last second.
 * Returns the new limit in bytes/s (0 = unlimited). */
double afr_gov_step(gov_t *g, int temp, double measured_bps);

/* ---------- Temperature ---------- */

typedef struct {
	int n;
	int fd[THERM_MAX_DEVS];         /* /dev/nvmeX for the SMART log (ioctl), or -1 */
	char hwmon[THERM_MAX_DEVS][640]; /* sysfs temp1_input, or "" */
	char name[THERM_MAX_DEVS][32];
	int have_t1;                    /* T1 counters readable (ioctl) */
} therm_dev_t;

/* Find the NVMe drive(s) holding the file. Returns 0 if at least one temperature
 * source works; desc describes what was found or why not. */
int afr_therm_open(therm_dev_t *t, const char *path, char *desc, size_t desclen);
/* Highest temperature over the drives, C, and the sum of T1/T2 throttling transitions
 * (0 if not available). Returns -1 if no temperature could be read. */
int afr_therm_read(therm_dev_t *t, int *temp_c, uint64_t *throttle_count);
void afr_therm_close(therm_dev_t *t);

/* ---------- Monitor thread ---------- */

typedef struct {
	therm_dev_t dev;
	gov_t gov;
	int governor;                  /* 1: control the read rate */
	_Atomic uint64_t *rate_limit;  /* where the governor publishes its limit (bytes/s) */
	_Atomic uint64_t *bytes_read;  /* total bytes read, to measure the rate */
	_Atomic int temp;              /* last temperature, C (-1 unknown) */
	_Atomic int max_temp;
	_Atomic uint64_t throttle;     /* throttling transitions since start */
	uint64_t throttle0;
	pthread_t th;
	atomic_int stop;
	int running;
} therm_mon_t;

int afr_therm_mon_start(therm_mon_t *m);
void afr_therm_mon_stop(therm_mon_t *m);

#endif
