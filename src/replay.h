/*
 * Shared run context and the report and replay interfaces.
 */
#ifndef AFR_REPLAY_H
#define AFR_REPLAY_H

#include "cli.h"
#include "index.h"
#include "pcap.h"
#include "sched.h"

typedef struct {
	opts_t *o;
	pcap_file_t pf;
	pkt_index_t ix;
	ts_result_t tsr;
	rate_result_t rr;
	int have_rr;
	double mult;           /* effective multiplier for MODE_TIMED */
	unsigned ip_threads;   /* number of IP shards/threads */
	int cpus[MAX_CPUS];
	int ncpus;
	int cpus_from_numa;
	unsigned mtu;
	double link_bps;       /* 0 means unknown */
	const char *link_src;
	int64_t index_ns, norm_ns; /* preparation time */
	int index_cached;          /* index was loaded from the cache */
	int64_t rate_lap_ns;       /* --mbps/--pps: duration of one lap of the rate timeline */
} afr_ctx_t;

/* Analysis report (--analyze) */
void afr_report_analysis(const afr_ctx_t *c);
/* Pre-start warnings; returns the number of warnings. */
int afr_report_warnings(const afr_ctx_t *c);

/* Replay; returns the exit code. */
int afr_replay_run(afr_ctx_t *c);

#endif
