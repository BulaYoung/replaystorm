#ifndef AFR_CLI_H
#define AFR_CLI_H

#include "afr.h"

enum { MODE_TIMED = 0, MODE_TOPSPEED, MODE_MBPS, MODE_PPS };
enum { LAG_CATCHUP = 0, LAG_REBASE };
enum { IO_AUTO = 0, IO_DIRECT, IO_MMAP };

#define MAX_CPUS 1024

typedef struct {
	const char *iface;
	const char *file;
	unsigned threads;     /* 0 means default */
	const char *cpus;

	int mode;
	double multiplier;    /* for MODE_TIMED */
	int64_t duration_ns;  /* --duration: multiplier is derived */
	double mbps, pps;
	double line_frac;     /* --mbps line / N%: fraction of the link on the wire (0 = off) */
	uint64_t loops;       /* 0 means infinite */

	int ts_order;
	int64_t max_gap;
	int exclude_outliers;
	int64_t outlier_jump;
	int lag_policy;
	int64_t lag_threshold;
	int64_t spin_ns;
	int64_t pace_slack;   /* --mbps/--pps: send packets due within this window at once */
	int64_t timing_res;
	int clock_mode;       /* CLOCK_MODE_* from clock.h */

	unsigned batch;
	unsigned ring_frames;
	int qdisc_bypass;
	int packet_loss;
	double link_speed_bps; /* 0 means auto-detect */
	unsigned mtu;          /* 0 means from interface */

	int preload;
	const char *index_cache; /* --index-cache FILE or "auto" */
	uint64_t readahead;   /* bytes kept requested ahead of the senders */
	int drop_behind;      /* -1 auto, 0 off, 1 on */
	int io_mode;          /* IO_AUTO / IO_DIRECT / IO_MMAP */
	unsigned io_threads;  /* direct I/O reader threads */
	uint8_t smac[6], dmac[6];

	int analyze;
	const char *stats_json;
	int quiet;

	int mutate_ip, mutate_port;
	uint32_t mutate_ip_offset; /* host byte order */
	uint32_t mutate_port_step;
} opts_t;

/* 0: continue, 1: help was printed (exit 0), -1: error (exit 2). */
int afr_parse_args(int argc, char **argv, opts_t *o);
void afr_usage(FILE *f);

#endif
