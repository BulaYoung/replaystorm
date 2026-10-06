#ifndef AFR_CLI_H
#define AFR_CLI_H

#include "afr.h"

enum { MODE_TIMED = 0, MODE_TOPSPEED, MODE_MBPS, MODE_PPS };
enum { LAG_CATCHUP = 0, LAG_REBASE };

#define MAX_CPUS 1024

typedef struct {
	const char *iface;
	const char *file;
	unsigned threads;     /* 0 — по умолчанию */
	const char *cpus;

	int mode;
	double multiplier;    /* для MODE_TIMED */
	int64_t duration_ns;  /* --duration: множитель подбирается */
	double mbps, pps;
	uint64_t loops;       /* 0 — бесконечно */

	int ts_order;
	int64_t max_gap;
	int exclude_outliers;
	int64_t outlier_jump;
	int lag_policy;
	int64_t lag_threshold;
	int64_t spin_ns;
	int64_t timing_res;

	unsigned batch;
	unsigned ring_frames;
	int qdisc_bypass;
	int packet_loss;
	double link_speed_bps; /* 0 — определить автоматически */
	unsigned mtu;          /* 0 — с интерфейса */

	int preload;
	uint8_t smac[6], dmac[6];

	int analyze;
	const char *stats_json;
	int quiet;

	int mutate_ip, mutate_port;
	uint32_t mutate_ip_offset; /* в порядке хоста */
	uint32_t mutate_port_step;
} opts_t;

/* 0 — продолжать, 1 — была напечатана справка (выход 0), -1 — ошибка (выход 2). */
int afr_parse_args(int argc, char **argv, opts_t *o);
void afr_usage(FILE *f);

#endif
