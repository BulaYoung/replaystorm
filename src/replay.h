/*
 * Общий контекст запуска и интерфейсы отчёта и отправки.
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
	double mult;           /* итоговый множитель для MODE_TIMED */
	unsigned ip_threads;   /* число IP-шардов/потоков */
	int cpus[MAX_CPUS];
	int ncpus;
	int cpus_from_numa;
	unsigned mtu;
	double link_bps;       /* 0 — неизвестна */
	const char *link_src;
	int64_t index_ns, norm_ns; /* сколько заняла подготовка */
} afr_ctx_t;

/* Отчёт анализа (--analyze) */
void afr_report_analysis(const afr_ctx_t *c);
/* Предупреждения перед стартом; возвращает число предупреждений. */
int afr_report_warnings(const afr_ctx_t *c);

/* Отправка; возвращает код выхода. */
int afr_replay_run(afr_ctx_t *c);

#endif
