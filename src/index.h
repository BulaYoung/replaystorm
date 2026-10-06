/*
 * Построение индекса пакетов: один последовательный проход по записям pcap
 * и параллельная классификация/хеширование в нескольких потоках.
 */
#ifndef AFR_INDEX_H
#define AFR_INDEX_H

#include "afr.h"
#include "dissect.h"
#include "pcap.h"

typedef struct {
	uint64_t pkts, bytes;            /* все записи файла (bytes — по caplen) */
	uint64_t truncated_caplen;       /* caplen < origlen */
	uint64_t skipped[SKIP_REASONS];
	uint64_t skipped_bytes;
	uint64_t ipv4, ipv6, nonip, vlan, qinq, mpls, pppoe, frag;
	uint64_t l2kind[L2K_COUNT];
} idx_stats_t;

typedef struct {
	size_t n;           /* число записей */
	uint64_t *offlen;   /* смещение + длина */
	int64_t *ts;        /* абсолютные метки, затем шкала расписания */
	uint16_t *shard;    /* номер шарда или SHARD_SKIP */
	size_t cap;
	int mmapped;
	unsigned nshards;   /* IP-шарды + 1 шард для не-IP */
	uint64_t *shard_pkts, *shard_bytes;
	idx_stats_t st;
	int tail_problem;   /* PCAP_REC_TRUNCATED / PCAP_REC_CORRUPT или 0 */
	uint64_t tail_off;  /* где оборвался разбор */
} pkt_index_t;

typedef struct {
	unsigned ip_shards;    /* число IP-шардов (= потоков отправки) */
	uint32_t max_frame;    /* MTU + 14 */
	unsigned hash_threads; /* потоков для хеширования */
} idx_cfg_t;

int afr_index_build(const pcap_file_t *pf, const idx_cfg_t *cfg, pkt_index_t *ix, char *err,
                    size_t errlen);
/* Освободить глобальные массивы (offlen/ts/shard). Счётчики остаются. */
void afr_index_free_arrays(pkt_index_t *ix);
void afr_index_free(pkt_index_t *ix);

/* Классификация одного кадра: номер шарда или SHARD_SKIP; reason — причина пропуска. */
unsigned afr_classify(const uint8_t *p, uint32_t caplen, int raw_ip, const idx_cfg_t *cfg,
                      dis_t *d, int *reason);

#endif
