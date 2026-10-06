/*
 * Packet index construction: one sequential pass over the pcap records
 * and parallel classification/hashing in several threads.
 */
#ifndef AFR_INDEX_H
#define AFR_INDEX_H

#include "afr.h"
#include "dissect.h"
#include "pcap.h"

typedef struct {
	uint64_t pkts, bytes;            /* all records in the file (bytes by caplen) */
	uint64_t truncated_caplen;       /* caplen < origlen */
	uint64_t skipped[SKIP_REASONS];
	uint64_t skipped_bytes;
	uint32_t max_frame;              /* largest frame that will be sent (with synthetic L2) */
	uint64_t l1_bytes;               /* sent frames counted on the wire: preamble, IFG, FCS, min 60 */
	uint64_t ipv4, ipv6, nonip, vlan, qinq, mpls, pppoe, frag;
	uint64_t l2kind[L2K_COUNT];
} idx_stats_t;

typedef struct {
	size_t n;           /* number of records */
	uint64_t *offlen;   /* offset + length */
	int64_t *ts;        /* absolute timestamps, then the schedule timeline */
	uint16_t *shard;    /* shard number or SHARD_SKIP */
	size_t cap;
	int mmapped;
	unsigned nshards;   /* IP shards + 1 shard for non-IP */
	uint64_t *shard_pkts, *shard_bytes;
	idx_stats_t st;
	int tail_problem;   /* PCAP_REC_TRUNCATED / PCAP_REC_CORRUPT or 0 */
	uint64_t tail_off;  /* where parsing stopped */
} pkt_index_t;

typedef struct {
	unsigned ip_shards;    /* number of IP shards (= sender threads) */
	uint32_t max_frame;    /* MTU + 14 */
	unsigned hash_threads; /* threads for hashing */
} idx_cfg_t;

int afr_index_build(const pcap_file_t *pf, const idx_cfg_t *cfg, pkt_index_t *ix, char *err,
                    size_t errlen);
/* Free the global arrays (offlen/ts/shard). Counters are kept. */
void afr_index_free_arrays(pkt_index_t *ix);
void afr_index_free(pkt_index_t *ix);

/* Classify one frame: shard number or SHARD_SKIP; reason = why it was skipped. */
unsigned afr_classify(const uint8_t *p, uint32_t caplen, int raw_ip, const idx_cfg_t *cfg,
                      dis_t *d, int *reason);

#endif
