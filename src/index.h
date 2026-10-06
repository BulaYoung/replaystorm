/*
 * Packet index construction: one sequential pass over the pcap records
 * and parallel classification/hashing in several threads.
 *
 * The index is built in two steps:
 *   1. build (or load from the index cache): per packet the offset+length, the
 *      timestamp, a 32-bit symmetric flow hash and classification flags. None of it
 *      depends on options, so it can be cached on disk.
 *   2. resolve: shard numbers for the current thread count and the MTU-dependent
 *      skip decision, plus the per-shard and per-skip-reason counters.
 */
#ifndef AFR_INDEX_H
#define AFR_INDEX_H

#include "afr.h"
#include "dissect.h"
#include "pcap.h"

/* Per-packet classification flags (independent of MTU and thread count). */
#define PF_NONIP 0x01     /* not IP: goes to the non-IP shard */
#define PF_VLAN8100 0x02  /* outer ethertype is 802.1Q: the kernel allows 4 more bytes */
#define PF_SMALL 0x04     /* always skipped: shorter than an Ethernet header */
#define PF_BADRAW 0x08    /* always skipped: RAW IP without version 4/6 */
#define PF_HUGE 0x10      /* always skipped: caplen above 64 KB */

typedef struct {
	/* filled by build (cached) */
	uint64_t pkts, bytes;            /* all records in the file (bytes by caplen) */
	uint64_t truncated_caplen;       /* caplen < origlen */
	uint64_t ipv4, ipv6, nonip, vlan, qinq, mpls, pppoe, frag;
	uint64_t l2kind[L2K_COUNT];
	/* filled by resolve (depend on MTU) */
	uint64_t skipped[SKIP_REASONS];
	uint64_t skipped_bytes;
	uint32_t max_frame;              /* largest frame that will be sent (with synthetic L2) */
	uint64_t l1_bytes;               /* sent frames counted on the wire: preamble, IFG, FCS, min 60 */
} idx_stats_t;

enum { IDX_MEM_NONE = 0, IDX_MEM_ANON, IDX_MEM_MALLOC, IDX_MEM_CACHE };

typedef struct {
	size_t n;           /* number of records */
	uint64_t *offlen;   /* offset + length */
	int64_t *ts;        /* absolute timestamps, then the schedule timeline */
	uint32_t *h32;      /* upper 32 bits of the symmetric flow hash (0 for non-IP) */
	uint8_t *flags;     /* PF_* */
	uint16_t *shard;    /* shard number or SHARD_SKIP (filled by resolve) */
	size_t cap;
	int mem;            /* IDX_MEM_*: how offlen/ts/h32/flags are allocated */
	void *cache_map;    /* IDX_MEM_CACHE: the mapped cache file */
	size_t cache_len;
	unsigned nshards;   /* IP shards + 1 shard for non-IP */
	uint64_t *shard_pkts, *shard_bytes;
	idx_stats_t st;
	int tail_problem;   /* PCAP_REC_TRUNCATED / PCAP_REC_CORRUPT or 0 */
	uint64_t tail_off;  /* where parsing stopped */
} pkt_index_t;

typedef struct {
	unsigned ip_shards;    /* number of IP shards (= sender threads) */
	uint32_t max_frame;    /* MTU + 14 */
	unsigned hash_threads; /* threads for hashing and resolving */
} idx_cfg_t;

/* Step 1: build the option-independent part of the index from the pcap. */
int afr_index_build(const pcap_file_t *pf, const idx_cfg_t *cfg, pkt_index_t *ix, char *err,
                    size_t errlen);
/* Step 2: shard numbers and MTU-dependent counters for the given configuration. */
int afr_index_resolve(pkt_index_t *ix, int raw_ip, const idx_cfg_t *cfg, char *err,
                      size_t errlen);
/* Free the per-packet arrays. Counters are kept. */
void afr_index_free_arrays(pkt_index_t *ix);
void afr_index_free(pkt_index_t *ix);

/* Classify a frame independently of options: returns PF_* flags and the flow hash. */
uint8_t afr_classify_frame(const uint8_t *p, uint32_t caplen, int raw_ip, dis_t *d,
                           uint32_t *h32);
/* Shard number for a classified frame, or SHARD_SKIP with the reason. */
unsigned afr_resolve_shard(uint32_t flen, uint32_t h32, uint8_t flags, const idx_cfg_t *cfg,
                           int *reason);
/* Both steps for one frame (used by tests). */
unsigned afr_classify(const uint8_t *p, uint32_t caplen, int raw_ip, const idx_cfg_t *cfg,
                      dis_t *d, int *reason);

#endif
