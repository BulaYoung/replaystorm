#include "index.h"

#include "sched.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define HASH_CHUNK 65536u
#define PUBLISH_EVERY 4096u

unsigned afr_classify(const uint8_t *p, uint32_t caplen, int raw_ip, const idx_cfg_t *cfg,
                      dis_t *d, int *reason)
{
	uint32_t flen = caplen + (raw_ip ? ETH_HLEN_ : 0);
	afr_dissect(p, caplen, raw_ip, d);
	if (raw_ip && caplen == 0) {
		*reason = SKIP_TOO_SMALL;
		return SHARD_SKIP;
	}
	if (flen < ETH_HLEN_) {
		*reason = SKIP_TOO_SMALL;
		return SHARD_SKIP;
	}
	if (raw_ip && !d->l3) {
		*reason = SKIP_BAD_RAW;
		return SHARD_SKIP;
	}
	/* Same check as the kernel: beyond MTU+14 only an 802.1Q tag is allowed. */
	uint32_t limit = cfg->max_frame + (!raw_ip && d->outer_ethertype == ETHT_VLAN ? 4 : 0);
	if (flen > limit || flen > 0xFFFF) {
		*reason = SKIP_TOO_BIG;
		return SHARD_SKIP;
	}
	if (!d->l3)
		return cfg->ip_shards; /* separate shard for non-IP */
	uint64_t h = afr_flow_hash(d);
	return (unsigned)(((unsigned __int128)h * cfg->ip_shards) >> 64);
}

typedef struct {
	const pcap_file_t *pf;
	const idx_cfg_t *cfg;
	pkt_index_t *ix;
	_Atomic size_t scanned;
	atomic_int done;
	_Atomic size_t next_chunk;
} build_ctx_t;

typedef struct {
	build_ctx_t *ctx;
	pthread_t th;
	idx_stats_t st;
	uint64_t *shard_pkts, *shard_bytes;
} hasher_t;

static void hash_range(hasher_t *h, size_t a, size_t b)
{
	const pcap_file_t *pf = h->ctx->pf;
	pkt_index_t *ix = h->ctx->ix;
	const int raw = pf->raw_ip;
	for (size_t i = a; i < b; i++) {
		uint64_t ol = ix->offlen[i];
		uint32_t len = OFFLEN_LEN(ol);
		const uint8_t *p = pf->base + OFFLEN_OFF(ol);
		dis_t d;
		int reason = 0;
		unsigned sh = afr_classify(p, len, raw, h->ctx->cfg, &d, &reason);
		uint32_t flen = len + (raw ? ETH_HLEN_ : 0);
		h->st.bytes += flen;
		if (sh == SHARD_SKIP) {
			h->st.skipped[reason]++;
			h->st.skipped_bytes += flen;
		} else {
			h->shard_pkts[sh]++;
			h->shard_bytes[sh] += flen;
			h->st.l1_bytes += afr_l1_bytes(flen);
			if (flen > h->st.max_frame)
				h->st.max_frame = flen;
		}
		ix->shard[i] = (uint16_t)sh;
		h->st.l2kind[d.l2kind]++;
		if (d.l3 == 4)
			h->st.ipv4++;
		else if (d.l3 == 6)
			h->st.ipv6++;
		else
			h->st.nonip++;
		if (d.vlan_depth)
			h->st.vlan++;
		if (d.vlan_depth >= 2)
			h->st.qinq++;
		if (d.mpls)
			h->st.mpls++;
		if (d.pppoe)
			h->st.pppoe++;
		if (d.frag)
			h->st.frag++;
	}
}

static void *hasher_main(void *arg)
{
	hasher_t *h = arg;
	build_ctx_t *c = h->ctx;
	for (;;) {
		size_t chunk = atomic_fetch_add(&c->next_chunk, 1);
		size_t a = chunk * HASH_CHUNK, b = a + HASH_CHUNK;
		size_t avail;
		for (;;) {
			int done = atomic_load_explicit(&c->done, memory_order_acquire);
			avail = atomic_load_explicit(&c->scanned, memory_order_acquire);
			if (avail >= b || done)
				break;
			struct timespec ts = {0, 100000};
			nanosleep(&ts, NULL);
		}
		if (a >= avail)
			return NULL;
		if (b > avail)
			b = avail;
		hash_range(h, a, b);
	}
}

static void *map_array(size_t bytes)
{
	void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
	               -1, 0);
	return p == MAP_FAILED ? NULL : p;
}

static int alloc_arrays(pkt_index_t *ix, size_t cap)
{
	ix->cap = cap;
	ix->offlen = map_array(cap * sizeof(uint64_t));
	ix->ts = map_array(cap * sizeof(int64_t));
	ix->shard = map_array(cap * sizeof(uint16_t));
	if (ix->offlen && ix->ts && ix->shard) {
		ix->mmapped = 1;
		return 0;
	}
	afr_index_free_arrays(ix);
	/* Fallback: growing arrays, hashing after the pass. */
	ix->mmapped = 0;
	ix->cap = 1u << 20;
	ix->offlen = malloc(ix->cap * sizeof(uint64_t));
	ix->ts = malloc(ix->cap * sizeof(int64_t));
	ix->shard = malloc(ix->cap * sizeof(uint16_t));
	return (ix->offlen && ix->ts && ix->shard) ? 0 : -1;
}

static int grow_arrays(pkt_index_t *ix)
{
	size_t nc = ix->cap * 2;
	uint64_t *o = realloc(ix->offlen, nc * sizeof(uint64_t));
	if (!o)
		return -1;
	ix->offlen = o;
	int64_t *t = realloc(ix->ts, nc * sizeof(int64_t));
	if (!t)
		return -1;
	ix->ts = t;
	uint16_t *s = realloc(ix->shard, nc * sizeof(uint16_t));
	if (!s)
		return -1;
	ix->shard = s;
	ix->cap = nc;
	return 0;
}

int afr_index_build(const pcap_file_t *pf, const idx_cfg_t *cfg, pkt_index_t *ix, char *err,
                    size_t errlen)
{
	memset(ix, 0, sizeof(*ix));
	ix->nshards = cfg->ip_shards + 1;
	ix->shard_pkts = calloc(ix->nshards, sizeof(uint64_t));
	ix->shard_bytes = calloc(ix->nshards, sizeof(uint64_t));
	/* Upper bound on the record count: each takes at least 16 bytes. */
	if (!ix->shard_pkts || !ix->shard_bytes ||
	    alloc_arrays(ix, (pf->size - PCAP_FILE_HDR_LEN) / PCAP_REC_HDR_LEN + 1) < 0) {
		snprintf(err, errlen, "out of memory for the packet index");
		afr_index_free(ix);
		return -1;
	}

	build_ctx_t ctx = {.pf = pf, .cfg = cfg, .ix = ix};
	unsigned nh = cfg->hash_threads ? cfg->hash_threads : 1;
	hasher_t *hs = calloc(nh, sizeof(*hs));
	if (!hs) {
		snprintf(err, errlen, "out of memory");
		afr_index_free(ix);
		return -1;
	}
	for (unsigned i = 0; i < nh; i++) {
		hs[i].ctx = &ctx;
		hs[i].shard_pkts = calloc(ix->nshards, sizeof(uint64_t));
		hs[i].shard_bytes = calloc(ix->nshards, sizeof(uint64_t));
	}
	unsigned started = 0;
	if (ix->mmapped) {
		for (; started < nh; started++)
			if (pthread_create(&hs[started].th, NULL, hasher_main, &hs[started]) != 0)
				break;
	}

	/* Sequential pass: the pcap record chain cannot be walked any other way. */
	uint64_t off = PCAP_FILE_HDR_LEN;
	pcap_rec_t r;
	size_t n = 0;
	int rc;
	int oom = 0;
	while ((rc = pcap_next(pf, &off, &r)) == PCAP_REC_OK) {
		if (n == ix->cap) {
			if (ix->mmapped || grow_arrays(ix) < 0) {
				oom = 1;
				break;
			}
		}
		/* A frame longer than 64 KB will be skipped as oversized anyway. */
		uint32_t len = r.caplen > 0xFFFF ? 0xFFFF : r.caplen;
		ix->offlen[n] = OFFLEN_MAKE(r.data_off, len);
		ix->ts[n] = r.ts_ns;
		if (r.caplen < r.origlen)
			ix->st.truncated_caplen++;
		n++;
		if ((n & (PUBLISH_EVERY - 1)) == 0)
			atomic_store_explicit(&ctx.scanned, n, memory_order_release);
	}
	if (rc != PCAP_REC_OK && rc != PCAP_REC_END) {
		ix->tail_problem = rc;
		ix->tail_off = off;
	}
	ix->n = n;
	atomic_store_explicit(&ctx.scanned, n, memory_order_release);
	atomic_store_explicit(&ctx.done, 1, memory_order_release);

	if (!ix->mmapped && !oom) {
		for (; started < nh; started++)
			if (pthread_create(&hs[started].th, NULL, hasher_main, &hs[started]) != 0)
				break;
	}
	if (started == 0 && !oom) {
		/* Threads failed to start; hash in this thread. */
		atomic_store(&ctx.next_chunk, 0);
		hasher_main(&hs[0]);
	}
	for (unsigned i = 0; i < started; i++)
		pthread_join(hs[i].th, NULL);

	for (unsigned i = 0; i < nh; i++) {
		idx_stats_t *s = &hs[i].st;
		ix->st.bytes += s->bytes;
		ix->st.skipped_bytes += s->skipped_bytes;
		ix->st.l1_bytes += s->l1_bytes;
		if (s->max_frame > ix->st.max_frame)
			ix->st.max_frame = s->max_frame;
		for (int k = 0; k < SKIP_REASONS; k++)
			ix->st.skipped[k] += s->skipped[k];
		for (int k = 0; k < L2K_COUNT; k++)
			ix->st.l2kind[k] += s->l2kind[k];
		ix->st.ipv4 += s->ipv4;
		ix->st.ipv6 += s->ipv6;
		ix->st.nonip += s->nonip;
		ix->st.vlan += s->vlan;
		ix->st.qinq += s->qinq;
		ix->st.mpls += s->mpls;
		ix->st.pppoe += s->pppoe;
		ix->st.frag += s->frag;
		for (unsigned k = 0; k < ix->nshards; k++) {
			if (hs[i].shard_pkts) {
				ix->shard_pkts[k] += hs[i].shard_pkts[k];
				ix->shard_bytes[k] += hs[i].shard_bytes[k];
			}
		}
		free(hs[i].shard_pkts);
		free(hs[i].shard_bytes);
	}
	free(hs);
	ix->st.pkts = n;
	if (oom) {
		snprintf(err, errlen, "out of memory for the index (%zu packets)", n);
		afr_index_free(ix);
		return -1;
	}
	return 0;
}

void afr_index_free_arrays(pkt_index_t *ix)
{
	if (ix->mmapped) {
		if (ix->offlen)
			munmap(ix->offlen, ix->cap * sizeof(uint64_t));
		if (ix->ts)
			munmap(ix->ts, ix->cap * sizeof(int64_t));
		if (ix->shard)
			munmap(ix->shard, ix->cap * sizeof(uint16_t));
	} else {
		free(ix->offlen);
		free(ix->ts);
		free(ix->shard);
	}
	ix->offlen = NULL;
	ix->ts = NULL;
	ix->shard = NULL;
}

void afr_index_free(pkt_index_t *ix)
{
	afr_index_free_arrays(ix);
	free(ix->shard_pkts);
	free(ix->shard_bytes);
	ix->shard_pkts = ix->shard_bytes = NULL;
}
