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

uint8_t afr_classify_frame(const uint8_t *p, uint32_t caplen, int raw_ip, dis_t *d, uint32_t *h32)
{
	uint32_t flen = caplen + (raw_ip ? ETH_HLEN_ : 0);
	uint8_t f = 0;
	afr_dissect(p, caplen, raw_ip, d);
	*h32 = 0;
	if ((raw_ip && caplen == 0) || flen < ETH_HLEN_)
		f |= PF_SMALL;
	else if (raw_ip && !d->l3)
		f |= PF_BADRAW;
	if (caplen >= 0xFFFF)
		f |= PF_HUGE; /* the index stores at most 0xFFFF; anything that long is too big */
	if (!raw_ip && d->outer_ethertype == ETHT_VLAN)
		f |= PF_VLAN8100;
	if (!d->l3)
		f |= PF_NONIP;
	else
		*h32 = (uint32_t)(afr_flow_hash(d) >> 32);
	return f;
}

unsigned afr_resolve_shard(uint32_t flen, uint32_t h32, uint8_t flags, const idx_cfg_t *cfg,
                           int *reason)
{
	if (flags & PF_SMALL) {
		*reason = SKIP_TOO_SMALL;
		return SHARD_SKIP;
	}
	if (flags & PF_BADRAW) {
		*reason = SKIP_BAD_RAW;
		return SHARD_SKIP;
	}
	/* Same check as the kernel: beyond MTU+14 only an 802.1Q tag is allowed. */
	uint32_t limit = cfg->max_frame + ((flags & PF_VLAN8100) ? 4 : 0);
	if ((flags & PF_HUGE) || flen > limit || flen > 0xFFFF) {
		*reason = SKIP_TOO_BIG;
		return SHARD_SKIP;
	}
	if (flags & PF_NONIP)
		return cfg->ip_shards; /* separate shard for non-IP */
	return (unsigned)(((uint64_t)h32 * cfg->ip_shards) >> 32);
}

unsigned afr_classify(const uint8_t *p, uint32_t caplen, int raw_ip, const idx_cfg_t *cfg,
                      dis_t *d, int *reason)
{
	uint32_t h32;
	uint8_t f = afr_classify_frame(p, caplen, raw_ip, d, &h32);
	return afr_resolve_shard(caplen + (raw_ip ? ETH_HLEN_ : 0), h32, f, cfg, reason);
}

/* ---------- Step 1: build ---------- */

typedef struct {
	const pcap_file_t *pf;
	pkt_index_t *ix;
	_Atomic size_t scanned;
	atomic_int done;
	_Atomic size_t next_chunk;
} build_ctx_t;

typedef struct {
	build_ctx_t *ctx;
	pthread_t th;
	idx_stats_t st;
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
		ix->flags[i] = afr_classify_frame(p, len, raw, &d, &ix->h32[i]);
		h->st.bytes += len + (raw ? ETH_HLEN_ : 0);
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
	void *p = mmap(NULL, bytes ? bytes : 1, PROT_READ | PROT_WRITE,
	               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	return p == MAP_FAILED ? NULL : p;
}

static int alloc_arrays(pkt_index_t *ix, size_t cap)
{
	ix->cap = cap;
	ix->mem = IDX_MEM_ANON;
	ix->offlen = map_array(cap * sizeof(uint64_t));
	ix->ts = map_array(cap * sizeof(int64_t));
	ix->h32 = map_array(cap * sizeof(uint32_t));
	ix->flags = map_array(cap);
	if (ix->offlen && ix->ts && ix->h32 && ix->flags)
		return 0;
	afr_index_free_arrays(ix);
	/* Fallback: growing arrays, hashing after the pass. */
	ix->mem = IDX_MEM_MALLOC;
	ix->cap = 1u << 20;
	ix->offlen = malloc(ix->cap * sizeof(uint64_t));
	ix->ts = malloc(ix->cap * sizeof(int64_t));
	ix->h32 = malloc(ix->cap * sizeof(uint32_t));
	ix->flags = malloc(ix->cap);
	return (ix->offlen && ix->ts && ix->h32 && ix->flags) ? 0 : -1;
}

static int grow_arrays(pkt_index_t *ix)
{
	size_t nc = ix->cap * 2;
	void *p;
	if (!(p = realloc(ix->offlen, nc * sizeof(uint64_t))))
		return -1;
	ix->offlen = p;
	if (!(p = realloc(ix->ts, nc * sizeof(int64_t))))
		return -1;
	ix->ts = p;
	if (!(p = realloc(ix->h32, nc * sizeof(uint32_t))))
		return -1;
	ix->h32 = p;
	if (!(p = realloc(ix->flags, nc)))
		return -1;
	ix->flags = p;
	ix->cap = nc;
	return 0;
}

int afr_index_build(const pcap_file_t *pf, const idx_cfg_t *cfg, pkt_index_t *ix, char *err,
                    size_t errlen)
{
	memset(ix, 0, sizeof(*ix));
	/* Upper bound on the record count: each takes at least 16 bytes. */
	if (alloc_arrays(ix, (pf->size - PCAP_FILE_HDR_LEN) / PCAP_REC_HDR_LEN + 1) < 0) {
		snprintf(err, errlen, "out of memory for the packet index");
		afr_index_free(ix);
		return -1;
	}

	build_ctx_t ctx = {.pf = pf, .ix = ix};
	unsigned nh = cfg->hash_threads ? cfg->hash_threads : 1;
	hasher_t *hs = calloc(nh, sizeof(*hs));
	if (!hs) {
		snprintf(err, errlen, "out of memory");
		afr_index_free(ix);
		return -1;
	}
	for (unsigned i = 0; i < nh; i++)
		hs[i].ctx = &ctx;
	unsigned started = 0;
	if (ix->mem == IDX_MEM_ANON) {
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
			if (ix->mem != IDX_MEM_MALLOC || grow_arrays(ix) < 0) {
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

	if (ix->mem == IDX_MEM_MALLOC && !oom) {
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

/* ---------- Step 2: resolve ---------- */

typedef struct {
	pkt_index_t *ix;
	const idx_cfg_t *cfg;
	int raw_ip;
	size_t a, b;
	pthread_t th;
	int started;
	uint64_t skipped[SKIP_REASONS];
	uint64_t skipped_bytes, l1_bytes;
	uint32_t max_frame;
	uint64_t *shard_pkts, *shard_bytes;
} resolver_t;

static void *resolve_main(void *arg)
{
	resolver_t *r = arg;
	pkt_index_t *ix = r->ix;
	const uint32_t extra = r->raw_ip ? ETH_HLEN_ : 0;
	for (size_t i = r->a; i < r->b; i++) {
		uint32_t flen = OFFLEN_LEN(ix->offlen[i]) + extra;
		int reason = 0;
		unsigned sh = afr_resolve_shard(flen, ix->h32[i], ix->flags[i], r->cfg, &reason);
		ix->shard[i] = (uint16_t)sh;
		if (sh == SHARD_SKIP) {
			r->skipped[reason]++;
			r->skipped_bytes += flen;
		} else {
			r->shard_pkts[sh]++;
			r->shard_bytes[sh] += flen;
			r->l1_bytes += afr_l1_bytes(flen);
			if (flen > r->max_frame)
				r->max_frame = flen;
		}
	}
	return NULL;
}

int afr_index_resolve(pkt_index_t *ix, int raw_ip, const idx_cfg_t *cfg, char *err,
                      size_t errlen)
{
	free(ix->shard_pkts);
	free(ix->shard_bytes);
	ix->nshards = cfg->ip_shards + 1;
	ix->shard_pkts = calloc(ix->nshards, sizeof(uint64_t));
	ix->shard_bytes = calloc(ix->nshards, sizeof(uint64_t));
	if (!ix->shard)
		ix->shard = map_array(ix->n * sizeof(uint16_t));
	unsigned nt = cfg->hash_threads ? cfg->hash_threads : 1;
	resolver_t *rs = calloc(nt, sizeof(*rs));
	int ok = ix->shard_pkts && ix->shard_bytes && ix->shard && rs;
	for (unsigned t = 0; ok && t < nt; t++) {
		rs[t].shard_pkts = calloc(ix->nshards, sizeof(uint64_t));
		rs[t].shard_bytes = calloc(ix->nshards, sizeof(uint64_t));
		ok = rs[t].shard_pkts && rs[t].shard_bytes;
	}
	if (!ok) {
		for (unsigned t = 0; rs && t < nt; t++) {
			free(rs[t].shard_pkts);
			free(rs[t].shard_bytes);
		}
		free(rs);
		snprintf(err, errlen, "out of memory for shard numbers");
		return -1;
	}

	memset(ix->st.skipped, 0, sizeof(ix->st.skipped));
	ix->st.skipped_bytes = ix->st.l1_bytes = 0;
	ix->st.max_frame = 0;
	size_t per = (ix->n + nt - 1) / nt;
	for (unsigned t = 0; t < nt; t++) {
		resolver_t *r = &rs[t];
		r->ix = ix;
		r->cfg = cfg;
		r->raw_ip = raw_ip;
		r->a = (size_t)t * per < ix->n ? (size_t)t * per : ix->n;
		r->b = r->a + per < ix->n ? r->a + per : ix->n;
		r->started = pthread_create(&r->th, NULL, resolve_main, r) == 0;
		if (!r->started)
			resolve_main(r);
	}
	for (unsigned t = 0; t < nt; t++) {
		resolver_t *r = &rs[t];
		if (r->started)
			pthread_join(r->th, NULL);
		for (int k = 0; k < SKIP_REASONS; k++)
			ix->st.skipped[k] += r->skipped[k];
		ix->st.skipped_bytes += r->skipped_bytes;
		ix->st.l1_bytes += r->l1_bytes;
		if (r->max_frame > ix->st.max_frame)
			ix->st.max_frame = r->max_frame;
		for (unsigned k = 0; k < ix->nshards; k++) {
			ix->shard_pkts[k] += r->shard_pkts[k];
			ix->shard_bytes[k] += r->shard_bytes[k];
		}
		free(r->shard_pkts);
		free(r->shard_bytes);
	}
	free(rs);
	return 0;
}

/* ---------- Freeing ---------- */

void afr_index_free_arrays(pkt_index_t *ix)
{
	switch (ix->mem) {
	case IDX_MEM_ANON:
		if (ix->offlen)
			munmap(ix->offlen, ix->cap * sizeof(uint64_t));
		if (ix->ts)
			munmap(ix->ts, ix->cap * sizeof(int64_t));
		if (ix->h32)
			munmap(ix->h32, ix->cap * sizeof(uint32_t));
		if (ix->flags)
			munmap(ix->flags, ix->cap);
		break;
	case IDX_MEM_MALLOC:
		free(ix->offlen);
		free(ix->ts);
		free(ix->h32);
		free(ix->flags);
		break;
	case IDX_MEM_CACHE:
		if (ix->cache_map)
			munmap(ix->cache_map, ix->cache_len);
		break;
	default: break;
	}
	if (ix->shard)
		munmap(ix->shard, (ix->n ? ix->n : 1) * sizeof(uint16_t));
	ix->offlen = NULL;
	ix->ts = NULL;
	ix->h32 = NULL;
	ix->flags = NULL;
	ix->shard = NULL;
	ix->cache_map = NULL;
	ix->mem = IDX_MEM_NONE;
}

void afr_index_free(pkt_index_t *ix)
{
	afr_index_free_arrays(ix);
	free(ix->shard_pkts);
	free(ix->shard_bytes);
	ix->shard_pkts = ix->shard_bytes = NULL;
}
