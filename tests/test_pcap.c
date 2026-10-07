#include "idxcache.h"
#include "index.h"
#include "pcap.h"
#include "t.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
	uint8_t buf[8192];
	size_t len;
	int be;
} wbuf_t;

static void put32(wbuf_t *w, uint32_t v)
{
	if (w->be)
		v = __builtin_bswap32(v);
	memcpy(w->buf + w->len, &v, 4);
	w->len += 4;
}

static void put16(wbuf_t *w, uint16_t v)
{
	if (w->be)
		v = __builtin_bswap16(v);
	memcpy(w->buf + w->len, &v, 2);
	w->len += 2;
}

static void file_hdr(wbuf_t *w, int nsec, int be, uint32_t linktype)
{
	w->len = 0;
	w->be = be;
	put32(w, nsec ? 0xa1b23c4du : 0xa1b2c3d4u);
	put16(w, 2);
	put16(w, 4);
	put32(w, 0);
	put32(w, 0);
	put32(w, 65535);
	put32(w, linktype);
}

static void rec(wbuf_t *w, uint32_t sec, uint32_t frac, uint32_t caplen, uint32_t origlen)
{
	put32(w, sec);
	put32(w, frac);
	put32(w, caplen);
	put32(w, origlen);
	for (uint32_t i = 0; i < caplen; i++)
		w->buf[w->len++] = (uint8_t)(i < 12 ? 0x02 : (i == 12 ? 0x88 : (i == 13 ? 0xb5 : i)));
}

static int open_mem(pcap_file_t *pf, const wbuf_t *w, char *err)
{
	memset(pf, 0, sizeof(*pf));
	pf->base = w->buf;
	pf->size = w->len;
	return pcap_parse_header(pf, err, 256);
}

static void formats(void)
{
	for (int nsec = 0; nsec < 2; nsec++) {
		for (int be = 0; be < 2; be++) {
			wbuf_t w;
			file_hdr(&w, nsec, be, 1);
			rec(&w, 1700000000, nsec ? 123456789 : 123456, 60, 60);
			rec(&w, 1700000001, nsec ? 5 : 5, 100, 1500);
			pcap_file_t pf;
			char err[256];
			CHECK_EQ(open_mem(&pf, &w, err), 0);
			CHECK_EQ(pf.nsec, nsec);
			CHECK_EQ(pf.swapped, be != (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__));
			CHECK_EQ(pf.linktype, 1);
			uint64_t off = PCAP_FILE_HDR_LEN;
			pcap_rec_t r = {0};
			CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_OK);
			CHECK_EQ(r.caplen, 60);
			CHECK_EQ(r.ts_ns, 1700000000LL * NS_PER_SEC + (nsec ? 123456789 : 123456000));
			CHECK_EQ(r.data_off, PCAP_FILE_HDR_LEN + PCAP_REC_HDR_LEN);
			CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_OK);
			CHECK_EQ(r.caplen, 100);
			CHECK_EQ(r.origlen, 1500);
			CHECK_EQ(r.ts_ns, 1700000001LL * NS_PER_SEC + (nsec ? 5 : 5000));
			CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_END);
		}
	}
}

static void truncated(void)
{
	wbuf_t w;
	file_hdr(&w, 0, 0, 1);
	rec(&w, 1, 0, 60, 60);
	rec(&w, 2, 0, 60, 60);
	size_t full = w.len;
	pcap_file_t pf;
	char err[256];
	uint64_t off;
	pcap_rec_t r = {0};

	/* Data of the last record truncated */
	w.len = full - 10;
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	off = PCAP_FILE_HDR_LEN;
	CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_OK);
	CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_TRUNCATED);

	/* Record header truncated */
	w.len = PCAP_FILE_HDR_LEN + 16 + 60 + 7;
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	off = PCAP_FILE_HDR_LEN;
	CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_OK);
	CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_TRUNCATED);

	/* File header truncated */
	w.len = 10;
	CHECK(open_mem(&pf, &w, err) < 0);

	/* Insane caplen */
	file_hdr(&w, 0, 0, 1);
	put32(&w, 1);
	put32(&w, 0);
	put32(&w, 0x7fffffff);
	put32(&w, 0x7fffffff);
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	off = PCAP_FILE_HDR_LEN;
	CHECK_EQ(pcap_next(&pf, &off, &r), PCAP_REC_CORRUPT);
}

static void bad_headers(void)
{
	wbuf_t w;
	pcap_file_t pf;
	char err[256];
	/* pcapng */
	w.len = 0;
	w.be = 0;
	put32(&w, 0x0a0d0d0a);
	put32(&w, 28);
	put32(&w, 0x1a2b3c4d);
	for (int i = 0; i < 4; i++)
		put32(&w, 0);
	CHECK(open_mem(&pf, &w, err) < 0);
	CHECK(strstr(err, "editcap -F pcap") != NULL);
	/* unknown magic */
	w.len = 0;
	put32(&w, 0xdeadbeef);
	for (int i = 0; i < 5; i++)
		put32(&w, 0);
	CHECK(open_mem(&pf, &w, err) < 0);
	/* unsupported linktype */
	file_hdr(&w, 0, 0, 105);
	CHECK(open_mem(&pf, &w, err) < 0);
	/* RAW and FCS bits in linktype */
	file_hdr(&w, 0, 0, 101);
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	CHECK_EQ(pf.raw_ip, 1);
	file_hdr(&w, 0, 0, 228);
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	CHECK_EQ(pf.raw_ip, 4);
	file_hdr(&w, 0, 0, 0x10000001u);
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	CHECK_EQ(pf.linktype, 1);
}

static void index_build(void)
{
	wbuf_t w;
	file_hdr(&w, 0, 0, 1);
	rec(&w, 1700000000, 0, 60, 60);
	rec(&w, 1700000000, 10, 2000, 2000); /* larger than MTU */
	rec(&w, 1700000000, 20, 10, 10);     /* shorter than Ethernet */
	rec(&w, 1700000000, 30, 64, 9000);   /* truncated at capture */
	pcap_file_t pf;
	char err[256];
	CHECK_EQ(open_mem(&pf, &w, err), 0);
	idx_cfg_t cfg = {.ip_shards = 4, .max_frame = 1514, .hash_threads = 2};
	pkt_index_t ix;
	CHECK_EQ(afr_index_build(&pf, &cfg, &ix, err, sizeof(err)), 0);
	CHECK_EQ(afr_index_resolve(&ix, pf.raw_ip, &cfg, err, sizeof(err)), 0);
	CHECK_EQ(ix.n, 4);
	CHECK_EQ(ix.st.skipped[SKIP_TOO_BIG], 1);
	CHECK_EQ(ix.st.skipped[SKIP_TOO_SMALL], 1);
	CHECK_EQ(ix.st.truncated_caplen, 1);
	CHECK_EQ(ix.shard[0], 4); /* non-IP shard */
	CHECK_EQ(ix.shard[1], SHARD_SKIP);
	CHECK_EQ(ix.shard[2], SHARD_SKIP);
	CHECK_EQ(OFFLEN_LEN(ix.offlen[3]), 64);
	CHECK_EQ(ix.ts[1], 1700000000LL * NS_PER_SEC + 10000);
	/* The same index resolves for another MTU without rebuilding. */
	idx_cfg_t jumbo = {.ip_shards = 4, .max_frame = 9014, .hash_threads = 2};
	CHECK_EQ(afr_index_resolve(&ix, pf.raw_ip, &jumbo, err, sizeof(err)), 0);
	CHECK_EQ(ix.st.skipped[SKIP_TOO_BIG], 0);
	CHECK(ix.shard[1] != SHARD_SKIP);
	CHECK_EQ(ix.st.max_frame, 2000);
	afr_index_free(&ix);
}

/* Write a pcap with many flows to a real file (the cache checks inode and mtime). */
static void write_flows_pcap(const char *path, int npkts, uint32_t salt)
{
	FILE *f = fopen(path, "wb");
	uint32_t hdr[6] = {0xa1b2c3d4u, 0x00040002u, 0, 0, 65535, 1};
	fwrite(hdr, 4, 6, f);
	for (int i = 0; i < npkts; i++) {
		uint8_t fr[80] = {0};
		for (int k = 0; k < 12; k++)
			fr[k] = (uint8_t)(k + 1);
		fr[12] = 0x08; /* IPv4 */
		fr[14] = 0x45;
		fr[23] = 17;
		uint32_t src = 0x0a000000u + (uint32_t)i % 97 + salt, dst = 0xc0a80001u;
		for (int k = 0; k < 4; k++) {
			fr[26 + k] = (uint8_t)(src >> (24 - 8 * k));
			fr[30 + k] = (uint8_t)(dst >> (24 - 8 * k));
		}
		fr[34] = (uint8_t)(i >> 8);
		fr[35] = (uint8_t)i;
		uint32_t len = (i % 5 == 0) ? 60 : 80;
		uint32_t rh[4] = {1700000000u + (uint32_t)i / 1000, (uint32_t)(i % 1000) * 1000, len, len};
		fwrite(rh, 4, 4, f);
		fwrite(fr, 1, len, f);
	}
	fclose(f);
}

static void index_cache(void)
{
	char pcap[] = "/tmp/afr_test_XXXXXX";
	int fd = mkstemp(pcap);
	close(fd);
	char cache[64];
	snprintf(cache, sizeof(cache), "%s.rsidx", pcap);
	unlink(cache);
	write_flows_pcap(pcap, 5000, 0);

	pcap_file_t pf;
	char err[256], why[256];
	CHECK_EQ(pcap_open(&pf, pcap, 0, err, sizeof(err)), 0);
	idx_cfg_t cfg = {.ip_shards = 3, .max_frame = 1514, .hash_threads = 2};
	pkt_index_t a, b;
	CHECK_EQ(afr_idxcache_load(cache, &pf, &b, why, sizeof(why)), 0); /* no file yet */
	CHECK_EQ(afr_index_build(&pf, &cfg, &a, err, sizeof(err)), 0);
	CHECK_EQ(afr_idxcache_save(cache, &pf, &a, err, sizeof(err)), 0);
	CHECK_EQ(afr_idxcache_load(cache, &pf, &b, why, sizeof(why)), 1);
	CHECK_EQ(b.n, a.n);
	CHECK(memcmp(a.offlen, b.offlen, a.n * 8) == 0);
	CHECK(memcmp(a.ts, b.ts, a.n * 8) == 0);
	CHECK(memcmp(a.h32, b.h32, a.n * 4) == 0);
	CHECK(memcmp(a.flags, b.flags, a.n) == 0);
	CHECK_EQ(b.st.ipv4, a.st.ipv4);
	/* Resolving the cached index gives the same shards, also for another -t */
	CHECK_EQ(afr_index_resolve(&a, 0, &cfg, err, sizeof(err)), 0);
	CHECK_EQ(afr_index_resolve(&b, 0, &cfg, err, sizeof(err)), 0);
	CHECK(memcmp(a.shard, b.shard, a.n * 2) == 0);
	for (unsigned k = 0; k < a.nshards; k++)
		CHECK_EQ(a.shard_pkts[k], b.shard_pkts[k]);
	idx_cfg_t cfg7 = {.ip_shards = 7, .max_frame = 1514, .hash_threads = 3};
	CHECK_EQ(afr_index_resolve(&b, 0, &cfg7, err, sizeof(err)), 0);
	uint64_t total = 0;
	for (unsigned k = 0; k < b.nshards; k++)
		total += b.shard_pkts[k];
	CHECK_EQ(total, 5000);
	/* Writing to the cached timestamps does not change the cache file */
	b.ts[0] = 12345;
	afr_index_free(&b);
	CHECK_EQ(afr_idxcache_load(cache, &pf, &b, why, sizeof(why)), 1);
	CHECK_EQ(b.ts[0], a.ts[0]);
	afr_index_free(&b);
	afr_index_free(&a);
	pcap_close(&pf);

	/* The pcap is rewritten with other content: the cache must be rejected */
	write_flows_pcap(pcap, 5000, 1000);
	CHECK_EQ(pcap_open(&pf, pcap, 0, err, sizeof(err)), 0);
	CHECK_EQ(afr_idxcache_load(cache, &pf, &b, why, sizeof(why)), 0);
	CHECK(strstr(why, "changed") != NULL);
	pcap_close(&pf);
	/* A damaged cache file is rejected */
	CHECK_EQ(truncate(cache, 4096 + 100), 0);
	CHECK_EQ(pcap_open(&pf, pcap, 0, err, sizeof(err)), 0);
	CHECK_EQ(afr_idxcache_load(cache, &pf, &b, why, sizeof(why)), 0);
	pcap_close(&pf);
	unlink(cache);
	unlink(pcap);
}

void test_pcap(void)
{
	formats();
	truncated();
	bad_headers();
	index_build();
	index_cache();
}
