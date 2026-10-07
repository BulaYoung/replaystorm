#include "idxcache.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define IDXC_MAGIC "AFRIDX\r\n"
/* Bump whenever the classification, hashing or the layout below changes. */
#define IDXC_VERSION 1u
#define IDXC_HDR_SIZE 4096u
#define IDXC_ALIGN 4096u
#define IDXC_SAMPLE (64u * 1024u)

typedef struct {
	char magic[8];
	uint32_t version;
	uint32_t hdr_size;
	uint32_t stats_size; /* sizeof(idx_stats_t), guards against layout changes */
	uint32_t linktype;
	int32_t raw_ip;
	int32_t tail_problem;
	/* identity of the pcap */
	uint64_t pcap_size;
	uint64_t pcap_ino;
	uint64_t pcap_dev;
	int64_t pcap_mtime_ns;
	uint64_t pcap_sample;
	/* index */
	uint64_t n;
	uint64_t tail_off;
	uint64_t off_offlen, off_ts, off_h32, off_flags;
	uint64_t file_size;
	idx_stats_t st;
} idxc_hdr_t;

_Static_assert(sizeof(idxc_hdr_t) <= IDXC_HDR_SIZE, "cache header does not fit");

static uint64_t mix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 29;
	h *= 0xbf58476d1ce4e5b9ULL;
	return h ^ (h >> 32);
}

/* Hash of the first and last 64 KB of the pcap: catches a file replaced in place. */
static uint64_t pcap_sample(const pcap_file_t *pf)
{
	uint64_t h = pf->size;
	size_t n = pf->size < IDXC_SAMPLE ? pf->size : IDXC_SAMPLE;
	for (size_t i = 0; i + 8 <= n; i += 8) {
		uint64_t v;
		memcpy(&v, pf->base + i, 8);
		h = mix(h, v);
	}
	for (size_t i = pf->size - n; i + 8 <= pf->size; i += 8) {
		uint64_t v;
		memcpy(&v, pf->base + i, 8);
		h = mix(h, v);
	}
	return h;
}

static int pcap_identity(const pcap_file_t *pf, idxc_hdr_t *h)
{
	struct stat st;
	if (fstat(pf->fd, &st) < 0)
		return -1;
	h->pcap_size = (uint64_t)st.st_size;
	h->pcap_ino = (uint64_t)st.st_ino;
	h->pcap_dev = (uint64_t)st.st_dev;
	h->pcap_mtime_ns = (int64_t)st.st_mtim.tv_sec * NS_PER_SEC + st.st_mtim.tv_nsec;
	h->pcap_sample = pcap_sample(pf);
	h->linktype = pf->linktype;
	h->raw_ip = pf->raw_ip;
	return 0;
}

static uint64_t align_up(uint64_t v)
{
	return (v + IDXC_ALIGN - 1) / IDXC_ALIGN * IDXC_ALIGN;
}

static void layout(idxc_hdr_t *h, uint64_t n)
{
	h->off_offlen = IDXC_HDR_SIZE;
	h->off_ts = align_up(h->off_offlen + n * sizeof(uint64_t));
	h->off_h32 = align_up(h->off_ts + n * sizeof(int64_t));
	h->off_flags = align_up(h->off_h32 + n * sizeof(uint32_t));
	h->file_size = align_up(h->off_flags + n);
}

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len) {
		size_t chunk = len > (64u << 20) ? (64u << 20) : len;
		ssize_t w = write(fd, p, chunk);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += w;
		len -= (size_t)w;
	}
	return 0;
}

static int write_at(int fd, uint64_t off, const void *buf, size_t len)
{
	if (lseek(fd, (off_t)off, SEEK_SET) < 0)
		return -1;
	return write_all(fd, buf, len);
}

int afr_idxcache_save(const char *path, const pcap_file_t *pf, const pkt_index_t *ix, char *err,
                      size_t errlen)
{
	idxc_hdr_t h;
	memset(&h, 0, sizeof(h));
	memcpy(h.magic, IDXC_MAGIC, 8);
	h.version = IDXC_VERSION;
	h.hdr_size = IDXC_HDR_SIZE;
	h.stats_size = sizeof(idx_stats_t);
	h.tail_problem = ix->tail_problem;
	h.tail_off = ix->tail_off;
	h.n = ix->n;
	h.st = ix->st;
	if (pcap_identity(pf, &h) < 0) {
		snprintf(err, errlen, "fstat of the pcap: %s", strerror(errno));
		return -1;
	}
	layout(&h, ix->n);

	size_t plen = strlen(path);
	char *tmp = malloc(plen + 16);
	if (!tmp) {
		snprintf(err, errlen, "out of memory");
		return -1;
	}
	snprintf(tmp, plen + 16, "%s.tmp%d", path, (int)getpid());
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		snprintf(err, errlen, "cannot create %s: %s", tmp, strerror(errno));
		free(tmp);
		return -1;
	}
	uint8_t hdr[IDXC_HDR_SIZE];
	memset(hdr, 0, sizeof(hdr));
	memcpy(hdr, &h, sizeof(h));
	int bad = ftruncate(fd, (off_t)h.file_size) < 0 ||
	          write_at(fd, 0, hdr, sizeof(hdr)) < 0 ||
	          write_at(fd, h.off_offlen, ix->offlen, ix->n * sizeof(uint64_t)) < 0 ||
	          write_at(fd, h.off_ts, ix->ts, ix->n * sizeof(int64_t)) < 0 ||
	          write_at(fd, h.off_h32, ix->h32, ix->n * sizeof(uint32_t)) < 0 ||
	          write_at(fd, h.off_flags, ix->flags, ix->n) < 0;
	int e = errno;
	if (close(fd) < 0 && !bad) {
		bad = 1;
		e = errno;
	}
	if (!bad && rename(tmp, path) < 0) {
		bad = 1;
		e = errno;
	}
	if (bad) {
		snprintf(err, errlen, "writing %s: %s", path, strerror(e));
		unlink(tmp);
	}
	free(tmp);
	return bad ? -1 : 0;
}

int afr_idxcache_load(const char *path, const pcap_file_t *pf, pkt_index_t *ix, char *why,
                      size_t whylen)
{
	why[0] = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(why, whylen, "%s", errno == ENOENT ? "no cache file yet" : strerror(errno));
		return 0;
	}
	struct stat st;
	idxc_hdr_t h;
	if (fstat(fd, &st) < 0 || pread(fd, &h, sizeof(h), 0) != (ssize_t)sizeof(h)) {
		snprintf(why, whylen, "cannot read the cache header");
		close(fd);
		return 0;
	}
	if (memcmp(h.magic, IDXC_MAGIC, 8) != 0 || h.hdr_size != IDXC_HDR_SIZE) {
		snprintf(why, whylen, "not an replaystorm index cache");
		close(fd);
		return 0;
	}
	if (h.version != IDXC_VERSION || h.stats_size != sizeof(idx_stats_t)) {
		snprintf(why, whylen, "cache was written by another replaystorm version");
		close(fd);
		return 0;
	}
	idxc_hdr_t cur;
	memset(&cur, 0, sizeof(cur));
	if (pcap_identity(pf, &cur) < 0) {
		snprintf(why, whylen, "fstat of the pcap failed");
		close(fd);
		return 0;
	}
	if (cur.pcap_size != h.pcap_size || cur.pcap_mtime_ns != h.pcap_mtime_ns ||
	    cur.pcap_ino != h.pcap_ino || cur.pcap_dev != h.pcap_dev ||
	    cur.pcap_sample != h.pcap_sample || cur.linktype != h.linktype ||
	    cur.raw_ip != h.raw_ip) {
		snprintf(why, whylen, "cache belongs to another file or the pcap has changed");
		close(fd);
		return 0;
	}
	idxc_hdr_t chk = h;
	layout(&chk, h.n);
	if (chk.off_ts != h.off_ts || chk.off_h32 != h.off_h32 || chk.off_flags != h.off_flags ||
	    chk.file_size != h.file_size || (uint64_t)st.st_size != h.file_size) {
		snprintf(why, whylen, "cache file is truncated or damaged");
		close(fd);
		return 0;
	}
	/* Private writable mapping: timestamps are normalized in place, which copies only
	 * those pages; the cache file itself never changes. */
	void *map = mmap(NULL, h.file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		snprintf(why, whylen, "mmap of the cache: %s", strerror(errno));
		return -1;
	}
	madvise(map, h.file_size, MADV_WILLNEED);
	memset(ix, 0, sizeof(*ix));
	ix->mem = IDX_MEM_CACHE;
	ix->cache_map = map;
	ix->cache_len = h.file_size;
	ix->n = h.n;
	ix->cap = h.n;
	ix->offlen = (uint64_t *)((uint8_t *)map + h.off_offlen);
	ix->ts = (int64_t *)((uint8_t *)map + h.off_ts);
	ix->h32 = (uint32_t *)((uint8_t *)map + h.off_h32);
	ix->flags = (uint8_t *)map + h.off_flags;
	ix->st = h.st;
	ix->tail_problem = h.tail_problem;
	ix->tail_off = h.tail_off;
	return 1;
}
