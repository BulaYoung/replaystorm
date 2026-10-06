#include "stream.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#define RLX memory_order_relaxed

typedef void (*range_fn)(streamer_t *s, uint64_t off, uint64_t len);

static void do_willneed(streamer_t *s, uint64_t off, uint64_t len)
{
	madvise((void *)(s->pf->base + off), len, MADV_WILLNEED);
	atomic_fetch_add_explicit(&s->ra_bytes, len, RLX);
}

#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22 /* Linux 5.14+ */
#endif

/* Map the pages into our page tables ahead of the senders, so they take no page
 * faults (and never wait for the disk) in the hot loop. Blocks this thread, not them. */
static void do_populate(streamer_t *s, uint64_t off, uint64_t len)
{
	if (s->populate && madvise((void *)(s->pf->base + off), len, MADV_POPULATE_READ) != 0 &&
	    (errno == EINVAL || errno == ENOSYS))
		s->populate = 0; /* old kernel: readahead only */
}

static void do_drop(streamer_t *s, uint64_t off, uint64_t len)
{
	/* Unmap our PTEs first (read-only private mapping, nothing to write back), then
	 * drop the now unmapped clean pages from the page cache. */
	madvise((void *)(s->pf->base + off), len, MADV_DONTNEED);
	posix_fadvise(s->pf->fd, (off_t)off, (off_t)len, POSIX_FADV_DONTNEED);
	atomic_fetch_add_explicit(&s->dropped_bytes, len, RLX);
}

/* Apply fn to the global range [g0, g1), split at lap boundaries and page aligned. */
static void apply(streamer_t *s, uint64_t g0, uint64_t g1, range_fn fn)
{
	const uint64_t size = s->pf->size;
	const uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE);
	while (g0 < g1 && !atomic_load_explicit(&s->stop, RLX)) {
		uint64_t off = g0 % size;
		uint64_t len = g1 - g0;
		if (len > size - off)
			len = size - off;
		if (len > STREAM_CHUNK)
			len = STREAM_CHUNK;
		uint64_t a = off & ~(page - 1);
		uint64_t e = off + len;
		if (e > size)
			e = size;
		fn(s, a, e - a);
		g0 += len;
	}
}

static void *stream_main(void *arg)
{
	streamer_t *s = arg;
	while (!atomic_load(&s->stop)) {
		uint64_t mn = UINT64_MAX, mx = 0;
		unsigned active = 0;
		for (unsigned i = 0; i < s->nw; i++) {
			if (atomic_load_explicit(&s->ws[i]->st.finished, RLX))
				continue;
			uint64_t g = atomic_load_explicit(&s->ws[i]->st.gpos, RLX);
			active++;
			if (g < mn)
				mn = g;
			if (g > mx)
				mx = g;
		}
		if (active) {
			/* Readahead: keep [slowest, fastest + window) requested. */
			uint64_t target = mx + s->window;
			uint64_t from = s->ra_upto > mn ? s->ra_upto : mn;
			if (from < target) {
				apply(s, from, target, do_willneed);
				s->ra_upto = target;
			}
			/* Pre-map the nearest part of the window. */
			if (s->populate) {
				uint64_t ahead = s->window < STREAM_POPULATE_AHEAD ? s->window : STREAM_POPULATE_AHEAD;
				uint64_t pfrom = s->pop_upto > mn ? s->pop_upto : mn;
				if (pfrom < mx + ahead) {
					apply(s, pfrom, mx + ahead, do_populate);
					s->pop_upto = mx + ahead;
				}
			}
			/* Drop-behind: everything the slowest thread has passed, minus a margin. */
			if (s->drop_behind && mn > STREAM_DROP_MARGIN) {
				uint64_t end = mn - STREAM_DROP_MARGIN;
				if (end > s->drop_upto + STREAM_CHUNK) {
					apply(s, s->drop_upto, end, do_drop);
					s->drop_upto = end;
				}
			}
		}
		struct timespec ts = {0, 20 * 1000 * 1000};
		nanosleep(&ts, NULL);
	}
	return NULL;
}

int afr_stream_start(streamer_t *s)
{
	atomic_store(&s->stop, 0);
	s->ra_upto = s->drop_upto = s->pop_upto = 0;
	s->populate = 1;
	s->running = pthread_create(&s->th, NULL, stream_main, s) == 0;
	if (s->running)
		pthread_setname_np(s->th, "afr-stream");
	return s->running ? 0 : -1;
}

void afr_stream_stop(streamer_t *s)
{
	if (!s->running)
		return;
	atomic_store(&s->stop, 1);
	pthread_join(s->th, NULL);
	s->running = 0;
}
