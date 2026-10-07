#include "dio.h"

#include "worker.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define RLX memory_order_relaxed

int afr_dio_open(dio_t *d, const char *path, uint64_t file_size, uint64_t window,
                 unsigned readers, uint64_t loops, char *err, size_t errlen)
{
	memset(d, 0, sizeof(*d));
	d->fd = open(path, O_RDONLY | O_DIRECT | O_CLOEXEC);
	if (d->fd < 0) {
		snprintf(err, errlen, "O_DIRECT open: %s", strerror(errno));
		return -1;
	}
	d->file_size = file_size;
	d->nchunks = (file_size + DIO_CHUNK - 1) / DIO_CHUNK;
	d->end_q = loops ? loops * d->nchunks : UINT64_MAX;
	uint64_t ns = window / DIO_CHUNK;
	if (ns < 4)
		ns = 4;
	/* No point in a window larger than the whole replay. */
	if (loops && ns > d->end_q)
		ns = d->end_q;
	d->nslots = (unsigned)ns;
	d->slot_len = DIO_CHUNK + DIO_TAIL;
	d->mem_len = (size_t)d->nslots * d->slot_len;
	d->mem = mmap(NULL, d->mem_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	d->slots = aligned_alloc(AFR_CACHELINE, d->nslots * sizeof(dio_slot_t));
	if (d->mem == MAP_FAILED || !d->slots) {
		snprintf(err, errlen, "cannot allocate a %.1f GB direct I/O window",
		         (double)d->mem_len / 1e9);
		if (d->mem != MAP_FAILED)
			munmap(d->mem, d->mem_len);
		free(d->slots);
		close(d->fd);
		d->mem = NULL;
		d->slots = NULL;
		return -1;
	}
	for (unsigned i = 0; i < d->nslots; i++) {
		atomic_store(&d->slots[i].loaded, 0);
		d->slots[i].buf = d->mem + (size_t)i * d->slot_len;
	}
	d->nreaders = readers < 1 ? 1 : (readers > DIO_MAX_READERS ? DIO_MAX_READERS : readers);

	/* Probe: one aligned direct read, so that an unsupported filesystem is caught here
	 * (and the caller can fall back) rather than inside the reader threads. */
	ssize_t r = pread(d->fd, d->slots[0].buf, DIO_ALIGN, 0);
	if (r < 0) {
		snprintf(err, errlen, "O_DIRECT read: %s", strerror(errno));
		afr_dio_close(d);
		return -1;
	}
	return 0;
}

/* Slowest next-read chunk of the sender threads (UINT64_MAX if all finished). */
static uint64_t slowest_chunk(const dio_t *d)
{
	uint64_t mn = UINT64_MAX;
	for (unsigned i = 0; i < d->nw; i++) {
		const worker_t *w = d->ws[i];
		if (atomic_load_explicit(&w->st.finished, RLX))
			continue;
		uint64_t g = atomic_load_explicit(&w->st.gpos, RLX);
		uint64_t q = (g / d->file_size) * d->nchunks + (g % d->file_size) / DIO_CHUNK;
		if (q < mn)
			mn = q;
	}
	return mn;
}

static int read_chunk(dio_t *d, uint64_t q, uint8_t *buf)
{
	uint64_t off = (q % d->nchunks) * DIO_CHUNK;
	size_t want = d->slot_len;
	if (off + want > d->file_size)
		want = (size_t)(d->file_size - off + DIO_ALIGN - 1) / DIO_ALIGN * DIO_ALIGN;
	size_t got = 0;
	const int64_t t0 = afr_now_ns();
	while (got < want) {
		ssize_t r = pread(d->fd, buf + got, want - got, (off_t)(off + got));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			snprintf(d->err, sizeof(d->err), "direct read at offset %llu: %s",
			         (unsigned long long)(off + got), strerror(errno));
			return -1;
		}
		if (r == 0)
			break; /* end of file */
		got += (size_t)r;
		if (got % DIO_ALIGN)
			break; /* short read at the end of the file */
	}
	atomic_fetch_add_explicit(&d->bytes_read, got, RLX);
	atomic_fetch_add_explicit(&d->read_ns, (uint64_t)(afr_now_ns() - t0), RLX);
	atomic_fetch_add_explicit(&d->reads, 1, RLX);
	return 0;
}

static void *reader_main(void *arg)
{
	dio_t *d = arg;
	while (!atomic_load(&d->stop)) {
		uint64_t q = atomic_fetch_add(&d->next_q, 1);
		if (q >= d->end_q)
			return NULL;
		/* The slot may hold chunk q - nslots, which some sender may still need. */
		int waited = 0;
		for (;;) {
			if (atomic_load(&d->stop))
				return NULL;
			uint64_t mn = slowest_chunk(d);
			if (mn == UINT64_MAX && d->nw)
				return NULL; /* every sender has finished */
			if (q < mn + d->nslots)
				break;
			if (!waited) {
				waited = 1;
				atomic_fetch_add_explicit(&d->reader_waits, 1, RLX);
			}
			struct timespec ts = {0, 200000};
			nanosleep(&ts, NULL);
		}
		dio_slot_t *s = &d->slots[q % d->nslots];
		atomic_store_explicit(&s->loaded, 0, memory_order_release);
		if (read_chunk(d, q, s->buf) < 0) {
			atomic_store(&d->failed, 1);
			atomic_store(&g_stop, 1);
			return NULL;
		}
		atomic_store_explicit(&s->loaded, q + 1, memory_order_release);
		atomic_fetch_add_explicit(&d->chunks_loaded, 1, RLX);
	}
	return NULL;
}

int afr_dio_start(dio_t *d, struct worker **ws, unsigned nw)
{
	d->ws = ws;
	d->nw = nw;
	atomic_store(&d->next_q, 0);
	atomic_store(&d->stop, 0);
	unsigned ok = 0;
	for (unsigned i = 0; i < d->nreaders; i++) {
		d->started[i] = pthread_create(&d->th[i], NULL, reader_main, d) == 0;
		if (d->started[i]) {
			pthread_setname_np(d->th[i], "afr-dio");
			ok++;
		}
	}
	return ok ? 0 : -1;
}

double afr_dio_prefill(dio_t *d, double timeout_s)
{
	uint64_t want = d->nslots < d->end_q ? d->nslots : d->end_q;
	int64_t t0 = afr_now_ns();
	while (atomic_load(&d->chunks_loaded) < want && !atomic_load(&d->failed) &&
	       !atomic_load(&g_stop)) {
		if ((double)(afr_now_ns() - t0) / 1e9 > timeout_s)
			break;
		struct timespec ts = {0, 5 * 1000 * 1000};
		nanosleep(&ts, NULL);
	}
	return (double)(afr_now_ns() - t0) / 1e9;
}

void afr_dio_stop(dio_t *d)
{
	atomic_store(&d->stop, 1);
	for (unsigned i = 0; i < d->nreaders; i++) {
		if (d->started[i])
			pthread_join(d->th[i], NULL);
		d->started[i] = 0;
	}
}

void afr_dio_close(dio_t *d)
{
	if (d->mem)
		munmap(d->mem, d->mem_len);
	free(d->slots);
	if (d->fd >= 0)
		close(d->fd);
	d->mem = NULL;
	d->slots = NULL;
	d->fd = -1;
}
