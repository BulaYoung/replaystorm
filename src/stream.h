/*
 * Streaming read of the pcap during replay: a background thread keeps a sliding
 * window of the file in the page cache ahead of the sender threads (readahead) and,
 * for files larger than RAM, drops what all threads have already sent (drop-behind).
 * Without it a file much larger than RAM would thrash the page cache, evict the index
 * and stall sender threads on disk reads inside the hot loop.
 */
#ifndef AFR_STREAM_H
#define AFR_STREAM_H

#include "worker.h"

typedef struct {
	const pcap_file_t *pf;
	worker_t **ws;
	unsigned nw;
	uint64_t window;     /* bytes to keep requested ahead of the fastest thread */
	int drop_behind;     /* drop pages behind the slowest thread */
	pthread_t th;
	atomic_int stop;
	int running;
	/* positions are "global": lap * file_size + offset */
	uint64_t ra_upto;    /* readahead requested up to here */
	uint64_t drop_upto;  /* dropped from the cache below here */
	uint64_t pop_upto;   /* pages mapped (MADV_POPULATE_READ) up to here */
	int populate;        /* STREAM_POP_*: how pages are pre-mapped */
	_Atomic uint64_t ra_bytes, dropped_bytes;
} streamer_t;

/* Margin kept behind the slowest thread before dropping (covers small reordering). */
#define STREAM_DROP_MARGIN (256ull << 20)
#define STREAM_CHUNK (64ull << 20)
/* One readahead request (the kernel caps each at the device readahead size anyway). */
#define STREAM_RA_PIECE (1ull << 20)

enum { STREAM_POP_OFF = 0, STREAM_POP_MADVISE, STREAM_POP_TOUCH };
/* How far ahead of the fastest thread pages are pre-mapped into the process. */
#define STREAM_POPULATE_AHEAD (512ull << 20)

int afr_stream_start(streamer_t *s);
void afr_stream_stop(streamer_t *s);

#endif
