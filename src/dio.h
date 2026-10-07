/*
 * Direct I/O streaming of the pcap: reader threads read the file with O_DIRECT in
 * large chunks into a ring of buffers in RAM (the window), bypassing the page cache.
 * Sender threads take packet data from the window and never touch the disk or take
 * page faults. A slot is reused only when every sender thread has moved past it.
 *
 * Chunks are numbered globally across laps: q = lap * nchunks + offset / chunk_size.
 * Each slot holds its chunk plus a tail of the next one, so a packet whose data starts
 * inside a chunk is always contiguous in its slot.
 */
#ifndef AFR_DIO_H
#define AFR_DIO_H

#include "afr.h"

#include <pthread.h>
#include <stdatomic.h>

#define DIO_CHUNK_SHIFT 25                 /* 32 MB chunks */
#define DIO_CHUNK (1ull << DIO_CHUNK_SHIFT)
#define DIO_TAIL (128u * 1024u)            /* > largest packet (64 KB) */
#define DIO_ALIGN 4096u                    /* O_DIRECT offset/size/buffer alignment */
#define DIO_MAX_READERS 32

struct worker;

typedef struct AFR_ALIGNED {
	_Atomic uint64_t loaded; /* q + 1 of the chunk in the slot, 0 if none */
	uint8_t *buf;
} dio_slot_t;

typedef struct {
	int fd;
	uint64_t file_size;
	uint64_t nchunks;     /* chunks per lap */
	uint64_t end_q;       /* stop after this chunk number (UINT64_MAX: loop forever) */
	unsigned nslots;
	dio_slot_t *slots;
	uint8_t *mem;
	size_t mem_len;
	size_t slot_len;
	/* readers */
	unsigned nreaders;
	pthread_t th[DIO_MAX_READERS];
	int started[DIO_MAX_READERS];
	_Atomic uint64_t next_q;
	atomic_int stop;
	atomic_int failed;
	char err[256];
	/* sender threads, for the slowest position */
	struct worker **ws;
	unsigned nw;
	/* statistics */
	_Atomic uint64_t bytes_read, chunks_loaded, reader_waits;
	_Atomic uint64_t reads, read_ns; /* chunk reads and their total duration */
	/* read rate limit from the thermal governor (bytes/s, 0 = none) */
	_Atomic uint64_t rate_limit;
	_Atomic int64_t next_ns; /* earliest start of the next read under the limit */
	int locked;              /* the window is locked in RAM */
} dio_t;

/* Open the file with O_DIRECT and allocate the window. Returns -1 with a reason if
 * direct I/O cannot be used (the caller falls back to mmap). */
int afr_dio_open(dio_t *d, const char *path, uint64_t file_size, uint64_t window,
                 unsigned readers, uint64_t loops, char *err, size_t errlen);
/* Start the reader threads. ws/nw: sender threads (their next-read positions). */
int afr_dio_start(dio_t *d, struct worker **ws, unsigned nw);
/* Wait until the window is filled (or the whole file is read); returns seconds taken. */
double afr_dio_prefill(dio_t *d, double timeout_s);
void afr_dio_stop(dio_t *d);
void afr_dio_close(dio_t *d);

/* Slot of chunk q, or NULL if it is not loaded (yet). */
static inline const uint8_t *afr_dio_chunk(dio_t *d, uint64_t q)
{
	dio_slot_t *s = &d->slots[q % d->nslots];
	if (atomic_load_explicit(&s->loaded, memory_order_acquire) == q + 1)
		return s->buf;
	return NULL;
}

#endif
