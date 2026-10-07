/*
 * Sender thread: its own AF_PACKET socket with TX_RING and its own packet shard.
 */
#ifndef AFR_WORKER_H
#define AFR_WORKER_H

#include "dio.h"
#include "mutate.h"
#include "replay.h"

#include <pthread.h>
#include <stdatomic.h>

/* What a sender thread is doing right now (for the watchdog and the wait statistics). */
enum {
	W_RUN = 0, /* sending */
	W_PACE,    /* waiting for the schedule: normal */
	W_RING,    /* TX ring full: waiting for the NIC to complete transmissions */
	W_QUEUE,   /* device queue full (ENOBUFS/EAGAIN) */
	W_DISK,    /* data not yet read from the disk (direct I/O) */
	W_FENCE,   /* too far ahead of the slowest thread */
	W_LINK,    /* interface down or being re-created */
	W_COUNT
};
extern const char *const afr_wstate_names[W_COUNT];

/* Shared run state. */
typedef struct {
	pthread_barrier_t bar;
	_Atomic int64_t t0;     /* common CLOCK_MONOTONIC reference point */
	_Atomic int64_t shift;  /* T0 shift for --lag-policy=rebase */
	_Atomic int64_t pause;  /* T0 shift for link outages (all modes) */
	_Atomic int64_t down_since; /* start of the current link outage, 0 if the link is up */
	atomic_int failed;
} shared_t;

extern atomic_int g_stop;

/* Thread counters: written only by the thread itself, read by the stats thread. */
typedef struct AFR_ALIGNED {
	_Atomic uint64_t pkts, bytes;
	_Atomic uint64_t sends, enobufs, eagain;
	_Atomic uint64_t asis_back;  /* packets "backward in time" under asis */
	_Atomic uint64_t rebases;
	_Atomic uint64_t fence_waits; /* times the thread waited for the slowest one */
	_Atomic uint64_t dio_waits;   /* times the thread waited for data from the disk */
	_Atomic int64_t late_max;
	_Atomic int64_t pos;         /* position on the timeline (lap*length + ts) */
	_Atomic uint64_t lap;
	_Atomic uint64_t gpos;       /* lap * file_size + file offset of the last packet */
	_Atomic int64_t t_end;       /* when the thread finished sending */
	atomic_int state;            /* W_* */
	_Atomic uint64_t wait_ns[W_COUNT];
	_Atomic uint64_t link_lost;  /* frames lost when the interface was re-created */
	atomic_int finished;
} wstats_t;

typedef struct {
	int fd;
	uint8_t *ring;
	size_t ring_size;
	unsigned frame_size, frame_nr;
	unsigned data_off;
} tx_ring_t;

typedef struct worker {
	/* settings */
	unsigned id;
	int cpu;
	int is_l2;
	const afr_ctx_t *c;
	shared_t *sh;
	mutate_cfg_t mut;
	int mutate;
	struct worker **peers;   /* all sender threads (NULL: no position fence) */
	unsigned npeers;
	uint64_t fence_lead;     /* how far ahead of the slowest thread this one may read */
	uint64_t fence_min;      /* last computed slowest position */
	dio_t *dio;              /* direct I/O window (NULL: data from the mmap) */
	uint64_t dio_q;          /* chunk of the last packet and its buffer */
	const uint8_t *dio_buf;
	/* data */
	pkt_t *pk;
	size_t n;
	tx_ring_t tx;
	pthread_t th;
	char err[256];
	int mlock_failed;
	/* hot state (thread only) */
	unsigned head, pending;
	int64_t now; /* last clock reading */
	int wstate;  /* W_* (thread-local copy) */
	unsigned ring_len; /* max frame length the ring was sized for */
	uint64_t l_pkts, l_bytes, l_sends, l_enobufs, l_eagain;
	/* published */
	wstats_t st;
	_Atomic uint64_t hist[LH_BUCKETS] AFR_ALIGNED; /* lateness, ns */
} worker_t;

void *afr_worker_main(void *arg);

/* Link outage bookkeeping shared by the sender threads and the stats thread: whoever
 * first sees the link come back shifts the schedule by the outage, exactly once. */
static inline void afr_link_down(shared_t *sh, int64_t now)
{
	int64_t zero = 0;
	atomic_compare_exchange_strong(&sh->down_since, &zero, now);
}

static inline void afr_link_up(shared_t *sh, int64_t now)
{
	int64_t v = atomic_load(&sh->down_since);
	if (v && atomic_compare_exchange_strong(&sh->down_since, &v, 0))
		atomic_fetch_add(&sh->pause, now - v);
}

#endif
