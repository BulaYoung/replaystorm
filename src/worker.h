/*
 * Sender thread: its own AF_PACKET socket with TX_RING and its own packet shard.
 */
#ifndef AFR_WORKER_H
#define AFR_WORKER_H

#include "mutate.h"
#include "replay.h"

#include <pthread.h>
#include <stdatomic.h>

/* Shared run state. */
typedef struct {
	pthread_barrier_t bar;
	_Atomic int64_t t0;     /* common CLOCK_MONOTONIC reference point */
	_Atomic int64_t shift;  /* T0 shift for --lag-policy=rebase */
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
	_Atomic int64_t late_max;
	_Atomic int64_t pos;         /* position on the timeline (lap*length + ts) */
	_Atomic uint64_t lap;
	_Atomic uint64_t gpos;       /* lap * file_size + file offset of the last packet */
	_Atomic int64_t t_end;       /* when the thread finished sending */
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
	uint64_t l_pkts, l_bytes, l_sends, l_enobufs, l_eagain;
	/* published */
	wstats_t st;
	_Atomic uint64_t hist[LH_BUCKETS] AFR_ALIGNED; /* lateness, ns */
} worker_t;

void *afr_worker_main(void *arg);

#endif
