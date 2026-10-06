/*
 * Поток отправки: свой AF_PACKET-сокет с TX_RING, свой шард пакетов.
 */
#ifndef AFR_WORKER_H
#define AFR_WORKER_H

#include "mutate.h"
#include "replay.h"

#include <pthread.h>
#include <stdatomic.h>

/* Общее состояние запуска. */
typedef struct {
	pthread_barrier_t bar;
	_Atomic int64_t t0;     /* общая точка отсчёта CLOCK_MONOTONIC */
	_Atomic int64_t shift;  /* сдвиг T0 при --lag-policy=rebase */
	atomic_int failed;
} shared_t;

extern atomic_int g_stop;

/* Счётчики потока: пишет только сам поток, читает поток статистики. */
typedef struct AFR_ALIGNED {
	_Atomic uint64_t pkts, bytes;
	_Atomic uint64_t sends, enobufs, eagain;
	_Atomic uint64_t asis_back;  /* пакетов «назад во времени» при asis */
	_Atomic uint64_t rebases;
	_Atomic int64_t late_max;
	_Atomic int64_t pos;         /* позиция на шкале (круг*длина + ts) */
	_Atomic uint64_t lap;
	_Atomic uint64_t file_off;
	_Atomic int64_t t_end;       /* когда поток закончил отправку */
	atomic_int finished;
} wstats_t;

typedef struct {
	int fd;
	uint8_t *ring;
	size_t ring_size;
	unsigned frame_size, frame_nr;
	unsigned data_off;
} tx_ring_t;

typedef struct {
	/* настройки */
	unsigned id;
	int cpu;
	int is_l2;
	const afr_ctx_t *c;
	shared_t *sh;
	double rate_share;     /* доля общей скорости (--mbps/--pps) */
	mutate_cfg_t mut;
	int mutate;
	/* данные */
	pkt_t *pk;
	size_t n;
	tx_ring_t tx;
	pthread_t th;
	char err[256];
	/* горячее состояние (только поток) */
	unsigned head, pending;
	int64_t now; /* последнее прочитанное время */
	uint64_t l_pkts, l_bytes, l_sends, l_enobufs, l_eagain;
	/* публикуемое */
	wstats_t st;
	_Atomic uint64_t hist[LH_BUCKETS] AFR_ALIGNED; /* опоздания, нс */
} worker_t;

void *afr_worker_main(void *arg);

#endif
