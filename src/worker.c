#include "worker.h"

#include "clock.h"
#include "util.h"

#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

atomic_int g_stop;

#define RLX memory_order_relaxed
#define PUB(field, v) atomic_store_explicit(&(field), (v), RLX)
#define STOP_REQUESTED() atomic_load_explicit(&g_stop, RLX)

/* The kernel may set timestamp flags in the status (commit 171c3b151118). */
static inline uint32_t status_mask(uint32_t s)
{
	return s & ~(uint32_t)(TP_STATUS_TS_SOFTWARE | TP_STATUS_TS_RAW_HARDWARE);
}

/* ---------- TX_RING ---------- */

static int tx_open(tx_ring_t *t, const char *iface, unsigned frames, unsigned max_len,
                   int bypass, int loss, char *err, size_t errlen)
{
	memset(t, 0, sizeof(*t));
	t->fd = socket(AF_PACKET, SOCK_RAW, 0); /* protocol 0: the socket receives nothing */
	if (t->fd < 0) {
		snprintf(err, errlen, "socket(AF_PACKET): %s%s", strerror(errno),
		         errno == EPERM ? " (requires root or CAP_NET_RAW)" : "");
		return -1;
	}
	int v = TPACKET_V2;
	if (setsockopt(t->fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v)) < 0) {
		snprintf(err, errlen, "PACKET_VERSION: %s", strerror(errno));
		goto fail;
	}
	if (bypass) {
		v = 1;
		if (setsockopt(t->fd, SOL_PACKET, PACKET_QDISC_BYPASS, &v, sizeof(v)) < 0) {
			snprintf(err, errlen, "PACKET_QDISC_BYPASS: %s", strerror(errno));
			goto fail;
		}
	}
	if (loss) {
		v = 1;
		if (setsockopt(t->fd, SOL_PACKET, PACKET_LOSS, &v, sizeof(v)) < 0) {
			snprintf(err, errlen, "PACKET_LOSS: %s", strerror(errno));
			goto fail;
		}
	}
	t->data_off = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
	unsigned fs = 2048;
	while (fs < t->data_off + max_len)
		fs <<= 1;
	unsigned block = fs < 65536 ? 65536 : fs;
	unsigned per_block = block / fs;
	unsigned nblocks = (frames + per_block - 1) / per_block;
	t->frame_size = fs;
	t->frame_nr = nblocks * per_block;
	/* The send buffer must hold the whole ring, otherwise send() hits EAGAIN. */
	int sndbuf = (int)((size_t)t->frame_nr * fs * 2 > (1u << 30) ? (1u << 30)
	                                                               : (size_t)t->frame_nr * fs * 2);
	if (setsockopt(t->fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0)
		setsockopt(t->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	struct tpacket_req req = {
	    .tp_block_size = block,
	    .tp_block_nr = nblocks,
	    .tp_frame_size = fs,
	    .tp_frame_nr = t->frame_nr,
	};
	if (setsockopt(t->fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
		snprintf(err, errlen, "PACKET_TX_RING (%u frames of %u bytes): %s", t->frame_nr, fs,
		         strerror(errno));
		goto fail;
	}
	t->ring_size = (size_t)block * nblocks;
	void *p = mmap(NULL, t->ring_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, t->fd, 0);
	if (p == MAP_FAILED) {
		snprintf(err, errlen, "mmap TX_RING: %s", strerror(errno));
		goto fail;
	}
	t->ring = p;
	struct sockaddr_ll ll = {
	    .sll_family = AF_PACKET,
	    .sll_protocol = 0,
	    .sll_ifindex = (int)if_nametoindex(iface),
	};
	if (ll.sll_ifindex == 0) {
		snprintf(err, errlen, "interface %s not found", iface);
		goto fail;
	}
	if (bind(t->fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
		snprintf(err, errlen, "bind %s: %s", iface, strerror(errno));
		goto fail;
	}
	return 0;
fail:
	if (t->ring)
		munmap(t->ring, t->ring_size);
	close(t->fd);
	t->fd = -1;
	t->ring = NULL;
	return -1;
}

static void tx_close(tx_ring_t *t)
{
	if (t->ring)
		munmap(t->ring, t->ring_size);
	if (t->fd >= 0)
		close(t->fd);
	t->ring = NULL;
	t->fd = -1;
}

static inline struct tpacket2_hdr *frame_at(const tx_ring_t *t, unsigned i)
{
	return (struct tpacket2_hdr *)(t->ring + (size_t)i * t->frame_size);
}

/* ---------- Sending ---------- */

static void publish(worker_t *w)
{
	PUB(w->st.pkts, w->l_pkts);
	PUB(w->st.bytes, w->l_bytes);
	PUB(w->st.sends, w->l_sends);
	PUB(w->st.enobufs, w->l_enobufs);
	PUB(w->st.eagain, w->l_eagain);
}

static void fatal(worker_t *w, const char *what, int e)
{
	if (!w->err[0])
		snprintf(w->err, sizeof(w->err), "thread %u: %s: %s%s", w->id, what, strerror(e),
		         (e == EMSGSIZE || e == EINVAL) && !w->c->o->packet_loss
		             ? " (kernel rejected the frame; --packet-loss lets it be skipped)"
		             : "");
	atomic_store(&w->sh->failed, 1);
	atomic_store(&g_stop, 1);
}

/* Batched send(): the kernel transmits all frames with status SEND_REQUEST. */
/*
 * Back off after the device queue rejected frames (ENOBUFS/EAGAIN). Hammering send()
 * in a tight loop only burns the CPU: the queue frees up at line rate anyway. The
 * first few attempts spin briefly, then the thread sleeps for 5..100 us.
 */
static void backoff(unsigned fails)
{
	if (fails <= 4) {
		for (unsigned i = 0; i < (64u << fails); i++)
			afr_cpu_relax();
		return;
	}
	unsigned sh = fails - 5 < 5 ? fails - 5 : 5;
	long ns = 5000L << sh;
	if (ns > 100000)
		ns = 100000;
	struct timespec ts = {0, ns};
	nanosleep(&ts, NULL);
}

static void flush(worker_t *w)
{
	unsigned fails = 0;
	w->pending = 0;
	for (;;) {
		w->l_sends++;
		ssize_t r = send(w->tx.fd, NULL, 0, MSG_DONTWAIT);
		if (AFR_LIKELY(r >= 0))
			break;
		int e = errno;
		if (e == ENOBUFS) {
			/* Device/qdisc queue is full. The frame stays SEND_REQUEST; the kernel
			 * retries it on the next send(). */
			w->l_enobufs++;
		} else if (e == EAGAIN || e == EWOULDBLOCK) {
			w->l_eagain++; /* socket buffer exhausted */
		} else if (e != EINTR) {
			fatal(w, "send", e);
			break;
		}
		if (STOP_REQUESTED())
			break;
		backoff(++fails);
	}
	publish(w);
	w->now = afr_clock_ns();
}

static struct tpacket2_hdr *acquire_slow(worker_t *w, struct tpacket2_hdr *h)
{
	unsigned spins = 0;
	for (;;) {
		uint32_t s = status_mask(__atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE));
		if (s == TP_STATUS_AVAILABLE)
			return h;
		if (s & TP_STATUS_WRONG_FORMAT) {
			fatal(w, "frame rejected by kernel (TP_STATUS_WRONG_FORMAT)", EINVAL);
			return NULL;
		}
		if (w->pending) {
			flush(w);
		} else if (s == TP_STATUS_SEND_REQUEST && (++spins & 255) == 0) {
			/* Frame not picked up after ENOBUFS/EAGAIN: kick it. */
			flush(w);
		} else if (++spins > 4096) {
			/* The ring is full of frames still in the driver: wait for completions
			 * without burning the CPU. */
			struct timespec ts = {0, 10000};
			nanosleep(&ts, NULL);
		} else {
			afr_cpu_relax();
		}
		if (STOP_REQUESTED())
			return NULL;
	}
}

static inline struct tpacket2_hdr *acquire(worker_t *w)
{
	struct tpacket2_hdr *h = frame_at(&w->tx, w->head);
	uint32_t s = __atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE);
	if (AFR_LIKELY(status_mask(s) == TP_STATUS_AVAILABLE))
		return h;
	return acquire_slow(w, h);
}

/* Wait until all ring frames have been sent (no longer than timeout). */
static void drain(worker_t *w, int64_t timeout)
{
	if (w->pending)
		flush(w);
	int64_t deadline = afr_now_ns() + timeout;
	for (unsigned i = 0; i < w->tx.frame_nr;) {
		struct tpacket2_hdr *h = frame_at(&w->tx, i);
		uint32_t s = status_mask(__atomic_load_n(&h->tp_status, __ATOMIC_ACQUIRE));
		if (s == TP_STATUS_AVAILABLE || (s & TP_STATUS_WRONG_FORMAT)) {
			i++;
			continue;
		}
		if (afr_now_ns() > deadline)
			break;
		if (s == TP_STATUS_SEND_REQUEST)
			flush(w);
		struct timespec ts = {0, 20000};
		nanosleep(&ts, NULL);
	}
	publish(w);
}

/* Copy a packet into the ring and mark it for sending. */
static inline int emit(worker_t *w, const pkt_t *p, uint64_t lap)
{
	struct tpacket2_hdr *h = acquire(w);
	if (AFR_UNLIKELY(!h))
		return -1;
	uint8_t *dst = (uint8_t *)h + w->tx.data_off;
	const uint32_t len = OFFLEN_LEN(p->offlen);
	const uint8_t *src = w->c->pf.base + OFFLEN_OFF(p->offlen);
	uint32_t flen = len;
	if (w->c->pf.raw_ip) {
		/* Synthetic Ethernet header for RAW IP. */
		memcpy(dst, w->c->o->dmac, 6);
		memcpy(dst + 6, w->c->o->smac, 6);
		int v6 = w->c->pf.raw_ip == 6 || (w->c->pf.raw_ip == 1 && (src[0] >> 4) == 6);
		dst[12] = v6 ? 0x86 : 0x08;
		dst[13] = v6 ? 0xdd : 0x00;
		memcpy(dst + 14, src, len);
		flen += 14;
	} else {
		memcpy(dst, src, len);
	}
	if (w->mutate && lap)
		afr_mutate(dst, flen, lap, &w->mut);
	h->tp_len = flen;
	__atomic_store_n(&h->tp_status, TP_STATUS_SEND_REQUEST, __ATOMIC_RELEASE);
	w->head = (w->head + 1 == w->tx.frame_nr) ? 0 : w->head + 1;
	w->pending++;
	w->l_pkts++;
	w->l_bytes += flen;
	if (w->pending >= w->c->o->batch)
		flush(w);
	return 0;
}

/* Hybrid wait: nanosleep for long pauses, busy-spin at the end. */
static int64_t wait_until(int64_t target, int64_t spin_ns)
{
	int64_t now = afr_clock_ns();
	while (now < target) {
		int64_t d = target - now;
		if (d > spin_ns) {
			/* Before sleeping, check TSC against CLOCK_MONOTONIC (reading the clock is free here). */
			if (afr_clock_resync()) {
				now = afr_clock_ns();
				continue;
			}
			int64_t sl = d - spin_ns;
			if (sl > 50 * NS_PER_MS)
				sl = 50 * NS_PER_MS; /* to notice a stop request in time */
			/* Our clock is calibrated against CLOCK_MONOTONIC, so it is valid for it. */
			int64_t wake = now + sl;
			struct timespec ts = {.tv_sec = wake / NS_PER_SEC, .tv_nsec = wake % NS_PER_SEC};
			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
			if (STOP_REQUESTED())
				return afr_clock_ns();
		} else {
			afr_cpu_relax();
		}
		now = afr_clock_ns();
	}
	return now;
}

/*
 * Wait until target and return the current time. If the packet is already
 * known to be due (target <= last clock reading), the clock is not read: when
 * lagging, this saves a call per packet, and lateness is underestimated by at
 * most the duration of one batch (the clock is updated after every send).
 */
static inline int64_t pace(worker_t *w, int64_t target, int64_t spin)
{
	int64_t now = w->now;
	if (now >= target)
		return now;
	now = afr_clock_ns();
	if (now < target) {
		/* Packet not yet due: flush what has accumulated early. */
		if (w->pending) {
			flush(w);
			now = w->now;
		}
		if (now < target)
			now = wait_until(target, spin);
	}
	w->now = now;
	return now;
}

static inline void hist_add(worker_t *w, int64_t late)
{
	uint64_t v = late > 0 ? (uint64_t)late : 0;
	_Atomic uint64_t *b = &w->hist[afr_lh_bucket(v)];
	atomic_store_explicit(b, atomic_load_explicit(b, RLX) + 1, RLX);
	if (late > atomic_load_explicit(&w->st.late_max, RLX))
		PUB(w->st.late_max, late);
}

static inline void publish_pos(worker_t *w, const pkt_t *p, uint64_t lap, int64_t lap_len)
{
	PUB(w->st.pos, (int64_t)lap * lap_len + p->ts);
	PUB(w->st.lap, lap);
	PUB(w->st.file_off, OFFLEN_OFF(p->offlen));
}

static void run(worker_t *w)
{
	const afr_ctx_t *c = w->c;
	const opts_t *o = c->o;
	const int64_t t0 = atomic_load(&w->sh->t0);
	const int64_t spin = o->spin_ns;
	const int64_t lap_len = c->tsr.lap_len;
	const uint64_t loops = o->loops;
	const int mode = o->mode;
	const int asis = o->ts_order == TS_ORDER_ASIS;
	const int rebase = o->lag_policy == LAG_REBASE;
	const int64_t lag_thr = o->lag_threshold;
	const double inv_mult = 1.0 / c->mult;
	const uint32_t l2_extra = c->pf.raw_ip ? 14 : 0;
	double ns_per_unit = 0; /* for --mbps: ns per byte, for --pps: ns per packet */
	if (mode == MODE_MBPS)
		ns_per_unit = 8e9 / (o->mbps * 1e6 * w->rate_share);
	else if (mode == MODE_PPS)
		ns_per_unit = 1e9 / (o->pps * w->rate_share);
	double cum = 0;

	/* All modes start simultaneously at the common point T0. */
	w->now = wait_until(t0, spin);
	for (uint64_t lap = 0; loops == 0 || lap < loops; lap++) {
		int64_t max_sched = INT64_MIN;
		for (size_t i = 0; i < w->n; i++) {
			if (AFR_UNLIKELY(STOP_REQUESTED()))
				return;
			const pkt_t *p = &w->pk[i];
			if (mode == MODE_TIMED) {
				if (asis && p->ts < max_sched) {
					/* "Backward in time" under asis: no wait, lateness not counted. */
					w->st.asis_back++;
				} else {
					max_sched = p->ts;
					int64_t shift = rebase ? atomic_load_explicit(&w->sh->shift, RLX) : 0;
					int64_t target = afr_target(t0 + shift, lap, lap_len, p->ts, inv_mult);
					int64_t late = pace(w, target, spin) - target;
					hist_add(w, late);
					if (rebase && late > lag_thr) {
						/* Shift the common T0 forward so this packet is on time. */
						int64_t want = shift + late;
						int64_t cur = shift;
						while (cur < want &&
						       !atomic_compare_exchange_weak(&w->sh->shift, &cur, want)) {
						}
						w->st.rebases++;
					}
				}
			} else if (mode != MODE_TOPSPEED) {
				pace(w, t0 + (int64_t)(cum * ns_per_unit), spin);
				cum += mode == MODE_MBPS ? (double)(OFFLEN_LEN(p->offlen) + l2_extra) : 1.0;
			}
			if (AFR_UNLIKELY(emit(w, p, lap) < 0))
				return;
			publish_pos(w, p, lap, lap_len);
		}
	}
}

static int build_shard(worker_t *w)
{
	const pkt_index_t *ix = &w->c->ix;
	unsigned sid = w->id;
	size_t cnt = ix->shard_pkts[sid];
	w->pk = malloc((cnt ? cnt : 1) * sizeof(pkt_t));
	if (!w->pk) {
		snprintf(w->err, sizeof(w->err), "thread %u: out of memory for shard", w->id);
		return -1;
	}
	size_t k = 0;
	for (size_t i = 0; i < ix->n && k < cnt; i++) {
		if (ix->shard[i] == sid)
			w->pk[k++] = (pkt_t){.ts = ix->ts[i], .offlen = ix->offlen[i]};
	}
	w->n = k;
	if (w->c->o->ts_order == TS_ORDER_SORT && !w->c->tsr.monotone) {
		/* Stable sort of the shard index by timestamp; data is not touched. */
		rec16_t *tmp = malloc((k ? k : 1) * sizeof(rec16_t));
		if (!tmp) {
			snprintf(w->err, sizeof(w->err), "thread %u: out of memory for sorting", w->id);
			return -1;
		}
		_Static_assert(sizeof(pkt_t) == sizeof(rec16_t), "pkt_t and rec16_t must match");
		afr_radix_sort16((rec16_t *)w->pk, tmp, k);
		free(tmp);
	}
	return 0;
}

/*
 * Ring slot size: the largest frame actually present in the file, not the MTU. With
 * MTU 9000 and ordinary traffic this gives 2 KB slots instead of 16 KB, which keeps
 * the ring compact in cache and TLB.
 */
static unsigned ring_frame_len(const afr_ctx_t *c)
{
	unsigned mtu_max = c->mtu + 14 + 4;
	unsigned m = c->ix.st.max_frame;
	return (m > 0 && m < mtu_max) ? m : mtu_max;
}

void *afr_worker_main(void *arg)
{
	worker_t *w = arg;
	const afr_ctx_t *c = w->c;
	int ok = 1;

	if (w->cpu >= 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(w->cpu, &set);
		if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
			fprintf(stderr, "WARNING: thread %u: failed to pin to CPU %d\n", w->id,
			        w->cpu);
	}
	prctl(PR_SET_TIMERSLACK, 1UL, 0, 0, 0);
	afr_clock_thread_init();
	char name[16];
	snprintf(name, sizeof(name), w->is_l2 ? "afr-l2" : "afr-tx%u", w->id);
	pthread_setname_np(pthread_self(), name);

	/* Shard memory and the ring are allocated after pinning, on the thread's own NUMA node. */
	w->tx.fd = -1;
	char terr[200] = "";
	if (build_shard(w) < 0) {
		atomic_store(&w->sh->failed, 1);
		ok = 0;
	} else if (tx_open(&w->tx, c->o->iface, c->o->ring_frames, ring_frame_len(c), c->o->qdisc_bypass,
	                   c->o->packet_loss, terr, sizeof(terr)) < 0) {
		snprintf(w->err, sizeof(w->err), "thread %u: %s", w->id, terr);
		atomic_store(&w->sh->failed, 1);
		ok = 0;
	}
	pthread_barrier_wait(&w->sh->bar); /* 1: everything is prepared */
	pthread_barrier_wait(&w->sh->bar); /* 2: T0 is set */
	if (ok && !atomic_load(&w->sh->failed)) {
		run(w);
		drain(w, 3 * NS_PER_SEC);
	}
	PUB(w->st.t_end, afr_now_ns());
	publish(w);
	free(w->pk);
	w->pk = NULL;
	tx_close(&w->tx);
	atomic_store(&w->st.finished, 1);
	return NULL;
}
