#include "replay.h"

#include "clock.h"
#include "util.h"
#include "stream.h"
#include "worker.h"

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define RLX memory_order_relaxed
#define LD(x) atomic_load_explicit(&(x), RLX)

static void on_signal(int sig)
{
	(void)sig;
	atomic_store(&g_stop, 1);
}

/* Snapshot of all threads' counters. */
typedef struct {
	uint64_t pkts, bytes, sends, enobufs, eagain, asis_back, rebases;
	int64_t late_max;
	uint64_t hist[LH_BUCKETS];
	uint64_t sys_tx, sys_drop;
	int sys_ok;
	int64_t pos_min, pos_last;
	uint64_t lap_min, lap_last;
	unsigned active;
} snap_t;

static void take_snap(worker_t **ws, unsigned nw, const char *iface, snap_t *s)
{
	memset(s, 0, sizeof(*s));
	s->pos_min = INT64_MAX;
	s->lap_min = UINT64_MAX;
	s->pos_last = INT64_MIN;
	for (unsigned i = 0; i < nw; i++) {
		worker_t *w = ws[i];
		int64_t lp = LD(w->st.pos);
		if (lp > s->pos_last) {
			s->pos_last = lp;
			s->lap_last = LD(w->st.lap);
		}
		s->pkts += LD(w->st.pkts);
		s->bytes += LD(w->st.bytes);
		s->sends += LD(w->st.sends);
		s->enobufs += LD(w->st.enobufs);
		s->eagain += LD(w->st.eagain);
		s->asis_back += LD(w->st.asis_back);
		s->rebases += LD(w->st.rebases);
		int64_t lm = LD(w->st.late_max);
		if (lm > s->late_max)
			s->late_max = lm;
		for (unsigned b = 0; b < LH_BUCKETS; b++)
			s->hist[b] += LD(w->hist[b]);
		if (!atomic_load(&w->st.finished)) {
			s->active++;
			int64_t p = LD(w->st.pos);
			if (p < s->pos_min)
				s->pos_min = p;
			uint64_t l = LD(w->st.lap);
			if (l < s->lap_min)
				s->lap_min = l;
		}
	}
	s->sys_ok = afr_sysfs_read_u64(iface, "statistics/tx_packets", &s->sys_tx) == 0 &&
	            afr_sysfs_read_u64(iface, "statistics/tx_dropped", &s->sys_drop) == 0;
}

static const char *mode_name(int m)
{
	switch (m) {
	case MODE_TOPSPEED: return "topspeed";
	case MODE_MBPS: return "mbps";
	case MODE_PPS: return "pps";
	default: return "timestamps";
	}
}

/* ---------- JSON ---------- */

static FILE *json_open(const afr_ctx_t *c, unsigned nw)
{
	const opts_t *o = c->o;
	FILE *f = fopen(o->stats_json, "w");
	if (!f) {
		afr_log_err("failed to open %s: %s", o->stats_json, strerror(errno));
		return NULL;
	}
	fprintf(f, "{\n  \"file\": \"");
	for (const char *p = o->file; *p; p++) {
		if (*p == '"' || *p == '\\')
			fputc('\\', f);
		fputc(*p, f);
	}
	fprintf(f, "\",\n  \"interface\": \"%s\",\n  \"mode\": \"%s\",\n", o->iface, mode_name(o->mode));
	fprintf(f, "  \"multiplier\": %.9g,\n  \"mbps\": %.9g,\n  \"pps\": %.9g,\n", c->mult, o->mbps,
	        o->pps);
	fprintf(f, "  \"loops\": %" PRIu64 ",\n  \"threads\": %u,\n  \"ip_shards\": %u,\n", o->loops, nw,
	        c->ip_threads);
	fprintf(f, "  \"timeline_ns\": %" PRId64 ",\n  \"lap_ns\": %" PRId64 ",\n", c->tsr.duration,
	        c->tsr.lap_len);
	fprintf(f, "  \"intervals\": [");
	fflush(f);
	return f;
}

typedef struct {
	double t;
	double dt;
	uint64_t pkts, bytes, sys_tx, sys_drop, enobufs, eagain, sends;
	int sys_ok;
	uint64_t p50, p99, pmax, late_n;
	int timed;
	double pos_s;
	uint64_t lap;
} row_t;

static void json_row(FILE *f, int first, const row_t *r)
{
	fprintf(f, "%s\n    {\"t\": %.3f, \"pkts\": %" PRIu64 ", \"bytes\": %" PRIu64
	           ", \"gbps\": %.6f, \"mpps\": %.6f, \"sends\": %" PRIu64 ", \"enobufs\": %" PRIu64
	           ", \"eagain\": %" PRIu64,
	        first ? "" : ",", r->t, r->pkts, r->bytes, (double)r->bytes * 8 / r->dt / 1e9,
	        (double)r->pkts / r->dt / 1e6, r->sends, r->enobufs, r->eagain);
	if (r->sys_ok)
		fprintf(f, ", \"sys_tx_packets\": %" PRIu64 ", \"sys_tx_dropped\": %" PRIu64, r->sys_tx,
		        r->sys_drop);
	if (r->timed)
		fprintf(f, ", \"late_p50_ns\": %" PRIu64 ", \"late_p99_ns\": %" PRIu64
		           ", \"late_max_ns\": %" PRIu64 ", \"pcap_pos_s\": %.6f, \"lap\": %" PRIu64,
		        r->p50, r->p99, r->pmax, r->pos_s, r->lap);
	fprintf(f, "}");
	fflush(f);
}

/* ---------- Output ---------- */

static void print_row(const row_t *r, const afr_ctx_t *c)
{
	char g[48], m[48], b[64];
	snprintf(g, sizeof(g), "%.3f", (double)r->bytes * 8 / r->dt / 1e9);
	snprintf(m, sizeof(m), "%.3f", (double)r->pkts / r->dt / 1e6);
	printf("[%7.1f s] %8s Gbit/s %8s Mpps", r->t, g, m);
	if (r->sys_ok)
		printf(" | sent (sysfs) %.3f Mpps, tx_dropped +%" PRIu64, (double)r->sys_tx / r->dt / 1e6,
		       r->sys_drop);
	else
		printf(" | sysfs unavailable");
	printf(" | ENOBUFS +%" PRIu64 " EAGAIN +%" PRIu64, r->enobufs, r->eagain);
	if (r->timed) {
		if (r->late_n) {
			char a[32], p[32], x[32];
			afr_fmt_ns(a, sizeof(a), (double)r->p50);
			afr_fmt_ns(p, sizeof(p), (double)r->p99);
			afr_fmt_ns(x, sizeof(x), (double)r->pmax);
			printf(" | lateness p50 %s p99 %s max %s", a, p, x);
		}
		afr_fmt_ns(b, sizeof(b), (double)c->tsr.duration);
		printf(" | pcap +%.3f s of %s", r->pos_s, b);
		if (c->o->loops != 1)
			printf(", lap %" PRIu64, r->lap + 1);
	}
	printf("\n");
}

static void make_row(row_t *r, const snap_t *cur, const snap_t *prev, double t, double dt,
                     const afr_ctx_t *c)
{
	memset(r, 0, sizeof(*r));
	r->t = t;
	r->dt = dt > 0 ? dt : 1;
	r->pkts = cur->pkts - prev->pkts;
	r->bytes = cur->bytes - prev->bytes;
	r->sends = cur->sends - prev->sends;
	r->enobufs = cur->enobufs - prev->enobufs;
	r->eagain = cur->eagain - prev->eagain;
	r->sys_ok = cur->sys_ok && prev->sys_ok;
	if (r->sys_ok) {
		r->sys_tx = cur->sys_tx - prev->sys_tx;
		r->sys_drop = cur->sys_drop - prev->sys_drop;
	}
	r->timed = c->o->mode == MODE_TIMED;
	if (r->timed) {
		uint64_t h[LH_BUCKETS];
		for (unsigned b = 0; b < LH_BUCKETS; b++) {
			h[b] = cur->hist[b] - prev->hist[b];
			r->late_n += h[b];
		}
		r->p50 = afr_lh_quantile(h, 0.5);
		r->p99 = afr_lh_quantile(h, 0.99);
		r->pmax = afr_lh_quantile(h, 1.0);
		if (cur->pos_min != INT64_MAX) {
			uint64_t lap = cur->lap_min;
			int64_t in_lap = cur->pos_min - (int64_t)lap * c->tsr.lap_len;
			r->pos_s = (double)in_lap / 1e9;
			r->lap = lap;
		} else if (cur->pos_last != INT64_MIN) {
			/* All threads finished or stopped: final position. */
			r->lap = cur->lap_last;
			r->pos_s = (double)(cur->pos_last - (int64_t)r->lap * c->tsr.lap_len) / 1e9;
		}
	}
}

static void print_summary(const afr_ctx_t *c, const snap_t *end, const snap_t *start,
                          double elapsed, worker_t **ws, unsigned nw, FILE *json, int stopped,
                          int64_t shift)
{
	char b1[64], b2[64], b3[64], b4[64];
	uint64_t pkts = end->pkts, bytes = end->bytes;
	double gbps = elapsed > 0 ? (double)bytes * 8 / elapsed / 1e9 : 0;
	double mpps = elapsed > 0 ? (double)pkts / elapsed / 1e6 : 0;
	printf("\n=== Summary%s ===\n", stopped ? " (stopped by signal)" : "");
	afr_fmt_count(b1, sizeof(b1), (double)pkts);
	printf("Sent to kernel: %" PRIu64 " packets (%s), %" PRIu64 " bytes in %.3f s: %.3f Gbit/s, "
	       "%.3f Mpps\n",
	       pkts, b1, bytes, elapsed, gbps, mpps);
	if (end->sys_ok && start->sys_ok) {
		uint64_t d = end->sys_tx - start->sys_tx;
		printf("Sent per sysfs tx_packets: %" PRIu64 " (%+.0f vs sent; other traffic on the "
		       "interface is counted too), tx_dropped: +%" PRIu64 "\n",
		       d, (double)d - (double)pkts, end->sys_drop - start->sys_drop);
	} else {
		printf("Interface statistics unavailable in sysfs\n");
	}
	printf("send(): %" PRIu64 " calls (%.1f frames per call), ENOBUFS: %" PRIu64
	       ", EAGAIN: %" PRIu64 "\n",
	       end->sends, end->sends ? (double)pkts / (double)end->sends : 0.0, end->enobufs,
	       end->eagain);
	uint64_t skipped = 0;
	for (int k = 0; k < SKIP_REASONS; k++)
		skipped += c->ix.st.skipped[k];
	printf("Skipped frames (per lap): %" PRIu64 ", truncated at capture: %" PRIu64
	       "\n",
	       skipped, c->ix.st.truncated_caplen);
	uint64_t late_n = 0;
	for (unsigned b = 0; b < LH_BUCKETS; b++)
		late_n += end->hist[b];
	if (c->o->mode == MODE_TIMED && late_n) {
		afr_fmt_ns(b1, sizeof(b1), (double)afr_lh_quantile(end->hist, 0.5));
		afr_fmt_ns(b2, sizeof(b2), (double)afr_lh_quantile(end->hist, 0.99));
		afr_fmt_ns(b3, sizeof(b3), (double)afr_lh_quantile(end->hist, 0.999));
		afr_fmt_ns(b4, sizeof(b4), (double)end->late_max);
		printf("Lateness vs schedule: p50 %s, p99 %s, p99.9 %s, max %s\n", b1, b2,
		       b3, b4);
		if (end->rebases)
			printf("T0 shifts (rebase): %" PRIu64 ", total shift %.3f ms\n", end->rebases,
			       (double)shift / 1e6);
		if (end->asis_back)
			printf("Sent without waiting (backward in time, asis): %" PRIu64 "\n",
			       end->asis_back);
	}
	printf("Per thread:\n");
	for (unsigned i = 0; i < nw; i++) {
		worker_t *w = ws[i];
		printf("  %s %2u (CPU %3d): %12" PRIu64 " packets, %14" PRIu64 " bytes, ENOBUFS %" PRIu64
		       "\n",
		       w->is_l2 ? "non-IP" : "thread", w->id, w->cpu, LD(w->st.pkts), LD(w->st.bytes),
		       LD(w->st.enobufs));
	}
	if (json) {
		fprintf(json, "\n  ],\n  \"summary\": {\"stopped\": %s, \"elapsed_s\": %.6f, \"pkts\": %" PRIu64
		              ", \"bytes\": %" PRIu64 ", \"gbps\": %.6f, \"mpps\": %.6f, \"sends\": %" PRIu64
		              ", \"enobufs\": %" PRIu64 ", \"eagain\": %" PRIu64 ", \"skipped\": %" PRIu64
		              ", \"truncated_caplen\": %" PRIu64,
		        stopped ? "true" : "false", elapsed, pkts, bytes, gbps, mpps, end->sends,
		        end->enobufs, end->eagain, skipped, c->ix.st.truncated_caplen);
		if (end->sys_ok && start->sys_ok)
			fprintf(json, ", \"sys_tx_packets\": %" PRIu64 ", \"sys_tx_dropped\": %" PRIu64,
			        end->sys_tx - start->sys_tx, end->sys_drop - start->sys_drop);
		if (c->o->mode == MODE_TIMED && late_n)
			fprintf(json, ", \"late_p50_ns\": %" PRIu64 ", \"late_p99_ns\": %" PRIu64
			              ", \"late_p999_ns\": %" PRIu64 ", \"late_max_ns\": %" PRId64
			              ", \"rebases\": %" PRIu64 ", \"asis_backward\": %" PRIu64,
			        afr_lh_quantile(end->hist, 0.5), afr_lh_quantile(end->hist, 0.99),
			        afr_lh_quantile(end->hist, 0.999), end->late_max, end->rebases,
			        end->asis_back);
		fprintf(json, ", \"per_thread\": [");
		for (unsigned i = 0; i < nw; i++)
			fprintf(json, "%s{\"id\": %u, \"non_ip\": %s, \"cpu\": %d, \"pkts\": %" PRIu64
			              ", \"bytes\": %" PRIu64 ", \"enobufs\": %" PRIu64 "}",
			        i ? ", " : "", ws[i]->id, ws[i]->is_l2 ? "true" : "false", ws[i]->cpu,
			        LD(ws[i]->st.pkts), LD(ws[i]->st.bytes), LD(ws[i]->st.enobufs));
		fprintf(json, "]}\n}\n");
	}
}

static void print_plan(const afr_ctx_t *c, worker_t **ws, unsigned nw)
{
	const opts_t *o = c->o;
	char b1[64], b2[64];
	afr_fmt_ns(b1, sizeof(b1), (double)c->index_ns);
	afr_log_info("File %s: %" PRIu64 " packets to send, index %s in %s", o->file, c->tsr.n,
	             c->index_cached ? "loaded from cache" : "built", b1);
	switch (o->mode) {
	case MODE_TOPSPEED: afr_log_info("Mode: top speed"); break;
	case MODE_MBPS:
		afr_fmt_bps(b1, sizeof(b1), o->mbps * 1e6);
		afr_log_info("Mode: fixed rate %s (packets paced in file order)", b1);
		break;
	case MODE_PPS:
		afr_fmt_count(b1, sizeof(b1), o->pps);
		afr_log_info("Mode: fixed rate %spps", b1);
		break;
	default:
		afr_fmt_ns(b1, sizeof(b1), (double)c->tsr.duration);
		afr_fmt_ns(b2, sizeof(b2), (double)c->tsr.duration / c->mult);
		afr_log_info("Mode: timestamps x%g, timeline %s -> %s per lap, lag-policy=%s", c->mult,
		             b1, b2, o->lag_policy == LAG_REBASE ? "rebase" : "catchup");
	}
	char cpus[256] = "";
	size_t len = 0;
	for (unsigned i = 0; i < nw && len < sizeof(cpus) - 8; i++)
		len += (size_t)snprintf(cpus + len, sizeof(cpus) - len, "%s%d", i ? "," : "", ws[i]->cpu);
	afr_fmt_bps(b1, sizeof(b1), c->link_bps);
	afr_log_info("Interface %s, MTU %u, link %s (%s); %u threads (CPU %s%s), qdisc-bypass %s, "
	             "packet-loss %s, batch %u, ring %u frames",
	             o->iface, c->mtu, c->link_bps > 0 ? b1 : "?", c->link_src, nw, cpus,
	             c->cpus_from_numa ? ", NIC NUMA node" : "", o->qdisc_bypass ? "on" : "off",
	             o->packet_loss ? "on" : "off", o->batch, o->ring_frames);
	if (o->loops == 0)
		afr_log_info("Loops: infinite (until SIGINT/SIGTERM)");
	else if (o->loops > 1)
		afr_log_info("Loops: %" PRIu64, o->loops);
}

int afr_replay_run(afr_ctx_t *c)
{
	opts_t *o = c->o;
	int rc = 0;

	afr_report_warnings(c);

	/* Threads: one per non-empty IP shard plus a separate one for non-IP. */
	unsigned nw = 0;
	worker_t **ws = calloc(c->ix.nshards, sizeof(*ws));
	shared_t *sh = aligned_alloc(AFR_CACHELINE, (sizeof(shared_t) + AFR_CACHELINE - 1) /
	                                                AFR_CACHELINE * AFR_CACHELINE);
	if (!ws || !sh) {
		afr_log_err("out of memory");
		return 1;
	}
	memset(sh, 0, sizeof(*sh));
	if (c->ip_threads > (unsigned)c->ncpus)
		afr_log_warn("more threads (%u) than CPUs (%d): several threads share a core",
		             c->ip_threads, c->ncpus);
	else if (c->ix.shard_pkts[c->ip_threads] && c->ip_threads == (unsigned)c->ncpus)
		afr_log_warn("the non-IP thread shares CPU %d with thread 0 (%u IP threads on %d CPUs); "
		             "use -t %u to give it its own core",
		             c->cpus[0], c->ip_threads, c->ncpus, c->ip_threads > 1 ? c->ip_threads - 1 : 1);
	for (unsigned s = 0; s < c->ix.nshards; s++) {
		if (c->ix.shard_pkts[s] == 0)
			continue;
		worker_t *w = aligned_alloc(AFR_CACHELINE, (sizeof(worker_t) + AFR_CACHELINE - 1) /
		                                               AFR_CACHELINE * AFR_CACHELINE);
		if (!w) {
			afr_log_err("out of memory");
			return 1;
		}
		memset(w, 0, sizeof(*w));
		w->id = s;
		w->is_l2 = (s == c->ip_threads);
		w->cpu = c->cpus[s % (unsigned)c->ncpus];
		w->c = c;
		w->sh = sh;
		w->mutate = o->mutate_ip || o->mutate_port;
		w->mut = (mutate_cfg_t){.ip = o->mutate_ip,
		                        .port = o->mutate_port,
		                        .ip_offset = o->mutate_ip_offset,
		                        .port_step = o->mutate_port_step,
		                        .raw_ip = 0};
		ws[nw++] = w;
	}
	print_plan(c, ws, nw);
	afr_log_info("Clock: %s", afr_clock_init(o->clock_mode));

	struct sigaction sa = {.sa_handler = on_signal};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	pthread_barrier_init(&sh->bar, NULL, nw + 1);
	unsigned started = 0;
	for (; started < nw; started++) {
		if (pthread_create(&ws[started]->th, NULL, afr_worker_main, ws[started]) != 0) {
			afr_log_err("failed to create thread %u", started);
			atomic_store(&sh->failed, 1);
			break;
		}
	}
	if (started < nw) {
		/* Already created threads are waiting on a barrier sized for all of them:
		 * they cannot be joined cleanly, so exit abruptly. */
		_exit(1);
	}

	pthread_barrier_wait(&sh->bar); /* 1 */
	/* Threads have copied their shards; the global index is no longer needed. */
	afr_index_free_arrays(&c->ix);
	for (unsigned i = 0; i < nw && o->drop_behind > 0; i++) {
		if (ws[i]->mlock_failed) {
			afr_log_warn("could not lock the packet index in RAM (mlock); with a file larger "
			             "than RAM it may be swapped out. Run as root or raise ulimit -l");
			break;
		}
	}
	/* Streaming of the file: readahead ahead of the senders, drop-behind for big files. */
	streamer_t stream = {.pf = &c->pf, .ws = ws, .nw = nw, .window = o->readahead,
	                     .drop_behind = o->drop_behind > 0};
	if (!c->pf.preloaded) {
		char ra[32];
		snprintf(ra, sizeof(ra), "%.1f GB", (double)o->readahead / (1 << 30));
		if (afr_stream_start(&stream) == 0)
			afr_log_info("File streaming: readahead %s, drop-behind %s", ra,
			             stream.drop_behind ? "on (file larger than free RAM)" : "off");
		else
			afr_log_warn("could not start the readahead thread");
	}
	snap_t start, prev, cur;
	take_snap(ws, nw, o->iface, &start);
	int64_t t0 = afr_now_ns() + 20 * NS_PER_MS;
	atomic_store(&sh->t0, t0);
	pthread_barrier_wait(&sh->bar); /* 2 */

	if (atomic_load(&sh->failed)) {
		for (unsigned i = 0; i < nw; i++)
			pthread_join(ws[i]->th, NULL);
		afr_stream_stop(&stream);
		for (unsigned i = 0; i < nw; i++)
			if (ws[i]->err[0])
				afr_log_err("%s", ws[i]->err);
		return 1;
	}

	FILE *json = o->stats_json ? json_open(c, nw) : NULL;
	if (o->stats_json && !json)
		atomic_store(&g_stop, 1);

	prev = start;
	int64_t tick = t0;
	int64_t last = t0;
	int first_row = 1;
	for (;;) {
		tick += NS_PER_SEC;
		/* Sleep until the next second, but wake earlier if all threads have finished. */
		for (;;) {
			int64_t now = afr_now_ns();
			if (now >= tick)
				break;
			int all_done = 1;
			for (unsigned i = 0; i < nw; i++)
				if (!atomic_load(&ws[i]->st.finished))
					all_done = 0;
			if (all_done)
				break;
			int64_t sl = tick - now;
			if (sl > 20 * NS_PER_MS)
				sl = 20 * NS_PER_MS;
			struct timespec ts = {0, sl};
			nanosleep(&ts, NULL);
		}
		int64_t now = afr_now_ns();
		take_snap(ws, nw, o->iface, &cur);
		if (now - last >= NS_PER_SEC / 2 || cur.active == 0) {
			row_t r;
			make_row(&r, &cur, &prev, (double)(now - t0) / 1e9, (double)(now - last) / 1e9, c);
			if (!o->quiet)
				print_row(&r, c);
			if (json) {
				json_row(json, first_row, &r);
				first_row = 0;
			}
			prev = cur;
			last = now;
		}
		if (cur.active == 0)
			break;
	}
	int64_t t_end = t0;
	for (unsigned i = 0; i < nw; i++) {
		pthread_join(ws[i]->th, NULL);
		if (LD(ws[i]->st.t_end) > t_end)
			t_end = LD(ws[i]->st.t_end);
	}
	afr_stream_stop(&stream);
	/* Wait for interface counters to catch up (frames may still be queued). */
	usleep(100000);
	take_snap(ws, nw, o->iface, &cur);
	int stopped = atomic_load(&g_stop) && !atomic_load(&sh->failed);
	print_summary(c, &cur, &start, (double)(t_end - t0) / 1e9, ws, nw, json, stopped,
	              atomic_load(&sh->shift));
	if (!c->pf.preloaded)
		printf("File streaming: requested ahead %.1f GB, dropped from page cache %.1f GB, pages "
		       "pre-mapped by %s\n",
		       (double)atomic_load(&stream.ra_bytes) / 1e9,
		       (double)atomic_load(&stream.dropped_bytes) / 1e9,
		       stream.populate == STREAM_POP_MADVISE ? "MADV_POPULATE_READ"
		                                             : "touching (kernel without MADV_POPULATE_READ)");
	for (unsigned i = 0; i < nw; i++) {
		if (ws[i]->err[0]) {
			afr_log_err("%s", ws[i]->err);
			rc = 1;
		}
	}
	if (atomic_load(&sh->failed))
		rc = 1;
	if (json)
		fclose(json);
	for (unsigned i = 0; i < nw; i++)
		free(ws[i]);
	free(ws);
	pthread_barrier_destroy(&sh->bar);
	free(sh);
	return rc;
}
