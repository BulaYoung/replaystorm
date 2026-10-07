#include "replay.h"

#include "clock.h"
#include "dio.h"
#include "therm.h"
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

static dio_t g_dio;
static int g_dio_on;
static therm_mon_t g_therm;
static int g_therm_on;

/* ---------- Link outages and the watchdog ---------- */

static int g_link_down;          /* shown in the per-second line */
static int64_t g_link_down_since;
static unsigned g_link_outages;
static int64_t g_link_down_ns;

/*
 * Link state from operstate (and from threads waiting in W_LINK). While the link is down
 * the schedule must not run on: when it comes back, T0 is shifted by the outage so the
 * replay continues where it was instead of bursting to catch up.
 */
static void link_check(worker_t **ws, unsigned nw, const char *iface, shared_t *sh, int64_t now)
{
	int down = 0;
	char st[32];
	if (afr_sysfs_read_str(iface, "operstate", st, sizeof(st)) == 0)
		down = strcmp(st, "up") != 0 && strcmp(st, "unknown") != 0;
	else if (access("/sys/class/net/lo", F_OK) == 0)
		down = 1; /* sysfs works but the interface is gone (driver reload, re-creation) */
	for (unsigned i = 0; i < nw && !down; i++)
		if (!atomic_load(&ws[i]->st.finished) && atomic_load(&ws[i]->st.state) == W_LINK)
			down = 1;
	/* A sender thread may already have seen the outage start or end before us. */
	if (atomic_load(&sh->down_since) && !g_link_down_since)
		down = 1;
	if (down && !g_link_down_since) {
		g_link_down_since = now;
		g_link_outages++;
		afr_link_down(sh, now);
		afr_log_warn("%s is down: waiting for it, the schedule is paused", iface);
	} else if (!down && g_link_down_since) {
		int64_t d = now - g_link_down_since;
		afr_link_up(sh, now); /* no-op if a sender thread already did it */
		g_link_down_ns += d;
		g_link_down_since = 0;
		afr_log_warn("%s is back after %.1f s, continuing", iface, (double)d / 1e9);
	}
	g_link_down = down;
}

typedef struct {
	uint64_t last_pkts;
	int64_t since;
	int warned;
} stall_t;

#define STALL_WARN_NS (3 * NS_PER_SEC)

/* A thread that sends nothing for a few seconds while not simply waiting for its
 * schedule: say what it waits for, and again when it moves on. */
static void watchdog(worker_t **ws, unsigned nw, stall_t *st, const afr_ctx_t *c, int64_t now)
{
	for (unsigned i = 0; i < nw; i++) {
		worker_t *w = ws[i];
		if (atomic_load(&w->st.finished))
			continue;
		uint64_t p = LD(w->st.pkts);
		int state = atomic_load(&w->st.state);
		if (!st[i].since) {
			st[i].since = now;
			st[i].last_pkts = p;
			continue;
		}
		if (p != st[i].last_pkts || state == W_PACE || g_link_down) {
			if (st[i].warned && p != st[i].last_pkts)
				afr_log_warn("thread %u resumed after %.1f s", w->id,
				             (double)(now - st[i].since) / 1e9);
			st[i].last_pkts = p;
			st[i].since = now;
			st[i].warned = 0;
			continue;
		}
		if (st[i].warned || now - st[i].since < STALL_WARN_NS)
			continue;
		st[i].warned = 1;
		const char *why = "";
		switch (state) {
		case W_RING: why = " (the NIC is not completing transmissions)"; break;
		case W_QUEUE: why = " (ENOBUFS: the device queue stays full)"; break;
		case W_DISK: why = " (the direct I/O window is empty: the disk is too slow)"; break;
		case W_FENCE: why = " (another thread is behind)"; break;
		case W_RUN: why = " (busy without progress)"; break;
		default: break;
		}
		uint64_t g = LD(w->st.gpos);
		afr_log_warn("thread %u (CPU %d) has sent nothing for %.0f s: waiting for %s%s, at %.1f%% "
		             "of the file, lap %" PRIu64,
		             w->id, w->cpu, (double)(now - st[i].since) / 1e9,
		             afr_wstate_names[state < W_COUNT ? state : 0], why,
		             c->pf.size ? 100.0 * (double)(g % c->pf.size) / (double)c->pf.size : 0.0,
		             c->pf.size ? g / c->pf.size + 1 : 0);
	}
}

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
	uint64_t disk_bytes, disk_reads, disk_read_ns;
	uint64_t gpos_min; /* slowest next-read position: lap * size + offset */
	int disk_temp;
	uint64_t throttle, rate_limit;
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
	s->gpos_min = UINT64_MAX;
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
			uint64_t g = LD(w->st.gpos);
			if (g < s->gpos_min)
				s->gpos_min = g;
		}
	}
	s->disk_bytes = g_dio_on ? LD(g_dio.bytes_read) : 0;
	s->disk_reads = g_dio_on ? LD(g_dio.reads) : 0;
	s->disk_read_ns = g_dio_on ? LD(g_dio.read_ns) : 0;
	s->disk_temp = g_therm_on ? atomic_load(&g_therm.temp) : -1;
	s->throttle = g_therm_on ? LD(g_therm.throttle) : 0;
	s->rate_limit = g_dio_on ? LD(g_dio.rate_limit) : 0;
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
	uint64_t pkts, bytes, sys_tx, sys_drop, enobufs, eagain, sends, disk;
	double disk_lat_ms;  /* mean duration of one 32 MB direct read */
	double file_pct;     /* slowest thread's position in the file, % (-1: unknown) */
	int disk_temp;       /* C, -1 unknown */
	uint64_t throttled;  /* new thermal throttling transitions during the interval */
	uint64_t rate_limit; /* governor read limit, bytes/s (0 = none) */
	uint64_t file_lap;
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
	if (g_dio_on)
		fprintf(f, ", \"disk_gbytes_per_s\": %.3f, \"disk_read_ms\": %.2f", (double)r->disk / r->dt / 1e9,
		        r->disk_lat_ms);
	if (r->file_pct >= 0)
		fprintf(f, ", \"file_pct\": %.2f, \"file_lap\": %" PRIu64, r->file_pct, r->file_lap);
	if (r->disk_temp >= 0)
		fprintf(f, ", \"disk_temp_c\": %d, \"disk_throttle_events\": %" PRIu64
		           ", \"disk_read_limit_gbytes_per_s\": %.3f",
		        r->disk_temp, r->throttled, (double)r->rate_limit / 1e9);
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
	if (g_dio_on)
		printf(" | disk %.2f GB/s, %.0f ms/read", (double)r->disk / r->dt / 1e9, r->disk_lat_ms);
	if (r->disk_temp >= 0)
		printf(", %d C", r->disk_temp);
	if (r->rate_limit)
		printf(", limit %.2f GB/s", (double)r->rate_limit / 1e9);
	if (r->throttled)
		printf(" THROTTLED");
	if (!r->timed && r->file_pct >= 0)
		printf(" | file %.1f%% lap %" PRIu64, r->file_pct, r->file_lap + 1);
	if (g_link_down)
		printf(" | LINK DOWN");
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
	r->disk = cur->disk_bytes - prev->disk_bytes;
	uint64_t nr = cur->disk_reads - prev->disk_reads;
	r->disk_lat_ms = nr ? (double)(cur->disk_read_ns - prev->disk_read_ns) / (double)nr / 1e6 : 0;
	r->file_pct = -1;
	r->disk_temp = cur->disk_temp;
	r->throttled = cur->throttle - prev->throttle;
	r->rate_limit = cur->rate_limit;
	if (cur->gpos_min != UINT64_MAX && c->pf.size) {
		r->file_lap = cur->gpos_min / c->pf.size;
		r->file_pct = 100.0 * (double)(cur->gpos_min % c->pf.size) / (double)c->pf.size;
	}
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
		printf("  %s %2u (CPU %3d): %12" PRIu64 " packets, %14" PRIu64 " bytes, ENOBUFS %" PRIu64,
		       w->is_l2 ? "non-IP" : "thread", w->id, w->cpu, LD(w->st.pkts), LD(w->st.bytes),
		       LD(w->st.enobufs));
		/* Where the thread spent its time waiting. */
		int any = 0;
		for (int k = W_PACE; k < W_COUNT; k++) {
			double sec = (double)LD(w->st.wait_ns[k]) / 1e9;
			if (sec < 0.05)
				continue;
			printf("%s%s %.1f s", any ? ", " : "; waited for: ", afr_wstate_names[k], sec);
			any = 1;
		}
		if (LD(w->st.link_lost))
			printf("; lost on interface re-creation: %" PRIu64, LD(w->st.link_lost));
		printf("\n");
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
		{
			fprintf(json, "%s{\"id\": %u, \"non_ip\": %s, \"cpu\": %d, \"pkts\": %" PRIu64
			              ", \"bytes\": %" PRIu64 ", \"enobufs\": %" PRIu64
			              ", \"link_lost\": %" PRIu64 ", \"wait_s\": {",
			        i ? ", " : "", ws[i]->id, ws[i]->is_l2 ? "true" : "false", ws[i]->cpu,
			        LD(ws[i]->st.pkts), LD(ws[i]->st.bytes), LD(ws[i]->st.enobufs),
			        LD(ws[i]->st.link_lost));
			static const char *const keys[W_COUNT] = {"send", "schedule", "tx_ring",
			                                          "device_queue", "disk", "fence", "link"};
			for (int k = W_PACE; k < W_COUNT; k++)
				fprintf(json, "%s\"%s\": %.3f", k > W_PACE ? ", " : "", keys[k],
				        (double)LD(ws[i]->st.wait_ns[k]) / 1e9);
			fprintf(json, "}}");
		}
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
	/* Threads stay within half the window of the slowest one. */
	const uint64_t lead = o->readahead / 2 > (256ull << 20) ? o->readahead / 2 : (256ull << 20);
	/* Direct I/O: reader threads fill a RAM window with O_DIRECT, bypassing the page cache. */
	int64_t dio_t0 = 0;
	int want_dio = !c->pf.preloaded &&
	               (o->io_mode == IO_DIRECT || (o->io_mode == IO_AUTO && c->big_file));
	/* The window must fit into free memory (the index is already loaded and locked). */
	if (want_dio) {
		uint64_t avail = afr_mem_available();
		uint64_t cap = avail > (3ull << 30) ? avail - (2ull << 30) : (1ull << 30);
		if (avail && o->readahead > cap) {
			afr_log_warn("--readahead %.1f GB does not fit into free memory (%.1f GB available); "
			             "using %.1f GB",
			             (double)o->readahead / (1 << 30), (double)avail / (1 << 30),
			             (double)cap / (1 << 30));
			o->readahead = cap;
		}
	}
	/* Disk temperature: shown in the statistics, used by --disk-max-temp/--disk-start-temp. */
	if (!c->pf.preloaded) {
		char tdesc[256];
		if (afr_therm_open(&g_therm.dev, o->file, tdesc, sizeof(tdesc)) == 0) {
			g_therm_on = 1;
			afr_log_info("Disk: %s", tdesc);
		} else if (o->disk_max_temp || o->disk_start_temp) {
			afr_log_warn("disk temperature unavailable (%s); --disk-max-temp/--disk-start-temp "
			             "are ignored",
			             tdesc);
		}
	}
	if (g_therm_on && o->disk_start_temp) {
		int64_t last_msg = 0;
		for (;;) {
			int temp;
			uint64_t thr;
			if (afr_therm_read(&g_therm.dev, &temp, &thr) < 0 || temp <= o->disk_start_temp)
				break;
			if (atomic_load(&g_stop))
				break;
			if (afr_now_ns() - last_msg > 5 * NS_PER_SEC) {
				afr_log_info("Waiting for the disk to cool down: %d C, start at %d C", temp,
				             o->disk_start_temp);
				last_msg = afr_now_ns();
			}
			struct timespec ts = {1, 0};
			nanosleep(&ts, NULL);
		}
	}
	if (want_dio) {
		char derr[256];
		if (afr_dio_open(&g_dio, o->file, c->pf.size, o->readahead, o->io_threads, o->loops, derr,
		                 sizeof(derr)) < 0) {
			afr_log_warn("direct I/O unavailable (%s); reading through the page cache", derr);
		} else if (afr_dio_start(&g_dio, (struct worker **)ws, nw) < 0) {
			afr_log_warn("could not start direct I/O readers; reading through the page cache");
			afr_dio_close(&g_dio);
		} else {
			g_dio_on = 1;
			dio_t0 = afr_now_ns();
			if (!g_dio.locked)
				afr_log_warn("could not lock the direct I/O window in RAM (mlock); it may be "
				             "swapped out under memory pressure");
			for (unsigned i = 0; i < nw; i++) {
				ws[i]->dio = &g_dio;
				ws[i]->peers = (struct worker **)ws;
				ws[i]->npeers = nw;
				ws[i]->fence_lead = lead;
			}
			if (g_therm_on) {
				g_therm.governor = o->disk_max_temp > 0;
				afr_gov_init(&g_therm.gov, o->disk_max_temp);
				g_therm.rate_limit = &g_dio.rate_limit;
				g_therm.bytes_read = &g_dio.bytes_read;
				if (afr_therm_mon_start(&g_therm) < 0)
					g_therm.governor = 0;
				if (g_therm.governor)
					afr_log_info("Thermal governor: keep the disk at or below %d C by limiting "
					             "the read rate",
					             o->disk_max_temp);
			}
			double wnd = (double)g_dio.nslots * DIO_CHUNK;
			double sec = afr_dio_prefill(&g_dio, 300.0);
			afr_log_info("Direct I/O: window %.1f GB (%u x 32 MB), %u reader threads; filled in "
			             "%.1f s (%.2f GB/s)",
			             wnd / (1 << 30), g_dio.nslots, g_dio.nreaders, sec,
			             sec > 0 ? (double)atomic_load(&g_dio.bytes_read) / sec / 1e9 : 0.0);
		}
	}
	if (g_therm_on && !g_therm.running) {
		if (o->disk_max_temp)
			afr_log_warn("--disk-max-temp works with direct I/O only (--io direct)");
		afr_therm_mon_start(&g_therm);
	}
	/* Streaming of the file: readahead ahead of the senders, drop-behind for big files. */
	streamer_t stream = {.pf = &c->pf, .ws = ws, .nw = nw, .window = o->readahead,
	                     .drop_behind = o->drop_behind > 0};
	if (!c->pf.preloaded && !g_dio_on) {
		char ra[32];
		snprintf(ra, sizeof(ra), "%.1f GB", (double)o->readahead / (1 << 30));
		if (afr_stream_start(&stream) == 0) {
			afr_log_info("File streaming: readahead %s, drop-behind %s", ra,
			             stream.drop_behind ? "on (file larger than free RAM)" : "off");
			for (unsigned i = 0; i < nw; i++) {
				ws[i]->peers = (struct worker **)ws;
				ws[i]->npeers = nw;
				ws[i]->fence_lead = lead;
			}
		} else
			afr_log_warn("could not start the readahead thread");
	}
	/* Is something else already sending on this interface (another replayer, for example)?
	 * It would share the link with us and distort every rate we report. */
	{
		uint64_t a, b;
		if (afr_sysfs_read_u64(o->iface, "statistics/tx_packets", &a) == 0) {
			usleep(300000);
			if (afr_sysfs_read_u64(o->iface, "statistics/tx_packets", &b) == 0 && b > a) {
				double pps = (double)(b - a) / 0.3;
				if (pps > 10000) {
					char cnt[32];
					afr_fmt_count(cnt, sizeof(cnt), pps);
					afr_log_warn("%s is already sending %spps before the start: another program "
					             "(another replayer?) shares the link, and the rates below will "
					             "be lower; \"sent (sysfs)\" includes its traffic",
					             o->iface, cnt);
				}
			}
		}
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
		if (g_dio_on) {
			afr_dio_stop(&g_dio);
			afr_dio_close(&g_dio);
		}
		if (g_therm_on)
			afr_therm_mon_stop(&g_therm);
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
	stall_t *stalls = calloc(nw ? nw : 1, sizeof(stall_t)); /* NULL: no watchdog */
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
		link_check(ws, nw, o->iface, sh, now);
		if (stalls)
			watchdog(ws, nw, stalls, c, now);
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
	free(stalls);
	int64_t t_end = t0;
	for (unsigned i = 0; i < nw; i++) {
		pthread_join(ws[i]->th, NULL);
		if (LD(ws[i]->st.t_end) > t_end)
			t_end = LD(ws[i]->st.t_end);
	}
	afr_stream_stop(&stream);
	if (g_dio_on)
		afr_dio_stop(&g_dio);
	if (g_therm_on)
		afr_therm_mon_stop(&g_therm);
	/* Wait for interface counters to catch up (frames may still be queued). */
	usleep(100000);
	take_snap(ws, nw, o->iface, &cur);
	int stopped = atomic_load(&g_stop) && !atomic_load(&sh->failed);
	print_summary(c, &cur, &start, (double)(t_end - t0) / 1e9, ws, nw, json, stopped,
	              atomic_load(&sh->shift));
	if (g_link_down_since) {
		g_link_down_ns += afr_now_ns() - g_link_down_since;
		g_link_down_since = 0;
	}
	if (g_link_outages)
		printf("Link outages: %u, %.1f s in total (the schedule was paused for that time)\n",
		       g_link_outages, (double)g_link_down_ns / 1e9);
	uint64_t fwaits = 0;
	for (unsigned i = 0; i < nw; i++)
		fwaits += LD(ws[i]->st.fence_waits);
	if (fwaits)
		printf("Threads waited %" PRIu64 " times for the slowest one (kept within half the "
		       "readahead window)\n",
		       fwaits);
	if (g_dio_on) {
		uint64_t dw = 0;
		for (unsigned i = 0; i < nw; i++)
			dw += LD(ws[i]->st.dio_waits);
		double secs = (double)(t_end - dio_t0) / 1e9;
		printf("Direct I/O: read %.1f GB, %.2f GB/s on average; senders waited for data %" PRIu64
		       " times, readers waited for the slowest sender %" PRIu64 " times\n",
		       (double)atomic_load(&g_dio.bytes_read) / 1e9,
		       secs > 0 ? (double)atomic_load(&g_dio.bytes_read) / secs / 1e9 : 0.0, dw,
		       (uint64_t)atomic_load(&g_dio.reader_waits));
		if (atomic_load(&g_dio.failed)) {
			afr_log_err("%s", g_dio.err);
			rc = 1;
		}
		afr_dio_close(&g_dio);
	}
	if (g_therm_on) {
		printf("Disk temperature: max %d C, thermal throttling events during the run: %" PRIu64,
		       atomic_load(&g_therm.max_temp), (uint64_t)LD(g_therm.throttle));
		if (g_therm.governor) {
			uint64_t lim = LD(g_dio.rate_limit);
			if (lim)
				printf(", governor read limit at the end: %.2f GB/s", (double)lim / 1e9);
			else
				printf(", governor read limit at the end: none");
		}
		printf("\n");
		afr_therm_close(&g_therm.dev);
	}
	if (!c->pf.preloaded && !g_dio_on)
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
