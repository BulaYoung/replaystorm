#include "idxcache.h"
#include "replay.h"
#include "util.h"

#include <inttypes.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

static afr_ctx_t g_ctx;

static int prepare(afr_ctx_t *c)
{
	opts_t *o = c->o;
	char err[512];

	/* CPUs and thread count. */
	if (o->cpus) {
		c->ncpus = afr_parse_cpulist(o->cpus, c->cpus, MAX_CPUS);
		if (c->ncpus <= 0) {
			afr_log_err("invalid --cpus list '%s'", o->cpus);
			return 2;
		}
	} else {
		c->ncpus = afr_iface_cpus(o->iface, c->cpus, MAX_CPUS, &c->cpus_from_numa);
		if (c->ncpus <= 0) {
			afr_log_err("failed to determine available CPUs");
			return 1;
		}
	}
	c->ip_threads = o->threads ? o->threads : (c->ncpus > 1 ? (unsigned)c->ncpus - 1 : 1);
	if (c->ip_threads >= SHARD_SKIP) {
		afr_log_err("too many threads");
		return 2;
	}

	/* MTU and link speed. */
	c->mtu = o->mtu;
	if (!c->mtu && o->iface) {
		if (afr_iface_mtu(o->iface, &c->mtu) < 0) {
			if (!o->analyze) {
				afr_log_warn("failed to read MTU of %s from sysfs, assuming 1500 (set --mtu)",
				             o->iface);
			}
			c->mtu = 1500;
		}
	}
	if (!c->mtu)
		c->mtu = 1500;
	c->link_bps = o->link_speed_bps;
	c->link_src = "--link-speed";
	if (c->link_bps <= 0 && o->iface && afr_iface_speed(o->iface, &c->link_bps) == 0)
		c->link_src = "ethtool";
	if (c->link_bps <= 0) {
		c->link_bps = 0;
		c->link_src = "unknown";
	}

	/* File. A file larger than RAM is streamed: --preload is pointless (it would
	 * only thrash the page cache), and already sent data is dropped from the cache. */
	{
		struct stat st;
		uint64_t avail = afr_mem_available();
		uint64_t fsize = stat(o->file, &st) == 0 ? (uint64_t)st.st_size : 0;
		int too_big = avail && fsize > avail / 10 * 8;
		if (o->preload && too_big) {
			afr_log_warn("--preload ignored: the file is %.1f GB but only %.1f GB of memory is "
			             "available; the file will be streamed from disk instead",
			             (double)fsize / 1e9, (double)avail / 1e9);
			o->preload = 0;
		}
		c->big_file = too_big;
		if (o->drop_behind < 0)
			o->drop_behind = !o->preload && too_big;
		if (o->preload)
			afr_log_info("Loading the whole file into memory (--preload)...");
	}
	if (pcap_open(&c->pf, o->file, o->preload, err, sizeof(err)) < 0) {
		afr_log_err("%s", err);
		return 1;
	}

	/* Index. */
	int64_t t0 = afr_now_ns();
	idx_cfg_t icfg = {
	    .ip_shards = c->ip_threads,
	    .max_frame = c->mtu + 14,
	    .hash_threads = c->ip_threads < (unsigned)c->ncpus ? c->ip_threads : (unsigned)c->ncpus,
	};
	/* Index cache: next to the pcap with "auto", or an explicit path. */
	char cache_path[4096] = "";
	if (o->index_cache) {
		if (!strcmp(o->index_cache, "auto"))
			snprintf(cache_path, sizeof(cache_path), "%s.rsidx", o->file);
		else
			snprintf(cache_path, sizeof(cache_path), "%s", o->index_cache);
	}
	if (cache_path[0]) {
		char why[256];
		if (afr_idxcache_load(cache_path, &c->pf, &c->ix, why, sizeof(why)) == 1) {
			c->index_cached = 1;
			afr_log_info("Index loaded from cache %s", cache_path);
		} else {
			afr_log_info("Index cache %s not used: %s; building the index", cache_path, why);
		}
	}
	if (!c->index_cached) {
		if (afr_index_build(&c->pf, &icfg, &c->ix, err, sizeof(err)) < 0) {
			afr_log_err("%s", err);
			return 1;
		}
		if (cache_path[0]) {
			int64_t ts0 = afr_now_ns();
			if (afr_idxcache_save(cache_path, &c->pf, &c->ix, err, sizeof(err)) < 0)
				afr_log_warn("index cache not saved: %s", err);
			else
				afr_log_info("Index saved to cache %s (%.1f GB) in %.1f s", cache_path,
				             (double)c->ix.n * 21 / 1e9, (double)(afr_now_ns() - ts0) / 1e9);
		}
	}
	/* Shards for the current thread count and MTU-dependent skipping. */
	if (afr_index_resolve(&c->ix, c->pf.raw_ip, &icfg, err, sizeof(err)) < 0) {
		afr_log_err("%s", err);
		return 1;
	}
	int64_t t1 = afr_now_ns();
	c->index_ns = t1 - t0;
	if (c->ix.n == 0) {
		afr_log_err("the file contains no packets%s",
		            c->ix.tail_problem ? " (file is truncated or corrupt right after the header)" : "");
		return 1;
	}

	/* Timeline. */
	ts_cfg_t tcfg = {
	    .order = o->ts_order,
	    .max_gap = o->max_gap,
	    .exclude_outliers = o->exclude_outliers,
	    .outlier_jump = o->outlier_jump,
	    .now_ns = afr_realtime_ns(),
	    .threads = icfg.hash_threads,
	};
	if (afr_ts_normalize(c->ix.ts, c->ix.shard, c->ix.n, &tcfg, &c->tsr) < 0) {
		afr_log_err("out of memory for timestamp normalization");
		return 1;
	}
	if (c->tsr.n == 0) {
		afr_log_err("all %" PRIu64 " frames would be skipped (see --analyze)", c->ix.st.pkts);
		if (!o->analyze)
			return 1;
	}

	if (o->mode == MODE_MBPS && o->line_frac > 0) {
		/* Pacing works on L2 bytes; convert the wire-rate target using the file's own
		 * ratio of L2 bytes to on-the-wire bytes (preamble, IFG, FCS, 60-byte minimum). */
		if (c->link_bps <= 0) {
			afr_log_err("--mbps line/N%%: link speed is unknown, set it with --link-speed");
			return 2;
		}
		uint64_t l2 = 0;
		for (unsigned s = 0; s < c->ix.nshards; s++)
			l2 += c->ix.shard_bytes[s];
		if (l2 == 0 || c->ix.st.l1_bytes == 0) {
			afr_log_err("--mbps line/N%%: no frames to send");
			return 1;
		}
		double ratio = (double)l2 / (double)c->ix.st.l1_bytes;
		o->mbps = c->link_bps * o->line_frac * ratio / 1e6;
		char b1[64];
		afr_fmt_bps(b1, sizeof(b1), c->link_bps);
		afr_log_info("--mbps %.4g%% of %s link on the wire -> %.0f Mbit/s L2 (L2/wire byte ratio %.4f)",
		             o->line_frac * 100, b1, o->mbps, ratio);
	}

	c->mult = o->mode == MODE_TIMED ? o->multiplier : 1.0;
	if (o->mode == MODE_TIMED && o->duration_ns > 0) {
		if (c->tsr.duration <= 0) {
			afr_log_err("--duration: the file has zero duration by timestamps");
			return 1;
		}
		c->mult = (double)c->tsr.duration / (double)o->duration_ns;
		char b1[64], b2[64];
		afr_fmt_ns(b1, sizeof(b1), (double)c->tsr.duration);
		afr_fmt_ns(b2, sizeof(b2), (double)o->duration_ns);
		afr_log_info("--duration: timeline %s -> %s, multiplier x%.6g", b1, b2, c->mult);
	}

	if (o->analyze || o->mode == MODE_TIMED) {
		rate_cfg_t rcfg = {
		    .mult = c->mult,
		    .timing_res = o->timing_res,
		    .l2_extra = c->pf.raw_ip ? 14 : 0,
		    .nshards = c->ix.nshards,
		    .threads = icfg.hash_threads,
		};
		if (afr_rate_profile(c->ix.ts, c->ix.offlen, c->ix.shard, c->ix.n, c->tsr.monotone, &rcfg,
		                     &c->rr) == 0)
			c->have_rr = 1;
	}
	if (!o->analyze && (o->mode == MODE_MBPS || o->mode == MODE_PPS)) {
		/* Pace in file order: every packet gets its place on a common rate timeline. */
		double ns_per_unit = o->mode == MODE_MBPS ? 8e9 / (o->mbps * 1e6) : 1e9 / o->pps;
		c->rate_lap_ns = afr_rate_timeline(c->ix.ts, c->ix.offlen, c->ix.shard, c->ix.n,
		                                   c->pf.raw_ip ? 14 : 0, o->mode == MODE_PPS,
		                                   ns_per_unit, icfg.hash_threads);
	}
	c->norm_ns = afr_now_ns() - t1;
	return 0;
}

int main(int argc, char **argv)
{
	opts_t o;
	int rc = afr_parse_args(argc, argv, &o);
	if (rc != 0)
		return rc > 0 ? 0 : 2;
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (o.status_query)
		return afr_status_query(&o);

	afr_ctx_t *c = &g_ctx;
	c->o = &o;
	c->pf.fd = -1;
	rc = prepare(c);
	if (rc == 0) {
		if (o.analyze) {
			afr_report_analysis(c);
			afr_report_warnings(c);
		} else {
			rc = afr_replay_run(c);
		}
	}
	afr_index_free(&c->ix);
	pcap_close(&c->pf);
	return rc;
}
