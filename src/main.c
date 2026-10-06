#include "replay.h"
#include "util.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static afr_ctx_t g_ctx;

static int prepare(afr_ctx_t *c)
{
	opts_t *o = c->o;
	char err[512];

	/* Ядра и число потоков. */
	if (o->cpus) {
		c->ncpus = afr_parse_cpulist(o->cpus, c->cpus, MAX_CPUS);
		if (c->ncpus <= 0) {
			afr_log_err("неверный список --cpus '%s'", o->cpus);
			return 2;
		}
	} else {
		c->ncpus = afr_iface_cpus(o->iface, c->cpus, MAX_CPUS, &c->cpus_from_numa);
		if (c->ncpus <= 0) {
			afr_log_err("не удалось определить доступные CPU");
			return 1;
		}
	}
	c->ip_threads = o->threads ? o->threads : (c->ncpus > 1 ? (unsigned)c->ncpus - 1 : 1);
	if (c->ip_threads >= SHARD_SKIP) {
		afr_log_err("слишком много потоков");
		return 2;
	}

	/* MTU и скорость линка. */
	c->mtu = o->mtu;
	if (!c->mtu && o->iface) {
		if (afr_iface_mtu(o->iface, &c->mtu) < 0) {
			if (!o->analyze) {
				afr_log_warn("не удалось прочитать MTU %s из sysfs, считаю 1500 (задайте --mtu)",
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
		c->link_src = "неизвестна";
	}

	/* Файл. */
	if (o->preload)
		afr_log_info("Загружаю файл в память целиком (--preload)...");
	if (pcap_open(&c->pf, o->file, o->preload, err, sizeof(err)) < 0) {
		afr_log_err("%s", err);
		return 1;
	}

	/* Индекс. */
	int64_t t0 = afr_now_ns();
	idx_cfg_t icfg = {
	    .ip_shards = c->ip_threads,
	    .max_frame = c->mtu + 14,
	    .hash_threads = c->ip_threads < (unsigned)c->ncpus ? c->ip_threads : (unsigned)c->ncpus,
	};
	if (afr_index_build(&c->pf, &icfg, &c->ix, err, sizeof(err)) < 0) {
		afr_log_err("%s", err);
		return 1;
	}
	int64_t t1 = afr_now_ns();
	c->index_ns = t1 - t0;
	if (c->ix.n == 0) {
		afr_log_err("в файле нет ни одного пакета%s",
		            c->ix.tail_problem ? " (файл обрезан или повреждён сразу после заголовка)" : "");
		return 1;
	}

	/* Шкала времени. */
	ts_cfg_t tcfg = {
	    .order = o->ts_order,
	    .max_gap = o->max_gap,
	    .exclude_outliers = o->exclude_outliers,
	    .outlier_jump = o->outlier_jump,
	    .now_ns = afr_realtime_ns(),
	};
	if (afr_ts_normalize(c->ix.ts, c->ix.shard, c->ix.n, &tcfg, &c->tsr) < 0) {
		afr_log_err("нет памяти для нормализации тайм-стампов");
		return 1;
	}
	if (c->tsr.n == 0) {
		afr_log_err("все %" PRIu64 " кадров будут пропущены (см. --analyze)", c->ix.st.pkts);
		if (!o->analyze)
			return 1;
	}

	c->mult = o->mode == MODE_TIMED ? o->multiplier : 1.0;
	if (o->mode == MODE_TIMED && o->duration_ns > 0) {
		if (c->tsr.duration <= 0) {
			afr_log_err("--duration: у файла нулевая длительность по тайм-стампам");
			return 1;
		}
		c->mult = (double)c->tsr.duration / (double)o->duration_ns;
		char b1[64], b2[64];
		afr_fmt_ns(b1, sizeof(b1), (double)c->tsr.duration);
		afr_fmt_ns(b2, sizeof(b2), (double)o->duration_ns);
		afr_log_info("--duration: шкала %s -> %s, множитель x%.6g", b1, b2, c->mult);
	}

	if (o->analyze || o->mode == MODE_TIMED) {
		rate_cfg_t rcfg = {
		    .mult = c->mult,
		    .timing_res = o->timing_res,
		    .l2_extra = c->pf.raw_ip ? 14 : 0,
		    .nshards = c->ix.nshards,
		};
		if (afr_rate_profile(c->ix.ts, c->ix.offlen, c->ix.shard, c->ix.n, c->tsr.monotone, &rcfg,
		                     &c->rr) == 0)
			c->have_rr = 1;
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
