#include "replay.h"
#include "util.h"

#include <inttypes.h>
#include <string.h>

static const char *order_name(int o)
{
	return o == TS_ORDER_ASIS ? "asis" : o == TS_ORDER_SORT ? "sort" : "clamp";
}

static double pct(uint64_t a, uint64_t b)
{
	return b ? 100.0 * (double)a / (double)b : 0.0;
}

static void fmt_bytes(char *buf, size_t n, double b)
{
	if (b >= 1e9)
		snprintf(buf, n, "%.2f GB", b / 1e9);
	else if (b >= 1e6)
		snprintf(buf, n, "%.2f MB", b / 1e6);
	else if (b >= 1e3)
		snprintf(buf, n, "%.2f KB", b / 1e3);
	else
		snprintf(buf, n, "%.0f B", b);
}

void afr_report_analysis(const afr_ctx_t *c)
{
	const pcap_file_t *pf = &c->pf;
	const pkt_index_t *ix = &c->ix;
	const ts_result_t *t = &c->tsr;
	const idx_stats_t *s = &ix->st;
	char b1[96], b2[96], b3[96];

	fmt_bytes(b1, sizeof(b1), (double)pf->size);
	printf("File: %s (%s)\n", c->o->file, b1);
	printf("  format: pcap, %s, %s, linktype %u (%s), snaplen %u\n",
	       pf->nsec ? "nanoseconds" : "microseconds",
	       pf->swapped ? "swapped byte order" : "native byte order", pf->linktype,
	       pcap_linktype_name(pf->linktype), pf->snaplen);
	if (ix->tail_problem)
		printf("  WARNING: file %s at offset %" PRIu64 ", cannot parse further\n",
		       ix->tail_problem == PCAP_REC_TRUNCATED ? "truncated" : "corrupt", ix->tail_off);
	fmt_bytes(b1, sizeof(b1), (double)s->bytes);
	printf("Packets: %" PRIu64 " (%s), to send: %" PRIu64 "\n", s->pkts, b1, t->n);
	afr_fmt_ns(b1, sizeof(b1), (double)(c->index_ns));
	afr_fmt_ns(b2, sizeof(b2), (double)(c->norm_ns));
	printf("Index %s in %s, timeline in %s (%u threads)\n",
	       c->index_cached ? "loaded from cache" : "built", b1, b2, c->ip_threads);

	/* Time */
	if (t->n > 0) {
		afr_fmt_abs_ts(b1, sizeof(b1), t->min_abs);
		afr_fmt_abs_ts(b2, sizeof(b2), t->max_abs);
		afr_fmt_ns(b3, sizeof(b3), (double)(t->max_abs - t->min_abs));
		printf("Timestamps: from %s to %s (%s)\n", b1, b2, b3);
		afr_fmt_ns(b1, sizeof(b1), (double)t->duration);
		printf("Replay timeline duration: %s (ts-order=%s", b1, order_name(c->o->ts_order));
		if (c->o->max_gap > 0) {
			afr_fmt_ns(b2, sizeof(b2), (double)c->o->max_gap);
			printf(", max-gap=%s", b2);
		}
		printf(")\n");
	}
	if (c->have_rr && c->rr.wall_duration_s > 0) {
		const rate_result_t *r = &c->rr;
		afr_fmt_bps(b1, sizeof(b1), r->avg_bps);
		afr_fmt_count(b2, sizeof(b2), (double)r->pkts / r->wall_duration_s);
		printf("Average rate (x%g): %s, %spps\n", c->mult, b1, b2);
		printf("Peak rate (x%g), L2 / on the wire with preamble and IFG:\n", c->mult);
		for (int w = 0; w < RATE_WINDOWS; w++) {
			afr_fmt_bps(b1, sizeof(b1), r->peak_bps[w]);
			afr_fmt_bps(b2, sizeof(b2), r->peak_l1_bps[w]);
			printf("  window %s: %s / %s%s\n", afr_rate_window_names[w], b1, b2,
			       r->wall_duration_s * 1e9 < (double)afr_rate_windows_ns[w]
			           ? " (file shorter than window: total volume divided by window)"
			           : "");
		}
		if (r->gaps_total) {
			afr_fmt_ns(b1, sizeof(b1), (double)c->o->timing_res);
			printf("Intervals within shards (x%g): < 1 us %.2f%%, < 10 us %.2f%%, "
			       "< 100 us %.2f%%; shorter than precision %s: %.2f%% (will go out in bursts)\n",
			       c->mult, pct(r->gaps_lt[0], r->gaps_total), pct(r->gaps_lt[1], r->gaps_total),
			       pct(r->gaps_lt[2], r->gaps_total), b1, pct(r->gaps_below_res, r->gaps_total));
		}
	}

	/* Anomalies */
	printf("Timestamp anomalies:\n");
	if (t->backward) {
		afr_fmt_ns(b1, sizeof(b1), (double)t->max_backward);
		printf("  backward in time: %" PRIu64 " packets (%.3f%%), max backward jump %s "
		       "(packet #%" PRIu64 ")\n",
		       t->backward, pct(t->backward, t->n), b1, t->max_backward_idx + 1);
	} else {
		printf("  backward in time: none\n");
	}
	if (t->outliers) {
		printf("  outliers: %" PRIu64 " (ts=0: %" PRIu64 ", before 1990: %" PRIu64
		       ", in the future: %" PRIu64 ", short clock jump: %" PRIu64 ") - %s\n",
		       t->outliers, t->outl_zero, t->outl_past, t->outl_future, t->outl_spike,
		       t->excluded ? "excluded from timeline" : "kept in timeline (to exclude: --ts-outliers exclude)");
	} else {
		printf("  outliers: none\n");
	}
	if (c->o->max_gap > 0) {
		afr_fmt_ns(b1, sizeof(b1), (double)t->gap_removed);
		printf("  pauses longer than max-gap: %" PRIu64 ", removed %s\n", t->gaps_over, b1);
	}
	if (t->ntop) {
		printf("  top-%d pauses:\n", t->ntop);
		for (int i = 0; i < t->ntop; i++) {
			afr_fmt_ns(b1, sizeof(b1), (double)t->top[i].len);
			afr_fmt_ns(b2, sizeof(b2), (double)(t->top[i].at - t->min_abs));
			afr_fmt_abs_ts(b3, sizeof(b3), t->top[i].at);
			printf("   %2d. %-12s after mark +%s (%s)", i + 1, b1, b2, b3);
			if (t->top[i].idx_known)
				printf(", before packet #%" PRIu64, t->top[i].idx + 1);
			printf("\n");
		}
	}

	/* Composition */
	printf("Traffic composition:\n");
	printf("  IPv4 %.2f%%, IPv6 %.2f%%, non-IP %.2f%% (ARP %" PRIu64 ", 802.3/LLC (STP etc.) %" PRIu64
	       ", LLDP %" PRIu64 ", other %" PRIu64 ")\n",
	       pct(s->ipv4, s->pkts), pct(s->ipv6, s->pkts), pct(s->nonip, s->pkts), s->l2kind[L2K_ARP],
	       s->l2kind[L2K_LLC], s->l2kind[L2K_LLDP], s->l2kind[L2K_OTHER]);
	printf("  VLAN %.2f%% (of which QinQ and deeper %" PRIu64 "), MPLS %" PRIu64 ", PPPoE %" PRIu64
	       ", IP fragments %" PRIu64 "\n",
	       pct(s->vlan, s->pkts), s->qinq, s->mpls, s->pppoe, s->frag);

	/* Skipped */
	uint64_t skipped = 0;
	for (int k = 0; k < SKIP_REASONS; k++)
		skipped += s->skipped[k];
	printf("Skipped frames: %" PRIu64, skipped);
	if (skipped)
		printf(" (larger than MTU+14=%u, +4 for 802.1Q: %" PRIu64 "; shorter than 14 bytes: %" PRIu64
		       "; RAW without IPv4/IPv6: %" PRIu64 ")",
		       c->mtu + 14, s->skipped[SKIP_TOO_BIG], s->skipped[SKIP_TOO_SMALL],
		       s->skipped[SKIP_BAD_RAW]);
	printf("\n");
	printf("Truncated at capture (caplen < origlen): %" PRIu64 " - will be sent with length caplen\n",
	       s->truncated_caplen);

	/* Shards */
	uint64_t maxp = 0, sum = 0;
	printf("Distribution across shards (%u IP + 1 non-IP):\n", c->ip_threads);
	for (unsigned i = 0; i < ix->nshards; i++) {
		fmt_bytes(b1, sizeof(b1), (double)ix->shard_bytes[i]);
		printf("  %s %3u: %12" PRIu64 " packets (%5.2f%%), %s\n",
		       i == c->ip_threads ? "non-IP" : "shard ", i, ix->shard_pkts[i],
		       pct(ix->shard_pkts[i], t->n), b1);
		if (i < c->ip_threads) {
			sum += ix->shard_bytes[i];
			if (ix->shard_bytes[i] > maxp)
				maxp = ix->shard_bytes[i];
		}
	}
	if (sum && c->ip_threads > 1)
		printf("  byte imbalance: busiest shard = %.2f x average\n",
		       (double)maxp / ((double)sum / c->ip_threads));
}

int afr_report_warnings(const afr_ctx_t *c)
{
	int n = 0;
	const ts_result_t *t = &c->tsr;
	char b1[96], b2[96], b3[96];
	const int timed = c->o->mode == MODE_TIMED;

	if (t->outliers && !t->excluded) {
		afr_log_warn("found %" PRIu64 " timestamp outliers (ts=0/before 1990/future/clock "
		             "jump); they distort the timeline. To exclude: --ts-outliers exclude",
		             t->outliers);
		n++;
	}
	if (t->backward && c->o->ts_order == TS_ORDER_ASIS) {
		afr_log_warn("%" PRIu64 " packets go backward in time; with ts-order=asis they "
		             "will be sent without waiting (alternatives: clamp, sort)",
		             t->backward);
		n++;
	}
	if (timed && c->mult > 0) {
		double wall = (double)t->duration / c->mult;
		if (wall > 86400e9) {
			afr_fmt_ns(b1, sizeof(b1), wall);
			afr_log_warn("replay will take %s; check outliers and pauses (--max-gap, "
			             "--ts-outliers exclude, --analyze)",
			             b1);
			n++;
		}
	}
	if (timed && c->have_rr && c->link_bps > 0) {
		for (int w = 0; w < RATE_WINDOWS; w++) {
			if (c->rr.peak_l1_bps[w] > c->link_bps) {
				afr_fmt_bps(b1, sizeof(b1), c->rr.peak_l1_bps[w]);
				afr_fmt_bps(b2, sizeof(b2), c->link_bps);
				afr_log_warn("at x%g the %s peak is %s (with preamble and IFG), exceeding the link %s "
				             "(%s); timing will be violated",
				             c->mult, afr_rate_window_names[w], b1, b2, c->link_src);
				n++;
			}
		}
	}
	if (timed && c->have_rr && c->rr.gaps_total && c->rr.gaps_below_res) {
		double p = pct(c->rr.gaps_below_res, c->rr.gaps_total);
		if (p >= 1.0) {
			afr_fmt_ns(b1, sizeof(b1), (double)c->o->timing_res);
			afr_log_warn("at x%g %.1f%% of intervals within shards are shorter than achievable precision %s: "
			             "these packets will effectively go out in bursts",
			             c->mult, p, b1);
			n++;
		}
	}
	if (c->o->mode == MODE_MBPS && c->link_bps > 0) {
		/* Compare on the wire: L2 bytes plus preamble, IFG, FCS (file's own ratio). */
		uint64_t l2 = 0;
		for (unsigned s = 0; s < c->ix.nshards; s++)
			l2 += c->ix.shard_bytes[s];
		double wire = c->o->mbps * 1e6 *
		              (l2 ? (double)c->ix.st.l1_bytes / (double)l2 : 1.0);
		if (wire > c->link_bps * 1.0001) {
			afr_fmt_bps(b1, sizeof(b1), c->o->mbps * 1e6);
			afr_fmt_bps(b2, sizeof(b2), wire);
			afr_fmt_bps(b3, sizeof(b3), c->link_bps);
			afr_log_warn("requested %s L2 = %s on the wire, above the %s link: the NIC will cap "
			             "the rate and threads will spend time on ENOBUFS; use --mbps line or "
			             "--mbps 99%%",
			             b1, b2, b3);
			n++;
		}
	}
	uint64_t skipped = 0;
	for (int k = 0; k < SKIP_REASONS; k++)
		skipped += c->ix.st.skipped[k];
	if (skipped) {
		afr_log_warn("%" PRIu64 " frames will not be sent (larger than MTU %u+14 or shorter than 14 "
		             "bytes), details: --analyze",
		             skipped, c->mtu);
		n++;
	}
	if (c->ix.tail_problem) {
		afr_log_warn("file %s at offset %" PRIu64 "; only the part before it will be sent",
		             c->ix.tail_problem == PCAP_REC_TRUNCATED ? "truncated" : "corrupt",
		             c->ix.tail_off);
		n++;
	}
	return n;
}
