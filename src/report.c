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
		snprintf(buf, n, "%.2f ГБ", b / 1e9);
	else if (b >= 1e6)
		snprintf(buf, n, "%.2f МБ", b / 1e6);
	else if (b >= 1e3)
		snprintf(buf, n, "%.2f КБ", b / 1e3);
	else
		snprintf(buf, n, "%.0f Б", b);
}

void afr_report_analysis(const afr_ctx_t *c)
{
	const pcap_file_t *pf = &c->pf;
	const pkt_index_t *ix = &c->ix;
	const ts_result_t *t = &c->tsr;
	const idx_stats_t *s = &ix->st;
	char b1[96], b2[96], b3[96];

	fmt_bytes(b1, sizeof(b1), (double)pf->size);
	printf("Файл: %s (%s)\n", c->o->file, b1);
	printf("  формат: pcap, %s, %s, linktype %u (%s), snaplen %u\n",
	       pf->nsec ? "наносекунды" : "микросекунды",
	       pf->swapped ? "обратный порядок байт" : "родной порядок байт", pf->linktype,
	       pcap_linktype_name(pf->linktype), pf->snaplen);
	if (ix->tail_problem)
		printf("  ВНИМАНИЕ: файл %s на смещении %" PRIu64 ", дальше разбор невозможен\n",
		       ix->tail_problem == PCAP_REC_TRUNCATED ? "обрезан" : "повреждён", ix->tail_off);
	fmt_bytes(b1, sizeof(b1), (double)s->bytes);
	printf("Пакетов: %" PRIu64 " (%s), к отправке: %" PRIu64 "\n", s->pkts, b1, t->n);
	afr_fmt_ns(b1, sizeof(b1), (double)(c->index_ns));
	afr_fmt_ns(b2, sizeof(b2), (double)(c->norm_ns));
	printf("Индекс построен за %s, шкала времени — за %s (%u потоков хеширования)\n", b1, b2,
	       c->ip_threads);

	/* Время */
	if (t->n > 0) {
		afr_fmt_abs_ts(b1, sizeof(b1), t->min_abs);
		afr_fmt_abs_ts(b2, sizeof(b2), t->max_abs);
		afr_fmt_ns(b3, sizeof(b3), (double)(t->max_abs - t->min_abs));
		printf("Тайм-стампы: от %s до %s (%s)\n", b1, b2, b3);
		afr_fmt_ns(b1, sizeof(b1), (double)t->duration);
		printf("Длительность шкалы реплея: %s (ts-order=%s", b1, order_name(c->o->ts_order));
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
		printf("Средняя скорость (x%g): %s, %spps\n", c->mult, b1, b2);
		printf("Пиковая скорость (x%g), L2 / на линии с преамбулой и IFG:\n", c->mult);
		for (int w = 0; w < RATE_WINDOWS; w++) {
			afr_fmt_bps(b1, sizeof(b1), r->peak_bps[w]);
			afr_fmt_bps(b2, sizeof(b2), r->peak_l1_bps[w]);
			printf("  окно %s: %s / %s%s\n", afr_rate_window_names[w], b1, b2,
			       r->wall_duration_s * 1e9 < (double)afr_rate_windows_ns[w]
			           ? " (файл короче окна: весь объём, делённый на окно)"
			           : "");
		}
		if (r->gaps_total) {
			afr_fmt_ns(b1, sizeof(b1), (double)c->o->timing_res);
			printf("Интервалы внутри шардов (x%g): < 1 мкс %.2f%%, < 10 мкс %.2f%%, "
			       "< 100 мкс %.2f%%; короче точности %s: %.2f%% (уйдут пачками)\n",
			       c->mult, pct(r->gaps_lt[0], r->gaps_total), pct(r->gaps_lt[1], r->gaps_total),
			       pct(r->gaps_lt[2], r->gaps_total), b1, pct(r->gaps_below_res, r->gaps_total));
		}
	}

	/* Аномалии */
	printf("Аномалии тайм-стампов:\n");
	if (t->backward) {
		afr_fmt_ns(b1, sizeof(b1), (double)t->max_backward);
		printf("  назад во времени: %" PRIu64 " пакетов (%.3f%%), максимальный скачок назад %s "
		       "(пакет #%" PRIu64 ")\n",
		       t->backward, pct(t->backward, t->n), b1, t->max_backward_idx + 1);
	} else {
		printf("  назад во времени: нет\n");
	}
	if (t->outliers) {
		printf("  выбросы: %" PRIu64 " (ts=0: %" PRIu64 ", до 1990 г.: %" PRIu64
		       ", в будущем: %" PRIu64 ", кратковременный скачок часов: %" PRIu64 ") — %s\n",
		       t->outliers, t->outl_zero, t->outl_past, t->outl_future, t->outl_spike,
		       t->excluded ? "исключены из шкалы" : "в шкале (исключить: --ts-outliers exclude)");
	} else {
		printf("  выбросы: нет\n");
	}
	if (c->o->max_gap > 0) {
		afr_fmt_ns(b1, sizeof(b1), (double)t->gap_removed);
		printf("  пауз длиннее max-gap: %" PRIu64 ", вырезано %s\n", t->gaps_over, b1);
	}
	if (t->ntop) {
		printf("  топ-%d пауз:\n", t->ntop);
		for (int i = 0; i < t->ntop; i++) {
			afr_fmt_ns(b1, sizeof(b1), (double)t->top[i].len);
			afr_fmt_ns(b2, sizeof(b2), (double)(t->top[i].at - t->min_abs));
			afr_fmt_abs_ts(b3, sizeof(b3), t->top[i].at);
			printf("   %2d. %-12s после отметки +%s (%s)", i + 1, b1, b2, b3);
			if (t->top[i].idx_known)
				printf(", перед пакетом #%" PRIu64, t->top[i].idx + 1);
			printf("\n");
		}
	}

	/* Состав */
	printf("Состав трафика:\n");
	printf("  IPv4 %.2f%%, IPv6 %.2f%%, не-IP %.2f%% (ARP %" PRIu64 ", 802.3/LLC (STP и др.) %" PRIu64
	       ", LLDP %" PRIu64 ", прочие %" PRIu64 ")\n",
	       pct(s->ipv4, s->pkts), pct(s->ipv6, s->pkts), pct(s->nonip, s->pkts), s->l2kind[L2K_ARP],
	       s->l2kind[L2K_LLC], s->l2kind[L2K_LLDP], s->l2kind[L2K_OTHER]);
	printf("  VLAN %.2f%% (из них QinQ и глубже %" PRIu64 "), MPLS %" PRIu64 ", PPPoE %" PRIu64
	       ", IP-фрагменты %" PRIu64 "\n",
	       pct(s->vlan, s->pkts), s->qinq, s->mpls, s->pppoe, s->frag);

	/* Пропуски */
	uint64_t skipped = 0;
	for (int k = 0; k < SKIP_REASONS; k++)
		skipped += s->skipped[k];
	printf("Пропущенные кадры: %" PRIu64, skipped);
	if (skipped)
		printf(" (больше MTU+14=%u, +4 для 802.1Q: %" PRIu64 "; короче 14 байт: %" PRIu64
		       "; RAW без IPv4/IPv6: %" PRIu64 ")",
		       c->mtu + 14, s->skipped[SKIP_TOO_BIG], s->skipped[SKIP_TOO_SMALL],
		       s->skipped[SKIP_BAD_RAW]);
	printf("\n");
	printf("Обрезанные при захвате (caplen < origlen): %" PRIu64 " — уйдут длиной caplen\n",
	       s->truncated_caplen);

	/* Шарды */
	uint64_t maxp = 0, sum = 0;
	printf("Распределение по шардам (%u IP + 1 не-IP):\n", c->ip_threads);
	for (unsigned i = 0; i < ix->nshards; i++) {
		fmt_bytes(b1, sizeof(b1), (double)ix->shard_bytes[i]);
		printf("  %s %3u: %12" PRIu64 " пакетов (%5.2f%%), %s\n",
		       i == c->ip_threads ? "не-IP" : "шард ", i, ix->shard_pkts[i],
		       pct(ix->shard_pkts[i], t->n), b1);
		if (i < c->ip_threads) {
			sum += ix->shard_bytes[i];
			if (ix->shard_bytes[i] > maxp)
				maxp = ix->shard_bytes[i];
		}
	}
	if (sum && c->ip_threads > 1)
		printf("  дисбаланс по байтам: самый загруженный шард = %.2f x среднего\n",
		       (double)maxp / ((double)sum / c->ip_threads));
}

int afr_report_warnings(const afr_ctx_t *c)
{
	int n = 0;
	const ts_result_t *t = &c->tsr;
	char b1[96], b2[96], b3[96];
	const int timed = c->o->mode == MODE_TIMED;

	if (t->outliers && !t->excluded) {
		afr_log_warn("найдено %" PRIu64 " выбросов тайм-стампов (ts=0/до 1990/будущее/скачок "
		             "часов); они искажают шкалу. Исключить: --ts-outliers exclude",
		             t->outliers);
		n++;
	}
	if (t->backward && c->o->ts_order == TS_ORDER_ASIS) {
		afr_log_warn("%" PRIu64 " пакетов идут назад во времени; при ts-order=asis они "
		             "отправятся без ожидания (варианты: clamp, sort)",
		             t->backward);
		n++;
	}
	if (timed && c->mult > 0) {
		double wall = (double)t->duration / c->mult;
		if (wall > 86400e9) {
			afr_fmt_ns(b1, sizeof(b1), wall);
			afr_log_warn("проигрыш займёт %s — проверьте выбросы и паузы (--max-gap, "
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
				afr_log_warn("на x%g пик за %s — %s (с преамбулой и IFG), это больше линка %s "
				             "(%s); тайминг будет нарушен",
				             c->mult, afr_rate_window_names[w], b1, b2, c->link_src);
				n++;
			}
		}
	}
	if (timed && c->have_rr && c->rr.gaps_total && c->rr.gaps_below_res) {
		double p = pct(c->rr.gaps_below_res, c->rr.gaps_total);
		if (p >= 1.0) {
			afr_fmt_ns(b1, sizeof(b1), (double)c->o->timing_res);
			afr_log_warn("на x%g %.1f%% интервалов внутри шардов короче достижимой точности %s: "
			             "эти пакеты фактически уйдут пачками",
			             c->mult, p, b1);
			n++;
		}
	}
	if ((c->o->mode == MODE_MBPS) && c->link_bps > 0 && c->o->mbps * 1e6 > c->link_bps) {
		afr_fmt_bps(b1, sizeof(b1), c->o->mbps * 1e6);
		afr_fmt_bps(b2, sizeof(b2), c->link_bps);
		afr_log_warn("запрошено %s, а линк %s", b1, b2);
		n++;
	}
	uint64_t skipped = 0;
	for (int k = 0; k < SKIP_REASONS; k++)
		skipped += c->ix.st.skipped[k];
	if (skipped) {
		afr_log_warn("%" PRIu64 " кадров не будут отправлены (больше MTU %u+14 или короче 14 "
		             "байт), подробности: --analyze",
		             skipped, c->mtu);
		n++;
	}
	if (c->ix.tail_problem) {
		afr_log_warn("файл %s на смещении %" PRIu64 "; отправлено будет только то, что до него",
		             c->ix.tail_problem == PCAP_REC_TRUNCATED ? "обрезан" : "повреждён",
		             c->ix.tail_off);
		n++;
	}
	(void)b3;
	return n;
}
