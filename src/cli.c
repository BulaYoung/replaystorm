#include "cli.h"

#include "clock.h"
#include "sched.h"
#include "util.h"

#include <getopt.h>
#include <string.h>

void afr_usage(FILE *f)
{
	fputs(
	    "afreplay — многопоточный реплеер pcap через AF_PACKET с сохранением L2\n"
	    "\n"
	    "Использование:\n"
	    "  afreplay -i ИНТЕРФЕЙС [опции] ФАЙЛ.pcap\n"
	    "  afreplay --analyze [опции] ФАЙЛ.pcap\n"
	    "\n"
	    "Режимы скорости (взаимоисключающие, по умолчанию --multiplier 1):\n"
	    "  --topspeed              максимально быстро\n"
	    "  --mbps X                фиксированная общая скорость, Мбит/с (L2, без FCS)\n"
	    "  --pps X                 фиксированная общая скорость, пакетов/с\n"
	    "  --multiplier X          реплей по тайм-стампам: 2.0 — вдвое быстрее, 0.5 — вдвое\n"
	    "                          медленнее, 1.0 — реальное время\n"
	    "  --duration T            подобрать множитель, чтобы файл проигрался за T\n"
	    "  --loop N                проиграть N раз (0 — бесконечно), по умолчанию 1\n"
	    "\n"
	    "Тайм-стампы:\n"
	    "  --ts-order MODE         asis | clamp | sort (по умолчанию clamp)\n"
	    "                            asis  — как есть, «назад во времени» шлётся без ожидания\n"
	    "                            clamp — «назад во времени» заменяется предыдущей меткой\n"
	    "                            sort  — стабильная сортировка индекса по меткам\n"
	    "  --max-gap T             сжимать паузы длиннее T до T\n"
	    "  --ts-outliers MODE      report | exclude: выбросы (ts=0, до 1990, будущее,\n"
	    "                          кратковременный скачок часов) только сообщать или\n"
	    "                          исключить из расчёта шкалы (по умолчанию report)\n"
	    "  --outlier-jump T        порог скачка часов для поиска выбросов (по умолчанию 60s,\n"
	    "                          0 — не искать)\n"
	    "  --lag-policy P          catchup | rebase: при отставании догонять или сдвигать T0\n"
	    "  --lag-threshold T       отставание, после которого срабатывает rebase (10ms)\n"
	    "  --spin-us N             последние N мкс ожидания — busy-spin (50)\n"
	    "  --timing-res T          достижимая точность тайминга для оценки пачек (2us)\n"
	    "  --clock C               auto | tsc | monotonic: часы горячего цикла. auto берёт TSC,\n"
	    "                          если clocksource ядра не tsc (тогда clock_gettime медленный)\n"
	    "\n"
	    "Отправка:\n"
	    "  -i, --interface IF      интерфейс\n"
	    "  -t, --threads N         потоков для IP-трафика (по умолчанию: CPU узла NUMA - 1);\n"
	    "                          не-IP кадры всегда идут отдельным потоком\n"
	    "  --cpus LIST             ядра для потоков, например 2-9,12 (по умолчанию —\n"
	    "                          /sys/class/net/IF/device/local_cpulist)\n"
	    "  --batch N               кадров на один send() (64)\n"
	    "  --ring-frames N         кадров в TX_RING каждого потока (4096)\n"
	    "  --qdisc-bypass          PACKET_QDISC_BYPASS: мимо qdisc прямо в драйвер\n"
	    "  --packet-loss           PACKET_LOSS: ядро молча пропускает битые кадры\n"
	    "  --link-speed X          скорость линка (25G, 10000M); по умолчанию из ethtool\n"
	    "  --mtu N                 MTU (по умолчанию с интерфейса, для --analyze 1500)\n"
	    "\n"
	    "Вход:\n"
	    "  --preload               загрузить файл в память целиком до старта\n"
	    "  --smac MAC, --dmac MAC  MAC-адреса синтетического Ethernet для RAW IP\n"
	    "\n"
	    "Зацикливание с модификацией:\n"
	    "  --loop-mutate WHAT      ip | port | ip,port — на круге k>0 сдвигать адреса/порты,\n"
	    "                          чтобы сенсор видел новые сессии (L2 не трогается)\n"
	    "  --mutate-ip-offset A    сдвиг IPv4 на круг, как адрес (по умолчанию 0.1.0.0)\n"
	    "  --mutate-port-step N    сдвиг портов >= 1024 на круг (по умолчанию 1)\n"
	    "\n"
	    "Вывод:\n"
	    "  --analyze               только анализ файла, без отправки\n"
	    "  --stats-json FILE       писать статистику в JSON\n"
	    "  -q, --quiet             не печатать ежесекундную статистику\n"
	    "  -h, --help              эта справка\n"
	    "\n"
	    "Примеры:\n"
	    "  afreplay --analyze big.pcap\n"
	    "  afreplay --analyze --multiplier 10 --link-speed 25G big.pcap\n"
	    "  afreplay -i ens1f0 --topspeed --qdisc-bypass -t 12 big.pcap\n"
	    "  afreplay -i ens1f0 --mbps 20000 --loop 0 big.pcap\n"
	    "  afreplay -i ens1f0 --multiplier 2 --max-gap 1s --ts-order sort big.pcap\n"
	    "  afreplay -i ens1f0 --duration 10m --stats-json run.json big.pcap\n"
	    "  afreplay -i ens1f0 --loop 5 --loop-mutate ip,port big.pcap\n"
	    "  afreplay -i ens1f0 --smac 02:00:00:00:00:01 --dmac 02:00:00:00:00:02 raw.pcap\n"
	    "\n"
	    "Код выхода: 0 — успех (в т.ч. остановка по SIGINT/SIGTERM), 1 — ошибка выполнения,\n"
	    "2 — ошибка в аргументах.\n",
	    f);
}

enum {
	O_TOPSPEED = 1000,
	O_MBPS,
	O_PPS,
	O_MULT,
	O_DURATION,
	O_LOOP,
	O_TS_ORDER,
	O_MAX_GAP,
	O_TS_OUTLIERS,
	O_OUTLIER_JUMP,
	O_LAG_POLICY,
	O_LAG_THRESHOLD,
	O_SPIN_US,
	O_TIMING_RES,
	O_CLOCK,
	O_CPUS,
	O_BATCH,
	O_RING,
	O_QDISC,
	O_LOSS,
	O_LINK,
	O_MTU,
	O_PRELOAD,
	O_SMAC,
	O_DMAC,
	O_ANALYZE,
	O_JSON,
	O_MUTATE,
	O_MUT_IP,
	O_MUT_PORT,
};

static const struct option long_opts[] = {
    {"interface", required_argument, NULL, 'i'},
    {"threads", required_argument, NULL, 't'},
    {"quiet", no_argument, NULL, 'q'},
    {"help", no_argument, NULL, 'h'},
    {"topspeed", no_argument, NULL, O_TOPSPEED},
    {"mbps", required_argument, NULL, O_MBPS},
    {"pps", required_argument, NULL, O_PPS},
    {"multiplier", required_argument, NULL, O_MULT},
    {"duration", required_argument, NULL, O_DURATION},
    {"loop", required_argument, NULL, O_LOOP},
    {"ts-order", required_argument, NULL, O_TS_ORDER},
    {"max-gap", required_argument, NULL, O_MAX_GAP},
    {"ts-outliers", required_argument, NULL, O_TS_OUTLIERS},
    {"outlier-jump", required_argument, NULL, O_OUTLIER_JUMP},
    {"lag-policy", required_argument, NULL, O_LAG_POLICY},
    {"lag-threshold", required_argument, NULL, O_LAG_THRESHOLD},
    {"spin-us", required_argument, NULL, O_SPIN_US},
    {"timing-res", required_argument, NULL, O_TIMING_RES},
    {"clock", required_argument, NULL, O_CLOCK},
    {"cpus", required_argument, NULL, O_CPUS},
    {"batch", required_argument, NULL, O_BATCH},
    {"ring-frames", required_argument, NULL, O_RING},
    {"qdisc-bypass", no_argument, NULL, O_QDISC},
    {"packet-loss", no_argument, NULL, O_LOSS},
    {"link-speed", required_argument, NULL, O_LINK},
    {"mtu", required_argument, NULL, O_MTU},
    {"preload", no_argument, NULL, O_PRELOAD},
    {"smac", required_argument, NULL, O_SMAC},
    {"dmac", required_argument, NULL, O_DMAC},
    {"analyze", no_argument, NULL, O_ANALYZE},
    {"stats-json", required_argument, NULL, O_JSON},
    {"loop-mutate", required_argument, NULL, O_MUTATE},
    {"mutate-ip-offset", required_argument, NULL, O_MUT_IP},
    {"mutate-port-step", required_argument, NULL, O_MUT_PORT},
    {NULL, 0, NULL, 0},
};

static int bad(const char *opt, const char *val)
{
	afr_log_err("неверное значение %s: '%s' (см. --help)", opt, val);
	return -1;
}

int afr_parse_args(int argc, char **argv, opts_t *o)
{
	memset(o, 0, sizeof(*o));
	o->mode = MODE_TIMED;
	o->multiplier = 1.0;
	o->loops = 1;
	o->ts_order = TS_ORDER_CLAMP;
	o->outlier_jump = 60 * NS_PER_SEC;
	o->lag_policy = LAG_CATCHUP;
	o->lag_threshold = 10 * NS_PER_MS;
	o->spin_ns = 50 * NS_PER_US;
	o->timing_res = 2 * NS_PER_US;
	o->batch = 64;
	o->ring_frames = 4096;
	static const uint8_t smac[6] = {0x02, 0, 0, 0, 0, 0x01}, dmac[6] = {0x02, 0, 0, 0, 0, 0x02};
	memcpy(o->smac, smac, 6);
	memcpy(o->dmac, dmac, 6);
	o->mutate_ip_offset = 0x00010000u;
	o->mutate_port_step = 1;

	int nmodes = 0;
	int c;
	uint64_t u;
	double d;
	opterr = 0;
	while ((c = getopt_long(argc, argv, ":i:t:qh", long_opts, NULL)) != -1) {
		switch (c) {
		case 'i': o->iface = optarg; break;
		case 't':
			if (afr_parse_u64(optarg, &u) < 0 || u == 0 || u > 1000)
				return bad("--threads", optarg);
			o->threads = (unsigned)u;
			break;
		case 'q': o->quiet = 1; break;
		case 'h': afr_usage(stdout); return 1;
		case O_TOPSPEED:
			o->mode = MODE_TOPSPEED;
			nmodes++;
			break;
		case O_MBPS:
			if (afr_parse_double(optarg, &d) < 0 || d <= 0)
				return bad("--mbps", optarg);
			o->mode = MODE_MBPS;
			o->mbps = d;
			nmodes++;
			break;
		case O_PPS:
			if (afr_parse_double(optarg, &d) < 0 || d <= 0)
				return bad("--pps", optarg);
			o->mode = MODE_PPS;
			o->pps = d;
			nmodes++;
			break;
		case O_MULT:
			if (afr_parse_double(optarg, &d) < 0 || d <= 0 || d > 1e9)
				return bad("--multiplier", optarg);
			o->mode = MODE_TIMED;
			o->multiplier = d;
			nmodes++;
			break;
		case O_DURATION:
			if (afr_parse_duration(optarg, &o->duration_ns) < 0 || o->duration_ns <= 0)
				return bad("--duration", optarg);
			o->mode = MODE_TIMED;
			nmodes++;
			break;
		case O_LOOP:
			if (afr_parse_u64(optarg, &o->loops) < 0)
				return bad("--loop", optarg);
			break;
		case O_TS_ORDER:
			if (!strcmp(optarg, "asis"))
				o->ts_order = TS_ORDER_ASIS;
			else if (!strcmp(optarg, "clamp"))
				o->ts_order = TS_ORDER_CLAMP;
			else if (!strcmp(optarg, "sort"))
				o->ts_order = TS_ORDER_SORT;
			else
				return bad("--ts-order", optarg);
			break;
		case O_MAX_GAP:
			if (afr_parse_duration(optarg, &o->max_gap) < 0)
				return bad("--max-gap", optarg);
			break;
		case O_TS_OUTLIERS:
			if (!strcmp(optarg, "report"))
				o->exclude_outliers = 0;
			else if (!strcmp(optarg, "exclude"))
				o->exclude_outliers = 1;
			else
				return bad("--ts-outliers", optarg);
			break;
		case O_OUTLIER_JUMP:
			if (afr_parse_duration(optarg, &o->outlier_jump) < 0)
				return bad("--outlier-jump", optarg);
			break;
		case O_LAG_POLICY:
			if (!strcmp(optarg, "catchup"))
				o->lag_policy = LAG_CATCHUP;
			else if (!strcmp(optarg, "rebase"))
				o->lag_policy = LAG_REBASE;
			else
				return bad("--lag-policy", optarg);
			break;
		case O_LAG_THRESHOLD:
			if (afr_parse_duration(optarg, &o->lag_threshold) < 0)
				return bad("--lag-threshold", optarg);
			break;
		case O_SPIN_US:
			if (afr_parse_u64(optarg, &u) < 0 || u > 1000000)
				return bad("--spin-us", optarg);
			o->spin_ns = (int64_t)u * NS_PER_US;
			break;
		case O_TIMING_RES:
			if (afr_parse_duration(optarg, &o->timing_res) < 0)
				return bad("--timing-res", optarg);
			break;
		case O_CLOCK:
			if (!strcmp(optarg, "auto"))
				o->clock_mode = CLOCK_MODE_AUTO;
			else if (!strcmp(optarg, "tsc"))
				o->clock_mode = CLOCK_MODE_TSC;
			else if (!strcmp(optarg, "monotonic"))
				o->clock_mode = CLOCK_MODE_MONO;
			else
				return bad("--clock", optarg);
			break;
		case O_CPUS: o->cpus = optarg; break;
		case O_BATCH:
			if (afr_parse_u64(optarg, &u) < 0 || u == 0 || u > 4096)
				return bad("--batch", optarg);
			o->batch = (unsigned)u;
			break;
		case O_RING:
			if (afr_parse_u64(optarg, &u) < 0 || u < 16 || u > (1u << 20))
				return bad("--ring-frames", optarg);
			o->ring_frames = (unsigned)u;
			break;
		case O_QDISC: o->qdisc_bypass = 1; break;
		case O_LOSS: o->packet_loss = 1; break;
		case O_LINK:
			if (afr_parse_bitrate(optarg, &o->link_speed_bps) < 0)
				return bad("--link-speed", optarg);
			break;
		case O_MTU:
			if (afr_parse_u64(optarg, &u) < 0 || u < 68 || u > 65521)
				return bad("--mtu", optarg);
			o->mtu = (unsigned)u;
			break;
		case O_PRELOAD: o->preload = 1; break;
		case O_SMAC:
			if (afr_parse_mac(optarg, o->smac) < 0)
				return bad("--smac", optarg);
			break;
		case O_DMAC:
			if (afr_parse_mac(optarg, o->dmac) < 0)
				return bad("--dmac", optarg);
			break;
		case O_ANALYZE: o->analyze = 1; break;
		case O_JSON: o->stats_json = optarg; break;
		case O_MUTATE: {
			char buf[64];
			snprintf(buf, sizeof(buf), "%s", optarg);
			char *save = NULL;
			for (char *t = strtok_r(buf, ",+", &save); t; t = strtok_r(NULL, ",+", &save)) {
				if (!strcmp(t, "ip"))
					o->mutate_ip = 1;
				else if (!strcmp(t, "port"))
					o->mutate_port = 1;
				else
					return bad("--loop-mutate", optarg);
			}
			if (!o->mutate_ip && !o->mutate_port)
				return bad("--loop-mutate", optarg);
			break;
		}
		case O_MUT_IP:
			if (afr_parse_ipv4(optarg, &o->mutate_ip_offset) < 0 || o->mutate_ip_offset == 0)
				return bad("--mutate-ip-offset", optarg);
			break;
		case O_MUT_PORT:
			if (afr_parse_u64(optarg, &u) < 0 || u == 0 || u >= 64512)
				return bad("--mutate-port-step", optarg);
			o->mutate_port_step = (uint32_t)u;
			break;
		case ':':
			afr_log_err("опции %s нужен аргумент", argv[optind - 1]);
			return -1;
		default:
			afr_log_err("неизвестная опция %s (см. --help)", argv[optind - 1]);
			return -1;
		}
	}
	if (nmodes > 1) {
		afr_log_err("--topspeed, --mbps, --pps, --multiplier и --duration взаимоисключающие");
		return -1;
	}
	if (optind != argc - 1) {
		afr_log_err(optind >= argc ? "не указан pcap-файл (см. --help)"
		                           : "ожидается ровно один pcap-файл");
		return -1;
	}
	o->file = argv[optind];
	if (!o->analyze && !o->iface) {
		afr_log_err("не указан интерфейс (-i), или используйте --analyze");
		return -1;
	}
	afr_quiet = o->quiet;
	return 0;
}
