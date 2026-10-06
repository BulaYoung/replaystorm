#include "cli.h"

#include "clock.h"
#include "sched.h"
#include "util.h"

#include <getopt.h>
#include <string.h>

void afr_usage(FILE *f)
{
	fputs(
	    "afreplay - multithreaded pcap replayer over AF_PACKET preserving L2\n"
	    "\n"
	    "Usage:\n"
	    "  afreplay -i INTERFACE [options] FILE.pcap\n"
	    "  afreplay --analyze [options] FILE.pcap\n"
	    "\n"
	    "Rate modes (mutually exclusive, default --multiplier 1):\n"
	    "  --topspeed              as fast as possible\n"
	    "  --mbps X                fixed total rate, Mbit/s (L2, without FCS)\n"
	    "  --mbps line | N%        rate as a share of the link speed counted on the wire\n"
	    "                          (preamble, IFG, FCS included): line = 100%, e.g. 99%\n"
	    "  --pps X                 fixed total rate, packets/s\n"
	    "  --multiplier X          replay by timestamps: 2.0 is twice as fast, 0.5 is twice\n"
	    "                          as slow, 1.0 is real time\n"
	    "  --duration T            pick the multiplier so the file plays in T\n"
	    "  --loop N                play N times (0 means infinite), default 1\n"
	    "\n"
	    "Timestamps:\n"
	    "  --ts-order MODE         asis | clamp | sort (default clamp)\n"
	    "                            asis  - as is, \"backward in time\" is sent without waiting\n"
	    "                            clamp - \"backward in time\" is replaced by the previous stamp\n"
	    "                            sort  - stable sort of the index by timestamp\n"
	    "  --max-gap T             compress pauses longer than T down to T\n"
	    "  --ts-outliers MODE      report | exclude: outliers (ts=0, before 1990, future,\n"
	    "                          short clock jump) are only reported or excluded\n"
	    "                          from the timeline computation (default report)\n"
	    "  --outlier-jump T        clock jump threshold for outlier detection (default 60s,\n"
	    "                          0 disables detection)\n"
	    "  --lag-policy P          catchup | rebase: when lagging, catch up or shift T0\n"
	    "  --lag-threshold T       lag after which rebase kicks in (10ms)\n"
	    "  --spin-us N             busy-spin for the last N us of each wait (50)\n"
	    "  --timing-res T          achievable timing precision for burst estimation (2us)\n"
	    "  --clock C               auto | tsc | monotonic: hot-loop clock. auto picks TSC\n"
	    "                          if the kernel clocksource is not tsc (clock_gettime is slow then)\n"
	    "\n"
	    "Sending:\n"
	    "  -i, --interface IF      interface\n"
	    "  -t, --threads N         threads for IP traffic (default: CPUs of the NUMA node - 1);\n"
	    "                          non-IP frames always go through a separate thread\n"
	    "  --cpus LIST             CPUs for threads, e.g. 2-9,12 (default:\n"
	    "                          /sys/class/net/IF/device/local_cpulist)\n"
	    "  --batch N               frames per send() call (64)\n"
	    "  --ring-frames N         frames in each thread's TX_RING (4096)\n"
	    "  --qdisc-bypass          PACKET_QDISC_BYPASS: bypass qdisc, straight to the driver\n"
	    "  --packet-loss           PACKET_LOSS: kernel silently skips malformed frames\n"
	    "  --link-speed X          link speed (25G, 10000M); default from ethtool\n"
	    "  --mtu N                 MTU (default from the interface, 1500 for --analyze)\n"
	    "\n"
	    "Input:\n"
	    "  --preload               load the whole file into memory before start\n"
	    "  --smac MAC, --dmac MAC  MAC addresses of the synthetic Ethernet header for RAW IP\n"
	    "\n"
	    "Looping with mutation:\n"
	    "  --loop-mutate WHAT      ip | port | ip,port - on lap k>0 shift addresses/ports\n"
	    "                          so the sensor sees new sessions (L2 is untouched)\n"
	    "  --mutate-ip-offset A    IPv4 shift per lap, as an address (default 0.1.0.0)\n"
	    "  --mutate-port-step N    shift of ports >= 1024 per lap (default 1)\n"
	    "\n"
	    "Output:\n"
	    "  --analyze               analyze the file only, do not send\n"
	    "  --stats-json FILE       write statistics as JSON\n"
	    "  -q, --quiet             do not print per-second statistics\n"
	    "  -h, --help              this help\n"
	    "\n"
	    "Examples:\n"
	    "  afreplay --analyze big.pcap\n"
	    "  afreplay --analyze --multiplier 10 --link-speed 25G big.pcap\n"
	    "  afreplay -i ens1f0 --topspeed --qdisc-bypass -t 12 big.pcap\n"
	    "  afreplay -i ens1f0 --mbps 20000 --loop 0 big.pcap\n"
	    "  afreplay -i ens1f0 --mbps 99% --loop 0 --loop-mutate ip,port big.pcap\n"
	    "  afreplay -i ens1f0 --multiplier 2 --max-gap 1s --ts-order sort big.pcap\n"
	    "  afreplay -i ens1f0 --duration 10m --stats-json run.json big.pcap\n"
	    "  afreplay -i ens1f0 --loop 5 --loop-mutate ip,port big.pcap\n"
	    "  afreplay -i ens1f0 --smac 02:00:00:00:00:01 --dmac 02:00:00:00:00:02 raw.pcap\n"
	    "\n"
	    "Exit code: 0 - success (including stop by SIGINT/SIGTERM), 1 - runtime error,\n"
	    "2 - invalid arguments.\n",
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
	afr_log_err("invalid value for %s: '%s' (see --help)", opt, val);
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
		case O_MBPS: {
			size_t len = strlen(optarg);
			if (!strcmp(optarg, "line")) {
				o->line_frac = 1.0;
			} else if (len > 1 && optarg[len - 1] == '%') {
				char buf[32];
				if (len >= sizeof(buf))
					return bad("--mbps", optarg);
				memcpy(buf, optarg, len - 1);
				buf[len - 1] = 0;
				if (afr_parse_double(buf, &d) < 0 || d <= 0 || d > 100)
					return bad("--mbps", optarg);
				o->line_frac = d / 100.0;
			} else if (afr_parse_double(optarg, &d) < 0 || d <= 0) {
				return bad("--mbps", optarg);
			} else {
				o->mbps = d;
			}
			o->mode = MODE_MBPS;
			nmodes++;
			break;
		}
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
			afr_log_err("option %s requires an argument", argv[optind - 1]);
			return -1;
		default:
			afr_log_err("unknown option %s (see --help)", argv[optind - 1]);
			return -1;
		}
	}
	if (nmodes > 1) {
		afr_log_err("--topspeed, --mbps, --pps, --multiplier and --duration are mutually exclusive");
		return -1;
	}
	if (optind != argc - 1) {
		afr_log_err(optind >= argc ? "no pcap file given (see --help)"
		                           : "exactly one pcap file expected");
		return -1;
	}
	o->file = argv[optind];
	if (!o->analyze && !o->iface) {
		afr_log_err("no interface given (-i), or use --analyze");
		return -1;
	}
	afr_quiet = o->quiet;
	return 0;
}
