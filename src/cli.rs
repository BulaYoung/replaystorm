//! Command line options and --help.

use crate::clock::ClockMode;
use crate::sched::TsOrder;
use crate::util::*;
use crate::{NS_PER_MS, NS_PER_SEC, NS_PER_US};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Timed,
    Topspeed,
    Mbps,
    Pps,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Topspeed => "topspeed",
            Mode::Mbps => "mbps",
            Mode::Pps => "pps",
            Mode::Timed => "timestamps",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LagPolicy {
    #[default]
    Catchup,
    Rebase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IoMode {
    #[default]
    Auto,
    Direct,
    Mmap,
}

pub const MAX_CPUS: usize = 1024;

#[derive(Clone, Debug)]
pub struct Opts {
    pub iface: Option<String>,
    pub file: String,
    pub threads: usize, // 0 means default
    pub cpus: Option<String>,

    pub mode: Mode,
    pub multiplier: f64,   // for Mode::Timed
    pub duration_ns: i64,  // --duration: multiplier is derived
    pub mbps: f64,
    pub pps: f64,
    pub line_frac: f64,    // --mbps line / N%: fraction of the link on the wire (0 = off)
    pub loops: u64,        // 0 means infinite

    pub ts_order: TsOrder,
    pub max_gap: i64,
    pub exclude_outliers: bool,
    pub outlier_jump: i64,
    pub lag_policy: LagPolicy,
    pub lag_threshold: i64,
    pub spin_ns: i64,
    pub pace_slack: i64,   // --mbps/--pps: send packets due within this window at once
    pub timing_res: i64,
    pub clock_mode: ClockMode,

    pub batch: u32,
    pub ring_frames: u32,
    pub qdisc_bypass: bool,
    pub packet_loss: bool,
    pub link_speed_bps: f64, // 0 means auto-detect
    pub mtu: u32,            // 0 means from interface

    pub preload: bool,
    pub index_cache: Option<String>, // --index-cache FILE or "auto"
    pub readahead: u64,    // bytes kept requested ahead of the senders
    pub drop_behind: i32,  // -1 auto, 0 off, 1 on
    pub io_mode: IoMode,
    pub io_threads: usize, // direct I/O reader threads
    pub disk_max_temp: i32,   // thermal governor target, C (0 = off)
    pub disk_start_temp: i32, // wait until the disk cools to this before start, C (0 = off)
    pub smac: [u8; 6],
    pub dmac: [u8; 6],

    pub analyze: bool,
    pub stats_json: Option<String>,
    pub status_file: Option<String>, // live status file (default /tmp/replaystorm-IF.status)
    pub status_query: bool,  // --status: print the status of a running replaystorm and exit
    pub quiet: bool,

    pub mutate_ip: bool,
    pub mutate_port: bool,
    pub mutate_ip_offset: u32, // host byte order
    pub mutate_port_step: u32,

    pub dpdk: Option<String>, // --dpdk PORT: send through DPDK instead of AF_PACKET
    pub eal: Option<String>,  // --eal "ARGS": DPDK EAL arguments
    pub link_from_port: bool, // the link speed was read from the DPDK port
    pub dpdk_bind: bool,      // --dpdk-bind: move the NIC to vfio-pci and back
    pub dpdk_hugepages: u64,  // --dpdk-hugepages: bytes reserved for the run (0 = none)
}

impl Opts {
    /// Name of the output: the interface, or the DPDK port (status file name, logs).
    pub fn label(&self) -> String {
        match (&self.iface, &self.dpdk) {
            (Some(i), _) => i.clone(),
            (None, Some(p)) => format!("dpdk-{}", p.replace('/', "_")),
            _ => String::new(),
        }
    }
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            iface: None,
            file: String::new(),
            threads: 0,
            cpus: None,
            mode: Mode::Timed,
            multiplier: 1.0,
            duration_ns: 0,
            mbps: 0.0,
            pps: 0.0,
            line_frac: 0.0,
            loops: 1,
            ts_order: TsOrder::Clamp,
            max_gap: 0,
            exclude_outliers: false,
            outlier_jump: 60 * NS_PER_SEC,
            lag_policy: LagPolicy::Catchup,
            lag_threshold: 10 * NS_PER_MS,
            spin_ns: 50 * NS_PER_US,
            pace_slack: 200 * NS_PER_US,
            timing_res: 2 * NS_PER_US,
            clock_mode: ClockMode::Auto,
            batch: 64,
            ring_frames: 4096,
            qdisc_bypass: false,
            packet_loss: false,
            link_speed_bps: 0.0,
            mtu: 0,
            preload: false,
            index_cache: None,
            readahead: 2 << 30,
            drop_behind: -1,
            io_mode: IoMode::Auto,
            io_threads: 4,
            disk_max_temp: 0,
            disk_start_temp: 0,
            smac: [0x02, 0, 0, 0, 0, 0x01],
            dmac: [0x02, 0, 0, 0, 0, 0x02],
            analyze: false,
            stats_json: None,
            status_file: None,
            status_query: false,
            quiet: false,
            mutate_ip: false,
            mutate_port: false,
            mutate_ip_offset: 0x0001_0000,
            mutate_port_step: 1,
            dpdk: None,
            eal: None,
            link_from_port: false,
            dpdk_bind: false,
            dpdk_hugepages: 0,
        }
    }
}

pub const USAGE: &str = "\
replaystorm - multithreaded pcap replayer over AF_PACKET preserving L2

Usage:
  replaystorm -i INTERFACE [options] FILE.pcap
  replaystorm --analyze [options] FILE.pcap

Rate modes (mutually exclusive, default --multiplier 1):
  --topspeed              as fast as possible
  --mbps X                fixed total rate, Mbit/s (L2, without FCS)
  --mbps line | N%        rate as a share of the link speed counted on the wire
                          (preamble, IFG, FCS included): line = 100%, e.g. 99%
  --pace-slack T          --mbps/--pps: threads sleep and send packets due within T at
                          once instead of busy-waiting each packet (default 200us)
  --pps X                 fixed total rate, packets/s
  --multiplier X          replay by timestamps: 2.0 is twice as fast, 0.5 is twice
                          as slow, 1.0 is real time
  --duration T            pick the multiplier so the file plays in T
  --loop N                play N times (0 means infinite), default 1

Timestamps:
  --ts-order MODE         asis | clamp | sort (default clamp)
                            asis  - as is, \"backward in time\" is sent without waiting
                            clamp - \"backward in time\" is replaced by the previous stamp
                            sort  - stable sort of the index by timestamp
  --max-gap T             compress pauses longer than T down to T
  --ts-outliers MODE      report | exclude: outliers (ts=0, before 1990, future,
                          short clock jump) are only reported or excluded
                          from the timeline computation (default report)
  --outlier-jump T        clock jump threshold for outlier detection (default 60s,
                          0 disables detection)
  --lag-policy P          catchup | rebase: when lagging, catch up or shift T0
  --lag-threshold T       lag after which rebase kicks in (10ms)
  --spin-us N             busy-spin for the last N us of each wait (50)
  --timing-res T          achievable timing precision for burst estimation (2us)
  --clock C               auto | tsc | monotonic: hot-loop clock. auto picks TSC
                          if the kernel clocksource is not tsc (clock_gettime is slow then)

Sending:
  -i, --interface IF      interface
  -t, --threads N         threads for IP traffic (default: CPUs of the NUMA node - 1);
                          non-IP frames always go through a separate thread
  --cpus LIST             CPUs for threads, e.g. 2-9,12 (default:
                          /sys/class/net/IF/device/local_cpulist)
  --batch N               frames per send() call (64)
  --ring-frames N         frames in each thread's TX_RING (4096)
  --qdisc-bypass          PACKET_QDISC_BYPASS: bypass qdisc, straight to the driver
  --packet-loss           PACKET_LOSS: kernel silently skips malformed frames
  --link-speed X          link speed (25G, 10000M); default from ethtool
  --mtu N                 MTU (default from the interface, 1500 for --analyze)
  --dpdk PORT             send through DPDK instead of AF_PACKET (binary built with
                          make dpdk): PORT is the NIC's interface name (ens1f0) or PCI
                          address (0000:3b:00.0), a virtual device name or a port
                          number; replaces -i
  --eal \"ARGS\"            DPDK EAL arguments, e.g. \"-a 0000:3b:00.0\" or
                          \"--no-huge --vdev=net_af_packet0,iface=eth1,qpairs=12\"
  --dpdk-bind             move the NIC from its kernel driver
                          to vfio-pci for the run and give it back at the end, with its
                          MTU and up state; refused if the interface has IP addresses
  --dpdk-hugepages SIZE   reserve SIZE of 2 MB hugepages (e.g. 4G) on the NIC's NUMA node
                          for the run and release them at the end

Input:
  --preload               load the whole file into memory before start
  --index-cache FILE      keep the packet index on disk: the first run builds and saves
                          it, later runs load it instead of scanning the pcap; auto =
                          FILE.pcap.rsidx next to the pcap. Rebuilt automatically if the
                          pcap changes; valid for any -t and MTU
  --readahead SIZE        how much of the file is kept in RAM ahead of the senders:
                          the direct I/O window or the page-cache readahead (2G)
  --drop-behind M         auto | on | off: drop already sent parts of the file from the
                          page cache; auto = on when the file is larger than free RAM
  --io MODE               auto | direct | mmap: how the file is read during replay.
                          direct: O_DIRECT reader threads fill a RAM window of
                          --readahead size, bypassing the page cache; mmap: through the
                          page cache; auto = direct when the file is larger than free RAM
  --io-threads N          direct I/O reader threads (default 4)
  --disk-max-temp C       thermal governor (direct I/O): limit the disk read rate to keep
                          the NVMe drive at or below C degrees instead of letting it hit
                          thermal throttling; e.g. 2-3 C below its throttling point
  --disk-start-temp C     before start, wait until the NVMe drive cools down to C
  --smac MAC, --dmac MAC  MAC addresses of the synthetic Ethernet header for RAW IP

Looping with mutation:
  --loop-mutate WHAT      ip | port | ip,port - on lap k>0 shift addresses/ports
                          so the sensor sees new sessions (L2 is untouched)
  --mutate-ip-offset A    IPv4 shift per lap, as an address (default 0.1.0.0)
  --mutate-port-step N    shift of ports >= 1024 per lap (default 1)

Output:
  --analyze               analyze the file only, do not send
  --stats-json FILE       write statistics as JSON
  --status-file F         live status file, rewritten every second (default
                          /tmp/replaystorm-IF.status)
  --status [-i IF]        print the live status of a running replaystorm and exit
                          (--status --dpdk PORT for a DPDK replay)
  -q, --quiet             do not print per-second statistics
  -h, --help              this help

Examples:
  replaystorm --analyze big.pcap
  replaystorm --status -i ens1f0          # statistics of a replay running elsewhere
  replaystorm -i ens1f0 --mbps 99% --index-cache /var/tmp/big.rsidx big.pcap
  replaystorm --analyze --multiplier 10 --link-speed 25G big.pcap
  replaystorm -i ens1f0 --topspeed --qdisc-bypass -t 12 big.pcap
  replaystorm -i ens1f0 --mbps 20000 --loop 0 big.pcap
  replaystorm -i ens1f0 --mbps 99% --loop 0 --loop-mutate ip,port big.pcap
  replaystorm -i ens1f0 --multiplier 2 --max-gap 1s --ts-order sort big.pcap
  replaystorm -i ens1f0 --duration 10m --stats-json run.json big.pcap
  replaystorm -i ens1f0 --loop 5 --loop-mutate ip,port big.pcap
  replaystorm -i ens1f0 --smac 02:00:00:00:00:01 --dmac 02:00:00:00:00:02 raw.pcap
  replaystorm --dpdk 0000:3b:00.0 --eal \"-a 0000:3b:00.0\" --mbps 99% --loop 0 big.pcap
  replaystorm --dpdk ens1f0 --dpdk-bind --dpdk-hugepages 4G --mbps 99% big.pcap

While running: press Enter (or s) for long-run statistics: minimum, worst minute,
percentiles, averages; r resets them, q stops; kill -USR1 PID prints them too.

Exit code: 0 - success (including stop by SIGINT/SIGTERM), 1 - runtime error,
2 - invalid arguments.
";

/// Long options: (name, takes an argument).
const LONG_OPTS: &[(&str, bool)] = &[
    ("interface", true),
    ("threads", true),
    ("quiet", false),
    ("help", false),
    ("topspeed", false),
    ("mbps", true),
    ("pps", true),
    ("multiplier", true),
    ("duration", true),
    ("loop", true),
    ("ts-order", true),
    ("max-gap", true),
    ("ts-outliers", true),
    ("outlier-jump", true),
    ("lag-policy", true),
    ("lag-threshold", true),
    ("spin-us", true),
    ("pace-slack", true),
    ("timing-res", true),
    ("clock", true),
    ("cpus", true),
    ("batch", true),
    ("ring-frames", true),
    ("qdisc-bypass", false),
    ("packet-loss", false),
    ("link-speed", true),
    ("mtu", true),
    ("preload", false),
    ("index-cache", true),
    ("readahead", true),
    ("drop-behind", true),
    ("io", true),
    ("io-threads", true),
    ("disk-max-temp", true),
    ("disk-start-temp", true),
    ("smac", true),
    ("dmac", true),
    ("analyze", false),
    ("stats-json", true),
    ("status", false),
    ("status-file", true),
    ("loop-mutate", true),
    ("mutate-ip-offset", true),
    ("mutate-port-step", true),
    ("dpdk", true),
    ("eal", true),
    ("dpdk-bind", false),
    ("dpdk-hugepages", true),
];

/// Short options: (letter, long name, takes an argument).
const SHORT_OPTS: &[(char, &str, bool)] =
    &[('i', "interface", true), ('t', "threads", true), ('q', "quiet", false), ('h', "help", false)];

pub enum Parsed {
    Run(Box<Opts>),
    Help,
}

fn bad(opt: &str, val: &str) -> Result<Parsed, ()> {
    log_err!("invalid value for {}: '{}' (see --help)", opt, val);
    Err(())
}

/// Find a long option by its exact name or an unambiguous prefix (like getopt_long).
fn find_long(name: &str) -> Option<(&'static str, bool)> {
    if let Some(&(n, a)) = LONG_OPTS.iter().find(|(n, _)| *n == name) {
        return Some((n, a));
    }
    let m: Vec<_> = LONG_OPTS.iter().filter(|(n, _)| n.starts_with(name)).collect();
    if m.len() == 1 && !name.is_empty() {
        Some((m[0].0, m[0].1))
    } else {
        None
    }
}

/// Ok(Run): continue, Ok(Help): help was printed (exit 0), Err: error (exit 2).
pub fn parse_args(args: &[String]) -> Result<Parsed, ()> {
    let mut o = Opts::default();
    let mut nmodes = 0;
    let mut positional: Vec<String> = Vec::new();

    // Split argv into (option name, value) pairs in order, getopt_long style.
    let mut items: Vec<(&'static str, Option<String>)> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == "--" {
            positional.extend(args[i..].iter().cloned());
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (body, None),
            };
            let Some((lname, has_arg)) = find_long(name) else {
                log_err!("unknown option {} (see --help)", a);
                return Err(());
            };
            if has_arg {
                let v = match inline {
                    Some(v) => v,
                    None if i < args.len() => {
                        i += 1;
                        args[i - 1].clone()
                    }
                    None => {
                        log_err!("option {} requires an argument", a);
                        return Err(());
                    }
                };
                items.push((lname, Some(v)));
            } else {
                if inline.is_some() {
                    log_err!("unknown option {} (see --help)", a);
                    return Err(());
                }
                items.push((lname, None));
            }
        } else if a.len() > 1 && a.starts_with('-') {
            let chars: Vec<char> = a[1..].chars().collect();
            let mut k = 0;
            while k < chars.len() {
                let c = chars[k];
                k += 1;
                let Some(&(_, lname, has_arg)) = SHORT_OPTS.iter().find(|(s, _, _)| *s == c) else {
                    log_err!("unknown option {} (see --help)", a);
                    return Err(());
                };
                if has_arg {
                    let v = if k < chars.len() {
                        chars[k..].iter().collect()
                    } else if i < args.len() {
                        i += 1;
                        args[i - 1].clone()
                    } else {
                        log_err!("option {} requires an argument", a);
                        return Err(());
                    };
                    items.push((lname, Some(v)));
                    break;
                }
                items.push((lname, None));
            }
        } else {
            positional.push(a.clone());
        }
    }

    for (name, val) in items {
        let v = val.as_deref().unwrap_or("");
        let opt = format!("--{}", name);
        macro_rules! dur {
            ($field:expr) => {
                match parse_duration(v) {
                    Some(x) => $field = x,
                    None => return bad(&opt, v),
                }
            };
        }
        match name {
            "interface" => o.iface = Some(v.to_string()),
            "threads" => match parse_u64(v) {
                Some(u) if u > 0 && u <= 1000 => o.threads = u as usize,
                _ => return bad("--threads", v),
            },
            "quiet" => o.quiet = true,
            "help" => {
                print!("{}", USAGE);
                return Ok(Parsed::Help);
            }
            "topspeed" => {
                o.mode = Mode::Topspeed;
                nmodes += 1;
            }
            "mbps" => {
                if v == "line" {
                    o.line_frac = 1.0;
                } else if v.len() > 1 && v.ends_with('%') {
                    match parse_double(&v[..v.len() - 1]) {
                        Some(d) if d > 0.0 && d <= 100.0 && v.len() < 32 => o.line_frac = d / 100.0,
                        _ => return bad("--mbps", v),
                    }
                } else {
                    match parse_double(v) {
                        Some(d) if d > 0.0 => o.mbps = d,
                        _ => return bad("--mbps", v),
                    }
                }
                o.mode = Mode::Mbps;
                nmodes += 1;
            }
            "pps" => match parse_double(v) {
                Some(d) if d > 0.0 => {
                    o.mode = Mode::Pps;
                    o.pps = d;
                    nmodes += 1;
                }
                _ => return bad("--pps", v),
            },
            "multiplier" => match parse_double(v) {
                Some(d) if d > 0.0 && d <= 1e9 => {
                    o.mode = Mode::Timed;
                    o.multiplier = d;
                    nmodes += 1;
                }
                _ => return bad("--multiplier", v),
            },
            "duration" => match parse_duration(v) {
                Some(d) if d > 0 => {
                    o.duration_ns = d;
                    o.mode = Mode::Timed;
                    nmodes += 1;
                }
                _ => return bad("--duration", v),
            },
            "loop" => match parse_u64(v) {
                Some(u) => o.loops = u,
                None => return bad("--loop", v),
            },
            "ts-order" => {
                o.ts_order = match v {
                    "asis" => TsOrder::Asis,
                    "clamp" => TsOrder::Clamp,
                    "sort" => TsOrder::Sort,
                    _ => return bad("--ts-order", v),
                }
            }
            "max-gap" => dur!(o.max_gap),
            "ts-outliers" => {
                o.exclude_outliers = match v {
                    "report" => false,
                    "exclude" => true,
                    _ => return bad("--ts-outliers", v),
                }
            }
            "outlier-jump" => dur!(o.outlier_jump),
            "lag-policy" => {
                o.lag_policy = match v {
                    "catchup" => LagPolicy::Catchup,
                    "rebase" => LagPolicy::Rebase,
                    _ => return bad("--lag-policy", v),
                }
            }
            "lag-threshold" => dur!(o.lag_threshold),
            "spin-us" => match parse_u64(v) {
                Some(u) if u <= 1_000_000 => o.spin_ns = u as i64 * NS_PER_US,
                _ => return bad("--spin-us", v),
            },
            "pace-slack" => dur!(o.pace_slack),
            "timing-res" => dur!(o.timing_res),
            "clock" => {
                o.clock_mode = match v {
                    "auto" => ClockMode::Auto,
                    "tsc" => ClockMode::Tsc,
                    "monotonic" => ClockMode::Monotonic,
                    _ => return bad("--clock", v),
                }
            }
            "cpus" => o.cpus = Some(v.to_string()),
            "batch" => match parse_u64(v) {
                Some(u) if u > 0 && u <= 4096 => o.batch = u as u32,
                _ => return bad("--batch", v),
            },
            "ring-frames" => match parse_u64(v) {
                Some(u) if (16..=1 << 20).contains(&u) => o.ring_frames = u as u32,
                _ => return bad("--ring-frames", v),
            },
            "qdisc-bypass" => o.qdisc_bypass = true,
            "packet-loss" => o.packet_loss = true,
            "link-speed" => match parse_bitrate(v) {
                Some(b) => o.link_speed_bps = b,
                None => return bad("--link-speed", v),
            },
            "mtu" => match parse_u64(v) {
                Some(u) if (68..=65521).contains(&u) => o.mtu = u as u32,
                _ => return bad("--mtu", v),
            },
            "preload" => o.preload = true,
            "index-cache" => o.index_cache = Some(v.to_string()),
            "readahead" => match parse_size(v) {
                Some(b) if b >= 16 << 20 => o.readahead = b,
                _ => return bad("--readahead", v),
            },
            "io" => {
                o.io_mode = match v {
                    "auto" => IoMode::Auto,
                    "direct" => IoMode::Direct,
                    "mmap" => IoMode::Mmap,
                    _ => return bad("--io", v),
                }
            }
            "io-threads" => match parse_u64(v) {
                Some(u) if u > 0 && u <= 32 => o.io_threads = u as usize,
                _ => return bad("--io-threads", v),
            },
            "disk-max-temp" | "disk-start-temp" => match parse_u64(v) {
                Some(u) if (20..=100).contains(&u) => {
                    if name == "disk-max-temp" {
                        o.disk_max_temp = u as i32;
                    } else {
                        o.disk_start_temp = u as i32;
                    }
                }
                _ => return bad(&opt, v),
            },
            "drop-behind" => {
                o.drop_behind = match v {
                    "auto" => -1,
                    "on" => 1,
                    "off" => 0,
                    _ => return bad("--drop-behind", v),
                }
            }
            "smac" => match parse_mac(v) {
                Some(m) => o.smac = m,
                None => return bad("--smac", v),
            },
            "dmac" => match parse_mac(v) {
                Some(m) => o.dmac = m,
                None => return bad("--dmac", v),
            },
            "analyze" => o.analyze = true,
            "stats-json" => o.stats_json = Some(v.to_string()),
            "status" => o.status_query = true,
            "status-file" => o.status_file = Some(v.to_string()),
            "loop-mutate" => {
                for t in v.split([',', '+']).filter(|t| !t.is_empty()) {
                    match t {
                        "ip" => o.mutate_ip = true,
                        "port" => o.mutate_port = true,
                        _ => return bad("--loop-mutate", v),
                    }
                }
                if !o.mutate_ip && !o.mutate_port {
                    return bad("--loop-mutate", v);
                }
            }
            "mutate-ip-offset" => match parse_ipv4(v) {
                Some(a) if a != 0 => o.mutate_ip_offset = a,
                _ => return bad("--mutate-ip-offset", v),
            },
            "mutate-port-step" => match parse_u64(v) {
                Some(u) if u > 0 && u < 64512 => o.mutate_port_step = u as u32,
                _ => return bad("--mutate-port-step", v),
            },
            "dpdk" => o.dpdk = Some(v.to_string()),
            "eal" => o.eal = Some(v.to_string()),
            "dpdk-bind" => o.dpdk_bind = true,
            "dpdk-hugepages" => match parse_size(v) {
                Some(b) if b >= 2 << 20 => o.dpdk_hugepages = b,
                _ => return bad("--dpdk-hugepages", v),
            },
            _ => unreachable!(),
        }
    }
    if o.status_query {
        set_quiet(o.quiet);
        return Ok(Parsed::Run(Box::new(o))); // no pcap needed
    }
    if nmodes > 1 {
        log_err!("--topspeed, --mbps, --pps, --multiplier and --duration are mutually exclusive");
        return Err(());
    }
    if positional.len() != 1 {
        if positional.is_empty() {
            log_err!("no pcap file given (see --help)");
        } else {
            log_err!("exactly one pcap file expected");
        }
        return Err(());
    }
    o.file = positional.remove(0);
    if o.iface.is_some() && o.dpdk.is_some() {
        log_err!("-i and --dpdk are mutually exclusive: --dpdk sends through a DPDK port instead of an interface");
        return Err(());
    }
    if (o.eal.is_some() || o.dpdk_bind || o.dpdk_hugepages > 0) && o.dpdk.is_none() {
        log_err!("--eal, --dpdk-bind and --dpdk-hugepages need --dpdk PORT");
        return Err(());
    }
    if o.dpdk_hugepages > 0 && o.eal.as_deref().unwrap_or("").split_whitespace().any(|a| a == "--no-huge") {
        log_err!("--dpdk-hugepages and --eal \"--no-huge\" contradict each other");
        return Err(());
    }
    if !o.analyze && o.iface.is_none() && o.dpdk.is_none() {
        log_err!("no interface given (-i), or use --dpdk PORT or --analyze");
        return Err(());
    }
    set_quiet(o.quiet);
    Ok(Parsed::Run(Box::new(o)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &[&str]) -> Result<Parsed, ()> {
        let mut v = vec!["replaystorm".to_string()];
        v.extend(a.iter().map(|s| s.to_string()));
        parse_args(&v)
    }

    fn opts(a: &[&str]) -> Opts {
        match parse(a) {
            Ok(Parsed::Run(o)) => *o,
            _ => panic!("parse failed: {:?}", a),
        }
    }

    #[test]
    fn options() {
        let o = opts(&["-i", "eth0", "--mbps", "99%", "f.pcap", "--loop=0", "-qt4"]);
        assert_eq!(o.iface.as_deref(), Some("eth0"));
        assert_eq!(o.mode, Mode::Mbps);
        assert!((o.line_frac - 0.99).abs() < 1e-12);
        assert_eq!(o.loops, 0);
        assert!(o.quiet);
        assert_eq!(o.threads, 4);
        assert_eq!(o.file, "f.pcap");
        // unambiguous prefix, like getopt_long
        let o = opts(&["--analyze", "--topsp", "f.pcap"]);
        assert_eq!(o.mode, Mode::Topspeed);
        assert!(parse(&["--analyze", "--m", "1", "f.pcap"]).is_err()); // ambiguous
        assert!(parse(&["--analyze", "--bogus", "f.pcap"]).is_err());
        assert!(parse(&["--analyze", "--topspeed", "--pps", "5", "f.pcap"]).is_err());
        assert!(parse(&["-i", "eth0"]).is_err());
        assert!(parse(&["--analyze", "f.pcap", "--mbps"]).is_err());
        let o = opts(&["--status"]);
        assert!(o.status_query);
        let o = opts(&["--analyze", "--loop-mutate", "ip,port", "--mutate-ip-offset", "0.2.0.0", "f"]);
        assert!(o.mutate_ip && o.mutate_port);
        assert_eq!(o.mutate_ip_offset, 0x20000);
    }
}
