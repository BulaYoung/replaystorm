use replaystorm::cli::{parse_args, Parsed};
use replaystorm::{prepare, replay};

fn main() {
    // Like a C program: output into a closed pipe (| head) ends the process quietly.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<String> = std::env::args().collect();
    let o = match parse_args(&args) {
        Ok(Parsed::Run(o)) => *o,
        Ok(Parsed::Help) => std::process::exit(0),
        Err(()) => std::process::exit(2),
    };
    if o.status_query {
        std::process::exit(replay::status_query(&o));
    }
    let mut o = o;
    if o.dpdk.is_some() && !o.analyze {
        // Ctrl-C/SIGTERM before the replay (index, timeline) stops cleanly as well, so that
        // the NIC and hugepages taken for DPDK are given back.
        replaystorm::replay::install_stop_signals();
        if let Err(e) = replaystorm::dpdk::init(&mut o) {
            replaystorm::util::log_err_str(&e);
            replaystorm::dpdk::shutdown();
            std::process::exit(1);
        }
    }
    let analyze = o.analyze;
    let rc = match prepare::prepare(o) {
        Err(rc) => rc,
        Ok(mut c) => {
            if analyze {
                replay::analyze(&c);
                0
            } else {
                let rc = replay::run(&mut c);
                // The port goes first: with zero-copy its queues still point into the file.
                replaystorm::dpdk::shutdown();
                drop(c);
                rc
            }
        }
    };
    replaystorm::dpdk::shutdown();
    std::process::exit(rc);
}
