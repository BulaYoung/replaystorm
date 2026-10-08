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
    let analyze = o.analyze;
    let rc = match prepare::prepare(o) {
        Err(rc) => rc,
        Ok(mut c) => {
            if analyze {
                replay::analyze(&c);
                0
            } else {
                replay::run(&mut c)
            }
        }
    };
    std::process::exit(rc);
}
