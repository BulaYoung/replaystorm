//! With the "dpdk" feature: compile the C layer over DPDK (src/dpdk/shim.c) and link DPDK,
//! found with pkg-config (libdpdk). Without the feature nothing is done.

#[cfg(feature = "dpdk")]
use std::process::Command;

#[cfg(feature = "dpdk")]
fn pkg_config(args: &[&str]) -> Vec<String> {
    let out = Command::new("pkg-config")
        .args(args)
        .arg("libdpdk")
        .output()
        .unwrap_or_else(|e| panic!("pkg-config not found ({}): install pkgconf and dpdk-devel", e));
    if !out.status.success() {
        panic!(
            "DPDK not found by pkg-config (libdpdk): install dpdk-devel, or set PKG_CONFIG_PATH to \
             the directory with libdpdk.pc\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).split_whitespace().map(String::from).collect()
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/dpdk/shim.c");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    #[cfg(feature = "dpdk")]
    build_dpdk();
}

#[cfg(feature = "dpdk")]
fn build_dpdk() {
    let mut build = cc::Build::new();
    build.file("src/dpdk/shim.c").opt_level(3).warnings(false);
    // "-include rte_config.h" is two tokens that must stay together.
    let cflags = pkg_config(&["--cflags"]);
    let mut it = cflags.iter();
    while let Some(f) = it.next() {
        if f == "-include" {
            if let Some(h) = it.next() {
                build.flag("-include").flag(h);
            }
        } else if let Some(dir) = f.strip_prefix("-I") {
            build.include(dir);
        } else {
            build.flag(f);
        }
    }
    build.compile("rsdpdk");
    for f in pkg_config(&["--libs"]) {
        if let Some(dir) = f.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={}", dir);
        } else if let Some(lib) = f.strip_prefix("-l:") {
            println!("cargo:rustc-link-arg=-l:{}", lib);
        } else if let Some(lib) = f.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={}", lib);
        } else {
            println!("cargo:rustc-link-arg={}", f);
        }
    }
}
