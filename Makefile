# replaystorm — multithreaded pcap replayer over AF_PACKET
# The build itself is cargo; this Makefile keeps the familiar targets.
CARGO ?= $(shell command -v cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)
BUILD := build
MUSL  := x86_64-unknown-linux-musl

.PHONY: all replaystorm static dpdk dpdk-test clean test unit-test func-test pcaps clippy

all: replaystorm

replaystorm:
	$(CARGO) build --release
	cp target/release/replaystorm replaystorm

# A fully static binary that runs on any x86_64 Linux (RHEL/CentOS 8 included),
# whatever its glibc: rustup target add x86_64-unknown-linux-musl
static:
	$(CARGO) build --release --target $(MUSL)
	cp target/$(MUSL)/release/replaystorm replaystorm

# With the DPDK backend (--dpdk): needs DPDK with pkg-config (dpdk-devel).
dpdk:
	$(CARGO) build --release --features dpdk
	cp target/release/replaystorm replaystorm

# DPDK tests through the af_packet driver on veth (no NIC, no hugepages needed).
dpdk-test: dpdk pcaps
	tests/func_veth.sh $(BUILD)/pcaps --dpdk

unit-test:
	$(CARGO) test --release

pcaps:
	python3 tests/gen_pcaps.py $(BUILD)/pcaps

func-test: replaystorm pcaps
	tests/func_veth.sh $(BUILD)/pcaps

test: unit-test func-test

clippy:
	$(CARGO) clippy --release --all-targets

clean:
	$(CARGO) clean
	rm -rf $(BUILD) replaystorm
