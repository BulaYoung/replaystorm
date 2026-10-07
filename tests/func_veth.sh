#!/bin/bash
# Functional tests on a veth pair in a separate network namespace.
# As root, unshare -n is used; without root, unshare -rn (user namespace).
# If a namespace cannot be created, the test is skipped (exit code 0, SKIP message).
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/.." && pwd)
PCAPS=${1:-$ROOT/build/pcaps}
shift || true

if [ -z "${AFR_IN_NS:-}" ]; then
	if [ "$(id -u)" = 0 ]; then
		NS="unshare -nm"
	else
		NS="unshare -rnm"
	fi
	if ! $NS true 2>/dev/null; then
		echo "SKIP: not root and user namespaces are unavailable — functional tests skipped"
		exit 0
	fi
	exec env AFR_IN_NS=1 $NS "$0" "$PCAPS" "$@"
fi

# Own sysfs to see this namespace's interfaces
mount -t sysfs sysfs /sys 2>/dev/null || echo "sysfs not mounted: interface statistics will be unavailable"
ip link add name va type veth peer name vb || { echo "SKIP: failed to create veth"; exit 0; }
for i in va vb; do
	echo 1 >/proc/sys/net/ipv6/conf/$i/disable_ipv6 2>/dev/null
	ip link set $i mtu 1500 up
done
ethtool -K vb gro off >/dev/null 2>&1
exec python3 "$DIR/func_test.py" --bin "$ROOT/replaystorm" --pcaps "$PCAPS" "$@"
