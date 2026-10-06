#!/bin/bash
# Функциональные тесты на паре veth в отдельном network namespace.
# Под root используется unshare -n, без root — unshare -rn (user namespace).
# Если namespace создать нельзя, тест пропускается (код 0, сообщение SKIP).
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
		echo "SKIP: нет root и недоступны user namespaces — функциональные тесты пропущены"
		exit 0
	fi
	exec env AFR_IN_NS=1 $NS "$0" "$PCAPS" "$@"
fi

# Свой sysfs, чтобы видеть интерфейсы этого namespace
mount -t sysfs sysfs /sys 2>/dev/null || echo "sysfs не смонтирован: статистика интерфейса будет недоступна"
ip link add name va type veth peer name vb || { echo "SKIP: не удалось создать veth"; exit 0; }
for i in va vb; do
	echo 1 >/proc/sys/net/ipv6/conf/$i/disable_ipv6 2>/dev/null
	ip link set $i mtu 1500 up
done
ethtool -K vb gro off >/dev/null 2>&1
exec python3 "$DIR/func_test.py" --bin "$ROOT/afreplay" --pcaps "$PCAPS" "$@"
