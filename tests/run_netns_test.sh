#!/bin/bash
#
# Exercises the AMT gateway library (amt.c) end to end across a real veth
# link between two Linux network namespaces: one plays the AMT relay, the
# other runs the gateway test client. This is closer to reality than
# testing over loopback, since gateway and relay are genuinely separate
# network stacks reached over an actual routed hop.
#
# Linux-only (network namespaces are a Linux kernel feature - there is no
# equivalent sandbox on macOS/BSD). Run as root, e.g.:
#
#   sudo tests/run_netns_test.sh
#
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
	echo "SKIP: network namespaces are Linux-only (running on $(uname -s))" >&2
	exit 77
fi

if [ "$(id -u)" != "0" ]; then
	echo "This test needs root (to create network namespaces). Try: sudo $0" >&2
	exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

NS_RELAY="amt_test_relay"
NS_GW="amt_test_gw"
VETH_RELAY="veth_relay"
VETH_GW="veth_gw"
RELAY_IP="10.200.0.1"
GW_IP="10.200.0.2"
GROUP_IP="232.1.2.3"
SRC_IP="198.51.100.7"

RELAY_PID=""
WORKDIR="$(mktemp -d)"

cleanup() {
	set +e
	if [ -n "$RELAY_PID" ]; then
		ip netns exec "$NS_RELAY" kill "$RELAY_PID" >/dev/null 2>&1
	fi
	ip netns del "$NS_GW" >/dev/null 2>&1
	ip netns del "$NS_RELAY" >/dev/null 2>&1
	rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "== building test client and library =="
cc -Wall -Wextra -O2 -I"$ROOT" -c "$ROOT/amt.c" -o "$WORKDIR/amt.o"
cc -Wall -Wextra -O2 -I"$ROOT" -o "$WORKDIR/test_amt_gateway" \
	"$HERE/test_amt_gateway.c" "$WORKDIR/amt.o"

echo "== setting up namespaces and veth link =="
ip netns add "$NS_RELAY"
ip netns add "$NS_GW"

ip link add "$VETH_RELAY" type veth peer name "$VETH_GW"
ip link set "$VETH_RELAY" netns "$NS_RELAY"
ip link set "$VETH_GW" netns "$NS_GW"

ip netns exec "$NS_RELAY" ip addr add "$RELAY_IP/30" dev "$VETH_RELAY"
ip netns exec "$NS_RELAY" ip link set "$VETH_RELAY" up
ip netns exec "$NS_RELAY" ip link set lo up

ip netns exec "$NS_GW" ip addr add "$GW_IP/30" dev "$VETH_GW"
ip netns exec "$NS_GW" ip link set "$VETH_GW" up
ip netns exec "$NS_GW" ip link set lo up

echo "== starting mock AMT relay in $NS_RELAY =="
ip netns exec "$NS_RELAY" python3 "$HERE/mock_amt_relay.py" \
	"$RELAY_IP" "$RELAY_IP" "$SRC_IP" "$GROUP_IP" \
	> "$WORKDIR/relay.log" 2>&1 &
RELAY_PID=$!

# Give the relay a moment to bind before the gateway starts probing it.
for _ in $(seq 1 20); do
	if ip netns exec "$NS_RELAY" ss -uln 2>/dev/null | grep -q ":2268"; then
		break
	fi
	sleep 0.1
done

echo "== running gateway test client in $NS_GW =="
set +e
ip netns exec "$NS_GW" "$WORKDIR/test_amt_gateway" "$RELAY_IP" "$GROUP_IP" "$SRC_IP"
RESULT=$?
set -e

echo "---- relay log ----"
cat "$WORKDIR/relay.log"
echo "--------------------"

if [ "$RESULT" -eq 0 ]; then
	# The mock relay hands out a short QQIC (5s) so the gateway's
	# proactive, self-scheduled refresh (amt_gateway_timeout()) fires
	# during the test; confirm it actually sent a second Request rather
	# than only ever relying on the relay's own unsolicited refresh Query.
	REQUEST_COUNT="$(grep -c '^request #' "$WORKDIR/relay.log" || true)"
	if [ "$REQUEST_COUNT" -lt 2 ]; then
		echo "FAIL: expected >=2 Request messages (initial + proactive refresh), saw $REQUEST_COUNT"
		RESULT=1
	fi
fi

if [ "$RESULT" -eq 0 ]; then
	echo "PASS: AMT gateway/relay netns test"
else
	echo "FAIL: AMT gateway/relay netns test (exit $RESULT)"
fi

exit "$RESULT"
