#!/usr/bin/env sh
set -eu

IFACE="${IFACE:-eth0}"
SUBNET="${SUBNET:-}"
PROTOCOLS="${PROTOCOLS:-}"
SAVE_CLICKHOUSE_DB="${SAVE_CLICKHOUSE_DB:-false}"
SAVE_BLOCKED_UDP="${SAVE_BLOCKED_UDP:-false}"

if [ -z "$SUBNET" ]; then
  echo "ERROR: SUBNET is required"
  exit 1
fi

iptables -I OUTPUT -o "$IFACE" -p tcp -s "$SUBNET" --tcp-flags RST RST -j DROP 2>/dev/null || true
iptables -I OUTPUT -o "$IFACE" -p tcp -s "$SUBNET" --tcp-flags FIN FIN -j DROP 2>/dev/null || true
iptables -I OUTPUT -o "$IFACE" -p icmp -s "$SUBNET" -j DROP 2>/dev/null || true

echo "Starting udpspoofer:"
echo "  IFACE=$IFACE"
echo "  SUBNET=$SUBNET"
echo "  PROTOCOLS=$PROTOCOLS"
echo "  SAVE_CLICKHOUSE_DB=$SAVE_CLICKHOUSE_DB"
echo "  SAVE_BLOCKED_UDP=$SAVE_BLOCKED_UDP"

ARGS="--interface ${IFACE} --subnet ${SUBNET} --protocols ${PROTOCOLS}"

if [ "$SAVE_CLICKHOUSE_DB" = "true" ]; then
  ARGS="${ARGS} --save-clickhouse-db"
fi

if [ "$SAVE_BLOCKED_UDP" = "true" ]; then
  ARGS="${ARGS} --save-blocked-udp"
fi

exec /app/udpspoofer $ARGS