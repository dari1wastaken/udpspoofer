#!/bin/sh

## Suppress kernel responses on TCP SYNs and UDPs
iptables -A OUTPUT -o eth0 -s 172.25.0.3 -p tcp --tcp-flags RST RST -j DROP
iptables -A OUTPUT -o eth0 -s 172.25.0.3 -p tcp --tcp-flags FIN FIN -j DROP
iptables -A OUTPUT -o eth0 -s 172.25.0.3 -p icmp -j DROP

# ./udpspoofer --subnet 172.25.0.3 --interface eth0 --protocols udp --save-clickhouse-db --save-blocked-udp

sleep infinity