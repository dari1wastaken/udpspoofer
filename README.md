# UDP/TCP Reactive Telescope

- Listens on the given interface for IPv4 packets (TCP and UDP supported)
- Crafts stateless valid replies and sends them back to scanners through the same interface
    - TCP: `SYN` --> `SYN-ACK`; `ACK [+ Data]` --> `ACK`; `RST/FIN` dropped to elicit more interaction
    - UDP: `UDP [+ Data]` --> `UDP [Empty]`
- Saves (only) incoming traffic to the configured Clickhouse database tables for UDP and TCP (schemas under `clickhouse/init`)

## udpspoofer

#### Build

- To build and export the binary: `./scripts/build-linux.sh`
- To build the container `docker compose build [--no-cache] udpspoofer`

#### Usage

```
USAGE:
   udpspoofer_database --subnet IPv4_SUBNET_OR_HOST [--interface,--protocols,--save-clickhouse-db,--save-blocked-udp,-h]

GLOBAL OPTIONS:
   --interface value     Name of the network interface to capture packets from (default: "eth0")
   --subnet value        Addresses to spoof
   --protocols value     List of comma-separated protocols to send replies for. Supported: [tcp, udp]
   --save-clickhouse-db  Save packets to Clickhouse tables (default FALSE)
   --save-blocked-udp    Save UDP packets that have been blocked by the rate limiter (default FALSE, useless without "--protocols udp" enabled and "--save-clickhouse-db")
   --help, -h            show help
```

Examples
```
./udpspoofer --interface eth0 --subnet 172.25.0.3 --protocols udp
./udpspoofer --interface eth0 --subnet 172.25.0.0/25 --protocols udp,tcp --save-blocked-udp
./udpspoofer --interface eth0 --subnet 172.25.0.0/24 --protocols tcp
```

#### Configuration and Setup

Configuration
- Variables are loaded from `.env` file for binary and `docker.env` for container.
- Descriptions can be found in `example.env`
- **Note:** a static drop log will print dropped packets in case of channel saturation, so that larger channel sizes can be set if needed. The interval can be regulated with `STATIC_DROP_LOG_SECS`.

Setup
- Firewall rules need to be set to prevent the OS from sending TCP RST/FIN to incoming scans, as well as ICMP "UDP port unreachable" messages.

```bash
# For TCP reactiveness
sudo iptables -A OUTPUT -o eth0 -p tcp -s IPv4_SUBNET --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -o eth0 -p tcp -s IPv4_SUBNET --tcp-flags FIN FIN -j DROP

# For UDP reactiveness
sudo iptables -A OUTPUT -o eth0 -p icmp -s IPv4_SUBNET -j DROP
```

#### Rate Limiting

When running a UDP reactive subnet (`--protocols udp[,tcp]`), blocking of replies will be triggered per source IP, source /24, or destination endpoint (ip:port). Thresholds and time intervals are defined and tunable in `example.env`, reference ones are given for a monitored /24 subnet.

EXAMPLES
- `src_ip` is blocked for `UDP_RL_BLOCK_TTL_MINUTES` if it sends `UDP_IP_LIMIT` packets within `UDP_RL_WINDOW_MINUTES`
- `src_24` is blocked for `UDP_RL_BLOCK_TTL_MINUTES` if it sends `UDP_SUBNET_LIMIT` packets within `UDP_RL_WINDOW_MINUTES`
- `dst_ip:dst_port` (from monitored `--subnet`) is blocked for `UDP_RL_BLOCK_TTL_MINUTES` if it receives `UDP_ENDPOINT_LIMIT` within `UDP_RL_WINDOW_MINUTES`
    - **NOTE:** because it is unlikely to monitor more than an IPv4 /16 subnet, only the lower two bytes of `dst_ip` are tracked together with `dst_port` to keep the tracked key as a uint32

## Testing Setup

The `docker-compose.yml` setup includes the `pcap_sender` module and some python3 scripts to create a local setup for stress testing the rate limiter (run `prep_compose.sh` to delete the container's Clickhouse data between rebuilds)
- `pcap_sender` replays the given pcap file
- `scripts/stress-endpoints.py` spoofs empty UDP packets with the option to randomize fields
- `scripts/stress-ports.py` used to test saturation of ports in rate tracking

#### pcap-sender

Non-spoofing (default):
```bash
./pcap-sender --pcap input.pcap --dst-ip udpspoofer --dst-port 9999 --pps 1000
```

Spoofing (requires CAP_NET_RAW and CAP_NET_ADMIN):
```bash
./pcap-sender --pcap input.pcap --dst-ip udpspoofer --dst-port 9999 --pps 1000 --spoof-srcip --iface eth0
```

Options:
- `--src-port <port>`: override UDP source port used in spoofed packets (default uses source port from pcap)
- `--pps <n>`: throttle sending to approx n packets per second
- `--iface`: interface used for ARP and raw injection (default `eth0` inside container)