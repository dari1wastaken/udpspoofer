# UDP/TCP Reactive Telescope

NOTE: docker compose setup is just for local testing. This includes the local dockerized clickhouse instance and the pcap-sender to simulate a scanner 

The `pcap-sender` supports `--spoof-srcip` to craft and inject raw Ethernet/IPv4/UDP frames with randomized source IPv4 addresses. Non-spoof mode keeps sending only UDP payloads via sockets.

## udpspoofer 

#### Build

Ignore the docker compose setup, just run `./build-linux.sh`

#### Examples of usage

```
./udpspoofer --interface eth0 --subnet 172.25.0.3 --protocols udp
./udpspoofer --interface eth0 --subnet 172.25.0.0/25 --protocols udp,tcp
./udpspoofer --interface eth0 --subnet 172.25.0.3/24 --protocols tcp
```

#### Rate Limiting

Per source IP, source /24, destination endpoint (ip:port)

EXAMPLES
- `src_ip` is blocked for `UDP_RL_BLOCK_TTL_MINUTES` if it sends us `UDP_IP_LIMIT` within `UDP_RL_WINDOW_MINUTES`
- `src_24` is blocked for `UDP_RL_BLOCK_TTL_MINUTES` if it sends us `UDP_SUBNET_LIMIT` within `UDP_RL_WINDOW_MINUTES`
- `dst_ip:dst_port` (from `--subnet`) is blocked for `UDP_RL_BLOCK_TTL_MINUTES` if it receives `UDP_ENDPOINT_LIMIT` within `UDP_RL_WINDOW_MINUTES`

## Docker Testing Setup

`docker-compose.yml` grants the necessary capabilities to `pcap-sender`. The default command demonstrates spoofing mode. ARP resolution is performed on the Docker bridge network to find the destination MAC for the `udpspoofer` service.

```bash
docker compose up --build
```

Adjust the compose command or flags as needed.


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