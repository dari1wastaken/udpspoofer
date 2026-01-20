# UDP Reactive Telescope - Containerized testing setup

This setup creates:
- A ClickHouse instance with test tables
- A simple UDP pcap sender
- The `udpspoofer` reactive telescope

## Prerequisites

- Docker and docker-compose
- A test pcap at `./testdata/input.pcap` containing UDP packets

## Structure

- `docker-compose.yml`: Orchestrates services
- `clickhouse/init/01_schema.sql`: Initializes `test.udppackets` and `test.tcppackets`
- `Dockerfile.udpspoofer`: Builds and runs the telescope
- `Dockerfile.pcap-sender`: Builds the UDP pcap sender
- `cmd/pcap-sender/main.go`: Sends UDP payloads from a pcap file
- `docker.env`: Environment for `udpspoofer` in Docker

## Usage

1. Place your pcap at `./testdata/input.pcap`.
2. Bring up the stack:

```bash
docker compose up --build
```

3. The sender will stream UDP payloads to the `udpspoofer` service. `udpspoofer` captures traffic on `eth0`, applies per-IP, /24, and per-endpoint rate limiting, reacts to UDP, and batches inserts into ClickHouse.
4. Inspect data:

```bash
# HTTP UI
http://localhost:8123

# clickhouse-client (docker exec)
docker exec -it clickhouse clickhouse-client \
  --user test --password test \
  --query "SELECT count() FROM test.udppackets"
```

## Configuration

- `docker.env` supplies DB connection and batching/channel sizes for `udpspoofer`.
- Network subnet is pinned to `172.25.0.0/16`. `udpspoofer` is invoked with:
  - `--interface eth0`
  - `--subnet 172.25.0.0/16`
  - `--protocols udp`

Adjust compose `command` or environment as needed.

## Notes

- `udpspoofer` uses libpcap and requires `NET_ADMIN` and `NET_RAW` capabilities to capture and send raw frames.
- The pcap sender uses `pcapgo` to read the file and sends only UDP payloads to the destination host/port. It does not preserve original headers.
- Table schemas match the current insertion fields (checksums omitted, TCP flags stored as UInt8).
- For higher throughput, tune `CHANNEL_SIZE` and `INSERT_BATCH_SIZE` in `docker.env`, and the sender's `--pps` flag.