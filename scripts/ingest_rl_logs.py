#!/usr/bin/env python3

import os
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from clickhouse_driver import Client

BATCH_SIZE = 50000
TABLE_NAME = "blocked_entries"

UTC = ZoneInfo("UTC")
AMS = ZoneInfo("Europe/Amsterdam")

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def load_config():
    load_dotenv()

    return {
        "host": os.getenv("DATABASE_HOST"),
        "port": int(os.getenv("DATABASE_PORT", 9000)),
        "database": os.getenv("DATABASE"),
        "user": os.getenv("DATABASE_USER"),
        "password": os.getenv("DATABASE_PASSWORD"),
        "client_name": os.getenv("DATABASE_CLIENT_NAME"),
    }





def connect_clickhouse(cfg):
    return Client(
        host=cfg["host"],
        port=cfg["port"],
        database=cfg["database"],
        user=cfg["user"],
        password=cfg["password"],
        client_name=cfg["client_name"],
    )


# ALTER TABLE blocked_entries
# ADD INDEX entry_type_idx entry_type TYPE set(3) GRANULARITY 1;

def create_table(client):
    query = f"""
    CREATE TABLE IF NOT EXISTS {TABLE_NAME}
    (
        start_time DateTime64(0, 'Europe/Amsterdam'),
        duration_min UInt16,
        entry_type LowCardinality(String),
        entry Tuple(IPv4, UInt16)
    )
    ENGINE = MergeTree
    PARTITION BY toStartOfWeek(start_time)
    ORDER BY (toDate(start_time), entry_type, entry)
    """

    client.execute(query)


def parse_time(timestr):
    """
    Convert log timestamp from UTC to Europe/Amsterdam timezone.
    """
    if timestr.endswith("Z"):
        timestr = timestr[:-1]

    # Parse as UTC
    dt = datetime.fromisoformat(timestr).replace(tzinfo=UTC)

    # Convert to Amsterdam time
    return dt.astimezone(AMS).replace(tzinfo=None)


def parse_log_line(line):
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        logging.warning("Invalid JSON line skipped")
        return None

    if obj.get("level") != "info":
        return None

    message = obj.get("message", "")

    if "BLOCKING" not in message:
        return None

    start_time = parse_time(obj["time"])
    duration = 10

    if "Endpoint" in message:
        ip = obj.get("dst_ip")
        port = obj.get("dst_port")

        if not ip or port is None:
            return None

        return (
            start_time,
            duration,
            "endpoint",
            (ip, int(port)),
        )

    if "Source IP" in message:
        ip = obj.get("src_ip")
        if not ip:
            return None

        return (
            start_time,
            duration,
            "src_ip",
            (ip, 32),
        )

    if "Source /24" in message:
        ip = obj.get("src_net")
        if not ip:
            return None

        return (
            start_time,
            duration,
            "src_24",
            (ip, 24),
        )

    return None


def insert_batch(client, batch):
    if not batch:
        return

    client.execute(
        f"INSERT INTO {TABLE_NAME} (start_time, duration_min, entry_type, entry) VALUES",
        batch,
    )


def process_file(client, filepath, batch):
    logging.info(f"Processing {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            row = parse_log_line(line)

            if row:
                batch.append(row)

            if len(batch) >= BATCH_SIZE:
                insert_batch(client, batch)
                batch.clear()


def find_log_files(root):
    for path in Path(root).rglob("*"):
        if path.suffix in (".log", ".err"):
            yield path


def main():
    setup_logging()

    parser = argparse.ArgumentParser()
    parser.add_argument("log_root", help="Root directory containing run_* folders")

    args = parser.parse_args()

    cfg = load_config()
    client = connect_clickhouse(cfg)

    create_table(client)

    batch = []
    total = 0

    for file in find_log_files(args.log_root):
        process_file(client, file, batch)

    if batch:
        insert_batch(client, batch)
        total += len(batch)

    logging.info("Finished processing logs")


if __name__ == "__main__":
    main()