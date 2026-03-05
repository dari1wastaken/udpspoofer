from scapy.all import *
import ipaddress
from random import randint
import argparse

parser = argparse.ArgumentParser(
    prog="stress-endpoints.py",
    description="Stress test with UDP",
    epilog="Epilogue",
)

parser.add_argument(
    "-c", "--pkt-count", type=int, default=600, help="Max packets to be sent"
)  # option that takes a value
parser.add_argument(
    "-p",
    "--spoof-ports",
    action="store_true",
    help="Randomize source and destination ports for every packet",
)
parser.add_argument(
    "-S",
    "--spoof-source",
    action="store_true",
    help="Randomize source IP address for every packet",
)
parser.add_argument(
    "-F",
    "--fix-source",
    type=str,
    default="",
    help="Spoof source IP address for every packet. Overrides -S",
)

flags = parser.parse_args()
pkt_count = flags.pkt_count
spoof_ports = flags.spoof_ports
spoof_source = flags.spoof_source
fix_source = flags.fix_source

for _ in range(0, pkt_count):
    if fix_source != "":
        src = fix_source
    elif spoof_source:
        src = str(ipaddress.ip_address(randint(0, 4294967295)))
    else:
        src = "172.25.0.4"

    if spoof_ports:
        sport = randint(0, 65535)
        dport = randint(0, 65535)
    else:
        sport = 53
        dport = 53
    packet = (
        IP(src=src, dst="172.25.0.3") / UDP(sport=sport, dport=dport) / Raw(b"test")
    )
    send(packet, verbose=False)
