from scapy.all import *
import ipaddress
from random import randint
import argparse

for p in range(0, 65535):
    src = str(ipaddress.ip_address(randint(0, 4294967295)))
    sport=p
    dport=p
    packet = (
            IP(src=src, dst="172.25.0.3") / UDP(sport=sport, dport=dport) / Raw(b"test")
    )
    send(packet, verbose=False)