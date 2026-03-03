from scapy.all import *
import ipaddress 
from random import randint

RATE_LIMIT = 600

for _ in range(0, RATE_LIMIT):
    src = str(ipaddress.ip_address(randint(0, 4294967295)))
    packet = IP(src=src, dst="172.25.0.3")/UDP(dport=53)/Raw(b"test")
    send(packet, verbose=False)