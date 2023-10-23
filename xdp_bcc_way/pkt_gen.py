from scapy.all import *

test_pkt = IP(src='10.0.2.15', dst='1.0.128.0')

for i in range(0, 500):
    send(test_pkt)