#!/usr/bin/env python3
from bcc import BPF, libbcc

def attach():
    b = BPF(src_file="std_trie_kern.c")

    b.attach_xdp(dev="veth-basic02", fn=b.load_func("xdp_prog_simple", BPF.XDP))

#def detach():
#    BPF.remove_xdp(dev="ens33")

attach()
#detach()