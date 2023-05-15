#!/usr/bin/env python3

from bcc import BPF, libbcc

cflgs = ['-O2', '-std=gnu89', '-w', '-D__KERNEL__', '-D__TARGET_ARCH_x86']

def attach(iface):
    b = BPF(src_file="std_trie_kern.c", cflags=cflgs)

    func = b.load_func("xdp_prog_simple", BPF.XDP)


    
    b.attach_xdp(iface, func, 0)#, flags=XDP_FLAGS_DRV_MODE)

#def detach():
#    BPF.remove_xdp(dev="ens33")

attach(iface = "ens4")
#detach()
