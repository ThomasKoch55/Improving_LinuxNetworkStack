#!/usr/bin/env python3

from bcc import BPF, libbcc
import ctypes as ct

cflgs = ['-O2', '-std=gnu89', '-w', '-D__KERNEL__', '-D__TARGET_ARCH_x86']

def attach(iface):
    b = BPF(src_file="std_trie_kern.c", cflags=cflgs)

    func = b.load_func("xdp_prog_simple", BPF.XDP)


    
    b.attach_xdp(iface, func, 0)#, flags=XDP_FLAGS_DRV_MODE)

    res = libbcc.lib.bpf_obj_pin(b["my_trie"].map_fd, ct.c_char_p("/sys/fs/bpf/my_trie".encode('utf-8')))
    print(res)



    

def detach():
    BPF.remove_xdp(dev="veth-basic02")




attach(iface = "veth-basic02")
#detach()


