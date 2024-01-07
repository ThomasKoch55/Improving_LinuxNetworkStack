#!/usr/bin/env python3

from bcc import BPF, libbcc
import ctypes as ct
import subprocess
import sys

cflgs = ['-O2', '-std=gnu89', '-w', '-D__KERNEL__', '-D__TARGET_ARCH_x86']

def attach(iface):
    b = BPF(src_file="xdpHelpers.c", cflags=cflgs)

    func = b.load_func("xdp_helper", BPF.XDP)


    
    res1 = b.attach_xdp(iface, func, 0)#, flags=XDP_FLAGS_DRV_MODE)
    print(res1)
    res = libbcc.lib.bpf_obj_pin(b["error_map"].map_fd, ct.c_char_p("/sys/fs/bpf/error_map".encode('utf-8')))
    print(res)

    

def detach(iface):
    BPF.remove_xdp(dev=iface)
    cmd = ['unlink', "/sys/fs/bpf/error_map"]
    subprocess.check_output(cmd)
    cmd = ['unlink', "/sys/fs/bpf/error_map"]
    subprocess.check_output(cmd)





if(sys.argv[1] == "-c"):
    attach(iface = "enp0s3")
elif(sys.argv[1] == "-d"):
    detach(iface = "enp0s3")
