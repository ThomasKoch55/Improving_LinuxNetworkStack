#!/usr/bin/env python3

from bcc import BPF, libbcc, table
import ctypes as ct
import sys

PIN_PATH = "/sys/fs/bpf/error_map"
MAX_ENTRIES = 100



class key_t(ct.Structure):
    _fields_ = [("idx", ct.c_uint32)]
    
    def printKey(self):
        return str(self.idx)
        

class value_t(ct.Structure):
    _fields_ = [("ecode", ct.c_uint32)]

    def printVal(self):
        return str(self.ecode)
    
class PinnedMap(table.Array):
    def __init__(self, path, leafType):
        map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(path.encode('utf-8')))
        if map_fd < 0:
            raise Exception("Unable to locate pinned Trie. Did you run compile.py?")
        self.map_fd = map_fd
        self.Key = key_t
        self.Leaf = leafType
        #self.maxEntries = MAX_ENTRIES


def print_map():

    trie = PinnedMap(PIN_PATH, value_t)

    total_pairs = 0
    for i,ii in trie.items():
        print("Trie Pair: {0}".format(total_pairs))
        print(i.printKey())
        print(ii.printVal())
        total_pairs += 1
    print("{0} total items dumped from the map.".format(total_pairs))


print_map()