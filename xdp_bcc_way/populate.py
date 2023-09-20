#!/usr/bin/env python3

from bcc import BPF, libbcc, table
#from ctypes import * 
import ctypes as ct

PIN_PATH = "/sys/fs/bpf/my_trie"



class key_t(ct.Structure):
    _fields_ = [("pfxlen", ct.c_uint),
                ("ip", ct.c_ubyte * 4)]
    
    def printKey(self):
        return "{}/{}".format(
            '.'.join(str(x) for x in self.ip),
            str(self.pfxlen)
        )

class value_t(ct.Structure):
    _fields_ = [("valid", ct.c_uint64)]

    def printVal(self):
        return str(self.valid)
    
class PinnedTrie(table.LpmTrie):
    def __init__(self, path, leafType):
        map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(path.encode('utf-8')))
        if map_fd < 0:
            raise Exception("Unable to locate pinned Trie. Did you run compile.py?")
        self.map_fd = map_fd
        self.Key = key_t
        self.Leaf = leafType
        #add self.maxEntries later

def addEntry(trie, key, value):
    trie[key] = value

def populate():
    trie = PinnedTrie(PIN_PATH, value_t)                   #libbcc.lib.bpf_obj_get(ct.c_char_p(PIN_PATH.encode('utf-8')))
    print(trie.map_fd) # this is our trie fd
    test_key = key_t(int(24), tuple((192, 168, 0, 0)))
    test_val = value_t(int(1))
    flag = ct.c_uint64(0)

    ret = addEntry(trie, test_key, test_val)
    #ret = libbcc.lib.bpf_map_update_elem(trie, test_key, test_val, flag)
    print(ret)

populate()