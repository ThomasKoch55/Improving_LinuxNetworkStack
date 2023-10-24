#!/usr/bin/env python3

from bcc import BPF, libbcc, table
import ctypes as ct

PIN_PATH = "/sys/fs/bpf/my_trie"
MAX_ENTRIES = 10000000



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
        self.maxEntries = MAX_ENTRIES

def addEntry(trie, key, value):
    trie[key] = value




def populate(filename):

    trie = PinnedTrie(PIN_PATH, value_t)

    val = value_t(1)

    # Each line is parsed into a list containing the IP as list[0] and the SNM as list[1]
    # each list is then fed into our trie located at PIN_PATH with a hardcoded value_t of 1
    # NOTE: the trie has a max size of MAX_ENTRIES

    with open(filename, "rt") as file:

        for line in file:

            output = line.split("\t")
            output = output[:-1]
            print(output)
            #Split IP at '.' and convert to int
            ip_list = output[0].split(".")
            count = 0
            for i in ip_list:
                ip_list[count] = int(i)
                count += 1
            
            key = key_t(int(output[1]), tuple(ip_list))

            ret = addEntry(trie, key, val)

            if(ret == -1):
                print("Add to Trie failed! KEY: {0}   VAL: {1}".format(key.printKey(), val.printVal()))
                exit(-1)
    


def print_trie():

    trie = PinnedTrie(PIN_PATH, value_t)

    total_pairs = 0
    for i,ii in trie.items():
        print("Trie Pair: {0}".format(total_pairs))
        print(i.printKey())
        print(ii.printVal())
        total_pairs += 1
    print("{0} total items dumped from the trie.".format(total_pairs))




def populate_test():
    trie = PinnedTrie(PIN_PATH, value_t)                   
    print("Trie FD: ", trie.map_fd) # this is our trie fd

    ### TEST KEY ###

    test_key = key_t(int(24), tuple((192, 168, 0, 0)))
    print("Test Key: ", test_key.printKey())

    ################


    ### TEST VAL ###

    test_val = value_t(int(1))
    print("Test Val: ", test_val.printVal())

    ################

    
    ret = addEntry(trie, test_key, test_val)
    #ret = libbcc.lib.bpf_map_update_elem(trie.map_fd, test_key, test_val, flag)
    print(ret)
   
    for i,ii in trie.items():
        print("Dumping Trie:")
        print(i.printKey())
        print(ii.printVal())

#populate_test()

#populate("test_routes.txt")

print_trie()