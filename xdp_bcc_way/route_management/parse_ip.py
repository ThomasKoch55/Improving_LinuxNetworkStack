# imports


# This function will load all routes from filename onto the LPMtrie
def load_routes(lpmTrie, filename):
    return -1

def parse_testing(filename):
    file = open(filename, "rt")

    for line in file:
        output = line.split("\t")
        output = output[:-1]

        ip_list = output[0].split(".")
        ipt = ()
        count = 0
        for i in ip_list:
            ip_list[count] = int(i)
            count += 1
        print(ip_list)
        print(tuple(ip_list))

parse_testing("test_routes.txt")