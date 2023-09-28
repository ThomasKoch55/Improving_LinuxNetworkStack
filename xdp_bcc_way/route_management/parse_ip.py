# imports


# This function will load all routes from filename onto the LPMtrie
def load_routes(lpmTrie, filename):
    return -1

def parse_testing(filename):
    file = open(filename, "rt")

    for line in file:
        output = line.split("\t")
        output = output[:-1]
        print(output)

parse_testing("test_routes.txt")