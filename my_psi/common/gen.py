from random import randint


def gendata(n, num_bits, fname):
    max = 2**num_bits - 1
    l = []
    for i in range(n):
        rnd = randint(0, max)
        while (rnd in l):
            rnd = randint(0, max)
        l.append(rnd)
    f = open(fname, "w")
    for v in l:
        f.write(str(v) + " ")
    f.close()

n_values = 3500
n_bits = 16
gendata(n_values, n_bits, "inp0")
gendata(n_values, n_bits, "inp1")
