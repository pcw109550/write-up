#!/usr/bin/env python3
from gmpy2 import next_prime


def genlist(start, l):
    result = []
    while len(result) != l:
        start = next_prime(start)
        temp = str(start)
        if temp == temp[::-1]:
            result.append(start)
    return result

cipher = ['100', '111', '100', '96', '112', '21', '209', '166', '216', '140', '330', '318', '321', '70221', '70414', '70544', '71414', '71810', '72211', '72827', '73000', '73319', '73722', '74088', '74643', '75542', '1002903', '1008094', '1022089', '1028104', '1035337', '1043448', '1055587', '1062541', '1065715', '1074749', '1082844', '1085696', '1092966', '1094000']
cipher = list(map(int, cipher))

key = genlist(1, 13)
key += genlist(50000, 13)
key += genlist(500000, len(cipher) - 26)
assert len(cipher) == len(key)

for c, k in zip(cipher, key):
    print(chr(c ^ k), end='', flush=True)

