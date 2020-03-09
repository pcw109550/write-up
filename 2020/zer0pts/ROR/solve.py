#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes as l2b

f = open('chall.txt')
data = list(map(int, f.read().strip().split('\n')))
f.close()

ror = lambda x, l, b: (x >> l) | ((x & ((1 << l) - 1)) << (b - l))
rol = lambda x, l, b: ror(x, b - l, b)

m = 0
for i in range(len(data)):
    m += (data[i] % 2) << i
flag = l2b(m).decode()
assert flag == 'zer0pts{0h_1t_l34ks_th3_l34st_s1gn1f1c4nt_b1t}'
print(flag)
