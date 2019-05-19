#!/usr/bin/env sage
from functools import reduce

f = open("result.txt", "r")
f.readline()
ct = f.readline().strip()
f.close()
ct = [ord(c) for c in ct.decode("hex")]
ct = [ct[5 * i:5 * (i + 1)] for i in range(len(ct) // 5)]
ct = [ct[:5], ct[5:]]

assert is_prime(251)
R = IntegerModRing(251)
ct = [matrix(R, c) for c in ct]
m2 = matrix(R, [[1, 3, 2, 9, 4],
    [0, 2, 7, 8, 4],
    [3, 4, 1, 9, 4],
    [6, 5, 3, -1, 4],
    [1, 4, 5, 3, 5]])

cand = []


def tostr(ct):
    ct = list(ct)
    ct = [list(c) for c in ct]
    ct = reduce((lambda x, y: x + y), ct)
    return "".join([chr(int(c)) for c in ct])

cand.append(tostr(ct[0] * m2.inverse()))
cand.append(tostr(ct[1] * m2.inverse()))
cand.append(tostr(m2.inverse() * ct[0]))
cand.append(tostr(m2.inverse() * ct[1]))

flag = (cand[0] + cand[1]).rstrip('%')
flag = "HarekazeCTF{" + flag + "}"
assert flag == "HarekazeCTF{Op3n_y0ur_3y3s_1ook_up_t0_th3_ski3s_4nd_s33}"
print(flag)
