#!/usr/bin/env sage
import random
from output import enc
from flag import FLAG
p = 8443
l = len(enc)


def transpose(x):
	result = [[x[j][i] for j in range(len(x))] for i in range(len(x[0]))]
	return result


def vsum(u, v):
	assert len(u) == len(v)
	l, w = len(u), []
	for i in range(l):
		w += [(u[i] + v[i]) % p]
	return w


def sprod(a, u):
	w = []
	for i in range(len(u)):
		w += [a*u[i] % p]
	return w

def decrypt(enc):
    l = len(enc)
    enc = transpose(enc)
    q = []
    for r in enc:
        r_set = set(r)
        for k in range(p):
            test = set()
            for t in range(0, 126):
                test.add(k * t % p)
            if len(r_set - test) <= 1:
                q.append(k)
                break
    assert l == len(q)
    pt = ""
    for e, i in zip(list(q), range(l)):
        pt += chr(e / (i + 1))
    return pt

flag = decrypt(enc)
assert flag == "CCTF{H0w_f1Nd_th3_4lL_3I9EnV4Lu35_iN_FiN173_Fi3lD5!???}"
print(flag)
