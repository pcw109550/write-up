#!/usr/bin/env sage
from random import randint
from Crypto.Util.number import long_to_bytes


def factor(n, e, d):
    while True:
        z = randint(2, n - 2)
        k, x = 0, e * d - 1
        while not int(x) & 1:
            k += 1
            x /= 2
        t = Integer(z).powermod(x, n)
        if t == 1 or t == (n-1):
            continue
        bad_z = False
        for _ in range(k):
            u = pow(t, 2, n)
            if u == -1 % n:
                bad_z = True
                break
            if u == 1:
                p = gcd(n, t-1)
                q = gcd(n, t+1)
                return p, q
            else:
                t = u
        if bad_z:
            continue


f = open("result.txt", "r")
params = f.readline().split(":")[-1].strip().split(", ")
n = int(params[0].lstrip("(").rstrip("L"))
e = int(params[1])
d = int(params[2].rstrip(")"))
Cx = int(f.readline().strip().split()[-1])
Cy = int(f.readline().strip().split()[-1])
f.close()
(p, q) = factor(n, e, d)
assert p * q == n
assert p % 3 == 2
assert q % 3 == 2
phin = (p - 1) * (q - 1)
assert (e * d - 1) % phin == 0
k = (e * d - 1) / phin

b = (pow(Cy, 2, n) - pow(Cx, 3, n)) % n
EC = EllipticCurve(Zmod(n), [0, b])
assert EC.is_on_curve(Cx, Cy)
E1 = EllipticCurve(IntegerModRing(p), [0, b % p])
E2 = EllipticCurve(IntegerModRing(q), [0, b % q])
C = EC(Cx, Cy)

# https://link.springer.com/content/pdf/10.1007%2FBFb0054116.pdf
# Fact 3
E_order = E1.order() * E2.order()
einv = inverse_mod(e, E_order)

G = einv * C
Gx, Gy = G.xy()

flag = long_to_bytes(Gy) + long_to_bytes(Gx)
assert flag == "HarekazeCTF{dynamit3_with_a_las3r_b3am}"
print(flag)
