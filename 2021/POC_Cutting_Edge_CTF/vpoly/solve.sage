#!/usr/bin/env sage
from sage.all import *
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l

a = 0x173EF9F2D78FE1CA7925215B67D67136
c1 = 0x6E62A8AE251A78497FF839F2F6CAC510
c2 = 0x2EC7AC61D3704B1AEE6AAD3FD1FDB4CE
p = 0x53935563C38A0FC5A3B133EDB401227D

R.<y> = GF(2 ^ 127)
P.<a> = PolynomialRing(GF(2))

modulus = (a ^ 127) + P(R.fetch_int(p))
assert modulus.is_irreducible()

K.<x> = GF(2 ^ 127, modulus=modulus)

b1 = discrete_log(K.fetch_int(c1), K.fetch_int(a))
b2 = discrete_log(K.fetch_int(c2), K.fetch_int(a))

print(b1)
print(b2)
