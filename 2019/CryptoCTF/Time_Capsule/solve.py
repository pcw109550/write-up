from config import c, n, t, z, factors
from Crypto.Util.number import long_to_bytes as l2b
from operator import mul

# factor by factordb
assert n == reduce(mul, factors)
phin = reduce(mul, [p - 1 for p in factors])
l = pow(2, pow(2, t, phin), n)
m = c ^ l ^ z
flag = l2b(m)

assert flag == "CCTF{_______________________________________________Happy_Birthday_LCS______________________________________________}"
print(flag)
