from Crypto.Util.number import long_to_bytes as l2b
from string import printable
from config import n, c
from gmpy2 import iroot

[n, c] = list(map(Integer, [n, c]))


def check(m):
    return all(ch in printable for ch in l2b(m))

# adlit(a) == 2 ** a.bit_length() - a - 1
nbit = n.nbits() // 2 + 1
p = var("p")
out = solve([p * (2 ** nbit - p - 1 + 31337) == n], p)
p = Integer(out[0].rhs())
assert n % p == 0
q = n // p
assert p * q == n
# assert is_prime(p) and is_prime(q)
phin = (p - 1) * (q - 1)

# e == 2 ** x - 1
x = 0
while True:
    x += 1
    e = (1 << x) - 1
    assert e & (e + 1) == 0
    g = gcd(e, phin)
    if g > 10 or e % (g ** 2) == 0:
        continue
    d1 = inverse_mod(e // g, phin)
    m, valid = iroot(int(pow(c, d1, n)), int(g))
    if valid and check(m):
        flag = l2b(m)
        break

assert flag == "CCTF{it5_3a5y_l1k3_5uNd4y_MOrn1N9}"
print(flag)
