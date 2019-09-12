from config import n, c, X, Y
from modular_sqrt import modular_sqrt
from Crypto.Util.number import long_to_bytes as l2b

[n, c, X, Y] = list(map(Integer, [n, c, X, Y]))

# assert Fraction(q - p - 1, q * (p + 1)) == Fraction(X + 2 * Y, s + Y)
# q - p - 1 = X + 2 * Y

p = var("p")
out = solve([p ** 2 + (1 + X + 2 * Y) * p - n == 0], p)
p = Integer(out[1].rhs())
assert n % p == 0
q = n / p
[p, q] = list(map(Integer, [p, q]))
assert n == p * q
phin = Integer((p - 1) * (q - 1))
e = 0x20002
e_ = Integer(e / 2)
d_ = inverse_mod(e_, phin)
m_ = pow(c, d_, n)

# Directly apply sqrt
assert modular_sqrt(m_, p) == 0
assert modular_sqrt(m_, q) == 0
flag = l2b(sqrt(Integer(m_)))

assert flag == "CCTF{4Ll___G1rL5___Are__T4len73E__:P}"
print(flag)
