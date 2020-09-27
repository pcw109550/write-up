from config import N, e, ct, hint
from Crypto.Util.number import long_to_bytes as l2b
N = Integer(N)

F.<x> = PolynomialRing(Zmod(N))
f = hint + x * (1 << 700)
f = f.monic()
beta = 2 / 3
epsilon = beta * beta / 7
set_verbose(2)
x0 = f.small_roots(X=2 ^ 324, beta=beta, epsilon=epsilon)
set_verbose(0)
N_ = Integer(hint + x0[0] * (1 << 700))
assert N % N_ == 0
p = N // N_
q = N_ // p
assert p * p * q == N
piN = p * (p - 1) * (q - 1)
d = inverse_mod(e, piN)

flag = l2b(pow(ct, d, N)).decode()
assert flag == 'flag{Easy_Coppersmith_and_bivariate_heuuung...}'

print(flag)
