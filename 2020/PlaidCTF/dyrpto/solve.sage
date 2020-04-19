from output import modulus as N, mlen, ct1, ct2
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l
N = Integer(N)
e = 3

# Coppersmith's short pad attack
PRxy.<x,y> = PolynomialRing(Zmod(N))
PRx.<xn> = PolynomialRing(Zmod(N))
PRZZ.<xz,yz> = PolynomialRing(Zmod(N))

g1 = x ** e - ct1
g2 = (x + y + (1 << (2152 + 192))) ** e - ct2

q1 = g1.change_ring(PRZZ)
q2 = g2.change_ring(PRZZ)

h = q2.resultant(q1)
h = h.univariate_polynomial()
h = h.change_ring(PRx).subs(y=xn)
h = h.monic()

kbits = 192
beta = float(sqrt((kbits / N.nbits()) * (7 / 6)))
epsilon = beta ** 2 / 7

set_verbose(2)
roots = h.small_roots(X=2 ** kbits, beta=beta, epsilon=epsilon)
set_verbose(0)
diff = roots[0]

if diff >= (1 << kbits):
    diff = N - diff
    ct1, ct2 = ct2, ct1
assert diff < (1 << kbits)

# Franklin-Reiter related message attack
x = PRx.gen()
g1 = (x + (1 << (2152 + 192))) ** e - ct1
g2 = (x + diff) ** e - ct2

# gcd
while g2:
    g1, g2 = g2, g1 % g2

g = g1.monic()
assert g.degree() == 1

msg = -g[0]
flag = l2b(msg)
assert flag == b'\x08\x00\x12\x8a\x02I never know what to put into these messages for CTF crypto problems. You gotta pad the length but flags can only reasonably be so long. Anyway, the flag should be coming any moment now... Ah, here it comes! The flag is: PCTF{w0w_such_p4d_v3ry_r34l1st1c_d0g3_crypt0}\xb4\xac\r\xc1\x1d:\xfd\xf0\x11W\x17\x9e\xb9"6\xfe\'\xe4\x0b\x82\xfc\xe9\xfa@'
flag = flag[flag.find(b'PCTF'):-24].decode()
print(flag)
