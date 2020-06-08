#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes as l2b
from config import n, C1, C2
e = 3

n1 = n
PRxy.<x,y> = PolynomialRing(Zmod(n1))
PRx.<xn> = PolynomialRing(Zmod(n1))
PRZZ.<xz,yz> = PolynomialRing(Zmod(n1))
 
g1 = x**e - C1
g2 = (x + y)**e - C2
 
q1 = g1.change_ring(PRZZ)
q2 = g2.change_ring(PRZZ)
 
h = q2.resultant(q1)
# need to switch to univariate polynomial ring
# because .small_roots is implemented only for univariate
h = h.univariate_polynomial() # x is hopefully eliminated
h = h.change_ring(PRx).subs(y=xn)
h = h.monic()
 
roots = h.small_roots(X=2**128, beta=0.3)
assert roots, "Failed1"
 
diff = roots[0]
if diff > 2**32:
    diff = -diff
    C1, C2 = C2, C1

print(diff)

x = PRx.gen() # otherwise write xn
g1 = x**e - C1
g2 = (x + diff)**e - C2
 
# gcd
while g2:
    g1, g2 = g2, g1 % g2
 
g = g1.monic()
assert g.degree() == 1, "Failed 2"
 
# g = xn - msg
msg = -g[0]
# convert to str
h = msg

print(l2b(h))
flag = 'Defenit{Oh_C@Pp3r_SM1TH_SH0Rt_P4D_4TT4CK!!_Th1S_I5_Ve12Y_F4M0US3_D0_Y0u_UnderSt4Nd_ab@ut_LLL_AlgoriTHM?}'