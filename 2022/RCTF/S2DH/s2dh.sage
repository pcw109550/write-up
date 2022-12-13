from sage.all import *

a = 43
b = 26
p = 2^a*3^b - 1
assert p in Primes()

K.<i> = GF(p^2, modulus=x^2+1)
E = EllipticCurve(K, [1, 0])

Pa = E(0)
while (2^(a-1))*Pa == 0:
    Pa = 3^b * E.random_point()
print(Pa)

Qa = Pa
while Pa.weil_pairing(Qa, 2^a)^(2^(a-1)) == 1:
    Qa = 3^b * E.random_point()
print(Qa)

Pb = E(0)
while (3^(b-1))*Pb == 0:
    Pb = 2^a * E.random_point()
print(Pb)

Qb = Pb
while Pb.weil_pairing(Qb, 3^b)^(3^(b-1)) == 1:
    Qb = 2^a * E.random_point()
print(Qb)

Sa = randint(0, 2^a-1)
Ta = randint(0, 2^a-1)
R = Sa*Pa + Ta * Qa
phi = E.isogeny(R)
Ea, phiPb, phiQb = phi.codomain(), phi(Pb), phi(Qb)
print(Ea, phiPb, phiQb)

Sb = randint(0, 3^b-1)
Tb = randint(0, 3^b-1)
R = Sb * Pb + Tb * Qb
psi = E.isogeny(R)
Eb, psiPa, psiQa = psi.codomain(), psi(Pa), psi(Qa)
print(Eb, psiPa, psiQa)

J = Eb.isogeny(Sa*psiPa + Ta*psiQa, algorithm='factored').codomain().j_invariant()
print(J)

flag = open("flag.txt","r").read()
assert flag[:5] == "RCTF{" and flag[-1] == "}"
flag = flag[5:-1]
print(int.from_bytes(flag.encode()) ^^ ((int(J[1]) << 84) + int(J[0])))
