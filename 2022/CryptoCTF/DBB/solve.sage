from Crypto.Util.number import long_to_bytes as l2b
from sage.arith.functions import LCM_list
from sage.rings.finite_rings.integer_mod import square_root_mod_prime

n = 34251514713797768233812437040287772542697202020425182292607025836827373815449
p = 11522256336953175349
q = 14624100800238964261
r = 203269901862625480538481088870282608241

assert p * q * r == n

a = 31337
Px = 10680461779722115247262931380341483368049926186118123639977587326958923276962
Py = 4003189979292111789806553325182843073711756529590890801151565205419771496727


b = Integer((Py**2 - Px**3 - a * Px) % n)

F = IntegerModRing(n)
E = EllipticCurve(F, [a, b])
P = E(Px, Py)

Gx = 7331


def sqrt(prime, x):
    return Integer(square_root_mod_prime(Mod(x**3 + a * x + b, prime), prime))


Ep = EllipticCurve(GF(p), [a % p, b % p])
Eq = EllipticCurve(GF(q), [a % q, b % q])
Er = EllipticCurve(GF(r), [a % r, b % r])

"""
kp = Ep.order()
kq = Eq.order()
kr = Er.order()
"""

"""
print(f"{kp = }")
print(f"{kq = }")
print(f"{kr = }")
"""

for i in range(8):
    Gyp = sqrt(p, Gx) * [1, -1][i & 1]
    Gyq = sqrt(q, Gx) * [1, -1][(i >> 1) & 1]
    Gyr = sqrt(r, Gx) * [1, -1][(i >> 2) & 1]
    assert Ep(Gx % p, Gyp)
    assert Eq(Gx % q, Gyq)
    assert Er(Gx % r, Gyr)

    Gy = CRT_list(
        [
            Gyp,
            Gyq,
            Gyr,
        ],
        [p, q, r],
    )
    G = E(Gx, Gy)

    Gp = Ep(Gx % p, Gy % p)
    Pp = Ep(Px % p, Py % p)
    xx = Integer(discrete_log(Pp, Gp, operation="+"))
    assert Pp == xx * Gp
    Gq = Eq(Gx % q, Gy % q)
    Pq = Eq(Px % q, Py % q)
    yy = Integer(discrete_log(Pq, Gq, operation="+"))
    assert Pq == yy * Gq
    Gr = Er(Gx % r, Gy % r)
    Pr = Er(Px % r, Py % r)
    zz = Integer(discrete_log(Pr, Gr, operation="+"))
    assert Pr == zz * Gr

    kp = Gp.order()
    kq = Gq.order()
    kr = Gr.order()

    m = CRT_list([xx, yy, zz], [kp, kq, kr])
    lll = LCM_list([kp, kq, kr])

    assert m * G == P
    flag = l2b(m)
    print(flag)
    if b"CCTF" in flag:
        print(flag)
        exit()

# CCTF{p0Hl!9_H31LmaN_4tTackin9!}
