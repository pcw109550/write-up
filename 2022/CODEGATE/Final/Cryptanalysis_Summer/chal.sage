from sage.rings.finite_rings.hom_finite_field import FiniteFieldHomomorphism_generic
import os 

def random():
    return int.from_bytes(os.urandom(32), "big")

def randomLR(l, r):
    return l + random() % (r - l + 1)

beta = 10
n = 100
q = 250007

Px = PolynomialRing(GF(q), 'x')
x = Px.gen()

Py = PolynomialRing(GF(q), 'y')
y = Py.gen()

def get_small_irreducible_poly(n):
    while True:
        f = x ** n
        for i in range(n // 2):
            f += randomLR(-1, 1) * (x ** i)
        if f.is_irreducible():
            return f 

def get_random_irreducible_poly(n):
    while True:
        F = y ** n 
        for i in range(n):
            F += randomLR(0, q - 1) * (y ** i)
        if F.is_irreducible():
            return F

f = get_small_irreducible_poly(n)
F = get_random_irreducible_poly(n)

GFx = GF(q ** n, 'x', modulus = f)
GFy = GF(q ** n, 'y', modulus = F)

H = FiniteFieldHomomorphism_generic(Hom(GFx, GFy))

def get_bounded_samples(num):
    samples = []
    for _ in range(num):
        polx = 0
        for i in range(n):
            polx += randomLR(-beta, beta) * (x ** i)
        samples.append(H(GFx(polx)))
    return samples 

def get_random_samples(num):
    samples = []
    for _ in range(num):
        poly = 0
        for i in range(n):
            poly += randomLR(0, q - 1) * (y ** i)
        samples.append(GFy(poly))
    return samples

def send(samples):
    for sample in samples:
        print(Py(sample).coefficients(sparse=False))

print(F.coefficients(sparse=False))

for _ in range(100):
    sample1 = get_bounded_samples(30)
    sample2 = get_random_samples(30)

    which = randomLR(0, 1) # 0 or 1

    if which == 0:
        send(sample1)
    else:
        send(sample2)
    
    answer = int(input())
    assert answer == which

with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), "flag.txt")) as f:
    FLAG = f.read().strip()
    print(FLAG)