from sys import argv

assert len(argv[1:]) == 2
[Px, Py] = list(map(Integer, argv[1:]))

a, b = 1, -1
p = 14753
E = EllipticCurve(Zmod(p), [a, b])
G = E(1, 1)
P = E(Px, Py)

d = discrete_log(P, G, operation="+")
assert P == d * G
print(d)
