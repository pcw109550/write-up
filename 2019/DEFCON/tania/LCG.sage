from consts import g, p, q, y, c
from sys import argv

assert len(argv[1:]) == 6
[r1, s1, r2, s2, z1, z2] = [int(x) for x in argv[1:]]


def Babai_closest_vector(M, G, target):
    # Babai's Nearest Plane algorithm
    small = target
    for _ in xrange(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

B = Matrix([
    [-r1, -r2,     0,     0,     0, 2 / q,        0,        0,        0,        0], # x
    [ s1,   0,     0, -c[0], -c[3],     0, 2 / c[9],        0,        0,        0], # k1
    [  0,  s2,     1,     0,     0,     0,        0, 2 / c[9],        0,        0], # k2
    [  0,   0, -c[6],     1,     0,     0,        0,        0, 2 / c[2],        0], # v1
    [  0,   0, -c[7],     0,     1,     0,        0,        0,        0, 2 / c[5]], # v2
    [  q,   0,     0,     0,     0,     0,        0,        0,        0,        0],
    [  0,   q,     0,     0,     0,     0,        0,        0,        0,        0],
    [  0,   0,  c[9],     0,     0,     0,        0,        0,        0,        0],
    [  0,   0,     0,  c[2],     0,     0,        0,        0,        0,        0],
    [  0,   0,     0,     0,  c[5],     0,        0,        0,        0,        0]
])

Y = vector([z1, z2, c[8], c[1], c[4], 1, 1, 1, 1, 1])

# k2 = (c[6] * ((c[0] * k1 + c[1]) % c[2]) + c[7] * ((c[3] * k1 + c[4]) % c[5]) + c[8]) % c[9]

# v1 = (c[0] * k1 + c[1]) % c[2]
# v2 = (c[3] * k1 + c[4]) % c[5]

# -r1 x + k1 s1 = z1 mod q
# -r2 x + k2 s2 = z2 mod q
# k2 - c[6] v1 - c[7] v2 = c[8] mod c[9]
# -c[0] * k1 + v1 = c[1] mod c[2]
# -c[3] * k1 + v2 = c[4] mod c[5]
# 1/x  ~ 2 / q
# 1/k1 ~ 2 / m3
# 1/k2 ~ 2 / m3
# 1/v1 ~ 2 / c[2]
# 1/v2 ~ 2 / c[5]

for itr in range(100):
    # print("Trial: {:d}".format(itr))
    for i in range(50):
        ia = randint(0, 9)
        ib = randint(0, 9)
        if ib == ia:
            ib = (ib + 1) % 10
        val = randint(-10, 10)
        B[ia] += val * B[ib]

    M = B.LLL()
    G = M.gram_schmidt()[0]

    W = Babai_closest_vector(M, G, Y)

    if (W[0] == Y[0]
        and W[1] == Y[1]
        and W[2] == Y[2]
        and W[3] == Y[3]
        and W[4] == Y[4]):
        break

x = W[5] * q / 2
k1 = W[6] * c[9] / 2
k2 = W[7] * c[9] / 2

assert pow(int(g), int(x), int(p)) == y

print("{:d}".format(int(x)))
print("{:d}".format(int(k1)))
print("{:d}".format(int(k2)))
