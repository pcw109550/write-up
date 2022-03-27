#!/usr/bin/env sage
from sage.all import *

# secp160r1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
n = 0x0100000000000000000001F4C8F927AED3CA752257
EC = EllipticCurve(Zmod(p), [a, b])
G = EC(
    0x4A96B5688EF573284664698968C38BB913CBFC82,
    0x23A628553168947D59DCC912042351377AC5FB32,
)

with open("Babycrypto_revisited_b1f108dea290b83253b80443260b12c3cadc0ed7.txt") as f:
    data = [[int(x, 16) for x in line.strip().split()] for line in f.readlines()]

samples = []
for ds in data:
    [r, s, k_, h] = ds
    c = EC.lift_x(Integer(r)) - k_ * G
    r_new = c[0].lift()
    s_new = s * pow(r, -1, n) * r_new % n
    h_new = (h - s * k_) * pow(r, -1, n) * r_new % n
    samples.append((r_new, s_new, h_new))


num_samples = len(data)
t = lambda r, s: pow(s, -1, n) * r
u = lambda s, h: pow(s, -1, n) * h
B = 2 ** 64

M = Matrix(QQ, num_samples + 2)
for row in range(num_samples):
    M[row, row] = n
for col in range(num_samples):
    M[num_samples, col] = t(samples[col][0], samples[col][1])
    M[num_samples + 1, col] = u(samples[col][1], samples[col][2])
M[num_samples, num_samples] = B / n
M[num_samples + 1, num_samples + 1] = B
M = M.LLL()
for row in M:
    if row[-1] == B:
        d = int(row[-2] * n // B) % n
        break

[r, s, k_, h] = data[0]
k = pow(s, -1, n) * (h + r * d) % n
assert k >> 64 == k_ >> 64

flag = f"LINECTF{{{hex(d)}}}"
assert flag == "LINECTF{0xd77d10fec685cbe16f64cba090db24d23b92f824}"
print(flag)
