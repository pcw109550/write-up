from Crypto.Util.number import long_to_bytes as l2b

from output import enc, n, x

# 01111101
xinv = pow(x, -1, n)
F.<c> = PolynomialRing(Zmod(n))

flag = []
prev = True
for i in range(len(enc) - 1):
    A = enc[i]
    if prev:
        A = A * xinv % n
    B = enc[i + 1]

    f = (B - A - c**2) ** 2 - 4 * c**2 * A
    f = f.monic()

    cs = f.small_roots(X=2**48)
    if len(cs) == 0:
        prev = True
        flag.append(1)
    else:
        prev = False
        flag.append(0)

flag.append(0)
flag = [1] + flag
flag = flag[::-1]
m = 0
print(l2b(int("".join(str(c) for c in flag), 2)))

# hope{r4nd0m_sh0uld_b3_truly_r4nd0m_3v3ry_t1m3_sh0uld_1t_n0t?}
