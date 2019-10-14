from Crypto.Util.number import long_to_bytes
from config import e, n as d, x, y, c as ct
import gmpy2

kn = e * d - 1
count = 0


def solve(a, b, c):
    D = b ** 2 - 4 * a * c
    assert gmpy2.is_square(D)
    x1 = (-b + gmpy2.isqrt(D)) // (2 * a)
    x2 = (-b - gmpy2.isqrt(D)) // (2 * a)
    return x1, x2


for k in range(3, e):
    if kn % k == 0:
        count += 1
        phi_n = kn // k
        # coefficients of quadratic eq
        a = x - 1
        b = x * y - 1 + (x - 1) * (y - 1) - phi_n
        c = (y - 1) * (x * y - 1)
        try:
            k1, k2 = solve(a, b, c)
            if (x * y - 1) % k1 == 0:
                k2 = (x * y - 1) // k1
            elif (x * y - 1) % k2 == 0:
                k1, k2 = k2, (x * y - 1) // k2
            else:
                assert False
            p, q = x + k2, y + k1
            N = p * q

            flag = long_to_bytes(pow(ct, d, N)).strip()
            break
        except AssertionError:
            pass

assert flag == "hitcon{1t_is_50_easy_t0_find_th3_modulus_back@@!!@!@!@@!}"
print(flag)
