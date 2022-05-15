from math import gcd
from random import randint
from typing import Tuple

import pwn
from Crypto.Util.number import long_to_bytes
from gmpy2 import is_prime, isqrt

# pwn.context.log_level = "DEBUG"

DEBUG = False
if DEBUG:
    tn = pwn.process(["python3", "server.py"])
else:
    IP, PORT = "challs.m0lecon.it", 1753
    tn = pwn.remote(IP, PORT)


def recvint() -> int:
    return int(tn.recvline(keepends=False).split()[-1].decode())


def solve_quadratic(a, b, c) -> Tuple[int, int]:
    print(a, b, c)
    assert (D := b**2 - 4 * a * c) > 0
    sqrtD = isqrt(D)
    x1 = (-b - sqrtD) // (2 * a)
    x2 = (-b + sqrtD) // (2 * a)
    return x1, x2


tn.recvline()
n, ct, e = [recvint() for _ in range(3)]

M_max = -1
for i in range(10):
    a = randint(1 << 32, 1 << 64)
    tn.sendlineafter(b"Choose a value: ", str(a).encode())
    M = recvint()
    M_max = max(M_max, M)
assert M_max % 2 == 0

a_add_b = (n - 1 - M_max * 2) // 2
a_mul_b = M_max // 2

a, b, c = 1, -a_add_b, a_mul_b
A, B = solve_quadratic(a, b, c)
p, q = 2 * A + 1, 2 * B + 1
assert is_prime(p) and is_prime(q)

d = pow(e, -1, (p - 1) * (q - 1))
flag = long_to_bytes(pow(ct, d, n))
assert flag == b"ptm{y0u_found_another_w4y_t0_factorize}"
pwn.log.info(f"{flag = }")

tn.close()
