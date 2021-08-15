#!/usr/bin/env sage
from Crypto.Util.number import *
from pwn import *


def gen():
    # primes = [getPrime(160) for _ in range(3)]
    primes = [986312121960150865241667828303677678571516492581, 869395606381715032783278208551057547499646226421, 1035226834817209162939468606061547002124205666651]

    phis = []
    for i in range(3):
        p, q = primes[i], primes[(i + 1) % 3]
        phi = (p - 1) * (q - 1)
        phis.append(phi)
    ee = (primes[0] - 1) * (primes[1] - 1) * (primes[2] - 1) + 1

    ee = 887702275058610465807044386438264338340298939800321822134189551408802776521402904683250217413528976405490177924517665112566817296042398233940001
    assert ee == (primes[0] - 1) * (primes[1] - 1) * (primes[2] - 1) + 1

    # factor with factordb
    ee = 271 * 397 * 25667 * 104779 * 16242781 * 21364331 * 386779723439 * 3130860874865196703 * 4971030815477506315219 * 2398854892368737798458520221 * 612252528352035224575533827434887347
    e = 271 * 397 * 25667 * 104779 * 16242781 * 386779723439 * 3130860874865196703 * 4971030815477506315219
    assert ee % e == 0
    d = ee // e
    assert 1 < e < min(phis) and 1 < d < min(phis)

    return primes, e, d


if __name__ == "__main__":
    context.log_level = "DEBUG"
    p = process("./Triplet.py")

    primes, e, d = gen()

    p.sendline("S")
    p.sendline(f"{primes[0]}, {primes[1]}")
    p.sendline(f"{primes[1]}, {primes[2]}")
    p.sendline(f"{primes[2]}, {primes[0]}")
    p.sendline(f"{e}, {d}")

    p.recvuntil("You got the flag: ")
    flag = p.recvline(keepends=False).decode()
    
    assert flag == "CCTF{7HrE3_b4Bie5_c4rRi3d_dUr1nG_0Ne_pr39naNcY_Ar3_triplets}"
    log.success(flag)
    
    p.close()
