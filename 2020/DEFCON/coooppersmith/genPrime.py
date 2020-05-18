from Crypto.Util.number import isPrime
from random import randrange
from math import gcd


def genPrime(seed):
    assert len(seed) <= 120
    v = int(seed, 16)
    l = len(seed)
    shift_val = 4 * (128 - l)
    v8 = v << shift_val
    v7 = 2 ** (shift_val / 2)
    v2 = 0
    for _ in range(100):
        r = randrange(v7)
        prime = r + v8
        while prime >> shift_val == v:
            if isPrime(prime):
                v2 = 1
                break
            prime += 1
        if v2:
            break
    return prime


ipt = 'ff' * 60
prime = genPrime(ipt)
print(prime)
print(hex(prime))
