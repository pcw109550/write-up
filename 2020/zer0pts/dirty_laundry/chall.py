#!/usr/bin/sage
from sage.all import *
from Crypto.Util.number import getStrongPrime, bytes_to_long

from secret import flag

class PRNG256(object):
    def __init__(self, seed):
        self.mask = (1 << 256) - 1
        self.seed = seed & self.mask

    def _pick(self):
        b = ((self.seed>>0)^(self.seed>>2)^(self.seed>>5)^(self.seed>>10)^1)&1
        self.seed = ((self.seed>>1)|(b<<255)) & self.mask
        return b

    def rand(self):
        x = 0
        for i in range(256):
            x = (x << 1) | self._pick()
        return x

PRIME = getStrongPrime(1024)
prng = PRNG256(PRIME)

def paillier_enc(m, p, noise):
    p = next_prime(p + noise)
    q = getStrongPrime(512)
    n = p * q
    key = prng.rand()
    g = (1 + key * n) % n**2
    r = prng.rand()
    c = pow(g, m, n**2) * pow(r, n, n**2) % n**2
    return n, g, c

def make_shares(secret, k, shares, prime=PRIME):
    PR, x = PolynomialRing(GF(prime), name='x').objgen()
    f = PR([secret] + [ZZ.random_element(prime) for _ in range(k-1)])
    xy = []
    pubkey = []
    for x in range(1, shares+1):
        noise = prng.rand()
        n, g, y = paillier_enc(f(x) + noise, prime, noise)
        pubkey.append([n, g])
        xy.append([x, y])
    return pubkey, xy

secret = bytes_to_long(flag)
pubkey, shares = make_shares(secret, 3, 5)


print("[+] len(flag):", len(flag))
print("[+] pubkey:", pubkey)
print("[+] shares:", shares)
