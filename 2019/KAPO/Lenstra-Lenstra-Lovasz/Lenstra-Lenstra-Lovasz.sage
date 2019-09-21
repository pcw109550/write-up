#!/usr/bin/env sage
from Crypto.Util.number import bytes_to_long as b2l

def generate():
    p = random_prime(2 ** 1024)
    q = random_prime(2 ** 1024)
    e = random_prime(200, False, 150)
    d = inverse_mod(e, (p-1)*(q-1))
    n = p * q
    return [n, e, p, q, d]

if __name__ == '__main__':
    n, e, p, q, d = generate()
    key = [n, e, p, q, d]

    flag = b2l(open("flag.txt").read())
    ct = pow(flag, e, n)

    secret = d % (p-1)
    bits = secret.nbits()
    bias = bits // 10

    secret = secret >> (bits//2 - bias)

    print (n, e, secret)
    print (ct)
