from Crypto.Util.number import long_to_bytes as l2b
from config import n, secret, ct
[n, secret, ct] = list(map(Integer, [n, secret, ct]))

e = 151


def factorize(e, dp):
    for i in range(2, e):
        p = (e * dp - 1 + i) // i
        if n % p == 0:
            return p
    return -1


def recover(secret):
    F.<x> = PolynomialRing(Zmod(n))
    einv = inverse_mod(e, n)
    for bits in reversed(range(1019, 1025)):
        bits = 1023
        unknownbits = (bits // 2 - bits // 10)
        for k in range(1, e):
            k = 130
            f = (secret << unknownbits) + x + (k - 1) * einv
            x0 = f.small_roots(X=2 ** (unknownbits + 1), beta=0.44, epsilon=1/32)
            if len(x0) != 0:
                dp = x0[0] + (secret << unknownbits)
                p_cand = factorize(e, Integer(dp))
                if p_cand < 0:
                    continue
                else:
                    return p_cand, dp


if __name__ == "__main__":
    p, dp = recover(secret)
    q = n // p
    assert p * q == n

    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)

    flag = l2b(pow(ct, d, n)).strip()

    assert flag == "POKA{You_4r3_Crypt0_N00000B_XDD}"
    print(flag)
