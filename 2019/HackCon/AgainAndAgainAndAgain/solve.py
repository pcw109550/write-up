from config import c
from Crypto.Util.number import long_to_bytes as l2b
from modular_sqrt import modular_sqrt
from string import printable

p = 5411451825594838998340467286736301586172550389366579819551237
q = 5190863621109915362542582192103708448607732254433829935869841

n = p * q


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def check(m):
    return all(ch in printable for ch in l2b(m))


def dec(t):
    mp = modular_sqrt(t, p)
    mq = modular_sqrt(t, q)
    _, yp, yq = egcd(p, q)
    r = (yp * p * mq + yq * q * mp) % n
    s = (yp * p * mq - yq * q * mp) % n
    ms = [r, s, n - r, n - s]
    for m in ms:
        if check(m):
            flag = l2b(m)
            assert flag == "d4rk{r3p3t1t1v3_r4b1n_1s_th4_w0rs7_3vaaaaaar!}code"
            print(flag)
            exit()
    for m in ms:
        dec(m)

dec(c)
