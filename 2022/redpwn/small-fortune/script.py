from Crypto.Util.number import *
from gmpy2 import legendre

# flag = bytes_to_long(open("flag.txt", "rb").read())
flag = bytes_to_long(b"h")

p, q = getPrime(256), getPrime(256)
n = p * q

x = getRandomRange(0, n)
while legendre(x, p) != -1 or legendre(x, q) != -1:
    x = getRandomRange(0, n)

def gm_encrypt(msg, n, x):
    y = getRandomRange(0, n)
    print(y)
    enc = []
    while msg:
        bit = msg & 1
        msg >>= 1
        enc.append((pow(y, 2) * pow(x, bit)) % n)
        c = getRandomRange(1, 2**48)
        y += c
        print(bit, c)
    return enc

print("n =", n)
print("x =", x)
print("enc =", gm_encrypt(flag, n, x))