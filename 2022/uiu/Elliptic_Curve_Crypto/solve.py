from hashlib import md5
from random import randrange, seed

from Crypto.Cipher import AES

# 256-bit security!
p = 62471552838526783778491264313097878073079117790686615043492079411583156507853


class Fp:
    def __init__(self, x):
        self.int = x % p

    def __str__(self):
        return str(self.int)

    __repr__ = __str__

    def __int__(self):
        return self.int

    def __eq__(a, b):
        return a.int == b.int

    def __ne__(a, b):
        return a.int != b.int

    def __add__(a, b):
        return Fp(a.int + b.int)

    def __sub__(a, b):
        return Fp(a.int - b.int)

    def __mul__(a, b):
        return Fp(a.int * b.int)

    def __truediv__(a, b):
        return a * Fp(pow(b.int, -1, p))


class ClockPoint:
    def __init__(self, x, y):
        assert int(x * x + y * y) == 1
        self.x = x
        self.y = y

    def __str__(self):
        return f"({self.x},{self.y})"

    def __eq__(self, other):
        return str(self) == str(other)

    __repr__ = __str__

    def get_hash(self):
        return md5(str(self).encode()).digest()

    def __add__(self, other):
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        return ClockPoint(x1 * y2 + y1 * x2, y1 * y2 - x1 * x2)


def scalar_mult(x: ClockPoint, n: int) -> ClockPoint:
    y = ClockPoint(Fp(0), Fp(1))
    if n == 0:
        return y
    if n == 1:
        return x
    while n > 1:
        if n % 2 == 0:
            x = x + x
            n = n // 2
        else:
            y = x + y
            x = x + x
            n = (n - 1) // 2
    return x + y


alice_public = ClockPoint(
    Fp(929134947869102207395031929764558470992898835457519444223855594752208888786),
    Fp(6062966687214232450679564356947266828438789510002221469043877962705671155351),
)
bob_secret = 470119051645934413907549310934910001519367949961450982116896622761840699674
shared_secret = scalar_mult(alice_public, bob_secret)

key = shared_secret.get_hash()

enc_flag = b" \xe9\x1aY.+E\xac\x1b\xc41\x1c\xf7\xba}\x80\x11\xa8;%]\x93\x88\x1fu\x87\x91\x88\x87\x88\x9b\x19"
print("Decrypted flag: ", AES.new(key, AES.MODE_ECB).decrypt(enc_flag))
# uiuctf{Circle5_ar3_n0t_ell1ptic}
