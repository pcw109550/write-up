from Crypto.Util.number import bytes_to_long as b2l
from gmpy2 import *
from random import *

M_weak = 4014476939333036189094441199026045136645885247730
M_strong = 962947420735983927056946215901134429196419130606213075415963491270

def get_weak_prime():
    while True:
        k = randint(2**18, 2**19-1) # 19-bit k
        a = randint(2**20, 2**62-1) # random a
        p = k * M_weak + pow(2**16+1, a, M_weak)

        if is_prime(p):
            return p

def get_strong_prime():
    while True:
        k = randint(2**36, 2**37-1) # 37-bit k
        a = randint(2**20, 2**62-1) # random a
        p = k * M_strong + pow(2**16+1, a, M_strong)

        if is_prime(p):
            return p

def generate_weak():
    p = get_weak_prime()
    q = get_weak_prime()
    n = p * q
    return n

def generate_strong():
    p = get_strong_prime()
    q = get_strong_prime()
    n = p * q
    return n

if __name__ == '__main__':
    wn = generate_weak()
    sn = generate_strong()

    flag = b2l(open("flag.txt").read())

    wct = pow(flag, 65537, wn)
    sct = pow(flag, 65537, sn)

    print (wn, wct)
    print (sn, sct)
