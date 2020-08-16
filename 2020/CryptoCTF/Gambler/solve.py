#!/usr/bin/env python3
from math import gcd
import pwn
import hashlib
import random
import string


def PoW():
    a = p.recvline(keepends=False).split()
    hashtype = getattr(hashlib, a[8].split(b'(')[0].decode())
    target = bytes.fromhex(a[-5].decode())
    hashlen = int(a[-1])
    print(hashtype, target, hashlen)
    chset = string.ascii_letters + string.digits
    while True:
        randbytes = ''.join(random.choices(chset, k=hashlen)).encode()
        result = hashtype(randbytes).digest()[-len(target):]
        if target == result:
            break
    p.sendline(randbytes)


def recvmenu():
    p.recvuntil('[Q]uit\n')


def encrypt(m):
    # assert m < p and isPrime(p)
    # return (m ** 3 + a * m + b) % p
    recvmenu()
    p.sendline('T')
    p.recvuntil('| please enter your message to encrypt:\n')
    p.sendline(str(m))
    return int(p.recvline().split()[-1])


def getflag():
    recvmenu()
    p.sendline('C')
    ct = int(p.recvline().split()[-1])
    return ct


def enclogic():
    recvmenu()
    p.sendline('E')


IP, PORT = "05.cr.yp.toc.tf", 33371
pwn.context.log_level = 'DEBUG'

p = pwn.remote(IP, PORT)

PoW()
enclogic()

b = encrypt(0)
a = encrypt(1) - 1 - b

bignum = 1 << 256
p1 = bignum ** 3 + a * bignum + b - encrypt(bignum)
bignum <<= 1
p2 = bignum ** 3 + a * bignum + b - encrypt(bignum)
bignum += 1
p3 = bignum ** 3 + a * bignum + b - encrypt(bignum)
prime = gcd(gcd(p1, p2), p3)
ct = getflag()

print(f'a = {a}')
print(f'b = {b}')
print(f'p = {prime}')
print(f'ct = {ct}')

p.interactive()
