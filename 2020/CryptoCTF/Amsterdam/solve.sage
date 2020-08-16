#!/usr/bin/env sage
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes as l2b
from config import enc


def encrypt(msg, n, k):
    msg = bytes_to_long(msg.encode('utf-8'))
    if msg >= binomial(n, k):
        return -1
    m = ['1'] + ['0' for i in range(n - 1)]
    for i in range(1, n + 1):
        if msg >= binomial(n - i, k):
            m[i - 1]= '1'
            msg -= binomial(n - i, k)
            k -= 1
    m = int(''.join(m), 2)
    c = encode(m)
    return c


def encode(m):
    i = 0
    c = 0
    while (m > 0):
        if m % 4 == 1:
            c += 3 ** i
            m -= 1
        elif m % 4 == 3:
            c += 2 * 3 ** i
            m += 1
        else:
            pass
        m //= 2
        i += 1
    return c


def decode(c):
    c = c.str(base=3)
    m = 0
    for t in c:
        m *= 2
        if t == '1':
            m += 1
        elif t == '2':
            m -= 1
    return m


def encrypt_(msg, n, k):
    if msg >= binomial(n, k):
        return -1
    m = ['1'] + ['0' for i in range(n - 1)]
    for i in range(1, n + 1):
        if msg >= binomial(n - i, k):
            m[i - 1]= '1'
            msg -= binomial(n - i, k)
            print(n - i, k)
            k -= 1
    return m


def decrypt_(m, n, k):
    msg = 0
    for i in range(2, n + 1):
        if m[i - 1] == '1':
            msg += binomial(n - i, k)
            k -= 1
    return msg


enc = Integer(enc)
m = decode(enc)
n = m.nbits()
m = list('{:b}'.format(m))


for k in reversed(range(n + 1)):
    cur_k = k
    msg = 0
    for i in range(2, n + 1):
        if m[i - 1] == '1':
            msg += binomial(n - i, cur_k)
            cur_k -= 1
    msg = l2b(msg)
    if b'CCTF' in msg:
        flag = msg.decode()
        print(flag)
        break


