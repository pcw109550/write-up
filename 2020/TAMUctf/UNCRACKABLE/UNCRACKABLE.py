#!/usr/bin/env python2
from Crypto.Util.strxor import strxor
c = 'e3f8e5110e29e6fde31a0861f0a4dd13530db5ffdd17113be6c2dd1c022f'
c = c.decode('hex')
a = 'gigem{'
key = strxor(a, c[:6])
flag = ''
for i in range(len(c) // 6):
    flag += strxor(key, c[6 * i: 6 * (i + 1)])
print(flag)
