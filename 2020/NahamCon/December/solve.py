#!/usr/bin/env python
from string import printable
from itertools import product
from Crypto.Cipher import DES
from Crypto.Util.strxor import strxor

with open('ciphertext', 'rb') as handle:
    ct = handle.read()

iv = '13371337'
plain = []
even = []
odd = []
key = '\xb3\xf9\x39\xa1\x93\x4f\x70\xa5'

for i in range(0, len(ct), 8) :
    block = ct[i:i + 8]
    out = strxor(block, iv)
    if all([c in printable + '\x00' for c in out]):
        even.append(out)
    else:
        out = strxor(key, out)
        odd.append(out)
    plain.append(out)

print(even)
print(odd)
print(''.join(plain))
