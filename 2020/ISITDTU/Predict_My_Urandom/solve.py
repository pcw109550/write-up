#!/usr/bin/env python3
from Crypto.Util.strxor import strxor

with open('cipher', 'rb') as f:
    enc = f.read()

header = b'ISITDTU'
SIZE = 16
enc_chunk = [enc[16 * i:16 * (i + 1)] for i in range(len(enc) // SIZE)]

base = 7
key = strxor(enc_chunk[0][base:base + len(header)], header)
key += strxor(b'le', enc_chunk[26][base + len(key): base + len(key) + len(b'le')])
key = b'\xdb~\x87\xb6\x7f\x00\xa40\xd6'
base = 7 - 3
key = strxor(b'omp', enc_chunk[2][base: base + len(b'omp')]) + key
key =b'\x1c%d\xdb~\x87\xb6\x7f\x00\xa40\xd6'
base = 0
key = strxor(b'_lam', enc_chunk[6][base: base + len(b'_lam')]) + key

pt = b''
for i, chunk in enumerate(enc_chunk):
    pt += strxor(key, chunk[base:base + len(key)])

flag = pt[pt.find(b'ISITDTU{'):].rstrip(b'\x10').strip().decode()
assert flag == 'ISITDTU{57r4n63_d1c7_l4mbd4_c0mpr3h3n510n}'

print(flag)
