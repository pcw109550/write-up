#!/usr/bin/env sage
from config import enc, pubkey
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import getPrime

nbit = 512
e = 0x10001
a = pubkey[0] # p * q * r
b = pubkey[1] # p + q + r

phin = b - 1
d = inverse_mod(e, phin)
flag = l2b(pow(enc, d, b))
print(flag)
