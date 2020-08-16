#!/usr/bin/python

from Crypto.Util.number import *
from flag import flag

def keygen(nbit):
	while True:
		p, q, r = [getPrime(nbit) for _ in range(3)]
		if isPrime(p + q + r):
			pubkey = (p * q * r, p + q + r)
			privkey = (p, q, r)
			return pubkey, privkey

def encrypt(msg, pubkey):
	enc = pow(bytes_to_long(msg.encode('utf-8')), 0x10001, pubkey[0] * pubkey[1])
	return enc

nbit = 512
pubkey, _ = keygen(nbit)
print('pubkey =', pubkey)

enc = encrypt(flag, pubkey)
print('enc =', enc)
