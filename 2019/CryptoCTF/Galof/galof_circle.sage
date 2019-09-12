#!/usr/bin/sage

from sage.all import *
import random, string
load("secret.sage")

def genrandstr(N):
	return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))

def encrypt(msg, base, key):
	key_1, key_2 = key
	m = bin(int(msg.encode('hex'), 16))[2:]
	assert len(m) <= 256
	f, e = 0, 0
	for b in m[::-1]:
		f += int(b) * x^e
		e += 1
	try:
		h = (key_1 * inverse_mod(f, base) + key_2) % base
	except:
		return 'can\'t encrypt such message, sorry!'
	EXP = h.exponents()
	enc = ''
	for i in range(256):
		if i in EXP:
			enc += '1'
		else:
			enc += '0'
	enc = hex(int(enc[::-1], 2)).lstrip('0x').rstrip('L').zfill(64)
	return enc

F.<x> = GF(2)[]
base = x^255 + x^199 + 1

for _ in range(100):
	r = genrandstr(30)
	print r, encrypt(r, base, key)

print 'flag'.center(30), encrypt(flag, base, key)
