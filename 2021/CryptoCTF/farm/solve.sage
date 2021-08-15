#!/usr/bin/env sage
import string, base64, math
from enc import enc

ALPHABET = string.printable[:62] + '\\='

F = list(GF(64, 'x'))


def keygen(l):
	key = [F[randint(1, 63)] for _ in range(l)] 
	key = math.prod(key) # Optimization the key length :D
	return key


def maptofarm(c):
	assert c in ALPHABET
	return F[ALPHABET.index(c)]


def get_pkey():
    c = enc[0]
    t = base64.b64encode(b"CCTF")[0]
    pkey = F[ALPHABET.index(c)] / maptofarm(chr(t))
    return pkey


def decrypt(enc):
    m64, pkey = '', get_pkey()
    for e in enc:
        m64 += ALPHABET[F.index(F[ALPHABET.index(e)] / pkey)]
    m = base64.b64decode(m64)
    return m


flag = decrypt(enc).decode()
assert flag == "CCTF{EnCrYp7I0n_4nD_5u8STitUtIn9_iN_Fi3Ld!}"
print(flag)
