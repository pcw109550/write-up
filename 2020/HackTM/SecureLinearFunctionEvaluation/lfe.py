#!/usr/bin/env python3
from Crypto.Util.number import *
from hashlib import sha256
import parse
from secret import flag

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
size = 128

def cal_res(a, b, cs, otinp):
	assert len(a) == size
	assert len(b) == size
	assert len(cs) == size
	assert len(otinp) == size
	response = []
	for i in range(size):
		g, y0, y1 = otinp[i]
		assert (y0 * y1) % p == cs[i]
		r0 = getRandomRange(0, p)
		r1 = getRandomRange(0, p)
		m0 = b[i]
		m1 = (a[i] + b[i]) % 2
		c0 = (pow(g, r0, p), int(sha256(long_to_bytes(pow(y0, r0, p))).hexdigest(), 16) ^ m0)
		c1 = (pow(g, r1, p), int(sha256(long_to_bytes(pow(y1, r1, p))).hexdigest(), 16) ^ m1)
		response.append((c0, c1))
	return response


def main():
	a = [getRandomRange(0, 2) for i in range(size)]
	b = [getRandomRange(0, 2) for i in range(size)]
	print("Performing Bellare-Micali OT")
	cs = [getRandomRange(0, p) for i in range(size)]
	print(cs)
	inp = input().strip().split(" ")
	otinp = []
	for r in inp:
		print(r)
		g, y0, y1 = parse.parse("({0},{1},{2})", r)
		g = int(g)
		y0 = int(y0)
		y1 = int(y1)
		otinp.append((g, y0, y1))
	print("Server response:")
	print(cal_res(a, b, cs, otinp))
	a_ = input("Enter a:")
	b_ = input("Enter b:")
	if str(a) == a_ and str(b) == b_:
		print(flag)
		exit(0)
	print("No flag for you!")
	exit(0)



if __name__ == '__main__':
	main()