#!/usr/bin/env python3
import gmpy2
import random
import z3
from config import N, c
gmpy2.get_context().precision = int(2048)

DEBUG = False

base_ = Integer(int(gmpy2.sqrt(N)))

if DEBUG:
    idx = 500 # tweak
    pbase = z3.BitVec('pbase', idx)
    S = z3.Solver()
    mask = int((1 << idx) - 1)

    S.add((pbase * pbase) & mask == N & mask)
    # Ask z3 to find other candida
    S.add(pbase != int(0b1000110100001000000111000101000000101010100100100010100110111011111100111000000011101011011011101111010110101100010001000001011101110111100010110001100100100101100110011100110111101000010100000001000110101001011111111110111110101101110111001110100101001000011101011011111011111101000000010111101111011110010010000110001000001000110110011110011111000001010001100110001100100110110000000110110000111000101011011111100111011100111010011110101011111000111001100010011100010010101111101101111000101010001))
    issat = S.check()
    assert issat == z3.sat
    ans = S.model()
    pbase_ = Integer(str(ans[pbase]))
else:
    pbase_ = 0b10111001011110111111000111010111111010101011011011101011001000100000011000111111100010100100100010000101001010011101110111110100010001000011101001110011011011010011001100011001000010111101011111110111001010110100000000001000001010010001000110001011010110111100010100100000100000010111111101000010000100001101101111001110111110111001001100001100000111110101110011001110011011001001111111001001111000111010100100000011000100011000101100001010100000111000110011101100011101101010000010010000111010101111

print(f'[*] base_ = {base_}')
print(f'[*] pbase_ = {pbase_}')

def factor():
    F.<x> = PolynomialRing(Zmod(N))
    while True:
        half = random.randint(16, 1024 // 2 - 8)
        rand = random.randint(8, half - 1)
        if not DEBUG:
            rand, half = 203, 443
        assert 1024 - half >= 1024 // 2
        print(f'[*] rand: {rand}, half: {half}')
        a = 1024 - rand
        base = base_ >> a
        pbase = pbase_ & ((1 << (1024 - rand - half)) - 1)
        f = (base << a) + pbase + x * (1 << (1024 - rand - half))
        f = f.monic()
        x0 = f.small_roots(X=(2 ** half), beta=0.44, epsilon=1/32)
        for xs in x0:
            pcand = (base << a) + pbase + xs * (1 << (1024 - rand - half))
            pcand = Integer(pcand)
            if N % pcand == 0:
                print(f'[+] p = {pcand}')
                return pcand

p = factor()
q = N // p
from Crypto.Util.number import long_to_bytes as l2b
e = 65537
d = inverse_mod(e, (p - 1) * (q - 1))
flag = l2b(pow(c, d, N)).decode()
print(flag)