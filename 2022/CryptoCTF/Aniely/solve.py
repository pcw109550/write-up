#!/usr/bin/env python3

#!/usr/bin/env python3

from os import *
from struct import *

# from secret import passphrase, flag


def aniely_stream(passphrase):
    def mixer(u, v):
        return ((u << v) & 0xFFFFFFFF) | u >> (32 - v)

    def forge(w, a, b, c, d):
        for i in range(2):
            w[a] = (w[a] + w[b]) & 0xFFFFFFFF
            w[d] = mixer(w[a] ^ w[d], 16 // (i + 1))
            w[c] = (w[c] + w[d]) & 0xFFFFFFFF
            w[b] = mixer(w[b] ^ w[c], (12 + 2 * i) // (i + 1))

    bring = [0] * 16
    bring[:4] = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    bring[4:12] = unpack("<8L", passphrase)
    bring[12] = bring[13] = 0x0
    bring[14:] = [0] * 2

    while True:
        w = list(bring)
        for _ in range(10):
            forge(w, 0x0, 0x4, 0x8, 0xC)
            forge(w, 0x1, 0x5, 0x9, 0xD)
            forge(w, 0x2, 0x6, 0xA, 0xE)
            forge(w, 0x3, 0x7, 0xB, 0xF)
            forge(w, 0x0, 0x5, 0xA, 0xF)
            forge(w, 0x1, 0x6, 0xB, 0xC)
            forge(w, 0x2, 0x7, 0x8, 0xD)
            forge(w, 0x3, 0x4, 0x9, 0xE)
        for c in pack("<16L", *((w[_] + bring[_]) & 0xFFFFFFFF for _ in range(16))):
            yield c
        bring[12] = (bring[12] + 1) & 0xFFFFFFFF
        if bring[12] == 0:
            bring[13] = (bring[13] + 1) & 0xFFFFFFFF


def aniely_encrypt(msg, passphrase):
    if len(passphrase) < 32:
        passphrase = (passphrase * (32 // len(passphrase) + 1))[:32]
    rand = urandom(2) * 16
    return bytes(a ^ b ^ c for a, b, c in zip(msg, aniely_stream(passphrase), rand))


key = bytes.fromhex("4dcceb8802ae3c45fe80ccb364c8de19f2d39aa8ebbfb0621623e67aba8ed5bc")
enc = bytes.fromhex("e67a67efee3a80b66af0c33260f96b38e4142cd5d9426f6f156839f2e2a8efe8")

for i in range(1 << 16):
    rand = i.to_bytes(2, byteorder="big") * 16
    flag = bytes(
        a ^ b ^ c ^ d for a, b, c, d in zip(rand, aniely_stream(key), enc, key)
    )
    if b"CCTF" in flag:
        print(flag)
        break

# CCTF{7rY_t0_D3cRyPT_z3_ChaCha20}
