#!/usr/bin/env python3
import os
import random
import string
from hashlib import sha256
from itertools import combinations

import pwn

IP, PORT = "choreography.chal.pwni.ng", 1337
tn = pwn.remote(IP, PORT)


QUERIES = 500
# fmt: off
sbox = [109, 86, 136, 240, 199, 237, 30, 94, 134, 162, 49, 78, 111, 172, 214, 117, 90, 226, 171, 105, 248, 216, 48, 196, 130, 203, 179, 223, 12, 123, 228, 96, 225, 113, 168, 5, 208, 124, 146, 184, 206, 77, 72, 155, 191, 83, 142, 197, 144, 218, 255, 39, 236, 221, 251, 102, 207, 57, 15, 159, 98, 80, 145, 22, 235, 63, 125, 120, 245, 198, 10, 233, 56, 92, 99, 55, 187, 43, 25, 210, 153, 101, 44, 252, 93, 82, 182, 9, 36, 247, 129, 3, 84, 74, 128, 69, 20, 246, 141, 2, 41, 169, 59, 217, 137, 95, 189, 138, 116, 7, 180, 60, 18, 238, 73, 133, 121, 62, 87, 40, 213, 37, 33, 122, 200, 192, 118, 205, 135, 53, 58, 89, 201, 21, 193, 149, 8, 112, 81, 243, 131, 158, 188, 154, 211, 147, 164, 195, 181, 222, 178, 67, 76, 115, 150, 127, 103, 254, 1, 249, 186, 88, 177, 61, 14, 152, 106, 161, 229, 70, 160, 175, 29, 224, 66, 38, 91, 79, 185, 114, 190, 6, 110, 194, 250, 119, 0, 230, 176, 51, 104, 219, 215, 151, 75, 13, 23, 165, 11, 139, 42, 167, 52, 85, 156, 253, 163, 19, 35, 140, 107, 31, 143, 166, 32, 47, 132, 239, 234, 71, 241, 157, 170, 64, 100, 16, 97, 227, 204, 34, 4, 50, 126, 209, 174, 46, 45, 28, 232, 24, 212, 244, 220, 173, 17, 54, 231, 108, 65, 202, 27, 68, 26, 183, 148, 242]
# fmt: on
ROUNDS = 2 ** 22 + 2
pairs = []

assert len(set(sbox)) == len(sbox)
sboxinv = [-1] * len(sbox)
for i in range(len(sbox)):
    sboxinv[sbox[i]] = i


def encrypt1(k, plaintext):
    a, b, c, d = plaintext
    for i in range(ROUNDS):
        a ^= sbox[b ^ k[(2 * i) & 3]]
        c ^= sbox[d ^ k[(2 * i + 1) & 3]]
        a, b, c, d = b, c, d, a
    return bytes([a, b, c, d])


def encrypt2(k, plaintext):
    a, b, c, d = plaintext
    for i in range(ROUNDS)[::-1]:
        b, c, d, a = a, b, c, d
        c ^= sbox[d ^ k[(2 * i) & 3]]
        a ^= sbox[b ^ k[(2 * i + 1) & 3]]
    return bytes([a, b, c, d])


def decrypt1(k, ciphertext):
    c, d, a, b = ciphertext
    c, d, a, b = encrypt2(k, bytes([a, b, c, d]))
    return bytes([a, b, c, d])


def generate_data():
    seen = set()
    data = []
    for _ in range(QUERIES * 2):
        while (rand := os.urandom(2)) in seen:
            continue
        seen.add(rand)
        p = bytes([rand[0], 0, rand[1], 0])
        data.append(p)
    return data


def PoW():
    printables = string.ascii_letters + string.digits
    temp = tn.recvline(keepends=False).split()
    prefix = temp[6]
    pwn.log.info(f"PoW {prefix=}")
    result = (
        prefix
        + pwn.iters.mbruteforce(
            lambda x: sha256(prefix + x.encode()).digest()[-3:] == b"\xff\xff\xff",
            printables,
            8,
            "fixed",
        ).encode()
    )
    tn.sendline(result)
    pwn.log.success(f"PoW {result=}")


def encryption_oracle_send(pts):
    pwn.log.info(f"Encryption Oracle with {QUERIES} queries")
    assert len(pts) == QUERIES
    tn.recvuntil(b"ENCRYPT 1\ninput (hex): ")
    pts = b"".join(pts)
    tn.sendline(pts.hex().encode())
    pts_recv = bytes.fromhex(tn.recvline(keepends=False).strip(b"'").decode())
    assert pts == pts_recv


def encryption_oracle_recv(pts, cts):
    global pairs
    assert len(pts) == len(cts)
    for p, c in zip(pts, cts):
        pairs.append((p, c))


def decryption_oracle_send(cts):
    pwn.log.info(f"Decryption Oracle with {QUERIES} queries")
    assert len(cts) == QUERIES
    tn.recvuntil(b"ENCRYPT 2\ninput (hex): ")
    cts_swapped = [bytes([c, d, a, b]) for a, b, c, d in cts]
    cts_swapped = b"".join(cts_swapped)
    tn.sendline(cts_swapped.hex().encode())
    cts_swapped_recv = bytes.fromhex(tn.recvline(keepends=False).strip(b"'").decode())
    assert cts_swapped == cts_swapped_recv


def decryption_oracle_recv(cts, pts_swapped):
    global pairs
    assert len(cts) == len(pts_swapped)
    pts = [bytes([c, d, a, b]) for a, b, c, d in pts_swapped]
    for p, c in zip(pts, cts):
        pairs.append((p, c))


def oracle_recv(data):
    tn.recvuntil(b"result: ")
    recv = bytes.fromhex(tn.recvline(keepends=False).decode())
    data_recv = [recv[i : i + 4] for i in range(0, len(recv), 4)]
    encryption_oracle_recv(data[:QUERIES], data_recv[:QUERIES])
    decryption_oracle_recv(data[QUERIES:], data_recv[QUERIES:])


def f_extract_key(X, Y, delta):
    k0 = sboxinv[X[0] ^ Y[0] ^ delta] ^ X[1]
    k1 = sboxinv[X[2] ^ Y[2] ^ delta] ^ X[3]
    return k0, k1


def recover_key():
    pwn.log.info(f"Searching Slides")
    global pairs
    for (A, B), (C, D) in combinations(pairs, r=2):
        if A[1] != D[1] or A[3] != D[3]:
            continue
        if B[1] != C[1] or B[3] != C[3]:
            continue
        for delta in range(256):
            k0t, k1t = f_extract_key(A, D, delta)
            k0l, k1l = f_extract_key(B, C, delta)

            if k0t != k0l or k1t != k1l:
                continue
            k0, k1 = k0t, k1t
            pwn.log.success(f"{k0=}")
            pwn.log.success(f"{k1=}")
            p, c = pairs[0]

            k2 = ord(
                pwn.iters.mbruteforce(
                    lambda _k2: encrypt1(bytes([k0, k1, ord(_k2), delta ^ ord(_k2)]), p)
                    == c,
                    "".join(chr(c) for c in range(256)),
                    1,
                    "fixed",
                )
            )
            k3 = k2 ^ delta
            pwn.log.success(f"{k2=}")
            pwn.log.success(f"{k3=}")
            key = bytes([k0, k1, k2, k3])
            return key
    assert False


def get_flag(key):
    tn.recvuntil(b"key guess (hex): ")
    tn.sendline(key.hex().encode())
    tn.recvline(b"Congrats!")
    flag = tn.recvline(keepends=False).decode()
    return flag


def main():
    data = generate_data()
    PoW()
    encryption_oracle_send(data[:QUERIES])
    decryption_oracle_send(data[QUERIES:])
    oracle_recv(data)
    key = recover_key()
    flag = get_flag(key)
    assert flag == "PCTF{square_dancin'_the_night_away~}"
    pwn.log.success(f"{flag=}")


if __name__ == "__main__":
    main()


"""
[+] Opening connection to choreography.chal.pwni.ng on port 1337: Done
[*] PoW prefix=b'rCfQgmHSd4'
[+] MBruteforcing: Found key: "aaaaGrT5"
[+] PoW result=b'rCfQgmHSd4aaaaGrT5'
[*] Encryption Oracle with 500 queries
[*] Decryption Oracle with 500 queries
[*] Searching Slides
[+] k0=218
[+] k1=208
[+] k2=52
[+] k3=206
[+] flag="PCTF{square_dancin'_the_night_away~}"
[*] Closed connection to choreography.chal.pwni.ng port 1337
"""
