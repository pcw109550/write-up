#!/usr/bin/env python3
from hashlib import sha256

import pwn
from Crypto.Util.number import long_to_bytes

pwn.context.log_level = "DEBUG"

IP, PORT = "ctf.b01lers.com", 9003
DEBUG = False
if DEBUG:
    tn = pwn.process("./Hardcore.py")
else:
    tn = pwn.remote(IP, PORT)


def solve1():
    tn.sendlineafter(b"Select a difficulty (1/2):", b"1")
    h = bytes.fromhex(
        tn.recvuntil(b"answer.\n\n").split()[10].lstrip(b"<").rstrip(b">.").decode()
    )
    pwn.log.info(f"{h = }")

    bits = []
    for i in range(256):
        state = [0] * 256
        state[i] = 1
        payload = "".join([str(c) for c in state]).encode()
        tn.sendline(payload)
        bit = int(tn.recvline(keepends=False).decode())
        bits.append(bit)
    flag = long_to_bytes(sum(bits[i] << (255 - i) for i in range(256)))
    assert flag == b"bctf{do_you_like_hardcore_chals}"
    pwn.log.success(f"{flag = }")


def solve2():
    # using the fact that end of the flag is b"}" or 0b01111101
    tn.sendlineafter(b"Select a difficulty (1/2):", b"2")
    h = bytes.fromhex(
        tn.recvuntil(b"answer.\n\n").split()[10].lstrip(b"<").rstrip(b">.").decode()
    )
    pwn.log.info(f"{h = }")

    bits = []
    for i in range(256):
        state = [0] * 256
        state[i] = 1
        temp = []

        for j in [0, 3, 5]:
            state[j] = 1
            payload = "".join([str(c) for c in state]).encode()
            tn.sendline(payload)

            # print(tn.recvline(keepends=False))

            temp_bit = int(tn.recvline(keepends=False).decode())
            temp.append(temp_bit)
        bits.append(1 if sum(temp) >= 2 else 0)
    print(bits)
    flag = long_to_bytes(sum(bits[i] << (255 - i) for i in range(256)))
    # b'bstf{golfreigh-levin-theorem.:D}'
    flag = b"bctf{goldreich-levin-theorem.:D}"
    pwn.log.success(f"{flag = }")


solve1()
solve2()

tn.close()
