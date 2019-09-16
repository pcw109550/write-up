from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.strxor import strxor
from itertools import product
from pwn import *
import random

context.log_level = "DEBUG"


def random_bytes():
    return l2b(random.getrandbits(32)).rjust(16, "\x00")


def findseed(seed):
    while True:
        seed = random.randint(1, 9999999999999999)
        random.seed(seed)
        test = []
        for _ in range(300):
            test.append(random.getrandbits(32))

        if len(set(test)) != len(test):
            for (i, j) in product(range(300), repeat=2):
                if i >= j:
                    continue
                if test[i] == test[j]:
                    break
            if i % 3 == j % 3:
                continue
            else:
                return seed, test, i, j


def getflag(seed):
    if not __debug__:
        p = remote("crypto.chal.csaw.io", 1002)
    else:
        p = process(["python", "local.py"])
    random.seed(seed)
    test = []
    for _ in range(300):
        test.append(random.getrandbits(32))
    for (i, j) in product(range(300), repeat=2):
        if i >= j:
            continue
        if test[i] == test[j]:
            break
    assert i % 3 != j % 3

    seed = str(seed).rjust(16, "0")
    assert len(seed) == 16
    random.seed(int(seed))

    p.recvuntil("Send me a random seed\n")
    p.sendline(seed)
    p.recvuntil("Encrypted flag:\n")

    # 16 < len(flag) <= 24
    data = p.recvuntil("Okay bye\n")[:-9]
    assert len(data) == (48 + 1) * 100
    enc = []
    for k in range(100):
        enc.append(data[49 * k: 49 * (k + 1)][:-1])

    header = "Encrypted Flag: "
    assert len(header) == 16

    enc_chunk = strxor(header, enc[j // 3][16 * (j % 3): 16 * (j % 3 + 1)])

    pt = strxor(enc_chunk, enc[i // 3][16 * (i % 3): 16 * (i % 3 + 1)])

    p.close()
    return pt

flag = getflag(2194417288928241)
flag += getflag(5689809437004447)

assert flag == "flag{U_c@n_coUn7_0n_m3_l1kE_123}"
log.success("flag = {:s}".format(flag))


