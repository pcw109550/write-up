#!/usr/bin/env sage
import os
from ast import literal_eval
from random import randint

os.environ["PWNLIB_NOTERM"] = "1"

import pwn
from Crypto.Util.number import inverse, long_to_bytes
from cysignals.alarm import AlarmInterrupt, alarm, cancel_alarm

pwn.context.log_level = "INFO"
IP, PORT = "65.21.255.31", 10101
nbit = 256

tn = pwn.remote(IP, PORT)
min_max_factor_bit_len = 1 << 32
while True:
    tn.recvuntil(
        b"| Send the `y' element of two points in your desired elliptic curve:  \n"
    )
    y1 = randint(0, 1 << (nbit - 1))
    y2 = randint(0, 1 << (nbit - 1))
    tn.sendline(f"{y1}, {y2}".encode())
    tn.recvuntil(b"| q = ")
    q = int(tn.recvline().decode().split()[-1])
    A = (y1**2 - y2**2 - 1337**3 + 31337**3) * inverse(-30000, q) % q
    B = (y1**2 - 1337**3 - A * 1337) % q
    E = EllipticCurve(GF(q), [A, B])
    tn.recvuntil(b"| G = ")
    G = E(literal_eval(tn.recvline().decode()))
    tn.recvuntil(b"| m * G = ")
    Q = E(literal_eval(tn.recvline().decode()))
    pwn.log.info(f"{E = }")
    pwn.log.info(f"{G = }")
    pwn.log.info(f"{Q = }")

    E_order = E.order()
    pwn.log.info(f"{E_order = }")
    try:
        alarm(15)
        factors = list(factor(E_order))
        pwn.log.info(f"{factors = }")
        max_factor = factors[-1][0]
        pwn.log.info(f"{max_factor = }")

    except AlarmInterrupt:
        pwn.log.info("Stop factoring because it took too long")
        continue
    else:
        cancel_alarm()
        max_factor_bit_len = max_factor.nbits()
        min_max_factor_bit_len = min(min_max_factor_bit_len, max_factor_bit_len)

    if max_factor_bit_len <= 52:
        pwn.log.info("Pohlig Hellman goes brrr")
        m = int(discrete_log(Q, G, operation="+"))
        flag = long_to_bytes(m)
        print(flag)
        # ASIS{(e$l6LH_JfsJ:~<}1v&}
        exit()
    else:
        pwn.log.info(f"max_factor_bit_len too big: {max_factor_bit_len}")
    pwn.log.info(f"{min_max_factor_bit_len = }")

tn.interactive()
