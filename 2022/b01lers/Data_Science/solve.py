#!/usr/bin/env python3
from math import sqrt

import pwn

pwn.context.log_level = "DEBUG"

IP, PORT = "ctf.b01lers.com", 9002
DEBUG = False


def recv_menu():
    tn.recvuntil(b"curve parameters:\n")
    A = float(tn.recvline(keepends=False).split(b"=")[-1])
    B = float(tn.recvline(keepends=False).split(b"=")[-1])
    C = float(tn.recvline(keepends=False).split(b"=")[-1])
    pwn.log.info(f"{A = }, {B = }, {C = }")
    return A, B, C


min_result = 1000

MAXab = 400
epsilon = 0.00000000001
while True:
    if DEBUG:
        tn = pwn.process(["./data_science", str("2.5099999999999998")])
    else:
        tn = pwn.remote(IP, PORT)

    A, B, C = recv_menu()
    D = sqrt(B ** 2 - 4 * A * C)
    xlo, xhi, xmid = (-B + D) / (2 * A), (-B - D) / (2 * A), -B / (2 * A)
    xdelta = xhi - xlo
    pwn.log.info(f"Curve: f = {A} * x ** 2 + {B} * x + {C}")
    pwn.log.info(f"{xlo = }, {xhi = }, {xmid = }, {xdelta = }")

    # heuristic
    mid_shift = xmid + 0.00001

    span_length = min(MAXab - epsilon - mid_shift, MAXab - epsilon + mid_shift) / 500
    a = mid_shift - 500 * span_length
    b = mid_shift + 500 * span_length
    pwn.log.info(f"{a = }, {b = }")

    assert a < b
    tn.sendlineafter(b"\npick your range [a,b]: ", f"{a},{b}".encode())
    tn.recvuntil(b"result= ")
    # our goal: result <= -0.63159265359
    result = float(tn.recvline(keepends=False).decode())
    min_result = min(min_result, result)
    pwn.log.info(f"{result = }")
    pwn.log.info(f"{min_result = }")
    temp = tn.recvline(keepends=False)
    if b"try harder" not in temp:
        assert b"bctf{alr1ght_g00d_job_now_on_t0_th3_REAL!_one}" in temp.strip().split()
        exit()
    tn.close()
