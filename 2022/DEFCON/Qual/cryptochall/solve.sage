import os
import random
import sys
from math import gcd, lcm

from Crypto.Util.strxor import strxor

os.environ["PWNLIB_NOTERM"] = "1"
import pwn
from Crypto.Util.number import inverse
from sage.all import Mod, crt, discrete_log

CONST = 0x48474645444342410000000000000000


def simulated_parameter_gen(p, q, e):
    n = p * q
    d = inverse(e, (p - 1) * (q - 1))
    r = random.randint(1, (1 << 32) - 1)
    p_ = CONST + r
    d_ = inverse(e, (p_ - 1) * (q - 1))
    return p_, d_


def simulated_decryption_oracle(d_, n, x):
    return pow(x, d_, n)


def recover_p_test(p, q, e):
    # Step 1. Game setting, this must be replaced to menu in the program.
    n = p * q
    simulated_p_, simulated_d_ = simulated_parameter_gen(p, q, e)

    # Step 2. Recover d_
    val = simulated_decryption_oracle(simulated_d_, n, 2)
    d_p = discrete_log(Mod(val % p, p), Mod(2, p))
    d_q = discrete_log(Mod(val % q, q), Mod(2, q))
    assert pow(2, d_p, p) == val % p
    assert pow(2, d_q, q) == val % q

    d_ = crt([d_p, d_q], [p - 1, q - 1])
    assert d_ == simulated_d_

    # Step 3. Recover p_
    chk = (d_ * e - 1) // (q - 1)
    assert chk * (q - 1) == (d_ * e - 1)
    range_mn = chk // (CONST + 2**32) - 1000
    range_mx = chk // CONST + 1000

    for k in range(range_mn, range_mx):
        if chk % k == 0:
            p_ = chk // k + 1
            assert p_ == simulated_p_
            return p_

    assert False


def recover_p_real(p, q, e, decrypt_function):
    # Step 1. Game setting, this must be replaced to menu in the program.
    n = p * q

    # Step 2. Recover d_
    val = decrypt_function(2)
    d_p = discrete_log(Mod(val % p, p), Mod(2, p))
    d_q = discrete_log(Mod(val % q, q), Mod(2, q))
    assert pow(2, d_p, p) == val % p
    assert pow(2, d_q, q) == val % q

    d_ = crt([d_p, d_q], [p - 1, q - 1])

    # Step 3. Recover p_
    chk = (d_ * e - 1) // (q - 1)
    assert chk * (q - 1) == (d_ * e - 1)
    range_mn = chk // (CONST + 2**32) - 1000
    range_mx = chk // CONST + 1000

    for k in range(range_mn, range_mx):
        if chk % k == 0:
            p_ = chk // k + 1
            return p_

    assert False


def hexlify(x):
    return b"0x" + x.hex().encode()


def create_key_algx(key1, key2, key3):
    p.sendlineafter(b">", b"0")
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b">", hex(key1).encode())
    p.sendlineafter(b">", hex(key2).encode())
    p.sendlineafter(b">", hex(key3).encode())


def create_key_rot13():
    p.sendlineafter(b">", b"0")
    p.sendlineafter(b">", b"1")


def create_key_rotn(n):
    p.sendlineafter(b">", b"0")
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b">", hex(n).encode())


def create_key_mes():
    p.sendlineafter(b">", b"0")
    p.sendlineafter(b">", b"0")


def decrypt(alg, msg, wait=False):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b">", str(alg).encode())
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b">", hexlify(msg))
    if wait:
        p.recvuntil(b"Your decrypted message is:")
        p.recvline()
        p.recvline()
        data = p.recvuntil(b"\n\nWhat can we assist you with?").replace(
            b"\n\nWhat can we assist you with?", b""
        )
        return data
    else:
        return None


def encrypt(alg, msg, wait=False):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b">", str(alg).encode())
    p.sendlineafter(b">", msg)
    p.recvuntil(b"Your encrypted message is:")
    p.recvline()
    p.recvline()
    data = (
        p.recvuntil(b"\n\nWhat can we assist you with?")
        .replace(b"\n\nWhat can we assist you with?", b"")
        .split(b"\n")
    )
    rv = b""
    for x in data:
        rv += bytes.fromhex(x[2:].decode("ascii"))
    return rv


def rsa_crt_optimize(p, q, d):
    dp = inverse(d, p - 1)
    dq = inverse(d, q - 1)
    qinv = inverse(q, p)
    return [dp, dq, qinv]


def decrypt_function(x):
    a = bytes([x])
    return int.from_bytes(decrypt(0, a, True), "big")


if __name__ == "__main__":
    LOCAL = len(sys.argv) < 2
    if LOCAL == True:
        p = pwn.process("./cryptochall")
    else:
        p = pwn.remote("crypto-challenge-lpw5gjiu6sqxi.shellweplayaga.me", 31337)
        p.sendlineafter(
            b"Ticket please:",
            b"TransomRudder2468n22:RrKw3WLEhS-RfbK2nXyb6r63qRseGuMsqazZuimXGywB8FpV",
        )

    # smooth primes p, q, with their length in 96 bits to 128 bits, having same bitlen
    Kp = 0xE2B0D927C8C33093AF7931395C27E643
    Kq = 0xF216A5566BCC63D14A8466E14CEDDB3B
    Ke = 0x10001

    # leak PIE
    create_key_algx(Ke, Kp, Kq)
    create_key_mes()
    for i in range(10):
        decrypt(0, b"aaaa")
    p.sendlineafter(b">", b"y")

    x = recover_p_real(Kp, Kq, Ke, decrypt_function)
    # x = 0x555555554000 + 0x25A48
    PIE = (x & 0xFFFFFFFFFFFFFFFF) - 0x25A48
    pwn.log.info("PIE: 0x%x" % PIE)
    vtable_ptr = PIE + 0x25A48
    fake_p = (0x4847464544434241 << 64) | vtable_ptr
    fake_q = 0xE
    fake_vtable = PIE + 0x25A70
    i = 0
    while True:
        target_d = fake_vtable | (i << 64)
        modulus = lcm(fake_p - 1, fake_q - 1)
        fake_e = inverse(target_d, modulus)
        if gcd(target_d, modulus) == 1 and gcd(fake_e, (Kp - 1) * (Kq - 1)) == 1:
            fake_d = inverse(fake_e, modulus)
            assert fake_d & 0xFFFFFFFFFFFFFFFF == fake_vtable
            break
        i += 1
    create_key_algx(fake_e, Kp, Kq)
    # reclaim p,q
    create_key_mes()
    create_key_rot13()
    # now p is fake_p and q is fake_q
    for i in range(10):
        decrypt(2, b"aaaa")
    p.sendlineafter(b">", b"y")
    flag = strxor(b"A" * 0x40, encrypt(3, b"A" * 0x40))
    print("FLAG: {}".format(flag))
    p.close()
