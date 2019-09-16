from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
from gmpy2 import gcd, is_prime
from pwn import *

menu = """====================================
            fault box
====================================
1. print encrypted flag
2. print encrypted fake flag
3. print encrypted fake flag (TEST)
4. encrypt
====================================\n"""

context.log_level = "DEBUG"

if not __debug__:
    p = remote("crypto.chal.csaw.io", 1001)
else:
    p = process(["python", "local.py"])


def s2n(s):
    return bytes_to_long(bytearray(s, 'latin-1'))


def n2s(n):
    return long_to_bytes(n).decode('latin-1')


def recvmenu():
    p.recvuntil(menu)


def enc_msg(msg):
    recvmenu()
    p.sendline("4")
    p.recvuntil("input the data:")
    p.sendline(msg)
    enc = int(p.recvline().strip(), 16)
    return enc


def enc_flag():
    recvmenu()
    p.sendline("1")
    enc_flag = int(p.recvline().strip(), 16)
    return enc_flag


def enc_fake_flag():
    recvmenu()
    p.sendline("2")
    enc = int(p.recvline().strip(), 16)
    return enc


def enc_fake_flag_TEST():
    recvmenu()
    p.sendline("3")
    enc = int(p.recvline().strip(), 16)
    return enc


e = 0x10001

# 1. find out public modulus n

while True:
    msg1 = enc_msg("\x02")
    msg2 = enc_msg("\x03")
    msg3 = enc_msg("\x04")
    n1 = gcd(pow(2, e) - msg1, pow(3, e) - msg2)
    n2 = gcd(pow(3, e) - msg2, pow(4, e) - msg3)
    if n1 == n2 and n1 % 2 == 1:
        n = n1
        log.success("n = {:d}".format(n))
        break
    else:
        # next trial
        enc_flag()
        enc_flag()

# 2. find fake flag and factor n
fake_flag_fault_enc = enc_fake_flag_TEST()

base = 0
while True:
    fake_flag_cand = "fake_flag{%s}" % (("%X" % base).rjust(32, "0"))
    p_cand = gcd((pow(s2n(fake_flag_cand), e, n) - fake_flag_fault_enc) % n, n)
    if p_cand != 1 and n % p_cand == 0:
        prime, q = p_cand, n / p_cand
        log.success("p = {:d}".format(prime))
        assert prime * q == n and is_prime(prime)
        break
    base += 1

# 3. Recover the real flag
real_flag_enc = enc_flag()

phin = (prime - 1) * (q - 1)
d = inverse(e, phin)
flag = n2s(pow(real_flag_enc, d, n))

assert flag == "flag{ooo000_f4ul7y_4nd_pr3d1c74bl3_000ooo}"
log.success("flag = {:s}".format(flag))
p.close()

# https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-4/
