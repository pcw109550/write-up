#!/usr/bin/env python3
from pwn import *
from ast import literal_eval
from lfe import size
from Crypto.Util.number import long_to_bytes as l2b
from hashlib import sha256

# context.log_level = "DEBUG"

if __debug__:
    p = process(["python3", "lfe.py"])
else:
    p = remote("crypto2.ctf.nullcon.net", 5000)


p.recvline()
cs = literal_eval(p.recvline().decode().strip())
assert len(cs) == size
log.info("Received cs")


def genotinp(cs):
    otinp = []
    for i in range(size):
        g, y0, y1 = cs[i], 1, cs[i]
        otinp.append("({:d},{:d},{:d})".format(g, y0, y1))
    return " ".join(otinp)

p.sendline(genotinp(cs))
log.info("Sent otinp")
p.recvuntil("Server response:")
log.info("Receiving server response")
response = literal_eval(p.recvuntil("Enter a:")[:-len("Enter a:")].decode().strip())
assert len(response) == size

a, b = [], []
for i in range(size):
    ((c00, c01), (c10, c11)) = response[i]
    H1 = int(sha256(l2b(1)).hexdigest(), 16)
    m0 = H1 ^ c01
    H2 = int(sha256(l2b(c10)).hexdigest(), 16)
    m1 = H2 ^ c11
    b.append(m0)
    a.append(m0 ^ m1)

p.sendline(str(a))
p.recvuntil("Enter b:")
p.sendline(str(b))
log.success(str(a))
log.success(str(b))

if not __debug__:
    flag = p.recvline().decode().strip()
    assert flag == "hackim20{this_was_the_most_fun_way_to_include_curveball_that_i_could_find}"
    log.success(flag)
    p.close()
else:
    p.interactive()
