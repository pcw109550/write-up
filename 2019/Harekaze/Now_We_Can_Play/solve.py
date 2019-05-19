#!/usr/bin/env python
from pwn import *
from Crypto.Util.number import long_to_bytes, inverse
from string import printable


def decrypt(conn, c1, c2):
    conn.recvuntil("Input your ciphertext c1 : ")
    conn.sendline(str(c1))
    conn.recvuntil("Input your ciphertext c2 : ")
    conn.sendline(str(c2))
    conn.recvuntil("('Your Decrypted Message :', ")
    m = int(conn.recvline().rstrip("L)\n"))
    return m

context.log_level = "DEBUG"
conn = remote("problem.harekaze.com", 30002)

conn.recvuntil("('Public Key :', (")
pk = conn.recvline().split(", ")
p = int(pk[0].rstrip("L"))
g = int(pk[1])
h = int(pk[2].rstrip("L))\n"))
conn.recvuntil("('Cipher text :', (")
cs = conn.recvline().split(", ")
c1 = int(cs[0].rstrip("L"))
c2 = int(cs[1].rstrip("L))\n"))

m_ = decrypt(conn, c1, c2)

conn.close()

for i in range(2**16, 2**17):
    flag = long_to_bytes(m_ * inverse(pow(3, i, p), p) % p)
    if all(c in printable for c in flag):
        break

assert flag == "HarekazeCTF{im_caught_in_a_dr3am_and_m7_dr3ams_c0m3_tru3}"
print(flag)
