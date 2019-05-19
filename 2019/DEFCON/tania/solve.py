#!/usr/bin/env python
from pwn import *
from random import randint
from hashlib import sha1
from consts import g, p, q, y, c
from Crypto.Util.number import inverse

context.log_level = "DEBUG"

if __debug__:
    conn = process("./tania")
else:
    conn = remote("tania.quals2019.oooverflow.io", 5000)


menu = """(S) sign
(X) execute
(E) exit
"""


def sign(cmd):
    conn.recvuntil(menu)
    conn.sendline("s")
    conn.recvuntil("cmd:")
    conn.sendline(cmd)
    temp = conn.recvline().strip()
    if temp == "I don't like this rule.":
        return None
    r = int(temp.split()[-1])
    s = int(conn.recvline().strip().split()[-1])
    return (r, s)


def execute(key, cmd):
    # execution needs proper signed pair
    (r, s) = key
    conn.recvuntil(menu)
    conn.sendline("x")
    conn.recvuntil("cmd:")
    conn.sendline(cmd)
    conn.recvuntil("r:")
    conn.sendline(str(r))
    conn.recvuntil("s:")
    conn.sendline(str(s))
    if conn.recvline().strip() == "was that a valid rule? debatable.":
        # did not pass the logic sub_1E53... our goal is to bypass
        return False
    # our goal: make it pass and execute our command, system(cmd)
    return True


# generation of random k
class myrand(object):
    def __init__(self):
        self.rand1 = randint(0, q)
        self.rand2 = randint(0, q)
        self.k_init = ((c[6] * self.rand1 + c[7] * self.rand2) + c[8]) % c[9]
        self.k_curr = self.k_init

    def rand(self):
        k1 = self.k_curr
        k2 = (c[6] * ((c[0] * k1 + c[1]) % c[2]) + c[7] * ((c[3] * k1 + c[4]) % c[5]) + c[8]) % c[9]
        self.k_curr = k2
        return k1

    def set_value(self, k):
        self.k_curr = k


def gen_sign(m, x, k):
    assert 1 < k and k < q
    r = pow(g, k, p) % q
    assert r != 0
    z = int(sha1(m).hexdigest(), 16)
    s = inverse(k, q) * (z + x * r) % q
    assert s != 0
    return (r, s)


def main():
    m1 = "the rules are the rules, no complaints"
    m2 = "reyammer can change the rules"
    (r1, s1) = sign(m1)
    (r2, s2) = sign(m2)
    [z1, z2] = [int(sha1(m).hexdigest(), 16) for m in [m1, m2]]
    arg_list = [str(x) for x in [r1, s1, r2, s2, z1, z2]]

    # Breaking LCG with LLL
    LCG = process(["/usr/local/src/SageMath/sage", "LCG.sage"] + arg_list)
    x = int(LCG.recvline().strip())
    k1 = int(LCG.recvline().strip())
    k2 = int(LCG.recvline().strip())
    LCG.close()

    # sanity check
    assert pow(g, x, p) == y
    G = myrand()
    G.set_value(k1)
    assert G.rand() == k1
    assert G.rand() == k2

    # Any value of k in 1 < k < q is allowed
    k = 2
    cmd = "cat flag"
    (r, s) = gen_sign(cmd, x, k)
    execute((r, s), cmd)

    flag = conn.recvline().strip()
    print(flag)

    conn.close()

if __name__ == "__main__":
    main()
