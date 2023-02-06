import os

import pwn
from Crypto.Util.number import bytes_to_long, long_to_bytes

os.environ["TERM"] = "linux"
os.environ["TERMINFO"] = "/etc/terminfo"

IP, PORT = "mc.ax", 31340
DEBUG = False
# pwn.context.log_level = "DEBUG"


def rng(a, x, b, p):
    return (a * x + b) % p


def gen_cycle(p, b):
    e = 11
    R.<x> = PolynomialRing(Zmod(p), "x")

    eq = x**5 - 1
    roots = eq.roots()
    for root, _ in roots:
        if root == 1:
            continue
        a = root
        seeds = [e]
        for i in range(4):
            seeds.append(rng(a, seeds[-1], b, p))
        if len(set(seeds)) != len(seeds):
            continue
        assert rng(a, seeds[-1], b, p) == seeds[0]
        return a, seeds

    assert False


def hastad(ns, rs, cs):
    e = 11
    # do not know the exact length of flag
    for L in reversed(range(30, 44)):
        pwn.log.info(f"{L = }")

        X_len = 8 * (L + 4)
        NUM = len(ns)
        assert NUM == 3
        C = bytes_to_long(b"dice{") << ((L + 4 + 16) * 8)
        P.<x> = PolynomialRing(Zmod(prod(ns)))
        ts = [crt([int(i == j) for j in range(NUM)], ns) for i in range(NUM)]
        gs = [
            (ts[i] * ((x * (1 << (16 * 8)) + rs[i] + C) ** e - cs[i]))
            for i in range(NUM)
        ]
        g = sum(gs)
        g = g.monic()
        beta = e * 8 * (L + 4) / (2048 * NUM)
        epsilon = 1 / 32
        pwn.log.info(f"beta = {float(beta)}")
        pwn.log.info(f"epsilon = {float(epsilon)}")

        set_verbose(2)
        roots = g.small_roots(X=2**X_len, beta=beta, epsilon=epsilon)
        set_verbose(0)
        for root in roots:
            flag_cand = Integer(root)
            FLAG_cand = long_to_bytes(flag_cand)[:-4]
            return FLAG_cand


def attack():
    e = 11
    if DEBUG:
        tn = pwn.process(["python3", "./bbbb.py"])
    else:
        tn = pwn.remote(IP, PORT)
    tn.recvuntil(b"[+] The parameters of RNG:\n")
    b = Integer(tn.recvline(keepends=False).decode()[2:])
    p = Integer(tn.recvline(keepends=False).decode()[2:])
    try:
        a, seeds = gen_cycle(p, b)
    except Exception as e:
        pwn.log.info("No cycle detected")
        tn.close()
        return False
    tn.sendlineafter(b"[+] Inject b[a]ckdoor!!: ", str(a).encode())
    for seed in seeds:
        tn.sendlineafter(b"[+] Please input seed: ", str(seed).encode())
    ns, rs, cs = [], [], []
    for _ in range(5):
        tn.recvuntil(b"[+] Public Key:\n")
        n = Integer(tn.recvline(keepends=False).decode()[2:])
        e_cand = Integer(tn.recvline(keepends=False).decode()[2:])
        r = Integer(int(tn.recvline(keepends=False).decode()[2:].strip("'"), 16))
        tn.recvuntil(b"[+] Cipher Text: ")
        c = Integer(tn.recvline(keepends=False).decode())
        if e_cand == e and len(ns) < 3:
            ns.append(n)
            rs.append(r)
            cs.append(c)

    pwn.log.info(f"e_cnt = {len(ns)}")
    if len(ns) < 3:
        pwn.log.info(f"not enough e = 11")
        tn.close()
        return False

    flag = hastad(ns, rs, cs)
    flag = b"dice{" + flag
    assert flag == b"dice{r3s0rt_t0_LCG_4ft3r_f41l1ng_t0_m4k3_ch4ll}"
    tn.close()

    pwn.log.success(flag)
    return True


while not attack():
    pass
