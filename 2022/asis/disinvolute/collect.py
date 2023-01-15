#!/usr/bin/env python3
from gevent import monkey, joinall
from gevent.pool import Pool
from os import urandom
monkey.patch_socket()
from time import sleep

import pwn

pwn.context.log_level = "INFO"
IP, PORT = "188.34.203.80", 12431
e = 1000

cnt = 0
while cnt < 30:
    menu = "[Q]uit"

    pool = Pool(8)

    ns = [None for _ in range(e)]
    cs = [None for _ in range(e)]


    def extract(idx: int) -> None:
        pwn.log.info(f"Trial #{idx + 1} START")
        while True:
            try:
                tn = pwn.remote(IP, PORT)
                tn.recvuntil(menu.encode())

                tn.sendline(b"F")
                tn.recvuntil(b"| n = ")
                n = int(tn.recvline(keepends=False).decode())

                tn.recvuntil(menu.encode())
                tn.sendline(b"E")
                tn.recvuntil(b"| pow(m, e, n) = ")
                c = int(tn.recvline(keepends=False).decode())

                tn.close()

                ns[idx] = n
                cs[idx] = c

                break
            except Exception as e:
                pwn.log.info(f"Trial #{idx + 1} EOF")
            # avoid EOF
            sleep(0.5)

        pwn.log.info(f"Trial #{idx + 1} DONE")
        pwn.log.info(f"nbits = {n.bit_length()}, cbits = {c.bit_length()}")


    jobs = []
    for idx in range(e):
        jobs.append(pool.spawn(extract, idx))

    joinall(jobs)

    prefix = urandom(6).hex()
    with open(f"n_{prefix}.py", "w") as f:
        f.write(f"{ns = }")
    with open(f"c_{prefix}.py", "w") as f:
        f.write(f"{cs = }")
    