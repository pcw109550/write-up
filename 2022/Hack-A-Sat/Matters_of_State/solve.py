from typing import Tuple

import pwn

pwn.context.log_level = "DEBUG"

IP, PORT = "matters_of_state.satellitesabove.me", 5300
ticket = b"ticket{zulu664841mike3:GKpmf_QYlQfqelAWRFDQ1T8ref_cggGsSbUNxZDppJ_BdDmq1Yidi4aS7tqg-N2l_Q}"


states_processed = [
    [
        -13816.83349609375,
        16032.40966796875,
        39975.738525390625,
        -3.017425537109375,
        -1.491546630859375,
        -0.152587890625,
    ]
    for _ in range(5)
]


def _interact(tn, s):
    [X, Y, Z, Vx, Vy, Vz] = s
    tn.recvuntil(b"Position: X,Y,Z \n")
    tn.sendline(f"{X},{Y},{Z}".encode())
    tn.recvuntil(b"Velocity: Vx,Vy,Vz\n")
    tn.sendline(f"{Vx},{Vy},{Vz}".encode())

    tn.recvuntil(b"dP: ")
    res = tn.recvline(keepends=False).split()
    dP, dV = float(res[0]), float(res[-1])

    res = tn.recvline()
    assert b"Correct" in res


def interact(pos: int, check: float) -> Tuple[float, float]:
    tn = pwn.remote(IP, PORT)
    tn.sendlineafter(b"Ticket please:\n", ticket)

    for s in states_processed:
        _interact(tn, s)

    if pos >= 0:
        states[pos] = check
    [X, Y, Z, Vx, Vy, Vz] = states
    tn.recvuntil(b"Position: X,Y,Z \n")
    tn.sendline(f"{X},{Y},{Z}".encode())
    tn.recvuntil(b"Velocity: Vx,Vy,Vz\n")
    tn.sendline(f"{Vx},{Vy},{Vz}".encode())

    tn.recvuntil(b"dP: ")
    res = tn.recvline(keepends=False).split()
    dP, dV = float(res[0]), float(res[-1])

    pwn.log.info(str(states))
    pwn.log.info(str([dP, dV]))

    if b"Correct" in tn.recvline(keepends=False):
        return 0.0, 0.0

    tn.close()

    return dP, dV


def binary_search():
    while True:
        states = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        pos = 0
        while pos < len(states):
            lo, hi = (-1.0e5, 1.0e5) if pos < 3 else (-1.0e3, 1.0e3)
            lw = interact(pos, lo)[pos >= 3]
            hw = interact(pos, hi)[pos >= 3]
            bound = [1, 1.0e-2][pos >= 3]
            while abs(lw - hw) > 1e-5 and lw > bound and hw > bound:
                mid = (lo + hi) / 2
                if lw < hw:
                    hi = mid
                    hw = interact(pos, hi)[pos >= 3]
                else:
                    lo = mid
                    lw = interact(pos, lo)[pos >= 3]
            pos += 1

        pwn.log.info(str(states))
        states_processed.append(states)


tn = pwn.remote(IP, PORT)
tn.sendlineafter(b"Ticket please:\n", ticket)

for s in states_processed:
    _interact(tn, s)
flag = tn.recvline(keepends=False).split()[-1].decode()
assert (
    flag
    == "flag{zulu664841mike3:GLLRieL3gOCFTMMfxTirog0bwCLybgjYxVGr5iH5TkPisZFQ6GYxTBnldOP9fnLsAe4w_yBaFjA00fgywnIAGMI}"
)
pwn.log.success(f"flag = {flag}")
