import random

import pwn

from constants import Rcon
from GF import GF
from sbox import rsbox, sbox

IP, PORT = "20.196.215.52", 8322
REMOTE = True

pwn.context.log_level = "INFO"
if REMOTE:
    tn = pwn.remote(IP, PORT)
else:
    tn = pwn.process(["python", "prob.py"])

BLOCK_SIZE = 16
ROUNDS = 10

round_keys = [[GF(0) for i in range(4 * (ROUNDS + 1))] for j in range(4)]


def key_schedule(round_keys, KEY):
    for i in range(4):
        for j in range(4):
            round_keys[i][j].val = KEY[i + 4 * j]

    for i in range(4, 4 * ROUNDS + 4):
        if i % 4 == 0:
            round_keys[0][i] = (
                round_keys[0][i - 4]
                + GF(sbox[round_keys[1][i - 1].val])
                + GF(Rcon[i // 4])
            )

            for j in range(1, 4):
                round_keys[j][i] = round_keys[j][i - 4] + GF(
                    sbox[round_keys[(j + 1) % 4][i - 1].val]
                )

        else:
            for j in range(4):
                round_keys[j][i] = round_keys[j][i - 4] + round_keys[j][i - 1]


def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] = state[i][j] + round_key[i][j]


def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = GF(rsbox[state[i][j].val])


def inv_mix_columns(state):
    mat = [
        [GF(14), GF(11), GF(13), GF(9)],
        [GF(9), GF(14), GF(11), GF(13)],
        [GF(13), GF(9), GF(14), GF(11)],
        [GF(11), GF(13), GF(9), GF(14)],
    ]
    tmp = [GF(0) for _ in range(4)]
    for j in range(4):
        for i in range(4):
            tmp[i] = (
                mat[i][0] * state[0][j]
                + mat[i][1] * state[1][j]
                + mat[i][2] * state[2][j]
                + mat[i][3] * state[3][j]
            )
        for i in range(4):
            state[i][j] = tmp[i]


def inv_shift_rows(state):
    state[1][1], state[1][2], state[1][3], state[1][0] = (
        state[1][0],
        state[1][1],
        state[1][2],
        state[1][3],
    )
    state[2][2], state[2][3], state[2][0], state[2][1] = (
        state[2][0],
        state[2][1],
        state[2][2],
        state[2][3],
    )
    state[3][3], state[3][0], state[3][1], state[3][2] = (
        state[3][0],
        state[3][1],
        state[3][2],
        state[3][3],
    )


def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = GF(sbox[state[i][j].val])


def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = (
        state[1][1],
        state[1][2],
        state[1][3],
        state[1][0],
    )
    state[2][0], state[2][1], state[2][2], state[2][3] = (
        state[2][2],
        state[2][3],
        state[2][0],
        state[2][1],
    )
    state[3][0], state[3][1], state[3][2], state[3][3] = (
        state[3][3],
        state[3][0],
        state[3][1],
        state[3][2],
    )


def mix_columns(state):
    mat = [
        [GF(2), GF(3), GF(1), GF(1)],
        [GF(1), GF(2), GF(3), GF(1)],
        [GF(1), GF(1), GF(2), GF(3)],
        [GF(3), GF(1), GF(1), GF(2)],
    ]
    tmp = [GF(0) for _ in range(4)]
    for j in range(4):
        for i in range(4):
            tmp[i] = (
                mat[i][0] * state[0][j]
                + mat[i][1] * state[1][j]
                + mat[i][2] * state[2][j]
                + mat[i][3] * state[3][j]
            )
        for i in range(4):
            state[i][j] = tmp[i]


def test_inv():
    random_state = [[GF(random.randint(0, 255)) for i in range(4)] for j in range(4)]
    temp_state = random_state[:]
    sub_bytes(temp_state)
    inv_sub_bytes(temp_state)
    assert random_state == temp_state
    mix_columns(temp_state)
    inv_mix_columns(temp_state)
    assert random_state == temp_state
    shift_rows(temp_state)
    inv_shift_rows(temp_state)
    assert random_state == temp_state


def honest_response():
    # brute force inv
    tn.recvuntil(b"inv(")
    x = GF(bytes.fromhex(tn.recvuntil(b" > ")[-10:].decode()[:2])[0])
    xinv = GF(0)
    if x.val != 0:
        for i in range(1, 256):
            xinv = GF(i)
            if x * (x * xinv - GF(1)) != GF(0):
                continue
            break
    tn.sendline("{:02x}".format(xinv.val).encode())


def forge_response(target):
    prefix = tn.recvuntil(b" > ")[-10:].decode()
    # make sure that given x == 0
    assert "inv(00) > " == prefix, prefix
    for i in range(256):
        xinv = GF(i)
        # affine transformation
        temp = (
            xinv
            + xinv.lrotate(1)
            + xinv.lrotate(2)
            + xinv.lrotate(3)
            + xinv.lrotate(4)
            + GF(99)
        )
        if temp.val != target:
            continue
        # desired outcome found
        # send xinv to take control of return value of get_sbox_and_verify()
        tn.sendline("{:02x}".format(xinv.val).encode())
        return
    assert False, "forge failure"


def print_state(s):
    r = []
    for i in range(4):
        for j in range(4):
            r.append(s[j][i].val)
    print(r)


test_inv()

info = tn.recvline(keepends=False).decode()
target_pt = bytes.fromhex(info[-32 - 32 - 4 : -32 - 4])
target_ct = bytes.fromhex(info[-32:])
pwn.log.info(f"target_pt = {target_pt.hex()}")
pwn.log.info(f"target_ct = {target_ct.hex()}")

# key idea: nullify state for forgery
KEY = target_pt[:]
tn.sendlineafter(b"KEY > ", KEY.hex().encode())

# local key scheduling
key_schedule(round_keys, KEY)

# prepare target state
# start with ciphertext
final_state = [[GF(0) for i in range(4)] for j in range(4)]
for i in range(4):
    for j in range(4):
        final_state[j][i].val = target_ct[j + 4 * i]

state = final_state[:]
# rewind
add_round_key(
    state,
    [[round_keys[z][j] for j in range(4 * ROUNDS, 4 * ROUNDS + 4)] for z in range(4)],
)
inv_shift_rows(state)
inv_sub_bytes(state)

for i in reversed(range(1, ROUNDS - 1)):
    add_round_key(
        state,
        [[round_keys[z][j] for j in range(4 * i + 4, 4 * i + 8)] for z in range(4)],
    )
    inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)

add_round_key(state, [[round_keys[z][j] for j in range(4, 8)] for z in range(4)])
inv_mix_columns(state)
inv_shift_rows(state)

# handle key scheduling
tn.recvuntil(b"### Key schedule ###\n")
for i in range(4 * ROUNDS):
    honest_response()

tn.recvuntil(b"### Encryption ###\n")
# forge state while encryption
for i in range(4):
    for j in range(4):
        forge_response(state[i][j].val)

for i in range(16 * ROUNDS - 16):
    honest_response()

tn.recvuntil(b"Good job! ")
flag = tn.recvline(keepends=False).decode()
tn.close()

pwn.log.success(f"{flag = }")
