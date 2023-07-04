from GF import GF
from constants import Rcon
import os

def get_sbox_and_verify(x):
    xinv = int(input(f"inv({x}) > "), 16)
    assert 0 <= xinv < 256
    xinv = GF(xinv)
    assert x * (x * xinv - GF(1)) == GF(0)
    return xinv + xinv.lrotate(1) + xinv.lrotate(2) + xinv.lrotate(3) + xinv.lrotate(4) + GF(99)

def key_schedule(round_keys, KEY):
    for i in range(4):
        for j in range(4):
            round_keys[i][j].val = KEY[i + 4*j]

    for i in range(4, 4*ROUNDS+4):
        if i % 4 == 0:
            round_keys[0][i] = round_keys[0][i-4] \
                            + get_sbox_and_verify(round_keys[1][i-1]) \
                            + GF(Rcon[i // 4])

            for j in range(1, 4):
                round_keys[j][i] = round_keys[j][i-4] \
                                + get_sbox_and_verify(round_keys[(j+1)%4][i-1])
        
        else:
            for j in range(4):
                round_keys[j][i] = round_keys[j][i-4] + round_keys[j][i-1]

def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] = state[i][j] + round_key[i][j]

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = get_sbox_and_verify(state[i][j])

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]


def mix_columns(state):
    mat = [[GF(2), GF(3), GF(1), GF(1)],
           [GF(1), GF(2), GF(3), GF(1)],
           [GF(1), GF(1), GF(2), GF(3)],
           [GF(3), GF(1), GF(1), GF(2)]]
    tmp = [GF(0) for _ in range(4)]
    for j in range(4):
        for i in range(4):
            tmp[i] = mat[i][0] * state[0][j] + mat[i][1] * state[1][j] + mat[i][2] * state[2][j] + mat[i][3] * state[3][j]
        for i in range(4):
            state[i][j] = tmp[i]

BLOCK_SIZE = 16

PLAINTEXT = os.urandom(BLOCK_SIZE)
CIPHERTEXT = os.urandom(BLOCK_SIZE)

ROUNDS = 10
round_keys = [[GF(0) for i in range(4 * (ROUNDS + 1))] for j in range(4)]

print(f"Your goal is to find KEY K which satisfies AES_K({PLAINTEXT.hex()}) = {CIPHERTEXT.hex()}")

try:
    KEY = bytes.fromhex(input("KEY > "))
    assert len(KEY) == BLOCK_SIZE
except:
    print("[-] Invalid Key")
    exit(-1)

print("### Key schedule ###")
key_schedule(round_keys, KEY)

print("### Encryption ###")
state = [[GF(0) for i in range(4)] for j in range(4)]

'''
P[0] P[4] P[8]  P[12]
P[1] P[5] P[9]  P[13]
P[2] P[6] P[10] P[14]
P[3] P[7] P[11] P[15]
'''
for i in range(4):
    for j in range(4):
        state[i][j].val = PLAINTEXT[i + 4*j]

add_round_key(state, [[round_keys[z][j] for j in range(4)] for z in range(4)] )

for i in range(ROUNDS - 1):
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, [[round_keys[z][j] for j in range(4*i+4, 4*i+8)] for z in range(4)])

sub_bytes(state)
shift_rows(state)
add_round_key(state, [[round_keys[z][j] for j in range(4*ROUNDS, 4*ROUNDS+4)] for z in range(4)])

out = ''

for i in range(4):
    for j in range(4):
        out += hex(state[j][i].val)[2:].zfill(2)

if out == CIPHERTEXT.hex():
    print("Good job!", open("flag", 'r').read())

else:
    print(f"{out} != {CIPHERTEXT.hex()} :(")