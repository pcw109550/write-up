#!/usr/bin/env python3
from config import flaglen, pubkey, shares
from Crypto.Util.number import getStrongPrime, bytes_to_long, long_to_bytes
from gmpy2 import invert as inverse
from copy import deepcopy
import z3

class PRNG256(object):
    def __init__(self, seed):
        self.mask = (1 << 256) - 1
        self.seed = seed & self.mask

    def _pick(self):
        b = ((self.seed >> 0) ^ (self.seed >> 2) ^ (self.seed >> 5) ^ (self.seed >> 10 ) ^ 1) & 1
        self.seed = ((self.seed >> 1) | (b << 255)) & self.mask
        return b

    def rand(self):
        x = 0
        for i in range(256):
            x = (x << 1) | self._pick()
        return x

if __debug__:
    PRIME = getStrongPrime(1024)
    prng = PRNG256(PRIME)
    key = prng.rand()
else:
    n0, g0 = pubkey[0][0], pubkey[0][1]
    assert (g0 - 1) % n0 == 0
    key = (g0 - 1) // n0

# Step 1: Recover seed of PRNG256
V = z3.BitVecs(' '.join(['v_{}'.format(i) for i in range(256)]), 1)
S = z3.Solver()
mask = (1 << 256) - 1

for i in reversed(range(256)):
    current = (key >> i) & 1
    S.add(V[0] ^ V[2] ^ V[5] ^ V[10] ^ 1 & 1 == current)
    for j in range(255):
        V[j] = V[j + 1]
    V[255] = current

issat = S.check()
if issat != z3.sat:
    print('unsat')
    quit()
ans = S.model()
ans = sorted([(d, ans[d]) for d in ans], key = lambda x: int(str(x[0]).lstrip('v_')))
result = []
for i in reversed(range(256)):
    result.append(str(ans[i][1]))
# Seed recovered
seed = int(''.join(result), 2)

if __debug__:
    assert PRIME & mask == seed
else:
    # Recover previous seeds
    V = z3.BitVecs(' '.join(['v_{}'.format(i) for i in range(256)]), 1)
    S = z3.Solver()
    for i in range(256):
        b = V[255 - 0] ^ V[255 - 2] ^ V[255 - 5] ^ V[255 - 10] ^ 1 & 1
        for j in reversed(range(255)):
            V[j + 1] = V[j]
        V[0] = b
    for i in range(256):
        S.add(V[255 - i] == (seed >> i) & 1)
    issat = S.check()
    if issat != z3.sat:
        print('unsat')
        quit()
    ans = S.model()
    ans = sorted([(d, ans[d]) for d in ans], key = lambda x: int(str(x[0]).lstrip('v_')))
    result = []
    for i in range(256):
        result.append(str(ans[i][1]))
    prevseed = int(''.join(result), 2)
    prng = PRNG256(prevseed)
    prng.rand()
    assert prng.seed == seed
    prng = PRNG256(prevseed)

    state = []
    # Sanity check of recovered seeds
    for i in range(5):
        state.append(prng.rand())
        n, g = pubkey[i][0], pubkey[i][1]
        key = (g - 1) // n
        current = prng.rand()
        if key != current:
            print('wrong seed!')
            quit()
        state.append(current)
        state.append(prng.rand())


if not __debug__:
    prng = PRNG256(prevseed)
    n = [pubkey[i][0] for i in range(5)]
    g = [pubkey[i][1] for i in range(5)]
    c = [shares[i][1] for i in range(5)]
    c_, c__ = [1] * 5, [1] * 5
    for i in range(5):
        c_[i] = c[i]
        r, key, noise = state[3 * i + 2], state[3 * i + 1], state[3 * i + 0]
        c_[i] *= inverse(pow(r, n[i], n[i] ** 2), n[i] ** 2) % (n[i] ** 2)
        c_[i] *= inverse(pow(g[i], noise, n[i] ** 2), n[i] ** 2) % (n[i] ** 2)
        c__[i] = (c_[i] - 1) * inverse(key, n[i] ** 2) % (n[i] ** 2)
        print(c__[i].bit_length())
        c__[i] //= n[i]
    # linear combination for flag
    secret = c__[0] * 3 + c__[1] * -3 + c__[2] * 1
    flag = long_to_bytes(secret).decode()
    assert flag == 'zer0pts{excellent_w0rk!y0u_are_a_master_0f_crypt0!!!}'
    print(flag)
