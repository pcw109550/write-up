from itertools import combinations
from decimal import Decimal, getcontext
import random
import struct
from config import ct

primes = [2]
for i in range(3, 100):
    f = True
    for j in primes:
        if i * i < j:
            break
        if i % j == 0:
            f = False
            break
    if f:
        primes.append(i)

getcontext().prec = int(100)
keys = []
for i in range(len(primes)):
    keys.append(int(Decimal(int(primes[i])).ln() * int(2 ** 256)))

n = len(keys)
d = n / log(max(keys), 2)
assert CDF(d) < 0.9408

M = Matrix.identity(n)

last_row = [128 for x in keys]
M_last_row = Matrix(ZZ, 1, len(last_row), last_row)

last_col = keys[:]
last_col.append(ct)
M_last_col = Matrix(ZZ, len(last_col), 1, last_col)

M = M.stack(M_last_row)
M = M.augment(M_last_col)

X = M.LLL()
target = X[0][:-1]
result = []

for x in target:
    if x != 128:
        result.append(128 - x)
    else:
        result.append(0)

flag_chr = [chr(c) for c in result]
cand_chr = flag_chr[:]

for c in 'flag{}':
    cand_chr.remove(c)
while '\x00' in cand_chr:
    cand_chr.remove('\x00')
compare_idxs = [flag_chr.index(c) for c in 'flag{']

for cand in combinations(cand_chr, 4):
    seed = struct.unpack('<i', ''.join(cand).encode())[0]
    random.seed(seed)
    idxs = list(range(len(keys)))
    random.shuffle(idxs)
    if compare_idxs == idxs[:len('flag{')]:
        break

flag = ['\x00'] * len(flag_chr)
for i, idx in enumerate(idxs):
    flag[i] = flag_chr[idx]
flag = ''.join(flag).rstrip('\x00')

assert flag == 'flag{r341_e1s3nst13n}'
print(flag)
