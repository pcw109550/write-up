import random
from secret import flag

ror = lambda x, l, b: (x >> l) | ((x & ((1<<l)-1)) << (b-l))

N = 1
for base in [2, 3, 7]:
    N *= pow(base, random.randint(123, 456))
e = random.randint(271828, 314159)

m = int.from_bytes(flag, byteorder='big')
assert m.bit_length() < N.bit_length()

for i in range(m.bit_length()):
    print(pow(ror(m, i, m.bit_length()), e, N))
