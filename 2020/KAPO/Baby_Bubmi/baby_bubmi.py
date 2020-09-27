#!/usr/bin/env python3

from decimal import *
import math
import random
import struct

from flag import flag

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

# Random shuffle the primes
# Now you cannot know the order
seed = struct.unpack('<i', flag[5:9])[0]
random.seed(seed)
random.shuffle(primes)

# Use ln function
# Now you cannot know the key itself
getcontext().prec = 100
keys = []
for i in range(len(flag)):
    keys.append(Decimal(primes[i]).ln())

# Sum values
# Now you cannot know the flag
sum_ = Decimal(0.0)
for i, c in enumerate(flag):
    sum_ += c * Decimal(keys[i])

ct = math.floor(sum_ * 2 ** 256)
print(ct)
