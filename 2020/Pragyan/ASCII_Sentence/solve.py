#!/usr/bin/env python3
from base64 import b64decode

# STEP 1: Split to recover reasonable plaintext
enc = "89 51 116 49 99 110 82 102 89 88 78 115 97 50 57 102 90 86 57 109 98 50 70 102 90 87 86 108 88 50 53 110 90 72 108 119 100 72 108 102 90 87 104 51 97 51 82 112 88 50 57 105 102 81 61 61"
# STEP 2: base64 decode
enc = b64decode("".join([chr(int(x)) for x in enc.split()]))
flag = ['\x00'] * len(enc)
# STEP 3: Demangle by weird permutation
for i in range(len(flag)):
    idx = i // 13
    if idx == 0:
        flag[2 + 3 * i] = enc[i]
    elif idx == 1:
        flag[1 + 3 * (i - 13)] = enc[i]
    else:
        flag[3 * (i - 26)] = enc[i]

flag = "".join([chr(c) for c in flag])
assert flag == "p_ctf{you_are_the_weakest_link_good_bye}"
print(flag)
