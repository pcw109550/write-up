#!/usr/bin/env python3
import string

allstr = string.printable[:62] + "!?@-_{|}"

with open("output.txt") as f:
    data = f.readlines()

FLAG_LEN = 40
cands = [set(ord(c) for c in allstr) for _ in range(FLAG_LEN)]

for info_raw in data:
    info = info_raw.strip().split(", ")
    [fake_flag, d, i] = [info[0], int(info[1].split()[-1]), int(info[2].split()[-1])]
    assert len(fake_flag) == 40 + 5 + 1
    if d == 40 and i == 10:
        for idx, c in enumerate(fake_flag[5:-1]):
            cands[idx].discard(ord(c))

flag = ""
for cand in cands:
    assert len(cand) == 1
    flag += chr(list(cand)[0])
flag = "ASIS{" + flag + "}"
print(flag)
# ASIS{Pr!v4t3_5E7_iNTeRS3c710N_p4St_Or_Pr3sEnT}
