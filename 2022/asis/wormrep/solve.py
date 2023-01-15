#!/usr/bin/env python3

from functools import partial

with open("wormrep.klr.enc1", "rb") as f:
    data = f.read()


with open("wormrep.klr", "w") as f:
    data_dec = "".join([chr(c ^ 0xCF) for c in data])
    f.write(data_dec)


"""
00003850: 494e 0f61 7369 735b 6e10 177f 604c 4c7f  IN.asis[n...`LL.
00003860: 5601 5255 1513 157f 6052 137f 6173 7f18  V.RU....`R..as..
00003870: 6044 7f41 157f 434f 5601 445d 0e5a 4950  `D.A..COV.D].ZIP
"""

# asis[n...`LL.V.RU....`R..as..`D.A..COV.D]

partials = [0x5B, 0x6E, 0x10, 0x17]
flag = ""
for c in partials:
    flag += chr(ord("[") ^ ord("{") ^ c)

partials = bytes.fromhex(
    "7f604c4c7f560152551513157f6052137f61737f1860447f41157f434f5601445d"
)
for c in partials:
    flag += chr(ord("_") ^ 0x7F ^ c)
flag = "ASIS" + flag
print(flag)
# ASIS{N07_@ll_v!ru535_@r3_AS_8@d_a5_cov!d}
