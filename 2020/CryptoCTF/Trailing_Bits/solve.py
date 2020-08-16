#!/usr/bin/env python3
from config import ct

ct = ct[ct.find(2 * '{:08b}'.format(ord('C'))):]
pt = ''
chunks = []
for i in range(len(ct) // 8):
    chunk = ct[8 * i: 8 * (i + 1)]
    chunks.append(chunk)
    pt += chr(int(chunk, 2))

pt = pt[:pt.find('}') + 1]
print(pt)

