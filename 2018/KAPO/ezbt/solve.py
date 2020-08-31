#!/usr/bin/env python3

flag_len = 66
with open('./ezbt', 'rb') as f:
    data = bytearray(f.read()[0x1020:0x1020 + flag_len])

for i in range(len(data) // 8):
    chunk = int.from_bytes(data[8 * i:8 * i + 8], byteorder='little')
    for j in reversed(range(1, 64)):
        chunk ^= ((chunk >> j) & 1) << (j - 1)
    data[8 * i:8 * i + 8] = chunk.to_bytes(8, byteorder='little')

for i in range(len(data)):
    for j in reversed(range(1, 8)):
        data[i] ^= ((data[i] >> j) & 1) << (j - 1)

flag = bytes(data).decode()
print(flag)

assert flag == 'KAPO{D1d_y0u_us3_z3?_Th3n_you_4re_f0oOo0o0O0o0Ol_guy_^__________^}'