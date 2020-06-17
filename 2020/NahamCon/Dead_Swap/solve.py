#!/usr/bin/env python3
with open('deadswap', 'rb') as f:
    data = f.read()

a = data.count(b'\xff')
b = data.count(b'\xfe')
assert a + b == len(data)

start = 0x4ffee8
flag = ''
for i in range(40):
    chunk = data[start + 8 * i:start + 8 * i + 8]
    chunk = chunk.replace(b'\xff', b'0')
    chunk = chunk.replace(b'\xfe', b'1')
    flag += chr(int(chunk, 2))
flag = flag.strip('\x00')[::-1]

print(flag)


