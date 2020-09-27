#!/usr/bin/env python3
from binascii import unhexlify

def crc64(x):
    crc = 0

    x += b'\x00' * 8
    for c in x:
        crc ^= c
        for i in range(8):
            if crc & (1 << 63) == 0:
                crc = crc << 1
            else:
                crc = crc << 1
                crc = crc & 0xFFFFFFFFFFFFFFFF
                crc = crc ^ 0xd39d6612f6bcad3f        

    ret = []
    for i in range(8):
        ret.append(crc & 255)
        crc >>= 8

    return bytes(ret[::-1])

inp_hex = input("> ")
inp = unhexlify(inp_hex)
assert len(inp) == 8, "Hey, check the length"

def f(s):
    ret = []
    for c in s:
        ret.append(inp[int(c)])
    return bytes(ret)

def g(t, s):
    return t + b"{" + f(s) + b"}"

def xor(a, b):
    return bytes([c1 ^ c2 for c1, c2 in zip(a, b)])

constraints = [
    [b"rbtree",   "01234567", "12345670", b'\x36\xb0\x16\xf7\x5f\x42\xa9\xf6'],
    [b"mathboy7", "12345670", "23456701", b'\x36\x94\xe4\xfc\x56\x1b\x9a\x5d'],
    [b"rubiya",   "23456701", "34567012", b'\xa8\xd8\x3a\xd2\x8d\x13\x4b\x16'],
    [b"bincat",   "34567012", "45670123", b'\xfc\x7f\xcc\xbe\xf9\xbc\x1b\xf6'],
    [b"5unkn0wn", "45670123", "56701234", b'\x08\xea\xb4\xc6\xc3\x3e\x12\x4f'],
    [b"saika",    "56701234", "67012345", b'\x68\x0c\xe0\x7e\x6f\xa7\xe4\x36'],
    [b"juno",     "67012345", "70123456", b'\x18\x7e\x80\xb9\x54\x7b\x35\xa7'],
    [b"wooeng",   "01234567", "76543210", b'\xc1\x5b\xe0\x2f\x1b\xf8\xb3\xaf']
]

for person, input_order, output_order, const in constraints:
    assert xor(crc64(g(person, input_order)), f(output_order)) == const, "WRONG :("

print("ERAI!")
print("Here's your flag")
print("flag{" + inp_hex + "}")
