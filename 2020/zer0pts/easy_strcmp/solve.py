#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l

dummy = b'zer0pts{********CENSORED********}'
dummy += (-len(dummy) % 8) * b'\x00'
data = [0, 0x410A4335494A0942, 0x0B0EF2F50BE619F0, 0x4F0A3A064A35282B, 0]

flag = b''
for i in range(len(dummy) // 8):
    temp = b2l(dummy[8 * i: 8 * (i + 1)][::-1]) + b2l(l2b(data[i]))
    temp &= (1 << 64) - 1
    flag += l2b(temp)[::-1]

flag = flag.rstrip(b'\x00').decode()
assert flag == 'zer0pts{l3ts_m4k3_4_DETOUR_t0d4y}'
print(flag)
