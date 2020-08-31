#!/usr/bin/env sage

R.<y> = GF(2 ^ 64)
P = PolynomialRing(GF(2), 'x')

flag_len = 8 * 4
with open('./hdbt', 'rb') as f:
    data = f.read()
    target = data[0x1020:0x1020 + flag_len]
    target = [int.from_bytes(target[8 * i:8 * (i + 1)], byteorder='little') for i in range(4)]
    a = int.from_bytes(data[0x80c:0x80c + 8], byteorder='little')
    p = int.from_bytes(data[0x820:0x820 + 8], byteorder='little')

assert is_prime(p) and is_prime(a)
a = P(R.fetch_int(a))
p = P(R.fetch_int(p))
target = [P(R.fetch_int(t)) for t in target]

flag = b''
for t in target:
    s = inverse_mod(a, p) * t % p
    s = R(s).integer_representation()
    flag += int(s).to_bytes(8, byteorder='little')
flag = flag.decode()
print(flag)

assert flag == 'KAPO{_b1t_w0rld_is_s0Oo0Oo_w1de}'