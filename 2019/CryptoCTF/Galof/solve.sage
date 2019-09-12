from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
import random, string


def genrandstr(N):
    return "".join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))

r, enc = [], []
with open("output.txt") as out:
    for line in out:
        r.append(b2l(line.split()[0]))
        enc.append(int(line.split()[1], 16))

F.<x> = GF(2 ** 256)
P = PolynomialRing(GF(2), "x")
base = P(x ** 255 + x ** 199 + 1)

msg = genrandstr(30)
f = P(F.fetch_int(b2l(msg)))

r = [P(F.fetch_int(rs)) for rs in r]
enc = [P(F.fetch_int(encs)) for encs in enc]

# Affine Hill Cipher Variant
f1, f2 = r[0], r[1]
e1, e2 = enc[0], enc[1]

key1 = e1 - e2
key1 *= inverse_mod(inverse_mod(f1, base) - inverse_mod(f2, base), base)
key1 %= base
key2 = e1 - key1 * inverse_mod(f1, base)
key2 %= base

cnt = 0
for (f, e) in zip(r[:-1], enc[:-1]):
    assert (key1 * inverse_mod(f, base) + key2) % base == e

flag = inverse_mod((enc[-1] - key2) * inverse_mod(key1, base), base)
flag %= base
flag = F(flag).integer_representation()
flag = l2b(flag)

assert flag == "CCTF{GF2_F1nI73_Crc13_f1elds}"
print(flag)
