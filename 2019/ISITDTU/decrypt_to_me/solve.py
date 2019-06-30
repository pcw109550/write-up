from binascii import hexlify
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from config import enc


def generate_prg_bit(n):
    state = n
    while True:
        last_bit = state & 1
        yield last_bit
        middle_bit = state >> len(bin(n)[2:])//2 & 1
        state = (state >> 1) | ((last_bit ^ middle_bit) << (len(bin(n)[2:])-1))

adjust = 1
enc = b2l(enc.decode("base64"))
enc = "0" * adjust + "{:b}".format(enc)
prg = generate_prg_bit(len(enc))
pt = ""
for e in enc:
    pt += str(next(prg) ^ int(e))
flag = l2b(int(pt, 2))
assert flag == "ISITDTU{Encrypt_X0r_N0t_Us3_Pseud0_Rand0m_Generat0r!!!!!}"

print flag

