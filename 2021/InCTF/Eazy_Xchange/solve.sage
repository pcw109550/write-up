#!/usr/bin/env sage
import pickle
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
EC = EllipticCurve(GF(p), [a, b])
G = EC.gens()[0]

data = pickle.load(open("enc.pickle", "rb"))
cip = bytes.fromhex(data["cip"])
iv = bytes.fromhex(data["iv"])


def gen_key(G, pvkey):
    print([i for i in pvkey])
    G = sum([i*G for i in pvkey])
    return G


def decrypt(msg, key, iv):
    key = hashlib.sha256(str(key).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(msg)
    return pt


i = 0
T = EC.gen(0)

for _ in range((4 * 256) ** 2):
    T += G
    pt = decrypt(cip, T.xy()[0], iv)
    if b"inctf" == pt[:5]:
        flag = unpad(pt, 16).decode()
        break
    i += 1

assert flag == "inctf{w0w_DH_15_5o_c00l!_3c9cdad74c27d1fc}"
print(flag)
