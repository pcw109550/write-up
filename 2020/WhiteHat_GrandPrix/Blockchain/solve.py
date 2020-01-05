#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes as l2b
from gmpy2 import gcd, invert
from base64 import b64decode
from pyzbar.pyzbar import decode
from PIL import Image
import json

m1 = "34a7370734caff5d129ad355f78f3ccf"
m2 = "8a95963d7bedd2b81ad09cd1838c7a4d"
key1 = RSA.import_key(open(m1 + ".pem").read())
key2 = RSA.import_key(open(m2 + ".pem").read())
block1 = json.loads(open("block1.json").read())
block2 = json.loads(open("block2.json").read())
block3 = json.loads(open("block3.json").read())
# e = 65537
n1, e1 = key1.n, key1.e
n2, e2 = key2.n, key2.e
p = gcd(n1, n2)
assert n1 % p == 0 and n2 % p == 0
q1, q2 = n1 // p, n2 // p
d1 = int(invert(e1, (p - 1) * (q1 - 1)))
d2 = int(invert(e2, (p - 1) * (q2 - 1)))

data11 = int(block1["data_block"][0][m1]["messger"])
print(l2b(pow(data11, d1, n1)))
data12 = int(block1["data_block"][1][m2]["messger"])
print(l2b(pow(data12, d2, n2)))

data21 = int(block2["data_block"][0][m1]["messger"])
print(l2b(pow(data21, d1, n1)))
data22 = int(block2["data_block"][1][m2]["messger"])
print(l2b(pow(data22, d2, n2)))

data31 = int(block3["data_block"][0][m1]["messger"])
print(l2b(pow(data31, d1, n1)))
data32 = int(block3["data_block"][1][m2]["messger"])
print(l2b(pow(data32, d2, n2)))

f = open("flag.txt")
flag = f.read()
f.close()

flag = b64decode(flag)
# print(flag)
out = open("flag.png", "wb")
out.write(flag)
out.close()

flag = decode(Image.open("flag.png"))[0][0].decode()
assert flag == "Whitehat{the_ flag_blockchain_ iot}"
print(flag)
