#!/usr/bin/python3
import random
import binascii
import re
from keys import flag

flag = re.findall(r'HarekazeCTF{(.+)}', flag)[0]
flag = flag.encode()
#print(flag)

def pad25(s):
    if len(s) % 25 == 0:
        return b''
    return b'\x25'*(25 - len(s) % 25)

def kinoko(text):
    text = text + pad25(text)
    mat = []
    for i in range(0, len(text), 25):
        mat.append([
            [text[i], text[i+1], text[i+2], text[i+3], text[i+4]],
            [text[i+5], text[i+6], text[i+7], text[i+8], text[i+9]],
            [text[i+10], text[i+11], text[i+12], text[i+13], text[i+14]],
            [text[i+15], text[i+16], text[i+17], text[i+18], text[i+19]],
            [text[i+20], text[i+21], text[i+22], text[i+23], text[i+24]],
            ])
    print("kinoko")
    print(mat)
    return mat

def takenoko(X, Y):
    W = [[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]]
    for i in range(5):
        for j in range(5):
            for k in range(5):
                W[i][j] = (W[i][j] + X[i][k] * Y[k][j]) % 251
                print(W)
            print(W)
    print(W)
    return W

def encrypt(m1, m2):
    c = b""
    for mat in m1:
        g = random.randint(0,1)
        if g == 0:
            mk = takenoko(m2, mat)
        else:
            mk = takenoko(mat, m2)
        for k in mk:
            c += bytes(k)
    return c


if __name__ == '__main__':
    m1 = kinoko(flag)
    m2 = [[1,3,2,9,4], [0,2,7,8,4], [3,4,1,9,4], [6,5,3,-1,4], [1,4,5,3,5]]
    print("Encrypted Flag:")
    enc_flag = binascii.hexlify(encrypt(m1, m2)).decode()
    print(enc_flag)
