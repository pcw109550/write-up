import binascii
from random import randint
from math import gcd
import gmpy

class pockets:
    def __init__(self):
        self.max_string_len = 28
    def gen_key(self):
        self.pocket = [randint(1,10)]

        for i in range(8 * self.max_string_len - 1):
            s = sum(self.pocket)
            self.pocket.append(s + randint(s, s*3))

        s = sum(self.pocket)
        self.mod = randint(s, s*3)

        self.mul = randint(1,self.mod)
        while gcd(self.mul,self.mod) != 1:
            self.mul = randint(1,self.mod)

        self.pubkey = list(map(lambda x : self.mul * x % self.mod, self.pocket))

    def encrypt(self,msg):
        if len(msg)  > 30:
            print("Message is too long!")
            return ''
        binary = bin(int(binascii.hexlify(msg),16))[2:]
        l = len(binary)
        if l % 8 != 0:
            binary = binary.rjust(l + (8-(l%8)),'0')
        c = 0
        for i in range(len(binary)):
            if binary[i] == '1':
                c += self.pubkey[i]
        return hex(c)[2:]

    def decrypt(self,enc):
        enc = int(enc,16)
        inv = int(gmpy.invert(self.mul, self.mod))
        m = inv * enc % self.mod
        s = ''
        for i in reversed(self.pocket):
            if m >= i:
                m -= i
                s += '1'
            else:
                s += '0'
        s = binascii.unhexlify(hex(int(s[::-1],2))[2:])
        return s

flag = open('flag','rb').read()[:28]
p = pockets()
p.gen_key()
print('public key: ' + str(p.pubkey))
print('encrypted: ' + p.encrypt(flag))
