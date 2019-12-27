from random import randint
from math import log,sqrt,ceil
from binascii import hexlify
from Crypto.Util.number import getPrime,getStrongPrime
from Crypto.PublicKey import RSA 
import gmpy


class chall:
    def __init__(self, p, guess):
        self.p = p
        self.guess = guess
        n = ceil(log(p,2))
        self.k = ceil(sqrt(n)) + ceil(log(n,2))

    def msb(self,query):
        bits = len(bin(self.p)[2:])
        mask = 2**self.k-1 << (bits - self.k)
        ans = query & mask
        return ans 

    def next(self):
        t = randint(1,self.p-1)
        return t,self.msb((self.guess * t) % self.p)

''' encryption'''
f = open('flag','rb')
m = f.read()

p = getPrime(1024)
q = getPrime(1024)

phi = (p-1) * (q-1)
n = p * q

e = 65537
d = int(gmpy.invert(e,phi))

rsa = RSA.construct((n,e,d))
encrypted = hexlify(rsa.encrypt(m,'')[0])
print('n: ' + str(n))
print('e: ' + str(e))
print('encrypted: ' + str(encrypted))

################################oracle!################################
field = getPrime(800)
challenge = chall(field,p - (p % 2**300) >> 300)
dim = 2 * ceil(sqrt(ceil(log(field,2))))

print("field: " + str(field))
l = []
for i in range(dim):
    t, oracle = challenge.next()
    l.append((t,oracle))
    # ({},{})".format(challenge.k,t,oracle))
print("(random, msb_{}((random * number) % field)):\n".format(challenge.k) + str(l))
