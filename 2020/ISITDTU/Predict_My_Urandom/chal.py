#!/usr/bin/env python2
from os import urandom
# from email import email
email = '\x00' * 16 * 16

BLOCK_SIZE = 16

pad = lambda x: x + chr(16-len(x)%16)*(16-len(x)%16)
unpad = lambda x: x[:-ord(x[-1])]
keys = [urandom(16) for i in range(100)]
print(keys[0].encode('hex'))
print('--')
keys = {i:{
    "enc":(lambda x: ''.join(chr(ord(a)^ord(b)) for a,b in zip(x,j)))
    } for i,j in enumerate(keys)}

email = pad(email)
ct = ""
for i in range(0,len(email),16):
    c = keys[i/16]["enc"](email[i:i+16])
    print(c.encode('hex'))
    ct += c
# print(ct)

#f = open('cipher','w')
#f.write(ct)
#f.close()

