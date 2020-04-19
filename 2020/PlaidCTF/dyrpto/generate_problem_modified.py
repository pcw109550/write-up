#!/usr/bin/env python2
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
import json

from message_pb2 import Message

privkey = generate_private_key(3, 4096, openssl_backend)
pubkey = privkey.public_key()
pubkey_numbers = pubkey.public_numbers()
modulus = pubkey_numbers.n
publicExponent = pubkey_numbers.e
privateExponent = privkey.private_numbers().d

def get_padding():
    with open('/dev/urandom', 'rb') as f:
        return f.read(24)

def bytes_to_int(message):
    return int(message.encode('hex'), 16)

def int_to_bytes(message):
    ms = hex(message)[2:].strip('L')
    if len(ms) % 2 != 0:
        ms = '0' + ms
    return ms.decode('hex')

def pad(mi):
    return (mi << 192) | bytes_to_int(get_padding())

def unpad(mi):
    return mi >> 192

def encrypt(message):
    ciphertext = pow(pad(bytes_to_int(message)), publicExponent, modulus)
    return int_to_bytes(ciphertext)

def decrypt(ciphertext):
    plaintext = unpad(pow(bytes_to_int(ciphertext), privateExponent, modulus))
    return int_to_bytes(plaintext)

# with open('message.txt', 'r') as f:
#    flag_message = f.read().strip()
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l

def randstr(n):
    from string import printable
    from random import choice
    return "".join(choice(printable) for _ in range(n))

length = 270 - 4
flag_message = 'Y' * length
flag_message = randstr(length)

message = Message(id=0, msg=flag_message)
print message
m1 = message.SerializeToString()
print len(m1)
print b2l(m1).bit_length()
print m1.encode('hex')

ct1 = encrypt(message.SerializeToString())

message.id = 1
print message
m2 = message.SerializeToString()
print len(m2)
print b2l(m2).bit_length()
print m2.encode('hex')

# diff is always constant
print 'diff ='
diff = b2l(m2) - b2l(m1)
print diff
assert diff == 1 << 2152
print (pad(b2l(m2)) - pad(b2l(m1))).bit_length()
print 2152 + 192

ct2 = encrypt(message.SerializeToString())
print modulus
print len(message.SerializeToString())
print ct1.encode('hex')
print ct2.encode('hex')

# https://developers.google.com/protocol-buffers/docs/encoding
