#!/usr/bin/env python3

# Obtained from
# https://gist.github.com/junorouse/831e5b8774104922705972d80d676ee4

'''
[iv]
954e47bb4976a6aef3bcf67b8dbe30c6
[server random]
439419b5
client random (hex) >> 954e47bb4976a6aef3bcf67b8dbe30c6
Here is your key => 11 38 84 77 55 f8 a0 60 63 f4 bd d0 f8 45 4e 41
key = '11 38 84 77 55 f8 a0 60 63 f4 bd d0 f8 45 4e 41'
'''
import hashlib
import binascii
from Crypto.Cipher import AES
from pwn import *

'''
username = b'admin'
password = b'asdf\n'
server_random = binascii.unhexlify(b'70ef3e33')
server_iv = binascii.unhexlify(b'd003547aa92414e5eaa062f4c3189f88')
client_random = binascii.unhexlify(b'd003547aa92414e5eaa062f4c3189f88')
key = username + password + server_random
md5_key = hashlib.md5(key).digest()
print(md5_key)
session_key = calc_session_key(md5_key, server_iv, client_random)
'''


def calc_session_key(key, iv, data):
    # iv = b'\x00' * 16
    target = bytearray(iv+data)

    for i in range(16):
        aes = AES.new(key, AES.MODE_ECB)
        x = aes.encrypt(target[i:i+16])
        target[i+16] ^= x[0]

    '''
    for i in range(16):
        print('%02x' % target[i+16], end=' ')
    '''

    return target[16:]


def get_command(session_key, data):
    aes = AES.new(session_key, AES.MODE_ECB)
    cmd = aes.encrypt(data.ljust(16, b'\x00'))
    return binascii.hexlify(cmd)


count = 0
context.log_level = 'debug'

TEST_MODE = False

while True:
    try:
        r = process('./main_v1')
    except:
        print('connection error')
        continue

    r.recvuntil('[iv]\n')
    count += 1
    server_iv = r.recv(32)
    if server_iv[0:2] != b'00' and not TEST_MODE and False:
        if count % 1000 == 0:
            print(count)
        r.close()
        continue

    r.recvuntil('[server random]\n')
    server_random = r.recv(8)

    if TEST_MODE:
        r.sendlineafter("username >> ", "guest")
    else:
        r.sendlineafter("username >> ", "admin".ljust(16, '\x00'))

    if TEST_MODE:
        username = b'guest'
        password = b'guest1234'
    else:
        username = b'admin'
        password = b'adminadmin123123122mkma'

    server_random = binascii.unhexlify(server_random)
    server_iv = binascii.unhexlify(server_iv)
    client_random = binascii.unhexlify(b'0'*32)
    key = username + password + server_random

    md5_key = hashlib.md5(key).digest()
    r.sendlineafter("client random (hex) >> ", b'0'*32)

    try:
        session_key = calc_session_key(md5_key, server_iv, client_random)
        print('session_key', count, binascii.hexlify(session_key))
        # print('debug', md5_key, server_random, server_iv, client_random)
    except:
        print('error', md5_key, server_iv, client_random)

    if not TEST_MODE:
        print('session key reset')
        session_key = b'\x00'*16

    r.sendlineafter('command (hex) >> ', get_command(session_key, b'hello'))
    try:
        r.recv(1)
        print('success')
        r.sendlineafter('command (hex) >> ', get_command(session_key, b'flag'))
        r.interactive()
        break
    except:
        r.close()
        continue
