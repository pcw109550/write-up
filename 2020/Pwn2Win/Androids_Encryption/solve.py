#!/usr/bin/env python3
import pwn
import base64
from Crypto.Cipher import AES

DEBUG = False
pwn.context.log_level = 'DEBUG'

if DEBUG:
    p = pwn.process(['python3', 'server_local.py'])
else:
    IP, PORT = 'encryption.pwn2.win', 1337
    p = pwn.remote(IP, PORT)

menu = '''MENU
1 - Encrypt your secret
2 - Encrypt my secret
3 - Exit
Choice: '''
BLOCK_SIZE = 16


def to_blocks(txt):
    return [txt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(txt)//BLOCK_SIZE)]


def xor(b1, b2=None):
    if isinstance(b1, list) and b2 is None:
        assert len(set([len(b) for b in b1])) == 1, 'xor() - Invalid input size'
        assert all([isinstance(b, bytes) for b in b1]), 'xor() - Invalid input type'
        x = [len(b) for b in b1][0]*b'\x00' # BLOCK_SIZE * 16
        for b in b1:
            x = xor(x, b)
        return x
    assert isinstance(b1, bytes) and isinstance(b2, bytes), 'xor() - Invalid input type'
    return bytes([a ^ b for a, b in zip(b1, b2)])



def encrypt_your_secret(pt):
    p.recvuntil(menu)
    p.sendline(str(1))
    pt = base64.b64encode(pt.encode())
    p.sendlineafter('Plaintext: ', pt)
    data = base64.b64decode(p.recvline(keepends=False).decode())
    pwn.log.info(data)
    iv, ct = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return iv, ct


def encrypt_my_secret():
    p.recvuntil(menu)
    p.sendline(str(2))
    data = base64.b64decode(p.recvline(keepends=False).decode())
    pwn.log.info(data)
    iv, ct = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return iv, ct


pt = 'A' * BLOCK_SIZE
_, ct = encrypt_your_secret(pt)
key2 = xor(to_blocks(ct))
iv, ct_flag = encrypt_my_secret()
assert len(ct_flag) == BLOCK_SIZE * 3

aes = AES.new(key2, AES.MODE_ECB)
flag = b''
blocks = to_blocks(ct_flag)
curr = iv
for block in blocks: # PCBC
    flag += xor(aes.decrypt(block), curr)
    curr = xor(flag[-BLOCK_SIZE:], block)
flag = flag.decode()
pwn.log.success(f'{flag}')

p.close()
