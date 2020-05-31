#!/usr/bin/python3 -u
# *-* coding: latin1 -*-
import sys
import base64
from Crypto.Cipher import AES

from secrets import flag, key1, iv1


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


BUFF = 256
BLOCK_SIZE = 16
iv2 = AES.new(key1, AES.MODE_ECB).decrypt(iv1)
key2 = xor(to_blocks(flag))


def encrypt(txt, key, iv):
    global key2, iv2
    assert len(key) == BLOCK_SIZE, f'Invalid key size'
    assert len(iv) == BLOCK_SIZE, 'Invalid IV size'
    assert len(txt) % BLOCK_SIZE == 0, 'Invalid plaintext size'
    bs = len(key)
    blocks = to_blocks(txt)
    ctxt = b''
    aes = AES.new(key, AES.MODE_ECB)
    curr = iv
    for block in blocks: # PCBC
        ctxt += aes.encrypt(xor(block, curr))
        curr = xor(ctxt[-bs:], block)
    iv2 = AES.new(key2, AES.MODE_ECB).decrypt(iv2)
    key2 = xor(to_blocks(ctxt))
    return str(base64.b64encode(iv+ctxt), encoding='utf8')


def enc_plaintext():
    print('Plaintext: ', end='')
    txt = base64.b64decode(input().rstrip())
    print(encrypt(txt, key1, iv1))


def enc_flag():
    print(encrypt(flag, key2, iv2))


def menu():
    while True:
        print('MENU')
        options = [('Encrypt your secret', enc_plaintext),
                   ('Encrypt my secret', enc_flag),
                   ('Exit', sys.exit)
                   ]
        for i, (op, _) in enumerate(options):
            print(f'{i+1} - {op}')
        print('Choice: ', end='')
        op = input().strip()
        assert op in ['1', '2', '3'], 'Invalid option'
        options[ord(op)-ord('1')][1]()


def main():
    print('Let\'s see if you are good enough in symmetric cryptography!\n')

    try:
        menu()
    except Exception as err:
        sys.exit(f'ERROR: {err}')


if __name__ == '__main__':
    main()

