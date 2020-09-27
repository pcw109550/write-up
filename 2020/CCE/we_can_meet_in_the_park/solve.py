from Crypto.Cipher import AES
from itertools import product
import hashlib

DEBUG = True

ENCRYPTED = b'\xA5\xD1\xDB\x88\xFD\x34\xC6\x46\x0C\xF0\xC9\x55\x0F\xDB\x61\x9E\xB9\x17\xD7\x0B\xC8\x3D\xE5\x1B\x09\x71\xAE\x5F\x1C\xB5\xC7\x2C\xC5\x3F\x5A\xA7\xFB\xED\x63\xE6\xAD\x04\x0D\x16\xF6\x33\x16\x01'
ENCHED = ENCRYPTED[:16]
HEADER = b'___FLAGHEADER___'
assert len(HEADER) == 16 and len(ENCHED) == 16

if DEBUG:
    key1 = b'ZH\\\t'
    key2 = b'>L*='
else:
    table = dict()
    chset = range(100)

    print('gen table')
    for key2 in product(chset, repeat=4):
        key2 = bytes(key2)
        aes2 = AES.new(hashlib.sha256(key2).digest(), AES.MODE_ECB)
        table[aes2.decrypt(ENCHED)] = key2
    print('gen table done')

    found = False
    for key1 in product(chset, repeat=4):
        key1 = bytes(key1)
        aes1 = AES.new(hashlib.sha256(key1).digest(), AES.MODE_ECB)
        target = aes1.encrypt(HEADER)
        if target in table:
            key2 = table[target]
            found = True
            break

    assert found

print(f'key1 = {key1}')
print(f'key2 = {key2}')

aes1 = AES.new(hashlib.sha256(key1).digest(), AES.MODE_ECB)
aes2 = AES.new(hashlib.sha256(key2).digest(), AES.MODE_ECB)
myBuf = aes1.decrypt(aes2.decrypt(ENCRYPTED))

flag = myBuf[16:].decode()
assert flag == 'cce2020{super_easy_mitm_attack!}'

print(flag)

