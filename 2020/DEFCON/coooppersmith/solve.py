#!/usr/bin/env python3
import pwn
import ctypes
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long as b2l

pwn.context.log_level = 'DEBUG'


class RandomWrapper():

    def __init__(self, delta, seed=None):
        self.c = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
        if seed:
            self.seed = seed - delta
        else:
            self.seed = self.c.time(0) - delta
        pwn.log.info('seed: {}'.format(self.seed))
        self.c.srand(self.seed)
        self.Random = self.c.rand

    def Random(self):
        return self.Random()


IP, PORT = 'coooppersmith.challenges.ooo', 5000
p = pwn.remote(IP, PORT)

seed = 'ff' * 60
p.recvuntil('Please input prefix IN HEX with length no more than 120: ')
p.sendline(str(seed))

p.recvline('Your public key:')
pubkeypem = p.recvuntil('-----END RSA PUBLIC KEY-----')
pubkey = RSA.importKey(pubkeypem)
assert not pubkey.has_private()
n, e = pubkey.n, pubkey.e
pwn.log.info(f'n: {n}')
pwn.log.info(f'e: {e}')
p.recvuntil('Question: \n')
qenc = int(p.recvline(), 16)
pwn.log.info(f'qenc: {qenc}')

# guess
delta = 0 # for adjusting delay
pwn.log.info('delta: {}'.format(delta))
r = RandomWrapper(delta)
s = r.Random()
t = r.Random()
ans = (s + t) & 0xffffffff
p.sendline(str(ans))

p.recvuntil('Your flag message:\n')
c = int(p.recvline(), 16)
pwn.log.info(f'c: {c}')

print(f'n = {n}')
print(f'e = {e}')
print(f'c = {c}')

p.close()


