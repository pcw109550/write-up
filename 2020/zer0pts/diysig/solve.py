#!/usr/bin/env python3
import pwn
from binascii import hexlify
from Crypto.Util.number import long_to_bytes as l2b

pwn.context.log_level = 'INFO'

menu = """=-=-=-=-= DIYSig =-=-=-=-=
[1] Encrypt and Sign
[2] Verify Encrypted Mesasge
[3] Public Key Disclosure
> """
b2s = lambda ba: ''.join(list(map(chr, ba)))
s2b = lambda st: b''.join(list(map(lambda c: bytes([ord(c)]), list(st))))


def init(opt):
    IP = '18.179.178.246'
    PORT = 3001
    p = pwn.remote(IP, PORT)
    p.recvuntil(menu)
    p.sendline(str(opt))
    return p


def recvhex(p):
    return int(p.recvline(keepends=False).split()[-1], 16)


def disclose():
    p = init(3)
    p.recvuntil('[PUBKEY]\n')
    n = recvhex(p)
    e = recvhex(p)
    pwn.log.info('n = {}'.format(n))
    pwn.log.info('e = {}'.format(e))
    return n, e


def encsig(msg):
    p = init(1)
    p.sendlineafter('MSG : ', hexlify(msg.encode()).decode())
    enc = recvhex(p)
    sig = recvhex(p)
    pwn.log.info('enc = {}'.format(enc))
    pwn.log.info('sig = {}'.format(sig))
    return enc, sig


def verify(enc, sig):
    p = init(2)
    p.sendlineafter('ENC : ', '{:x}'.format(enc))
    p.sendlineafter('SIG : ', '{:08x}'.format(sig))
    response = p.recvline(keepends=False).decode()
    if 'OK' in response:
        return True
    else:
        response = response.replace('!=', '').split()[-2:]
        [h, H] = [int(hashval, 16) for hashval in response]
        return h, H

targetenc = 0x3cfa0e6ea76e899f86f9a8b50fd6e76731ca5528d59f074491ef7a6271513b2f202f4777f48a349944746e97b9e8a4521a52c86ef20e9ea354c0261ed7d73fc4ce5002c45e7b0481bb8cbe6ce1f9ef8228351dd7daa13ccc1e3febd11e8df1a99303fd2a2f789772f64cbdb847d6544393e53eee20f3076d6cdb484094ceb5c1
targetsig = 0x3b71ec3d
n, e = disclose()

hi = n
lo = 0
for i in range(1, 1024):
    chosen_ct = (targetenc * pow(1 << i, e, n)) % n
    h, H = verify(chosen_ct, targetsig)
    if H % 2 == 0:
        hi = (hi + lo) // 2
    elif H % 2 == 1:
        lo = (hi + lo) // 2
    if (hi < lo) { break }
    pwn.log.info('hi, lo = {}, {}'.format(hi, lo))
    pwn.log.info('hi, lo = {}, {}'.format(l2b(hi), l2b(lo)))

pwn.log.success(l2b(hi))
pwn.log.success(l2b(lo))

flag = 'zer0pts{n3v3r_r3v34l_7h3_LSB}'