#!/usr/bin/env python2

from pwn import *
from Crypto.Util.strxor import strxor
from base64 import b64encode, b64decode

# context.log_level = "DEBUG"
SIZE = 16
# padding oracle attack


def form(ct, iv):
    assert len(ct) % 16 == 0 and len(iv) == 16
    return b64encode(ct) + "|" + b64encode(iv)


def listxor(l1, l2):
    return [chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(l1, l2)]


def leak():
    plaintext = []
    for targetnum in reversed(range(-1, len(ct_target) // 16 - 1)):
        iv_xor_pt = ["\x00"] * SIZE
        for i in reversed(range(SIZE)):
            for j in range(256):
                p = remote("ctf.pragyan.org", 8500)
                p.recvline("Enter in format '<Ciphertext>|<Initialisation Vector>'")
                if targetnum >= 0:
                    ct = list(ct_target)
                    ct[SIZE * targetnum:SIZE * (targetnum + 1)] = listxor(iv_xor_pt, list(chr(SIZE - i) * SIZE))
                    ct[SIZE * targetnum + i] = chr(j)
                    ct = "".join(ct)
                    ct = ct[:SIZE * (targetnum + 2)]
                    log.info("plaintext : {:s}".format(ct.encode("hex")))
                    p.sendline(form(ct, iv_default))
                elif targetnum == -1:
                    ct = ct_target[:SIZE]
                    iv = listxor(iv_xor_pt, list(chr(SIZE - i)) * SIZE)
                    iv[i] = chr(j)
                    iv = "".join(iv)
                    log.info("plaintext : {:s}".format(iv.encode("hex")))
                    p.sendline(form(ct, iv))
                p.recvline(b64encode(iv_default))
                output = p.recvline().strip()
                if "Cipher Error!" in output: # Bad data
                    iv_xor_pt[i] = chr(j ^ (SIZE - i))
                    log.success("#{:03d} : ".format(j) + output)
                    log.success("iv_xor_pt : " + str(iv_xor_pt))
                    if targetnum >= 0:
                        ptchunk = listxor(list(ct_target)[SIZE * targetnum:SIZE * (targetnum + 1)], iv_xor_pt)
                    elif targetnum == -1:
                        ptchunk = str(listxor(list(iv_default), iv_xor_pt))
                    pt = ptchunk + pt
                    log.success("ptchunk : " + str(ptchunk))
                    break
                else: # Wrong padding or correct data :D 
                    log.info("#{:03d} : ".format(j) + output)
                    p.close()
    return plaintext


ct_target = b64decode("TIe8CkeWpqPFBmFcIqZG0JoGqBIWZ9dHbDqqfdx2hPlqHvwH/+tbAXDSyzyrn1Wf")
assert len(ct_target) == SIZE * 3
iv_default = "This is an IV456"
log.info("pt length : {}".format(len(ct_target)))

if __debug__:
    plaintext = ['@', 't', 'c', 'h', '}', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b', '\x0b']
    plaintext = ['@', 'r', '3', '_', '3', 'v', '3', 'r', 'y', 'w', 'h', '3', 'r', '3', '_', 'c'] + plaintext
    plaintext = ['p', 'c', 't', 'f', '{', 'b', '@', 'd', '_', 'p', '@', 'n', 'd', '@', 's', '_'] + plaintext
else:
    plaintext = leak()

flag = "".join(plaintext).rstrip(plaintext[-1])
assert flag == "pctf{b@d_p@nd@s_@r3_3v3rywh3r3_c@tch}"
log.success("flag = {:s}".format(flag))
