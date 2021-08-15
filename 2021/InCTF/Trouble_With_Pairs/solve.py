#!/usr/bin/env python3
from Crypto.Util.number import inverse
from Crypto.Util.strxor import strxor
from pwn import *
from data import data
import json
from hashlib import sha256
from py_ecc.optimized_bls12_381 import (
    curve_order,
    multiply,
)
from py_ecc.bls.g2_primitives import (
    G2_to_signature,
    signature_to_G2,
)

header =    '''We are testing a new Optimised Signature scheme for Authentication in Voting System.

               You can send the Published Result in Specified Format
               Json Format : {'Name' : name, 'Vote' : vote, 'Sign' : signature}
            '''

context.log_level = "DEBUG"
DEBUG = False
# number of sigs: 46
assert len(data) == 46


def hash(msg, hash):
    m = int(hash(msg).hexdigest(),16)
    return m


def forgery(prev_sign_raw):
    s0 = signature_to_G2(bytes.fromhex(prev_sign_raw))
    m1 = hash(b"R", sha256)
    m0 = hash(b"D", sha256)
    s1 = G2_to_signature(multiply(s0, (m1 * inverse(m0, curve_order)) % curve_order)).hex()
    return s1


def get_flag(get_fake_flag=False):
    if DEBUG:
        p = process("./server.py")
    else:
        p = remote("crypto.challenge.bi0s.in", 1337)   
    p.recvuntil(header)

    if get_fake_flag:
        data[0]['Name'], data[2]['Name'] = data[2]['Name'], data[0]['Name']
    for d in data[:-1]:
        p.recvuntil("> ")
        if d["Vote"] == "D":
            d["Vote"] = "R"
            d["Sign"] = forgery(d["Sign"])
        p.sendline(json.dumps(d))
     # D must exist at least once
    assert data[-1]["Vote"] == "D"
    p.sendline(json.dumps(data[-1]))
    # reorder
    if get_fake_flag:
        data[0]['Name'], data[2]['Name'] = data[2]['Name'], data[0]['Name']

    if get_fake_flag:
        p.recvuntil("but, this one is already known, so here is your fake reward : ")
        sec = p.recvline(keepends=False)
    else:
        p.recvuntil("Seems like we could never patch this bug, here is your reward : ")
        sec = bytes.fromhex(p.recvline(keepends=False).decode())

    p.close()

    return sec


if __name__ == "__main__":
    fake_flag = get_flag(get_fake_flag=True)
    flag_xor = get_flag()
    
    flag = strxor(flag_xor, fake_flag).decode()
    assert flag == "inctf{BLS_574nd5_f0r_B0n3h_Lynn_Sh4ch4m}"
    log.success(flag)
    