import sys
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
import os
import random

FLAG = "flag{SAMPLE_FLAG_LONG}"
assert len(FLAG) == 22


def wline(msg=''):
    sys.stdout.write(msg)
    sys.stdout.flush()


def rline(msg=None):
    if msg is not None:
        wline(msg)
    return sys.stdin.readline().strip()


def xor(x, y):
    return strxor(x, y)


def random_bytes():
    return l2b(random.getrandbits(32)).rjust(16, "\x00")


def encrypt(aes, msg):
    blocks = [msg[idx:idx+16] for idx in range(0, len(msg), 16)]
    cipher = b''
    for block in blocks:
        block += "\x00" * (16 - len(block))
        cipher += xor(aes.encrypt(random_bytes()), block)
    return cipher


def send_enc(aes, msg):
    wline(encrypt(aes, msg))


def recv_exact(length):
    buf = rline().strip()[:length]
    assert len(buf) == length
    return buf


def recv_msg():
    return recv_exact(32)


def recv_seed():
    try:
        data = int(recv_exact(16))
    except ValueError as e:
        wline('Not a valid int\n')
        raise(e)
    return data


def main():
    try:
        wline(b'Send me a random seed\n')
        random.seed(recv_seed())
        aes = AES.new(os.urandom(16), AES.MODE_ECB)

        wline(b'Encrypted flag:\n')
        for _ in range(100):
            send_enc(aes, b'Encrypted Flag: ' + FLAG)
            wline(b'\n')

        wline(b'Okay bye\n')
        return
    except Exception as e:
        pass

main()
