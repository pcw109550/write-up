#!/usr/bin/env python3
from pwn import *
from string import ascii_lowercase, ascii_uppercase, digits
punc = "~`!@#$%^&*()_-+=<,>.?|"

# context.log_level = "DEBUG"

p = remote("15.164.159.194", 8006)

p.recvuntil("Your cipher key: ")
enckey = p.recvline().strip().split()


def enc(msg):
    p.recvuntil("Your choice: ")
    p.sendline(str(1))
    p.recvuntil("Enter your message: ")
    p.sendline(msg)
    return p.recvline().strip()


def genlist(chset, start=None, end=None):
    mapping = []
    for c in chset:
        mapping.append([query[start:end] for query in enc(str(c) * 64).split()])
    # Transpose
    mapping = list(map(list, zip(*mapping)))
    for c in mapping:
        assert len(set(c)) == len(chset)
    return mapping

log.info("Generating mapping")

alphabetupperlist = genlist(ascii_uppercase, 6, 10)
alphabetlowerlist = genlist(ascii_lowercase, -10, -6)
digitlist = genlist(digits, -4, None)
punclist = genlist(punc, None, 4)

key = ""
for i in range(64):
    query = enckey[i]
    n = len(query)
    if n == 16:
        # plaintext char is digit
        key += digits[digitlist[i].index(query[-4:])]
    elif n == 22:
        if query[6:10] in alphabetupperlist[i]:
            # plaintext char is uppercase alphabet
            key += ascii_uppercase[alphabetupperlist[i].index(query[6:10])]
        elif query[-10:-6] in alphabetlowerlist[i]:
            # plaintext char is lowercase alphabet
            key += ascii_lowercase[alphabetlowerlist[i].index(query[-10:-6])]
        else:
            assert False
    elif n == 28:
        # plaintext char is punctuation
        key += punc[punclist[i].index(query[:4])]
    else:
        assert False

assert len(key) == 64
log.success("Key recovered: " + key)

p.recvuntil("Your choice: ")
p.sendline(str(2))
p.recvuntil("Please enter the key to get flag: ")
p.send(key)

result = p.recv().strip()
if b"WRONG KEY" in result:
    log.failure("Try again")
    p.close()
    exit()

p.close()
flag = result.split()[-1].decode()
assert flag == "Hav3_y0u_had_4_h3adach3_4ga1n??_Forgive_me!^^"
log.success("flag = " + flag)
