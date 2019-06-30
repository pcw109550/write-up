from pwn import *
from string import ascii_uppercase
# context.log_level = "DEBUG"

p = remote("104.154.120.223", 8085)


def encrypt(msg):
    p.recvuntil("Your choice: ")
    p.sendline("1")
    p.recvuntil("Enter your message: ")
    p.sendline(msg)
    p.recvuntil("Here is your cipher: ")
    ct = p.recvline()
    return ct


def main():
    p.recvuntil("Your cipher key: Here is your cipher: ")
    ct = p.recvline()
    ct = ct.split()
    punctuation = "~`!@#$%^&*()_-+=<,>.?|"
    pt = ""

    # from observations
    for c in ct:
        if len(c) == 8:
            pt += c[0]
        elif len(c) == 11 and c[6] in punctuation:
            pt += c[3]
        elif len(c) == 11 and c[6] in ascii_uppercase:
            pt += c[7]
        else:
            pt += c[-1]

    assert len(pt) == 64
    log.success("pt : {:s}".format(pt))

    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("Please enter the key to get flag: ")
    p.sendline(pt)
    flag = p.recvuntil("}").split()[-1]
    log.success("flag : {:s}".format(flag))

    p.close()

if __name__ == "__main__":
    main()
