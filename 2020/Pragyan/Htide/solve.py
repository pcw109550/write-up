#!/usr/bin/env python2
from pwn import *

context.log_level = "DEBUG"
key_default = "0daaba74f35afe20988172f4680e68b8"


def authorize(key):
    p = remote("ctf.pragyan.org", 13500)
    p.recvuntil("To view the Flag u should be root user userid:350 groupid:123\n")
    p.recvuntil("Enter the secret key : ")
    p.sendline(key)
    p.recvline()
    try:
        userid = p.recvline().strip().lstrip("userid:")
        groupid = p.recvline().strip().lstrip("groupid:")
        return userid, groupid
    except:
        return None


def leak(additional):
    usermap = {}
    groupmap = {}
    for i in range(256):
        log.info(i)
        key = key_default[:-(len(additional) + 1) * 2] + chr(i).encode("hex")
        key += "".join([chr(c).encode("hex") for c in additional])
        output = authorize(key)
        if output != None:
            log.success(output)
            userid, groupid = output
            usermap[i] = userid
            groupmap[i] = groupid
    return usermap, groupmap


def main():
    # Use leak function to get mapping of (ct, pt) pair
    # Start leaking at the end of ciphertext, complete guessing
    # Find mapping and generate desired plaintext
    additional = [131, 113, 128, 104, 11, 104, 128]
    key = key_default[:-len(additional) * 2]
    key += "".join([chr(c).encode("hex") for c in additional])
    p = remote("ctf.pragyan.org", 13500)
    p.recvuntil("To view the Flag u should be root user userid:350 groupid:123\n")
    p.recvuntil("Enter the secret key : ")
    p.sendline(key)
    p.recvline()
    p.recvline()
    p.recvline()
    flag = p.recvline().strip()
    assert flag == "p_ctf{th3_c@ne_$f_Ic3Cre@m_is_m3lted}"
    log.success("flag = {:s}".format(flag))

if __name__ == "__main__":
    main()

