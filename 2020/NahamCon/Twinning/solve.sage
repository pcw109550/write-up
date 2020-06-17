from Crypto.Util.number import inverse
import os
os.environ['TERM'] = 'linux'
os.environ['TERMINFO'] = '/etc/terminfo'
import pwn
import gmpy2

pwn.context.log_level = 'DEBUG'
IP, PORT = 'jh2i.com', 50013
p = pwn.remote(IP, PORT)

p.recvline()
n = int(p.recvline(keepends=False).decode().split(',')[-1].rstrip(')'))
c = int(p.recvline(keepends=False).decode().split()[-1])
pwn.log.info(f'n = {n}')
pwn.log.info(f'c = {c}')
e = 65537

phin = 1
for f, _ in factor(n):
    phin *= f - 1
d = inverse(e, phin)
m = pow(c, d, n)
pwn.log.success(f'd = {d}')
pwn.log.success(f'm = {m}')
p.sendline(str(m))

# flag{thats_the_twinning_pin_to_win}

p.interactive()

