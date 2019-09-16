from pwn import *

context.log_level = "DEBUG"
sagepath = "/usr/local/src/SageMath/sage"

if not __debug__:
    p = remote("crypto.chal.csaw.io", 1000)
else:
    p = process(["python3", "server.py"])

a = int(p.recvline().strip().split()[-1])
b = int(p.recvline().strip().split()[-1])
prime = int(p.recvline().strip().split()[-1])
n = int(p.recvline().strip().split()[-1])
pubkey = p.recvline().strip().split()
Px = int(pubkey[-2].lstrip("(").rstrip(","))
Py = int(pubkey[-1].rstrip(")"))
p.recvuntil("What is the secret?")

argv = list(map(str, [Px, Py]))
ECDLP = process([sagepath, "ecdlp.sage"] + argv)
d = int(ECDLP.recvline())
p.sendline(str(d))
p.recvline()

flag = p.recvline().strip()
p.close()

assert flag == "flag{use_good_params}"
log.success("flag = {:s}".format(flag))
