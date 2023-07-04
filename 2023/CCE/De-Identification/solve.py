import string

import pwn
from ff3 import FF3Cipher

charset = string.digits + string.ascii_lowercase

IP, PORT = "20.196.206.255", 18080

# pwn.context.log_level = "DEBUG"
tn = pwn.remote(IP, PORT)


C = tn.recvline(keepends=False).split()[-1].decode()
Key = bytes.fromhex(tn.recvline(keepends=False).split()[-1].decode())
Tweak = bytes.fromhex(tn.recvline(keepends=False).split()[-1].decode())
assert len(C) == 32 and len(Key) == 16 and len(Tweak) == 8
tn.recvline(b"decrypt:\n")

cipher = FF3Cipher.withCustomAlphabet(Key.hex(), Tweak.hex(), charset)
pt = cipher.decrypt(C)
tn.sendline(pt.encode())

tn.recvuntil(b"here is FLAG ::  ")
flag = tn.recvline(keepends=False).decode()

tn.close()

assert flag == "cce2023{De-Identify_is_yours}"
pwn.log.success(f"{flag = }")
