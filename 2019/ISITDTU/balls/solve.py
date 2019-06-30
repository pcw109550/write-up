from pwn import *

# context.log_level = "DEBUG"

p = remote("34.68.81.63", 6666)


def decide():
    token = p.recvline().split()[3]
    if token == "heavier":
        return ">"
    elif token == "lighter":
        return "<"
    else:
        return "="


def trial():
    ans = 0
    p.recvuntil("Weighting 1: ")
    p.sendline("1,2,3,4 5,6,7,8")
    token = decide()

    p.recvuntil("Weighting 2: ")
    if token == "=":
        p.sendline("8,9 10,11")
        token = decide()
        p.recvuntil("Weighting 3: ")
        if token == ">":
            p.sendline("10 11")
            token = decide()
            if token == "=":
                ans = 9
            elif token == ">":
                ans = 11
            else:
                ans = 10
        elif token == "<":
            p.sendline("10 11")
            token = decide()
            if token == "=":
                ans = 9
            elif token == ">":
                ans = 10
            else:
                ans = 11
        else:
            p.sendline("1 2")
            token = decide()
            ans = 12
    elif token == ">":
        p.sendline("1,2,5 3,6,9")
        token = decide()
        p.recvuntil("Weighting 3: ")
        if token == "=":
            p.sendline("7 8")
            token = decide()
            if token == "=":
                ans = 4
            elif token == ">":
                ans = 8
            else:
                ans = 7
        elif token == ">":
            p.sendline("1 2")
            token = decide()
            if token == "=":
                ans = 6
            elif token == ">":
                ans = 1
            else:
                ans = 2
        else:
            p.sendline("5 9")
            token = decide()
            if token == "<":
                ans = 5
            elif token == ">":
                ans = 9
            else:
                ans = 3
    else:
        p.sendline("5,6,1 7,2,9")
        token = decide()
        p.recvuntil("Weighting 3: ")
        if token == "=":
            p.sendline("3 4")
            token = decide()
            if token == "=":
                ans = 8
            elif token == ">":
                ans = 4
            else:
                ans = 3
        elif token == ">":
            p.sendline("5 6")
            token = decide()
            if token == "=":
                ans = 2
            elif token == ">":
                ans = 5
            else:
                ans = 6
        else:
            p.sendline("1 9")
            token = decide()
            if token == "=":
                ans = 7
            else:
                ans = 1

    p.sendline(str(ans))

for i in range(50):
    trial()

flag = p.recvuntil("}").split("\n")[-1]
assert flag == "ISITDTU{y0u_hav3_200iq!!!!}"

log.success("flag : {:s}".format(flag))

p.close()

# http://www.mytechinterviews.com/12-identical-balls-problem
