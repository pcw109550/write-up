from pwn import *
from chars import ints, opts

# context.log_level = "DEBUG"

p = remote("104.154.120.223", 8083)

for _ in range(100):
    evalstr = p.recvuntil(">>> ").rstrip(">>> ")
    evalstr = evalstr.split("\n")
    evalstr = [list(x)[:-9] for x in evalstr][1:-2]
    evalstr = zip(*evalstr)
    parsed_list = []
    q = []
    for i in range(len(evalstr)):
        if "#" in evalstr[i]:
            q.append(evalstr[i])
        else:
            parsed_list.append(q)
            q = []

    evalstr = ""
    for q in parsed_list:
        if q in ints:
            evalstr += str(ints.index(q))
        elif q in opts:
            if opts.index(q) == 0:
                evalstr += "+"
            elif opts.index(q) == 1:
                evalstr += "*"
            else:
                evalstr += "-"

    res = str(eval(evalstr))
    p.sendline(res)

flag = p.recvuntil("}").split()[-1]
assert flag == "ISITDTU{sub5cr1b3_b4_t4n_vl0g_4nd_p3wd13p13}"

log.success("flag = {:s}".format(flag))

p.close()
