#!/usr/bin/env python
from pwn import *
import json

# context.log_level = "DEBUG"

p = remote("challenges.fbctf.com", 8089)
p.recvline("Done! Thank you for your patience")

cmdlist = ["help", "sign", "info", "spec", "flag", "save", "list"]


def genjson(command, args=None, sig=None):
    assert command in cmdlist
    request = dict()
    params = dict()
    if args is not None:
        for (arg, data) in args:
            params[arg] = data
    request["params"] = params
    if sig is not None:
        request["sig"] = sig
    request["command"] = command
    return json.dumps(request, sort_keys=True)


def request(req):
    p.recvuntil("> ")
    p.sendline(req)
    data = p.recv()
    return data


def getsign(out):
    sign = json.loads(out)
    [r, s] = map(int, sign["sig"].decode("base64").split("|"))
    return (r, s)


def main():
    log.info("Signing cmd: sign(command='spec')")
    out = request(genjson("sign", [("command", "spec")]))
    log.info("Result: signing algorithm")
    dsaalgo = request(out)
    log.success(dsaalgo)

    log.info("Signing cmd: sign(command='list')")
    out = request(genjson("sign", [("command", "list")]))
    log.info("Result: flag_filename")
    flag_filename = request(out).strip()
    log.success(flag_filename)

    message_to_forge = genjson("flag", [("name", flag_filename)])
    log.info("message to forge: {:s}".format(message_to_forge))

    log.info("Signing cmd: sign(command='info')")
    out = request(genjson("sign", [("command", "info")]))
    log.info("Result: curve spec")
    curve_spec = request(out)
    log.success(curve_spec.strip().rstrip("\n> "))
    [curve, gen, pub] = curve_spec.split("\n")[:3]
    a = int(curve.split()[5].rstrip("*x"))
    b = int(curve.split()[7])
    q = int(curve.split()[-1].rstrip(")"))
    Gx = int(gen.split()[1].lstrip("(").rstrip(","))
    Gy = int(gen.split()[2].rstrip(")"))
    Hx = int(pub.split()[2].lstrip("(").rstrip(","))
    Hy = int(pub.split()[3].rstrip(")"))

    arg_list = [str(x) for x in [a, b, q, Gx, Gy, Hx, Hy, message_to_forge]]

    # Breaking discrete log with pohlig hellman algorithm
    DISCRETE_LOG = process(["/usr/local/src/SageMath/sage", "ECDLP.sage"] + arg_list)
    primes = DISCRETE_LOG.recvline().strip()
    log.info("prime list: " + primes)
    primelen = int(DISCRETE_LOG.recvline().strip())
    log.info("Solving ECDLP with pohlig hellman algorithm")
    for i in range(primelen):
        log.info(DISCRETE_LOG.recvline().strip())
    key = int(DISCRETE_LOG.recvline().strip())
    log.success("privkey: {:d}".format(key))
    sig = DISCRETE_LOG.recvline().strip().decode("utf-8")
    log.success("forged signature: {:s}".format(sig))
    DISCRETE_LOG.close()

    forged = json.loads(message_to_forge)
    forged["sig"] = sig
    forged = json.dumps(forged, sort_keys=True)
    p.recvuntil("> ")
    p.sendline(forged)
    flag = p.recvline().strip()
    p.close()

    log.success(flag)

    flag = "fb{random_curves_are_not_safe?}"

if __name__ == "__main__":
    main()
