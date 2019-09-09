from config import ct, pubkey
from modular_sqrt import modular_sqrt
from Crypto.Util.number import long_to_bytes as l2b
from string import printable


def check(m):
    return all(ch in printable for ch in l2b(m))


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def dec(t, p, q):
    n = p * q
    mp = modular_sqrt(t, p)
    mq = modular_sqrt(t, q)
    _, yp, yq = egcd(p, q)
    r = (yp * p * mq + yq * q * mp) % n
    s = (yp * p * mq - yq * q * mp) % n
    ms = [r, s, n - r, n - s]
    for m in ms:
        if check(m):
            flag = l2b(m)
    return flag

B = var("B")
p = 4 * B ** 2 + 3 * B + 7351
q = 19 * B ** 2 + 18 * B + 1379

out = solve([p * q == Integer(pubkey)], B)
B = int(out[3].rhs())
p = int(p.subs(B=B))
q = int(q.subs(B=B))

assert p * q == pubkey
# rabin cryptosystem
flag = dec(ct, p, q)
flag = "AFFCTF{" + flag + "}"
assert flag == "AFFCTF{##just!c3_just!c3_y0u_sh@ll_pursu3_##_d3m@nd__p3@c3__@nd__pursu3__!t##}"

print(flag)
