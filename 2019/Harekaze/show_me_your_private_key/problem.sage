from Crypto.Util.number import getPrime, bytes_to_long

Gx = bytes_to_long(flag[len(flag)//2:])
Gy = bytes_to_long(flag[:len(flag)//2])

def getC2Prime(kbits):
    while True:
        p = getPrime(int(kbits))
        if p % 3 == 2:
            break
    return p


def gen_key(kbits):
    p = getC2Prime(kbits//2)
    q = getC2Prime(kbits//2)
    return 65537, p, q


e, p, q = gen_key(512)
d = inverse_mod(e, (p-1)*(q-1))
n = p*q
print "[+] (n, e, d) :", (n, e, d)

b = (pow(Gy, 2, n) - pow(Gx, 3, n)) % n
EC = EllipticCurve(Zmod(n), [0, b])

G = EC(Gx, Gy)
Cx, Cy = (e*G).xy()
print "[+] Cx:", Cx
print "[+] Cy:", Cy
