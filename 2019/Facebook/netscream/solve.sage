from Crypto.Util.number import bytes_to_long
from crypt import ige_decrypt
from config import a, b, p, P, Q
# http://dualec.org/DualECTLS.pdf


def log(message):
    print("[+] " + message)

with open("d", "r") as f:
    d = int(f.readline().strip(), 16)

with open("enc", "r") as f:
    enc = f.readline().strip()

flag_enc = enc[32:]
iv = enc[:32]

E = EllipticCurve(Zmod(p), [0, 0, 0, a, b])
[G, P] = [E(P), E(Q)]

assert G in E and P in E
assert G == d * P

R = IntegerModRing(p)

out = bytes_to_long(iv)
out_ = out >> (2 * 8)
check = out & ((2 ** 16) - 1)

log("Bruteforcing for the next 28 bytes of PRNG")

for i in range(2 ** 16):
    guess = out_ + (i << (30 * 8))
    x = R(guess)
    if E.is_x_coord(x):
        rP = E.lift_x(x)
        # A = d * r * P = r * G
        A = d * rP
        s = Integer(A[0])
        B = s * P
        r = Integer(B[0]) & ((2 ** (8 * 30)) - 1)
        r = r >> (8 * 28)
        if r == check:
            log("Recover success")
            s = Integer((s * G)[0])
            C = s * P
            r = Integer(C[0]) & ((2 ** (8 * 30)) - 1)
            key = "{:x}".format(r)

            s = Integer((s * G)[0])
            D = s * P
            r = Integer(D[0]) & ((2 ** (8 * 30)) - 1)
            key += "{:x}".format(r)
            key = key[:64].decode("hex")

            assert len(key) == 32

            log("Calcuating key using previous state of PRNG")
            log("key: {:s}".format(key.encode("hex")))
            log("iv: {:s}".format(iv.encode("hex")))
            log("flag_enc: {:s}".format(flag_enc.encode("hex")))

            flag = ige_decrypt(flag_enc, key, iv).strip()
            log(flag)
            break

flag = "fb{dual_ec_is_not_a_good_prng_}"
