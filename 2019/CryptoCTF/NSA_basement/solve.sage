from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from itertools import product
from operator import mul


pubkey, e = [], 65537
keynum = 15933
for i in range(keynum):
    key = RSA.importKey(open("keys/pubkey_{:s}.pem".format(str(i).rjust(5, "0"))))
    pubkey.append(key.n)
    assert e == key.e

factors = [set()] * keynum
res, idx = [], -1

for (i, j) in product(range(keynum), repeat=2):
    if i == j:
        continue
    k1, k2 = pubkey[i], pubkey[j]
    g = gcd(k1, k2)
    if g != 1:
        assert is_prime(g)
        factors[i].add(g)
        factors[j].add(g)
    if len(list(factors[i])) == 5:
        res = list(factors[i])
        n = pubkey[i]
        idx = i
        break


enc = open("enc/flag_{:s}.enc".format(str(idx).rjust(5, "0"))).read()
res.append(n / reduce(mul, res))

# assert all([is_prime(p) for p in res])
assert n == reduce(mul, res)
phin = reduce(mul, [p - 1 for p in res])
d = inverse_mod(65537, phin)
r = 5
[n, d, r] = list(map(int, [n, d, r]))


class Key:
    # Emulate pycryptodome's private RSA key
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d

    def _decrypt(self, ciphertext):
        result = pow(ciphertext, self.d, self.n)
        return result

key = Key(n, e, d)
cipher = PKCS1_OAEP.new(key)
flag = cipher.decrypt(enc)

assert flag == "CCTF{RSA_w17H_bAl4nc3d_1nC0mple73_bl0ck__d35igN__BIBD____}"
print(flag)
