from config import n, e, c, field, l
from Crypto.Util.number import long_to_bytes as l2b
from math import log, sqrt, ceil


# 0. Preprocess constants

dim = 2 * ceil(sqrt(ceil(log(field, 2))))
assert dim == len(l)
k = ceil(sqrt(ceil(log(field, 2))))
k += ceil(log(ceil(log(field, 2)), 2))
k = Integer(k)
assert k == 39
bits = field.bit_length()
assert bits == 800
mask = 2 ** bits - 2 ** (bits - k)


# 1. Construct Lattice for recovering guess

print("[*] Constructing lattice")
num_samples = Integer(dim)
t = [row[0] for row in l]
u = [row[1] for row in l]

B = 2 ** (800 - k)
M = Matrix(QQ, num_samples + 2)
for row in range(num_samples):
    M[row, row] = field
for i, col in enumerate(range(num_samples)):
    M[num_samples, col] = t[i]
    M[num_samples + 1, col] = u[i]
M[num_samples, num_samples] = B / field
M[num_samples + 1, num_samples + 1] = B

# Embedding information of bit length of guess
temp = vector([0] * (num_samples + 2))
temp[num_samples] = 2 ** 52
M = M.augment(temp)
print("[*] Running LLL for guess")
M = M.LLL()

# Sanity Check of guess
def sanity(guess):
    for (ti, ui) in zip(t, u):
        if ((ti * guess % field) & mask) != ui:
            return False
    return True
guess = 0
for i in range(num_samples):
    guess_temp = int(abs(M[i, num_samples] * field / B))
    if sanity(guess_temp):
        guess = guess_temp
if guess == 0:
    print("[-] Recovering guess failed")
    exit()
print("[+] guess = {:d}".format(guess))


# 2. Coppersmith: Recover p using guess
print("[*] Recovering p")
F.<x> = PolynomialRing(Zmod(n))
f = (guess << 300) + x
x0 = f.small_roots(X=(2 ** 300), beta=0.44, epsilon=1/32)
p = int((guess << 300) + x0[0])
print("[+] p = {:d}".format(p))


# 3. Recover private key d and profit

n = Integer(n)
assert n % p == 0
q = n // p
d = inverse_mod(e, (p - 1) * (q - 1))
flag = l2b(pow(c, d, n)).strip()
assert flag == "XMAS{hide_on_lattice}"

print("[+] flag = {:s}".format(flag))
