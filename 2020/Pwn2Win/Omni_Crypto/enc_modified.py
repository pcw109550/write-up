import gmpy2
import random
from Crypto.Util.number import bytes_to_long

def getPrimes(size):
    half = random.randint(16, size // 2 - 8) # 16 to 504
    rand = random.randint(8, half - 1)       # 8 to 503
    sizes = [rand, half, size - half - rand] # 8 to 503, 16 to 504
    print(sizes)
    while True:
        p, q = 0, 0
        for s in sizes:
            p <<= s
            q <<= s
            chunk = random.getrandbits(s)
            p += chunk
            if s == sizes[1]: # half
                chunk = random.getrandbits(s)
            q += chunk
        p |= 2**(size - 1) | 2**(size - 2) | 1
        q |= 2**(size - 1) | 2**(size - 2) | 1
        # print(bin(p))
        # print(bin(q))
        # exit()
        if gmpy2.is_prime(p) and gmpy2.is_prime(q):
            return p, q

e = 65537
p, q = getPrimes(1024)
N = p*q
phi = (p-1)*(q-1)
d = gmpy2.invert(e, phi)
m = bytes_to_long(open("flag.txt", "rb").read())
c = pow(m, e, N)
print("p =", hex(p))
print("q =", hex(q))
print("N =", hex(N))
print("c =", hex(c))
