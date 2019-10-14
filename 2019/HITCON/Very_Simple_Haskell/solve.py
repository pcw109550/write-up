from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import inverse
from gmpy2 import gcd
from string import printable
from config import c, n, primes, k


def encode(m):
    m = list("{:b}".format(b2l(m)))
    m = list(map(int, m))
    m = m[::-1]

    m += (8 - len(m) % 8) * [0]
    extended = m
    oriLen = len(m)
    extended = (k - len(extended) % k) * [0] + extended
    extendedBits = extended

    oriLenBits = list("{:b}".format(oriLen))
    oriLenBits = list(map(int, oriLenBits))
    oriLenBits = (k - len(oriLenBits) % k) * [0] + oriLenBits

    extendedOriLenBits = oriLenBits

    finalBits = extendedOriLenBits + extendedBits
    finalBits = finalBits[::-1]

    return finalBits


def form(flag):
    return "the flag is hitcon{" + flag + "}"


def calc(num, arr):
    num2 = num ** 2 % n
    block, restArr = arr[:k], arr[k:]
    mul = 1
    for (i, j) in zip(block, primes):
        if i * j != 0:
            mul *= i * j
    result = num2 * mul % n
    if len(restArr) == 0:
        return result
    else:
        return calc(result, restArr)


def calc2(num, arr):
    num2 = num ** 2 % n
    block, restArr = arr[:k], arr[k:]
    mul = 1
    for (i, j) in zip(block, primes):
        if i * j != 0:
            mul *= i * j
    result = num2 * mul % n
    return result


def encrypt(finalBits):
    res = calc(1, finalBits)
    return res


def decrypt(cipher):
    msg = []
    for (i, prime) in enumerate(primes):
        data = (gcd(prime, cipher ** s) - 1) // (prime - 1)
        msg.append(int(data))
    return msg


flag = "SAMPLE"
finalBits = encode(form(flag))
res = encrypt(finalBits)

# We know first k = 131 bits of plaintext
result_ = calc2(1, finalBits[:k])

# private key s
s = 1

# We also know final k = 131 bits of plaintext, since knowing len
mul = 1
for (i, j) in zip(finalBits[2 * k: 3 * k], primes):
    if i * j != 0:
        mul *= i * j
num2_ = c * inverse(mul, n) % n

assert decrypt(result_) == finalBits[:k]

# simply meet in the middle and get ciphertext
test = num2_ * inverse(result_ ** 4, n) % n

# decrypt to get intermediate k = 131 bits
m = decrypt(test)

# "o"'s 5 bits + "n{"
m = m[5 + 8 * 2:]
flag = ""

# len(flag) == 6
for i in range(6):
    flag += chr(int("".join(list(map(str, m[8 * i:8 * (i + 1)]))), 2))

flag = "hitcon{" + flag + "}"
print(flag)

# https://eprint.iacr.org/2017/421.pdf
