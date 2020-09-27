from Crypto.Util.number import bytes_to_long 

flag = "flag{CENSORED}"

p = random_prime(2^512)
q = random_prime(2^512)

N = p * p * q
e = 0x10001

piN = p * (p-1) * (q-1)

d = inverse_mod(e, piN)
m = bytes_to_long(flag)

ct = pow(m, e, N)

assert pow(ct, d, N) == m

hint = (p * q) % 2^700

print((N, e, ct))
print(hint)