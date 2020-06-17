from Crypto.Util.number import long_to_bytes as l2b, inverse
from config import N, e, c

p = 1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428207
q = 1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428213
assert p * q == N
phiN = (p - 1) * (q - 1)
d = inverse(e, phiN)
m = pow(c, d, N)
flag = l2b(m)
print(flag)
