from sage.all import *

k = var("k")
p = k**6 + 7 * k**4 - 40 * k**3 + 12 * k**2 - 114 * k + 31377
q = k**5 - 8 * k**4 + 19 * k**3 - 313 * k**2 - 14 * k + 14011

n = 44538727182858207226040251762322467288176239968967952269350336889655421753182750730773886813281253762528207970314694060562016861614492626112150259048393048617529867598499261392152098087985858905944606287003243
out = solve([p * q == n], k)
k = 9291098683758154336
p = int(p.subs(k=k))
q = int(q.subs(k=k))
assert p * q == n

c = 37578889436345667053409195986387874079577521081198523844555524501835825138236698001996990844798291201187483119265306641889824719989940722147655181198458261772053545832559971159703922610578530282146835945192532
phin = (p - 1) * (q - 1)
e = 31337
d = pow(e, -1, phin)
m = pow(c, d, n)

from Crypto.Util.number import long_to_bytes as l2b

print(l2b(int(m)))
# CCTF{F4C70r!N9_tRIcK5_aR3_fUN_iN_RSA?!!!}
