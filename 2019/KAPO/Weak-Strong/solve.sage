from config import wn, wct, sn, sct, M_weak, M_strong
from Crypto.Util.number import long_to_bytes as l2b
from weak_strong import get_strong_prime, get_weak_prime

p = 96519019965985189420318021978086209355220104728842768493515285964382881562961
q = 69517189020993799354976567194165615733741804094602331588109289689403844859157
e = 65537
assert p * q == sn
d = inverse_mod(e, (p - 1) * (q - 1))

flag = l2b(pow(sct, d, sn)).strip()

assert flag == "POKA{ROCA_POKA_Return_Of_Coppersmith_Attack}"
print(flag)
