#!/usr/bin/env sage
from string import printable
from config import n1, e1, c1, n2, e2, c2


def is_printable(m):
    return all([c in printable for c in m])


flag = b''

phin1 = 6855675971449186118919050033054935041919154406906295276114704567770571336810815416855352652631934085003246812454124820643165748616933723108547495985152000
d1 = inverse_mod(e1, phin1)
m1 = int(pow(c1, d1, n1))

flag += m1.to_bytes(64, byteorder='big')

# https://crypto.stackexchange.com/questions/83570/how-to-decrypt-c-when-phin-and-e-are-not-relatively-prime
p2 = 110818190048489041673110922235667224953
q2 = 245503461123389175221964239541301684621

assert (p2 - 1) % e2 == 0 and (p2 - 1) % (e2 ^ 2) != 0
phin2 = (p2 - 1) * (q2 - 1)
l = phin2 // gcd(p2 - 1, q2 - 1)
d = inverse_mod(e2, l // e2)
L = pow(2, l // e2, n2)
assert L != 1

for i in range(e2):
    m_cand = int(pow(c2, d, n2) * pow(L, i, n2) % n2)
    m_cand = m_cand.to_bytes(64, byteorder='big').strip(b'\x00')
    try:
        if is_printable(m_cand.decode()):
            flag += m_cand
    except:
        continue

flag = flag.decode()
assert flag == 'h4c(pr0gress_is_imp0ssible_with0ut_chng_th0se_wh0_cant_chng_th31r_m1nds_c4nt_ch4ng3_anyth1ng)'

print(flag)