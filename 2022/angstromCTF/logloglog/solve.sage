#!/usr/bin/env sage
from Crypto.Util.number import long_to_bytes as l2b
from sage.all import *

q = 127049168626532606399765615739991416718436721363030018955400489736067198869364016429387992001701094584958296787947271511542470576257229386752951962268029916809492721741399393261711747273503204896435780180020997260870445775304515469411553711610157730254858210474308834307348659449375607755507371266459204680043
p = q * 2 ^ 1024 + 1
a = 0xAF99914E5FB222C655367EEAE3965F67D8C8B3A0B3C76C56983DD40D5EC45F5BCDE78F7A817DCE9E49BDBB361E96177F95E5DE65A4AA9FD7EAFEC1142FF2A58CAB5A755B23DA8AEDE2D5F77A60EFF7FB26AEC32A9B6ADEC4FE4D5E70204897947EB441CC883E4F83141A531026E8A1EB76EE4BFF40A8596106306FDD8FFEC9D03A9A54EB3905645B12500DAEABDB4E44ADCFCECC5532348C47C41E9A27B65E71F8BC7CBDABF25CD0F11836696F8137CD98088BD244C56CDC2917EFBD1AC9B6664F0518C5E612D4ACDB81265652296E4471D894A0BD415B5AF74B9B75D358B922F6B088BC5E81D914AE27737B0EF8B6AC2C9AD8998BD02C1ED90200AD6FFF4A37
g = 3
flagbits = 880

g_ = pow(g, q, p)
a_ = pow(a, q, p)
assert pow(g_, 2 ^ 1024, p) == 1
assert pow(a_, 2 ^ 1024, p) == 1

# goal: find x s.t. pow(g_, x, p) == a_

# order 2 ^ 1024 = 2 ^ e
e = 1024
gamma = pow(g_, 2 ^ (e - 1), p)
g_inv = pow(g_, -1, p)

xs = [0]
for k in range(e - 1):
    hk = (pow(g_inv, xs[k], p) * a_) % p
    hk = pow(hk, 2 ^ (e - 1 - k), p)
    # this works because base == 2
    dk = 1 if hk == gamma else 0
    xs.append(xs[k] + (2 ^ k) * dk)
flag = l2b(xs[-1] % (2 ^ flagbits))

assert (
    flag
    == b"actf{it's log, it's log, it's big, it's heavy, it's wood, it's log, it's log, it's better than bad, it's good}"
)
print(flag)
