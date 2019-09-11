#!/usr/bin/env python

import gmpy2
from hashlib import sha256
from secret import u, v, x, y

assert ((u+1)**2 + u**2 - v**2)**2 + ((x+1)**3 - x**3 - y**2)**4 + (gmpy2.is_prime(v) + 1)**6 + (gmpy2.is_prime(y) - 1)**8 + (len(bin(u)[2:]) - 664)**10 + (len(bin(x)[2:]) - 600)**12 == 664 - 600

flag = 'CCTF{' + sha256(str(u) + str(v) + str(x) + str(y)).hexdigest() + '}'
