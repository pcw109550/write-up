#!/usr/bin/env python3
from itertools import product
import subprocess

chset = ['가', '나', '다', '라', '마', '바', '사', '아', '자', '차', '카', '타', '파', '하']
MAXLEN = 4
archive = 'flag.7z'

for cand in product(chset, repeat=4):
    cand = ''.join(cand)
    cmd = f'7z t -p{cand} {archive}'
    print(cmd)
    res = subprocess.call(
				cmd, 
				stderr=subprocess.DEVNULL, 
				stdout=subprocess.DEVNULL, 
				shell=True
			)
    if res == 0:
        print(cand)
        break
# 아자가자