#!/usr/bin/env python3
import pwn
import cv2
import zxing
from PIL import Image
from itertools import product

pwn.context.log_level = 'DEBUG'

IP, PORT = 'qr-generator.ctf.defenit.kr', 9000
p = pwn.remote(IP, PORT)

name = 'pcw109550'
p.sendlineafter('What is your Hero\'s name? ', name)
p.recvline(f'Thank you so much *{name}* please escape from the QR devil')
decoder = zxing.BarCodeReader()

for _ in range(100):
    p.recvuntil('< QR >\n')
    mat = []
    firstrow = list(map(int, p.recvline(keepends=False).split()))
    mat.append(firstrow)
    height = width = len(firstrow)
    for _ in range(width - 1):
        row = list(map(int, p.recvline(keepends=False).split()))
        mat.append(row)
    assert len(mat) == height

    p.recvuntil('>> ')

    pwn.log.info(f'width: {width}')
    scale = 20
    margin = 20 #100
    out = Image.new('1', (width * scale + margin * 2, height * scale + margin * 2))
    outpx = out.load()

    for indX, indY in product(range(width * scale + margin * 2), repeat=2):
        pos = indX, indY
        outpx[pos] = 1

    for indX, indY in product(range(width * scale), repeat=2):
        pos = indX + margin, indY + margin
        outpx[pos] = mat[indY // scale][indX // scale] == 0
    out.save('out.png')
    rs = decoder.decode('out.png')
    p.sendline(rs.raw)

flag = 'Defenit{QQu!_3sC4p3_FR0m_D3v1l!_n1c3_C0gN1z3!}'
p.interactive()

