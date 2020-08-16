#!/usr/bin/env python3
from itertools import product
from config import cipher
import math

mapstr = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!{}_'
# 2
n = len(cipher)
# 17
p = len(cipher[0])
# 64 <= flaglen < 68


def plain_to_matrix(msg, n):
    p = int(math.ceil(len(msg) // (2 * n))) + 1

    matrix_row_size = n
    matrix_col_size = p
    index = 0
    matrix_plain = []
    for i in range(matrix_row_size):
        col = []
        for j in range(matrix_col_size):
            if index >= len(msg):
                col.append(0 + 0.j)
            elif index == len(msg)-1:
                col.append(mapstr.index(msg[index]) + 0.j)
                index += 1
            else:
                col.append(mapstr.index(msg[index]) + mapstr.index(msg[index+1]) * 1.j)
                index += 2
        matrix_plain.append(col)
    return matrix_plain


def multiply(A, B):
    ac, ar, bc, br = len(A[0]), len(A), len(B[0]), len(B)
    if ac != br:
        return None
    result = []
    for i in range(ar):
        r = []
        for j in range(bc):
            r.append(0)
        result.append(r)
    for i in range(ar):
        for j in range(bc):
            for k in range(br):
                result[i][j] += A[i][k] * B[k][j]
    return result


def matrix_to_plain(mat, n):
    plain = ''
    for row in mat:
        for elem in row:
            r, i = mapstr[int(elem.real)], mapstr[int(elem.imag)]
            plain += r + i

    # must get rid of trailing zeros
    return plain


def comple_congruent(z):
    a = z.real % len(mapstr)
    b = z.imag % len(mapstr)
    return a + b * 1j


flag = ''
DEBUG = True

# first chunk
if not DEBUG:
    idx = mapstr.index('C')
    idx2 = mapstr.index('T')
    idx3 = mapstr.index('F')

    for a, b, c, d in product(range(len(mapstr)), repeat=4):
        c1 = complex(a, b)
        c2 = complex(c, d)
        result = comple_congruent(c1 * cipher[0][0] + c2 * cipher[1][0])
        # Flag starts with CCTF
        if result.real == result.imag and result.imag == idx:
            result2 = comple_congruent(c1 * cipher[0][1] + c2 * cipher[1][1])
            if result2.real == idx2 and result2.imag == idx3:
                key11 = complex(a, b)
                key12 = complex(c, d)
                break
else:
    key11 = comple_congruent(18 + 25j)
    key12 = comple_congruent(34 + 14j)

print(f'key11 = {key11}')
print(f'key12 = {key12}')

# decrypt half flag
for i in range(p):
    elem = comple_congruent(key11 * cipher[0][i] + key12 * cipher[1][i])
    flag += mapstr[int(elem.real)] + mapstr[int(elem.imag)]

print(f'flag = {flag}')


# second chunk
if not DEBUG:
    idx1 = mapstr.index('}')
    for a, b, c, d in product(range(len(mapstr)), repeat=4):
        c1 = complex(a, b)
        c2 = complex(c, d)
        result = comple_congruent(c1 * cipher[0][-1] + c2 * cipher[1][-1])
        result2 = comple_congruent(c1 * cipher[0][-2] + c2 * cipher[1][-2])
        if result.real == 0 and result.imag == 0 and \
            result2.real == idx1 and result2.imag == 0:
            temp = ''
            for i in range(p):
                elem = comple_congruent(c1 * cipher[0][i] + c2 * cipher[1][i])
                temp += mapstr[int(elem.real)] + mapstr[int(elem.imag)]
            if '{' in temp: # in temp or temp.count('_') < 4:
                continue
            print(temp)
            print(a, b, c, d)
else:
    key21 = comple_congruent(39 + 19j)
    key22 = comple_congruent(34 + 19j)

print(f'key21 = {key21}')
print(f'key22 = {key22}')

# decrypt final flag
for i in range(p):
    elem = comple_congruent(key21 * cipher[0][i] + key22 * cipher[1][i])
    flag += mapstr[int(elem.real)] + mapstr[int(elem.imag)]

flag = flag.rstrip('0')
print(f'flag = {flag}')
