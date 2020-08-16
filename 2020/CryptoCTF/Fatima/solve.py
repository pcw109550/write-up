#!/usr/bin/env python3
from fastecdsa.curve import Curve
from fastecdsa.point import Point
from string import printable
import math, random
from config import enc
from itertools import permutations

name = 'curve'.encode('utf-8')
p, a, b, q, gx, gy, aux = 241, 173, 41, 256, 53, 192, ''
curve = Curve(name, p, a, b, q, gx, gy)
G = Point(gx, gy, curve=curve)
TEN = True


def c2p(c):
    C = ord(c) * G
    return bin(C.x)[2:].zfill(8) + bin(C.y)[2:].zfill(8)


def p2c(C):
    x = int(C[:8], 2)
    y = int(C[8:], 2)
    for i in range(256):
        c = chr(i)
        temp = c2p(c)
        tempx = int(temp[:8], 2)
        tempy = int(temp[8:], 2)
        if tempx == x and tempy == y:
            return c

    assert False, 'dlp not found'


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


def circulant(v):
    C, n = [], len(v)
    for i in range(n):
        C.append(v)
        tmp = []
        tmp.append(v[-1])
        tmp.extend(v[:-1])
        v = tmp
    return C


def spiral(A):
    row = len(A)
    col = len(A[0])
    top = 0
    left = 0
    tmp = []

    while top < row and left < col:
        for i in range(left, col):
            tmp.append(A[top][i])
        top += 1
        for i in range(top, row):
            tmp.append(A[i][col - 1])
        col -= 1
        if top < row:
            for i in range(col - 1, (left - 1), -1):
                tmp.append(A[row - 1][i])
            row -= 1
        if left < col:
            for i in range(row - 1, top - 1, -1):
                tmp.append(A[i][left])

        left += 1
    result = []
    for i in range(len(A)):
        r = []
        for j in range(len(A[0])):
            r.append(tmp[i*len(A[0]) + j])
        result.append(r)
    return result


def spiral_rev(A):
    B = [[0 for _ in range(len(A))] for _ in range(len(A))]
    cnt = 0

    row = len(A)
    col = len(A[0])
    top = 0
    left = 0

    while top < row and left < col:
        for i in range(left, col):
            B[top][i] = A[cnt // len(A)][cnt % len(A)]
            cnt += 1
        top += 1
        for i in range(top, row):
            B[i][col - 1] = A[cnt // len(A)][cnt % len(A)]
            cnt += 1
        col -= 1
        if top < row:
            for i in range(col - 1, (left - 1), -1):
                B[row - 1][i] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
            row -= 1
        if left < col:
            for i in range(row - 1, top - 1, -1):
                B[i][left] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
        left += 1
    assert cnt == len(B) ** 2

    return B


def revspiral(A):
    tmp = sum(spiral(A), [])
    tmp = tmp[::-1]
    result = []
    for i in range(len(A)):
        r = []
        for j in range(len(A[0])):
            r.append(tmp[i * len(A[0]) + j])
        result.append(r)
    return result


def revspiral_rev(A):
    B = [[0 for _ in range(len(A))] for _ in range(len(A))]
    cnt = 0
    for i in range(len(A)):
        for j in range(len(A)):
            B[cnt // len(A)][cnt % len(A)] = A[len(A) - 1 - i][len(A) - 1 - j]
            cnt += 1
    return spiral_rev(B)


def helical(A):
    row = len(A)
    col = len(A[0])
    tmp = []
    dir = 0
    for k in range(0, row):
        if dir == 0:
            i = k
            for j in range(0, k+1):
                tmp.append(A[i][j])
                i -= 1
            dir = 1
        else:
            j = k
            for i in range(0, k+1):
                tmp.append(A[i][j])
                j -= 1
            dir = 0
    for k in range(1, row):
        if dir == 0:
            i = row - 1
            for j in range(k, row):
                tmp.append(A[i][j])
                i -= 1
            dir = 1
        else:
            j = row - 1
            for i in range(k, row):
                tmp.append(A[i][j])
                j -= 1
            dir = 0
    result = []
    for i in range(len(A)):
        r = []
        for j in range(len(A[0])):
            r.append(tmp[i*len(A[0]) + j])
        result.append(r)
    return result


def helical_rev(A):
    B = [[0 for _ in range(len(A))] for _ in range(len(A))]
    cnt = 0

    row = len(A)
    col = len(A[0])
    tmp = []
    dir = 0
    for k in range(0, row):
        if dir == 0:
            i = k
            for j in range(0, k+1):
                B[i][j] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
                i -= 1
            dir = 1
        else:
            j = k
            for i in range(0, k+1):
                B[i][j] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
                j -= 1
            dir = 0
    for k in range(1, row):
        if dir == 0:
            i = row - 1
            for j in range(k, row):
                B[i][j] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
                tmp.append(A[i][j])
                i -= 1
            dir = 1
        else:
            j = row - 1
            for i in range(k, row):
                B[i][j] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
                j -= 1
            dir = 0
    assert cnt == len(A) ** 2

    return B


def revhelical(A):
    tmp = sum(helical(A), [])
    tmp = tmp[::-1]
    result = []
    for i in range(len(A)):
        r = []
        for j in range(len(A[0])):
            r.append(tmp[i*len(A[0]) + j])
        result.append(r)
    return result


def revhelical_rev(A):
    # FIXED
    B = [[0 for _ in range(len(A))] for _ in range(len(A))]
    cnt = 0
    for i in range(len(A)):
        for j in range(len(A)):
            B[cnt // len(A)][cnt % len(A)] = A[len(A) - 1 - i][len(A) - 1 - j]
            cnt += 1
    return helical_rev(B)


def sinwaveform(A):
    row = len(A)
    col = len(A[0])
    tmp = []
    for j in range(col):
        if j % 2 == 0:
            for i in range(row):
                tmp.append(A[i][j])
        else:
            for i in range(row-1, -1, -1):
                tmp.append(A[i][j])
    result = []
    for i in range(len(A)):
        r = []
        for j in range(len(A[0])):
            r.append(tmp[i * len(A[0]) + j])
        result.append(r)
    return result


def sinwaveform_rev(A):
    B = [[0 for _ in range(len(A))] for _ in range(len(A))]
    cnt = 0

    row = len(A)
    col = len(A[0])
    for j in range(col):
        if j % 2 == 0:
            for i in range(row):
                B[i][j] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
        else:
            for i in range(row-1, -1, -1):
                B[i][j] = A[cnt // len(A)][cnt % len(A)]
                cnt += 1
    assert cnt == len(A) ** 2
    return B


def aux(msg):
    enc = ''
    for c in msg:
        enc += c2p(c)
    print(enc)
    return enc


def aux_rev(enc):
    dec = ''
    for i in range(0, len(enc), 16):
        dec += p2c(enc[i:i + 16])
    return dec


def pprint(A):
    for row in A:
        print(row)


dict_traversal = {
    1: spiral_rev,
    2: revspiral_rev,
    3: sinwaveform_rev,
    4: helical_rev,
    5: revhelical_rev
}


def enmat(c, l=3):
    s = int(math.sqrt(len(c) // l))
    return [[int(c[i * l:i * l + l], 2) for i in range(s * j, s * (j + 1))] for j in range(s)]


def decmat(enc):
    dec = ''
    for i in range(len(enc)):
        for j in range(len(enc[0])):
            dec += '{:03b}'.format(enc[i][j])
    return dec


def rot(n, i):
    r = [0 for i in range(n - 1)] + [1]
    r = r[i:] + r[:i]
    out = circulant(r)
    return out


ct = enc[1]

for i in range(len(enc[0])):
    i = 43
    CAL = rot(len(ct), i)
    B_ = multiply(ct, CAL)
    for S in permutations(range(1, 6), 5):
        B = B_
        S = (1, 4, 3, 2, 5)
        for idx in range(5):
            B = dict_traversal[S[idx]](B)
        temp = decmat(B)
        temp = temp[:16 * (len(temp) // 16)]
        try:
            rec = aux_rev(temp)
        except:
            continue
        if 'CCTF' in rec:
            print(S, i)
            print(rec)
            exit()
