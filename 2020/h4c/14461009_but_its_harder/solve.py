#!/usr/bin/env python3
import hgtk
import itertools
from config import ct

table_sclen = len(hgtk.const.CHO+hgtk.const.JOONG+hgtk.const.JONG)
alphahangul={
    '0':'영',
    '1':'하나',
    '2':'둘',
    '3':'셋',
    '4':'넷',
    '5':'다섯',
    'a':'에이',
    'b':'비이',
    'c':'씨이',
    'd':'디이',
    'e':'이이',
    'f':'에프',
    'g':'쥐이',
    'h':'에이치',
    'i':'아이',
    'j':'제이',
    'k':'케이',
    'l':'엘',
    'm':'엠',
    'n':'엔',
    'o':'오우',
    'p':'피이',
    'q':'큐우',
    'r':'알',
    's':'에스',
    't':'티이',
    'u':'유우',
    'v':'븨이',
    'w':'더블유',
    'x':'엑스',
    'y':'와이',
    'z':'즤즤이',
    '(':'괄호열고',
    ')':'괄호닫고',
    '_':"아래막대기"
}

def hangul_to_seq(x):
    def decompepe(i):
        ch,ju,jo=hgtk.letter.decompose(i)
        chi=hgtk.const.CHO.index(ch)
        jui=hgtk.const.JOONG.index(ju) + 19 #len(hgtk.const.CHO)
        joi=hgtk.const.JONG.index(jo) + 40 #len(hgtk.const.CHO) + len(hgtk.const.JOONG)
        return (chi,jui,joi)
    return list(itertools.chain.from_iterable(map(decompepe,x)))


def seq_to_hangul(x):
    assert len(x) % 3 == 0
    hangul = []
    for i in range(len(x) // 3):
        chunk = x[3 * i: 3 * (i + 1)]
        ch = hgtk.const.CHO[chunk[0]]
        ju  = hgtk.const.JOONG[chunk[1] - 19]
        jo  = hgtk.const.JONG[chunk[2] - 40]
        hangul.append(hgtk.letter.compose(ch, ju, jo))
    return ''.join(hangul)


def encrypt(plain, key):
    return list(itertools.starmap(lambda x, y:(x + y) % table_sclen, zip(plain, itertools.cycle(key))))


def decrypt(ciphertext, key):
    return list(itertools.starmap(lambda x, y:(x - y) % table_sclen, zip(ciphertext, itertools.cycle(key))))


key = hangul_to_seq('이것은바로암호')
# print(seq_to_hangul(decrypt(ct, key)))
# 에이치 넷 씨이 괄호열고 에이치 에이 엔 쥐이 유우 엘 아래막대기 영 엔 아래막대기 븨이 아이 쥐이 이이 엔 이이 알 이이 괄호닫고
# h4c(hangul_0n_vigenere)
exit()


# 이것은바로
end = encrypt(hangul_to_seq(alphahangul[')']), [0])
ct_end = ct[-len(end):]
key_part = []
for c, k in zip(ct_end, end):
    key_part.append((c - k) % table_sclen)
# print(seq_to_hangul(key_part))
# key length may be 7 * 3

# flag: e)

key = hangul_to_seq('이것은바로암호') #ends with 호
acc = []
for i in range(len(ct) // 3):
    ct_start = ct[3 * i:3 * i + len(key)]
    pt_start = []
    for c, k in zip(ct_start, key):
        pt_start.append((c - k) % table_sclen)
    try:
        print(seq_to_hangul(pt_start))
        acc.append(i)
    except:
        pass
    if i == 35:
        break

for val in alphahangul.values():
    end = encrypt(hangul_to_seq(val), [0])
    ct_end = ct[-3 * 6-len(end):-3 * 6]
    key_part = []
    for c, k in zip(ct_end, end):
        key_part.append((c - k) % table_sclen)
    try:
        print(seq_to_hangul(key_part))
        print(1, val)
    except:
        pass