import hgtk
import itertools

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
        jui=hgtk.const.JOONG.index(ju)+len(hgtk.const.CHO)
        joi=hgtk.const.JONG.index(jo)+len(hgtk.const.CHO)+len(hgtk.const.JOONG)
        return (chi,jui,joi)
    return itertools.chain.from_iterable(map(decompepe,x))

def encrypt(plain,key):
    return itertools.starmap(lambda x,y:(x+y)%table_sclen, zip(plain,itertools.cycle(key)))

with open('book.txt', 'r',encoding='u8') as f:
    dummytext=''.join(filter(lambda x:hgtk.checker.is_hangul(x) and not hgtk.checker.is_jamo(x),f.read()))

with open('flag.txt', 'r') as f:
    flag=''.join(map(lambda x: alphahangul[x],f.read()))

plaintext=list(hangul_to_seq(dummytext))+list(hangul_to_seq(flag))
key=list(hangul_to_seq(input()))
print(list(encrypt(plaintext,key)))