from Crypto.Util.strxor import strxor

c1 = "\x05F\x17\x12\x14\x18\x01\x0c\x0b4"
c2 = ">\x1f\x00\x14\n\x08\x07Q\n\x0e"
assert len(c1) == len(c2)

temp = strxor(c1, c2)

# for i in range(len(c2) - 3):
#   print strxor(temp[i:i + 4], "meme")

m1 = strxor(temp[:5], '_meme')
key1 = strxor(m1[:5], c1[:5])

m2 = strxor(temp[5:], 'meme_')
key2 = strxor(m2, c2[5:])

key = key1 + key2
flag = strxor(c1[:5], key1)
flag += strxor(c1[5:], key2)
flag += strxor(c2[:5], key1)
flag += strxor(c2[5:], key2)

assert flag == "d4rk{meme__meme}c0de"

print(flag)
