from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.strxor import strxor

enc = open("flag.png.enc", "r").read()

# png magic header
header = [137, 80, 78, 71, 13, 10, 26, 10]
header += [0, 0, 0, 13]
header = "".join(list(map(chr, header)))
header += "IHDR"

out = strxor(header, enc[:len(header)])
out = list(map(int, bin(b2l(out))[2:]))


def drift(R, s):
    ans, ini = R[-1], 0
    for i in range(s):
        ini ^= R[i - 1]
    R = [ini] + R[:-1]
    return ans, R


def findstate(out):
    for r in range(7, 129):
        for s in range(2, r + 1):
            R = out[:r][::-1]
            for i in range(len(out)):
                ans, R = drift(R, s)
                if ans != out[i]:
                    break
            if i == len(out) - 1:
                R = out[:r][::-1]
                return r, s, R

r, s, R = findstate(out)

enc = bin(int(enc.encode("hex"), 16))[2:]
enc = (8 - len(enc) % 8) * "0" + enc
pt = []
for i in range(len(enc)):
    ans, R = drift(R, s)
    pt += [int(enc[i]) ^ ans]
pt = "".join([str(b) for b in pt])
f = open("flag.png", "w")
f.write(l2b(int(pt, 2)))
f.close()

flag = "CCTF{LFSR__In___51mPL3___w0rD5}"
print(flag)
