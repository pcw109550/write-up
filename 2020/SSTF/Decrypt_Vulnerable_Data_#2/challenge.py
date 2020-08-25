from Crypto.Util.number import getRandomInteger
import zlib

#flag and permutation table
if __debug__:
	flag = "SCTF{This is a fake flag}"
	pt = [10, 233, 129, 64, 138, 182, 2, 167, 92, 250, 31, 123, 48, 148, 36, 83, 179, 165, 117, 185, 195, 251, 196, 131, 42, 236, 23, 43, 253, 53, 212, 216, 203, 76, 8, 28, 133, 20, 0, 17, 102, 168, 200, 190, 199, 16, 235, 140, 249, 208, 209, 44, 127, 85, 26, 70, 21, 206, 218, 135, 51, 38, 99, 142, 72, 58, 189, 243, 217, 156, 11, 240, 98, 113, 201, 32, 254, 101, 96, 184, 3, 245, 252, 71, 160, 119, 108, 6, 114, 197, 12, 22, 176, 80, 141, 50, 4, 107, 34, 49, 186, 82, 183, 181, 144, 152, 221, 172, 40, 56, 7, 239, 68, 103, 45, 134, 139, 100, 74, 67, 227, 52, 19, 126, 188, 115, 169, 118, 37, 79, 166, 222, 238, 59, 161, 105, 230, 94, 93, 163, 69, 180, 90, 14, 187, 86, 65, 191, 128, 136, 132, 177, 125, 5, 237, 89, 111, 75, 18, 91, 146, 204, 223, 120, 116, 77, 109, 110, 159, 66, 15, 155, 174, 246, 219, 248, 121, 46, 149, 241, 33, 145, 147, 54, 106, 215, 192, 61, 55, 164, 130, 214, 41, 29, 193, 220, 154, 137, 162, 73, 210, 104, 157, 60, 151, 158, 24, 205, 228, 207, 112, 25, 170, 9, 171, 244, 247, 27, 124, 224, 211, 35, 30, 198, 225, 202, 57, 88, 122, 242, 213, 84, 97, 232, 234, 87, 175, 143, 39, 194, 173, 153, 78, 63, 229, 95, 81, 255, 231, 1, 226, 62, 150, 47, 178, 13]

else:
	import random
	from secret import flag

	pt = list(range(256))
	random.shuffle(pt)

assert flag.startswith("SCTF{") and flag.endswith("}")

#mangling function, C and k are 5 short integers
def shuffle(C, k, perm):
	A = [0] * 5
	B = [0] * 5

	B[0] = perm[C[0] ^ k[0]]
	for i in range(1, 5):
		B[i] = perm[B[i - 1] ^ C[i] ^ k[i]]

	A[0] = perm[B[4] ^ B[0] ^ k[0]]
	for i in range(1, 5):
		A[i] = perm[A[i - 1] ^ B[i] ^ k[i]]

	if __debug__:
		print "[shuffle] k", k
		print "[shuffle] A", A
		print "[shuffle] B", B
		print "[shuffle] C", C

	return A

#LFSR class
class LFSR:
	def __init__(self, size, salt, invert):
		assert(size == 17 or size == 25)
		self.size = size
		self.register = ((salt >> 3) << 4) + 8 + (salt & 0x7)
		self.taps = [0, 14]
		if size == 25:
			self.taps += [3, 4]
		self.invert = 1 if invert == True else 0
	def clock(self):
		output = reduce(lambda x, y: x ^ y, [(self.register >> i) & 1 for i in self.taps])
		self.register = (self.register >> 1) + (output << (self.size - 1))

		output ^= self.invert
		return output

#split 40bit-int to 8bit-int array
def int_to_bytes(n):
	x = "%010x"%n
	return [ord(c) for c in x.decode("hex")]

#convert 8bit-int array to long int
def bytes_to_int(a):
	r = 0
	for i in a:
		r <<= 8
		r |= i
	return r

#key encryption function
def encryptKey(key):
	assert(key < 2**40)
	lfsr17 = LFSR(17, key >> 24, False)
	lfsr25 = LFSR(25, key & 0xffffff, False)

	keystream1 = 0
	keystream2 = 0
	for i in range(40):
		keystream1 <<= 1
		keystream2 <<= 1
		keystream1 |= lfsr17.clock()
		keystream2 |= lfsr25.clock()

	if __debug__:
		print "LFSR17 output", hex(keystream1)
		print "LFSR25 output", hex(keystream2)

	keystream = keystream1 ^ keystream2
	keystream = int_to_bytes(keystream)
	ct = shuffle(int_to_bytes(key), keystream, pt)
	return ct

def encryptData(key, data):
	assert(key < 2**40)
	data = data.decode("hex")

	lfsr17 = LFSR(17, key >> 24, True)
	lfsr25 = LFSR(25, key & 0xffffff, False)

	keystream = 0
	for i in range(len(data) * 8):
		keystream <<= 1
		keystream |= lfsr17.clock() ^ lfsr25.clock()

	pt = int(data.encode("hex"), 16)
	ct = ("%x"%(pt ^ keystream)).rjust(len(data) * 2, "0")

	return ct

#key generation
keylen = 5
if __debug__:
	key = 0x1234567890
else:
	key = getRandomInteger(keylen * 8) & 0xfffffffff0

#secret step
if __debug__:
	print "##### challenge secret "#####
	print "key = 0x%010x"%key

keyHash = encryptKey(key)

if __debug__:
	print "keyHash =", keyHash
	print ""

print "####### given data #######"
print "pt =", pt
C = [0x31, 0x33, 0x33, 0x33, 0x37]
A = shuffle(C, keyHash, pt)
print "A =", A
print "C =", C
print "xorK =", reduce(lambda x,y:x^y, keyHash)

flag = flag[5:-1]						#removing CTF template. please make template again when submitting the flag.
flag = zlib.compress(flag)[2:-4]		#deompress: zlib.decompress(data, -zlib.MAX_WBITS)

print "enc = \"" + encryptData(key, flag.encode("hex")) + "\""
