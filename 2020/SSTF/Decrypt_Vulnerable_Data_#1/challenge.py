from Crypto.Util.number import getRandomInteger
from secret import flag

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

def decryptData(key, ct):
	return encryptData(key, ct)

disc_data = "The flag is: %s"%flag

keylen = 5
key = getRandomInteger(keylen * 8)

ct = encryptData(key, disc_data.encode("hex"))
assert(decryptData(key, ct).decode("hex") == disc_data)

with open("enc_data.txt", "w") as f:
	f.write(ct)
