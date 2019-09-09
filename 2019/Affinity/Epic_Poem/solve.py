from Crypto.Util.strxor import strxor

f1 = open("enc1")
enc1 = f1.read()
f2 = open("enc2")
enc2 = f2.read()

alt = "AFFCTF{M4"

test = "Lithuania"
# print(strxor(test, enc2[:len(test)]))
# print(strxor(alt, enc2[:len(alt)]))
# print(strxor(alt, enc1[:len(alt)]))

# Search Litwo! in google
test2 = "Litwo! Ojczyzno moja! Ty jestes j"
flag = strxor(test2, enc1[:len(test2)])

assert flag == "AFFCTF{M4nY_t1m3_PaD_1$_b@d__!!!}"
print(flag)
