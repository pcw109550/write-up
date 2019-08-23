def encrypt(m):
      return pow(m,2,n)

p = 5411451825594838998340467286736301586172550389366579819551237
q = 5190863621109915362542582192103708448607732254433829935869841

n = p*q

flag = int('d4rk{*************REDACTED!!!!!!************}code'.encode('hex'),16)

l = encrypt(flag)
while  l > flag:
      l = encrypt(l)
print l
