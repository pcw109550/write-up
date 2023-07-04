# De-Identification Writeup

## CCE 2023 - crypto 451 - 3 solves

> Here are the special features of the cipher. Can decrypt it?

> `( len(P) == len(C) and type(P) == type(C) ) is True`

> This cipher uses the Feistel structure like Data Encryption Standard! But, the security level is similar to Advanced Encryption Standard.

> `nc 20.196.206.255 18080`

### Recon

There is no source code provided. If I connect to server, I get below response and get almost immediate timeout.

```
C: o8dix9txcy1gbozj93c86qfu3svhy9a1
Key: 4062C906651A331B5E0F80480D2614CA
Tweak: 06651A331B5E0F80
decrypt:
Time Out!
```

It seems obvious that I need to _guess_ the cipher suite because I received the `Key`.

According to the description, the length of plaintext and ciphertext is equal, and its type is also identical. 

### Guess The Scheme

The most helpful keyword while guessing is that the type of plaintext and ciphertext is equal. I guess that it is related with [format-preserving encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption). Citing the wikipedia:

> In cryptography, format-preserving encryption (FPE), refers to encrypting in such a way that the output (the ciphertext) is in the same format as the input (the plaintext).

The stdout gave us `Tweak` value. Now its time to google to find a ciphersuite which has format-preserving property, and be tweakable. If I google by `format preserving encryption tweak`, it shows [FF3](https://csrc.nist.gov/news/2017/recent-cryptanalysis-of-ff3) and other schemes like FF1. 

Since this is a guess challenge, lets try each cipher scheme(FF3, FF1 etc) one by one. Is there a python implementation for FF3? [Yes it is](https://github.com/mysto/python-fpe)! `pip3 install ff3`.

Lets skim threw the code example of `ff3` pip module.

```python
from ff3 import FF3Cipher

key = "2DE79D232DF5585D68CE47882AE256D6"
tweak = "CBD09280979564"
c = FF3Cipher(key, tweak)

plaintext = "3992520240"
ciphertext = c.encrypt(plaintext)
decrypted = c.decrypt(ciphertext)

print(f"{plaintext} -> {ciphertext} -> {decrypted}")

# format encrypted value
ccn = f"{ciphertext[:4]} {ciphertext[4:8]} {ciphertext[8:12]} {ciphertext[12:]}"
print(f"Encrypted CCN value with formatting: {ccn}")
```

It really seems that I have guessed right. However, If I try the example script directly, I could not get flag. I compared ciphertext from the example with the chall's ciphertext. 

The challenge ciphertext consists of digits and lowercase ascii. By reading the docs, I found that using custom alphabet is possible, using `FF3Cipher.withCustomAlphabet` method. Let me guess again,

```python
charset = string.digits + string.ascii_lowercase
cipher = FF3Cipher.withCustomAlphabet(Key.hex(), Tweak.hex(), charset)
pt = cipher.decrypt(C)
tn.sendline(pt.encode())
```

Guess correct 😏, I get flag: 

```
cce2023{SAMPLE_FLAG}
```

guess driver code: [solve.py](solve.py) requiring [requirements.txt](requirements.txt)
