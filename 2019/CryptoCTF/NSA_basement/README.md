# NSA basement Writeup

### CryptoCTF 2019 - crypto 314 - 4 solves

> Our agents have gathered too many [public keys](https://cryp.toc.tf/tasks/stuff_73ada86861bb1773151df868dafb230ae09807f5.txz) that all of them were used to encrypt the secret flag. Can you decrypt the flag with a performant approach?

Solved after the CTF was ended.

#### Understanding the settings and factoring public key `n`

15933 [RSA public keys](keys) in PEM format and 15933 [encrypted flag](enc) was given. As the description says, all the plaintext must be the flag. If public modulus `n` is factored, we can decrypt and get the plaintext flag.

Bunch of RSA public keys were given, so I immediately calculated [gcd](https://en.wikipedia.org/wiki/Greatest_common_divisor) between different public modulus `n`. After calculating the gcd of public modulus `n` of file [pubkey_00000.pem](keys/pubkey_00000.pem) with other public keys, I got five `256` bit prime factors of `n`. `n` had bit length of `2048`, so all I need to do is to factor out the remaining `(2048 - 256 * 5) = 768` bits.

Luckily, the remaining `768` bit was prime! So I have completely factored out public modulus `n`. By calculating modular inverse over `phin`, I recoverd the private key `d`.

#### Decryption by PKCS1_OAEP with multiprime settings

I first assumed that the encryption scheme was plain textbook RSA, but immediately found out it was wrong, observing the unprintable results.

I tried to construct private RSA key using [Pycryptodome](https://pycryptodome.readthedocs.io/)'s [OAEP](https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html) implementation, but It kept failing. I guess the problem was triggered because of the multiprime settings. Pycryptodome kept failing when generating the private key.

To fix the problem, I read the [implementation](https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/PublicKey/RSA.py) of `Crypto.PublicKey.RSA` and `Crypto.Cipher.PKCS1_OAEP`. Private key generation was failing because it was trying to recover `p` and `q` from `d` on multiprime settings. In order to bypass this situation, I made a custom `Key` class as shown below.

```python
class Key:
    # Emulate pycryptodome's private RSA key
    def __init__(self, n, e, d):
        self.n = n
        self.e = e
        self.d = d

    def _decrypt(self, ciphertext):
        result = pow(ciphertext, self.d, self.n)
        return result
```

The upper code partially emulates Pycryptodome's RSA key class. Now I create class `Key` by using the values `n`, `e = 65537`, and `d`.

```python
key = Key(n, e, d)
cipher = PKCS1_OAEP.new(key)
flag = cipher.decrypt(enc)
```

Thanks for the great implementation by Pycryptodome, I get the flag:
```
CCTF{RSA_w17H_bAl4nc3d_1nC0mple73_bl0ck__d35igN__BIBD____}
```

exploit driver code: [solve.sage](solve.sage)

given parameters: [enc](enc), [keys](keys)
