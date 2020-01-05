# Cryptography 01 Writeup

### WhiteHat Grand Prix 06 Quals 2020 - crypto 200

#### Observations

Our goal is to submit `key` to get flag. By interacting(encrypting arbitrary printable strings), the system is simply pseudo-substitution cipher.(Almost same setting with problem [ISITDTU CTF 2019 Chaos](https://github.com/pcw109550/write-up/tree/master/2019/ISITDTU/Chaos)) Let `enckey` be the given ciphertext, and `key` be the plaintext. Pattern for decryption is obtained simply by observations, which is stated below.

1. Length of encrypted block indicates particular charset. Block length 16 be digits, 22 be alphabet, 28 be punctuations.
2. Some part of ciphertext block only depends on the index of char in plaintext and the char itself.

By constructing mapping table based on the observations, I got the flag. The mapping is not perfect, so I tried several times to decode `enckey`. By sending `key` to server, profit.

```
Hav3_y0u_had_4_h3adach3_4ga1n??_Forgive_me!^^
```

Exploit code: [solve.py](solve.py)
