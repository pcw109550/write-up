# Epic Poem Writeup

### Affinity 2019 - crypto 500 - 25 solves

> Alicja sent text for her friend translator Bob. Because Alicja likes privacy, she encrypted text with key. Bob translate the text and sent back to her also in encrypted form. Can you find the key?

#### Guessing and getting the flag

Since the challenge asked to find the key, I first use the flag format. The flag starts with `AFFCTF{`. I guessed that the cryptosystem is just a simple xor cipher.

By xoring `AFFCTF{` with [enc2](enc2), I get some readable plaintext: `Litwo! `. I searched the plaintext in google, and guessed the further plaintext assuming the plaintext is from [here](https://pl.wikisource.org/wiki/Litwo,_Ojczyzno_moja!). Xor it back with [enc2](enc2) to get the key.

I get the flag:

```
AFFCTF{M4nY_t1m3_PaD_1$_b@d__!!!}
```

exploit driver code: [solve.py](solve.py)

Original problem: [enc1](enc1), [enc2](enc2)