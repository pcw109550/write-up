# One Line Crypto Writeup

### Crypto CTF 2020 - Crypto 142 - 30 solves

> A [profile](one_line_crypto_cae0eabdac83be6254daa5683a39c441d3c48aa8.txz), a look, a voice, can capture a heart ♥ in no time at all.

#### Encryption logic

Plain textbook RSA, which prime generation logic is exposed and seems weak. All prime has form `x ** (m + 1) - (x + 1) ** m`

#### Exploit

I can assume the public modulus' size is almost same with ciphertext. 
Bit length of ciphertext: `2047` so I can deduce that prime sizes are bigger than `2 ** 1020`.

By iterating `x` and `m` for 5 minutes to generate primes using upper filtering condition, I could gather primes which are candidates of primes used in encryption. Try few prime pairs to decrypt ciphertext. 

I get flag:

```
CCTF{0N3_1!nE_CrYp7O_iN_202O}
```

Exploit code: [solve.sage](solve.sage) with [config.py](config.py)