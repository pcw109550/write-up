# Three Ravens Writeup

### Crypto CTF 2020 - Crypto 90 - 52 solves

> There were [three](./three_ravens_6779f709c7700ec542f26dcecbc8d23e6f6d7044.txz) ravens sat on a tree, Downe a downe, hay downe, a downe, They were as black as they might be.

#### Encryption Logic

Multiprime rsa using 512 bit primes `p`, `q`, `r`, `p + q + r`, using public exponent `e = 0x10001` and public modulus `N = p * q * r * (p + q + r)`. `N` and `p + q + r` was given

#### Exploit

Use public modulus as `p + q + r`. I can derive private key `d` since `p + q + r` is prime: `d = inverse_mod(e, p + q + r - 1)`. Luckily this works because message size is lower than size of `p + q + r`.

I get flag:

```
CCTF{tH3_thr3E_r4V3n5_ThRe3_cR0w5}
```

Exploit code: [solve.sage](solve.sage) with [config.py](config.py)