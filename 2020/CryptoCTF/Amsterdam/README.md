# Amsterdam Writeup

### Crypto CTF 2020 - Crypto 55 - 96 solves

> Is it normal to have such [encoding](./amsterdam_9e529fa12c74f176f23ca19ea4d9aa5fe2e98e6e.txz)?

#### Encryption logic

Flag was encoded to bit contained list, and encoded again by adding binomai coefficients. 

#### Exploit

Write `decode()` function which simply reverses encryption logic. Used sage for faster calculation of binomials.

I get flag:

```
CCTF{With_Re3p3ct_for_Sch4lkwijk_dec3nt_Encoding!}
```

Exploit code: [solve.sage](solve.sage) with [config.py](config.py)