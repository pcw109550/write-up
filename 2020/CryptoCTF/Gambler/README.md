# Gambler Writeup

### Crypto CTF 2020 - Crypto 85 - 55 solves

> Gamble as an ancient Philossepher!

> `nc 05.cr.yp.toc.tf 33371`

Solved after the CTF was ended.

#### Encryption logic

Encryption function:

```python
def encrypt(m):
    assert m < p and isPrime(p)
    return (m ** 3 + a * m + b) % p
```

I know result of `encrypt(flag)` and have encryption oracle.

#### Exploit

First thing first. Get values of coefficients and prime.

1. `b`
    - `encrypt(0) = 0 ** 3 + a * 0 + b = b`
2. `a`
    - `encrypt(1) = 1 ** 3 + a * 1 + b`
    - `encrypt(1) - b - 1 = a`
3. `p`
    - Choose some big values `d1`, `d2`, almost having same size with `enc(flag)`.
    - `e1 = d1 ** 3 + a * d1 * b - encrypt(d1)`
    - `e2 = d2 ** 3 + a * d2 * b - encrypt(d2)`
    - `p = gcd(e1, e2)` for high probabilty.

Now solve cubic equation over polynomial ring. Use sage's powerful [`roots()`](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_element.html#sage.rings.polynomial.polynomial_element.Polynomial.roots) method.

```python
F.<x> = PolynomialRing(Zmod(p))
f = x ^ 3 + a * x + b - ct
sols = f.roots()
```

Test all solutions to get flag.

I get flag:

```
CCTF{__Gerolamo__Cardano_4N_itaLi4N_p0lYma7H}
```

Exploit code: 

- Server interaction: [solve.py](solve.py)
- Root calculation: [solve.sage](solve.sage)