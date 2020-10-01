# Child Beubmi Writeup

### KAPO 2020 - Crypto 100 - 0 solves

> [Child_Beubmi.zip](Child_Beubmi.zip)

Solved after the CTF was ended.

#### Analysis

```
p = random_prime(2^512)
q = random_prime(2^512)

N = p * p * q
e = 0x10001

piN = p * (p-1) * (q-1)

d = inverse_mod(e, piN)
m = bytes_to_long(flag)

ct = pow(m, e, N)

assert pow(ct, d, N) == m

hint = (p * q) % 2^700
```

Factoring `N` is necessary to get flag. Let `N_ = p * q`. I know lower 700 lsbs of `N_`.

#### Application of Coppersmith Attack to recover `N_`

I can construct a polynomial over ring of integer modulo composite `N`.

```python
F.<x> = PolynomialRing(Zmod(N))
f = hint + x * (1 << 700)
```

My goal is to find a solution over ring of integer modulo composite `N_`, even though I do not know `N_`. [Coppersmith attack](https://www.math.uni-frankfurt.de/~dmst/teaching/WS2015/Vorlesung/Alex.May.pdf) works well in this case. `N_ >= N ^ beta`. `N_` has bit length 1024, and N has bit length 1536, so let `beta = 2 / 3`. Set `epsilon = beta * beta / 7`. Now I get solution over ring of integer modulo composite `N_`, which recovers `N_`.

```python
f = f.monic()
x0 = f.small_roots(X=2 ^ 324, beta=beta, epsilon=epsilon)
```

Sanity check:

```python
N_ = Integer(hint + x0[0] * (1 << 700))
assert N % N_ == 0
p = N // N_
q = N_ // p
assert p * p * q == N
```

I know factors `p` and `q`. Decrypt and get flag:

```
flag{Easy_Coppersmith_and_bivariate_heuuung...}
```

Exploit code: [solve.sage](solve.sage)

Can I solve by applying Coppersmith attack in the bivariate case, according to flag? Maybe solution using univariate case is unintended.