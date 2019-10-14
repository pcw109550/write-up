# Lost Modulus Again Writeup

### HITCON 2019 - crypto 200 - 64 solved

> It seems something wrong with my modulus. [lma-96272ceb426c53449452d3618953eeb4daf07b74.tar.gz](lma-96272ceb426c53449452d3618953eeb4daf07b74.tar.gz)

#### Analyzing the conditions

Flag is encrypted by textbook RSA scheme. Interestingly, public exponent `e` and private exponent `d`, `x = inverse_mod(q, p)`, `y = inverse_mod(p, q)` is given, not giving the public modulus `n` directly. Therefore, my goal is to calculate `n = p * q` by using the given conditions.

#### Deriving public modulus `n`

I can calculate the candidate values of `phi(n) = (p - 1) * (q - 1)` by using the following equation. By enumerating possible `k`s from `3` to `e - 1`, I obtained the candidates of `phi(n)`.

```python
e * d == 1 (mod phi(n))
e * d == k * phi(n) + 1 # for some nonnegative integer k
# Since d < phi(n), e > k >= 3
```

Let `k1`, `k2` be the nonnegative integer which satisfies the following equations.

```python
x, y == inverse_mod(q, p), inverse_mod(p, q)
q * x == 1 + k1 * p # x < p
p * y == 1 + k2 * q # y < q
```

By subtracting the two equations, I get `q * (x + k2) == p * (y + k1)`. `p` and `q` are coprime, so `q` must divide `y + k1` and `p` must divide `x + k2`. `0 < x + k2 < 2 * p` and `0 < y + k1 < 2 * q`, so `p = x + k2` and `q = y + k1`. Since `k1 = q - y`, `q * x = 1 + (q - y) * p` and finally get `x * y = 1 + k1 * k2`


Evaluate `phi(n)` by using the newly derived equations.

```python
phi(n) = (p - 1) * (q - 1)
       = (x + k2 - 1) * (y + k1 - 1)
       = (x - 1 + k2) * (y - 1 + k1)
       = (x - 1) * (y - 1) + (x - 1) * k1 + (y - 1) * k2 + k1 * k2
```

Now I make quadratic equation with respect to `k1`, by knowing the values of `x` and `y`.

```python
phi(n) = x * y - 1 + (y - 1) * (x * y - 1) / k1 + k1 * (x - 1) + (x - 1) * (y - 1)
# quadratic equation f(k1) = 0
(x - 1) * k1 ** 2 + (x * y - 1 - phi(n) + (x - 1) * (y - 1)) * k1 + (y - 1) * (x * y - 1) = 0
```

`k1` must be integer, so by traversing all the candidates of `phi(n)` and solving quadratic equations, I can distinguish the actual value of `phi(n)`, directly recovering `k1`, `k2`, `p`, `q` and `n`.

Now by knowing `n` and `d`, simply decrypt and get the flag:

```
hitcon{1t_is_50_easy_t0_find_th3_modulus_back@@!!@!@!@@!}
```

Full exploit code: [solve.py](solve.py)

Original problem: [prob.py](prob.py)

Output: [output](output)