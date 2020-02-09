# SecureLinearFunctionEvaluation Writeup

### nullcon HackIM 2020 - crypto 419

> In this challenge we provide a sytem that calculates a * x + c in F_2^128 , where a and b are server supplied and x is client supplied. To get the flag you have to find a and b. Server runs at: `nc crypto2.ctf.nullcon.net 5000`

#### Observations

My goal is to recover `a` and `b`, which is list containing random 128 bits. I am allowed to supply `g`, `y0`, `y1` to obtain `c0`, `c1`, which has information about `a` and `b`. I must derive `a` and `b` by using and satisfying below constraints.

```python
y0 * y1 == cs[i] (mod p)
m0 == b[i]
m1 == (a[i] + b[i]) % 2
c0 == (pow(g, r0, p), int(sha256(long_to_bytes(pow(y0, r0, p))).hexdigest(), 16) ^ m0)
c1 == (pow(g, r1, p), int(sha256(long_to_bytes(pow(y1, r1, p))).hexdigest(), 16) ^ m1)
```

Since `a[i]` and `b[i]` are bits, `(a[i] + b[i]) % 2` is equivalent to `a[i] ^ b[i]`. By using the property of xor and selecting values of `y0`, `y1` and `g` well, I can derive `a` and `b`.

#### Exploit

Let `g = cs[i]`, `y0 = 1`, `y1 = cs[i]`. This satisfies contraint `y0 * y1 == cs[i] (mod p)`. Now plug in the values to constraints. We know the value of `c0 = (c00, c01)` and `c1 = (c10, c11)`. By using those values, I could successfully obtain values of `a[i]` and `b[i]`.

```python
(c00, c01) == (pow(cs[i], r0, p), int(sha256(long_to_bytes(1.hexdigest(), 16) ^ a[i])
(c10, c11) == (pow(cs[i], r1, p), int(sha256(long_to_bytes(pow(cs[i], r1, p))).hexdigest(), 16) ^ a[i] ^ b[i])
a[i] == c01 ^ int(sha256(long_to_bytes(1.hexdigest(), 16)
b[i] == c11 ^ int(sha256(long_to_bytes(c10).hexdigest(), 16) ^ a[i]
```

Derive `a` and `b` using upper equations and get the flag:
```
hackim20{this_was_the_most_fun_way_to_include_curveball_that_i_could_find}
```

Exploit code: [solve.py](solve.py)

Original problem: [lfe.py](lfe.py), [secret.py](secret.py)


