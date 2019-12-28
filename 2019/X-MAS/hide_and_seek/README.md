# hide and seek Writeup

### Christmas CTF 2019 - crypto 1000 - 2 solves

> Hide & Seek.

#### Observation and exploit plan

Flag is encrypted with plain RSA scheme, public modulus `n = p * q`. I have `dim` modulo linear constraints related with `1024 - 300 = 724` MSBs of prime `p`, denoted as `guess`. `n` can be factored by following the below stages.

1. Recover `guess`(which is `1024 - 300 = 724` bits) by solving hidden number problem
	- Exact same setting with [biased nonce attack on DSA](https://eprint.iacr.org/2019/023.pdf)
	- Embedding information of bit length of `guess` is required
2. Apply Coppersmith's attack and factor `n`
	- I know 724 MSBs of `p` from A
	- Recovering `p` and `q` is [feasible](https://www.iacr.org/archive/crypto2003/27290027/27290027.pdf) since bit length of `guess` is longer than half of `p`
	- Construct polynomial `f` over `Zmod(p)` and recover `p`
3. Recover private key `d`
	- Trivial because factors already known

#### Constructing lattice to solve hidden number problem

Let `t_{i}`s be the random number generated, and `u_{i}`s be the output of method `next`, where `i` in `1` to `dim`. Let `b_{i}` be the masked out part of `guess * t_{i}` and `k_{i}` be some arbitrary integer, The following modulo constraint is satisfied.

`guess * t_{i} = u_{i} + b_{i} (mod field)`

`guess * t_{i} = b_{i} + b_{i} + field * k_{i}`

Let me observe the bit length of each term. `t_{i}` and `u_{i}` has size of `800` bit value, guess is `724`, and `b_{i}` is `761`. I will construct lattice `M` for cracking [DSA on biased nonce](https://eprint.iacr.org/2019/023.pdf), and add extra column(last column of `M`) for embedding the information of bit length of `guess`. Let `B = 2 ** 761`, `C = 2 ** 52`. `B` is the suppression term of `b_{i}`s, and `C` the suppression term for `guess`.

```python
M = Matrix([
	[  field,      0,      0,   ..  ,      0,      0,      0,      0], # k_{1}
    [      0,  field,      0,   ..  ,      0,      0,      0,      0], # k_{2}
    [      0,      0,  field,   ..  ,      0,      0,      0,      0], # k_{3}
    [   :   ,   :   ,   :   ,       ,   :   ,   :   ,   :   ,   :   ], #  :
    [      0,      0,      0,      0,  field,      0,      0,      0], # k_{dim}
	[  t_{1},  t_{2},  t_{3},   ..  ,t_{dim},B/field,      0,      C], # guess
    [  u_{1},  u_{2},  u_{3},   ..  ,u_{dim},      0,      B,      0]  # 1
#--->  b_{1}   b_{2}   b_{3}    ..   b_{dim} B*guess/field B
])
```

Apply LLL to find `guess`, extracting rows of matrix. Sanity check of recovered `guess` is done by checking the previously used linear constraints.

#### Coppersmith's attack and profit

Since `guess` is known, let me apply Coppersmith's attack to recover `p`. Construct polynomial over `Zmod(n)` and solve to get small roots. Sanity check is done by simply checking the divisibility of `n` over `p`. Below code does the job.

```python
F.<x> = PolynomialRing(Zmod(n))
f = (guess << 300) + x
x0 = f.small_roots(X=(2 ** 300), beta=0.44, epsilon=1/32)
p = int((guess << 300) + x0[0])
```

By knowing factors of `n`, calculate private exponent `d` and get profit:

```
XMAS{hide_on_lattice}
```

exploit driver code: [solve.sage](solve.sage)

original challenge and parameters: [hide_and_seek.py](hide_and_seek.py), [output](output)

parameters: [config.py](config.py)


