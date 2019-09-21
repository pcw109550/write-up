# Lenstra-Lenstra-Lovász Writeup

### KAPO 2019 - crypto 1 - 2 solves

> I am not good at Linear Algebra : (
Can you tell me about Lenstra-Lenstra-Lovász lattice basis reduction algorithm?
Add) e=151. This is for make challenge easy.

#### Analysis of the condition

The flag was encrypted by textbook RSA. Factors `p`, `q` had size of 1024 bits. Public exponent `e = 151` was also given. Let `dp = d % (p - 1)`, which is helpful for [efficiently encrypting/decrypting](https://www.techscience.com/doi/10.3970/icces.2008.005.255.pdf#targetText=Chinese%20Remainder%20Theorem%20in%20RSA%2DCRT&targetText=It%20results%20in%20a%20decryption,system%20can%20be%20totally%20broken.) RSA cryptosystem. Let `bits` be the bitlength of `dp`. The upper bits of `dp` was leaked(upper consecutive bits of length `bits - bits // 2 - bits // 10`).

Being inspired from [this great challenge](https://github.com/p4-team/ctf/tree/master/2019-09-02-tokyowesterns/happy), I will first try to recover the value of `dp` by using [Coppersmith's attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack). After recovering `dp`, it is [very easy](https://medium.com/@nicebowlofsoup/picoctf-2017-weirderrsa-writeup-194b30cb3316) to recover `p`(just bruteforce `e` times).

#### Application of Coppersmith's attack to recover `dp`

Designing appropriate monic polynomial is crucial for applying Coppersmith's attack. Let me derive the polynomial `f(x)`. I first start with relation between `e` and `d`. There exists integer `k` which satisfies the following equation. Let `a` and `b` be the quotient and remainder of the result of `d` divided by `p - 1`. Of course, `b = dp`.

```python
e * d == 1 (mod (p - 1) * (q - 1))
k * (p - 1) * (q - 1) + 1 == e * d
k * (p - 1) * (q - 1) + 1 == e * (a * (p - 1) + dp)
```

Next, divide the both side of equation by `p - 1`. There exists integer `k_` which satisfies the following equation.

```python
1 == e * dp (mod p - 1)
k_ * (p - 1) + 1 == e * dp
```

`dp` is the remainder when `d` is divided by `p - 1`. Therefore `dp < p - 1`, by definition of remainder. `k_ * (p - 1) + 1 == e * dp`, so `k_ < e`. Divide the both side of equation by `p`.

```python
- k_ + 1 == e * dp (mod p)
0 == e * dp + k_ - 1 (mod p)
```

Let `unknownbits = bits // 2 - bits // 10` be the number of unknown bits of `dp`. Let `x` be the unknown information of `dp`. `dp == (secret << unknownbits) + x` by the definitions. Plug in to the equation and derive the polynomial defined over modulo `p`.

```python
g(x) == 0 == e * ((secret << unknownbits) + x) + k_ - 1 (mod p)
```

Let me make `g(x)` monic. Although sage has method `monic()` to do the job, I just muliplied `einv = inverse_mod(e, n)`. I finally get the polynomial `f(x)` for applying Coppersmith's attack.

```python
f(x) == 0 == (secret << unknownbits) + x + einv * (k_ - 1) (mod n)
```

The value of `k_` can be varied from `1` to `e = 151`. Also I do not know the value of `bits` exactly. I assume `bits` is in `1019` to `1024` by observation(running the original challenge). Bruteforce by changing values of `k_` and `bits` and apply `small_roots()` method. Tweak parameters `beta` and `epsilon` for optimization. I set `epsilon = 1/32` for faster iteration and low precision. The whole process was implemented in `recover()` function.

#### Recovering `p` from `dp`

While running the script, I noticed some several small roots for different `k_` and `bits`. I tried to recover `p` from candidate value of `dp`. Because `dp < p - 1`, `t < e` from equation `dp * e = t * (p - 1) + 1`. Try all possible values of `t`(possible since `e` is small) and derive `p`. If the algorithm(`factorize()` method) fails, this means I have an incorrect `dp`.

When `k_ = 130` and `bits = 1023`, I could recover `dp` and `p`. Since factor of `n` is known, I simply decrypt ciphertext and get the flag:

```
POKA{You_4r3_Crypt0_N00000B_XDD}
```

exploit driver code: [solve.sage](solve.sage)

original challenge and parameters: [Lenstra-Lenstra-Lovasz.sage](Lenstra-Lenstra-Lovasz.sage), [enc.txt](enc.txt)

parameters: [config.py](config.py)


