# GolanG_Heights Writeup

### Affinity 2019 - crypto 350 - 29 solves

> Note: put flag into AFFCTF{} format

#### Observations and getting the flag

After observing the given [go script](golang_heights.go), I immediately realize the algorithm for generating `pub`. The flag is encrypted by [rabin cryptosytem](https://en.wikipedia.org/wiki/Rabin_cryptosystem), so factoring the public key `pub` leads to decryption of the [flag](flag.txt).

The algorithm of generating public key `pub` is ported as the following python code.

```python
p = 4 * B ** 2 + 3 * B + 7351
q = 19 * B ** 2 + 18 * B + 1379
pub = p * q
```

Ask sage to solve the equation to find integer `B`.

```sage
out = solve([p * q == Integer(pubkey)], B)
B = int(out[3].rhs())
p = int(p.subs(B=B))
q = int(q.subs(B=B))
```

Integer `B` is recovered, and we get the value of `p` and `q`, which is the factor of `pub`. Decrypt flag by applying modular sqrt algorithm and chinese remainder theorem. I get the flag.

```
AFFCTF{##just!c3_just!c3_y0u_sh@ll_pursu3_##_d3m@nd__p3@c3__@nd__pursu3__!t##}
```

exploit driver code: [solve.sage](solve.sage)

constants: [config.py](config,py)

Original problem: [golang_heights.go](golang_heights.go), [flag.txt](flag.txt)

Modular sqrt algorithm: [modular_sqrt.py](modular_sqrt.py)
