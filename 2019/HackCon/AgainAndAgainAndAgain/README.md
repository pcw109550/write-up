# AgainAndAgainAndAgain Writeup

### HackCon 2019 - Crypto 467 - 30 solves

> Someone was thinking encrypting again and again helps, proving them wrong.

The flag was encrypted by [Rabin cryptosystem](https://en.wikipedia.org/wiki/Rabin_cryptosystem) for multiple times. Since the factor `p` and `q` were given, I directly apply [extended euclidean algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm) and [chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) to find the four candidates(`r`, `s`, `n - r`, `n - s`) of plaintext.

Obviously the actual flag must be printable. By using this criteria which the plaintext must satisfy, I performed a [breadth-first search](https://en.wikipedia.org/wiki/Breadth-first_search) to find the flag. Each stage generated four candidates of plaintext, so BFS implementation was necessary.

The modular sqrt algorithm is obtained from [here](https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python).

I get the flag:

```
d4rk{r3p3t1t1v3_r4b1n_1s_th4_w0rs7_3vaaaaaar!}code
```

Full exploit code: [solve.py](solve.py)

Original problem: [q1.py](q1.py)

Ciphertext: [config.py](config.py)

Modular sqrt algorithm: [modular_sqrt.py](modular_sqrt.py)