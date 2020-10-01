# Baby Bubmi Writeup

### KAPO 2020 - Crypto 100 - 0 solves

> [Baby_Bumbi.zip](Baby_Bumbi.zip)

Solved after the CTF was ended.

#### Analysis

1. Generate `primes` which contains primes lesser than 100. 
2. Initialize python's random seed by `flag[5:9]`.
3. Shuffle `primes` list.
4. Generate `keys` list which having same length with `flag`, by using `ln` function for elements in `primes`.
5. Evaluate subset sum by using chset of flag:
  ```python
  sum_ = Decimal(0.0)
  for i, c in enumerate(flag):
      sum_ += c * Decimal(keys[i])
  ```
6. Return `ct = math.floor(sum_ * 2 ** 256)`.

#### Extension of Knapsack cipher

Given system is generalization of 0-1 knapsack problem. Coefficients lie in range of 0 to 128, which is the range of ascii codes of printables. Scale up `keys` by `2 ** 256` because `ct` is calculated by scaling `sum_` by `2 ** 256`. `keys` will be the public key of [knapsack cryptosystem](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem). `ct` will be the ciphertext. I must solve the subset sum problem to find out coefficients, which is ascii value of flag chars.

There are multiple ways to solve knapsack cipher. One of the most powerful attack is [low density attack](https://link.springer.com/article/10.1007/s10623-007-9058-5). Apply CJLOSS algorithm which works on knapsacks having relatively high density. The only difference is the target vector. In original 0-1 knapsack case, I need to use target vector of the form `(1/2, 1/2, .. , 1/2, ct)`. Now coefficents have scaled up to range of 256, range of ascii values! Therefore modify target vector to `(128, 128, .. , 128, ct)`.

Final matrix structure:

```python
M = Matrix([
 [1, 0, 0, .. , 0, 0, 0, keys[0]],
 [0, 1, 0, .. , 0, 0, 0, keys[1]],
 [0, 0, 1, .. , 0, 0, 0, keys[2]],
 [:, :, :,  0 , :, :, :,    :   ],
 [0, 0, 0, .. , 1, 0, 0, keys[n - 3]],
 [0, 0, 0, .. , 0, 1, 0, keys[n - 2]],
 [0, 0, 0, .. , 0, 0, 1, keys[n - 1]],
 [128, 128, 128,.., 128, ct]
])
```

After running LLL and examining rows, I get following row:
```python
(31, 128, 26, 77, 27, 18, 3, 14, 77, 128, 79, 20, 12, 18, 13, 33, 76, 128, 79, 13, 128, 25, 79, 5, 77)
```

Translating to printable char values, I get:
```
['a', '\x00', 'f', '3', 'e', 'n', '}', 'r', '3', '\x00', '1', 'l', 't', 'n', 's', '_', '4', '\x00', '1', 's', '\x00', 'g', '1', '{', '3']
```

I see some correct flag chars: `flag{`. Its time to find the correct permutation. There are printable 21 chars, total `21 choose 4` possibilities for initial seed. Iterate all seed candidates to find the correct seed. After finding correct seed, simply reverse permuted result and get flag:

```
flag{r341_e1s3nst13n}
```

Exploit code: [solve.sage](solve.sage)
