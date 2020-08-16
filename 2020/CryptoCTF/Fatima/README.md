# Fatima Writeup

### Crypto CTF 2020 - Crypto 316 - 9 solves

> I think we should all learn elliptic curves and [fatima](./fatima_6b3793a65ef501ea52e9993d25bc20f2647e131f.txz) is a good start, enjoy!

#### Encryption logic

1. `c2p()`: Flag's each byte is mutiplied to point `G` on elliptic curve, and generate new point `C`. Point's x,y coordinates are bit encoded and concatenated, producing bin string having length of 16. All generated bin strings are concatenated to make single bin string.
2. `enmat()`: Bin string is divided every `l=3` bits, and decoded to make a matrix.
3. `dict_traversal`: random permutation(`shuffle(range(1, 6)))`) is generated. `1: spiral`, `2: revspiral`,	`3: sinwaveform`, `4: helical`, `5: revhelical` is applied to the matrix following permutation order.
4. `CAL`: Matrix is multiplied to `CAL` matrix, which is some circulant matrix.
5. We get the final matrix.

#### Exploit

I must write inverse function of encryption logic.

1. `p2c()`: Inverse of `c2p()`. Brute to solve DLP since there are only 256 candidates.
2. `decmat()`: Inverse of `decmat()`
3. `dict_traversal`: I wrote corresponding inverse functions: `1: spiral_rev`, `2: revspiral_rev`,	`3: sinwaveform_rev`, `4: helical_rev`, `5: revhelical_rev`. The number of permutation is `5! = 120`, so feasible to brute.
4. `CAL`: Circulant matrix `C` is generated based on row(`([0 for i in range(len(B)-1)] + [1]`). After that, it is somewhat multipled few times by itself. There are only `100 = len(B)` candidates for `CAL` which are cyclic permutations because of the property of [circulant matrix](https://en.wikipedia.org/wiki/Circulant_matrix).

Writing the inverse functions were tedious. Total Complexity: `O(100 * 5! * 256 * len(flag)) = O(2 ** 28)` so feasible.

I get flag:

```
CCTF{Elliptic_Curv3_1s_fun_&_simpLE_Circulaitng_it_make_it_funnier!!}
```

Exploit code: [solve.py](solve.py) with [config.py](config.py)