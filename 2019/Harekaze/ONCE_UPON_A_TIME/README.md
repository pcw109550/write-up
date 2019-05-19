# ONCE UPON A TIME Writeup

### Harekaze 2019 - crypto 100

A simple [Hill cipher](https://en.wikipedia.org/wiki/Hill_cipher) with some randomness and padding. Calculate the inverse of `m2` over integer mod ring over `251`, and multiply with ciphertext. Since matrix multiplication is not commutative, we check two cases: `inverse * ciphertext` or `ciphertext * inverse`. We may check the sanity of plaintext by checking the padding and printability(flag must be containing only printables).

Parse [result.txt](result.txt) and decode it.

The flag is:

```
HarekazeCTF{Op3n_y0ur_3y3s_1ook_up_t0_th3_ski3s_4nd_s33}
```

Full exploit code: [solve.sage](solve.sage)

Original problem: [problem.py](problem.py)

Output: [result.txt](result.txt)