# count on me Writeup

### CSAW Quals 2019 - crypto 100 - 120 solves

> If you ever find yourself lost in the dark and you can't see, I'll be the light to guide you `	nc crypto.chal.csaw.io 1002`

#### Analysis of encryption scheme

The encryption process is done by the following five steps.

1. Initialize python random seed using my integer input(from `1` to `9999999999999999`).
2. String `"Encrypted Flag: "` with the length of `16` bytes is concated front to the flag `m`.
3. Data generated from 2. is cut into `16` byte chunks, padded with null byte.
4. Random `16` bytes is generated and encrypted using AES, and the encryption result is xored wth each chunk.
5. Step 2 to 4 is done 100 times, and the encryption result is given.kc

The length of the encryption result given by the server was `4900`, which means the resulting padded data has the length of `48` bytes because `4900 = (48 + 1) * 100`, where `1` byte came from newline. Each random `16` bytes is created by `random_bytes()` method, so the function must be called `100 * (48 / 16) == 300` times.

#### Choosing appropriate seed value and get the flag

To recover the flag, I deliberately chose the value of initial seed to satisfy the following conditions.

1. `random_bytes()` method must generate two identical random `16` byte blocks during 300 calls of it.
2. Two random `16` byte chunks from 1. must encrypt different plaintext chunks, while one must include  the first chunk which the value is known.

The upper conditions can be tested locally. I found the seed by implementing my function `findseed`. Let the two corresponding ciphertext chunks be `c1`, `c2` and plaintext chunks be `m1`,`m2`. Let `R` be the random `16` byte chunk which the value is same, by the first condition of the seed. I already know the value of `m1`(`"Encrypted Flag: "`) by the second condition of seed. I can recover `m2` by the following formula.

```python
c1 = m1 ^ AES(R)
c2 = m2 ^ AES(R)
m2 = c1 ^ c2 ^ m1
```

The value of `c1`, `c2`, `m1` is known, so simply recover `m2`. I have to recover `32` bytes excluding the known value `m1`. Find different seeds which generates same random outputs at `i`th and `j`th trial, where `i != j` and `i % 3 == 0`(to satisfy condition 2), `j % 3 == 1 or 2` to recover the left `48` bytes. Recover plaintext `m` and get the flag:

```
flag{U_c@n_coUn7_0n_m3_l1kE_123}
```

exploit driver code: [solve.py](solve.py)

server: [chal.py](chal.py)

server ported to local: [local.py](local.py)
