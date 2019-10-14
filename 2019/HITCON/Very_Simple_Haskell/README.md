# Very Simple Haskell Writeup

### HITCON 2019 - crypto 200 - 64 solved

> It can't be easier. [very_simple_haskell-787b99eed31be779ccfb7bd4f78b280387c173c4.tar.gz](very_simple_haskell-787b99eed31be779ccfb7bd4f78b280387c173c4.tar.gz)

#### Porting to python from haskell

Python code is more readable and easier to observe the intermediate values, I decided to port the given [haskell code](prob.hs) to [python code](solve.py).

#### Decrypting Naccache-Stern Knapsack problem

After some searching based on the ported code, I found that the given system is [Naccache-Stern Knapsack Cryptosystem](https://en.wikipedia.org/wiki/Naccache%E2%80%93Stern_knapsack_cryptosystem). I searched with the keyword `knapsack` and `prime` because the cryptosystem was similar with [original knapsack cryptosystem](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem).

Detailed decryption of the cryptosystem is given [here](https://eprint.iacr.org/2017/421.pdf). The haskell implementation uses the secret key `s = 1`(the system directly multiplies primes for evaluating ciphertext over modulo `n`), directly leading to decryption of ciphertext.

By knowing the length of flag, plaintext is divided into three chunks of list containing 131 bits. The first and last plaintext chunk is known, using the prefix `"the flag is hitcon{"` and length of plaintext. By decrypting the last chunk and encrypting the first chunk, we can decrypt the second chunk and get the flag. First calculate the encrypted result of second chunk, and simply decrypt it since knowing `s`. I get the flag:

```
hitcon{v@!>A#}
```

Ported code + Full exploit code: [solve.py](solve.py)

Original problem: [prob.hs](prob.hs)

Output: [output](output)