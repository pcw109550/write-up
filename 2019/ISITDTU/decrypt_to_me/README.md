# decrypt to me Writeup

### ISITDTU Quals 2019 - crypto 395 - 42 solves

> decrypt to me?????

#### Observations

The seed of a given random number generator is the length of flag. By observing the code, length of ciphertext and plaintext are the same. Therefore I directly obtain the seed of [prng](https://en.wikipedia.org/wiki/Pseudorandom_number_generator) and decrypt(XORing ciphertext and random number output bit by bit) to get the flag. I get the flag:
```
ISITDTU{Encrypt_X0r_N0t_Us3_Pseud0_Rand0m_Generat0r!!!!!}
```

Given ciphertext: [config.py](config.py)

Encryption code: [task.py](task.py)

Exploit code: [solve.py](solve.py)
