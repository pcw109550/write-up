# Complex to Hell Writeup

### Crypto CTF 2020 - Crypto 285 - 11 solves

> I Already Know I'm Going to [Hell](./complex_to_hell_e5f781f7dc1fb5f010a31d92547feb21a6f28fa5.txz)

> At This Point, It's Really Go Big Or Go Home!

#### Encryption logic

Flag is encoded using `plain_to_matrix()` function, stored by `2 * n` matrix. Then it is left multiplied to `2 * 2` key matrix. Every matrix elements are complex numbers, each real and complex parts are in range of `66 = len(mapstr)`

#### Exploit

I can bruteforce key matrix row by row. Each row has key space `66 ** 4 ~= 2 ** 25` so feasible. We need flag oracle for choose the real decrypted flag.

1. 1st row: `[key11, key12]`
    - Guessed that flag must start with string `CCTF`.
    - `key11 = 18 + 25j, key12 = 34 + 14j`
    - Recovered partial flag: `CCTF{This_0n3_Is_State_0f_th3_4rt_`
2. 2nd row: `[key21, key22]`
    - It was so tricky to find the correct plaintext.
    - I scrutinized `plain_to_matrix()` function. It seemed to add zero valued elements for padding. 
    - Guessed that flag ends with `000`.
    - `key21 = 39 + 19j, key22 = 34 + 19j`
    - Recovered partial flag with padding: `and_C0mplex_is_Truly_compl3x!!}00`

Total Complexity: `O(2 * 2 ** 25) = O(2 ** 26)`. Concat two plaintext chunks and rstrip zero padding.

I get flag:

```
CCTF{This_0n3_Is_State_0f_th3_4rt_and_C0mplex_is_Truly_compl3x!!}
```

Exploit code: [solve.py](solve.py) with [config.py](config.py)