# netscream Writeup

### Facebook 2019 - crypto 974 - 18 solves

> We discovered a mysterious constant associated with this encryption scheme. Can you figure out how to decrypt the file?

#### Understanding the system

Three files were given; [d](d), [enc](enc), and the [binary](bin). Our first goal is to reverse the binary, and find out why `d` and `enc` files were given. After some [reversing](bin.i64), I found out some several critical facts to solve this challenge. The facts are

1. Inspecting function `ECC_initialization()`, elliptic curve was initialized by [openssl function](https://www.openssl.org/docs/man1.1.0/man3/EC_GROUP_new_by_curve_name.html), `EC_GROUP_new_by_curve_name(415LL)`. The number `415` [indicates](http://wooya.me/tldextract-rs/src/openssl_sys/lib.rs.html#318) that the used curve is NID_X9_62_prime256v1 curve, which is also named as NIST P-256 curve or secp256r1. Its curve parameters(`a`, `b`, `p`, `G`) can be found [here](https://www.secg.org/SEC2-Ver-1.0.pdf) at page 16. Also, elliptic curve point `P` is initialized. All the parameters were parsed and stored [here](config.py).

2. Inspecting function `ECC_RNG()`, 240 bits(30 bytes) were generated and dumped, do some strange logic and dump 16 bits(2bytes) again. By these observation, and some googling, the function implements [Dual_EC_DRBG](https://en.wikipedia.org/wiki/Dual_EC_DRBG) which is a [PRNG](https://en.wikipedia.org/wiki/Pseudorandom_number_generator). It uses `G` and `P` to generate the output. The total 32 bytes are written to [enc](enc). The followings are the steps to generate RNG.
	- Initialize the PRNG with random seed `t` (initialized with urandom)
	- let `s` be the `x` coordinate of point `t * G`
	- let `r` be the `x` coordinate of point `s * P`
	- Publish 30 lowest bytes of `r`
	- Set `t` equal to `s` and it will be the new seed for generating random number


3. The PRNG generates next 32 bytes, using it as a AES key to encrypt flag(filename given as `argv[1]`) by [IGE block cipher mode](https://blog.susanka.eu/ige-block-cipher-mode/). The encryption result(32 bytes) is written to [enc](enc), resulting 64 bytes as the final filesize.

My goal is to recover internal state of the given PRNG, based on the knowledge of fragmented (30 + 2) byte state, which was dumped to the first 32 bytes of [enc](enc) at fact2. By knowing the previous state, I directly recover AES key, and decrypt the flag using the encrypted result, stored to the last 32 byes of [enc](enc).

#### Vulnerability: Dual_EC_DRBG is a Backdoored PRNG!!!

The backdoor `d` was given to recover the internal state of PRNG, which was stored at [d](d). The backdoor must satisfy `G == d * P`. Section 2 of this [paper](http://dualec.org/DualECTLS.pdf) introduces the attack theory. I know the 30 lowest bytes of `x` coordinate of `s * P`. Bruteforce 2 bytes, obtain `y` coordinates(two of them!), and check whether the point is on the curve(which has complexity about `2 ** 17`). For the valid points, the attacker evaluates the next state(by using the equation `s * d * P == s * G`, since `t` becomes previous `s`) and compare the 2 highest bytes.

I successfully recovered the next state of PRNG, and recovered the key. By [decrypting](crypt.py)(src obtained from [here](https://github.com/Surye/telepy/blob/master/crypt.py)) the last 32 bytes of [enc](enc), I get the flag:

```
fb{dual_ec_is_not_a_good_prng_}
```

exploit driver code: [solve.sage](solve.sage)

Original binary: [bin](bin)

Original enc and d: [enc](enc), [d](d)

Reversing result: [bin.i64](bin.i64)

Parsed Parameters: [config.py](config.py)

Decryptor for IGE: [crypt.py](crypt.py)




