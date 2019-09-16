# Fault Box Writeup

### CSAW Quals 2019 - crypto 400 - 108 solves

> who's fault?? `nc crypto.chal.csaw.io 1001`

#### Analysis of given system

`flag` and `fake_flag` is signed by textbook RSA. I have only two oracles to recover real flag since `cnt` variable is initially set to `2` and decremented after using the oracle. Public modulus `n` will be newly updated after two trials. Luckily, we can use RSA encryption oracle without decreasing `cnt`.

`TEST_CRT_encrypt()` method deliberately injects error while RSA signing, by XORing `fun` with intermediate values. I notice this is a classic [fault attack on RSA CRT](https://crypto.stackexchange.com/questions/63710/fault-attack-on-rsa-crt).

#### Steps for recovering information and getting the flag

I followed three steps to obtain the plaintext `flag`. Each step will be elaborated.

1. By using the encryption oracle, recover public modulus `n`.
2. Find fake flag and factor `n` by using faulty signed `fake_flag` value.
3. Derive private key `d` based on prime factors of `n` and get the `flag`.

Step 1: To recover `n`, I first signed message `msg1 = "\x02"`, `msg2 = "\x03"`, `msg3 = "\x04"`. Public exponent `e = 65537` is given. I can obtain `n` by using [gcd](https://en.wikipedia.org/wiki/Greatest_common_divisor), based on the fact of basic RSA encryption.

```python
msg1 = enc_msg("\x02")
msg2 = enc_msg("\x03")
msg3 = enc_msg("\x04")
n1 = gcd(pow(2, e) - msg1, pow(3, e) - msg2)
n2 = gcd(pow(3, e) - msg2, pow(4, e) - msg3)
```

If `n1 == n2` and `n1 % 2 == 1`, the value of `n1` is very likely to be `n`. If not, I can simply try again.

Step 2: After knowing the value of `n`, its time to recover `fake_flag` and `n`'s factor (`p`, `q`). `fake_flag` has interesting format: `fake_flag = "fake_flag{%s}" % (("%X" % base).rjust(32, "0"))`. I can simply bruteforce the value of `base` and recover `fake_flag` because of the following equations from method `TEST_CRT_encrypt()`. Let me denote the candidate `fake_flag` be `fake_flag_cand`.

```python
c1 = pow(fake_flag_cand, e, p)
c2 != pow(fake_flag_cand, e, q) ^ fun # fault injected!!!
c1 - pow(fake_flag_cand, e) = k1 * p
c2 - pow(fake_flag_cand, e) != k2 * p
=> c - pow(fake_flag_cand, e) = k * p
```

Therefore, If I calculate gcd of `c - pow(fake_flag_cand, e, n)` and `n`, and when its value is positive integer larger than `1`, then the gcd will be the factor `p`. `fake_flag_cand` will be the real `fake_flag`. Get the value `c = fake_flag_fault_enc` by calling method `TEST_CRT_encrypt()`(`cnt` becomes `1`). The factor can be justified by calculating remainder of `n` divided by `p` to be `0`. The process can be implemented by the below python script.

```python
while True:
    fake_flag_cand = "fake_flag{%s}" % (("%X" % base).rjust(32, "0"))
    p_cand = gcd((pow(s2n(fake_flag_cand), e, n) - fake_flag_fault_enc) % n, n)
    if p_cand != 1 and n % p_cand == 0:
        prime, q = p_cand, n / p_cand
        assert prime * q == n and is_prime(prime)
        break
    base += 1
```

Step 3: By knowing factors of `n`, I derive private key `d` and get the real `flag`. Ask server to get the value of encrypted real flag(`cnt` finally becomes `0`). I get the flag:

```
flag{ooo000_f4ul7y_4nd_pr3d1c74bl3_000ooo}
```

exploit driver code: [solve.py](solve.py)

server: [server.py](server.py)

server ported to local: [local.py](local.py)
