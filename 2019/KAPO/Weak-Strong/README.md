# Weak_Strong Writeup

### KAPO 2019 - crypto 1 - 1 solves (by KAIST)

> You have two choice- "Weak" and "Strong". What do you want? **Caution! Maybe "Strong" one will took 2 hours to get your treasure.**

#### Analysis of the condition

I first factorize `M_weak` and `M_strong` and inspected prime generating functions, `get_weak_prime()` and `get_strong_prime()`. Surprisingly, `M_weak` and `M_strong` had small factors(less than `200`). By googling with these conditions, I found out that prime generating function is vulnerable! The challenge asks me to apply [ROCA attack](https://acmccs.github.io/papers/p1631-nemecA.pdf) based on [Coppersmith's attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack).

#### Applying ROCA attack

While implementing the attack based on the [paper](https://acmccs.github.io/papers/p1631-nemecA.pdf), I was also parallelly searching the preimplemented scripts. Luckily, [this gitlab repository](https://gitlab.com/jix/neca), `neca` had the full implentation of the attack, and used in previous [ctf challenge](https://ctftime.org/writeup/8805).

Thanks to `neca`, I recovered factor `p` and `q` of `sn`(strong one with 512 bit). Here is the [output](output) from `neca`, which took 102 seconds to recover the factors. Since factors of `n` are known, I simply decrypt ciphertext and get the flag:

```
POKA{ROCA_POKA_Return_Of_Coppersmith_Attack}
```

exploit driver code: [solve.sage](solve.sage)

original challenge and parameters: [weak_strong.py](weak_strong.py), [enc.txt](enc.txt)

parameters: [config.py](config.py)

output of `neca`: [output](output)
