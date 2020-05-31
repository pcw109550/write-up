# Omni Crypto Writeup

### Pwn2Win CTF 2020 - crypto 246 - 32 solves

> One of the first versions of the S1 Protocol had a faulty encryption protocol. We captured the communication between two important ButcherCorp leaders and now it's up to you know what they were planning. Although it's an old communcation, the information there can still be useful to the Rebelious Fingers.

#### Observation

Vulnerable prime generation algorithm for RSA is given. I can find out lsbs and msbs of RSA prime `p` and `q`. Each primes can be divided by three bit chunks, each having length of `sizes = [rand, half, size - half - rand]`. The middle chunk having `half` length is the only difference between `p` and `q`.

##### Leak MSBs

`p` and `q` are almost identical. I experimentally checked the similarity of MSBs of how much public modulus `N`'s square root `base_` and `p`s. Bit length of identical MSBs can be guessed in `rand = random.randint(8, half - 1)`. By this method, I leak MSBs of `p` with length `rand`.

##### Leak LSBs

The third bit chunk having length of `size - half - rand` can be also derived, since `p` and `q` share same last chunk. I used z3 for obtaining LSBs. z3 gave me two solutions.

```python
idx = 500 # tweak
pbase = z3.BitVec('pbase', idx)
S = z3.Solver()
mask = int((1 << idx) - 1)

S.add((pbase * pbase) & mask == N & mask)
# Ask z3 to find other candidate
S.add(pbase != int(0b1000110100001000000111000101000000101010100100100010100110111011111100111000000011101011011011101111010110101100010001000001011101110111100010110001100100100101100110011100110111101000010100000001000110101001011111111110111110101101110111001110100101001000011101011011111011111101000000010111101111011110010010000110001000001000110110011110011111000001010001100110001100100110110000000110110000111000101011011111100111011100111010011110101011111000111001100010011100010010101111101101111000101010001))
issat = S.check()
assert issat == z3.sat
ans = S.model()
pbase_ = Integer(str(ans[pbase]))
```

#### Coppersmith's attack and profit

Length of known consecutive bits(MSBs and LSBs) can be derived as below.

```python
half = random.randint(16, size // 2 - 8) # 16 to 504
known = 0
known += rand # MSBs
known += size - half - rand # LSBs
assert len(known) == size - half
```

The minimum length of exposed bits are larger than half of `p`'s bit length(always longer than `1024 - 503`). Therefore Coppersmith attack is always feasible. The only problem is that I do not exactly know the value of `half` and `size`. Guess these values!

```python
def factor():
    F.<x> = PolynomialRing(Zmod(N))
    while True:
        half = random.randint(16, 1024 // 2 - 8)
        rand = random.randint(8, half - 1)
        if not DEBUG:
            rand, half = 203, 443
        # Is Coppersmith Attack feasible?
        assert 1024 - half >= 1024 // 2
        # Yes it is!
        print(f'[*] rand: {rand}, half: {half}')
        a = 1024 - rand
        base = base_ >> a
        pbase = pbase_ & ((1 << (1024 - rand - half)) - 1)
        f = (base << a) + pbase + x * (1 << (1024 - rand - half))
        f = f.monic()
        x0 = f.small_roots(X=(2 ** half), beta=0.44, epsilon=1/32)
        for xs in x0:
            pcand = (base << a) + pbase + xs * (1 << (1024 - rand - half))
            pcand = Integer(pcand)
            if N % pcand == 0:
                print(f'[+] p = {pcand}')
                return pcand
```

Factors known, get the flag!

```
CTF-BR{w3_n33d_more_resources_for_th3_0mni_pr0j3ct}
```

Original problem source: [enc.py](enc.py), [output.txt](output.txt)

Exploit code: [solve.sage](solve.sage) with [config.py](config.py)