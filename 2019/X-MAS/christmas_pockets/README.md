# christmas pockets Writeup

### Christmas CTF 2019 - crypto 995 - 8 solves

> Christmas Pockets!

#### Analysis of cryptosystem

I immediately notice that given system is classical [knapsack cryptosystem](https://en.wikipedia.org/wiki/Merkle%E2%80%93Hellman_knapsack_cryptosystem).

#### Lattice Attack

It is well known that classical knapsack cryptosystem is vulnerable to LLL attacks. [Here](http://www.dtc.umn.edu/~odlyzko/doc/arch/knapsack.survey.pdf) are some proofs of fall of knapsack cryptosystem. Given public key satisfy conditions for [low density attack](https://eprint.iacr.org/2007/066.pdf)(`d = n / log(max(pk)) < 0.9408`), and can be broken on polynomial time(since LLL have polynomial complexity).

I will construct [lattice and run LLL](http://www.cs.sjsu.edu/faculty/stamp/papers/topics/topic16/Knapsack.pdf), to reduce subset sum problem to shortest vector problem. I get flag:

```
X-MAS{Pocket_o_Fukuramasete}
```

exploit driver code: [solve.sage](solve.sage)

original challenge and parameters: [prob.py](prob.py), [output](output)

parameters: [const.py](const.py)