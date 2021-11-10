# vpoly Writeup

### POC Cutting Edge CTF 2021 - reversing/crypto 992 - 4 solves

> I love both vectors and polynomials, And you? flag is DH{$yourinput}.

#### Analysis

By reversing through the binary, the problem inputs two 128 bit numbers `b1`, `b2`. After that, It calculates `c1 = pow(a, b1)`, `c2 = pow(a, b2)` over finite field `GF(2 ^ 127)`, which is defined by the field extension `GF(2)[x]/(p)`. `a`, `c1`, `c2`, `p` are constants. My goal is to find out correct exponents `b1` and `b2` which satisfies the contraints. Therefore my goal is to solve discrete logarithm problem over finite field.

### Solving DLP with Sage

Lets ask Sage to calculate the DLP for me.

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l

a = 0x173EF9F2D78FE1CA7925215B67D67136
c1 = 0x6E62A8AE251A78497FF839F2F6CAC510
c2 = 0x2EC7AC61D3704B1AEE6AAD3FD1FDB4CE

P.<x> = PolynomialRing(GF(2))

modulus = (x ^ 127) + P(R.fetch_int(0x53935563C38A0FC5A3B133EDB401227D))
assert modulus.is_irreducible()

K.<a> = GF(2 ^ 127, modulus=modulus)

b1 = discrete_log(K.fetch_int(c1), K.fetch_int(a))
b2 = discrete_log(K.fetch_int(c2), K.fetch_int(a))
```

Sadly, Sage took so much memory(over 32G) and led to OOM. Is this a bug? Basically solving DLP falls in to MitM attack. Hogging memory is reasonable, but 32G was to much. TODO: Find out why.

### Solving DLP with Magma

Magma is another a fascinating tool for solving DLP over extension field.

```magma
F<x> := ext<GF(2) | Polynomial([1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1])>;
a := x^124 + x^122 + x^121 + x^120 + x^117 + x^116 + x^115 + x^114 + x^113 + x^111 + x^110 + x^109 + x^108 + x^107 + x^104 + x^103 + x^102 + x^101 + x^100 + x^97 + x^95 + x^94 + x^92 + x^90 + x^89 + x^88 + x^87 + x^83 + x^82 + x^81 + x^80 + x^79 + x^78 + x^77 + x^72 + x^71 + x^70 + x^67 + x^65 + x^62 + x^61 + x^60 + x^59 + x^56 + x^53 + x^50 + x^48 + x^45 + x^40 + x^38 + x^36 + x^35 + x^33 + x^32 + x^30 + x^29 + x^26 + x^25 + x^24 + x^23 + x^22 + x^20 + x^18 + x^17 + x^14 + x^13 + x^12 + x^8 + x^5 + x^4 + x^2 + x;
c1 := x^126 + x^125 + x^123 + x^122 + x^121 + x^118 + x^117 + x^113 + x^111 + x^109 + x^107 + x^103 + x^101 + x^99 + x^98 + x^97 + x^93 + x^90 + x^88 + x^84 + x^83 + x^81 + x^78 + x^77 + x^76 + x^75 + x^70 + x^67 + x^64 + x^62 + x^61 + x^60 + x^59 + x^58 + x^57 + x^56 + x^55 + x^54 + x^53 + x^52 + x^51 + x^45 + x^44 + x^43 + x^40 + x^39 + x^38 + x^37 + x^36 + x^33 + x^31 + x^30 + x^29 + x^28 + x^26 + x^25 + x^23 + x^22 + x^19 + x^17 + x^15 + x^14 + x^10 + x^8 + x^4;
c2 := x^125 + x^123 + x^122 + x^121 + x^119 + x^118 + x^114 + x^113 + x^112 + x^111 + x^109 + x^107 + x^106 + x^102 + x^101 + x^96 + x^95 + x^94 + x^92 + x^89 + x^88 + x^86 + x^85 + x^84 + x^78 + x^75 + x^73 + x^72 + x^68 + x^67 + x^65 + x^63 + x^62 + x^61 + x^59 + x^58 + x^57 + x^54 + x^53 + x^51 + x^49 + x^47 + x^45 + x^43 + x^42 + x^40 + x^37 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 + x^30 + x^28 + x^24 + x^23 + x^22 + x^21 + x^20 + x^19 + x^18 + x^16 + x^15 + x^13 + x^12 + x^10 + x^7 + x^6 + x^3 + x^2 + x;
b1 := Log(a, c1);
b2 := Log(a, c2);
b1;
b2;
```

[Run](http://magma.maths.usyd.edu.au/calc/) and boom! Get the result for about a second. What makes this huge difference compared to sage? Food for thought.

Result:

```
73363953903257010471851770511044850017
72049349907947449284501819607742625081
```

Hexify and concat. I get the flag:

```
DH{a1793895580c1b1795c976a03f796346}
```

exploit driver code: [solve.magma](solve.magma)

Original binary: [vpoly](vpoly)