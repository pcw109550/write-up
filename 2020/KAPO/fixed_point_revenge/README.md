# fixed point revenge Writeup

### KAPO 2020 - Crypto 100 - 0 solves

> [fixed_point_revenge.zip](fixed_point_revenge.zip)

Solved after the CTF was ended.

#### Analysis

My goal is to find 8 byte input which satisfies below assertions.

```python
def f(s):
    ret = []
    for c in s:
        ret.append(inp[int(c)])
    return bytes(ret)

def g(t, s):
    return t + b"{" + f(s) + b"}"

def xor(a, b):
    return bytes([c1 ^ c2 for c1, c2 in zip(a, b)])

constraints = [
    [b"rbtree",   "01234567", "12345670", b'\x36\xb0\x16\xf7\x5f\x42\xa9\xf6'],
    [b"mathboy7", "12345670", "23456701", b'\x36\x94\xe4\xfc\x56\x1b\x9a\x5d'],
    [b"rubiya",   "23456701", "34567012", b'\xa8\xd8\x3a\xd2\x8d\x13\x4b\x16'],
    [b"bincat",   "34567012", "45670123", b'\xfc\x7f\xcc\xbe\xf9\xbc\x1b\xf6'],
    [b"5unkn0wn", "45670123", "56701234", b'\x08\xea\xb4\xc6\xc3\x3e\x12\x4f'],
    [b"saika",    "56701234", "67012345", b'\x68\x0c\xe0\x7e\x6f\xa7\xe4\x36'],
    [b"juno",     "67012345", "70123456", b'\x18\x7e\x80\xb9\x54\x7b\x35\xa7'],
    [b"wooeng",   "01234567", "76543210", b'\xc1\x5b\xe0\x2f\x1b\xf8\xb3\xaf']
]

for person, input_order, output_order, const in constraints:
    assert xor(crc64(g(person, input_order)), f(output_order)) == const, "WRONG :("
```

#### Useful properties of crc64 function

`crc64` function is an [affine transformation](https://en.wikipedia.org/wiki/Affine_transformation) over the vector space `GF(2 ^ 64)`. By exploiting affineness, I result in below two properties:

1. `crc64(x ^ y) = crc64(x) ^ crc64(y)`
    - Inital crc64 state is null(`x += b'\x00' * 8` in function).
    - If initial state is non-null, `crc64(x ^ y ^ z) = crc64(x) ^ crc64(y) ^ crc64(z)` holds. 
2. `a = crc64(x), b = crc64(x + b'\x00' * 9)` then `a << 72 == b`

#### Reducing constraints and solving systems of equation

Let me examine first constraints. Every computation is performed over `GF(2 ^ 64)`. Let input be `[a0, a1, .. , a7]`. The constraint will be:

```python
crc64(b'rbtree{' + a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + b'}') == (a1 + a2 + a3 + a4 + a5 + a6 + a7 + a0) ^ const[0]
```

By using first property, 

```python
crc64(a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + b'\x00') ^ (a1 + a2 + a3 + a4 + a5 + a6 + a7 + a0) == const[0] ^ crc64(b'rbtree{' + b'\x00' * 8 + b'}')
```

I know the right hand side of equation. Calculate `constants` based on `const` and `person` for every 8 tuples:

```python
constants = []
for person, input_order, output_order, const in constraints:
    value = int.from_bytes(xor(crc64(g_empty(person)), const), byteorder='big')
    constants.append(F.fetch_int(value))
```

Total problem can be translated into system of equations: 8 unknowns with 8 equations. Use second property to construct matrix:

```python
a = lambda n : x ^ (8 * n + 80)
b = lambda n : x ^ (8 * n)

M = [[0 for _ in range(8)] for _ in range(8)]
for i, (_, input_order, output_order, _) in enumerate(constraints):
    for j in reversed(range(8)):
        M[i][7 - j] = a(int(input_order[j])) + b(int(output_order[j]))
M = matrix(F, M)
```

Reason that shifting `80` instead of `72` is that additional null byte is included due to existence of `}` in original constraint.

Find vector `x` such that `M * x = const`. Invert `M` and get `x`: `x = Minv * const`. Every element in `x` must be polynomial of order less than 8 because it must represent single byte. Translate each element to bytes.

```python
Minv = M.inverse()

inp_hex = ''
for i in range(8):
    val = sum([Minv[i][j] * constants[j] for j in range(8)])
    inp_hex += format(val.integer_representation(), '02x')

inp = unhexlify(inp_hex)
```

I get flag:

```
flag{8bb7cb9b53d5b3b2}
```

Exploit code: [solve.sage](solve.sage)