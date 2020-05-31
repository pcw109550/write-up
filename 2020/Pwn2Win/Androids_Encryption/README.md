#  Androids Encryption Writeup

### Pwn2Win CTF 2020 - crypto 115 - 108 solves

> We intercept an algorithm that is used among Androids. There are many hidden variables. Is it possible to recover the message? `nc encryption.pwn2.win 1337`

#### Observation

`BLOCK_SIZE = 16`. Two modes:

1. Encrypt user input plaintext: `enc_plaintext()`
    - AES with PCBC using `key1`, `iv1`.
    - `key2`, `iv2` is updated based on ciphertext result and `iv2`.
        - `iv2 = AES.new(key2, AES.MODE_ECB).decrypt(iv2)`
        - `key2 = xor(to_blocks(ctxt))`
    - Encrypted result and iv given.
2. Encrypt flag: `enc_flag()`
    - AES with PCBC using `key2`, `iv2`.
    - `iv2`, `key2` is updated with same logic introduced at `1.`
    - Encrypted result and iv given.

#### Exploit

I can control `key2` by encrypting single block(`'A' * BLOCK_SIZE`). `key2` is updated by the following logic.

```python
def to_blocks(txt):
    return [txt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(txt)//BLOCK_SIZE)]


def xor(b1, b2=None):
    if isinstance(b1, list) and b2 is None:
        assert len(set([len(b) for b in b1])) == 1, 'xor() - Invalid input size'
        assert all([isinstance(b, bytes) for b in b1]), 'xor() - Invalid input type'
        x = [len(b) for b in b1][0]*b'\x00' # BLOCK_SIZE * 16
        for b in b1:
            x = xor(x, b)
        return x
    assert isinstance(b1, bytes) and isinstance(b2, bytes), 'xor() - Invalid input type'
    return bytes([a ^ b for a, b in zip(b1, b2)])

key2 = xor(to_blocks(ctxt))
```

After controlling `key2`, ask the server to get encrypted flag. The flag must be encrypted with `key2`. Also, I know the value of `ctxt`, so `key2` is known and iv used for flag encryption is given.

```python
pt = 'A' * BLOCK_SIZE
_, ct = encrypt_your_secret(pt)
key2 = xor(to_blocks(ct))
iv, ct_flag = encrypt_my_secret()
assert len(ct_flag) == BLOCK_SIZE * 3

aes = AES.new(key2, AES.MODE_ECB)
flag = b''
blocks = to_blocks(ct_flag)
curr = iv
for block in blocks: # PCBC
    flag += xor(aes.decrypt(block), curr)
    curr = xor(flag[-BLOCK_SIZE:], block)
flag = flag.decode()
```

By knowing iv and key, decrypt and get the flag:

```
CTF-BR{kn3W_7h4T_7hEr3_4r3_Pc8C_r3pe471ti0ns?!?}
```

Original source: [server.py](server.py)

Exploit code: [solve.py](solve.py)