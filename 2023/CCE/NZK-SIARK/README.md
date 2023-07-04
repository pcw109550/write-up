# NZK-SIARK Writeup

## CCE 2023 - crypto 451 - 3 solves

> Not Zero-Knowledge Succint Interactive Argument of Knowledge

> Not Zero-Knowledge : This system is "not" zero-knowledge. Succint : The verifier does not directly compute the inverse; it only verifies it.
Interactive : The prover and verifier should interact.
Argument of Knowledge : A malicious prover cannot cheat.

> [for_user.zip](for_user.zip)

> `nc 20.196.215.52 8322`

### Analysis

The challenge asks us to find the `KEY` which satisfies `AES_K(PLAINTEXT) = CIPHERTEXT`. Here, `PLAINTEXT` and `CIPHERTEXT` is random bytestring having length `BLOCK_SIZE = 16`.

Lets inspect the given cryptosystem `AES_K()`. At first glance, it seems like plain [AES-128](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) because block size is 16 bytes(= 128 bits). But I immediately notice some fishy function name: `get_sbox_and_verify()`. Every other functions/steps are all from vanilla AES.

### AES `SubBytes` Step

AES is based on [SPN network](https://en.wikipedia.org/wiki/Substitution%E2%80%93permutation_network), and its [SubBytes](https://en.wikipedia.org/wiki/Rijndael_S-box) step introduces nonlinearity which makes the cipher safer. The sbox maps a byte input $x$ to a byte output $y$. The input $x$ is first mapped to its multiplicative inverse $x^{-1}$ over [Rijndael's finite field](https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field). After that, affine transformation is applied to $x^{-1}$; resulting in $y = x^{-1} \oplus (x^{-1} \lll 1 ) \oplus (x^{-1} \lll 2) \oplus (x^{-1} \lll 3 ) \oplus (x^{-1} \lll 4 ) \oplus 99$.

### `get_sbox_and_verify()` Inspection

Because `get_sbox_and_verify()` is the only difference compared to plain AES, let me inspect this line by line. `get_sbox_and_verify()` method astonishingly asks the attacker $x^{-1}$ by exposing $x$ (which follows problem description 😎: `Interactive : The prover and verifier should interact.`).

```python
xinv = int(input(f"inv({x}) > "), 16)
assert 0 <= xinv < 256
xinv = GF(xinv)
```

After receiving $x^{-1}$, It first checks that the attacker is honest and actually gave the correct $x^{-1}$ (which follows problem description 😎: `Succint : The verifier does not directly compute the inverse; it only verifies it.`). 

```python
assert x * (x * xinv - GF(1)) == GF(0)
```

Finally, calculate the final result using affine transformation:

```python
return xinv + xinv.lrotate(1) + xinv.lrotate(2) + xinv.lrotate(3) + xinv.lrotate(4) + GF(99)
```

## Vulnerability

The inverse validation logic of `get_sbox_and_verify()` is flawed when $x = 0$ (which DOES NOT follow problem description 😲: `Argument of Knowledge : A malicious prover cannot cheat.`). 

```python
assert x * (x * xinv - GF(1)) == GF(0)
# when x = GF(0)
assert GF(0) * (GF(0) * xinv - GF(1)) == GF(0)
```

Above assertion will be passed by any value in $x^{-1} \in [0, 256)$. In other words, I can forge the result of `get_sbox_and_verify()` only when $x = 0$. If I want some value $z$ to be the outcome, I can try every $x^{-1} \in [0, 256)$ to find out $x^{-1}$. This is because the result is derived from affine transformation of $x^{-1}$. Here is the implementation:

```python
def forge_response(target):
    prefix = tn.recvuntil(b" > ")[-10:].decode()
    # make sure that given x == 0
    assert "inv(00) > " == prefix, prefix
    for i in range(256):
        xinv = GF(i)
        # affine transformation
        temp = (
            xinv
            + xinv.lrotate(1)
            + xinv.lrotate(2)
            + xinv.lrotate(3)
            + xinv.lrotate(4)
            + GF(99)
        )
        if temp.val != target:
            continue
        # desired outcome found
        # send xinv to take control of return value of get_sbox_and_verify()
        tn.sendline("{:02x}".format(xinv.val).encode())
        return
    assert False, "forge failure"
```

### AES State Nullification

My goal is to find the `KEY` which satisfies `AES_K(PLAINTEXT) = CIPHERTEXT`. If I can forge the entire intermediate AES state(16 bytes), I may use any `KEY`. 

Forgery must occur at SubBytes step, `sub_bytes(state)`. To take control of state, previous input state must be only consist of null byte, to set parameter $x$ of `get_sbox_and_verify` to be $0$. 

Initial state of AES is set to `PLAINTEXT`, then xored with initial round key. After that, each AES step is applied. In code,

```python
for i in range(4):
    for j in range(4):
        state[i][j].val = PLAINTEXT[i + 4*j]

add_round_key(state, [[round_keys[z][j] for j in range(4)] for z in range(4)] )

for i in range(ROUNDS - 1):
    sub_bytes(state)
    ...
```

Initial round key is equal to `KEY`, due to [AES key schedule](https://en.wikipedia.org/wiki/AES_key_schedule). Therefore, if I set `KEY == PLAINTEXT`, state will be set to `KEY ^ PLAINTEXT == b"\x00" * BLOCK_SIZE`. I nullified AES State and became ready to forge.

### Forgery

At this point, `KEY`, `PLAINTEXT`, `CIPHERTEXT` is determined. I need to find the target state, result of first call of `sub_bytes(state)` when state is nullified.

By using determined `KEY = PLAINTEXT` and `CIPHERTEXT`, I can run the decryption process starting from final state which is `CIPHERTEXT`. Rewind AES steps until the first call of `sub_bytes(state)`. The intermediate state will be the desired state, and must be forged. Rewind process needs inverse AES steps to be implemeneted, which is not so difficult. Rewind process in code:

```python
# prepare target state
# start with ciphertext
final_state = [[GF(0) for i in range(4)] for j in range(4)]
for i in range(4):
    for j in range(4):
        final_state[j][i].val = target_ct[j + 4 * i]

state = final_state[:]
# rewind
add_round_key(
    state,
    [[round_keys[z][j] for j in range(4 * ROUNDS, 4 * ROUNDS + 4)] for z in range(4)],
)
inv_shift_rows(state)
inv_sub_bytes(state)

for i in reversed(range(1, ROUNDS - 1)):
    add_round_key(
        state,
        [[round_keys[z][j] for j in range(4 * i + 4, 4 * i + 8)] for z in range(4)],
    )
    inv_mix_columns(state)
    inv_shift_rows(state)
    inv_sub_bytes(state)

add_round_key(state, [[round_keys[z][j] for j in range(4, 8)] for z in range(4)])
inv_mix_columns(state)
inv_shift_rows(state)
# reached desired state
```

### Final Exploit

1. Receive `PLAINTEXT`, `CIPHERTEXT` from server.
2. Let `KEY = PLAINTEXT`.
3. Apply key scheduling.
    - This step requires `4 * ROUNDS` honest sbox substitution.
4. Rewind using `KEY` and `CIPHERTEXT`.
    - Derive target intermediate state.
5. Forge first call of `sub_bytes()` using derived target intermediate state.
    - Requires 16 forgeries; for each state byte.
6. Apply reset AES logic
    - This step requires `16 * ROUNDS - 16` honest sbox substitution.

This system is definitely not zero knowledge. I get flag:

```
cce2023{SAMPLE_FLAG}
```

Problem src: [prob.py](prob.py), [GF.py](GF.py), [constants.py](constants.py)

exploit driver code: [solve.py](solve.py) requiring [requirements.txt](requirements.txt), [sbox.py](sbox.py)
