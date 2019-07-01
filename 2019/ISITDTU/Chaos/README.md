# Chaos Writeup

### ISITDTU Quals 2019 - crypto 304 - 47 solves

> Could you help me solve this case? I have a tool but do not understand how it works.
nc 104.154.120.223 8085

#### Observations

Our goal is to submit `key` to get flag. By interacting(encrypting arbitrary printable strings), the system is simply pseudo-substitution cipher. Let `ct` be the given ciphertext, and `pt` the plaintext(`key`). Pattern for decryption is obtained simply by observations, which is stated below.

```python
pt = ""
for c in ct:
    if len(c) == 8:
        pt += c[0]
    elif len(c) == 11 and c[6] in punctuation:
        pt += c[3]
    elif len(c) == 11 and c[6] in ascii_uppercase:
        pt += c[7]
    else:
        pt += c[-1]
```

By sending `key` to server, I get the flag:

```
ISITDTU{Hav3_y0u_had_a_h3adach3??_Forgive_me!^^}
```

Exploit code: [solve.py](solve.py)
