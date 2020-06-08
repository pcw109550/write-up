# QR Generator Writeup

### Defenit CTF 2020 - Misc 181 - 82 solves

> Escape from QR devil! `nc qr-generator.ctf.defenit.kr 9000`

#### Observation

Straightforward task. Let me read QRCode with varying size 100 times.

#### Exploit

Iterate below steps 100 times.

1. Parse input and save QRCode as png using [PIL](https://pillow.readthedocs.io/en/stable/).
2. Use [zxing](https://pypi.org/project/zxing/) python module for read QRCode data.
3. Send result to server.

```python
for _ in range(100):
    p.recvuntil('< QR >\n')
    mat = []
    firstrow = list(map(int, p.recvline(keepends=False).split()))
    mat.append(firstrow)
    height = width = len(firstrow)
    for _ in range(width - 1):
        row = list(map(int, p.recvline(keepends=False).split()))
        mat.append(row)
    assert len(mat) == height

    p.recvuntil('>> ')

    pwn.log.info(f'width: {width}')
    scale = 20
    margin = 20
    out = Image.new('1', (width * scale + margin * 2, height * scale + margin * 2))
    outpx = out.load()

    for indX, indY in product(range(width * scale + margin * 2), repeat=2):
        pos = indX, indY
        outpx[pos] = 1

    for indX, indY in product(range(width * scale), repeat=2):
        pos = indX + margin, indY + margin
        outpx[pos] = mat[indY // scale][indX // scale] == 0
    
    # Save QR
    out.save('out.png')
    # Read QR
    rs = decoder.decode('out.png')
    # Send result
    p.sendline(rs.raw)
```

Get flag: 

```
Defenit{QQu!_3sC4p3_FR0m_D3v1l!_n1c3_C0gN1z3!}
```

Exploit code: [solve.py](solve.py)