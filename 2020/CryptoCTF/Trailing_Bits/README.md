# Trailing Bits Writeup

### Crypto CTF 2020 - Crypto 29 - 280 solves

> The [text](./trailing_bits_f62ab56d6be7ff17355f364f56fa1a1a073a82aa.txz) that includes the flag is transmitted while unfortunately both of its head and tail bits are lost 😟

#### Exploit

The description says some header/footer bits are truncated. Express `CCTF` string as bit string and search for it. Locate the flag and decode.

I get flag:

```
CCTF{it5_3n0u9h_jU5T_tO_sH1ft_M3}
```

Exploit code: [solve.py](solve.py) with [config.py](config.py)