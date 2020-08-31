# hdbt Writeup

### KAPO 2018 - Reversing 50

> [Binary](./hdbt)

#### Encryption logic

```c
  if ( (unsigned int)strlen(input) != 32 )
    return 0LL;
  for ( i = 0; ; ++i )
  {
    v2 = 32;
    if ( i >= v2 >> 3 )
      break;
    v8 = 0x8000000000000000LL;
    v5 = 0LL;
    v6 = *(_QWORD *)&input[8 * i];
    v7 = 0xA5118FA1C766BF85LL;
    while ( !(v8 & 0xE273A75A9956DAA7LL) )
      v8 >>= 1;
    while ( v7 )
    {
      if ( v7 & 1 )
        v5 ^= v6;
      v7 >>= 1;
      v6 *= 2LL;
      if ( v8 & v6 )
        v6 ^= 0xE273A75A9956DAA7LL;
    }
    if ( v5 != target[i] )
      return 0LL;
  }
  return 1LL;
```


#### Exploit

Upper logic implements [multiplication over Galois Field](https://en.wikipedia.org/wiki/Finite_field_arithmetic). Let `a = 0xA5118FA1C766BF85`, `p = 0xE273A75A9956DAA7`. Flag has length 32 and divided into four 8 byte chunks, `flag[i], i = 0 to 3`. `target[i] = a * flag[i] (mod p)` over finite field. Simply calculate inverse of `a`, multiply to `target[i]` and recover flag.

I get flag:

```
KAPO{_b1t_w0rld_is_s0Oo0Oo_w1de}
```

Exploit code: [solve.sage](solve.sage)
