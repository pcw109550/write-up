# ezbt Writeup

### KAPO 2018 - Reversing 50

> [Binary](./ezbt)

#### Encryption logic

```c
  v5 = strlen(input);
  for ( i = 0; i < v5; ++i )
    input[i] ^= (const unsigned __int8)input[i] >> 1;
  for ( j = 0; j < v5 / 8; ++j )
    *(_QWORD *)&input[8 * j] ^= *(_QWORD *)&input[8 * j] >> 1;
  for ( k = 0; k <= 65; ++k )
  {
    if ( target[k] != input[k] )
      return 0LL;
  }
  return 1LL;
```

#### Exploit

XOR consecutive bits to implement inverse function.

I get flag:

```
KAPO{D1d_y0u_us3_z3?_Th3n_you_4re_f0oOo0o0O0o0Ol_guy_^__________^}
```

Exploit code: [solve.py](solve.py)