# ETERNAL_GAME Writeup

### TAMUctf 2020 - Crypto 338

> No one has ever won my game except me! 
> `nc challenges.tamuctf.com 8812`

#### Hash Length Extension Attack

My goal is to pass sufficient score, some random bit integer, starting from integer `1`. The score server checks the score by the following logic. Let current integer score value `score`, secret string value `key`, and hash function `H`(sha512).

1. Server will give client of value `h = H(key + str(score)[::-1])`
2. Client will submit its `score` with return value `h`.
3. Server will recalculate hash using method by using client-submitted score and compare with client-submitted hash for verification.

Therefore if I forge value `h`, I can submit arbitrary score to server and get flag! The overall setting is suitable for hash length extension attack. I used [Hashpump](https://github.com/bwall/HashPump), famous tool for this attack! Detailed description for the attack is introduced [here](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks). Use python subprocess module to execute tool. Bruteforce key length to forge hash `h' = H(key + str(some_big_score)[::-1])`, which is the signature for random big integer(`'9' * 50` for my case for ignoring reversing string). Submit forged hash `h'` and get flag:

```
gigem{a11_uR_h4sH_rR_be10nG_to_m3Ee3}
```

Exploit code: [solve.py](solve.py)

Original problem: [game.py](game.py)