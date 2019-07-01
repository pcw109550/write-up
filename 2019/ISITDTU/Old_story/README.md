# Old Story Writeup

### ISITDTU Quals 2019 - crypto 239 - 47 solves

> This is an old story about wheat and chessboard, and it's easy, right?

#### Observations

[Ciphertext](cipher.txt) contained a list with all the elements to be power of 2. I calculated all the bit lengths, and found out they are all less then 63. The flag must be encrypted or encoded to the given list. After some googling to find encoding, hash, or encrytion scheme that uses charset with the number of 64, I guessed that the ciphertext is a [base64](https://en.wikipedia.org/wiki/Base64) encoded string! Simply convert all the bit length to corresponding elements in base64 index table, and decode it. I get the flag:

```
ISITDTU{r1c3_che55b0ard_4nd_bs64}
```

Given parameters: [config.py](config,py), [cipher.txt](cipher.txt)

Exploit code: [solve.py](solve.py)
