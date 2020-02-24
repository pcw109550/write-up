# AskTheOracle Writeup

### Pragyan CTF 2020 - crypto 150

> Mr Robot has worked all night to find the Cipher "TIe8CkeWpqPFBmFcIqZG0JoGqBIWZ9dHbDqqfdx2hPlqHvwH/+tbAXDSyzyrn1Wf" then he faints of Overdose. You are left with a challenge to get the key to the database before EVIL CORP starts backing up the data.
> `nc ctf.pragyan.org 8500`
> P.S- After solving you will get a flag in the format of pctf{code}, change it to p_ctf{code} and submit it.

#### Oracle Padding Attack

It is a traditional [oracle padding attack(OPA)](https://en.wikipedia.org/wiki/Padding_oracle_attack). To apply the attack,

1. Leak block size
	- Can be found by sending various length of inputs and observing responses.
	- `SIZE = 16`
2. Leak initialization vector(`iv`)
	- This was included in server response, encoded by base64.
	- `iv = "This is an IV456"`
3. Confirm the [block mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) is CBC.
	- Checked by sending intentionally malformed `iv|ct` pairs.
4. Check server response behavior is vulnerable for attack. Needed for information leakage.
	-  Wrong padding
	-  Correct data
	-  Cipher error

Reason of why OPA works will be not introduced here. Check [here](https://robertheaton.com/2013/07/29/padding-oracle-attack/) for detailed explanation. The total ciphertext length was `48` bytes, and we need 256 queries per leaking bytes. Therefore, we need at most `48 * 256` queries. Each query took about more than `0.5`s, and it took quite a time to leak the whole flag. With patience and time, I get the flag:

```
pctf{b@d_p@nd@s_@r3_3v3rywh3r3_c@tch}
```

Exploit code: [solve.py](solve.py)


