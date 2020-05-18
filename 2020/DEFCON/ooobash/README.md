# ooobash Writeup

### DEFCON 2020 Quals - reversing 120 - 58 solves

> Execute 'getflag' to get the flag. `ooobash.challenges.ooo 5000`

#### Observation

Modified `bash` cli is given. After reversing key functions `getflag_builtin`, `update_ooostate`, I found out that all I have to do to get that flag is to input specific bash commands to unlock 13 stages. The number of locked stages is stored at `leftnum` with initial value of 13, and `update_ooostate` decrements `leftnum` by one. Find xrefs to `update_ooostate` and reverse to find out proper bash commands.

#### Exploit

Each function below unlocks each stages.

```python
def lock0():
    shell('unlockbabylock')
    check(0)


def lock1():
    shell('set -o noclobber; cd /var/tmp; echo yo > badr3d1r90123456')
    shell('set -o noclobber; cd /var/tmp; echo yo > badr3d1r90123456')
    check(1)


def lock2():
    shell('set -o sneaky; echo 1 > /tmp/.sneakyhihihiasd')
    check(2)


def lock3():
    shell('bash -iL')
    check(3)


def lock4():
    shell('export OOOENV=alsulkxjcn92')
    shell('bash -i')
    check(4)


def lock5():
    shell('a')
    shell('b')
    shell('c')
    check(5)


def lock6():
    shell('$(exit 57)')
    check(6)


def lock7():
    shell('echo >/dev/udp/127.0.0.1/53')
    check(7)


def lock8():
    shell('kill -10 $$')
    check(8)


def lock9():
    shell('alias yo=\'echo yo!\'')
    shell('alias yo=\'echo yo!\'')
    check(9)


def lock10():
    shell('declare -r ARO=ARO; declare -r ARO=ARO')
    check(10)


def lock11():
    shell('function fnx { exit; }; function fn { exit; }')
    check(11)


def lock12():
    fname = os.urandom(6)
    shell(f'echo -e \'if :\nthen\n\n\n\nfalse\nfi\' > /var/tmp/{fname}; source /var/tmp/{fname}')
    check(12)
```

 I had to choose the sequence for unlocking each lock carefully because some of unlock functions executed bash again. Unlock everything with carefully chosen sequences:

```python
def unlock():
    lock4()
    lock3()
    lock5()
    lock6()
    lock0()
    lock1()
    lock9()
    lock7()
    lock8()
    lock11()
    lock2()
    lock10()
    lock12()
```

And get the flag:

```
OOO{r3VEr51nG_b4sH_5Cr1P7s_I5_lAm3_bU7_R3vErs1Ng_b4SH_is_31337}
```

Original binary: [bash](bash)

Exploit code: [solve.py](solve.py)

### Somewhat interesting

I used directory `/var/tmp` to store temp files. Others had the same idea, and some teams even wrote their payloads to scripts stored in that directory. Because of this, I didn't fully reversed the whole binary, but read all contents by `cat /var/tmp/*` to steal others' solution! One stolen example script:

```
  5066	#!/bin/sh
  5067	OOOENV=alsulkxjcn92 ./ooobash -L <<EOF
  5068	if :
  5069	then
  5070	# 3
  5071	# 4
  5072	# 5
  5073	false
  5074	fi
  5075	
  5076	a
  5077	b
  5078	c
  5079	
  5080	unlockbabylock
  5081	set -o noclobber; echo 1 2> /tmp/badr3d1rzzzzzza; echo 1 2> /tmp/badr3d1rzzzzzza 
  5082	set -o sneaky; echo 1 > /tmp/.sneakyhihihiasd
  5083	(exit 57);
  5084	echo 1 > /dev/tcp/127.0.0.1/53
  5085	kill -10 $$
  5086	alias yo="echo yo!" - 9
  5087	declare -r ARO=ARO; declare -r ARO=ARO - 10
  5088	function fnx { echo $1 ; } ; fn 1 -  11
  5089	EOF
```