#!/usr/bin/env python3
import pwn
import os

IP, PORT = 'ooobash.challenges.ooo', 5000
# pwn.context.log_level = 'DEBUG'
p = pwn.remote(IP, PORT)

def shell(cmd):
    p.sendline(cmd)


def check(num):
    pwn.log.info('unlocking {}'.format(num))
    temp = p.recvuntil(' ({})'.format(num))
    assert b'unlocking' in temp
    pwn.log.success(temp.split(b'\n')[-1].decode())
    checklock()


def checklock():
    shell('getflag')
    result = p.recvuntil('No flag for you.\n', timeout=1)
    if len(result):
        pwn.log.info(result.split(b'\n')[-2].decode())
    else:
        flag = p.recv().replace(b' ', b'\n').split(b'\n')[-3].decode()
        pwn.log.success(flag)
        assert flag == 'OOO{r3VEr51nG_b4sH_5Cr1P7s_I5_lAm3_bU7_R3vErs1Ng_b4SH_is_31337}'
        p.close()


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


unlock()
