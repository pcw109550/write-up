#!/usr/bin/env python3
import pwn
import subprocess

# pwn.context.log_level = 'DEBUG'

if __debug__:
    p = pwn.process(['python', 'game.py'])
else:
    IP, PORT = 'challenges.tamuctf.com', 8812
    p = pwn.remote(IP, PORT)

menu = '1. New Game\n2. Claim Prize\n3. Exit\n'
welcome = '''
            Welcome the The Game. You are allowed to multiply the initial number (which is 1) by any
            number in the range 2-10. Make decisions wisely! You can only multiply by each
            number at most 5 times... so be careful. Also, at a random point during The Game, an asteroid
            will impact the Earth and The Game will be over.

            Feel free to get your proof of achievement and claim your prize at the main menu once
            you start reaching big numbers. Bet you can't beat my high score!\n'''
game_menu = '1. Multiply\n2. Print current value\n3. Get proof and quit\n'
p.recvuntil(menu)

# hash length extenstion attack
# luckily key is constant, find out key length by bruteforcing

def extract_int(s):
    i = len(s) - 1
    result = 0
    while i >= 0 and s[i].isdigit():
        result *= 10
        result += ord(s[i]) - ord('0')
        i -= 1
    return result


def get_hash():
    p.sendline(str(1))
    p.recvuntil(welcome)
    p.recvuntil(game_menu)
    p.sendline(str(3))
    return p.recvline(keepends=False).decode()


def prize(num, proof):
    p.sendline(str(2))
    p.recvuntil('Input the number you reached: \n')
    p.sendline(num)
    p.recvuntil('Present the proof of your achievement: \n')
    p.sendline(proof)
    response = p.recvline(keepends=False).decode()
    if 'gigem' in response:
        return response

base_hash = get_hash()
additional = '9' * 50
args = ' -s "{}" '.format(base_hash)
args += '-d 1 '
args += '-a "{}" '.format(additional)
args += '-k {:d}'

for keylength in range(1, 128):
    keylength = 10
    args_real = args.format(keylength)
    output = subprocess.getoutput('hashpump' + args_real)
    hashval, num = output[:len(base_hash)], output[len(base_hash):].strip().encode().decode('unicode-escape')
    response = prize(num, hashval)
    if response:
        pwn.log.success('flag = {:s}'.format(response))
        quit()

p.interactive()
