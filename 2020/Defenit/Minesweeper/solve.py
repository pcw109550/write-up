#!/usr/bin/env python2
import pwn
from mines import mines_main

IP, PORT = 'minesweeper.ctf.defenit.kr', 3333

pwn.context.log_level = 'DEBUG'
p = pwn.remote(IP, PORT)
minesleft = 40
header = 'Enter the cell ({:d} mines left): '.format(minesleft)
bar = '   -----------------------------------------------------------------\n'
p.sendlineafter(header, 'p1')


def readMap(done=False):
    Map = []
    for _ in range(16):
        p.recvuntil(bar)
        row = p.recvline(keepends=False).split(' | ')[-16:]
        row[-1] = row[-1].rstrip('|')
        if not done:
            row = [int(x.strip()) if len(x.strip()) != 0 else -1 for x in row]
        Map.append(row)
    assert len(Map) == 16 and len(Map[0]) == 16
    return Map


def printMap(Map):
    print('   a   b   c   d   e   f   g   h   i   j   k   l   m   n   o   p  ')
    for i, row in enumerate(Map):
        print(bar[:-1])
        print(' ' + str(i + 1) + ' | ' + ' | '.join([str(x) if x != -1 else '?' for x in row]) + ' |')
    print(bar[:-1])


def decide(Map, UpdatedMap):
    coord = None
    for y in range(16): #height
        for x in range(16): #width
            if UpdatedMap[y][x] == -1:
                assert Map[y][x] == -1
            else:
                if Map[y][x] == -1 and UpdatedMap[y][x] == 0:
                    coord = y, x
                    break
                elif UpdatedMap[y][x] == 1:
                    assert Map[y][x] == -1
    if coord == None:
        return None
    y, x = coord
    return '{:s}{:d}'.format(chr(ord('a') + x), y + 1)


Map = readMap()
UpdatedMap = mines_main(16, 16, minesleft, Map)
result = decide(Map, UpdatedMap)
pwn.log.info('result: {}'.format(result))
p.sendline(result)

for i in range(200):
    pwn.log.info('Mines left: {}'.format(minesleft))

    p.recvuntil('Enter the cell (')
    minesleft = int(p.recvuntil('left): ').strip().split()[0])
    Map = readMap()
    empty = 0
    end = None
    for y in range(16): #height
        for x in range(16): #width
            if Map[y][x] == -1:
                end = y, x
                empty += 1
    if empty == minesleft:
        break
    else:
        UpdatedMap = mines_main(16, 16, minesleft, Map)
        result = decide(Map, UpdatedMap)
        if result == None:
            break
        pwn.log.success('Trial {}: {}'.format(i + 1, result))

    p.sendline(result)

cnt = 0
end = None
for y in range(16): #height
    for x in range(16): #width
        if Map[y][x] == -1:
            end = y, x
            break
for row in Map:
    print(row)
    for x in row:
        if x == -1:
            cnt += 1
printMap(Map)
y, x = end
p.sendline('{:s}{:d}f'.format(chr(ord('a') + x), y + 1))

for _ in range(39):
    p.recvuntil('left): ')
    Map = readMap(True)

    for y in range(16): #height
        for x in range(16): #width
            if Map[y][x].strip() == '':
                end = y, x
                break
    y, x = end
    p.sendline('{:s}{:d}f'.format(chr(ord('a') + x), y + 1))

flag = 'Defenit{min35w33p3r_i5_ezpz}'

p.interactive()