#!/usr/bin/env python3
from itertools import product
import pwn
import itertools
import hashlib

pwn.context.log_level = 'DEBUG'
IP, PORT = 'dodge.ctf.defenit.kr', 1357
p = pwn.remote(IP, PORT)

WIDTH, HEIGHT = 40, 20


def PoW():
    target = p.recvline(keepends=False)[-33:-1].decode()
    assert len(target) == 32
    for i in range(1 << 24):
        cand = i.to_bytes(3, 'big')
        if hashlib.md5(cand).hexdigest() == target:
            pwn.log.info('PoW done')
            p.send(cand)
            break
    p.recvuntil('q, e : move focus(*)\nw, a, s, d : move player(p)\n')


def recvMap():
    Map = []
    p.recvuntil('##########################################\n')
    for _ in range(HEIGHT):
        row = list(p.recvline(keepends=False).decode().strip('#'))
        Map.append(row)
    p.recvuntil('##########################################\n')
    return Map


def printMap(Map):
    print('##########################################')
    for row in Map:
        print('#' + ''.join(row) + '#')
    print('##########################################')


class Solver:
    def __init__(self, GAMENUM):
        self.Maps = [None] * GAMENUM
        self.numRound = 1
        self.focus = 0

    def roundUpdate(self):
        pwn.log.info('Round: {}'.format(self.numRound))
        pwn.log.info('focus: {}'.format(self.focus))
        for i in range(GAMENUM):
            try:
                ind = p.recvline(keepends=False).decode()
            except:
                pwn.log.info('####################')
                pwn.log.info('### Score: {:3d} #####'.format(self.numRound))
                pwn.log.info('####################')
                p.close()
                exit()
            assert int(ind.rstrip('*')) == i
            if '*' in ind:
                self.focus = i
            self.Maps[i] = recvMap()
        self.numRound += 1

    """
    def command(self, cmd=''):
        self.roundUpdate()
        # q: focus up(3 -> 2, 2 -> 1, 1 -> 0, 0 -> 3)
        # e: focus dn(0 -> 1, 1 -> 2, 2 -> 3, 3- > 0)
        # wasd: trivial
        direction = {'w':'up', 'a':'left', 's':'down', 'd':'right'}
        if cmd == '':
            return
        for c in cmd:
            assert c in 'qewasd'

        #p.sendline(cmd)

        cmd = cmd.replace('q','').replace('e','')
        if len(cmd) == 1:
            pwn.log.info('Task {}: Move {}'.format(self.focus, direction[cmd]))
        else:
            pwn.log.info('Multiple Moves: {}'.format(cmd))
    """

def findPos(Map):
    bullet = []
    player = None
    for y, x in product(range(HEIGHT), range(WIDTH)):
        if Map[y][x] == '*':
            bullet.append((y, x))
        elif Map[y][x] == 'p':
            player = y, x
    return bullet, player


def updatePos(pos, speed):
    y, x = pos
    ys, xs = speed
    bounceY, bounceX = False, False
    yUpdated, xUpdated = None, None

    if 0 > y + ys:
        bounceY = True
        yUpdated = abs(y + ys)
    elif HEIGHT <= y + ys:
        bounceY = True
        yUpdated = HEIGHT - 1 - (y + ys - (HEIGHT - 1))
    else:
        yUpdated = y + ys

    if 0 > x + xs:
        bounceX = True
        xUpdated = abs(x + xs)
    elif WIDTH <= x + xs:
        bounceX = True
        xUpdated = WIDTH - 1 - (x + xs - (WIDTH - 1))
    else:
        xUpdated = x + xs

    return bounceY, bounceX, yUpdated, xUpdated


class Bullet:
    def __init__(self, pos, speed):
        assert isinstance(pos, tuple) and isinstance(speed, tuple)
        self.pos = pos
        self.speed = speed
        y, x = self.pos
        assert 0 <= y and y < HEIGHT
        assert 0 <= x and x < WIDTH

    def update(self):
        ys, xs = self.speed
        bounceY, bounceX, yUpdated, xUpdated = updatePos(self.pos, self.speed)

        if bounceY:
            print('bounceY')
            ys = -ys
        if bounceX:
            print('bounceX')
            xs = -xs

        self.speed = ys, xs
        self.pos = yUpdated, xUpdated


class Player(Bullet):
    # inherit update method from bullet
    def __init__(self, pos, speed):
        assert isinstance(pos, tuple) and isinstance(speed, tuple)
        self.pos = pos
        self.speed = speed
        y, x = self.pos
        assert 0 <= y and y < HEIGHT
        assert 0 <= x and x < WIDTH
        ys, xs = self.speed
        assert xs == 0 or ys == 0
        if xs == 0:
            assert abs(ys) == 1
        elif ys == 0:
            assert abs(xs) == 1
        else:
            assert False, 'Player velocity stupid: {self.speed}'

    def updatespeed(self, direction):
        assert isinstance(direction, str) and len(direction) == 1
        assert direction in 'wasd'
        speedlist = [(-1, 0), (0, -1), (1, 0), (0, 1)]
        self.speed = speedlist['wasd'.index(direction)]


def bulletUpdate(bulletList):
    [bullet.update() for bullet in bulletList]


def playerUpdate():
    global playerLists
    global playerPrevPos
    playerPrevPos = [player.pos for player in playerLists]
    [player.update() for player in playerLists]


def playerPosCheck(idx, estimate, truth):
    if estimate != truth:
        if player != None:
            pwn.log.info(f'Player[{idx}] is {truth} but estimate {estimate}')
        else:
            pwn.log.info('##################### GAME OVER #####################')
            pwn.log.info(f'### Collision at game {idx} with player pos {estimate} ###')
            pwn.log.info('#####################################################')


def decide(focus, swap=False):
    global bulletLists
    global playerLists
    global playerPrevPos
    decision = []
    for i in range(GAMENUM):
        # only nextPos, ignore bounceX, bounceY
        bulletNextPos = [updatePos(x.pos, x.speed)[2:] for x in bulletLists[i]]
        playerNextPos = playerLists[i].pos
        pwn.log.info('############')
        pwn.log.info('# Decision #')
        pwn.log.info('############')
        bulletCurrentPos = [x.pos for x in bulletLists[i]]
        print(f'bulletCurrentPos: {bulletCurrentPos}')
        print(f'bulletNextPos: {bulletNextPos}')
        print(f'playerCurrentPos: {playerPrevPos[i]}')
        print(f'playerNextPos: {playerNextPos}')
        current = bulletCurrentPos if swap else bulletNextPos

        if playerNextPos in current:# or playerNextPos in bulletCurrentPos: # At most 1
            pwn.log.info('####################################')
            pwn.log.info(f'# Collision will occur at game {i} #')
            pwn.log.info('####################################')
            pwn.log.info(f'Collision at {playerNextPos}')
            speedlist = [(-1, 0), (0, -1), (1, 0), (0, 1)]
            survival = False
            for j, speed in enumerate(speedlist):
                newPos = updatePos(playerPrevPos[i], speed)[2:] # ignoring bounce
                if newPos in current:
                    continue

                playerLists[i].pos = newPos
                playerLists[i].speed = speed
                decision.append((i, 'wasd'[j]))
                survival = True
                pwn.log.info(f'Updating to {newPos}')
                break
            if not survival:
                pwn.log.failure('############################')
                pwn.log.failure('### Collision inevitable ###')
                pwn.log.failure('############################')
                return ''

    print('### decision result ###')
    print(decision)
    payload = ''
    for i, direction in decision:
        if i < focus:
            payload += 'q' * (focus - i)
        elif i > focus:
            payload += 'e' * (i - focus)
        payload += direction
    print(f'payload: {payload}')
    print('#######################')

    return payload

PoW()
GAMENUM = 4
solver = Solver(GAMENUM)
bulletLists = [[] for _ in range(GAMENUM)]
playerLists = [None for _ in range(GAMENUM)]
playerPrevPos = [None for _ in range(GAMENUM)]
# c = solver.command
r = solver.roundUpdate
# first two rounds are free(no bullets are spawned!).
# Use this to track players: playerLists/playerPos1/playerPos2
# or just initialize it :C

playerPos1 = [None for _ in range(GAMENUM)]
playerPos2 = [None for _ in range(GAMENUM)]

r()

for i in range(GAMENUM):
    Map = solver.Maps[i]
    printMap(Map)
    _, player = findPos(Map)
    playerPos1[i] = player

r()

for i in range(GAMENUM):
    Map = solver.Maps[i]
    printMap(Map)
    _, player = findPos(Map)
    playerPos2[i] = player

# Now player velocity is determined!
# Update playerLists

for i in range(GAMENUM):
    y1, x1 = playerPos1[i]
    y2, x2 = pos = playerPos2[i]
    speed = y2 - y1, x2 - x1
    player = Player(pos, speed)
    player.update()
    playerLists[i] = player
    pwn.log.info(f'Player {i}: pos: {pos}, speed: {speed}')

for _ in range(200):
    bullet1 = [[] for _ in range(GAMENUM)]
    bullet2 = [[] for _ in range(GAMENUM)]
    bullet3 = [[] for _ in range(GAMENUM)]
    # Now new bullet fire for every three rounds

    p.sendline(decide(solver.focus))

    r()

    for i in range(GAMENUM):
        Map1 = solver.Maps[i]
        printMap(Map1)
        bullet1[i], player = findPos(Map1)
        playerPosCheck(i, playerLists[i].pos, player)

        print(f'bullet1[{i}]', bullet1[i])
        bulletUpdate(bulletLists[i])
        print('estimat', [bullet.pos for bullet in bulletLists[i]])
        # remove tracked bullets
        bullet1trash = []
        for x in [bullet.pos for bullet in bulletLists[i]]:
            if x in bullet1[i]:
                bullet1[i].remove(x)
                bullet1trash.append(x)
            elif x in bullet1trash:
                print(f'Bullet ({x}) overlapped')
            else:
                print(f'Tracing bullet ({x}) failed')
                #exit()

        print(f'bullet1[{i}]', bullet1[i])
        #assert len(bullet1[0]) == 1

    playerUpdate()

    p.sendline(decide(solver.focus))

    r()

    for i in range(GAMENUM):
        Map2 = solver.Maps[i]
        printMap(Map2)
        bullet2[i], player = findPos(Map2)
        playerPosCheck(i, playerLists[i].pos, player)

        print(f'bullet2[{i}]', bullet2[i])
        bulletUpdate(bulletLists[i])
        print('estimat', [bullet.pos for bullet in bulletLists[i]])
        # remove tracked bullets
        bullet2trash = []
        for x in [bullet.pos for bullet in bulletLists[i]]:
            if x in bullet2[i]:
                bullet2[i].remove(x)
                bullet2trash.append(x)
            elif x in bullet2trash:
                print(f'Bullet ({x}) overlapped')
            else:
                print(f'Tracing bullet ({x}) failed')
                #exit()

        print(f'bullet2[{i}]', bullet2[i])
        #assert len(bullet2[0]) == 1

    playerUpdate()

    for i in range(GAMENUM):
        if len(bullet1[i]) != len(bullet2[i]):
            pwn.log.failure(f'Game {i}: ')
            pwn.log.failure('New bullet overlapped {:d} {:d}'.format(len(bullet1[i]), len(bullet2[i])))

    # determine new bullet's pos and speed
    # At least two position needed

    for i in range(GAMENUM):
        bulletUpdate(bulletLists[i])
        if len(bullet1[i]) == len(bullet2[i]):
            y1, x1 = bullet1[i][0]
            y2, x2 = pos = bullet2[i][0]
            speed = y2 - y1, x2 - x1
            bullet = Bullet(pos, speed)
            bullet.update()
            bulletLists[i].append(bullet)
        else:
            pwn.log.info(f'Game {i}: ')
            pwn.log.info('New bullet overlapped, not adding estimat!')

    p.sendline(decide(solver.focus, True))

    r()

    for i in range(GAMENUM):
        Map3 = solver.Maps[i]
        bullet3[i], player = findPos(Map3)
        playerPosCheck(i, playerLists[i].pos, player)

        printMap(Map3)

        print(f'bullet3[{i}]', bullet3[i])
        print('estimat', [bullet.pos for bullet in bulletLists[i]])

        bullet3trash = []
        # check estimated postition
        for j, bullet in enumerate(bulletLists[i]):
            y, x = pos = bullet.pos
            pwn.log.info(f'I think bullet is at ({y}, {x})')
            if not pos in bullet3[i]:
                if pos in bullet3trash:
                    print(f'Bullet ({pos}) overlapped')
                else:
                    pwn.log.failure(f'{pos} was not in {bullet3[i]} or {bullet3trash}')
                    errorpos = pos
                    erroridx = j
                    pwn.log.info(f'Error correction: {errorpos} to {bullet3[i]}')
                    y1, x1 = bullet2[i][0]
                    y2, x2 = bulletLists[i][erroridx].pos = bullet3[i][0]
                    bulletLists[i][erroridx].speed = y2 - y1, x2 - x1
            else:
                pwn.log.info(f'Yes the bullet is at ({y}, {x})')
                bullet3[i].remove(pos)
                bullet3trash.append(pos)
                pwn.log.info(f'Bullet ({y}, {x}) removed')
                pwn.log.info(f'bullet3[{i}]: {bullet3[i]}')
                pwn.log.info(f'bullet2[{i}]: {bullet2[i]}')
                pwn.log.info(f'bullet1[{i}]: {bullet1[i]}')

        print(f'bullet3[{i}] final', bullet3[i])

        if len(bullet3[i]) != 0:
            pwn.log.info('New bullet was overlapped so not added')
            pwn.log.info(f'{bullet3[i]} are not tracked')

    playerUpdate()

flag = 'Defenit{dodg3_d0dg3_d0dge_d0dge_dodge}'
p.interactive()
