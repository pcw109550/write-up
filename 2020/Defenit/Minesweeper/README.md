# Minesweeper Writeup

### Defenit CTF 2020 - Misc 298 - 35 solves

> Can you solve the minesweeper in one minute? `nc minesweeper.ctf.defenit.kr 3333`

#### Observation

Straightforward task. Let me solve 16x16 size minesweeper less than a minute.
To solve the task, flag all 40 mines and unlock full map.

#### Exploit

Searched opensource since minesweeper is an old game. Used [this repo](https://github.com/madewokherd/mines) and slightly modifed to solve the game(solver uses python2).

1. Ask minesweeper solver the position with most safe space.
2. Unlock all safe space by repeating 1, until only 40 locked spaces left.
3. Flag all 40 leftover dangerous spaces.

Get flag: 

```
Defenit{min35w33p3r_i5_ezpz}
```

Minesweeper solver: [mines.py](mines.py)

Exploit code: [solve.py](solve.py)