# Locked KitKat Writeup

### zer0pts CTF 2020 - forensics 100

> We've extracted the internal disk from the Android device of the suspect. Can you find the pattern to unlock the device? Please submit the correct pattern here.

### Extract gesture.key

Mount given image and find `gesture.key` which contains hashed information of locked pattern.

```sh
$ mkdir tempdir
$ sudo mount -o loop android.4.4.x86.img tempdir
$ find tempdir/ -name gesture.key
```

Now bruteforce to get the lock pattern code. I used [GestureCrack](https://github.com/KieronCraggs/GestureCrack). Below is the output.

```
        The Lock Pattern code is [3, 2, 1, 5, 6, 4]

        For reference here is the grid (starting at 0 in the top left corner):

        |0|1|2|
        |3|4|5|
        |6|7|8|
```

Submit the pattern code to given server, and get the flag:

```
zer0pts{n0th1ng_1s_m0r3_pr4ct1c4l_th4n_brut3_f0rc1ng}
```
