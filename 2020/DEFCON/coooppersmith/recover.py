n = 16560379602206469878642040724734782524471652184425568199376531218304959723079099494061696962898146302790990640308166046320996547003199970357682771281249444627288194940908457745348616259707293222668519330090699453824892126571382412313626098908456043505552225398755139173074200557063668562681181037016907178765434766138977799967705623358615398130863910258580093283414781103145514263119654540542844577475636596835335294772173922782276008155166627081245441786606779731368870953008009168947172908703060792853824608604243742851935101696271394947461262657372822142026376864657914137999684052968427854408796623411405505211057

start = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000

while True:
    if (n - 1) % start == 0:
        print(start)
        exit()
    start += 1
    if start & 0xffff == 0:
        print(hex(start & 0xffffffff))


