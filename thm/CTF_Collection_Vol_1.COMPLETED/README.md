# CTF Collection Vol 1

Laurent Chauvin | November 02, 2022

## Resources

## Progress

### Task 1 : Author Note

### Task 2 : What does the base said?

```
echo "VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==" | base64 -d

THM{ju57_d3c0d3_7h3_b453}
```

### Task 3 : Meta meta

```
exiftool Findme.jpg

Owner Name                      : THM{3x1f_0r_3x17}
``` 

### Task 4 : Mon, are we going to be okay?

```
stegseek Extinction.jpg /opt/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "Final_message.txt".
[i] Extracting to "Extinction.jpg.out".
```

```
cat Final_message.txt

It going to be over soon. Sleep my child.

THM{500n3r_0r_l473r_17_15_0ur_7urn}
```

### Task 5 : Erm......Magick

Flag is written in white

```
Huh, where is the flag? 
```

### Task 6 : QRrrrr

Scanning the QR code using a phone reveal (or you could use this website otherwise: https://zxing.org/w/decode.jspx)

```
THM{qr_m4k3_l1f3_345y}
```

### Task 7 : Reverse it or read it?

```
strings hello.hello | grep THM

THM{345y_f1nd_345y_60}
```

### Task 8 : Another decoding stuff

Using http://www.dcode.fr we identify a base58 encoding

```
THM{17_h45_l3553r_l3773r5}
```

#### Task 9 : Left or right

Rot19

```
THM{hail_the_caesar}
```

### Task 10 : Make a comment

Looking at source code

```
THM{4lw4y5_ch3ck_7h3_c0m3mn7} 
```

### Task 11 : Can you fix it?

PNG Magic numbers are ```89 50 4e 47 0d 0a 1a 0a```

Use ```hexedit``` to fix them (F2 to save file)

```
THM{y35_w3_c4n}
```

### Task 12 : Read it

Searching for ```TryHackMe rooms Reddit``` and following first link.

```
THM{50c14l_4cc0un7_15_p4r7_0f_051n7}
```

### Task 13 : Spin my head

http://www.dcode.fr says it's a Brainfuck cipher

```
THM{0h_my_h34d}
```

### Task 14 : An exclusive!

Using https://onlinehextools.com/xor-hex-numbers we can xor strings, and convert the results from hexadecimal to ASCII.

```
THM{3xclu51v3_0r}
```

### Task 15 : Binary walk

```
binwalk -e hell.jpg
```

```
cat hello_there.txt

Thank you for extracting me, you are the best!

THM{y0u_w4lk_m3_0u7}
```

### Task 16 : Darkness

The hint says to use stegsolve

```
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
```

Opening with ```stegsolve``` and playing with the arrow at the bottom to be in 'gray bits' reveal

```
THM{7h3r3_15_h0p3_1n_7h3_d4rkn355}
```

### Task 17 : A sounding QR

Using https://zxing.org/w/decode.jspx with the QR code gives us the URL 

https://soundcloud.com/user-86667759/thm-ctf-vol1

Which when listened spells

```
THM{SOUNDINGQR}
```

### Task 18 : Dig up the past

Using the wayback machine with URL https://web.archive.org/web/20200102131252/https://www.embeddedhacker.com/

```
THM{ch3ck_th3_h4ckb4ck}
```

### Task 19 : Uncrackable!

Hints says this is a Vigenere

Using http://www.dcode.fr we found (make sure it's specified the clear text is in English)

```
TRYHACKME{YOU_FOUND_THE_KEY}
```

### Task 20 : Small bases

Hints says 'dec -> hex -> ascii'

Use https://www.rapidtables.com/convert/number/decimal-to-hex.html to convert from decimal to hex, then https://www.rapidtables.com/convert/number/hex-to-ascii.html to convert from hex to ascii

```
THM{17_ju57_4n_0rd1n4ry_b4535}
```

### Task 21 : Read the packet

Use wireshark to open .pcapng file

Follow TCP Stream. Check last one.

```
THM{d0_n07_574lk_m3}
```
