# Shop

Laurent Chauvin | October 27, 2022

## Resources

## Progress

```
wget https://mercury.picoctf.net/static/f7b8db17d0891fb38c01a716052d1c04/source
nc mercury.picoctf.net 24851
```

Couldn't find a good debugger. Ghidra cannot start debugger (Java issue, couldn't fix). Radare2 is too fucking complicated to use. IDA got me somewhere, but while I found the value to check, it kept changing in memory.


I noticed that we could bought negative amount of items, giving us a lot of money.

After checking writeup, I realized that option 2 was a 'fruitful flag'. Didn't see it before.

With enough money you could buy it.

Returned:
```
Flag is:  [112 105 99 111 67 84 70 123 98 52 100 95 98 114 111 103 114 97 109 109 101 114 95 53 51 50 98 99 100 57 56 125]
```

Run:
```
python3 decode.py
```

## Flag

picoCTF{b4d_brogrammer_532bcd98}
