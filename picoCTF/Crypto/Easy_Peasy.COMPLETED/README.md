# Easy Peasy

Laurent Chauvin | October 26, 2022

## Resources

http://www.crypto-it.net/eng/attacks/two-time-pad.html

## Progress

```
nc mercury.picoctf.net 11188 > encoded_flag.txt
wget https://mercury.picoctf.net/static/3cdfde8de474ba94b23aba4a2dfc7eeb/otp.py
subl otp.py
```

Inspection of otp.py seems to indicate KEY_LENGTH is 5000. Reusing same key after 50000 characters.
Flag XOR Key XOR Key = Flag

Where Flag XOR Key = 551e6c4c5e55644b56566d1b5100153d4004026a4b52066b4a5556383d4b0007

Sending it to be XORed again with same values will output the flag. Has to be done after 50000 characters.

```
python3 decode.py
```

## Flag

picoCTF{7904ff830f1c5bba8f763707247ba3e1}
