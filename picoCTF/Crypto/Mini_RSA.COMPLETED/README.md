# Mini RSA

Laurent Chauvin | October 28, 2022

## Resources

[1] https://www.comparitech.com/blog/information-security/rsa-encryption/

[2] https://crypto.stackexchange.com/questions/64302/best-way-to-attack-a-small-e-and-small-m-rsa-problem

[3] https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Franklin-Reiter/exploit.sage

[4] https://crypto.stackexchange.com/questions/30884/help-understanding-basic-franklin-reiter-related-message-attack

[5] https://crypto.stackexchange.com/questions/6770/cracking-an-rsa-with-no-padding-and-very-small-e/6771#6771

## Progress

```
wget https://mercury.picoctf.net/static/81689952b7442c3e23a9f703198c0a4c/ciphertext
```

From [4] on Resources, here the c provided correspond to C2. As we know M^e is barely larger than N, we could use decreasing values starting from N as C1 (bruteforcing).

Then we could perform the Franklin Reiter attack.

In [5], they seems to say that we could calculate ```n*k + c``` that is a eth power, and where ```m = (k*n+c)^(1/e)``` 

Run:
```
python3 decode.py
```

## Flag

picoCTF{e_sh0u1d_b3_lArg3r_7adb35b1}
