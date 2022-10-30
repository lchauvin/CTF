# Nice Netcat

Laurent Chauvin | October 26, 2022

## Resources

## Progress

```
nc mercury.picoctf.net 49039 > encoded_flag.txt
while read -r line; do printf \\$(printf "%o" $line); done < encoded_flat.txt
```
## Flag

picoCTF{g00d_k1tty!_n1c3_k1tty!_3d84edc8}
