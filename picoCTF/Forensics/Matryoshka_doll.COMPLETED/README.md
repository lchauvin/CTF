# Matryoshka doll

Laurent Chauvin | October 26, 2022

## Resources

## Progress

```
wget https://mercury.picoctf.net/static/1b70cffdd2f05427fff97d13c496963f/dolls.jpg
binwalk -e dolls.jpg
cd _dolls.jpg.extracted/base_images
binwalk -e 2_c.jpg
cd _2_c.jpg.extracted/base_images 
binwalk -e 3_c.jpg 
cd _3_c.jpg.extracted/base_images 
binwalk -e 4_c.jpg 
cd _4_c.jpg.extracted
cat flag.txt
```

## Flag

picoCTF{bf6acf878dcbd752f4721e41b1b1b66b}

