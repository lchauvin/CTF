# Static ain't always noise

Laurent Chauvin | October 26, 2022

## Resources

## Progress

```
wget https://mercury.picoctf.net/static/e9dd71b5d11023873b8abe99cdb45551/static
wget https://mercury.picoctf.net/static/e9dd71b5d11023873b8abe99cdb45551/ltdis.sh
chmod +x ltdis.sh
./ltdis.sh static
cat static.ltdis.strings.txt| grep picoCTF{.*}
```

## Flag

picoCTF{d15a5m_t34s3r_ae0b3ef2}
