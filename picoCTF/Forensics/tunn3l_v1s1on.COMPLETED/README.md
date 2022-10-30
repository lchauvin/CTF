# tunn3l v1s1on

Laurent Chauvin | October 26, 2022


## Resources

https://en.wikipedia.org/wiki/BMP_file_format#Bitmap_file_header

## Progress

```
file tunn3l_v1s10n [output: tunn3l_v1s10n: data]
xxd tunn3l_v1s10n | less [start with 424d -> Bitmap image]
mv tunn3l_v1s10n tunn3l_v1s10n.bmp
hexeditor tunn3l_v1s10n.bmp [edit height of the image, too small for the image size, in 0x16. Replaced 01 by 03. Save as tunn3l_v1s10n_height_modified.bmp]
display tunn3l_v1s10n_height_modified.bmp
```

## Flag

picoCTF{qu1t3_a_v13w_2020}
