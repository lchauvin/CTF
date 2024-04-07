# Confidential

Laurent Chauvin | April 07, 2024

## Resources

## Progress

```
export IP=10.10.254.203
```

The challenge states that we should use the included VM view, but I don't really like it (not many tools installed).

So I started an ssh server on my local machine:

```bash
sudo systemctl start ssh
```

and sent the file from the target host to my local machine with `scp`.

One thing we notice with the pdf is that the 'page' behind looks a bit blurry (like a scan or a photo), while the red sign looks sharp. Could be a layer added to the PDF.
After some research, it seems PDF can have layers. We would need to find a way to remove a layer then.

Opening the file in `inkscape` and going to `Object -> Layers and Objects`, and hidding the first layer, we can hide the red sign and get access to the QR code, which give us the flag once scanned.

## Flag

```
flag{e08e6ce2f077a1b420cfd4a5d1a57a8d}
```
