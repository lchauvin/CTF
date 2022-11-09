# Sakura Room

Laurent Chauvin | November 08, 2022

## Resources

## Progress

### Task 1 : Introduction

1. Are you ready to begin?
```
Let's Go!
```

### Task 2 : Tip Off

1. What username does the attacker go by?

Looking at exif of the images, we can see the export filename contain the full path of the image, including the name of the home directory 'SakuraSnowAngelAiko'

```
exiftool sakurapwnedletter.svg 

ExifTool Version Number         : 12.44
File Name                       : sakurapwnedletter.svg
Directory                       : .
File Size                       : 850 kB
File Modification Date/Time     : 2022:11:08 23:28:09-05:00
File Access Date/Time           : 2022:11:08 23:28:22-05:00
File Inode Change Date/Time     : 2022:11:08 23:28:09-05:00
File Permissions                : -rw-r--r--
File Type                       : SVG
File Type Extension             : svg
MIME Type                       : image/svg+xml
Xmlns                           : http://www.w3.org/2000/svg
Image Width                     : 116.29175mm
Image Height                    : 174.61578mm
View Box                        : 0 0 116.29175 174.61578
SVG Version                     : 1.1
ID                              : svg8
Version                         : 0.92.5 (2060ec1f9f, 2020-04-08)
Docname                         : pwnedletter.svg
Export-filename                 : /home/SakuraSnowAngelAiko/Desktop/pwnedletter.png
Export-xdpi                     : 96
Export-ydpi                     : 96
Metadata ID                     : metadata5
Work Format                     : image/svg+xml
Work Type                       : http://purl.org/dc/dcmitype/StillImage
Work Title                      : 
```

### Task 3 : Reconnaissance

1. What is the full email address used by the attacker?

Using 'https://instantusername.com/' we can see this username has a GitHub account.

When looking at the repository, PGP caught my eye. We can find a public PGP key. After searching for a while, I found that it is possible to get email from PGP keys.

I used the Chrome 'Mailvelop' extension to import the PGP key, which revealed the email address

```
SakuraSnowAngel83@protonmail.com
```

2. What is the attacker's full real name?

Looking for the username 'SakuraSnowAngelAiko' on https://lullar-com-3.appspot.com/en reveal a linkedin profile linked to it with the name

```
Aiko Abe
```

### Task 4 : Unveil

1. What cryptocurrency does the attacker own a cryptocurrency wallet for?

When on his Github profile, we saw a repository 'ETH' which stands for 

```
Ethereum
```

2. What is the attacker's cryptocurrency wallet address?

When going into the repository, we can see a file 'miningscript'. When looking at the history, we can see the file has been updated. Clicking on the initial commit, we see

```
stratum://0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.Aiko:pswd@eu1.ethermine.org:4444
```

where '0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef.Aiko' is its wallet id.

3. What mining pool did the attacker receive payments from on January 23, 2021 UTC?

Using https://etherscan.io/ and entering the wallet id (https://etherscan.io/txs?a=0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef) we can hover the mouse on the 'Age' of the transactions to see the date.

Finding the one from January 23, 2021 UTC we can see it's from

```
Ethermine
```

4. What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet?

By looking at the list of transactions, we can see some transactions to

```
Tether: USDT Stablecoin
```

Where 'Tether' is another crypto.

### Task 5 : Taunt

1. What is the attacker's current Twitter handle?

Looking at the image, we can see a twitter username '@AikoAbe3', when searching it on Google, we find an account named

```
SakuraLoverAiko
```

2. What is the URL for the location where the attacker saved their WiFi SSIDs and passwords?

If we look through the posts on the twitter account, we can see it posted 2 screenshots of a hash with a title 'Regular WiFi and Passwords'. When looking at the comments, we can see the author saying that people will have to go on the Dark Web, and do a DEEP search to find the PASTE. Firing up Tor, we can go to the deeppaste onion service, and search for the hash given in the screenshot.

We then find the paste with the link

```
http://deepv2w7p33xa4pwxzwi2ps4j62gfxpyp44ezjbmpttxz3owlsp4ljid.onion/show.php?md5=b2b37b3c106eb3f86e2340a3050968e2
```

3. What is the BSSID for the attacker's Home WiFi?

Looking at the paste we can see his home SSID is 

```
DK1F-G
```

Let's go to https://wigle.net/

We use the SSID of the city 'HIROSAKI_FREE_Wi-Fi' to identify the city first (or we could search Hirosaki on Google), but we also saw on his Twitter account, he seems to be from Japan.

Once zooming in on Hirosaki city on wigle.net, we can filter by SSID, using his home SSID 'DK1F-G'. Wigle.net is not very well designed, and it can be difficult to spot the point on the map.

Once we found it, we have to zoom in ALL THE WAY. Sometimes you can click on the point to get info, but here, it was not working for some reason. Zooming all the way, will show the BSSID

```
84:af:ec:34:fc:f8
```

### Task 6 : Homebound

1. What airport is closest to the location the attacker shared a photo from prior to getting on their flight?

On the twitter account, we can see a retweet saying

```
Today, in Bethesda, the beginnings of 🌸 cherry blossom season 🌸
```

Looking for Bethesda nearest airport, we find it's Reagan Washington or

```
DCA
```

2. What airport did the attacker have their last layover in?

Making a Google Image search on the image of the Sakura Lounge, we find similar pictures from the Haneda Airport or 

```
HND
```

3. What lake can be seen in the map shared by the attacker as they were on their final flight home?

Going to google map, with satellite view, and going from Hirosaki toward Tokyo, we find a similar topography at the west of Fukushima. The lake is called the 

```
Lake Inawashiro
```

4. What city does the attacker likely consider "home"?

We saw earlier that his 'home' router is in the city of

```
Hirosaki
```
