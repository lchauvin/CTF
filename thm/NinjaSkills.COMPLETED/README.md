# NinjaSkills

Laurent Chauvin | April 10, 2024

## Resources

## Progress

```
export IP=10.10.135.16
```

We can ssh with `new-user:new-user`.

First, let's find all the files with command `find / -name [filename] 2>/dev/null`:

8V2L: /etc/8V2L
bny0: Not found
c4ZX: /mnt/c4ZX
D8B3: /mnt/D8B3
FHl1: /var/FHl1
oiMO: /opt/oiMO
PFbD: /opt/PFbD
rmfX: /media/rmfX 
SRSq: /etc/ssh/SRSq
uqyw: /var/log/uqyw 
v2Vb: /home/v2Vb
X1Uy: /X1Uy

Let's make a list so we could execute commands:

```bash
declare -a arr=("/etc/8V2L" "/mnt/c4ZX" "/mnt/D8B3" "/var/FHl1" "/opt/oiMO" "/opt/PFbD" "/media/rmfX" "/etc/ssh/SRSq" "/var/log/uqyw" "/home/v2Vb" "/X1Uy"); for i in "${arr[@]}"; do [cmd] "$i"; done
```

1. Which of the above files are owned by the best-group group(enter the answer separated by spaces in alphabetical order)

```bash
declare -a arr=("/etc/8V2L" "/mnt/c4ZX" "/mnt/D8B3" "/var/FHl1" "/opt/oiMO" "/opt/PFbD" "/media/rmfX" "/etc/ssh/SRSq" "/var/log/uqyw" "/home/v2Vb" "/X1Uy"); for i in "${arr[@]}"; do ll "$i"; done
```

2. Which of these files contain an IP address?

Searching for IP

```bash
declare -a arr=("/etc/8V2L" "/mnt/c4ZX" "/mnt/D8B3" "/var/FHl1" "/opt/oiMO" "/opt/PFbD" "/media/rmfX" "/etc/ssh/SRSq" "/var/log/uqyw" "/home/v2Vb" "/X1Uy"); for i in "${arr[@]}"; do echo "$i";  grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$i";  done
```

3. Which file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94

```bash
declare -a arr=("/etc/8V2L" "/mnt/c4ZX" "/mnt/D8B3" "/var/FHl1" "/opt/oiMO" "/opt/PFbD" "/media/rmfX" "/etc/ssh/SRSq" "/var/log/uqyw" "/home/v2Vb" "/X1Uy"); for i in "${arr[@]}"; do echo "$i"; sha1sum "$i";  done
```

4. Which file contains 230 lines?

```bash
declare -a arr=("/etc/8V2L" "/mnt/c4ZX" "/mnt/D8B3" "/var/FHl1" "/opt/oiMO" "/opt/PFbD" "/media/rmfX" "/etc/ssh/SRSq" "/var/log/uqyw" "/home/v2Vb" "/X1Uy"); for i in "${arr[@]}"; do echo "$i"; cat "$i"  | wc -l;  done
```

All files contains 209 lines, so by deduction, the one with 230 lines should be the one we can't find.

5. Which file's owner has an ID of 502?

Let's find whos is user 502:

```bash
cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
saslauth:x:499:76:"Saslauthd user":/var/empty/saslauth:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
ec2-user:x:500:500:EC2 Default User:/home/ec2-user:/bin/bash
new-user:x:501:501::/home/new-user:/bin/bash
newer-user:x:502:503::/home/newer-user:/bin/bash
```

It's `newer-user`. Let's check which files he owns:

```bash
declare -a arr=("/etc/8V2L" "/mnt/c4ZX" "/mnt/D8B3" "/var/FHl1" "/opt/oiMO" "/opt/PFbD" "/media/rmfX" "/etc/ssh/SRSq" "/var/log/uqyw" "/home/v2Vb" "/X1Uy"); for i in "${arr[@]}"; do ll "$i"; done
```

5. Which file is executable by everyone?

With the same command as previous, we can find it.

## Flag

1. `D8B3 v2Vb`

2. `oiMO`

3. `c4ZX`

4. `bny0`

5. `X1Uy`

6. `8V2L`
