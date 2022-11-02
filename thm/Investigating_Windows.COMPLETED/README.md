# Investigating Windows

Laurent Chauvin | November 01, 2022

## Resources

## Progress

1. Whats the version and year of the windows machine?

Going to Start -> Settings -> System -> About, we can find this is a 'Windows Server 2016'

2. Which user logged in last?

```
User accounts for \\EC2AMAZ-I8UHO76

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Jenny                    John                     
The command completed successfully.
```

Checking last login for each:
```
net user John | findstr "Last"
Last logon                   3/2/2019 5:48:32 PM 

net user Jenny | findstr "Last" 
Last logon                   Never 

net user Administrator | findstr "Last"
Last logon                   11/2/2022 12:06:54 AM                                                                                                                         

net user Guest | findstr "Last" 
Last logon                   Never 

net user DefaultAccount | findstr "Last" 
Last logon                   Never                                                                                                                      
```

Last login is from 'Administrator'.


3. When did John log onto the system last?

```
3/2/2019 5:48:32 PM
```

4. What IP does the system connect to when it first starts?

Let's check what is running at startup.

```
regedit

Go to: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

We find a key
```
C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt
```

Connecting to '10.34.2.3'

5. What two accounts had administrative privileges (other than the Administrator user)?

```
net user John | findstr "Administrator" 
Local Group Memberships      *Users

net user Jenny | findstr "Administrator"
Local Group Memberships      *Administrators *Users

net user Administrator | findstr "Administrator" 
Local Group Memberships      *Administrators 

C:\Users\Administrator>net user Guest | findstr "Administrator"
Local Group Memberships      *Administrators       *Guests  

C:\Users\Administrator>net user DefaultAccount | findstr "Administrator"
Local Group Memberships      *System Managed Group     
```

We find Jenny and Guest have Administrator privileges.

6. Whats the name of the scheduled task that is malicous.

Start -> Task Scheduler

We can find a task
```
Clean file system
```

That runs ```C:\TMP\nc.ps1 -l 1348```. Looks malicious.

7. What file was the task trying to run daily?

```nc.ps1```

8. What port did this file listen locally for?

Port 1348

9. When did Jenny last logon?

As we saw previously: Never

10. At what date did the compromise take place?

File has been created on
```
03/02/2019  04:37 PM            37,640 nc.ps1    
```

11. At what time did Windows first assign special privileges to a new logon?

Answer format: MM/DD/YYYY HH:MM:SS AM/PM

I think the Answer format should be: MM/DD/YYYY H:MM:SS AM/PM instead

Going to Start -> Event Viewer -> Windows Logs -> Security

We can find the 'Special Logon'

12. What tool was used to get Windows passwords?

```
  .#####.   mimikatz 2.0 alpha (x86) release "Kiwi en C" (Feb 16 2015 22:17:52)
 .## ^ ##.  
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 15 modules * * */


mimikatz(powershell) # sekurlsa::logonpasswords
```

13. What was the attackers external control and command servers IP?

We can see in 'C:\Windows\System32\driver\etc\hosts'
```
76.32.97.132 google.com
76.32.97.132 www.google.com
```
Which are not google IPs.

14. What was the extension name of the shell uploaded via the servers website?

Server is running at
```
C:\inetpub\wwwroot
```

We can find a file named ```shell.gif```.

However, there is another file ```tests.jsp``` which seems to be the answer. Not sure why.

15. What was the last port the attacker opened?

Go to Start -> Firewall -> Inbound Rules

```
Name	Group	Profile	Enabled	Action	Override	Program	Local Address	Remote Address	Protocol	Local Port	Remote Port	Authorized Users	Authorized Computers	Authorized Local Principals	Local User Owner	Application Package	

Allow outside connections for development		Public	Yes	Allow	No	Any	Any	Any	TCP	1337	Any	Any	Any	Any	Any	Any	
```

Answer: 1337

16. Check for DNS poisoning, what site was targeted?

We can look in ```hosts``` file:
```
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
10.2.2.2	update.microsoft.com 
127.0.0.1  www.virustotal.com 
127.0.0.1  www.www.com 
127.0.0.1  dci.sophosupd.com 
10.2.2.2	update.microsoft.com 
127.0.0.1  www.virustotal.com 
127.0.0.1  www.www.com 
127.0.0.1  dci.sophosupd.com 
10.2.2.2	update.microsoft.com 
127.0.0.1  www.virustotal.com 
127.0.0.1  www.www.com 
127.0.0.1  dci.sophosupd.com 
76.32.97.132 google.com
76.32.97.132 www.google.com
```
