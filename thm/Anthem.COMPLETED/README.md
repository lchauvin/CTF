# Anthem

Laurent Chauvin | April 05, 2024

## Resources

## Progress

```
export IP=10.10.165.200
```
### Task 1 : Website Analysis

1. Let's run nmap and check what ports are open.

Running nmap scan:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 00:35 EDT
Nmap scan report for 10.10.165.200
Host is up (0.091s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Anthem.com - Welcome to our blog
| http-robots.txt: 4 disallowed entries 
|_/bin/ /config/ /umbraco/ /umbraco_client/
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-04-05T04:35:46+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2024-04-04T04:21:44
|_Not valid after:  2024-10-04T04:21:44
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-05T04:35:41+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.09 seconds
```

2. What port is for the web server?

`80`

3. What port is for remote desktop service?

`3389`

4. What is a possible password in one of the pages web crawlers check for?

Going to $IP/robots.txt we find:

```
UmbracoIsTheBest!

# Use for all search robots
User-agent: *

# Define the directories not to crawl
Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/
```

5. What CMS is the website using?
```
Umbraco
```

6. What is the domain of the website?
```
anthem.com
```

7. What's the name of the Administrator

Looking at the website, we can find a post about the IT admin with a poem about him:
```
Born on a Monday,
Christened on Tuesday,
Married on Wednesday,
Took ill on Thursday,
Grew worse on Friday,
Died on Saturday,
Buried on Sunday.
```

After a search, this is a poem written by `Solomon Grundy`.

8. Can we find find the email address of the administrator?

We found the email address of author Jane Doe is jd@anthem.com, so we could assume the email address of the admin `Solomon Grundy` would be `sg@anthem.com`.

### Task 2 : Spot the flags

1. What is flag 1?

Searching for '{' in the page http://10.10.165.200/archive/we-are-hiring/ we can find in the metadata:

```html
<meta content="THM{L0L_WH0_US3S_M3T4}" property="og:description">
```

2. What is flag 2?

Inspecting the source code (searching for '{') we can find in the search bar:

```html
<input type="text" name="term" placeholder="Search... 								THM{G!T_G00D}">
```

with the flag `THM{G!T_G00D}`.

3. What is flag 3?

Going to http://10.10.165.200/authors/jane-doe/ we can find the flag `THM{L0L_WH0_D15}`

4. What is flag 4?

Searching for '{' in the page http://10.10.165.200/archive/a-cheers-to-our-it-department/ we can find in the metadata:

```html
<meta content="THM{AN0TH3R_M3TA}" property="og:description">
```

### Task 3 : Final stage

1. Let's figure out the username and password to log in to the box.(The box is not on a domain)

This one is a bit tricky as we have several options. I initially thought we were supposed to login as Jane Doe, as we are required after to get a `user.txt` and find the root password.
However, after multiple tries, I tried to login as the admin `Solomon Grundy`, with his first name, last name, both together, and then with its initials, like in its email.
For the password, I used the one found in `robots.txt`.

2. Gain initial access to the machine, what is the contents of user.txt?

I connected using Remmina, with the username `SG` and password `UmbracoIsTheBest!`.
Opening the file `user.txt` reveal the flag `THM{N00T_NO0T}`

3. Can we spot the admin password?

By looking around (with hidden files visible), we can see a directory `backup` in `C:` with a file `restore.txt` in it. When trying to open, it says we don't have the permissions.
However, we can go in the properties, and change the permissions to give us read access. 

Then we find the password `ChangeMeBaby1MoreTime`.

4.

Now that we have the administrator password, let's check it's home directory in `C:\Users\Administrator` and more particularly in `Desktop` where we find a `root.txt` file with the flag `THM{Y0U_4R3_1337}`.

## Flag

1. User

```
THM{N00T_NO0T}
```

2. Privesc

```
THM{Y0U_4R3_1337}
```
