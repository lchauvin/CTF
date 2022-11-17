# Juicy Details

Laurent Chauvin | November 17, 2022

## Resources

## Progress

### Task 1 : Introduction

### Task 2 : Reconnaissance

1. What tools did the attacker use? (Order by the occurrence in the log)

Looking at the 'access.log' we find the tools used in chronological order:

- nmap (seen in the User Agent)
- Hydra (seen in the User Agent when attempting bruteforcing)
- sqlmap (for SQLi)
- curl
- feroxbuster

2. What endpoint was vulnerable to a brute-force attack?

As we can see during the bruteforce attack, the vulnerable endpoint is ```/rest/user/login```

3. What endpoint was vulnerable to SQL injection?

As we can see at the end of the log, the vulnerable injection point for SQL is ```/rest/products/search```

4. What parameter was used for the SQL injection?

The parameter used for the injection is ```q```

5. What endpoint did the attacker try to use to retrieve files? (Include the /)

The endpoint the attacker tried to use to retrieve files is ```/ftp```

### Task 3 : Stolen data

1. What section of the website did the attacker use to scrape user email addresses?

We can see at the beginning of the attack that the attackers requested a lot of information for ```Product Review``` (e.g. '/rest/products/1/reviews')

2. Was their brute-force attack successful? If so, what is the timestamp of the successful login? (Yay/Nay, 11/Apr/2021:09:xx:xx +0000)

We can see on this line that their bruteforce attack was successful

```
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
```

And we have the timestamp

```Yay, 11/Apr/2021:09:16:31 +0000```

3. What user information was the attacker able to retrieve from the endpoint vulnerable to SQL injection?

By searching for 'FROM%20Users' in the document, we can find 4 occurences, url encoded which decode for 2 of them as

```
UNION SELECT '1', '2', '3', '4', '5', '6', '7', '8', '9' FROM Users
```

and 2 of them that decode as

```
UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users
```

which show attackers extracted ```email,password```

4. What files did they try to download from the vulnerable endpoint? (endpoint from the previous task, question #5)

Checking 'vsftpd.log' we see attackers tried to download

```
coupons_2013.md.bak, www-data.bak
```

5. What service and account name were used to retrieve files from the previous question? (service, username)

We can see they used an ftp with anonymous connection in the line '[ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "?"'

```
ftp,anonymous
```

6. What service and username were used to gain shell access to the server? (service, username)

By looking at 'auth.log' we can see on line 'Apr 11 09:39:37 thunt sshd[8232]: Failed password for www-data from 192.168.10.5 port 40084 ssh2' attackers used ssh with username 'www-data' to gain access

```
ssh,www-data
```
