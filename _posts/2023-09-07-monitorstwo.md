---
layout: post
title: "MonitorsTwo"
description: "MonitorsTwo is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

### Nmap
![Pasted image 20240715105628.png](/images/Pasted image 20240715105628.png){: .normal }

## _**Initial Foothold**_

### Website Enumeration
Visiting the website reveals a vulnerable version of cacti (CVE-2022-46169)
![Pasted image 20240715105623.png](/images/Pasted image 20240715105623.png){: .normal }


### Exploiting the vulnerability
Setup a nc listener and run the Python exploit:
![Pasted image 20240715105619.png](/images/Pasted image 20240715105619.png){: .normal }
![Pasted image 20240715105614.png](/images/Pasted image 20240715105614.png){: .normal }


## _**Privilege Escalation**_

### Escaping the docker container
Priv esc (sticky bit on /sbin/capsh)
![Pasted image 20240715105601.png](/images/Pasted image 20240715105601.png){: .normal }

Become the root user of the docker container.
![Pasted image 20240715105607.png](/images/Pasted image 20240715105607.png){: .normal width="500" }

DB credentials in [entrypoint.sh](http://entrypoint.sh/).
![Pasted image 20240715105557.png](/images/Pasted image 20240715105557.png){: .normal }

Using the SQL credentials we find password hashes in the user_auth table.
![Pasted image 20240715105553.png](/images/Pasted image 20240715105553.png){: .normal }

We cracked the hash for the marcus user: (funkymonkey).
![Pasted image 20240715105550.png](/images/Pasted image 20240715105550.png){: .normal }

We can now SSH into the box:
![Pasted image 20240715105544.png](/images/Pasted image 20240715105544.png){: .normal }


### Getting root
Running Linpeas:
![Pasted image 20240715105539.png](/images/Pasted image 20240715105539.png){: .normal }

Root owned mail? Let's check it out:
![Pasted image 20240715105535.png](/images/Pasted image 20240715105535.png){: .normal }

We can use the last CVE since docker is not up to date:
![Pasted image 20240715105531.png](/images/Pasted image 20240715105531.png){: .normal width="500" }

Step 1: is to assign a sticky bit to /bin/bash in the docker environment.
![Pasted image 20240715105526.png](/images/Pasted image 20240715105526.png){: .normal width="600" }

Step 2: we execute the exploit.
![Pasted image 20240715105522.png](/images/Pasted image 20240715105522.png){: .normal }


## User.txt
![Pasted image 20240715105516.png](/images/Pasted image 20240715105516.png){: .normal width="400" }


## Root.txt
![Pasted image 20240715105512.png](/images/Pasted image 20240715105512.png){: .normal width="400" }


## PWNED
![Pasted image 20240715105507.png](/images/Pasted image 20240715105507.png){: .normal }


### Sources:
- [Cacti CVE](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22/blob/main/CVE-2022-46169.py)
- [Capsh PrivEsc](https://gtfobins.github.io/gtfobins/capsh/#suid)
- [docker PrivEsc](https://github.com/UncleJ4ck/CVE-2021-41091/blob/main/README.md)