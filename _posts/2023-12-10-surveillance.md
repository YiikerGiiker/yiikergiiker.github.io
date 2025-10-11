---
layout: post
title: "HTB Linux Medium: Surveillance"
description: "Surveillance is a Medium rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240714205848.png](/images/Pasted image 20240714205848.png){: .normal }

Add the `surveillance.htb` domain to the hosts file.
![Pasted image 20240714205841.png](/images/Pasted image 20240714205841.png){: .normal width="450"}

## _**Initial Foothold**_
### Enumerate HTTP (Port 80)
Webpage.
![Pasted image 20240714205836.png](/images/Pasted image 20240714205836.png){: .normal }

The website uses craft CMS (Possible CVE).
![Pasted image 20240714205830.png](/images/Pasted image 20240714205830.png){: .normal width="550"}

Dir busting.
![Pasted image 20240714205825.png](/images/Pasted image 20240714205825.png){: .normal }

Craft CMS exploit (run PHP code).
![Pasted image 20240714205821.png](/images/Pasted image 20240714205821.png){: .normal }


### Shell
Use the Python script to gain shell access (remove proxy to localhost).
![Pasted image 20240714205817.png](/images/Pasted image 20240714205817.png){: .normal width="500" }


## _**Lateral Movement**_
### Upgrade to meterpreter session
Generate payload using msfvenom.
![Pasted image 20240714205807.png](/images/Pasted image 20240714205807.png){: .normal }

Upload the payload to the box.
![Pasted image 20240714205812.png](/images/Pasted image 20240714205812.png){: .normal width="600" }

Set up listener in Metasploit
![Pasted image 20240714205804.png](/images/Pasted image 20240714205804.png){: .normal width="600" }

Make the ELF file payload executable, then execute it to trigger the reverse shell in Metasploit.
![Pasted image 20240714205755.png](/images/Pasted image 20240714205755.png){: .normal width="200"}

Improved shell.
![Pasted image 20240714205748.png](/images/Pasted image 20240714205748.png){: .normal }


### Enumerate filesystem
Whilst enumerating the filesystem we come across an SQL backup ZIP file.
![Pasted image 20240714205744.png](/images/Pasted image 20240714205744.png){: .normal }

Download the file and check out its contents to reveal a password hash for the admin user.
![Pasted image 20240714205741.png](/images/Pasted image 20240714205741.png){: .normal }


### Shell as matthew
We can use crackstation.net to bruteforce the password `matthew:starcraft122490`.
![Pasted image 20240714205736.png](/images/Pasted image 20240714205736.png){: .normal }

SSH into the box as the matthew user
![Pasted image 20240714205731.png](/images/Pasted image 20240714205731.png){: .normal }


### Enumerate as matthew
Using the www-data user we find that port 8080 is only listening on the localhost, we can use ssh port forwarding to access this page.
![Pasted image 20240714205727.png](/images/Pasted image 20240714205727.png){: .normal }

Webpage.
![Pasted image 20240714205722.png](/images/Pasted image 20240714205722.png){: .normal }

Zoneminder has Metasploit modules.
![Pasted image 20240714205719.png](/images/Pasted image 20240714205719.png){: .normal }

Select and configure the exploit.
![Pasted image 20240714205714.png](/images/Pasted image 20240714205714.png){: .normal }

## _**Priv Esc**_
### Enumerate as zoneminder
Sudo -l output.
![Pasted image 20240714205711.png](/images/Pasted image 20240714205711.png){: .normal }


### Become root
Create rev.sh payload in the /tmp directory.
![Pasted image 20240714205708.png](/images/Pasted image 20240714205708.png){: .normal width="600" }

Run the following command.
![Pasted image 20240714205700.png](/images/Pasted image 20240714205700.png){: .normal }

You should now have a root shell.
![Pasted image 20240714205656.png](/images/Pasted image 20240714205656.png){: .normal width="600" }


## User.txt
![Pasted image 20240714205650.png](/images/Pasted image 20240714205650.png){: .normal width="400"}


## Root.txt
![Pasted image 20240714205642.png](/images/Pasted image 20240714205642.png){: .normal width="400"}


## You have PWNED
![Pasted image 20240714205636.png](/images/Pasted image 20240714205636.png){: .normal }


### Sources
- [Craft CMS](https://threatprotect.qualys.com/2023/09/25/craft-cms-remote-code-execution-vulnerability-cve-2023-41892/)
- [Craft CMS RCE](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce)