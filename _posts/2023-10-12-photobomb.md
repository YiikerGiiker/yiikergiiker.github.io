---
layout: post
title: "HTB Linux Easy: Photobomb"
description: "Photobomb is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240715104806.png](/images/Pasted image 20240715104806.png){: .normal }


Edit the hosts file and add the `photobomb.htb` domain:
![Pasted image 20240715104802.png](/images/Pasted image 20240715104802.png){: .normal width="500" }

## _**Initial Foothold**_

### Enumerating HTTP (port 80)
Webpage.
![Pasted image 20240715104757.png](/images/Pasted image 20240715104757.png){: .normal }

Pressing the `click here` button redirects to a /printer page that asks for credentials.
![Pasted image 20240715104751.png](/images/Pasted image 20240715104751.png){: .normal width="500" }

The error page reveals sinatra is running on the system.
![Pasted image 20240715104746.png](/images/Pasted image 20240715104746.png){: .normal width="500" }

In the photobomb.js file we find credentials: `pH0t0:b0Mb!`.
![Pasted image 20240715104740.png](/images/Pasted image 20240715104740.png){: .normal }

After logging into the /printer page we find a webpage that allows us to download images.
![Pasted image 20240715104736.png](/images/Pasted image 20240715104736.png){: .normal }

Using burpsuite to capture the request we can test for RCE, setting sleep for 5 seconds after the filetype makes the response time longer (6.633 millis instead of 1.633 millis).
![Pasted image 20240715104732.png](/images/Pasted image 20240715104732.png){: .normal }


### Gain shell
URL encode key characters in the payload.
![Pasted image 20240715104724.png](/images/Pasted image 20240715104724.png){: .normal }

Shell.
![Pasted image 20240715104720.png](/images/Pasted image 20240715104720.png){: .normal }


## _**Priv Esc**_
Sudo -l output.
![Pasted image 20240715104715.png](/images/Pasted image 20240715104715.png){: .normal }

The cleanup.sh script executes /opt/.bashrc.
![Pasted image 20240715104708.png](/images/Pasted image 20240715104708.png){: .normal }

In .bashrc the `enable -n` command is used, this command disables the built-in shell command (in this case `[`), this means that it will look through the path to find the command.
![Pasted image 20240715104911.png](/images/Pasted image 20240715104911.png){: .normal width="500" }

Craft payload with the name `[` (chmod +x).
![Pasted image 20240715104658.png](/images/Pasted image 20240715104658.png){: .normal width="500" }

Become root:
![Pasted image 20240715104648.png](/images/Pasted image 20240715104648.png){: .normal }



## User.txt
![Pasted image 20240715104643.png](/images/Pasted image 20240715104643.png){: .normal width="400" }


## Root.txt
![Pasted image 20240715104639.png](/images/Pasted image 20240715104639.png){: .normal width="400" }


## You have PWNED
![Pasted image 20240715104632.png](/images/Pasted image 20240715104632.png){: .normal }


### Sources
- [enable -n](https://linuxcommand.org/lc3_man_pages/enableh.html)