---
layout: post
title: "HTB Linux Easy: Pilgrimage"
description: "Pilgrimage is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240715110721.png](/images/Pasted image 20240715110721.png){: .normal }


## Initial foothold
The site redirects to `pilgrimage.htb`, add the domain to the hosts file.
![Pasted image 20240715110714.png](/images/Pasted image 20240715110714.png){: .normal width="400" }

Website:
![Pasted image 20240715110710.png](/images/Pasted image 20240715110710.png){: .normal }

In the Nmap scan we find a .git repository, we can retrieve the content in the.git directory using git-dumper.
![Pasted image 20240715110706.png](/images/Pasted image 20240715110706.png){: .normal }


Looking through the files we find an outdated version of ImageMagick that is being used to convert the images. This version of ImageMagick is vulnerable to LFI (local file inclusion) `CVE-2022-44268`.
![Pasted image 20240715110701.png](/images/Pasted image 20240715110701.png){: .normal }

In login.php we find a file location that is being used for database credentials `/var/db/pilgrimage`, using our previously mentioned exploit we can retrieve this file and get some credentials.
![Pasted image 20240715110656.png](/images/Pasted image 20240715110656.png){: .normal }

Create the payload.
![Pasted image 20240715110651.png](/images/Pasted image 20240715110651.png){: .normal }

Upload and retrieve the file and use the identify command to get more information.
![Pasted image 20240715110645.png](/images/Pasted image 20240715110645.png){: .normal width="500" }

Convert hex found in “Raw profile type” to utf8: `emily:abigchonkyboi123`.
![Pasted image 20240715110638.png](/images/Pasted image 20240715110638.png){: .normal width="300" }

SSH as emily:
![Pasted image 20240715110635.png](/images/Pasted image 20240715110635.png){: .normal }



## Priv Esc
Linpeas:
![Pasted image 20240715110631.png](/images/Pasted image 20240715110631.png){: .normal }

The malware.sh script uses a deprecated and vulnerable version of binwalk.
![Pasted image 20240715110626.png](/images/Pasted image 20240715110626.png){: .normal }



### Create payload
Use the Python script to generate a payload image.
![Pasted image 20240715110619.png](/images/Pasted image 20240715110619.png){: .normal }


### Gain shell
Setup a nc listener and transfer the payload into the /shrunk folder on the target host.
![Pasted image 20240715110615.png](/images/Pasted image 20240715110615.png){: .normal }

You should now have a shell as the root user.
![Pasted image 20240715110611.png](/images/Pasted image 20240715110611.png){: .normal width="500" }


## User.txt
![Pasted image 20240715110607.png](/images/Pasted image 20240715110607.png){: .normal width="400" }


## Root.txt
![Pasted image 20240715110603.png](/images/Pasted image 20240715110603.png){: .normal width="400" }


## Pwned
![Pasted image 20240715110558.png](/images/Pasted image 20240715110558.png){: .normal }


### Sources
- [git dumper](https://github.com/arthaud/git-dumper)
- [CVE-2022-44268](https://github.com/Sybil-Scan/imagemagick-lfi-poc)
- [Binwalk exploit](https://www.exploit-db.com/exploits/51249)