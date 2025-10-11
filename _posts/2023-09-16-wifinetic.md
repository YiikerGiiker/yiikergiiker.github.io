---
layout: post
title: "HTB Linux Easy: Wifinetic"
description: "Wifinetic is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240715102032.png](/images/Pasted image 20240715102032.png){: .normal }


## Initial foothold
Log in as the anonymous user over FTP and retrieve all files:
![Pasted image 20240715102017.png](/images/Pasted image 20240715102017.png){: .normal }

Retrieved files:
![Pasted image 20240715102023.png](/images/Pasted image 20240715102023.png){: .normal }

In MigrateOpenWrt we find a possible attack vector using Reaver.
![Pasted image 20240715102009.png](/images/Pasted image 20240715102009.png){: .normal width="500" }

Decompress the tar file and explore contents to discover configuration files.
![Pasted image 20240715102001.png](/images/Pasted image 20240715102001.png){: .normal width="400" }

In etc/config/wireless we find a possible password: `VeRyUniUqWiFIPasswrd1!`.
![Pasted image 20240715101956.png](/images/Pasted image 20240715101956.png){: .normal width="400" }

Lastly, the passwd file can be found in the etc folder. Possible bruteforce SSH attack vector?
![Pasted image 20240715101948.png](/images/Pasted image 20240715101948.png){: .normal width="500" }

Let's try to bruteforce SSH with the users and password that we found, start by saving all the usernames to a file.
![Pasted image 20240715101930.png](/images/Pasted image 20240715101930.png){: .normal width="450"}

Use Hydra `netadmin:VeRyUniUqWiFIPasswrd1!`.
![Pasted image 20240715101926.png](/images/Pasted image 20240715101926.png){: .normal }

SSH into the box as the netadmin user.
![Pasted image 20240715101922.png](/images/Pasted image 20240715101922.png){: .normal }


## Priv Esc
Since we havent used the reaver hint we should probably try to take a look at that, In order to use reaver properly we need to know what interface to attack. Ifconfig reveals 2 possible wlan interfaces that have IP addresses (wlan0 and wlan1).
![Pasted image 20240715101903.png](/images/Pasted image 20240715101903.png){: .normal }

However when we take a look at the wpa_supplicant service which is used for wireless networking we can verify that wlan1 is the listening interface, this means that wlan0 is the AP interface.
![Pasted image 20240715101915.png](/images/Pasted image 20240715101915.png){: .normal }

In the man page we can verify what -i means.
![Pasted image 20240715101857.png](/images/Pasted image 20240715101857.png){: .normal }

Alternatively we can use iwconfig to find out which interface is set to master aka used as the AP.
![Pasted image 20240715101852.png](/images/Pasted image 20240715101852.png){: .normal }


Now that we know what interface to attack all we have to know now is what interface to use for our attack, we'll need a monitoring interface which in this case is mon0, let's bruteforce the wps pin to retrieve the wifi password: `WhatIsRealAnDWhAtIsNot51121!`.
![Pasted image 20240715101848.png](/images/Pasted image 20240715101848.png){: .normal }


Now we can use the newly found password to rebruteforce SSH: `root:WhatIsRealAnDWhAtIsNot51121!`.
![Pasted image 20240715101842.png](/images/Pasted image 20240715101842.png){: .normal }


Now SSH as root.
![Pasted image 20240715101837.png](/images/Pasted image 20240715101837.png){: .normal }


## User.txt
![Pasted image 20240715101833.png](/images/Pasted image 20240715101833.png){: .normal width="400" }


## Root.txt
![Pasted image 20240715101828.png](/images/Pasted image 20240715101828.png){: .normal width="400" }


## PWNED
![Pasted image 20240715101822.png](/images/Pasted image 20240715101822.png){: .normal }


### Sources
- [Reaver](https://www.kali.org/tools/reaver/)
- [Find interface](https://www.youtube.com/watch?v=jJqTpTK6ydA&ab_channel=CYBERFREQ)