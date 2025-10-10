---
layout: post
title: "Devvortex"
description: "Devvortex is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240715101112.png](/images/Pasted image 20240715101112.png){: .normal }

Add the `devvortex.htb` domain to the hosts file:
![Pasted image 20240715101108.png](/images/Pasted image 20240715101108.png){: .normal width="450" }


## _**Initial Foothold**_
Located the `dev` subdomain using ffuf (add the subdomain to the hosts file).
![Pasted image 20240715101103.png](/images/Pasted image 20240715101103.png){: .normal }


In robots.txt we find the following entries.
![Pasted image 20240715101058.png](/images/Pasted image 20240715101058.png){: .normal }


Version found in the README.txt file (Joomla! CMS 4.2).
![Pasted image 20240715101054.png](/images/Pasted image 20240715101054.png){: .normal }


Looking for exploits we find an exploit that will give us credentials of users.
![Pasted image 20240715101049.png](/images/Pasted image 20240715101049.png){: .normal width="550" }

We can use these credentials to log into the /administrator panel `lewis:P4ntherg0t1n5r3c0n##`.
![Pasted image 20240715101044.png](/images/Pasted image 20240715101044.png){: .normal }


On the webpage, go to: system > extensions and upload the zip file from the github repo, next go to manage extensions and filter by date, you should now see your webshell.
![Pasted image 20240715101041.png](/images/Pasted image 20240715101041.png){: .normal }


You should now have RCE.
![Pasted image 20240715101037.png](/images/Pasted image 20240715101037.png){: .normal }


Gain a shell: step 1, start the Python server and create the payload file.
![Pasted image 20240715101033.png](/images/Pasted image 20240715101033.png){: .normal }


Next, start a nc listener and run your exploit.
![Pasted image 20240715101029.png](/images/Pasted image 20240715101029.png){: .normal }


You should now have a shell as www-data.
![Pasted image 20240715101025.png](/images/Pasted image 20240715101025.png){: .normal }



## _**Lateral Movement**_
Log in to the MySQL database.
![Pasted image 20240715101021.png](/images/Pasted image 20240715101021.png){: .normal }


Find usernames and password hashes in the MySQL database.
![Pasted image 20240715101016.png](/images/Pasted image 20240715101016.png){: .normal }


The password hash can be cracked using JohnTheRipper: `tequieromucho`.
![Pasted image 20240715101013.png](/images/Pasted image 20240715101013.png){: .normal }


SSH into the box using: `logan:tequieromucho`.
![Pasted image 20240715101008.png](/images/Pasted image 20240715101008.png){: .normal }


## _**Priv Esc**_
Sudo -l output:
![Pasted image 20240715101005.png](/images/Pasted image 20240715101005.png){: .normal }


Checking the version reveals the following version of apport-cli:
![Pasted image 20240715101001.png](/images/Pasted image 20240715101001.png){: .normal width="450" }


Start by generating a crash file.
![Pasted image 20240715100956.png](/images/Pasted image 20240715100956.png){: .normal width="600" }


Next up, run apport-cli as sudo and open the crash file.
![Pasted image 20240715100952.png](/images/Pasted image 20240715100952.png){: .normal }


Here, we press `V`. After the file has opened, we can get a shell by typing `!/bin/bash`.
![Pasted image 20240715100948.png](/images/Pasted image 20240715100948.png){: .normal width="450" }


## User.txt
![Pasted image 20240715100943.png](/images/Pasted image 20240715100943.png){: .normal width="450" }


## Root.txt
![Pasted image 20240715100939.png](/images/Pasted image 20240715100939.png){: .normal width="450" }


## You have PWNED
![Pasted image 20240715100934.png](/images/Pasted image 20240715100934.png){: .normal }


### Sources
- [ffuf usage](https://www.youtube.com/watch?v=of3jAxXrYUw)
- [Joomla! exploit](https://www.exploit-db.com/exploits/51334)
- [Joomla! webshell](https://github.com/p0dalirius/Joomla-webshell-plugin/tree/master)
- [Priv-Esc](https://flattsecurity.medium.com/cve-2020-15702-race-condition-vulnerability-in-handling-of-pid-by-apport-4047f2e00a67)
- [Priv-EscV2](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb)