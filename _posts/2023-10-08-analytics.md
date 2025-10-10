---
layout: post
title: "Analytics"
description: "Analytics is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240715101403.png](/images/Pasted image 20240715101403.png){: .normal }

## _**Initial Foothold**_

### Enumerating HTTP (port 80)
The site redirects to `analytical.htb`, add the domain to the hosts file.
![Pasted image 20240715101358.png](/images/Pasted image 20240715101358.png){: .normal width="450" }


Visiting the login page results in a redirect to: `data.analytical.htb`, add the subdomain to the hosts file:
![Pasted image 20240715101354.png](/images/Pasted image 20240715101354.png){: .normal width="500" }


Login page to the Metabase platform: `subdomain data.analytical.htb`:
![Pasted image 20240715101343.png](/images/Pasted image 20240715101343.png){: .normal width="350" }



### Gain shell
Looking for Metabase vulnerabilities we find one with RCE: `CVE-2023-38646`, step 1 is retrieving the setup token on the `/api/session/properties` page.
![Pasted image 20240715101349.png](/images/Pasted image 20240715101349.png){: .normal }


Next up we can use the PoC to gain a reverse shell, modify the base64 string (base64 encode your own bash reverse shell and replace it in Burp). The request has to be sent with a POST to `/api/setup/validate`.
![Pasted image 20240715101336.png](/images/Pasted image 20240715101336.png){: .normal width="450" }
![Pasted image 20240715101330.png](/images/Pasted image 20240715101330.png){: .normal width="600" }


Your nc listener should have turned into a shell:
![Pasted image 20240715101325.png](/images/Pasted image 20240715101325.png){: .normal }



## _**Lateral movement**_
We know we are in a Docker container thanks to the `.dockerenv` file.
![Pasted image 20240715101320.png](/images/Pasted image 20240715101320.png){: .normal }


Credentials can be found in the environment variables: `metalytics:An4lytics_ds20223#`
![Pasted image 20240715101301.png](/images/Pasted image 20240715101301.png){: .normal width="400"}


Use these credentials to SSH as the metalytics user:
![Pasted image 20240715101257.png](/images/Pasted image 20240715101257.png){: .normal }



## _**Priv Esc**_
The system is vulnerable to the overlayfs kernel exploit, we can compile the C program on our host and then execute it on the target machine to get a root shell:
![Pasted image 20240715101250.png](/images/Pasted image 20240715101250.png){: .normal width="500" }



## User.txt
![Pasted image 20240715101245.png](/images/Pasted image 20240715101245.png){: .normal width="350" }

## Root.txt
![Pasted image 20240715101240.png](/images/Pasted image 20240715101240.png){: .normal width="350" }

## You have PWNED
![Pasted image 20240715101233.png](/images/Pasted image 20240715101233.png){: .normal }



### Sources
- [metabase RCE](https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/)
- [print env variables](https://www.geeksforgeeks.org/environment-variables-in-linux-unix/)
- [OverlayFS ubuntu](https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability)
- [OverlayFS github](https://github.com/briskets/CVE-2021-3493)