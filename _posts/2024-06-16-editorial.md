---
layout: post
title: "Editorial"
description: "Editorial is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap Scan
![Pasted image 20240715112509.png](/images/Pasted image 20240715112509.png){: .normal }


Modify the hosts file and add the `editorial.htb` domain:
![Pasted image 20240715112504.png](/images/Pasted image 20240715112504.png){: .normal width="400"}


## Enumerate HTTP (Port 80)
Trigger the SSRF payload by pressing "Preview". Use the Kali IP as the payload.
![Pasted image 20240715112459.png](/images/Pasted image 20240715112459.png){: .normal }
![Pasted image 20240715112455.png](/images/Pasted image 20240715112455.png){: .normal width="600" }

Using the Repeater tab in Burp we manually test internal ports using the SSRF vuln. We end up finding port 5000:
![Pasted image 20240715112450.png](/images/Pasted image 20240715112450.png){: .normal }

When we upload an image and use our SSRF, we can browse to the Response page in Burp to find the following API endpoints
![Pasted image 20240715112446.png](/images/Pasted image 20240715112446.png){: .normal }

For the next request we can try to enumerate the API endpoints. In the `/api/latest/metadata/messages/authors/` endpoint we end up finding sensitive information:
![Pasted image 20240715112440.png](/images/Pasted image 20240715112440.png){: .normal }
![Pasted image 20240715112434.png](/images/Pasted image 20240715112434.png){: .normal }


Since we know SSH is available on the machine we can use these credentials to log in:
![Pasted image 20240715112428.png](/images/Pasted image 20240715112428.png){: .normal width="500" }


User flag: `1b5f02e974b28e2a15ad1a6eb9f0800b`
![Pasted image 20240715112423.png](/images/Pasted image 20240715112423.png){: .normal width="500" }



## Lateral movement
Found a second pair of credentials in the git logs.
![Pasted image 20240715112419.png](/images/Pasted image 20240715112419.png){: .normal }
![Pasted image 20240715112414.png](/images/Pasted image 20240715112414.png){: .normal }


## Privilege Escalation
Sudo -l output
![Pasted image 20240715112410.png](/images/Pasted image 20240715112410.png){: .normal }


We are able to use the following CVE to get the root flag: [CVE](https://github.com/gitpython-developers/GitPython/issues/1515?source=post_page-----0fba80ca64e8--------------------------------)
![Pasted image 20240715112405.png](/images/Pasted image 20240715112405.png){: .normal }


## PWNED!!!
![Pasted image 20240715112359.png](/images/Pasted image 20240715112359.png){: .normal }