---
layout: post
title: "HTB Linux Easy: TwoMillion"
description: "TwoMillion is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap
![Pasted image 20240715110116.png](/images/Pasted image 20240715110116.png){: .normal }

## Enumerate HTTP (Port 80)
### Website redirects to `2million.htb`
Add the domain to the hosts file.
![Pasted image 20240715110109.png](/images/Pasted image 20240715110109.png){: .normal width="600" }

To sign up to the website we need an invitation code.
![Pasted image 20240715110103.png](/images/Pasted image 20240715110103.png){: .normal width="600" }


### Obtain invitation code
Analyzing the source code we find obfuscated js code.
![Pasted image 20240715110055.png](/images/Pasted image 20240715110055.png){: .normal }

Checking the js file in the debugger tab reveals function names:
![Pasted image 20240715110050.png](/images/Pasted image 20240715110050.png){: .normal }

We can generate an invite code using the "makeInviteCode function".
![Pasted image 20240715110045.png](/images/Pasted image 20240715110045.png){: .normal }


### Decrypt invitation code
The enctype is set to rot13 which can easily be converted using online converters.
![Pasted image 20240715110041.png](/images/Pasted image 20240715110041.png){: .normal }

We can obtain an invite code by sending a POST request to the API.
![Pasted image 20240715110037.png](/images/Pasted image 20240715110037.png){: .normal width="600" }

The code is still base64 encoded:
![Pasted image 20240715110032.png](/images/Pasted image 20240715110032.png){: .normal width="600" }


### Register
Enter the code and give some credentials to create an account.
![Pasted image 20240715110027.png](/images/Pasted image 20240715110027.png){: .normal width="600" }



### Obtain shell
On the website we can generate VPN configs, let's see what API calls happen using Burp (press connection pack on the access page).
![Pasted image 20240715110020.png](/images/Pasted image 20240715110020.png){: .normal }

Let's try to make an API call to /api to check for output.
![Pasted image 20240715110011.png](/images/Pasted image 20240715110011.png){: .normal width="500"}

Now we can try making an API call to /api/v1 to list other potential endpoints.
![Pasted image 20240715110003.png](/images/Pasted image 20240715110003.png){: .normal width="460"}

/api/v1/admin/settings/update looks very interesting, let's try to make an API call to it (dont forget to send a PUT request instead of a GET).
![Pasted image 20240715105958.png](/images/Pasted image 20240715105958.png){: .normal }

Looks like it wants json as the content type.
![Pasted image 20240715105953.png](/images/Pasted image 20240715105953.png){: .normal }

We need to specify an email.
![Pasted image 20240715105949.png](/images/Pasted image 20240715105949.png){: .normal }

And lastly we can set our user to admin.
![Pasted image 20240715105944.png](/images/Pasted image 20240715105944.png){: .normal }

Now that our user is admin we can try to create an admin VPN config, this works fine when we specify a username.
![Pasted image 20240715105939.png](/images/Pasted image 20240715105939.png){: .normal }

The OVPN config could be generated either using PHP or a bash script so let's check for command injection:
![Pasted image 20240715105936.png](/images/Pasted image 20240715105936.png){: .normal }


### Obtain shell
We have command injection! Let's get a reverse shell.
![Pasted image 20240715105930.png](/images/Pasted image 20240715105930.png){: .normal }

No response, this means that the shell was successful.
![Pasted image 20240715105926.png](/images/Pasted image 20240715105926.png){: .normal }


### Enumeration
Listing all the files and directories reveals a .env file. This is where PHP stores environment variables.
![Pasted image 20240715105920.png](/images/Pasted image 20240715105920.png){: .normal width="500" }

Credentials can be found in the .env file: `admin:SuperDuperPass123`.
![Pasted image 20240715105909.png](/images/Pasted image 20240715105909.png){: .normal width="400" }

Let's check /etc/passwd to see if the admin user exists.
![Pasted image 20240715105904.png](/images/Pasted image 20240715105904.png){: .normal width="600" }

SSH with found creds: `admin:SuperDuperPass123`
![Pasted image 20240715105859.png](/images/Pasted image 20240715105859.png){: .normal width="600" }


### User.txt
![Pasted image 20240715105854.png](/images/Pasted image 20240715105854.png){: .normal width="400" }


### Root.txt
While connecting with SSH we see that we got mail, let's check the mail content.
![Pasted image 20240715105847.png](/images/Pasted image 20240715105847.png){: .normal }

Googling for overlayfs vulnerability we find CVE-2023-0386, let's get it on the target machine.
![Pasted image 20240715105840.png](/images/Pasted image 20240715105840.png){: .normal }

Follow GitHub instructions to gain root access.
![Pasted image 20240715105833.png](/images/Pasted image 20240715105833.png){: .normal }
![Pasted image 20240715105828.png](/images/Pasted image 20240715105828.png){: .normal }

### Root flag:
![Pasted image 20240715105822.png](/images/Pasted image 20240715105822.png){: .normal width="500" }


## PWNED!!
![Pasted image 20240715105816.png](/images/Pasted image 20240715105816.png){: .normal }


### Sources
- [CVE](https://github.com/sxlmnwb/CVE-2023-0386)