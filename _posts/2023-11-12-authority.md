---
layout: post
title: "HTB AD Medium: Authority"
description: "Authority is a Medium rated AD machine on HTB."
categories: [CTF,HTB]
tags: [AD,Medium]
author: g
---

## Nmap
![Pasted image 20240714194937.png](/images/Pasted image 20240714194937.png){: .normal }
![Pasted image 20240714194933.png](/images/Pasted image 20240714194933.png){: .normal }
![Pasted image 20240714194927.png](/images/Pasted image 20240714194927.png){: .normal }
![Pasted image 20240714194923.png](/images/Pasted image 20240714194923.png){: .normal }

## _**Initial Foothold**_
### Enumerating SMB
Connecting to the SMB share without credentials results in the following output.
![Pasted image 20240714194914.png](/images/Pasted image 20240714194914.png){: .normal width="600" }


Download all files in the Development share.
![Pasted image 20240714194908.png](/images/Pasted image 20240714194908.png){: .normal }


Ansible vault can be found in `Automation/Ansible/PWM/defaults/main.yml`, save the following output of this file (first hash):
![Pasted image 20240714194902.png](/images/Pasted image 20240714194902.png){: .normal }


Now we can use ansible2john to generate a crackable hash.
![Pasted image 20240714194858.png](/images/Pasted image 20240714194858.png){: .normal }


Finally we can crack the hash using John: `!@#$%^&*`.
![Pasted image 20240714194853.png](/images/Pasted image 20240714194853.png){: .normal }


Now that we have the Ansible vault encrypted password we can decrypt all the encrypted Ansible playbooks stored in the main.yml file we find more credentials.
![Pasted image 20240714194847.png](/images/Pasted image 20240714194847.png){: .normal width="500" }


### Enumating HTTP (Port 8443)
We get redirected to /pwm.
![Pasted image 20240714194837.png](/images/Pasted image 20240714194837.png){: .normal }


Going to the configuration manager we can download the configuration, the config script tries to query the following address. We can replace this with our own IP and use responder to get the hash.
![Pasted image 20240714194832.png](/images/Pasted image 20240714194832.png){: .normal }


Modify the config file with your VPN IP.
![Pasted image 20240714194825.png](/images/Pasted image 20240714194825.png){: .normal width="600" }


Start responder `sudo responder -I tun0` and upload the new configuration file `svc_ldap:lDaP_1n_th3_cle4r!`.
![Pasted image 20240714194819.png](/images/Pasted image 20240714194819.png){: .normal }


We can use the found credentials to establish a shell using evil-winrm.
![Pasted image 20240714194815.png](/images/Pasted image 20240714194815.png){: .normal }



## _**Priv Esc**_
We can add machines to the domain using the SeMachineAccountPrivilege (addcomputer module impacket).
![Pasted image 20240714194808.png](/images/Pasted image 20240714194808.png){: .normal width="600" }


Using impacket to add a machine to the domain (password must be strong enough).
![Pasted image 20240714194804.png](/images/Pasted image 20240714194804.png){: .normal }


Next up we can request a certificate template from the server using the newly created machine account.
![Pasted image 20240714194758.png](/images/Pasted image 20240714194758.png){: .normal }


Examining the certificate we find out that it allows any computer in the domain to request an administrator certificate (Authority-CA, enrolle supplies subject True).
![Pasted image 20240714194754.png](/images/Pasted image 20240714194754.png){: .normal width="600" }


Before requesting the administrator certificate, add the following line to your hosts file.
![Pasted image 20240714194749.png](/images/Pasted image 20240714194749.png){: .normal width="600" }


Request administrator certificate.
![Pasted image 20240714194745.png](/images/Pasted image 20240714194745.png){: .normal }


We can now create 2 new certificates (one without private key and one without certificate).
![Pasted image 20240714194741.png](/images/Pasted image 20240714194741.png){: .normal }


We can use the 2 newly created certificates to change the administrator password.
![Pasted image 20240714194733.png](/images/Pasted image 20240714194733.png){: .normal }


Log in as adminstrator using evil-winrm.
![Pasted image 20240714194727.png](/images/Pasted image 20240714194727.png){: .normal }



## User.txt
![Pasted image 20240714194720.png](/images/Pasted image 20240714194720.png){: .normal width="600" }


## Root.txt
![Pasted image 20240714194714.png](/images/Pasted image 20240714194714.png){: .normal width="600" }


## You have PWNED!!!
![Pasted image 20240714194709.png](/images/Pasted image 20240714194709.png){: .normal }


### Sources
- [Decrypting Ansible Playbook](https://exploit-notes.hdks.org/exploit/cryptography/algorithm/ansible-vault-secret/)
- [Domain escalation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)