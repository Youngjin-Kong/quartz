# Wheels — 실행 감사기록 (2026-08-21 인스턴스)

- 타겟 `192.168.248.202` / LHOST `192.168.45.207` (tun0)
- 결과: **부분 0/2 — 셸 미확보, foothold 블록**
- Kali 산출물: `~/PG/Wheels/` (19개, `writeup_notes.txt` 포함)

## 정찰

nmap `-sCV -p- -Pn -A`:
```
22/tcp open ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
80/tcp open http    Apache httpd 2.4.41 ((Ubuntu))  http-title: Wheels - Car Repair Services
```
UDP 미실시(웹 중심 판단). 웹은 무료 "CarServ" Bootstrap 템플릿 + 커스텀 인증(login/register/portal).

디렉터리(gobuster common/medium/raft-large, 인증 세션 포함):
```
index.html  login.php  register.php  portal.php(302->login.php)  config.php(200, 0 bytes)
assets/{check.php(302->login), header.php, footer.php}
css/ js/ img/ lib/   (server-status 403)
```
그 외 엔드포인트 전무. vhost 퍼징(subdomains-top5000, Host: FUZZ.wheels.serv / FUZZ.serv) → 없음.
whatweb 가 `info@wheels.serv` 노출 → hosts 등록했으나 default 와 동일 응답(별도 vhost 아님).

## 앱 로직 (관측)

- **register.php**: `username`(클라 pattern `[a-zA-Z0-9]+`, **서버 미강제** — `a'b`·`q'q` 등록됨),
  `email`(**UNIQUE** — 중복 시 `The email address is already registered!`), `password`.
  **사용자명 중복 허용, 이메일만 유니크.** verify 느림(~0.4s, bcrypt 추정).
- **login.php**: `username`+`password` → 302 index.html, `Congratulations, you are logged in!` /
  실패 `Username password combination is wrong!` (성공·미존재·오답 메시지 동일 = 사용자 열거 불가).
- **portal.php** "Employee Portal": 미로그인 302→login, 로그인(일반) → `<h1>Access Denied</h1>`(23B).
  admin/employee 게이트는 로그인 시 매칭된 행의 role/is_admin 을 세션에 담아 판정(파라미터 이전에 die).
- **check.php**: 로그인 상태만 검증(인증 시 200 빈응답, 미인증 302→login). portal 이 include 하는 게이트.

## 발견한 취약점 — first-row 로그인 + 사용자 열거

로그인이 **username 으로 첫 행을 조회한 뒤 그 한 행에 대해서만 password 검증**한다(중복 사용자명 존재 시).
증명(직렬):
```
register admin/P1(early) ; register admin/MyPass123
  login admin/P1 -> Congrat ;  login admin/MyPass123 -> wrong
register dupx/AAApass1 ; register dupx/BBBpass1
  login dupx/AAApass1 -> Congrat ; login dupx/BBBpass1 -> wrong
```
`WHERE username=? AND password=?`(양쪽 바인딩)이면 BBB 도 성공해야 하나 실패 → 첫 행 조회 구조.

**사용자 열거 오라클**: 새 비밀번호로 U 등록 후 U 로그인 실패 ⇒ U 는 이미 존재(내 행이 두 번째).
- ⚠️ register+login 은 **오염**된다(내 등록이 행이 되어 이후 검사가 거짓 양성). 병렬 xargs 는 레이스로 거짓 양성 대량 발생.
- **직렬 최초검사에서만 신뢰.** 확정 시드 계정: **`bob`** (bob/랜덤 → wrong, 최초검사). dung·eba 는 병렬 거짓양성(직렬 재검 시 Congrat=미존재).

## 반증한 것 (전부 시도했고 아님)

- **SQLi 전무**: login user/pass(time-based SLEEP, boolean, ffifdyop), register user/email/pass(time+boolean),
  저장 username 경유 2차 주입. 전부 prepared — 깔끔한 `wrong`, 지연 없음, 500 없음.
- **인증우회 전무**: `password[]`/`username[]` 배열, ffifdyop 매직해시, 사용자명 충돌(trailing space·대소문자),
  쿠키(role/admin/is_admin/level/...), `X-Forwarded-For: 127.0.0.1`. 전부 Access Denied.
- **mass-assignment 전무**: register 에 role/admin/is_admin/isadmin/usertype/type/access_level/user_level/
  level/privilege/is_employee/employee/staff/active/verified/approved/user_type/account_type/access/group/
  position/rank/... ~35개. 전부 Access Denied.
- **LFI 전무**: burp-parameter-names 를 config/login/register/index 에 (`/etc/passwd`, size-diff). 없음.
  config.php 를 파라미터로 출력시키는 시도(GET/POST) → 무출력.
- **소스유출 전무**: `*.php.bak`/`~`/`.swp`/`.phps`(부재파일도 403 = 전면차단)/`.git`. 없음. DB 덤프/CSV 없음.
- **크레덴셜 브루트 실패**: admin·bob 에 fasttrack + rockyou top-500/top-1500(hydra) + 수동 테마 비밀번호.
  히트 없음. bob 비밀번호는 rockyou top-1500 밖. verify ~0.4s/try → 온라인 브루트 비현실적.

## 블록 원인

employee/admin 세션이 필요한데, 로그인은 시드된 직원 행의 **비밀번호를 요구**하고 그 비밀번호는
온라인 브루트로는 실질적으로 못 뚫는다(bcrypt 추정, rockyou 상위 부재). 오프라인 크랙용 해시 확보 경로 없음
(SQLi/덤프 부재). bob 이 is_admin 인지도 portal 접근 없이는 확인 불가. **셸 0, 플래그 0/2.**

## 다음 후보 (총괄 판단용)

1. bob(및 다른 직렬-확정 시드 계정) 에 **더 긴 rockyou 브루트**(bcrypt라 시간당 ~수천 시도, 수 시간). Fundamental 답지 않음.
2. **직렬** 열거로 시드된 직원 계정 전수 파악 후, 그중 하나가 is_admin 이길 기대하고 타겟 브루트. 오염 관리 필요.
3. 놓친 벡터 재검토: 세션/PHP objekt, 2차 주입 정밀화, config.php 유출 재시도, UDP 스캔.
4. SSH(22) 직접 브루트 — 시드 웹 사용자가 시스템 계정일 가능성(근거 약함).

## 남긴 흔적 / 정리

- **정리 확인**: tmux 세션 0개(wh_nmap/wh_hydra/wh_bob/wh_enum/wh_enum2/wh_spray 전부 종료 확인).
  내 리스너 0개(`ss -lntp` — 5432 postgres·41187 로컬은 기존/무관). `hydra.restore`(154MB) 삭제.
- **박스에 남긴 것**: 등록으로 다수 더미 계정 생성(admin·administrator·tester1·dupx·firstname 다수·이메일 오라클/열거 잔여).
  **되돌리지 못함**(DB 접근 없음) — 박스 리버트로만 제거. 웹 로그·Apache access 로그에 내 스캔/브루트 흔적 다수(삭제 안 함).
- 산출물 로그 전부 보존(`hydra_*.txt`·`gobuster_root.txt`·`enum_users*.txt`·`writeup_notes.txt` 등). 0바이트 `spray.txt` 보존.
- 브루트 규모: hydra admin(rockyou, ~1500 시도 후 종료), hydra bob(rockyou, ~1500 시도 후 종료),
  이름 열거 register+login 약 2000+8700(병렬), 스프레이 일부. 총 수천~1만 요청대.

---

## 해결됨 (후속, 2026-08-21) — 완료 2/2

이 초기 기록의 "BLOCK" 은 웹 전문이 넘었다: 포털 게이트는 **가입 이메일 도메인 `@wheels.service`**(내가 본 `wheels.serv` 는 whatweb 오탐), 진짜 취약점은 포털 검색의 **XPath injection**(`portal.php:68`) → XML 평문 비번 → `ssh bob`.
권한상승(내 담당): 커스텀 SUID **`/opt/get-list`** 의 `system("/bin/cat /root/details/%s")` **명령주입**. `strchr` 가 `;|&` 만 막아 **`$()`** 로 우회 → `employees$(chmod +s /bin/bash)` → `bash -p` → root.
- user `dad9316cbb189a7deeeaf3106eaf489d` (/home/bob/local.txt) · root `f7769b4377f22a16f5ec85e7da8c4aca` (/root/proof.txt)
- 정리: `/bin/bash` 0755 복구 확인, `/tmp/.h` 삭제 확인. 전체 노트 → `03. PG/Wheels.md`(status/solved).
- 내 초기 "bcrypt 라 브루트 불가" 는 **맞았으나** 우회 불필요였음(XML 평문). 교훈은 6장.
