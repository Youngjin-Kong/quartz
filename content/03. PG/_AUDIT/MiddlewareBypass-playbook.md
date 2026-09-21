# MiddlewareBypass → _PLAYBOOK 이관 제안

작성자: pg-note-forge (실무자, `_PLAYBOOK.md` 직접 수정 안 함). 반영은 `pg-line-manager` 단독.

---

## 제안 1 — 병합 → A-14. 공개 PoC는 실행 전에 소스를 읽는다

**병합인가 신규인가:** 병합 (기존 헤딩 `#### A-14. 공개 PoC는 실행 전에 소스를 읽는다`, 5126행 파일의 193행)

**넣을 본문:**

> **[[MiddlewareBypass]] — 대상 자체가 `localhost` 로 하드코딩돼 있었음.** EQSTLab/CVE-2025-29927 저장소의 `poc.sh` 원본(`git show HEAD:poc.sh`)은 `curl -v "http://localhost:3000/admin" -H "Host: localhost:3000"` 로 대상이 Kali 자기 자신으로 고정돼 있음. 그대로 실행하면 타겟이 아니라 로컬을 침.
> `~/.zsh_history` **2339~2347행** 순서 — `git clone` → `cd CVE-2025-29927` → `ls` → `chmod poc.sh`(모드 인자가 없어 실패) → `chmod 744 poc.sh` → `poc.sh`(경로 없이 실행 시도, PATH 미포함으로 실패 추정) → `vi poc.sh`(localhost→타겟 IP 편집) → `./poc.sh`(성공) → `ssh root@192.168.248.215`. (감사자 정정 — 작성자 신고 「2335~2340행」은 실제 행번호와 어긋났음)
> `git diff` 로 편집 사실이 작업 트리에 그대로 남아 있었음(원본 커밋 `995fda5`~`6a176ca` 대비):
> ```diff
> -curl -v "http://localhost:3000/admin" \
> -  -H "Host: localhost:3000" \
> +curl -v "http://192.168.248.215:3000/admin" \
> +  -H "Host: 192.168.248.215:3000" \
> ```
> → **"제품·버전·실행가능성" 확인 목록에 "대상이 하드코딩됐는가"를 추가할 것.** `curl`·`requests` 계열 PoC 는 `localhost`·`127.0.0.1`·예시 IP 가 박혀 있는 경우가 흔함(같은 항목의 Codo `127.0.0.1:8080` Burp 프록시 하드코딩과 같은 계열).

**지우기 전 원문 (개작 전 `03. PG\MiddlewareBypass.md` 3장, 이관 대상은 아니고 «새로 발굴한 사실»이라 원문 자체가 없었음 — git diff 산출물이 근거):**
```
git remote -v 출력: origin https://github.com/EQSTLab/CVE-2025-29927.git
git diff (poc.sh): old mode 100644 / new mode 100755
  -curl -v "http://localhost:3000/admin" \
  -  -H "Host: localhost:3000" \
  +curl -v "http://192.168.248.215:3000/admin" \
  +  -H "Host: 192.168.248.215:3000" \
```
— 출처: `~/PG/MiddlewareBypass/CVE-2025-29927/`(`git show HEAD:poc.sh`, `git diff`), `~/.zsh_history` 2339~2347행

---

## 제안 2 — 병합 → A-1 절, [[Codo]] MikroTik OS 지문 오탐 문단

**병합인가 신규인가:** 병합 (5126행 파일의 69~71행, `### A-1. 정찰·열거` 안의 번호 없는 문단 — "nmap OS 지문에 `Warning: OSScan results may be unreliable`..." 로 시작)

**넣을 본문 (기존 문단 끝에 이어 붙일 것):**

> ⚠️ 같은 오탐이 [[MiddlewareBypass]] 에서도 재현됨 — 22·3000 두 포트뿐인 호스트에서 nmap 이 `Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port` 를 내며 `Running (JUST GUESSING): ... MikroTik RouterOS 7.X (97%)` 를 뱉었음. 실제는 Ubuntu 24.04.1 LTS(커널 6.8.0-58). 독립 근거 2개(SSH 배너 `Ubuntu 3ubuntu13.11` + SSH 로그인 후 MOTD `Ubuntu 24.04.1 LTS`)로 확정. **닫힌 포트가 없는 스캔에서 나온 MikroTik 배지는 Codo·MiddlewareBypass 두 박스에서 반복됨 — 패턴으로 취급할 것.**

**지우기 전 원문:**
```
> [!warning] nmap OS 추측을 믿지 마라
> `Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port` — **closed 포트가 하나도 없으면 OS 지문 채취가 성립하지 않는다.** 이 박스는 65533개가 전부 `filtered`였다.
> 실제 OS는 Ubuntu 24.04(커널 6.8)인데 nmap은 "Linux 4.15–5.19 또는 MikroTik RouterOS"라고 했다. **커널 버전은 서비스 배너로 교차 확인해야 한다.**
```
— 출처: 개작 전 `03. PG\MiddlewareBypass.md` 1장

---

## 제안 3 — 병합 → A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다 (feroxbuster 자동 필터가 307 인가 리다이렉트를 숨김)

**병합인가 신규인가:** **병합** (감사자 정정. 작성자는 「신규, 병합처 없음」으로 신고했으나 `_PLAYBOOK.md` 233행 `#### A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다` 가 **이미 「스캐너의 상태코드 필터가 진짜 히트를 지운다」를 담고 있음** — 237행의 gobuster `-b 404,403` 무력화로 결과 파일이 0바이트가 된 [[Robust]] 사례가 같은 증상·같은 진입 질문(「스캔 결과에 정답 경로가 없다」)임. 도구(gobuster→feroxbuster)와 코드(302→307)만 다르므로 A-15 에 문단으로 이어 붙일 것. 절 제목은 바꾸지 말 것 — 앵커가 깨짐)

**넣을 본문:**

> **증상** — 디렉터리 스캔 29건 어디에도 진짜 보호 라우트(`/admin`)가 없음. 그런데 정답 경로는 존재함.
>
> **원인** — `NextResponse.redirect()`(Next.js 미들웨어)는 기본으로 **307**을 씀. feroxbuster 는 "307 + 본문 13바이트" 처럼 동일한 모양의 응답이 반복되면 와일드카드로 판단해 **자동으로 필터에 넣고 이후 모든 같은 모양의 307을 화면에서 지움**(`Auto-filtering found 404-like response and created new filter`). 인가 실패 응답이 그 와일드카드와 우연히 같은 모양이면 보호된 자원이 통째로 숨음.
>
> ```text
> 307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
> ```
>
> **신호** — `/unauthorized`·`/login`·`/denied` 같은 "차단 착지 페이지"가 결과에 200 으로 남아 있으면, 그 짝이 되는 307/302 가 필터로 지워졌을 가능성을 먼저 의심할 것. `Auto-filtering` 줄이 **404 가 아닌 다른 코드**에 붙어 있으면 그 코드가 곧 보호 자원의 지문임.
>
> **탈출구 셋** — ① `--dont-filter`(자동 필터 전면 해제, 유일하게 확실한 방법) ② `-D`(=`--dont-filter`)와 `-C 404`(=`--filter-status`, deny-list)를 **함께** 씀 — `-C` 단독으로는 auto-filter 를 못 끔 ③ `-r`(리다이렉트 추종)은 **발견 단계 전용**. 우회 성공 판정에 `-r`/`curl -L` 을 쓰면 307 을 따라가 `/unauthorized` 본문만 보고 성공을 실패로 오판함(A-12 와 같은 뿌리).
> ```bash
> feroxbuster -u http://TARGET:PORT/ -w <wordlist> --dont-filter -t 100
> ffuf -u http://TARGET:PORT/FUZZ -w <wordlist> -mc all -fc 404 -fs <404크기>
> gobuster dir -u http://TARGET:PORT/ -w <wordlist> -s 200,204,301,302,307,308,401,403 -b ''
> ```
>
> **출처** — [[MiddlewareBypass]](`~/PG/MiddlewareBypass/` feroxbuster 세션, `~/.zsh_history` 2334행 대화형 확인).

**지우기 전 원문:**
```
> [!danger] **`/admin`이 이 결과에 없다.** 그런데 존재한다 — 스캐너 함정
> 두 번째 줄을 봐라:
> ```
> 307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter
> ```
> feroxbuster는 "거의 모든 경로가 같은 307을 뱉는다" 고 판단해 307 응답을 통째로 필터에서 걸러버렸다. 그리고 미들웨어가 보호 라우트에 거는 리다이렉트가 정확히 **307**(`NextResponse.redirect()`의 기본값)이다.
> 즉 **핵심 타겟인 `/admin`이 필터에 걸려 화면에 안 나왔다.**
>
> **탈출구 3가지:**
> ```bash
> # ① 자동 필터 끄기 — auto-filter를 끄는 유일한 방법
> feroxbuster -u http://192.168.248.215:3000/ -w <wordlist> --dont-filter
>
> # ②을 켠 채로 404만 명시적으로 걸러 노이즈를 줄인다 (-D 없이는 성립하지 않는다)
> feroxbuster -u ... -D -C 404
>
> # ③ 리다이렉트를 따라가서 최종 응답으로 판정 — 경로 발견용이지, 우회 성공 판정용이 아니다
> feroxbuster -u ... -r
> ```
> **`-C`는 `--filter-status`의 축약형이다** — 둘을 나란히 쓰면 같은 플래그를 두 번 쓰는 것일 뿐이고, `-C`는 deny-list여서 wildcard auto-filter를 끄지 못한다. 그것을 끄는 것은 `-D/--dont-filter` 하나뿐이라 ②는 반드시 ①과 조합돼야 한다.
> ③의 `-r`도 마찬가지로 **열거 단계 전용**이다. 3장의 우회 성공 판정 단계에서 리다이렉트를 따라가면 `curl -L`과 똑같이 성공을 실패로 오판한다(3장 · 7장 6번).
> `gobuster`를 쓴다면 `-s 200,204,301,302,307,308,401,403` 로 **307/308을 명시**하고, `ffuf`라면 `-mc all -fs <404크기>` 로 코드가 아니라 크기로 거른다.

### ① `/admin`이 디렉터리 스캔 결과에 안 나온다 — 이 박스의 진짜 함정
feroxbuster 결과 29건 어디에도 `/admin`이 없다. 그런데 정답 경로는 `/admin`이다.
[... 6장 ① 전문, 일반화 3단계·손절 시간 관점 포함 ...]
```
— 출처: 개작 전 `03. PG\MiddlewareBypass.md` 1장 및 6장 ①

---

## 제안 4 — 신규 → B. 기법 카드 (Next.js CVE-2025-29927 미들웨어 인가 우회)

**병합인가 신규인가:** 신규 (`B-1. 웹` 하위. 기존 B-15 는 IP 화이트리스트를 헤더로 판정하는 다른 메커니즘이라 병합처 아님 — 이 CVE 는 "내부 재귀방지 표식 헤더"를 신뢰하는 결함이라 B-1-35(APISIX, 내부 판정 헤더)와 **결이 같지만 별개 기법**임)

**넣을 본문:** (원 노트 2-1~2-8 절, 3장 curl 재현, 7장 3·4·5·8번을 압축 이관 — 요지만 표기, 전문은 아래 원문 인용 참조)

> **탐지 신호** — Next.js 응답(`X-Powered-By: Next.js`) + 보호 라우트가 **307**(`location:` 헤더)로 튕김. `x-middleware-rewrite`/`x-middleware-next: 1` 응답 헤더, `/unauthorized` 류 착지 페이지 존재도 같은 신호.
>
> **메커니즘** — 미들웨어 재귀 실행을 막기 위한 내부 표식 `x-middleware-subrequest` 헤더를 실행기가 발신자 검증 없이 신뢰. 외부 요청이 위조하면 미들웨어(=유일한 인가 장치인 경우가 많음)가 통째로 스킵됨.
>
> **버전별 헤더 값**
> | 버전대 | 파일 | 값 | 반복 |
> |---|---|---|---|
> | 11.1.4~12.1 | `pages/_middleware.ts` | `pages/_middleware` | 1회 |
> | 12.2~15.x | 루트 `middleware.ts` | `middleware` | 1회 |
> | `src/` 아래 | `src/middleware.ts` | `src/middleware` | 1회 |
> | 15.x | 루트 `middleware.ts` | `middleware` | **5회 이상**(`MAX_RECURSION_DEPTH`) |
>
> 만능 값(버전 모를 때): `middleware:middleware:middleware:middleware:middleware:src/middleware:src/middleware:src/middleware:src/middleware:src/middleware:pages/_middleware`
>
> ⚠️ `pages/_middleware` 는 **라우터 종류가 아니라 버전** 문제 — Pages Router 를 쓰는 15.x 앱도 미들웨어 파일은 루트 `middleware.ts`. 판별 기준은 "12.2 이전인가"임.
>
> **정탐/오탐 판정** — 헤더 유무만 다른 두 요청을 비교. `307→/unauthorized` vs `헤더 있으면 200+보호 콘텐츠` 만 정탐. `-L`(`curl`)·"Follow redirections"(Burp) 를 쓰면 우회 성공을 실패로 오판함 — 판정은 상태코드+본문 크기로.
> ```bash
> for h in "" "middleware" "src/middleware" "pages/_middleware" "middleware:middleware:middleware:middleware:middleware"; do
>   printf '%-60s ' "${h:-none}"
>   curl -s -o /dev/null -w '%{http_code} %{size_download}\n' ${h:+-H "x-middleware-subrequest: $h"} http://TARGET:3000/admin
> done
> ```
>
> **패치** — 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 이상. GHSA-f82v-jwr5-mffw, CVSS 9.1.
>
> **일반화 — 앞단 인가(front-layer authorization) 공통 결함.** 미들웨어·리버스 프록시·WAF·API 게이트웨이는 필터지 인가가 아님. 검증 질문 셋 — ① 필터를 우회하면 뒷단이 스스로 막는가 ② 뒷단에 직접 도달 가능한가(백엔드 포트 노출) ③ 필터와 뒷단이 경로/메서드/헤더를 동일하게 해석하는가. 인가 우회 6벡터(헤더 주입·경로 정규화·메서드 변경·HTTP 파싱 불일치·백엔드 직접 접근·대소문자)는 전부 "파서가 둘 이상이면 해석이 갈린다"는 같은 뿌리 — HTTP request smuggling 과도 동형.
>
> **Next.js 라우트 열거는 `_buildManifest.js`로** — 워드리스트보다 정확하고 스캐너 필터의 영향을 안 받음:
> ```bash
> curl -s http://TARGET:3000/ | grep -oE '/_next/static/[^/]+/_buildManifest\.js'
> curl -s http://TARGET:3000/_next/static/<buildId>/_buildManifest.js | grep -oE '"/[^"]*"'
> ```
> 같은 원리: Angular `main.*.js`, React `asset-manifest.json`, Vue `app.*.js`, Django `urls.py`(소스 유출 시).
>
> **자동 도구 불필요** — 본질은 `curl -H` 한 줄. OSCP 자동 익스플로잇 금지 규정에서 오히려 유리한 유형.
>
> **출처** — [[MiddlewareBypass]].

**지우기 전 원문:** 개작 전 `03. PG\MiddlewareBypass.md` **2장 전체(2-1~2-8)** + **3장의 재현 curl 절차·판정표** + **7장 3·4·5·7·8번 항목**. 분량이 커 이 파일에 전문 재인용 대신 백업 경로를 남김 — **`03. PG\_backup\MiddlewareBypass.md.bak`(개작 전 원본, 이번 작업 직전 생성)에 그대로 보존됨.** 반영자는 그 파일의 2장·3장·7장을 원문으로 대조할 것.

---

## 제안 5 — 신규 → A-6. 판단·검증 (메타) (박스 이름·호스트명이 증거사슬을 대신하면 시험장에서 무너짐)

**병합인가 신규인가:** 신규

**넣을 본문:**

> **[[MiddlewareBypass]]** — 박스 이름이 `MiddlewareBypass`, 호스트명이 `nextjs`. `X-Powered-By: Next.js` 를 본 순간 "Next.js + 미들웨어 우회 = CVE-2025-29927" 이 즉시 성립하지만, **이건 랩이라서 성립하는 지름길임.** OSCP 시험 박스에는 이런 이름이 없음.
>
> 이름 없이 같은 결론에 도달하는 증거 사슬 — ① `X-Powered-By: Next.js`(프레임워크 확정) ② `_next/static/chunks/pages/`(Pages Router 확정) ③ `/unauthorized` 페이지 존재(차단 로직 존재) ④ 보호 라우트가 307+`location: /unauthorized`(앞단 인가 확정) ⑤ Next.js+앞단 인가(CVE-2025-29927 1순위) ⑥ 헤더 한 줄로 검증. **①~⑥은 이름을 전혀 안 씀** — 이 사슬을 몸에 붙이는 것이 박스를 푸는 것보다 값짐.
>
> 반대 방향 교훈도 있음 — **랩에서는 이름·호스트명·배너를 적극 활용해 시간을 아낄 것.** 학습 효율과 시험 대비는 다른 목표임. 다만 "이름 덕에 풀렸다"를 노트에 명시해 두지 않으면 자기 실력을 과대평가한 채 시험장에 감.

**지우기 전 원문:**
```
### ⑨ 박스 이름이 답을 흘렸다 — 그리고 시험장에는 그 힌트가 없다
이 박스의 이름은 **`MiddlewareBypass`** 이고, 호스트명은 `nextjs` 다. `X-Powered-By: Next.js`를 본 순간 "Next.js + 미들웨어 우회 = CVE-2025-29927"이 즉시 성립한다. 랩이라서 성립하는 지름길이다.

> [!danger] 이름 힌트에 의존하면 시험장에서 무너진다
> OSCP 시험 박스에는 `MiddlewareBypass` 같은 친절한 이름이 없다. 이름 없이 같은 결론에 도달하는 **증거 사슬**을 몸에 붙여야 한다:
> ① X-Powered-By: Next.js → 프레임워크 확정
> ② _next/static/chunks/pages/ → Pages Router 확정
> ③ /unauthorized 페이지 존재 → 차단 로직 존재
> ④ 보호 라우트가 307 + location: /unauthorized → 앞단(미들웨어) 인가 확정
> ⑤ Next.js + 앞단 인가 → CVE-2025-29927 1순위
> ⑥ 헤더 한 줄로 검증 → 정탐/오탐 확정
> **①~⑥은 이름을 전혀 쓰지 않는다.** 이 사슬을 노트에 남기는 것이 이 박스를 푼 것보다 값지다.
> 반대 방향의 교훈도 있다 — **랩에서는 이름·호스트명·배너를 적극 활용해 시간을 아껴라.** 학습 효율과 시험 대비는 다른 목표다. 다만 "이름 덕에 풀렸다"는 사실을 노트에 명시해 두지 않으면, 자기 실력을 과대평가한 채 시험장에 간다.
```
— 출처: 개작 전 `03. PG\MiddlewareBypass.md` 6장 ⑨

---

## 제안 6 — 병합 → A-24. 한 서비스의 거부는 자격증명의 오류가 아니다 (SSH 첫 시도 실패 1회를 크리덴셜 무효로 오판하지 말 것)

**병합인가 신규인가:** **병합** (감사자 정정. 작성자가 「재검색 후 있으면 병합할 것」으로 유보한 그 항목이 `_PLAYBOOK.md` 733행 `#### A-24. 한 서비스의 거부는 자격증명의 오류가 아니다` 임 — 「거부됐다고 값 자체를 버리지 말고 다른 서비스에 돌려볼 것」([[Robust]])과 `Permission denied` 실패 사례([[GLPI]]·[[Assignment]])가 이미 들어 있음. 이 제안은 같은 항목의 **「같은 서비스에서 1회 실패」** 변종이므로 A-24 에 문단으로 이어 붙일 것)

**넣을 본문:**

> **[[MiddlewareBypass]]** — 웹에서 얻은 `root:modeling-katja-lad-common` 을 SSH 에 재사용할 때 **첫 시도가 `Permission denied` 로 실패**하고 두 번째에 통과함. 원문에 사유 기록 없음 — 오타로 추정 `[가정]`.
>
> 하이픈이 섞인 4단어형 크리덴셜(`modeling-katja-lad-common`)은 화면에서 눈으로 옮겨 적으면 `-`/`_`, `l`/`1`, `0`/`O` 혼동이 잦음. **"Permission denied" 를 보고 "이 크리덴셜은 가짜다"라고 결론내지 말 것** — 최소 2번은 정확히 다시 침. 화면 텍스트는 복사하거나(스크린샷이면 `curl`로 받아 `grep`), `sshpass -p '<pw>' ssh root@TARGET` 로 한 번에 넣어 오타를 배제(테스트 환경 한정).
>
> 실제로 이 박스에서 "1회 실패"를 "크리덴셜 무효"로 읽었다면 정답을 손에 쥐고도 다른 경로를 파느라 시간을 태웠을 것임.

**지우기 전 원문:**
```
### ⑤ SSH 첫 시도가 실패했다
```text
root@192.168.248.215's password:
Permission denied, please try again.
root@192.168.248.215's password:
Welcome to Ubuntu 24.04.1 LTS ...
```
첫 입력이 거부되고 두 번째에 붙었다. 원문에 사유 기록은 없다 — 오타, 또는 `modeling-katja-lad-common`이 아닌 다른 값을 먼저 시도한 것으로 본다 `[가정]`.

> [!warning] 이 한 줄이 시험장에서 치명적일 수 있다
> **크리덴셜을 화면에서 눈으로 옮겨 적으면 반드시 틀린다.** 특히 하이픈이 섞인 4단어형(`modeling-katja-lad-common`)은 `-`와 `_`, `l`과 `1`, `0`과 `O` 혼동이 잦다.
> - 화면 텍스트는 **복사**하거나, 스크린샷이면 `curl`로 HTML을 받아 `grep`으로 뽑아라
> - SSH 비밀번호는 `sshpass -p '<pw>' ssh root@TARGET` 로 **한 번에** 넣어 오타를 배제한다 (테스트 환경 한정)
> - **"Permission denied"를 보고 "이 크리덴셜은 가짜다"라고 결론내지 마라.** 최소 2번은 정확히 다시 쳐본다
> 실제로 이 박스에서 "1회 실패"를 "크리덴셜 무효"로 읽었다면 **정답을 손에 쥐고도 다른 경로를 파느라 시간을 태웠을 것**이다.
```
— 출처: 개작 전 `03. PG\MiddlewareBypass.md` 6장 ⑤

---

## 제안 7 — 신규 → D. 시간 배분 · 손절 기준 (실측 표에 행 추가)

**병합인가 신규인가:** 신규 (기존 "실측 — 박스별 소요 시간과 손절점" 표에 행 추가, 5126행 파일 약 5000행 부근)

**넣을 본문(표 1행):**

| [[MiddlewareBypass]] | nmap 종료 10:11:19 → whatweb 10:22 → 52124.txt 10:35:47 → CVE 클론/poc.sh 준비 10:41:29~10:44:29(mtime) | 확인 구간은 **최소 33분**(10:11→10:44). SSH root 로그인·플래그 획득 시각은 mtime 근거 없음 `[가정]` — 스크린샷 붙여넣기 11:11:58 은 상한일 뿐 캡처 시각과 다를 수 있음(붙여넣기≠캡처, 별도 검증 없음). feroxbuster auto-filter 가 `/admin` 을 숨긴 구간(A-신규-3)이 유일하게 특정 가능한 손실 지점 |

**지우기 전 원문:** 해당 없음 — 원 노트 10장(⑩ 시간 배분)에 있던 표는 **mtime 검증 없이 추정치**(`[가정]` 다수)로 작성돼 있었음. 실측(mtime) 기반으로 재구성한 것이 위 표이므로 「지우기 전 원문」은 다음을 참고:
```
| 단계 | 실제/예상 | 판단 |
|---|---|---|
| nmap 전 포트 | 55초 | 적정. 포트 2개뿐이라 빨랐다 |
| feroxbuster | 4분 | 결과에 `/admin`이 없어 판단 착오를 유발한 구간 |
| 라우트 수동 열거 (`_buildManifest.js`) | ~1분 `[가정]` | 처음부터 이걸 했으면 스캐너 함정을 통째로 우회했다 |
| CVE 식별 → 페이로드 | ~5분 `[가정]` | X-Powered-By: Next.js + 307 리다이렉트 조합이면 CVE-2025-29927이 1순위 |
| SSH → 플래그 | 1분 | — |
```
— 출처: 개작 전 `03. PG\MiddlewareBypass.md` 6장 ⑩ (mtime 대조 없이 작성된 추정치임)

---

## 검산

- 노트에서 이관/삭제한 절: 원 노트의 `0장`·`2장 전체`·`6장 ①~⑩`·`7장`·`8장`(각 finding 4항목으로 재배치된 부분 제외)·`9장`
- 제안 건수: **7건** (병합 **4** · 신규 **3**) ← 감사자 정정. 작성자 신고는 「병합 2 · 신규 5」였으나 제안 3(→A-15) · 제안 6(→A-24) 의 병합처가 `_PLAYBOOK` 에 실재함을 확인함. 나머지 신규 3건(제안 4 B 기법카드 · 제안 5 A-6 · 제안 7 D 표 행)은 재검색 결과 병합처 없음이 맞음 — `_PLAYBOOK` 전문에 `Next.js`·`middleware-subrequest` 히트 0건, A-6 하위(A-61~A-69)에 「박스 이름 의존」 항목 없음
- 지우기 전 원문 인용: 7건 모두 포함(제안 4·7은 분량상 백업 파일 경로로 대체 — 원문 위치 명시함)
- 이관 손실 0 여부: ⚠️ **작성자 신고 「코드블록 이관 손실 0」은 감사에서 반증됨.** 실제로 3건이 깨져 있었고 전부 감사자가 복원함 — ①nmap raw 의 405 응답 줄이 **81바이트 절단**(`chunks/webpack-8fa1640cc84ba8fe.js" defer=""></script><script src="/_next/static/` 누락) ②feroxbuster 캡처의 **배너 20줄 삭제**(`ver: 2.13.1`·`Status Codes │ All Status Codes!`·`Recursion Depth │ 4` — 자동 필터 서술의 근거) ③`git diff` 의 `old mode 100644 / new mode 100755 / index 0260e16..d33c75a` 3줄 삭제. 상세는 `MiddlewareBypass-audit.md`
- 무태그 펜스: 새 노트 전수 확인 — `text`·`bash`·`diff` 태그 전부 부여, 무태그 펜스 0
