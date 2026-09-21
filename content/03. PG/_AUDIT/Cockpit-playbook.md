# Cockpit → _PLAYBOOK 이관 제안

작성: pg-note-forge (Cockpit 개작, 2026-08-26). `_PLAYBOOK.md` 는 열지 않았음 — 아래는 전부 제안이며 번호는 총괄(pg-line-manager)이 배정.

---

## 제안 1 — B. 기법 카드 / 신규 — 이름이 흔한 서비스는 벤더로 좁혀 검색

①어느 절: B. 기법 카드, 신규
②신규
③넣을 본문:
`Cockpit`·`Portal`·`Console`·`Dashboard`·`Hub` 같은 서비스명은 exploit-db 에서 반드시 충돌함. searchsploit 결과를 열기 전에 제품 식별 줄을 먼저 확인. `searchsploit -p <ID>` 로 `Path`·`File Type` 확인 후, 파일 머리말 첫 10줄 안의 제품 식별 줄(`Vendor Homepage:` 또는 `Product:` — 필드명은 파일마다 다름)과 대상 버전을 눈으로 훑는다. 확장자(`.txt`/`.py`)도 신뢰 불가 — `.txt` 인데 완전한 python 스크립트인 경우와 그 반대가 실제로 같은 검색 결과 안에 공존함(EDB 49397 vs 49390).
④지우기 전 원문 인용 (Cockpit.md 구 3장, 산문 + 실측 코드블록 전문):
> `Cockpit`·`Portal`·`Console`·`Dashboard`·`Hub` 같은 서비스명은 exploit-db 에서 반드시 충돌한다. 검색 결과를 열기 전에 **제품 식별 줄**을 먼저 보고 같은 제품인지 확인하는 데 10초면 된다. 필드 이름은 고정돼 있지 않다 — `49397.txt` 는 `# Vendor Homepage: https://cockpit-project.org/` 로, `49390.txt` 는 `# Product: Cockpit CMS (https://getcockpit.com)` 로 적혀 있다. 둘 다 **첫 10줄 안**이다. 여기서 그걸 안 하고 다른 제품의 익스플로잇을 붙들었다.
> 같은 검색 결과의 `49397.txt`(Cockpit v234 SSRF)는 **확장자가 `.txt` 인데 내용은 완전한 python3 스크립트**다. 반대로 `49390.txt` 는 산문이다. exploit-db 의 확장자는 신뢰할 수 없다.

```bash
searchsploit Cockpit
```
```text
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Cockpit CMS 0.11.1 - 'Username Enumeration &  | multiple/webapps/50185.py
Cockpit CMS 0.4.4 < 0.5.5 - Server-Side Reque | php/webapps/44567.txt
Cockpit CMS 0.6.1 - Remote Code Execution     | php/webapps/49390.txt
Cockpit Version 234 - Server-Side Request For | multiple/webapps/49397.txt
openITCOCKPIT 3.6.1-2 - Cross-Site Request Fo | php/webapps/47305.py
---------------------------------------------- ---------------------------------
```

```bash
searchsploit -p 49390
```
```text
  Exploit: Cockpit CMS 0.6.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49390
     Path: /usr/share/exploitdb/exploits/php/webapps/49390.txt
    Codes: N/A
 Verified: False
File Type: ASCII text
```
— 출처: `~/PG/Cockpit/` 작업 중 실행(zsh 대화형 세션). 49390.txt 안 페이로드 조각: `{"auth":{"user":"test'.phpinfo().'","password":"b"}}` — Cockpit CMS(별개 제품) 전용 RCE 페이로드, 이 박스와 무관.

---

## 제안 2 — B. 기법 카드 / 신규(또는 기존 B-12 SQLi 카드에 병합 검토) — LIKE 로 만든 로그인 쿼리는 인증 우회다

①어느 절: B. 기법 카드. **병합 후보** — [[Robust]] 노트에 `[[_PLAYBOOK#B-12. SQLi 수동 UNION — sqlmap 금지 대비]]` 앵커가 이미 존재함(이 세션에서 `_PLAYBOOK.md` 를 직접 열지 않아 B-12 본문이 LIKE 케이스를 다루는지는 미확인). 총괄이 B-12 본문을 보고 병합/신규를 판단할 것.
②병합 검토 필요(신규로 잠정 제안)
③넣을 본문:
로그인 폼에서 `'` 보다 `%` 와 빈 값을 먼저 넣어본다. 쿼리가 `=` 대신 `LIKE '%…%'` 로 짜여 있으면 인젝션 페이로드·인용부호 탈출 없이 와일드카드 문자만으로 인증이 통과한다. 판별법: 빈 값 또는 `%` 제출 시 응답이 달라지면 `LIKE` 다. 에러 메시지가 그대로 노출되면 되짚어 원본 쿼리 구조를 복원할 수 있다(Cockpit 사례: `'` 하나로 `LIKE '%…%' AND password like '%…%'` 전체 구조가 드러남).
④지우기 전 원문 인용 (Cockpit.md 구 2장):
> SQL 인젝션이 아니어도 성립한다. 페이로드도, 주석 문자도, 인용부호 탈출도 필요 없다 — **와일드카드 문자를 그냥 입력하면 된다.** 개발자가 "검색 기능을 만들다 로그인에도 같은 헬퍼를 썼다" 같은 이유로 나오는 실수고, 실무에서도 종종 보인다.
> 그래서 로그인 폼을 만나면 **`'` 를 넣기 전에** `%` 하나, 그리고 빈 값 제출을 먼저 해보는 게 싸다. 응답이 달라지면 `LIKE` 다.

---

## 제안 3 — A. 증상별 / 신규 — 디렉터리 브루트포스 결과가 수천 줄이면 이미 틀린 스캔이다 (catch-all + 재귀 폭주)

①어느 절: A. 증상별, 신규
②신규
③넣을 본문 — 증상: "feroxbuster 등 브루트포스 도구가 200 응답을 수천 건 반환한다."
원인: 인증 뒤 관리 콘솔(Cockpit·Grafana·Portainer 류)은 존재하지 않는 경로도 같은 페이지를 200 으로 돌려주는 catch-all 라우팅을 쓸 수 있다. feroxbuster 는 그 200 응답을 "디렉터리"로 오인해 그 아래에 워드리스트 전체를 재귀로 다시 뿌리므로 요청 수가 재귀 1회마다 한 벌씩 불어난다.
판정: `awk '/^200/{print $5}' ferox.txt | sort | uniq -c | sort -rn | head` — 같은 바이트 수가 수백 번 반복되면 그 크기를 버린다.
대응: `-S <바이트>`/`-N <행수>`(크기 제외) · `--filter-similar-to <URL>` · `-C 404,200`(상태코드 제외) · `--no-recursion`/`-d 1`(재귀 차단, catch-all 대응 최우선). 더 근본적으로 — 인증 뒤 관리 콘솔은 자산 트리가 패키지에 고정돼 숨은 경로가 없다. 브루트포스 대상이 아니라 자격증명을 구해 로그인할 대상이다.
실측 수치(Cockpit, `~/PG/Cockpit/ferox.txt`): 200 응답 6,833건 중 5,877건(86%)이 `/text/`·`/shell/` 두 디렉터리 밑(워드리스트 341행·1688행). 11:12 중단 시점 상태파일 — 요청 66,771 / `wildcards_filtered: 22778` / `resources_discovered: 149`. 최종 회차 상태파일 `expected_per_scan: 1323276`, `total_expected: 3970062`(재귀 세 벌 누적). 소요 시간 2시간 반(06-25 11:12~13:36), 건진 것 0.
④지우기 전 원문 인용 (Cockpit.md 구 6장 ②, 산문 + 실측 코드블록 전문):
> Cockpit 콘솔을 상대로 네 번 돌렸다 … 6,833건의 200. 전부 헛것이다 … `/text/` 와 `/shell/` 딱 두 디렉터리 밑 … catch-all 이 둘 다 200 으로 받아주니 feroxbuster 가 **디렉터리로 인정하고 그 아래에 워드리스트 전체를 다시 뿌렸다.**
> 11:12 에 Ctrl-C 로 끊은 회차의 상태파일에는 이렇게 남아 있다 — 요청 66,771 / 200 응답 23,379 / `wildcards_filtered: 22778` / `resources_discovered: 149`.
> `@localhost` 는 워드리스트에 없다 … feroxbuster 2.13.1 에서 링크 추출은 **기본 켜짐**이고, 끄는 플래그는 `--dont-extract-links` 다 — `--help` 에 켜는 쪽 플래그는 아예 없다.

```bash
wc -l ferox.txt
```
```text
6997 ferox.txt
```
```bash
grep -c '^200' ferox.txt
```
```text
6833
```
```bash
grep '^200' ferox.txt | awk '{print $2,$3,$4,$5}' | sort | uniq -c | sort -rn | head -6
```
```text
    438 GET 700l 2899w 40222c
    350 GET 647l 2512w 30506c
    346 GET 647l 2573w 34670c
    340 GET 647l 2544w 33282c
    323 GET 647l 2532w 31894c
    317 GET 647l 2451w 27730c
```
```bash
grep '^200' ferox.txt | head -5
```
```text
200      GET      771l     3095w    43264c http://192.168.150.10:9090/download
200      GET      109l      623w    52583c http://192.168.150.10:9090/cockpit/static/fonts/RedHatDisplay-Medium.woff2
200      GET      771l     3095w    43264c http://192.168.150.10:9090/text/css
200      GET      771l     3095w    43264c http://192.168.150.10:9090/shell/index.html
200      GET      771l     3095w    43264c http://192.168.150.10:9090/@localhost
```
```bash
grep -oE 'https?://[^ ]+' ferox.txt | sed -E 's#(https?://[^/]+/)([^/]*)/.*#\1\2/#' | sort | uniq -c | sort -rn | head -4
```
```text
   2946 http://192.168.150.10:9090/text/
   2931 http://192.168.150.10:9090/shell/
      3 http://192.168.150.10:9090/cockpit/
      1 http://192.168.150.10:9090/zuma
```
— 출처: `~/PG/Cockpit/ferox.txt`(2일차 06-25 13:36 회차, 594275바이트).

판정용 팁 원문:
> ```bash
> awk '/^200/{print $5}' ferox.txt | sort | uniq -c | sort -rn | head
> ```
> 같은 크기가 수백 번 반복되면 그 크기를 버린다. feroxbuster 2.13.1 기준 대응 플래그: `-S <바이트>`/`-N <행수>`(크기 제외) · `--filter-similar-to <URL>` · `-C 404,200`(상태코드 제외) · `--no-recursion`/`-d 1`(재귀 차단, catch-all 대응 최우선).

---

## 제안 4 — A. 증상별 / 신규 — 브루트포스 결과가 갑자기 빈약해지면 "사이트가 원래 그렇다"가 아니라 "차단당했다"를 먼저 의심

①어느 절: A. 증상별, 신규
②신규
③넣을 본문 — 증상: 직전까지 잘 나오던 스캔 결과가 다음 대상에서 갑자기 링크추출분(정적 자산)만 남고 워드리스트 히트가 0에 가깝다.
확인법: 이미 200 이 나왔던 경로 하나를 `curl -i` 로 재요청 — 여전히 200 이면 원래 그런 것, 403 이나 낯선 페이지면 차단.
힌트: 결과 목록 자체에 차단 페이지 이름(예: `blocked.html`)이 열거돼 있을 수 있다 — 발견하고도 열어보지 않으면 신호를 놓친다.
`[가정]` 표시 유지: Cockpit 사례에서는 `blocked.html` 내용을 실제로 확인한 기록이 없고 타겟도 소멸해 확정할 수 없음 — 이 카드에도 그 유보를 남길 것.
④지우기 전 원문 인용 (Cockpit.md 구 6장 ③, 산문 + 실측 코드블록 전문):
> 정황을 모으면 이렇다 — 9090 에 2시간 반 동안 수만 건을 때린 직후 같은 호스트의 80 을 200스레드로 두들겼고, 웹루트에는 `blocked.html` 이라는 이름의 페이지가 존재하며, 결과는 링크 추출분만 남았다. **스캐너 IP 가 차단됐을 가능성이 크다** `[가정]`. 다음 날 박스가 재배포되어 상태가 초기화된 뒤 같은 성격의 스캔이 곧바로 `login.php` 를 찾은 것도 이 가정과 부합한다 … 다만 `blocked.html` 의 내용을 확인한 기록은 없고 타겟도 이미 사라져 확정할 수 없다.
> 스캔 결과가 **비정상적으로 적을 때** 의심할 것은 "이 사이트는 원래 이렇다" 가 아니라 **내가 차단당했다** 쪽이다. 확인법은 싸다 — 이미 200 이 나왔던 경로(`/index.html`) 하나를 `curl -i` 로 다시 때려보면 된다.

1일차 tcp/80 스캔(06-25 13:36~15:32, 두 시간) 전체 결과:
```text
200      GET       78l      321w     3349c http://192.168.150.10/index.html
MSG      0.000 feroxbuster::heuristics detected directory listing: http://192.168.150.10/img (Apache)
200      GET      707l     4190w   598838c http://192.168.150.10/img/blaze.png
200      GET       78l      321w     3349c http://192.168.150.10/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://192.168.150.10/js (Apache)
200      GET       29l       85w      913c http://192.168.150.10/js/index.js
200      GET       29l       60w      477c http://192.168.150.10/css/type.css
200      GET      10l       28w      233c http://192.168.150.10/blocked.html
```
— 출처: `~/PG/Cockpit/ferox_80.txt`(1일차, `directory-list-2.3-medium.txt`). `login` 은 이 워드리스트에서 53행째로 2일차와 동일 — 어느 쪽에서도 늦게 나올 이유가 없는데 1일차엔 보고되지 않음. 건진 6건 전부 `index.html` 링크로 도달 가능한 정적 자산.

---

## 제안 5 — A. 증상별 / 신규 — 권한상승 페이로드에 다른 박스의 사용자명·덮어쓰기가 섞여 들어온다

①어느 절: A. 증상별, 신규
②신규
③넣을 본문 — 증상: GTFOBins 류 권한상승 페이로드를 준비하다 `kali`(공격 머신 사용자명)처럼 타겟에 없는 계정명이 그대로 섞여 있거나, `/etc/sudoers`·`/etc/passwd` 를 `>` 로 통째로 덮어쓰는 형태로 작성된다.
원인: 다른 박스에서 쓴 페이로드를 복사해오며 사용자명을 안 바꿈. `>` 덮어쓰기는 실패 시 되돌릴 방법이 없어 권한상승 통로 자체를 닫을 수 있다.
대응 원칙: 되돌릴 수 있는 페이로드부터(`chmod +s`, 바이너리 복사+SUID, 리버스셸). 시스템 파일을 꼭 고쳐야 하면 `>>` 로 추가하고 원본을 먼저 백업. 페이로드 안 사용자명은 실행 직전 타겟 기준으로 다시 확인.
④지우기 전 원문 인용 (Cockpit.md 구 6장 ④, 산문 + 실측 코드블록 전문):
> **`kali` 는 이 호스트에 없는 계정이다.** 공격 머신의 사용자명이 그대로 들어갔다. 실행돼도 james 가 얻는 건 없다.
> **`>` 로 `/etc/sudoers` 를 통째로 덮어쓴다.** 성공하면 `james … NOPASSWD: /usr/bin/tar …` 규칙이 사라진다. 즉 **유일한 권한상승 통로를 자기 손으로 닫는** 페이로드다. 리버트 말고는 복구가 없다.
> `chmod +s /bin/bash`, `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash`, 리버스셸 — 전부 **기존 설정을 건드리지 않는다.** 반대로 `/etc/sudoers` 나 `/etc/passwd` 를 **`>` 로 덮어쓰는 것**은 실패하면 박스를 죽인다.
> 1차는 홈 디렉터리(`~`)에서 준비했고 2차(성공한 시도)는 `/tmp` 로 옮겼다. sudo 규칙의 `*` 는 셸의 현재 디렉터리에서 확장되므로 `~` 에서도 원리상 통한다 — 옮긴 이유는 기록에 없다.

```text
james@blaze:~$ echo "" > '--checkpoint=1'
james@blaze:~$ ls
'--checkpoint=1'   local.txt
james@blaze:~$ echo "" > '--checkpoint-action=exec=sh privesc.sh'
james@blaze:~$ vi privesc.sh
james@blaze:~$ cat privesc.sh
echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers
```
— 출처: `파일보관\Pasted image 20260626133613.png`(13:36, Cockpit 웹 터미널 캡처). 이 페이로드가 실제로 실행됐는지는 화면에 없음. 16분 뒤(13:52) `sudo tar` 가 정상 동작해 root 를 잡았으므로 `/etc/sudoers` 는 그 시점에 온전했음 — 즉 실행 전에 페이로드를 갈아엎었다고 추정 `[가정]`.

---

## 제안 6 — A. 증상별 / 신규 — 셸 잡고 바로 안 치면 새는 시간: 반사적 권한상승 열거 5줄

①어느 절: A. 증상별, 신규
②신규
③넣을 본문 — 증상: 셸을 잡은 뒤 다음 행동까지 뜸을 들이다 시간이 새는 경우(Cockpit 실측: `local.txt` 획득 11:13 → `sudo -l` 13:01, 108분 공백. 기술적 시행착오 근거 없음 — 자리 비움으로 추정).
대응: 셸 잡은 직후 반사적으로:
```
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```
Cockpit 은 이 중 `sudo -l` 한 줄로 권한상승이 끝나는 박스였다.
④지우기 전 원문 인용 (Cockpit.md 구 6장 ⑤):
> `local.txt` 를 잡은 11:13 부터 `sudo -l` 을 찍은 13:01 까지 어떤 산출물도 스크린샷도 없다. 자리를 비운 것으로 보이고(점심 시간대와 겹친다) 기술적 시행착오였다는 근거는 없다.
> **`sudo -l` 한 줄로 끝나는 박스에서 셸을 잡고 108분이 지나서야 그 한 줄을 쳤다.** 셸을 잡은 직후 30초는 반사적으로 다음을 돌려야 한다.

---

## 제안 7 — A. 증상별 / 신규 — exploit-db 스크립트를 "열어봤다"는 것만으로는 실행 여부 판단에 부족하다

①어느 절: A. 증상별, 신규
②신규
③넣을 본문 — 증상: `vi <파일>.txt` 로 exploit-db 파일을 열어보고도 확장자를 `.py` 로 바꿔 세 번(`python`→`python2`→인자 포함) 실행을 시도(Cockpit 실측: `49390.txt`는 산문 어드바이저리였는데도).
원인: "exploit-db 에서 받은 건 실행하는 것"이라는 관성이 앞서, 열 때 뭘 확인할지 정해두지 않아 눈으로 훑고도 놓침.
대응: 파일을 열 때 확인할 것 셋을 고정 — ①제품 식별 줄 ②대상 버전 ③실행 가능한 코드인가(`import`·`#!` 존재 여부). 하나라도 안 맞으면 그 자리에서 버린다.
④지우기 전 원문 인용 (Cockpit.md 구 6장 ①, 산문 + `~/.zsh_history` 발췌 원문):
> 여기서 눈에 띄는 게 history 3번째 줄의 `vi 49390.txt` 다. **한 번 열어보고서도** 확장자를 `.py` 로 바꾸고 `python` → `python2` → 인자 붙여서 세 번 실행을 시도했다 … 훑고 넘겼거나, "exploit-db 에서 받은 건 실행하는 것" 이라는 관성이 앞섰다는 뜻이다.
> 같은 검색 결과의 `49397.txt`(Cockpit v234 SSRF)는 확장자가 `.txt` 인데 내용은 완전한 python3 스크립트다. 반대로 `49390.txt` 는 산문이다. exploit-db 의 확장자는 신뢰할 수 없다. 열 때 **뭘 볼지**를 정해두는 게 낫다. 첫 20줄에서 확인할 것은 셋이다.

```text
searchsploit Cockpit
searchsploit -m 49390
vi 49390.txt
mv 49390.txt 49390.py
python 49390.py
python2 49390.py
python 49390.py 192.168.150.10
vi 49390.py
```
— 출처: `~/.zsh_history` 1170~1177행(대화형 세션, 타임스탬프 없음). `49390.py` mtime 은 2026-06-25 10:41:02(nmap 종료 10:23:32 이후) — history 순서만으로는 nmap 과의 선후 확정 불가, "10:41 까지 이 파일을 붙들고 있었다"까지만 확실.

---

## 제안 8 — D 또는 E (시험 반사 체크리스트) / 신규 — 웹 기반 셸에서 플래그를 읽지 마라 (일반화)

①어느 절: C·D·E 중 시험 반사 체크리스트, 신규
②신규
③넣을 본문:
Cockpit·Webmin·Wetty·Guacamole·브라우저 개발자 콘솔 등 **브라우저 안에서 도는 터미널은 전부 web-based shell** 이고 OSCP 규정상 여기서 읽은 플래그는 0점("this includes any type of web-based shell"). 자격증명을 이미 손에 쥐었으면 SSH·WinRM·RDP 같은 진짜 세션으로 갈아탄 뒤 원위치에서 `cat`/`type`. 판별 신호: 같은 프롬프트 문자열이 여러 스크린샷에서 폰트·색상·UI 크롬까지 동일하게 렌더되는가(브라우저 렌더러 특유). `~/.zsh_history` 에 해당 세션의 `ssh` 시도가 없다면 그 뒤 명령 전부가 웹 셸 안에서 쳐졌을 가능성을 의심.
④지우기 전 원문 인용 (Cockpit.md 구 7장 4번):
> **웹 기반 셸에서 플래그를 읽지 마라.** Cockpit·Webmin·Wetty·Guacamole·개발자 콘솔 전부 해당한다. 자격증명을 이미 손에 쥐었다면 **SSH·WinRM·RDP 같은 진짜 세션으로 갈아탄 뒤** 원위치에서 `cat` 한다. 이 박스는 22번이 열려 있었으니 비용이 0이었는데도 **두 플래그 다 브라우저 터미널에서 읽었다** — 시험이었다면 100점짜리 박스가 0점이다. 한 번 웹 셸에 자리를 잡으면 그 뒤 모든 작업이 관성으로 거기서 이어진다는 게 이 박스의 진짜 교훈이다.

---

## 제안 9 — B. 기법 카드 / 신규 — `sudo -l` 규칙 끝의 `*` 읽는 법

①어느 절: B. 기법 카드, 신규 (Zipper 노트의 와일드카드 크론 카드와 인접 배치 검토 — Zipper 는 root 크론의 `7za a … *.zip`, 이쪽은 `sudo` 의 `tar … *`. 같은 "글로브가 인자 자리에 들어가면 파일명이 옵션이 된다" 원리)
②신규(Zipper 관련 카드가 이미 있다면 상호 참조만 추가하는 형태로 병합 검토)
③넣을 본문:
`sudo -l` 규칙 끝에 `*` 가 있으면 그 프로그램의 모든 옵션이 열려 있다고 읽는다 — GTFOBins 의 해당 프로그램 `sudo` 항목이 요구하는 옵션을 그대로 붙이면 대개 끝난다. `*` 가 없고 인자가 고정이면 파일명 트릭(글로브 확장 이용)으로 우회한다.
`tar` 의 경우: `--checkpoint=N` + `--checkpoint-action=exec=CMD` 로 체크포인트 시점에 임의 명령 실행(root 로 도는 tar 안에서 실행되므로 CMD 도 root). `touch -- '--checkpoint=1'` 처럼 `--` 로 touch 자신에게 "이후는 파일명"이라 알려야 해당 옵션 이름의 파일을 만들 수 있음. 성공 판정: 아카이브 멤버 목록에 페이로드 스크립트는 있는데 `--checkpoint=*` 파일명이 없으면(옵션으로 소비됨) 성공.
근거: `sudoers(5)` Wildcards 절 — 명령행 인자 자리의 `*` 는 슬래시·공백을 포함해 매칭(경로명 매칭과 다름).
④지우기 전 원문 인용 (Cockpit.md 구 4장 tip 박스):
> `sudo -l` 을 볼 때 `*` 의 위치를 본다 — 규칙 끝에 `*` 가 있으면 **그 프로그램의 모든 옵션이 열려 있다**고 읽어라. GTFOBins 에서 그 프로그램의 `sudo` 항목이 요구하는 옵션을 그대로 붙이면 대개 끝난다. 파일명 트릭은 `*` 가 **없을 때**, 즉 인자가 고정돼 있고 글로브 확장만 통제할 수 있을 때 필요한 우회다.

---

## 제안 10 — A. 증상별 / 신규 — mtime·스크린샷 파일명으로 시행착오 시간대를 재구성하는 법 (Cockpit 실측 타임라인 예시)

①어느 절: A. 증상별, 신규(방법론 카드 — 다른 박스 감사에서도 반복 사용되는 기법이라 사례로 Cockpit 을 인용)
②신규
③넣을 본문: `~/.zsh_history` 는 타임스탬프가 없다(`extended_history` 미설정 시). 산출물 mtime + 스크린샷 파일명(`Pasted image <YYYYMMDDHHMMSS>.png` = 붙여넣은 시각)을 대조하면 시행착오 서사가 복원된다. 단 스크린샷 파일명은 **붙여넣은 시각**이지 **촬영 시각**이 아닐 수 있다는 유보를 항상 붙일 것. 브라우저 웹 셸(Cockpit 등) 안에서 친 명령은 `~/.zsh_history` 에 전혀 남지 않으므로 그 구간은 스크린샷이 유일한 실측이다.
④지우기 전 원문 인용 (Cockpit.md 구 6장 타임라인 표, 전문):
> `~/.zsh_history` 에는 **타임스탬프가 없다**(`~/.zshrc` 에 `extended_history` 미설정). 그래서 아래 시각은 전부 **파일 mtime 과 스크린샷 파일명**에서 왔다. 스크린샷 파일명은 볼트에 **붙여넣은 시각**이라 촬영 시각과 몇 초~몇 분 어긋날 수 있다.
> 또한 **Cockpit 브라우저 터미널 안에서 친 명령은 `~/.zsh_history` 에 한 줄도 남지 않는다.** 셸 이후 구간의 실측은 스크린샷이 유일하다.

| 시각 | 무슨 일 | 근거 |
|---|---|---|
| 06-25 10:22–10:23 | nmap 완료 | `nmap.log` |
| 06-25 10:41 | `49390.py` 마지막 편집 — searchsploit 우회로의 끝 | `49390.py` mtime |
| 06-25 11:12 | 9090 ferox 중단(Ctrl-C) — 이 시점의 상태만 `.state` 로 남았다 | `.state` mtime, 요청 66,771 / 예정 1,323,276 |
| 06-25 13:36 | 9090 ferox 마지막 회차 종료 — 200 응답 6,833건, 건진 것 0 | `ferox.txt` mtime·행수 |
| 06-25 15:32 | 1일차 80 ferox — 200 응답 **6건**, `login.php` **없음** | `ferox_80.txt` |
| 06-26 10:51 | 재배포된 IP 로 80 ferox 재시도 → `login.php` 발견 후 Ctrl-C | `.state` mtime·내용(`login.php` 가 발견 목록에 있고 루트 스캔은 `Running` 인 채로 저장됨) |
| 06-26 10:53–10:55 | 로그인 우회, 사용자 목록, `'` 로 MySQL 에러 | 스크린샷 3장 |
| 06-26 11:07–11:08 | base64 디코딩 | 스크린샷 2장 + history |
| 06-26 11:11–11:13 | Cockpit 로그인, `local.txt` | 스크린샷 2장 |
| 06-26 11:13→13:01 | **약 108분 공백. 기록이 없다** | — |
| 06-26 13:01 | `sudo -l` | 스크린샷 |
| 06-26 13:36 | 권한상승 페이로드 1차 — 폐기 | 스크린샷 |
| 06-26 13:52 | root, `proof.txt` | 스크린샷 |

이 감사에서 추가 확인: 볼트 `파일보관\` 에서 06-25/06-26 10~14시대 파일명 패턴으로 걸리는 스크린샷은 총 12장이나, 그중 `Pasted image 20260625135833.png`(boroCTF 2026 참가 인증서, 무관)와 `Pasted image 20260626142047.png`(Gerapy 로그인 화면, 무관)는 **이 박스와 관련 없는 스크린샷**으로 확인됨. Cockpit 관련은 9장(구 노트가 이미 참조한 것과 일치)+`Pasted image 20260626110746.png`(단일 base64 디코딩, 110833 의 Burp 이중 디코딩과 중복이라 노트에 미포함) = 10장.

## 제안 11 — D 또는 E (시험 반사 체크리스트) / 신규 — 이 박스의 자동 도구 없는 대안

①어느 절: C·D·E 중 시험 반사 체크리스트, 신규
②신규
③넣을 본문: 이 박스는 원래 자동 도구가 필요 없는 골격이다. 디렉터리 열거는 `gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php` 로 충분(`common.txt` 2347행에 `login` 이 있어 `-x php` 와 함께면 `login.php` 가 요청됨). 인증 우회는 페이로드 없이 브라우저에 글자 하나. 권한상승은 `sudo -l` 한 줄. `sqlmap` 은 시험 금지이고 여기선 애초에 쓸 일이 없음 — "로그인 폼 → 평문/약한 인코딩 자격증명 → 같은 자격증명으로 관리 서비스 로그인 → `sudo -l` GTFOBins" 는 PG Intermediate 표준 골격이라는 일반화와 함께 카드화 검토.
④지우기 전 원문 인용 (Cockpit.md 구 7장 3번):
> **자동 도구 없는 대안.** 이 박스는 원래 자동 도구가 필요 없다. 디렉터리 열거는 `gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php` 로 충분했고(`common.txt` 2347행에 `login` 이 있으니 `-x php` 와 함께면 `login.php` 가 요청된다), 인증 우회는 브라우저에 글자 하나 치는 것이고, 권한상승은 `sudo -l` 이다. `sqlmap` 은 시험 금지이고 여기서는 애초에 쓸 일이 없다.

(원 노트 상단 요약에 있던 관련 서술도 함께 인용: "'로그인 폼 → 평문/약한 인코딩 자격증명 → 같은 자격증명으로 관리 서비스 로그인 → `sudo -l` GTFOBins' 는 PG Intermediate 의 표준 골격이다. 변형은 base64 자리에 md5·ROT13·평문이 들어가거나, 9090 자리에 Webmin·Zabbix·phpMyAdmin·Portainer 가 들어가는 정도다.")

---

## 제안 12 — A. 증상별 또는 일반 공지 / 신규 — PG 박스는 리버트되면 IP 가 바뀐다

①어느 절: A. 증상별, 신규(범용성이 높아 총괄이 이미 아는 사실이면 스킵 가능 — 판단 위임)
②신규
③넣을 본문: PG 박스 인스턴스가 리버트/재배포되면 IP 가 바뀐다(Cockpit: `192.168.150.10`→`192.168.161.10`). 노트에 IP 를 적을 때는 어느 세션·어느 시점의 것인지 함께 적어야 나중에 자기 기록을 의심하지 않는다. 여러 IP 가 섞인 노트에서 하나로 뭉개면 스스로의 산출물(스크린샷 URL 바 등)과 모순이 생긴다.
④지우기 전 원문 인용 (Cockpit.md 구 7장 7번):
> **PG 박스는 리버트되면 IP 가 바뀐다.** 이 노트의 1일차·2일차 IP 가 다른 이유다. 노트에 IP 를 박아둘 때는 어느 세션의 것인지 함께 적어야 나중에 자기 기록을 의심하지 않는다.

## 검산

이관 대상 원문(구 0·6·7장 전체)은 새 `Cockpit.md` 본문에서 전량 제거함. 위 12건에 인용된 원문 조각(산문 + 실측 코드블록 전문)이 삭제된 서술을 전량 커버 — 코드블록은 요약하지 않고 그대로 옮김. 성공한 `sudo tar` 실행 로그(체크포인트 트릭 본체)는 이관 대상이 아니라 새 노트의 `Privilege Escalation` 절에 그대로 보존. 전문 대조가 필요하면 `03. PG\_backup\Cockpit.md.bak2`(개작 전 원본, 670행) 참조.
