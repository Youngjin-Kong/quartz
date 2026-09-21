---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---

# Butch — 적대적 검증 (웨이브 14)

대상: `03. PG\Butch.md` (개작 직후 717행 → 감사 후 **719행**)
원본: `03. PG\_backup\Butch.md.bak2` (1008행)
이관 제안: `03. PG\_AUDIT\Butch-playbook.md` (26건 → 감사자 보충 2건 = **28건**)

## 근거 출처 — 실제로 연 것만

| 출처 | 무엇을 확인 |
|---|---|
| `~/PG/Butch/nmap.log` (2219B) | nmap 블록 전문 대조 — **본문 전량 일치** |
| `~/PG/Butch/whatweb.txt` (529B, ANSI 포함) | whatweb 한 줄 대조 — ANSI 제거 후 **문자열 완전 일치** |
| `~/PG/Butch/nc64.exe` (45272B, mtime `2026-08-18 12:53:36`) | 리버스셸 「준비 기록」 실재 확인 |
| `~/.zsh_history` | `:2179`·`:2222`·`:2223`·`:2225`·`:2226`·`:2228`·`:2289`·`:2314`·`:2315`·`:2318`·`:2181`·`:2182`·`:2290` |
| 볼트 `파일보관\` 6장 | 전부 **직접 열어봄** (아래 각 항목) |
| Kali 직접 실행 | `sha256sum` 4회 · `nmap-services` 450/tcp 순위 조회 |

---

## 1. 고친 것 (6건)

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `**Vulnerability Explanation:** 세 결함이 사슬로 엮임.` | **내부 모순** — 「세 결함」인데 이어지는 불릿이 **4개**. 심사관이 세다 걸림 | `결함 넷이 겹쳐 무인증 RCE 로 이어짐.` 로 정정. 「사슬」도 뺌 — R-3 으로 ①이 ②를 무기화했다는 인과가 반증됐으므로 「겹침」이 정확 |
| nmap 블록 캡션 `— 출처: ~/PG/Butch/nmap.log` | **출처 오귀속.** 블록의 첫 줄(`Starting Nmap 7.98 ( https://nmap.org ) at …`)과 끝 줄(`Nmap done: …`)은 **stdout 배너라 `-oN` 파일에 없음.** 로그 파일은 `# Nmap 7.98 scan initiated …` / `# Nmap done at …` 형태 | 캡션을 「대화형 Kali 터미널 세션 캡처. 스캔 본문은 `nmap.log` 와 일치하고 첫·끝 줄만 stdout 배너」로 정정. **펜스 안은 한 바이트도 안 건드림** |
| `` ```ps `` (RID 500 비밀번호 재설정) | `ps` 는 Prism/Obsidian 이 인식하지 않는 태그 — 하이라이팅이 죽음 | `` ```powershell `` |
| `> ``` ` ×2 (`reg add` 원복 · `reg save`→PtH, 시험 대안 콜아웃 안) | **언어 태그 없음** (표준 「코드펜스에는 반드시 언어를 붙인다」 위반). 유일한 무태그 2건 | 둘 다 `` ```text `` |
| `- PayloadsAllTheThings — MSSQL Injection` | 원본에 있던 **URL 이 소실**됨. 참고 자료 항목이 주소 없이 이름만 남음 | 원본 URL 복원 |
| 시험 규정 콜아웃(`Privilege Escalation`) | **이관 손실.** 「다른 응시자 방해」 반증 문단이 노트·제안서·`_PLAYBOOK` **셋 다에서 사라짐** — 아래 §3 참조 | 압축 복원(1문단). 1차 인용 4개 유지 |

## 2. 삭제한 것

**없음.** 이번 감사에서 노트 본문의 서술을 지운 것은 0건임.

---

## 3. 이관 손실 — 제안 26건 어디에도 없던 것 (하드 3건 + 경계 1건)

제안서의 자기 검산(「26건 전량 원문 인용」)을 믿지 않고 `.bak2` 를 직접 대조해 셈. **`Butch.md` · `Butch-playbook.md` · `_PLAYBOOK.md` 셋에 대해 `grep -c` 로 부재를 확인함.**

### L-1 🔴 「다른 응시자 방해」 반증 문단 — **제안서가 「노트에 남겼음」이라고 자기 신고했으나 거짓**

제안서 786행:

> ⚠️ 「타겟 변조 금지 조항은 없다 / … / 「다른 응시자 방해」는 은퇴한 PWK 랩에서 온 틀린 근거」 전문 콜아웃은 **이 박스가 실제로 그 변조를 했으므로 노트에 남겼음**(`Privilege Escalation` 절).

실측 — `grep "응시자\|private VPN\|PWK\|dedicated environment"` 히트: `Butch.md` **0** · `Butch-playbook.md` 0(위 신고 줄 제외) · `_PLAYBOOK.md` **0**.

**지우기 전 원문(`.bak2` 732–735행):**

`````
> "다른 응시자의 재현을 방해한다"는 틀린 근거인데, 왜 다들 그렇게 아는지는 따로 볼 값이 있다. OSCP 시험 환경은 응시자 전용이고 다른 응시자와 타겟을 공유하지 않는다.
> > "simulates a live network in a **private VPN**" / "The exam lab is a **dedicated environment with no learners connected other than yourself**" / "All of the machines have been freshly reverted at the start of your exam"
>
> 이 통념의 출처는 은퇴한 통합 PWK 랩이다. 당시 공식 문서는 *"Students may encounter exploits left by other learners"* 라고 공유 환경임을 명시했고, 그래서 "남의 익스플로잇이 굴러다닌다", "내가 망가뜨리면 남이 못 푼다"가 상식이었다. 현행 PG 는 정반대로 *"private machines … without having to worry that other users will access it"* 다. 커뮤니티 상식에도 유통기한이 있고, 랩 구조가 바뀌면 그 위에 세운 규칙도 함께 무효가 된다.
`````

**처리** — 반증된 서술이 아니라 **근거가 붙은 정확한 서술**이고(1차 인용 4개), 이 문단이 없으면 남은 콜아웃이 독자가 실제로 갖고 있는 통념을 처분하지 않은 채 끝남. 노트에 **압축 복원**했고, `_PLAYBOOK` 복제 등재 여부는 반영자 판단으로 남겨 제안서에 전문을 실어 뒀음.

### L-2 「자동화에 5분 이상 들어가면 손으로 넘어간다」 손절 기준 (`.bak2` 176행)

```
VIEWSTATE 파싱이 귀찮으면 브라우저에서 손으로 하는 편이 빠르고, 이 박스도 실제로 브라우저로 풀었다(스크린샷 참조). 시험에서 시간을 재는 기준은 단순하다 — 자동화에 5분 이상 들어가면 손으로 넘어간다.
```

노트에는 앞부분(「이 박스는 브라우저로 진행했고 스크린샷이 그 기록임」)만 남고 **손절 기준 숫자가 빠짐.** 손절선은 `_PLAYBOOK` 소재라 노트에 되살리지 않고 제안서에 「감사자 제안 1」로 추가.

### L-3 「남긴 것과 원복 방법을 함께 적고, 원복 불가 변경은 사전 서면 승인」 (`.bak2` 1001행)

```
이 목록이 곧 실무에서 하면 안 되는 것들의 목록이다. 침투테스트 보고서에는 남긴 것과 원복 방법을 반드시 적고, 원복이 불가능한 변경(해시 덮어쓰기·관리자 비밀번호 변경)은 사전 서면 승인 없이는 하지 않는다.
```

제안서에 「감사자 제안 2」로 추가.

### L-4 (경계) `.bak2` 618행 — 「IIS 박스에서 `SeImpersonate`→Potato 가 압도적으로 흔한 경로이고 이 박스는 그마저 필요 없었던 예외」

노트의 `whoami` 결과 표가 Potato 행을 이미 갖고 있어 **정보로서는 커버됨.** 「예외적이다」라는 상대적 위치 판단만 소실. 손실로 세되 조치는 안 함.

### 손실 아님으로 판정한 것 (제안서가 원문 인용을 안 했지만 내용이 살아 있음)

- `.bak2` 99–102 「웹이 80 이 아니라 450 에 있다」 콜아웃 → 노트 `-p-` 플래그 표 + A6 + B1 로 분산 생존
- `.bak2` 700 「여기서 막혀 30분을 태우는 사람이 많다」 → A 제안 1 의 「20~30분이 날아감」과 실질 중복
- `.bak2` 750 「목표는 플래그를 읽는 것이지 관리자로 로그인하는 것이 아니다」 → 0점 콜아웃이 같은 내용을 담음
- `.bak2` 626–632 foothold 5단계 요약 → 두 finding 의 `Steps to reproduce` 가 대체

---

## 4. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 «옳았던» 것

### R-A 🔴 ⓘ 「작성자가 §2 체인 논증과 §6⑨ 갈래를 지운 것이 과했나」 → **과하지 않았음. 되살리지 않음**

지시가 「최대 위험」으로 지목한 항목이라 스크린샷을 직접 열었음.

`파일보관\Pasted image 20260818110442.png` — 브라우저 URL 바 `192.168.243.63:450/Dev/` 가 보이고 **페이지 최상단**(제목 `192.168.243.63 - /Dev/` + `[To Parent Directory]` 가 다 보임)이라 스크롤 잘림 없음. 리스팅 본문:

```text
5/20/2020   6:37 AM        1014 site.master.txt
5/20/2020   6:37 AM        1191 style.css
```

**정확히 두 파일.** 이하 여백. 부재 증거가 아니라 **리스팅이라는 양성 증거**임.

추가 검산 — 노트가 싣고 있는 `site.master.txt` 전문 블록의 바이트 수를 셌음: LF 기준 990바이트 / 26행. 원본이 CRLF + 최종 개행 없음이면 `990 − 1 + 25 = **1014**` 로 리스팅 값과 **정확히 일치.** 즉 노트의 전문 전사는 **잘림도 개변도 없음**이고, 그 안에 DB 코드·`password_hash`·SHA-256 호출은 없음.

→ 「스키마·해시 알고리즘을 `/Dev/` 소스에서 얻었다」는 **반증이 맞음.** `§6 ⑨` 4행째(`/dev/` 의 나머지 파일)도 존재한 적 없는 갈래이므로 삭제가 옳음. 노트의 현재 서술(「셋을 어디서 얻었는지는 관측 없음」)이 정확함.

### R-B ⓔ Kali 프롬프트 4곳 — **전량 실측. 지우지 않았고 지워서도 안 됨**

`~/.zsh_history` 에 `cd Butch`(:2179·:2223·:2289) · `mkdir Butch`(:2222) · `whatweb …`(:2225·:2226) · `feroxbuster …`(:2228) · `cp nc64.exe ~/PG/butch`(:2314) · `cp … ~/PG/Butch`(:2315) · `rm butch`(:2318) — zsh 는 **대화형 세션에서만** 기록하므로 사람이 대화형 터미널에서 푼 레거시 박스임. 개작본이 4곳을 그대로 둔 것이 옳음.
타겟 pty 프롬프트는 `*Evil-WinRM* PS` **10곳** 전량 보존됨. 확인만 하고 손대지 않음.

### R-C ⓗ 「웹셸 0점」 서술 방향 — **정방향 유지됨. 뒤집히지 않았음**

- 취소선 행 `~~⑤ 특권 웹셸에서 직접 type proof.txt~~` 존재
- `> [!danger] ⚠️ 웹셸로 플래그를 읽으면 0점이다` 콜아웃 존재, 규정 원문 `this includes any type of web-based shell` 인용 정확
- `Local.txt value:` 에 「실제로 읽은 것은 권한상승 뒤 `Administrator` evil-winrm 세션에서임」 유보가 붙어 있고, `Post-Exploitation` 세션 블록이 타겟 pty 프롬프트로 그것을 증명함
- 4곳(요약 표 · 콜아웃 · 대안 목록 · 증거 형식 표)이 서로 모순 없음

정정 불필요.

### R-D 「기본 1000포트 스캔에 450 이 없다」 — **Kali 에서 직접 확인. 노트가 옳음**

표준이 명시적으로 경고한 유형의 단정(과거 「8082·9999는 기본 1000포트 밖」이 반증된 전례)이라 때려봄.

```text
tserver	450/tcp	0.000050	# Computer Supported Telecomunication Applications
```
`/usr/share/nmap/nmap-services` 를 개방빈도 내림차순 정렬해 상위 1000개를 뽑으면 `450/tcp` **히트 0**. 노트의 `-p-` 표와 `Steps to reproduce` 1번이 맞음.

### R-E 해시 대비 표 4행 — **Kali 에서 4회 계산, 전량 일치**

```text
printf 'butch'  → 48f9460fe0dc9f272e7414963dd2b52287ec07d872d665d2e9364c957f163ab0
echo 'butch'    → 141714383b1614e77057017a9d38eaf033724353a1d9a8c25cbf57566faf51cd
printf 'Butch'  → 7e4a6c94d902af155773c2c8c6c115e5414716c276b34f347b98e82d2a22c37e
printf 'BUTCH'  → faf32403fa9556a16f621d8c764586b4c0dcd9ce2d1a9fb4ed053d598bfa61d6
```
심은 값과 4행 표 전부 일치. 페이로드의 해시도 동일.

### R-F ⓕ 작성자 반증 4건 — **전부 노트에 «실제로» 반영돼 있음**

| # | 반영 여부 |
|---|---|
| ① DBMS 판정이 실측(스크린샷 `…110543`) → `[가정]` 제거 | ✅ 반영. 스크린샷 원문과 **한 글자씩 대조** — `(0x80131904)` · `Unclosed quotation mark after the character string "';.` · `MyNamespaceMain.MyClassMain.Login(Object sender, EventArgs e)` · `ClientConnectionId:26f38126-57aa-4687-b967-e9c7b267c2fc` · `Error Number:105,State:1,Class:15` 전부 일치. 출처 캡션도 붙음 |
| ② 앱풀 신원이 관측(스크린샷 `…111513`) → `[가정]` 제거 | ✅ 반영. 스크린샷 URL `192.168.243.63:450/webshell.ashx?cmd=whoami`, 응답 `nt authority\system`, 하단 `By @Hypn, for educational purposes only.` 전부 일치 |
| ③ 리버스셸 「준비 기록 있음 / 연결 관측 없음」 | ✅ 반영(`Post-Exploitation` 끝 문단). `nc64.exe` mtime `2026-08-18 12:53:36` 과 `~/.zsh_history:2289 cd Butch` → `:2290 rlwrap nc -lnvp 4444` 로 뒷받침됨 |
| ④ `shell.ashx` → `webshell.ashx` | ✅ 반영. 노트 7곳 전부 `webshell.ashx`. `shell.ashx` 는 GitHub 원본 파일명으로 1회만 등장(정확) |

### R-G 개작이 **원본의 오류를 고친** 곳 (통과)

`.bak2` 354행 「`src=` 속성은 **컴파일 시점** 컴파일을 뜻한다」 → 노트 「`src=` 는 **런타임** 컴파일을 뜻함」. ASP.NET `@Master`/`@Page` 의 `Src` 는 첫 요청 시 동적 컴파일이고, 미리 컴파일된 어셈블리를 가리키는 것은 `CodeBehind` 임. **개작 쪽이 옳음.**

### R-H 스크린샷 3장 추가 대조 — 전부 일치

- `…111108` — `Welcome to Butch's Ultimate File Repository!` + 업로드 폼 ✅ (URL 바는 잘려 있으나 경로 `repo.aspx` 는 `…111445` 가 증명)
- `…111445` — URL `192.168.243.63:450/repo.aspx` · 파일 `webshell.ashx` · `File uploaded successfully!` ✅
- `…111626` — URL `…/webshell.ashx?cmd=net+localgroup+"Remo…` · 명령 칸 `net localgroup "Remote Man` · `The command completed successfully.` ✅ 노트의 「URL 이 잘려 있으나」 캡션까지 정확

### R-I `whatweb.txt` — ANSI 제거본이 원문과 완전 일치

파일에는 ANSI 색상 이스케이프가 박혀 있음(`cat -A` 확인). 노트는 그것을 제거한 형태로 실었고, **제거 후 문자열은 한 글자도 다르지 않음.** 터미널 화면에 보인 것과 동일하므로 개변 아님.

---

## 5. 구조·색인 판정

| 항목 | 판정 |
|---|---|
| 4항목(`Vulnerability Explanation`·`Fix`·`Severity`·`Steps to reproduce`) | `Initial Access` · `Privilege Escalation` **각각 4개 = 8** ✅ |
| 4항목 안 「아래」·「위」 상대 참조 | **0건** ✅ |
| 두 `Initial Access` 제목 | 앞 = 긴 서술형 / 뒤 = 짧은 형, **서로 다름** ✅ |
| `Port Scan Results` 표 | 존재 ✅ |
| nmap raw 포트 줄(`21/tcp   open  ftp …`) | 7줄 전량 보존 — `PORT_RE` 정상 추출 ✅ |
| 코드펜스 언어 태그 | 54 펜스줄 = 27쌍, **무태그 0** (감사 전 2건 → 0) ✅ |
| Kali 프롬프트 / 타겟 pty 프롬프트 | 4 / 10 — **전량 보존** ✅ |
| 플래그 2개 값 | `0c5dba72fd1984addf833413a2f9c58e` · `18c3403c59645f8a20b213fe2b1768ef` — 무손실 ✅ |
| 프론트매터 주석 | 값 줄에 주석 **없음** ✅ |
| `manual_tags: true` · `tech_count: 7` | `tech/*` 7개와 일치. `tech/payload/revshell` **제거가 옳음**(연결 성립 관측 없음) ✅ |
| `manual_cves` | 불필요 — 본문에 `CVE-` 문자열 0건 ✅ |
| `manual_ports` | 불필요 — raw 에 오탐 포트 없음 ✅ |
| 정정 이력 콜아웃 | 노트 본문에 **없음** ✅ |
| 요약 줄 절 번호 나열 | 없음, `→ [[_PLAYBOOK]]` 로 끝남 ✅ |

**남은 흠(고치지 않음)** — `> [!info] 요약` 에 **난이도가 없고** 프론트매터에 `difficulty` 필드가 없음. `.bak2` 도 마찬가지였음. 확인된 출처가 없어 채우면 날조가 되므로 **비워 둠.** 총괄이 포털 값을 알면 채울 것.

## 6. 문체 이관

`pg-doc-reviewer` 로 넘길 건 **0건.** 산문 종결이 전량 명사형이고, 서술형이 남은 곳은 코드펜스 안과 규정 인용문(영문 원문)뿐임 — 둘 다 대상 아님.
