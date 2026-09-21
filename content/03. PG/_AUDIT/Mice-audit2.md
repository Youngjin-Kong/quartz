---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---

# Mice — 적대적 검증 2차 (개작본 감사, 2026-08-26)

대상: `03. PG\Mice.md` (개작 후 559행 → 정정 후 580행)
백업: `03. PG\_backup\Mice.md.bak` (489행)
이관 제안: `03. PG\_AUDIT\Mice-playbook.md` (본 감사에서 4곳 정정)
출처: `ssh kali@10.44.44.128:~/PG/Mice/` · 볼트 `파일보관\PG-Mice-*.png` 5장 · NVD/MITRE · Kali 로컬 실행

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `**어느 포트가 나가는지부터 한 번에 쟀다.** 포트를 바꿔가며 리스너를 찍는 대신` | **자기 산출물에 반박당함.** `shell53.log`(22:28:34)·`shell4444.log`(22:28:39)·`shell8080.log`(22:28:46)가 프로브(22:29:35)보다 **먼저** 생성됨 — 실제로는 포트별 리스너를 먼저 띄웠음 | 실제 순서대로 서술. 세 파일의 mtime 과 「`listening on ...` 한 줄로 끝났다」는 사실을 명시하고, 그래서 계층 구분이 안 돼 프로브로 전환했다는 인과로 교체 |
| `— 출처: ~/PG/Mice/shell443.log:866-869` | 866 행은 `Microsoft Visual C++ 2019 X86 Additional Runtime` 으로 **인용 블록에 없는 줄**. 인용된 3행은 867–869 | `867-869` 로 정정 + `--INSTALLED-SW` 절 발췌임을 캡션에 명시 |
| `— 출처: ~/PG/Mice/shell443.log:7832-7847` | 인용 블록의 마지막 줄(`CommandLine     :`)이 7848 행이라 범위가 한 줄 모자람 | `7832-7848` 로 정정 |
| `Get-Date 가 뱉은 DisplayHint~Year 전체 속성 목록은 위 인용에서 뺌` | 코드펜스 안 **생략**. 명시는 돼 있으나 실측 블록에 편집자의 손이 들어간 상태 | `proof_user.txt` 600B **전문**으로 복원. 캡션은 「전문(600B)」 + 첫 줄이 `divin`/`e\Desktop` 로 갈린 것이 셸 줄바꿈이라는 설명으로 교체 |
| `**원시 터미널 캡처가 없는 이유.** … 그 시점에 Kali SSH 가 끊겨 있었음` | **잘못된 인과 (백업에서 상속).** SYSTEM 획득(00:05) 이후에도 Kali 에 파일이 계속 기록됨 — `rdp41~44.png` 00:05:12~00:11:20, `harvest_admin.txt` 00:10:35, `http.log` `[21/Aug/2026 00:08:08] "GET /harvest.ps1"`. 끊긴 것은 Kali 접속이 아님 | 진짜 원인으로 교체 — **타겟→Kali 파일 회수 채널**(nc 리버스셸)이 `logoff`·재부팅으로 23:27:14 에 죽었고 재주입 2회도 콜백 없음(`rce_retry.log` 23:39 · `shell443b.log` 23:43). Kali 가 살아 있었다는 반증 근거를 본문에 명시 |
| `경위부터 적음. 세션 중 Kali SSH 를 세션 내내 잃었고 … 그 정리 과정에서 타겟으로 통하던 셸 세션도 함께 닫혔고` | 같은 오인과. 게다가 **타겟 셸은 Kali 정리보다 훨씬 앞선 23:27 에 logoff·재부팅으로 죽었음** — 정리가 원인이 아님 | 실제 경위로 교체. Kali 정리(tmux 세션명 종료 · `ss` 로 PID 특정)는 사실이므로 유지 |
| `*확인한 것* — 파일 업로드 없음` | 바로 아래 「확인 못 한 것」에 타겟 생성 파일 3개가 나열돼 표면상 모순 | `타겟에 올린 파일 없음(스크립트는 전부 irm 인메모리 실행)` 으로 명확화 |
| `— 실제 타이핑된 문자열: attempt3_obf.log` | 3회차가 성공한 주입인 것처럼 읽힘 | 3회차(22:31:11)임을 명시하고 1·2회차 로그·시각 병기 |
| `문자열을 쪼개고 iex 를 없앤 판으로 교체한 뒤(www/a mtime 22:32:24) 즉시 붙음` | 시각 서사가 압축돼 「어느 요청이 통했나」가 안 보임 | `http.log` 의 `/a` 요청 5건(22:28:02·22:29:35·22:31:11 / 22:33:06·22:34:14)과 교체 시각 22:32:24 를 대조해 서술. 3회차까지도 평문판이었다는 사실 추가 |
| `Local.txt / Proof.txt 셸 판정 표` | `proof_admin.txt` 가 무엇인지 노트 어디에도 없어 캡처로 오독될 여지 | 표 아래에 「`proof_admin.txt`(579B)는 캡처가 아니라 손으로 라벨을 붙인 요약본」 한 줄 추가 |
| tmux 리스너 블록 | 백업의 `세션 전문은 ~/PG/Mice/shell443.log(7,868행)` 출처가 개작에서 누락(제안 파일에도 없음) | 캡션으로 복원 |

### 이관 제안 파일(`Mice-playbook.md`) 정정 4건

| 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| A-2 `shell443.log:944-952` / `955-961` | 실제는 941–949 / 952–959. **3행씩 밀림** | 두 범위 모두 정정 |
| A-6 transcript 코드펜스 | `Configuration Name:` · `Machine: REMOTE-PC (Microsoft Windows NT 10.0.19042.0)` 두 줄을 **표시 없이 뺌**(undeclared elision). 그대로 `_PLAYBOOK` 에 들어가면 실측 파괴가 상속됨 | 두 줄 복원, 출처를 `288-294` 로 정정 |
| A-9 `그 시점에 Kali SSH 가 끊겨 있었음` | 노트와 같은 오인과 | 진짜 원인 + 반증 근거로 교체 |
| A-1 `하지 말 것 — 포트를 바꿔가며 리스너를 하나씩 찍는 것` / 「스테이저는 짧게」 앞 | Mice 가 **실제로 그것을 먼저 했다**는 시행착오와, **주입 4회 실패 순서**(`attempt1/2/3` · `rce_retry`)가 노트·제안 양쪽에서 소실 | 두 항목 모두 A-1 본문에 mtime 근거로 추가. 「주입 문자열이 아니라 서버 페이로드를 바꿔야 했다」는 반사로 승격 |

## 2. 삭제한 것

**없음.** 정정·강등만 수행. 코드펜스 안 실측(명령·출력·해시·플래그·IP·타겟 프롬프트)은 한 바이트도 바꾸지 않았고, `proof_user.txt` 는 오히려 **생략분을 복원**했다.

⛔ **`PS C:\WINDOWS\system32>` · `C:\>` 는 전부 유지했다.** Windows 에는 pty 개념이 없으므로 판정 근거는 산출물 자체다 — `proof_user.txt` 는 명령 에코 + 출력 + 프롬프트가 한 덩어리로 떨어진 nc 리버스셸 캡처이고, `C:\>` 는 스크린샷 픽셀에 그대로 있다.

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

1. **지시가 준 전제 「`shell443.log` 가 `~/PG/Mice/` 목록에 없다」가 틀렸다.** 파일은 존재한다 — `-rw-rw-r-- 1 kali kali 430595 2026-08-20 23:27:14 shell443.log`, 7,868행. 강등할 근거가 없으므로 관련 서술을 `근거부족` 으로 내리지 않았다.
2. **CVE-2021-35448 의 `It binds to local ports to listen for incoming connections.`** — NVD 페이지 렌더에서는 안 보여 「인용 날조」로 올렸으나, MITRE 원본(`cveawg.mitre.org/api/cve/CVE-2021-35448`)의 `descriptions` 에 그대로 있다. **노트가 옳다.**
3. **CVE-2022-3365 NVD 인용문** — *"Due to reliance on a trivial substitution cipher, sent in cleartext, and the reliance on a default password when the user does not set a password …"* 원문과 **한 글자도 다르지 않다.** CVSS 3.1 = 9.8 Critical 이라 노트의 `Severity: Critical` 도 맞다.
4. **Metasploit 모듈이 대상을 `< 4.200` 으로 명시한다** — Kali 로컬 소스 확인. `/usr/share/metasploit-framework/modules/exploits/windows/misc/remote_mouse_rce.rb` 의 Description 에 `on versions < 4.200 (500 server response)`, References 에 `[ 'EDB', '46697' ]` + `[ 'CVE', '2022-3365' ]`. **노트가 옳다.**
5. **「1978~1980 이 기본 1000 포트 밖」** — 표준이 경고한 유형(Hub 사례)이라 의심했으나 실측으로 확인. `nmap-services` 에서 `unisql 1978/tcp 0.000000` · `unisql-java 1979/tcp 0.000000` · `pearldoc-xact 1980/tcp 0.000000`, `--top-ports 1000` 목록에 셋 다 없음. `nmap_quick.log` 가 스스로 3389 하나만 뱉은 것과도 일치. **노트가 옳다.**
6. **`dir C:\freezeScript` → `File Not Found`** — 백업은 `The system cannot find the file specified` 라고 적었고 개작본이 `File Not Found` 로 바꿨다. 「개작이 문구를 지어냈다」로 올렸으나 `shell443.log:380` 이 `cmd : File Not Found`. 백업 쪽이 **`icacls` 의 에러 문구를 `dir` 의 것으로 오인**한 것이었다. **개작본이 옳고 원본을 고친 것이다.**
7. **`harvest_divine.txt:429-434` · `shell443.log:470-486` · `:671-673`** — 전부 행 단위로 정확히 일치. 인용 정확도는 전반적으로 높다.
8. **`harvest_divine.txt` 6,692행** — `wc -l` 로 확인, 일치. `SeImpersonatePrivilege` 는 파일 전체 grep 에 0건이라 「없음」 서술도 맞다.
9. **`proof_admin.txt` 는 한 화면이 아니다** — 작성자의 자기반증이 맞다. 실물이 `whoami:   nt authority\system` 식 라벨 형식의 수기 요약이다. 노트의 `proof.txt` 1차 증거를 스크린샷으로 잡은 판단이 옳다.
10. **`PG-Mice-proof-system.png` 픽셀 대조** — 노트 전사본 7행이 화면과 일치(명령행·`nt authority\system`·`Remote-PC`·IPv4·`Thu 08/20/2026`·`08:05 AM`·플래그). `PG-Mice-harvest-system-9282.png` 전사본도 일치(`9282`·`===== DONE =====` 포함).
11. **구조 요건 전부 충족** — 두 finding 각각에 4항목, 첫 `Initial Access` 는 4항목만, `Port Scan Results` 표 있음, nmap raw `1978/tcp open …` 보존, `## Target #1` 래퍼 + `###` 헤딩, 두 `Initial Access` 제목 상이(긴 서술형 / 짧은 형), **여는 펜스 28개 전부 언어 태그 있음**.
12. **이관 손실 0** — 백업 0장 4항목·6장 10문단·7장 8항목·1장 1항목 = 22건이 전부 제안 파일에 「지우기 전 원문」으로 인용돼 있고, 8장 4항목은 노트의 `Vulnerability Fix:` 두 곳으로 분산돼 있다. `[가정]` 2건(평문 스테이저 AMSI 추론 · 트레이 아이콘 렌더링 메커니즘) 보존, 「관측 없음」 1건(`ERR_*`·`RTP_unknown` 의미) 보존.

## 4. 근거 출처

- **Kali 산출물** — `~/PG/Mice/` 전량 나열(mtime 포함) · `nmap.log`·`nmap_quick.log`·`nmap_udp.log`·`banner_1978.txt`·`banner_others.txt`·`http.log`·`proof_user.txt`·`proof_admin.txt`·`attempt1_type.log`·`attempt2_diag.log`·`attempt3_obf.log`·`rce_retry.log`·`shell443.log`·`shell443b.log`·`shell53/4444/8080.log`·`up80.log`·`writeup_notes.txt`·`harvest_divine.txt`·`www/a`·`www/a.revshell443`·`www/rpc.ps1`
- **스크린샷** — `파일보관\PG-Mice-proof-system.png` · `PG-Mice-harvest-system-9282.png` 직접 열어 픽셀 대조
- **1차 사료** — NVD CVE-2022-3365 · MITRE CVE-2021-35448 (`cveawg.mitre.org` API)
- **Kali 직접 실행** — `grep … /usr/share/nmap/nmap-services` · `nmap --top-ports 1000 -sL` · `cat …/remote_mouse_rce.rb`
- **git/백업** — `03. PG\_backup\Mice.md.bak` 대조

## 5. 총괄에 넘기는 것 (감사자가 손대지 않음)

- **frontmatter** — `os/windows` 태그 및 `os: windows` 필드 부재, `ports` 에 7680 누락(본문 `Port Scan Results` 표는 `1978, 1979, 1980, 3389, 7680`). 색인 파이프라인 소관이라 미수정.
- **색인 갱신 필요** — 본문 정정으로 `refresh.ps1` 재실행이 필요하나 공유 인프라라 실행하지 않음.
- **`_STATUS.md`** — 판정: **완료 2/2**(`local.txt` `e5fe064cc8ccf3adb8c974baf67f12c5` · `proof.txt` `31a64d6f198f495e89d3f3e134da9588`, 둘 다 대화형 셸 원위치 읽기 증거 있음). 기록은 `pg-line-manager` 몫.
- **`_PLAYBOOK` 반영 시 주의** — A-2 · A-6 · A-9 · A-1 을 본 감사에서 고쳤으므로 **정정된 `Mice-playbook.md` 를 기준으로** append 할 것.
