---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# Nagoya — 적대적 검증 + 정정 (웨이브 13)

대상: `03. PG\Nagoya.md` (개작 직후 807행 → 정정 후 829행)
기준: `03. PG\_WRITEUP-STANDARD.md` · `CLAUDE.md` §3·§4·§8

---

## 총평

**이 노트는 산출물 대조에서 이례적으로 정확했다.** 날조는 한 건도 나오지 않았다.
zsh 히스토리 명령 20여 건, BloodHound JSON 4종, `hash.txt` 바이트 길이, ferox state 3종,
스크린샷 8장을 대조했고 **값·명령·출력이 전부 일치**했다. 정정은 전부 「설명·인과·표기」 쪽이다.

### 실측으로 «확인»된 것 (반증 실패 = 노트가 옳음)

| 노트의 주장 | 대조 출처 | 결과 |
|---|---|---|
| `┌──(kali㉿kali)` 프롬프트 25개 | `파일보관\Pasted image 20260707111021.png` 등 **스크린샷에 프롬프트가 그대로 찍혀 있음** | ✅ 실측. 전량 보존 |
| `proof.txt = be83df05d75cfee867192bdf8dcd2fdb` | `…20260707105621.png` 확대 판독 | ✅ 한 글자도 안 틀림 |
| NT해시 `e3a0168bc21cfb88b95c954a5b18f57c` | `…111021.png` + `~/.zsh_history` ticketer 명령 | ✅ 이중 확인 |
| 도메인 SID `S-1-5-21-1969309164-1513403977-1686805993` | `…111134.png` + ticketer 명령 | ✅ 이중 확인 |
| `hash.txt` 두 줄 = 2389자 / 2383자 | `awk '{print length($0)}' hash.txt` | ✅ 정확 |
| krb5tgs 접두 160자 인용 | `cut -c1-200 hash.txt` | ✅ 바이트 일치 |
| kerbrute 출력 블록 26줄 전문 + `405 usernames (26 valid) in 139.416 seconds` | `…20260706144017.png` | ✅ 전줄 일치 |
| klist / mssqlclient 배너 블록 | `…20260707104049.png` (노트 미임베드) | ✅ 전줄 일치 |
| `xp_cmdshell whoami` → `nagoya-ind\svc_mssql` | `…20260707104209.png` | ✅ 일치 |
| `nagoya-ind\nagoya$` · `50031` · `10.0.17763.4252` | `…20260707105454.png` | ✅ 일치 |
| GetUserSPNs 표(`2023-04-30 16:31:06.190955` 등) | `…20260707111345.png` (노트 미임베드) | ✅ 일치 |
| EMPLOYEES → GenericAll 4명(iain.white·joanna.wood·bethan.webster·svc_helpdesk) | `20260706153247_users.json` 파싱 | ✅ 정확히 4명 |
| HELPDESK → GenericAll **21명 = EMPLOYEES 멤버 21명과 동일 집합** | 같은 JSON + `groups.json` | ✅ 집합이 정확히 일치 |
| DEVELOPERS = Remote Management Users 의 유일 멤버 | `groups.json` | ✅ |
| `Domain Controllers`→`GetChangesAll` / `Enterprise Domain Controllers`→`GetChanges` | `20260706153247_domains.json` | ✅ 정확 |
| ferox 200 응답 12개 · 3회차 913 중 901이 503 · 세 state 전부 `Running` | state 3종 JSON 파싱 | ✅ 정확 |
| ticketer `-groups` 기본 `513, 512, 520, 518, 519` / `-duration` 기본 `24*365*10` | Kali 에서 `impacket-ticketer -h` 직접 실행 | ✅ 문자열까지 일치 |
| ligolo-ng **v0.8.2** | `go version -m ~/PG/Nagoya/agent.exe` → `-X main.version=0.8.2` | ✅ 정확 |
| `names.txt` 28 / `users.txt` 405 / `valid_users.txt` 26 / `season_pass.txt` 4 | 파일 직접 확인 | ✅ |
| `net rpc password` 두 줄(따옴표 형태까지) | `~/.zsh_history` 1686·1687행 | ✅ 바이트 일치 |
| 타겟 시계 UTC-7 (`18:30:42-07:00` → KST 10:30:42) | nmap `System_Time +00:00` 대조 환산 | ✅ 정합 |
| `Administrator.ccache` mtime 2026-07-07 10:39:08 = klist `Valid starting` | `ls --time-style=full-iso` | ✅ 정합 |
| 「이 박스 구간 스크린샷 24장」 | `파일보관\` 의 `Pasted image 2026070[67]*` 28장 중 오전 4장(Resourced)을 뺀 24장 | ✅ 정확 |

---

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `- 시행착오·시험 관점·기법 카드 전량 → [[_PLAYBOOK]] (이관 제안: …)` | **내부 작업 경로 노출.** `_WRITEUP-STANDARD` §4 위반 — 공개 발행 노트에 감사·이관 작업 기록이 남음 | `- [[_PLAYBOOK]] — 시행착오·시험 관점·기법 카드의 유일한 소재지` 로 교체 |
| `[[_PLAYBOOK]] \`B\` (스프레이 카드) · \`A-5\`(자격증명은 맞는데 로그인이 안 된다)` | **댕글링 앵커.** `_PLAYBOOK` 의 `A-5` 는 「Active Directory」 **카테고리 제목**이고 「자격증명은 맞는데 로그인이 안 된다」 항목이 아님. `B` 는 번호가 아니라 대분류. 두 항목 모두 아직 append 되지 않은 신규 제안(`Nagoya-playbook.md` #5·#7) | 번호를 빼고 `[[_PLAYBOOK]]` 만 남김. 실재 앵커 `A-24`·`B-71` 은 `## 관련` 절에 그대로 유지 |
| `나머지 DEVELOPERS 멤버 … 는 ACCOUNT OPERATORS 만 통제` | **실측과 불일치.** `users.json` 상 네 계정 모두 Domain Admins(Owns+GenericAll)·Enterprise Admins·Administrators(WriteDacl 등)·Account Operators 가 함께 통제. 「Account Operators **만**」은 거짓 | 「도메인 특권 그룹만 있고 **EMPLOYEES/HELPDESK 는 없음**」으로 재서술 + 출처 파일 명시. 결론(2홉이 필요한 이유)은 그대로 성립 |
| `-Pn 필수 — 이 박스는 ICMP 를 안 받음.` | **근거 없는 단정.** nmap 을 처음부터 `-Pn` 으로 돌려 ICMP 응답 여부를 관측한 적이 없음 | 「PG 타겟은 대체로 ICMP 를 드롭함. 이 박스가 실제로 받는지는 확인 기록 없음(관측 없음)」으로 강등 |
| `웹 자체에는 취약점이 없고` | 「배제했다」와 「못 찾았다」의 혼동(`CLAUDE.md` §3) | 「웹에서 별도 취약점은 찾지 못했고」 |
| `(26줄 전부 같은 메시지. 원문은 \`~/PG/Nagoya/\` 세션 기록 참조.)` | **없는 출처를 가리킴.** `~/PG/Nagoya/` 에 GetNPUsers 출력 파일이 없음 | 「출처: 원본 손기록. … 출력 파일은 남지 않음」으로 정정 |
| nmap raw 블록 | **TRACEROUTE 4홉 블록 + `OS and Service detection performed…` 줄이 생략**됨. `\| rdp-ntlm-info:` 등 4곳의 후행 공백도 탈락 | `~/PG/Nagoya/nmap.log` 원문 그대로 복원 + 출처 캡션 추가 |
| ligolo 코드펜스 `# (1) ligolo 인터페이스 UP …` 외 2줄 | **펜스 안에 작성자가 쓴 한국어 주석.** 실측 명령이 아님 | 주석을 펜스 밖 산문으로 이동. 명령은 `~/.zsh_history` 원문(`sudo ip tuntap add … && sudo ip link set ligolo up` 포함)으로 **바이트 그대로** 유지 + 출처 캡션 |
| nxc 스프레이 블록 | 출처 표기 없음(`…(중략)…` 가 원문 표기인지 후가공인지 불명) | 캡션 추가 — 원본 손기록 출처, 출력 파일 미보존, `craig.carr:Spring2023` 은 이후 명령 6건으로 독립 확인됨을 명시 |
| `28명 중 matthew.harrison·emma.miah 는 kerbrute 목록에 없어 26개` | 관측은 옳으나 **결론이 빠짐** — 두 계정은 실재하는 활성 계정이고 kerbrute 가 거짓 음성을 냄 | 「⚠️ kerbrute 의 거짓 음성」 단락 신설. `users.json` 의 `enabled: true` + EMPLOYEES 멤버십을 근거로 제시하고, 원인은 「관측 없음」으로 유보 |

## 되살린 것 (이관 손실 복원)

`Nagoya-playbook.md` 검산 247행이 **「수동 대안 표는 finding 프로즈에 흡수」라고 적었으나 실제로는 흡수되지 않았다.**
`.bak2` 7장 「수동 대안(자동 도구 없이)」 7행 표와 910행 「금지 도구 없음」 판정이 노트·playbook 어느 쪽에도 없었다.
`_WRITEUP-STANDARD` 원칙 5(수동 대안 항상 병기, 자리는 해당 finding 재현 산문)에 따라 복원:

| 복원 위치 | 내용 |
|---|---|
| `Initial Access` 재현 — 계정명 생성 뒤 | username-anarchy → 손규칙 5개 / kerbrute → `impacket-GetNPUsers -no-pass` 반복 |
| 스프레이 블록 뒤 | nxc → `for p; do for u; do smbclient -L …` (비밀번호 바깥 루프 유지). **「이 박스에서 실행한 형태는 아님」 명시** |
| ACL 표 뒤 | BloodHound → `impacket-lookupsid` + `ldapsearch … memberOf`. ACE 는 `nTSecurityDescriptor` 수동 파싱이라 느림 |
| ACL 표 뒤 | **시험 규정 판정 복원** — 쓴 도구 전부 허용(BloodHound·kerbrute·username-anarchy·nxc·impacket·hashcat·ligolo·PrintSpoofer). Metasploit 미사용 |
| nxc-sweep 판정 뒤 | nxc-sweep → `nc -zv` + 서비스별 클라이언트 / ligolo → chisel·`plink -R`, SSH 가 있으면 `ssh -L`(이 박스엔 SSH 없음) |
| PrintSpoofer 실행 뒤 | PrintSpoofer → GodPotato·JuicyPotatoNG |

`nxc-sweep` 이 「nxc 호출 래퍼」라는 서술은 `/usr/local/bin/nxc-sweep` 원문을 열어 확인함(bash 스크립트).

## 삭제한 것

**없다.** 정정·강등·재서술만 했고 실측 블록은 한 줄도 지우지 않았다.
프롬프트 25개·스크린샷 임베드 20개 전량 보존.

---

## 반증한 것 — 내 자신의 지적 중 되짚어보니 틀렸던 것

1. **「nxc 스프레이 블록과 nxc-sweep 블록은 산출물이 없으니 날조 의심」** → **틀렸다.**
   `.bak2` 380~458행과 **바이트 단위로 동일**하다. 개작이 만든 것이 아니라 사람이 쓴 원본 노트에서 그대로 옮겨진 것이고,
   명령 자체는 `~/.zsh_history` 에 있으며 `craig.carr:Spring2023` 은 이후 6건의 명령에서 실제로 쓰였다.
   부재를 근거로 삭제했다면 실측 파괴였다. **등급 `근거부족` 이 상한**이라는 규율이 정확히 이 자리에서 작동했다.

2. **「`whatweb http://192.168.120.21` 이 `~/.zsh_history` 에 없으니 창작」** → **틀렸다.**
   히스토리에는 다른 박스(`192.168.120.100`)의 whatweb 만 남아 있으나,
   `~/PG/Nagoya/whatweb.log`(mtime 07-06 13:32:07)에 **192.168.120.21 대상 출력이 실재**한다.
   zsh 히스토리는 `hist_ignore_dups` 등으로 완전하지 않다 — 히스토리 부재는 미실행의 증거가 아니다.

3. **「HELPDESK GenericAll 대상 21명 = EMPLOYEES 멤버 21명은 스크린샷 육안 판정이라 부정확할 것」** → **틀렸다.**
   `groups.json`·`users.json` 을 파싱해 두 집합을 실제로 비교했고 **정확히 일치**했다.
   오히려 스크린샷(`…154341.png`)에 `matthew.harrison`·`emma.miah` 가 보이는 것이
   kerbrute 거짓 음성을 잡는 단서가 됐다.

4. **「ligolo v0.8.2 는 출처 없는 버전 단정」** → **틀렸다.**
   `go version -m agent.exe` 의 ldflags 에 `-X main.version=0.8.2` 가 박혀 있다.

5. **「`Local.txt value: 없음` 은 근거가 얇다」** → **틀리지 않았으나 강등 불필요.**
   「산출물·히스토리·스크린샷 24장을 확인했으나 흔적 없음 / 박스 정지로 재수집 불가 / `[가정]` 표준 위치」로
   이미 근거·유보가 모두 붙어 있다. 스크린샷 24장이라는 수치도 실측과 일치했다. **판정 `partial` 유지가 옳다.**

---

## 총괄 판단이 필요한 것 — 다른 노트의 같은 유형

같은 「내부 작업 경로 노출」이 **스코프 밖 노트 3건**에 있다(수정하지 않음):

| 노트 | 행 | 문자열 |
|---|---|---|
| `Exghost.md` | 28 | `> 시행착오·교훈 → [[_PLAYBOOK]] (이관 제안: \`03. PG\_AUDIT\Exghost-playbook.md\`)` |
| `Fikklish.md` | 84 | `(시행착오는 \`_PLAYBOOK\` 이관, \`03. PG\_AUDIT\Fikklish-playbook.md\` 항목 6)` |
| `LazySysAdmin.md` | 28 | `> 시행착오·교훈 → [[_PLAYBOOK]] — 상세는 \`03. PG\_AUDIT\LazySysAdmin-playbook.md\`` |

**성격이 다른 두 번째 부류** — `_AUDIT\portal-진행도-실측-20260820.md` 를 **근거 출처로** 인용하는 노트 5건
(`Codo`:257 · `Exghost`:33,284 · `Hawat`:489 · `Jacko`:748 · `Muddy`:344).
이쪽은 「작업 과정 기록」이 아니라 「판정의 근거」라 §4 의 나가는 것/남는 것 중 **남는 것 쪽에 가깝다.**
다만 공개 발행 시 내부 파일 경로가 그대로 노출되는 것은 같으므로 **표기 방식(경로 대신 「포털 전수 조회 실측」 등)을 총괄이 일괄 결정**할 사안이다.

## 색인

`ports`·`services` 는 자동 갱신 필드이고 이번 정정으로 nmap raw 의 포트 줄은 **21개 그대로**다(TRACEROUTE 복원은 포트 줄이 아님).
`manual_tags`·`manual_cves`·`manual_status` 선언 유지, `tech_count: 13` = 실제 `tech/*` 13개 일치.
**색인 갱신은 불필요하나**, 이번 웨이브의 다른 노트와 묶어 돌린다면 함께 반영되면 된다. `refresh.ps1` 은 실행하지 않았다.

## 근거 출처

- Kali 산출물 — `~/PG/Nagoya/` 전량(`nmap.log`·`whatweb.log`·`names.txt`·`users.txt`·`valid_users.txt`·`season_pass.txt`·`hash.txt`·BloodHound JSON 7종·ferox state 3종·`agent.exe`·`Administrator.ccache`)
- `~/.zsh_history` — Nagoya 구간 약 60행
- 볼트 `파일보관\` — `Pasted image 20260706144017 / 154341 / 20260707104049 / 104209 / 105242 / 105454 / 105621 / 111021 / 111134 / 111345 .png` (8+2장 Read 로 직접 판독)
- 백업 — `03. PG\_backup\Nagoya.md.bak2`(967행)
- Kali 직접 실행 — `impacket-ticketer -h` · `go version -m agent.exe` · `head /usr/local/bin/nxc-sweep` · BloodHound JSON python 파싱
- 기준 — `03. PG\_WRITEUP-STANDARD.md` · `CLAUDE.md`
