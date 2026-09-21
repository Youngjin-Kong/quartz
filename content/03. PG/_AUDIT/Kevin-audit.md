---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
manual_ports: true
manual_services: true
---
# Kevin — 적대적 검증 + 정정 (2026-08-26)

대상 `03. PG\Kevin.md` (개작본 598행). 감사자가 근거를 쥔 채 직접 정정함.

> [!warning] 증거 상황
> Kali `~/PG/Kevin/`·`~/Kevin/` **부재 재확인**(`ls: cannot access '/home/kali/PG/Kevin'`·`'/home/kali/Kevin'`) · 볼트 `파일보관\` 스크린샷 0장 · `~/.zsh_history` 흔적 0건.
> 따라서 **노트 본문 자체가 유일한 사료**임. 부재를 근거로 한 날조 판정은 하지 않았고, 검증은 ①블록 바이트 대조 ②노트 내부 정합성 ③Kali 직접 실행으로 반증 가능한 단정 셋에 집중함.

## 1. 고친 것 (5건 — 위치 · 무엇이 틀렸나 · 어떻게 고쳤나)

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 플래그 해설표 `` `-p-` `` 행 | 「`-p-` 없으면 3573 과 **49152~49160(동적 RPC)**을 놓침」 — **반증됨.** 49152(0.007907)·49153(0.006158)·49154(0.006767)·49155(0.005702)·49156(0.005322)·49160(0.000380) 전부 top-1000 커트라인 **0.000152** 위라 기본 스캔에도 잡힘 | 「`-p-` 로만 추가되는 것은 **3573 하나**」로 정정하고 빈도 수치를 근거로 명시 |
| 플래그 해설표 `` `-sV` `` 행 | 「**이게 없으면 이 박스는 못 품** — `GoAhead WebServer` 가 안 나옴」 — **반증됨.** 결정적 단서인 `http-title: HP Power Manager` 는 `-sC` 만으로도 나옴. **바로 다음 행(`-sC`)이 스스로 그렇게 적고 있어 내부 모순이기도 했음** | `-sV` 가 단독으로 주는 것(VERSION 열 · `http-server-header`)만 남기고, 제품명은 `-sC` 소관임을 명시 |
| 「확인 후 접은 벡터」 445 SMB 행 | 「Win7 7600 은 MS17-010 후보이긴 하나 **Metasploit 카드를 소모함**」 — MS17-010 은 비-MSF 공개 PoC 로도 익스플로잇되므로 카드 소모가 필연이 아님. 미검증 단정 | 카드 서술을 빼고 실제 판단 근거(80번이 제품명까지 특정된 더 명확한 경로)로 대체 + 「**관측 없음** — SMB 벡터는 시도하지 않았음」 유보 부착 |
| badchar 절 「`,`·`;` 를 빠뜨린 것이…」 | `` `[가정 — 352바이트를 전수 대조하지는 않았음]` `` — **대조가 가능한데 안 한 것이었음.** 셸코드가 노트 본문에 전량 실려 있음 | **전수 대조를 실행해 `[가정]` 을 실측으로 승격.** 352바이트 확인 · `,`(0x2c)·`;`(0x3b) **0개** · 모듈 정본 목록 중 실제 혼입은 `$`(0x24) **1개**뿐. `$` 는 RFC 7230 `tchar` 라 `Accept:` 파싱을 깨지 않음 |
| 오프셋 지도 `\xeb\xc2` 설명 | 「753 − 62 = 691 — NOP 슬레드(689~718) **한가운데**」 — 691 은 30바이트 슬레드의 **3번째 바이트**임 | 「슬레드의 **3번째 바이트**」로 정정 |

## 2. 삭제한 것

**없음.** 정정·강등만 했고 절 단위 삭제는 하지 않음.

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 «노트가 옳았던» 것

| 의심 | 확인 방법 | 결과 |
|---|---|---|
| **ⓑ 코드블록 절단** (직전 웨이브에서 nmap raw 가 줄 중간 81바이트 절단된 전례) | `git show HEAD:"03. PG/Kevin.md"` 와 **md5 바이트 대조** | **절단 0건.** 19블록 중 17블록이 직전판과 **바이트 완전 일치**(nmap raw 2,907B 포함). 작성자 신고가 정확했음 |
| 새로 등장한 블록 2개가 창작인가 | Kali 직접 조회 | ① `tag-ups-1\t3573/tcp\t0.000000\t# Advantage Group UPS Suite` → `/usr/share/nmap/nmap-services` 와 **탭 위치까지 바이트 일치**(`cat -A` 확인) ② `-b '\x00\x0a…\x5c'` 은 관측 출력이 아니라 모듈 `BadChars` 중복제거 산물이고 **20바이트 계산이 정확함** |
| **「이 명령의 실제 결과 : 00 0a 0b 0d 1a 20 23 25 26 2b 2f 35 3a 3f 5c 78」이 지어낸 계산인가** | Kali 에서 `Rex::Text.dehex` 를 **직접 실행** | **문자 하나까지 일치.** `\x5` 가 정규식 `/\x5cx[0-9a-f]{2}/` 에 매치되지 않아 리터럴 `\`·`x`·`5` 로 남는다는 인과도 소스(`rex-text-0.2.61/lib/rex/text/hex.rb:147`)로 확인. msfvenom 이 `-b` 를 `hex_to_raw` 가 아니라 **`dehex` 로 파싱**하는 것도 `/usr/share/metasploit-framework/msfvenom:153` 에서 확인 |
| top-1000 커트라인 `0.000152` | `nmap-services` tcp 빈도 정렬 1000번째 | **정확함** |
| **ⓒ 이관 손실** — 「삭제 561 / 이관 562 / 인용 없이 사라진 행 0」 | `bak2` 1115행 전수 대조(부록 인용 범위 562행 + 새 노트 본문 매칭) | **실측 손실 0건.** 다만 「인용 없이 사라진 행 **0**」은 **부정확**함 — 원본 446~491행(2-7 페이로드 조립)이 부록 인용 범위 밖임. 실제로는 그 구간 내용이 새 노트(오프셋 지도·세 가지 짚을 것)와 `Kevin-playbook.md` 제안 7 로 **나뉘어 살아 있고**, 어디에도 없는 것은 수사·상투구 3줄뿐임(「세 가지를 짚어야 한다」·「이 박스에서는 PoC가 이미 맞춰 놨으므로…」·`.pack('V*')` 부연 1줄) |
| **ⓐ 4항목 중복 계상** | 절 전수 확인 | **정본대로임.** 4항목은 긴 서술형 `Initial Access` 절에만 있고, 짧은 제목의 재현 절·`Privilege Escalation – 없음` 에는 없음 |
| **ⓔ Kali 프롬프트 창작** | 4개 블록 전부 md5 로 직전판과 대조 | **전부 기존 블록.** 작성자가 새로 만들어 붙인 프롬프트 **0개** → 그대로 둠. 타겟 pty 블록(`C:\Windows\system32>` 2개)도 바이트 일치 상태로 보존 |
| **ⓕ 작성자 반증의 노트 반영** | 본문 확인 | ① `tag-ups-1` = 「HP 제품 확정 근거 아님」 → 본문 3573 절에 `[가정]`·「관측 없음」으로 반영됨 ② `manual_services: true` 선언·`manual_ports` 미선언 → frontmatter 그대로 ③ Metasploit `check` 카드 소모 단정 → **노트 본문에서 제거되고 playbook 제안 17 로 이관, 「규정 원문 미검증」 경고 부착.** 세 건 모두 반영 완료, 보고에만 있고 노트에 없는 것 없음 |
| **ⓖ 자기모순** | frontmatter ↔ nmap raw ↔ 표 ↔ 산문 대조 | `ports`·`ip`·CVE·플래그 값·오프셋 산술(721−32=689 · 751 · 755..757 · `0xC2`=−62)·페이로드 크기 352B **전부 정합.** 발견된 모순은 위 1절 `-sV` 행 하나뿐 |
| 셸코드 첫 12바이트가 `call4_dword_xor` 디코더 스텁인가 | 본문 `buf` 파싱 | `31 c9 83 e9 ae e8 ff ff ff ff c0 5e` — `call $+4`/`inc eax`/`pop esi` 스텁과 일치. 「`alpha_mixed` 가 아니다」는 판정이 맞음 |

## 4. 총괄 판단이 필요한 것 — `inject.py` 가 `manual_services`·`manual_ports` 를 지운다 (**사실 확인됨**)

작성자 주장이 **맞음.** 고치지 않았음 — 공유 인프라라 총괄 몫.

- `_INDEX\_tools\inject.py` `build_fm()` 는 프론트매터를 **전량 재작성**하는데, 되돌려 쓰는 선언은 `manual_tags`(64행) · `manual_cves`(67행) · `manual_status`(70행) · `manual_domain`(74행) **넷뿐**임
- `manual_ports`·`manual_services` 는 **출력되지 않음** → 다음 `refresh.ps1` 에서 선언이 사라지고, 그 다음 `extract.py` 가 본문 스캔을 되살려 **오탐이 색인에 복귀함**(Kevin 은 `services` 에 `tag-ups-1` 이 되돌아옴)
- `extract.py` 쪽은 정상임 — `MANUAL_SVC_RE`(173행)·`MANUAL_PORT_RE`(175행)로 선언을 읽고 `meta["manual_services"]`(390행)·`meta["manual_ports"]`(376행)까지 세움. **끊긴 지점은 `inject.py` 한 곳**
- 같은 함정을 `manual_domain` 주석(77행)이 이미 명시하고 있음 — 「이 줄을 빼면 선언이 사라져 다음 refresh 때 휴리스틱이 되살아난다 — 무한 회귀다」. **동일 결함이 두 키에 남아 있는 것**
- 영향 범위는 Kevin 하나가 아님 — `manual_ports`/`manual_services` 를 선언한 노트 전부([[Muddy]]·[[MiddlewareBypass]] 등)

**색인 갱신 필요** — 이 노트는 `services` 에서 `tag-ups-1` 을 뺀 상태이나 `refresh.ps1` 은 감사자가 돌리지 않았음(규율).

## 5. 근거 출처

- git — `git show 15671e5:"03. PG/Kevin.md"`(176행 최초판) · `git show HEAD:"03. PG/Kevin.md"`(1115행 직전판) · `03. PG\_backup\Kevin.md.bak2`(1115행, 직전판과 굵게·콜아웃 표기만 다름)
- Kali 직접 실행 —
  - `grep -P '^tag-ups-1\t' /usr/share/nmap/nmap-services | cat -A`
  - `ruby -e 'Rex::Text.dehex(...)'` (rex-text 0.2.61)
  - `grep -n badchars /usr/share/metasploit-framework/msfvenom` → 153행 `Rex::Text.dehex(b)`
  - `awk` 로 nmap-services tcp 빈도 정렬 → 1000번째 = `0.000152`, 49152~49160 순위 확인
  - **`-sC` 단독으로 `http-title` 이 나오는지 로컬 재현** — `/tmp/nsetest` 에 `<title>HP Power Manager</title>` 를 띄우고 `nmap -sC -p80` vs `nmap -sV -sC -p80` 비교. `-sC` 단독에서 `http-title` 출력됨, `http-server-header` 는 `-sV` 에서만 출력됨. **테스트 서버·디렉터리는 정리함**
  - `ls -d ~/PG/Kevin ~/Kevin` → 둘 다 부재 확인
- 1차 사료 — Metasploit 모듈 `hp_power_manager_filename.rb`(`Targets`·`BadChars`) · NVD CVE-2009-3999 / 4000 / 2685 · HPSBMA02485 원문(노트 인용 블록)
- 노트 내부 — `buf` 352바이트 전수 파싱(모듈 badchar 20종 대조)

## 6. 판정

- **완료 1/1** — `proof.txt` = `4b506d7e0c989b3b7053f9081881a8d3`, `C:\Users\Administrator\Desktop\proof.txt`. `local.txt` 는 존재하지 않음(플래그 슬롯 1개 · SYSTEM 직행). 근거: 노트 본문의 `type proof.txt` 세션 캡처
- **구조** — `Port Scan Results` 표 O · nmap raw 라인 무손상(`PORT_RE` 색인 가능) · 4항목 완비·중복 없음 · 두 `Initial Access` 제목 상이 · 헤딩 레벨 일관
- **문체 이관 0건** — `pg-doc-reviewer` 로 넘길 건 없음(코드펜스 밖 산문이 이미 명사 종결형이고, 코드펜스 안·`[가정]`·「관측 없음」·타겟 pty 프롬프트가 「다듬어진」 흔적 없음)
