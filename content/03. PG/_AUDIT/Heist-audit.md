---
type: audit
target: "[[Heist]]"
wave: 17
date: 2026-08-26
manual_tags: true
manual_cves: true
---

# Heist — 적대적 검증 (웨이브 17)

대상: `03. PG\Heist.md` (개작본 860행 → 정정 후 858행)
대조본: `git show 15671e5:"03. PG/Heist.md"`(404행, 사람이 푼 원본) · `git show aba5a29:...`(1352행, 1차 개작본)
산출물: `~/PG/Heist/` 11개 · `파일보관\Pasted image 2026070814~1551*.png` 14장 · `~/.zsh_history`

---

## 1. 지시받은 4건 재확인 — **전부 사실이었음**

| # | 작성자 주장 | 재확인 결과 | 근거 |
|---|---|---|---|
| 1 | §2-6 「ReadGMSAPassword principal 은 둘」이 틀림 — **셋** | ✅ 사실 | `jq` 재실행: `HEIST.OFFSEC-S-1-5-32-544`(Group) · `-1000`(Computer) · `-1104`(Group). 1352행판 L378-379 는 첫 행이 누락된 채 「두 principal뿐이다」로 단정. 현재본 L578-580 은 셋 전부이고 **jq 실제 출력과 바이트 일치** |
| 2 | jq 블록에 손으로 넣은 축약·주석이 있었음 | ✅ 사실 | 1352행판 L1196 `GetChanges S-1-5-21-...-498 Group      # Enterprise Read-only Domain Controllers` — SID 축약 + 주석 둘 다 실제 출력에 없음. L424-426 도 `# Domain Admins` 등 주석. 현재본은 축약·주석 0 이고 `20260708141821_groups.json` 재조회와 일치 |
| 3 | `ntpdate`·`faketime` 둘 다 현행 Kali 에 없음 | ✅ 사실 | `apt-cache policy ntpdate` → `Installed: (none) / Candidate: (none)`. `which faketime` → not found. `/usr/sbin/rdate` 만 존재(18512B, 2023-01-31). 해당 두 블록은 현재본에서 제거되고 `_AUDIT\Heist-playbook.md` 제안 3(A-51)에 원문 보존 |
| 4 | §6-10 「개작하며 잡은 것」을 본문에서 제거하고 부록에 원문 보존 | ✅ 사실 | 본문 grep — `정정 이력`·`적대적 검증`·`감사자`·`초고를 대조` 전부 0건. `Heist-playbook.md:870-892` 에 `>` 인용으로 **전문** 보존(표 4행 + 「태그가 서술을 오염시킨다」 단락 + 일반화 단락) |

---

## 2. 고친 것 — 6건

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `크랙` 블록 `enox::HEIST:...:0101000000000000...` (`cat hash.txt` 2줄) | **코드펜스 안 손 축약.** 실측 출력이 아닌 형태. 같은 값이 50행 위(`hash.txt` 인용)에 바이트 일치로 이미 있어 중복이기도 함 | 해당 `cat hash.txt` 서브블록 **삭제**(원문은 아래 §3 에 인용) |
| 같은 블록 `ENOX::HEIST:...0101000000000000...:california` | 동일 — 크랙 «결과» 줄이 손으로 잘려 있었음 | 15671e5 원본 L210 의 **673자 전문으로 복원.** 스크린샷 `20260708141125.png` 와 대조해 일치 확인 |
| `- \`enox\` 의 비밀번호가 \`california\` (rockyou 4,096번째 후보)라 2초에 깨짐` | **틀린 인과.** `Progress: 4096` 은 처리한 후보 수(배치 경계까지 올림)이지 정답 순번이 아님 | `(rockyou **598행**)` 로 정정. 근거: `grep -n -x california /usr/share/wordlists/rockyou.txt` → `598`. 파일 크기 139921507B 가 hashcat 출력의 `Bytes.....` 와 일치해 **같은 워드리스트임을 확인** |
| `\`Progress: 4096/14344385\` — 1,434만 후보 중 4,096번째에서 끝났음` | 동일 오류의 두 번째 발생 | 「첫 배치 4,096개 안에서 끝났음」으로 바꾸고, `Progress` 를 순번으로 읽으면 안 되는 이유를 한 문단 추가 |
| L37 출처 구분 단락의 `` `hashcat -hh` `` | **댕글링 참조.** `hashcat -hh` 블록은 이번 개작에서 `_PLAYBOOK` 제안으로 빠져 노트에 존재하지 않음 | `hash.txt 디코드` 로 교체(실재하는 블록) |
| nmap 블록 캡션 / 해시 캡처 블록 캡션 | **출처 부정확.** nmap 블록의 첫·끝 줄은 `nmap.log` 의 `#` 주석이 아니라 터미널 stdout 형식. 해시 블록 3줄 중 `hash.txt` 에 있는 것은 마지막 한 줄뿐 | 두 캡션에 각각 한 절 추가. 실제 출처(`Pasted image 20260708140953.png`)를 명시 |

---

## 3. 삭제한 원문 (복원 가능하도록 인용)

```
┌──(kali㉿kali)-[~/PG/Heist]
└─$ cat hash.txt
enox::HEIST:a9a24c7373e7eaf6:812295EA02430380A3C69B6C8CD67A27:0101000000000000...
```
삭제 사유 — 코드펜스 안 손 축약이고, 같은 값 전문이 노트 L311-315(`[HTTP] NTLMv2 Hash :` 블록)에 `hash.txt` 와 **바이트 일치**로 이미 실려 있음(662자 검증).

---

## 4. 반증한 것 — 지적으로 올렸다가 노트가 옳았던 것

| # | 의심 | 확인 결과 |
|---|---|---|
| 1 | **nmap raw 블록이 절단됐을 것**(웨이브 15 에서 줄 중간 81B 절단 전례) | **절단 없음.** 69행 전량 대조 — 포트 라인·NSE 출력 전부 무손상. 3243B vs 3124B 의 119B 차이는 **전부 설명됨**: 헤더 줄 형식 차이 83B + 푸터 줄 형식 차이 32B + 후행 공백 4행 4B = 119B. 지시서의 「54바이트」·「3189B」는 실측과 다름 |
| 2 | **에이전트가 붙인 Kali 프롬프트(`┌──(kali㉿kali)`)를 걷어내야 하는가** — jq 5개·nxc 소스·Responder.conf grep·`.state` 파싱·hash 디코드 등 9블록은 15671e5 원본에 없고 `~/.zsh_history` 에도 없음 | **걷어내지 않음.** ① `~/.zsh_history` 는 `EXTENDED_HISTORY` 미설정 + HISTSIZE 트리밍으로 커버리지가 불완전함이 이미 문서화돼 있음(1352행판 §6-8) → **부재 증거의 등급 상한은 `근거부족`**. ② 노트 L37 이 「Kali 프롬프트가 붙어 있어도 그 시각의 세션 캡처는 아님 `[가정]`」으로 **이미 강등 표기**함. CLAUDE.md §8 「근거가 없을 뿐인 서술은 `[가정]` 강등, 지우지 마라」에 정확히 부합 |
| 3 | 프롬프트를 지운 흔적이 있는가 | **없음. 오히려 늘었음.** 원본 9 → 1352행판 37 → 현재 22(감소분은 시행착오 블록의 `_PLAYBOOK` 이관분). **타겟측 증거는 순증** — evil-winrm 프롬프트 13→14, 타겟 `PS C:\` 2 유지, RDP SYSTEM 콘솔의 `C:\Windows\system32>` 프롬프트 **4개 신규**(스크린샷 전사) |
| 4 | 「rockyou 4,096번째」 외에 다른 일반 지식 오류가 있는가 | **없음.** Kali 실행 검증 통과 — 8080/tcp 는 nmap-services 빈도 **15위**(top-1000 확실), 49666/49667 은 top-1000 **밖**, `sed -n '122,134p' .../nxc/protocols/winrm.py` 는 노트 블록과 **완전 일치**(`self.admin_privs = True` 무조건 대입 확인), Responder.conf grep 5줄 재현 일치, `hash.txt` AV_PAIR 디코드 재실행 → `MsvAvTargetName = HTTP/192.168.45.175` 일치, `.state` 파싱 재실행 → `148104 / 622887` · `200 3608 /` 일치 |
| 5 | 스크린샷 전사에 오독이 있는가(`4`→`f` 류) | **없음.** 14장 중 플래그·자격증명이 걸린 4장을 직접 열어 대조 — `proof.txt` = `b041c78918d81a4a4a15732053a1e416`(153113·155109 두 장에서 독립 확인), `:california`(141125), NetNTLMv2 blob(140953, 662자 `hash.txt` 와 일치), Responder 배너·프롬프트(140946) 전부 일치 |
| 6 | 이관 손실(1352→860, 492행) | **손실 없음.** 정규화 대조 결과 「어디에도 없는 줄」 0건. 핵심 문자열 전수 확인 — `18200`·`13100`·`19700`·`usersfile`·`GodPotato`·`AlwaysInstallElevated`·`file://`·`127.0.0.1`·`4662`·`DONT_REQ_PREAUTH`·`best64`·`gen-relay-list`·`MS16-075`·`potfile`·`HISTSIZE`·`SAVEHIST`·`시간 배분` 전부 `Heist-playbook.md` 에 존재. **§6-8「히스토리를 근거로 쓸 때의 함정」은 제안 5(A-64)에 수록됨**(지시서가 지목한 항목) |
| 7 | 「AD 노트 오독 위험」(`<SID>` 꺾쇠 · `svc_apache$` · `::` 구분자 · Ruby 백트레이스) | **훼손 없음.** `undefined method \`quoting_detection_proc'' for module Reline` 의 이중 따옴표까지 15671e5 원본과 동일. `svc_apache$` 표기·`enox::HEIST:` 콜론 구분 전부 보존 |
| 8 | 「볼트 taxonomy 에 `tech/ad/gmsa`·`tech/ad/coerced-auth` 가 없다」는 작성자 주장 | **사실.** 전 볼트 grep 결과 두 문자열은 `_AUDIT\Heist-playbook.md` 와 `_AUDIT\Vault-audit.md` **문장 안에서만** 등장하고 실제 프론트매터 태그로는 0건 |

---

## 5. 구조·색인 검증 (전부 통과)

- **4항목 완비** — `Initial Access`(긴 제목, L43) · `Privilege Escalation – gMSA 비밀번호 읽기 → PtH → SeRestorePrivilege`(L500) **양쪽** 에 `Vulnerability Explanation:`·`Vulnerability Fix:`·`Severity:`·`Steps to reproduce the attack:` 4개 전부 존재
- **절 순서** — `Initial Access`(요약) → `Service Enumeration` → `Initial Access`(상세, 짧은 제목) → `Privilege Escalation` → `Post-Exploitation`. `_WRITEUP-STANDARD.md:97-129` 템플릿과 동일. 두 `Initial Access` 제목 상이 ✅(L168 의 「`Initial Access` 재현 절의 스윕 출력」이 STANDARD:192 의 ✅ 참조 패턴)
- **경로 A·B 한 절 안** — `utilman.exe` 치환+RDP(본선)와 `SeRestoreAbuse.exe`(대안)가 `Privilege Escalation` 한 절 안에 본선/대안으로 배치. 절 분할 없음
- **`Port Scan Results` 표** 존재. **nmap raw 포트 라인 21줄** 유지 → `extract.py PORT_RE` 정상 동작
- **펜스** — 66개(짝수, 균형) · 무태그 여는 펜스 **0** · 펜스 안 한국어 **0**
- **스크린샷** — embed 14개 = `파일보관` 실존 14개, 전부 링크 유효. (`Pasted image 20260708155108.png` 1장은 미참조이나 `155109` 와 거의 동일 프레임이라 손실 아님)
- **위키링크** — `Vault`·`Butch`·`Squid`·`Resourced`·`Nagoya`·`Hutch`·`Exghost`·`_PLAYBOOK`·`_WRITEUP-STANDARD`·`_STATUS` 전부 실존. `_PLAYBOOK` 앵커 7개(A-11·A-23·A-51·A-64·B-42·B-53·B-66) 제목 문자열 완전 일치
- **프론트매터** — `manual_tags: true`·`manual_cves: true` 유지. `tech/*` 11개 = `tech_count: 11` 일치. `ports` 는 49xxx 제외(Windows 노트 의도된 제외, CLAUDE.md §5)
- **시간 서사** — L37 「2026-07-08 13:56~15:51」이 `nmap.log` 시작(13:56:08)과 마지막 스크린샷(`155147`)에 정합

## 6. 태그 판정 — `tech/ad/ntlm-relay` 유지

릴레이는 **시도했으나 성립하지 않았음**(SMB 서명 필수 + 단일 호스트)이라 「실제 사용한 기법」 기준으로는 제거 대상. 그러나 **유지**를 택함:
- 볼트 taxonomy 에 `ntlm-capture`/`coerced-auth` 대체 태그가 **없음**(§4-8 확인). 지우면 「Responder·강제 인증」 검색에서 이 노트가 **색인에서 사라짐** — CLAUDE.md §0 「안 찾아지는 노트는 없는 노트다」에 정면 충돌
- 노트 본문이 세 곳에서 「릴레이는 성립하지 않았다」를 명시해 오독 위험을 이미 차단함
- 동일 사안이 `_AUDIT\Vault-audit.md:168` 에서 이미 총괄에 에스컬레이션돼 있음(중복 제기)

## 7. 근거 출처

- Kali 산출물 — `~/PG/Heist/{nmap.log,hash.txt,ferox-*.state,20260708141821_*.json}` · `~/.zsh_history`(`heist` 대소문자 무시 9건)
- 볼트 스크린샷 — `파일보관\Pasted image 20260708{140946,140953,141125,153113,155108,155109}.png` 직접 열람
- git — `15671e5`(원본 404행) · `aba5a29`(1352행)
- Kali 직접 실행 — `jq` 6종 재조회 · `apt-cache policy ntpdate` · `which faketime rdate` · `md5sum`/`wc -c nmap.log` · `grep -n -x california rockyou.txt` · `sed -n '122,134p' nxc/protocols/winrm.py` · `grep Responder.conf` · `hash.txt` AV_PAIR 디코드 · `.state` 파싱 · nmap-services 빈도 순위
